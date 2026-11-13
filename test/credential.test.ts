import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_LIFETIME_S,
  CREDENTIAL_REFRESH_AFTER_S,
  credentialKeys,
  csvSet,
  deriveInstallId,
  issueCredential,
  stableInstallIdentifier,
  verifyCredential,
  type CredentialKeys,
} from "../src/credential";
import { b64urlDecode, b64urlEncode } from "../src/encoding";
import type { AppTransactionPayload } from "../src/appTransaction";

const keys: CredentialKeys = { current: { kid: "k2", secret: "current-secret" } };
const rotated: CredentialKeys = {
  current: { kid: "k2", secret: "current-secret" },
  previous: { kid: "k1", secret: "old-secret" },
};
const NOW = 1_800_000_000;
const fields = { iid: "aWlkLWZvci10ZXN0aW5nMQ", bid: "com.example.TestApp", env: "Sandbox" };

function claimsOf(credential: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlDecode(credential.split(".")[1])));
}

describe("issueCredential", () => {
  it("produces the v1 wire shape with the contract's lifetimes", async () => {
    const out = await issueCredential(keys, fields, NOW);
    expect(out.credential).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(out.install_id).toBe(fields.iid);
    expect(out.expires_at).toBe(NOW + CREDENTIAL_LIFETIME_S);
    expect(out.refresh_after).toBe(NOW + CREDENTIAL_REFRESH_AFTER_S);
    expect(CREDENTIAL_LIFETIME_S).toBe(180 * 86400);
    expect(CREDENTIAL_REFRESH_AFTER_S).toBe(30 * 86400);
    expect(claimsOf(out.credential)).toEqual({
      v: 1,
      kid: "k2",
      iid: fields.iid,
      bid: fields.bid,
      env: "Sandbox",
      iat: NOW,
      exp: NOW + CREDENTIAL_LIFETIME_S,
    });
  });

  it("signs the exact b64url payload string with HMAC-SHA256", async () => {
    const out = await issueCredential(keys, fields, NOW);
    const [, payload, sig] = out.credential.split(".");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("current-secret"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)));
    expect(sig).toBe(b64urlEncode(expected));
  });
});

describe("verifyCredential", () => {
  it("accepts a fresh credential", async () => {
    const { credential } = await issueCredential(keys, fields, NOW);
    const check = await verifyCredential(credential, keys, NOW + 10);
    expect(check.ok && check.claims.iid).toBe(fields.iid);
  });

  it("rejects an expired credential", async () => {
    const { credential } = await issueCredential(keys, fields, NOW);
    expect(await verifyCredential(credential, keys, NOW + CREDENTIAL_LIFETIME_S)).toEqual({
      ok: false,
      reason: "expired",
    });
    // Still good one second before expiry.
    expect((await verifyCredential(credential, keys, NOW + CREDENTIAL_LIFETIME_S - 1)).ok).toBe(true);
  });

  it("rejects a credential issued in the future", async () => {
    const { credential } = await issueCredential(keys, fields, NOW + 3600);
    expect((await verifyCredential(credential, keys, NOW)).ok).toBe(false);
  });

  it("rejects a tampered payload or signature", async () => {
    const { credential } = await issueCredential(keys, fields, NOW);
    const [v, payload, sig] = credential.split(".");
    const forged = b64urlEncode(JSON.stringify({ ...claimsOf(credential), iid: "someone-else" }));
    expect(await verifyCredential(`${v}.${forged}.${sig}`, keys, NOW)).toEqual({ ok: false, reason: "bad_signature" });
    const badSig = b64urlDecode(sig);
    badSig[0] ^= 1;
    expect(await verifyCredential(`${v}.${payload}.${b64urlEncode(badSig)}`, keys, NOW)).toEqual({
      ok: false,
      reason: "bad_signature",
    });
  });

  it("rejects a credential signed with a different secret under the same kid", async () => {
    const { credential } = await issueCredential({ current: { kid: "k2", secret: "attacker" } }, fields, NOW);
    expect(await verifyCredential(credential, keys, NOW)).toEqual({ ok: false, reason: "bad_signature" });
  });

  it("rejects a revoked install id", async () => {
    const { credential } = await issueCredential(keys, fields, NOW);
    expect(await verifyCredential(credential, keys, NOW, new Set([fields.iid]))).toEqual({
      ok: false,
      reason: "revoked",
    });
  });

  it("rejects an unknown kid", async () => {
    const { credential } = await issueCredential({ current: { kid: "k9", secret: "current-secret" } }, fields, NOW);
    expect(await verifyCredential(credential, keys, NOW)).toEqual({ ok: false, reason: "unknown_kid" });
  });

  it("accepts the previous kid during rotation, and only while it is configured", async () => {
    const { credential } = await issueCredential({ current: { kid: "k1", secret: "old-secret" } }, fields, NOW);
    expect((await verifyCredential(credential, rotated, NOW)).ok).toBe(true);
    expect(await verifyCredential(credential, keys, NOW)).toEqual({ ok: false, reason: "unknown_kid" });
  });

  it("rejects malformed tokens", async () => {
    for (const t of ["", "v1", "v1.a", "v2.a.b", "v1.!!.b", `v1.${b64urlEncode("[]")}.AA`, "v1." + "a".repeat(3000) + ".b"]) {
      expect((await verifyCredential(t, keys, NOW)).ok).toBe(false);
    }
  });
});

describe("install id", () => {
  const tx = (o: Partial<AppTransactionPayload>): AppTransactionPayload => ({
    bundleId: "com.example.TestApp",
    receiptType: "Production",
    ...o,
  });

  it("prefers appTransactionId, else bundleId + originalPurchaseDate + deviceVerification", () => {
    expect(stableInstallIdentifier(tx({ appTransactionId: "7042", originalPurchaseDate: 1, deviceVerification: "d" }))).toBe(
      "7042",
    );
    expect(stableInstallIdentifier(tx({ originalPurchaseDate: 1700, deviceVerification: "dv" }))).toBe(
      "fallback:com.example.TestApp:1700:dv",
    );
    expect(stableInstallIdentifier(tx({ originalPurchaseDate: 1700 }))).toBeNull();
    expect(stableInstallIdentifier(tx({ appTransactionId: "" }))).toBeNull();
  });

  it("is a deterministic 16-byte b64url HMAC of 'iid:' + the stable id", async () => {
    const a = await deriveInstallId("s", "7042");
    expect(a).toBe(await deriveInstallId("s", "7042"));
    expect(b64urlDecode(a).length).toBe(16);
    expect(a).not.toBe(await deriveInstallId("s", "7043"));
    expect(a).not.toBe(await deriveInstallId("other", "7042"));
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("s"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const full = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("iid:7042")));
    expect(a).toBe(b64urlEncode(full.subarray(0, 16)));
  });
});

describe("config parsing", () => {
  it("is disabled without a secret and defaults the kid to k1", () => {
    expect(credentialKeys({})).toBeNull();
    expect(credentialKeys({ RELAY_CREDENTIAL_SECRET: "s" })).toEqual({
      current: { kid: "k1", secret: "s" },
      previous: undefined,
    });
  });
  it("needs both halves of the previous key, which may not shadow the current kid", () => {
    expect(credentialKeys({ RELAY_CREDENTIAL_SECRET: "s", RELAY_CREDENTIAL_SECRET_PREV: "p" })?.previous).toBeUndefined();
    expect(
      credentialKeys({ RELAY_CREDENTIAL_SECRET: "s", RELAY_CREDENTIAL_SECRET_PREV: "p", RELAY_CREDENTIAL_KID_PREV: "k1" })
        ?.previous,
    ).toBeUndefined();
    expect(
      credentialKeys({
        RELAY_CREDENTIAL_SECRET: "s",
        RELAY_CREDENTIAL_KID: "k2",
        RELAY_CREDENTIAL_SECRET_PREV: "p",
        RELAY_CREDENTIAL_KID_PREV: "k1",
      })?.previous,
    ).toEqual({ kid: "k1", secret: "p" });
  });
  it("splits comma lists, trimming blanks", () => {
    expect([...csvSet(" a, b ,,c ")]).toEqual(["a", "b", "c"]);
    expect(csvSet(undefined).size).toBe(0);
  });
});
