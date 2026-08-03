import { describe, expect, it } from "vitest";
import { apnsHost, apsPayload, makeJwtSigner, p8ToPkcs8Bytes, relayStatus, validate, type RelayRequest } from "../src/relay";
import { rateLimited } from "../src/index";

const good: RelayRequest = {
  device_token: "a".repeat(64),
  environment: "production",
  handle: "h_abc123",
  server_id: "s_1",
  severity: "alert",
  "apns-collapse-id": "review-42",
};

describe("validate", () => {
  it("accepts the sidecar's wire payload", () => {
    expect(validate({ ...good })).toBeNull();
  });
  it("rejects missing and non-string fields", () => {
    expect(validate({ ...good, handle: undefined })).toMatch(/handle/);
    expect(validate({ ...good, severity: 3 })).toMatch(/severity/);
  });
  it("rejects a non-hex device token", () => {
    expect(validate({ ...good, device_token: "zz".repeat(20) })).toMatch(/hex/);
  });
  it("rejects unknown environments", () => {
    expect(validate({ ...good, environment: "staging" })).toMatch(/environment/);
  });
  it("rejects oversized fields", () => {
    expect(validate({ ...good, handle: "h".repeat(400) })).toMatch(/too long/);
  });
});

describe("apnsHost", () => {
  it("routes sandbox and production separately", () => {
    expect(apnsHost("sandbox")).toBe("api.sandbox.push.apple.com");
    expect(apnsHost("production")).toBe("api.push.apple.com");
  });
});

describe("apsPayload", () => {
  it("is content-free: only templated text plus the opaque handle", () => {
    const p = apsPayload(good) as any;
    expect(p.aps.alert.body).toBe("New alert on your server");
    expect(p.aps["mutable-content"]).toBe(1);
    expect(p.handle).toBe("h_abc123");
    // Nothing camera- or label-shaped may exist anywhere in the payload.
    expect(JSON.stringify(p)).not.toMatch(/camera|label|snapshot/);
  });
  it("keys the template and sound off severity", () => {
    const quiet = apsPayload({ ...good, severity: "detection" }) as any;
    expect(quiet.aps.alert.body).toBe("Activity on your server");
    expect(quiet.aps.sound).toBeUndefined();
    expect((apsPayload(good) as any).aps.sound).toBe("default");
  });
});

describe("relayStatus", () => {
  it("passes the two permanent dead-token statuses through for pruning", () => {
    expect(relayStatus(410, '{"reason":"Unregistered"}').status).toBe(410);
    expect(relayStatus(400, '{"reason":"BadDeviceToken"}').status).toBe(400);
  });
  it("does NOT pass through other 400s — only BadDeviceToken prunes", () => {
    expect(relayStatus(400, '{"reason":"BadCollapseId"}').status).toBe(502);
  });
  it("maps success and server-side failures", () => {
    expect(relayStatus(200, "").status).toBe(200);
    expect(relayStatus(500, "oops").status).toBe(502);
    expect(relayStatus(403, '{"reason":"ExpiredProviderToken"}').status).toBe(502);
  });
});

describe("jwt signer", () => {
  async function freshP8(): Promise<string> {
    const pair = (await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"],
    )) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey) as ArrayBuffer);
    let s = "";
    for (const b of pkcs8) s += String.fromCharCode(b);
    return `-----BEGIN PRIVATE KEY-----\n${btoa(s)}\n-----END PRIVATE KEY-----`;
  }

  it("signs a three-part ES256 JWT with kid and iss", async () => {
    const signer = makeJwtSigner(await freshP8(), "KEY123", "TEAM456");
    const token = await signer.token(1_000_000);
    const [header, claims] = token.split(".").slice(0, 2).map((p) =>
      JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()),
    );
    expect(token.split(".")).toHaveLength(3);
    expect(header).toEqual({ alg: "ES256", kid: "KEY123" });
    expect(claims).toEqual({ iss: "TEAM456", iat: 1_000_000 });
  });

  it("caches inside 45 minutes and re-signs after", async () => {
    const signer = makeJwtSigner(await freshP8(), "K", "T");
    const first = await signer.token(1_000_000);
    expect(await signer.token(1_000_000 + 44 * 60)).toBe(first);
    expect(await signer.token(1_000_000 + 46 * 60)).not.toBe(first);
  });

  it("accepts a p8 with or without PEM armor", async () => {
    const armored = await freshP8();
    const bare = armored.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
    expect(p8ToPkcs8Bytes(armored)).toEqual(p8ToPkcs8Bytes(bare));
  });
});

describe("rate limiter", () => {
  it("allows 60 per hour then refuses, and forgets old sends", () => {
    const sends = new Map<string, number[]>();
    const t0 = 10_000_000;
    for (let i = 0; i < 60; i++) expect(rateLimited("tok", t0 + i, sends)).toBe(false);
    expect(rateLimited("tok", t0 + 61, sends)).toBe(true);
    // An hour later the window has rolled — sends are allowed again.
    expect(rateLimited("tok", t0 + 3_600_100, sends)).toBe(false);
  });
  it("limits per token, not globally", () => {
    const sends = new Map<string, number[]>();
    for (let i = 0; i < 60; i++) rateLimited("a", 1000 + i, sends);
    expect(rateLimited("a", 2000, sends)).toBe(true);
    expect(rateLimited("b", 2000, sends)).toBe(false);
  });
});
