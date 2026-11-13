import { describe, expect, it } from "vitest";
import { APPLE_ROOT_CA_G3, APPLE_ROOT_CA_G3_SHA256 } from "../src/appleRoot";
import {
  APPLE_LEAF_MARKER_OID,
  APPLE_WWDR_INTERMEDIATE_OID,
  VerificationError,
  verifyAppTransaction,
  type AppTransactionPolicy,
} from "../src/appTransaction";
import { b64urlDecode, b64urlEncode, toHex } from "../src/encoding";
import { ecdsaDerToRaw, isCA, isSignedBy, parseCertificate } from "../src/x509";
import { BUNDLE_ID, NOW_MS, TEST_ROOT, certDer, fixturePem, pemBody, pemToDer, signJws, txPayload } from "./helpers";

const policy: AppTransactionPolicy = { allowedBundleIds: new Set([BUNDLE_ID]), allowXcodeEnv: false };

async function reason(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof VerificationError) return e.reason;
    throw e;
  }
  return "accepted";
}

describe("pinned Apple root", () => {
  it("is Apple Root CA - G3, byte for byte (SHA-256 matches Apple's published fingerprint)", async () => {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", APPLE_ROOT_CA_G3));
    expect(toHex(digest)).toBe(APPLE_ROOT_CA_G3_SHA256);
    const root = parseCertificate(APPLE_ROOT_CA_G3);
    expect(new TextDecoder().decode(root.subject)).toContain("Apple Root CA - G3");
    expect(new Date(root.notAfter).toISOString()).toBe("2039-04-30T18:19:06.000Z");
  });

  it("verifies Apple's real WWDR G6 intermediate (parser + P-384/SHA-384 path on real certs)", async () => {
    const g6 = parseCertificate(pemToDer(fixturePem("apple/AppleWWDRCAG6.pem")));
    const root = parseCertificate(APPLE_ROOT_CA_G3);
    expect(await isSignedBy(g6, root)).toBe(true);
    expect(isCA(g6)).toBe(true);
    expect(g6.extensions.has(APPLE_WWDR_INTERMEDIATE_OID)).toBe(true);
    // And the test root does not vouch for it.
    expect(await isSignedBy(g6, parseCertificate(TEST_ROOT))).toBe(false);
  });

  it("the default (production) trust root rejects a test-root chain", async () => {
    const jws = await signJws(txPayload());
    expect(await reason(verifyAppTransaction(jws, policy, undefined, NOW_MS))).toBe("root_not_pinned");
  });

  it("the default root rejects a forged leaf under Apple's real intermediate and root", async () => {
    const jws = await signJws(txPayload(), {
      header: {
        x5c: [
          pemBody(fixturePem("chain/leaf.pem")),
          pemBody(fixturePem("apple/AppleWWDRCAG6.pem")),
          Buffer.from(APPLE_ROOT_CA_G3).toString("base64"),
        ],
      },
    });
    expect(await reason(verifyAppTransaction(jws, policy, undefined, NOW_MS))).toBe("leaf_signature");
  });
});

describe("x509 helpers", () => {
  it("reads the test chain's marker extensions and CA flags", () => {
    const leaf = parseCertificate(certDer("leaf"));
    const inter = parseCertificate(certDer("intermediate"));
    expect(leaf.extensions.has(APPLE_LEAF_MARKER_OID)).toBe(true);
    expect(inter.extensions.has(APPLE_WWDR_INTERMEDIATE_OID)).toBe(true);
    expect(isCA(inter)).toBe(true);
    expect(isCA(leaf)).toBe(false);
  });
  it("rejects trailing garbage after a certificate", () => {
    const der = certDer("leaf");
    const padded = new Uint8Array(der.length + 1);
    padded.set(der);
    expect(() => parseCertificate(padded)).toThrow();
  });
  it("converts DER ECDSA signatures to fixed-width r||s", () => {
    // SEQUENCE { INTEGER 0x00 0x80 (leading zero kept positive), INTEGER 0x01 }
    const der = new Uint8Array([0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]);
    const raw = ecdsaDerToRaw(der, 4);
    expect(Array.from(raw)).toEqual([0, 0, 0, 0x80, 0, 0, 0, 1]);
  });
});

describe("verifyAppTransaction", () => {
  it("accepts a valid chain and returns the payload", async () => {
    const tx = await verifyAppTransaction(await signJws(txPayload()), policy, TEST_ROOT, NOW_MS);
    expect(tx.bundleId).toBe(BUNDLE_ID);
    expect(tx.receiptType).toBe("Production");
  });

  it("accepts Sandbox (TestFlight)", async () => {
    const jws = await signJws(txPayload({ receiptType: "Sandbox" }));
    expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("accepted");
  });

  it("rejects Xcode and LocalTesting unless allowed", async () => {
    for (const env of ["Xcode", "LocalTesting"]) {
      const jws = await signJws(txPayload({ receiptType: env }));
      expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("environment");
      const allow = { ...policy, allowXcodeEnv: true };
      expect(await reason(verifyAppTransaction(jws, allow, TEST_ROOT, NOW_MS))).toBe("accepted");
    }
  });

  it("rejects unknown or missing environments", async () => {
    for (const receiptType of ["production", "Staging", undefined, 3]) {
      const jws = await signJws(txPayload({ receiptType }));
      expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("environment");
    }
  });

  it("rejects a wrong or missing bundle id", async () => {
    for (const bundleId of ["com.example.Other", undefined]) {
      const jws = await signJws(txPayload({ bundleId }));
      expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("bundle_id");
    }
  });

  it("rejects a tampered payload", async () => {
    const jws = await signJws(txPayload({ bundleId: "com.example.Other" }));
    const [h, , s] = jws.split(".");
    const forged = b64urlEncode(JSON.stringify(txPayload()));
    expect(await reason(verifyAppTransaction(`${h}.${forged}.${s}`, policy, TEST_ROOT, NOW_MS))).toBe(
      "jws_signature",
    );
  });

  it("rejects a tampered signature", async () => {
    const jws = await signJws(txPayload());
    const [h, p, s] = jws.split(".");
    const sig = b64urlDecode(s);
    sig[10] ^= 1;
    expect(await reason(verifyAppTransaction(`${h}.${p}.${b64urlEncode(sig)}`, policy, TEST_ROOT, NOW_MS))).toBe(
      "jws_signature",
    );
  });

  it("rejects a chain to the wrong root", async () => {
    // Whole rogue hierarchy: the third certificate is not the pinned root.
    const rogue = await signJws(txPayload(), { chain: ["rogue-leaf", "rogue-intermediate", "rogue-root"] });
    expect(await reason(verifyAppTransaction(rogue, policy, TEST_ROOT, NOW_MS))).toBe("root_not_pinned");
    // Pinned root appended, but the intermediate was signed by someone else.
    const spliced = await signJws(txPayload(), { chain: ["rogue-leaf", "rogue-intermediate", "root"] });
    expect(await reason(verifyAppTransaction(spliced, policy, TEST_ROOT, NOW_MS))).toBe("intermediate_signature");
    // Leaf from another hierarchy under the genuine intermediate.
    const wrongLeaf = await signJws(txPayload(), { chain: ["rogue-leaf", "intermediate", "root"] });
    expect(await reason(verifyAppTransaction(wrongLeaf, policy, TEST_ROOT, NOW_MS))).toBe("leaf_signature");
  });

  it("rejects expired and not-yet-valid certificates", async () => {
    const jws = await signJws(txPayload());
    const leaf = parseCertificate(certDer("leaf"));
    const after = leaf.notAfter + 2 * 60_000;
    expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, after))).toBe("certificate_expired");
    const before = leaf.notBefore - 2 * 60_000;
    expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, before))).toBe("certificate_expired");
    // Within the 60 s skew either side is still fine.
    expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, leaf.notAfter + 30_000))).toBe("accepted");
  });

  it("rejects a bad alg", async () => {
    for (const alg of ["ES384", "HS256", "none", undefined]) {
      const jws = await signJws(txPayload(), { header: { alg } });
      expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("alg");
    }
  });

  it("requires exactly three certificates", async () => {
    for (const chain of [["leaf", "intermediate"], ["leaf", "intermediate", "root", "root"]]) {
      const jws = await signJws(txPayload(), { chain });
      expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("chain_length");
    }
    const none = await signJws(txPayload(), { header: { x5c: undefined } });
    expect(await reason(verifyAppTransaction(none, policy, TEST_ROOT, NOW_MS))).toBe("chain_length");
  });

  it("requires Apple's marker OIDs and a CA intermediate", async () => {
    const noLeafMarker = await signJws(txPayload(), { chain: ["leaf-no-marker", "intermediate", "root"] });
    expect(await reason(verifyAppTransaction(noLeafMarker, policy, TEST_ROOT, NOW_MS))).toBe("leaf_marker");
    const noInterMarker = await signJws(txPayload(), {
      chain: ["leaf-under-no-marker", "intermediate-no-marker", "root"],
    });
    expect(await reason(verifyAppTransaction(noInterMarker, policy, TEST_ROOT, NOW_MS))).toBe(
      "intermediate_marker",
    );
    const notCa = await signJws(txPayload(), { chain: ["leaf-under-not-ca", "intermediate-not-ca", "root"] });
    expect(await reason(verifyAppTransaction(notCa, policy, TEST_ROOT, NOW_MS))).toBe("intermediate_not_ca");
  });

  it("rejects malformed input without throwing anything but VerificationError", async () => {
    const good = await signJws(txPayload());
    const [h, p, s] = good.split(".");
    const cases = [
      "",
      "a.b",
      `${h}.${p}`,
      `${h}.${p}.${s}.x`,
      `!!.${p}.${s}`,
      `${b64urlEncode("not json")}.${p}.${s}`,
      `${b64urlEncode(JSON.stringify({ alg: "ES256", x5c: ["AAAA", "AAAA", "AAAA"] }))}.${p}.${s}`,
      `${h}.${b64urlEncode("[1,2]")}.${s}`,
      "x".repeat(20_000),
    ];
    for (const c of cases) {
      expect(await reason(verifyAppTransaction(c, policy, TEST_ROOT, NOW_MS))).not.toBe("accepted");
    }
  });

  it("rejects mistyped optional identity fields", async () => {
    const jws = await signJws(txPayload({ appTransactionId: 123 }));
    expect(await reason(verifyAppTransaction(jws, policy, TEST_ROOT, NOW_MS))).toBe("payload");
  });
});
