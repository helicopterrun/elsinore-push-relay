// Shared test scaffolding: the self-generated chains in test/fixtures/chain
// (see gen-test-chain.sh) and a signer that mints AppTransaction-shaped JWS
// with the test leaf key.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { b64urlEncode } from "../src/encoding";
import { parseCertificate } from "../src/x509";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));

export function pemBody(pem: string): string {
  return pem.replace(/-----(BEGIN|END) [A-Z ]+-----/g, "").replace(/\s+/g, "");
}

export function pemToDer(pem: string): Uint8Array {
  return new Uint8Array(Buffer.from(pemBody(pem), "base64"));
}

export function fixturePem(path: string): string {
  return readFileSync(`${FIXTURES}${path}`, "utf8");
}

export function certDer(name: string): Uint8Array {
  return pemToDer(fixturePem(`chain/${name}.pem`));
}

/** base64 (not url) DER, as it appears in an `x5c` header entry. */
export function x5cEntry(name: string): string {
  return pemBody(fixturePem(`chain/${name}.pem`));
}

export const TEST_ROOT = certDer("root");

/** A moment inside every test certificate's validity window. */
export const NOW_MS = parseCertificate(certDer("leaf")).notBefore + 24 * 3600 * 1000;

let leafKey: Promise<CryptoKey> | null = null;
function signingKey(): Promise<CryptoKey> {
  leafKey ??= crypto.subtle.importKey(
    "pkcs8",
    pemToDer(fixturePem("chain/leaf-TEST-ONLY.key.pem")),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  return leafKey;
}

export const BUNDLE_ID = "com.example.TestApp";

export function txPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    receiptType: "Production",
    appAppleId: 1234567890,
    bundleId: BUNDLE_ID,
    applicationVersion: "42",
    versionExternalIdentifier: 0,
    receiptCreationDate: NOW_MS - 1000,
    requestDate: NOW_MS,
    originalApplicationVersion: "1",
    originalPurchaseDate: 1_700_000_000_000,
    deviceVerification: "dGVzdC1kZXZpY2UtdmVyaWZpY2F0aW9u",
    deviceVerificationNonce: "6f0f4d4e-1111-2222-3333-444455556666",
    appTransactionId: "704289572311663110",
    originalPlatform: "iOS",
    ...overrides,
  };
}

export interface JwsOptions {
  chain?: string[];
  header?: Record<string, unknown>;
}

export async function signJws(payload: Record<string, unknown>, opts: JwsOptions = {}): Promise<string> {
  const chain = opts.chain ?? ["leaf", "intermediate", "root"];
  const header = b64urlEncode(JSON.stringify({ alg: "ES256", x5c: chain.map(x5cEntry), ...opts.header }));
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await signingKey(),
    new TextEncoder().encode(`${header}.${body}`),
  );
  return `${header}.${body}.${b64urlEncode(new Uint8Array(sig))}`;
}
