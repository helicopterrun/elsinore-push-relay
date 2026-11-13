// Verifies a StoreKit 2 AppTransaction JWS (`AppTransaction.shared`'s
// `jwsRepresentation`) the way Apple's own server library does, on WebCrypto.
//
// Reference implementation mirrored here: Apple's
// app-store-server-library-node, `jws_verification.ts`,
// `SignedDataVerifier.verifyAndDecodeAppTransaction` → `verifyJWT` →
// `verifyCertificateChainWithoutCaching`
// (https://github.com/apple/app-store-server-library-node). It checks:
//   - the `x5c` header holds exactly 3 certificates;
//   - the intermediate is signed by a trusted root and names it as issuer;
//   - the leaf is signed by the intermediate and names it as issuer;
//   - the intermediate is a CA (basicConstraints cA);
//   - the leaf carries extension OID 1.2.840.113635.100.6.11.1 and the
//     intermediate carries 1.2.840.113635.100.6.2.1 (Apple's JWSDecodedHeader
//     docs name the latter "Apple Worldwide Developer Relations");
//   - leaf, intermediate and root are inside their validity period (±60 s)
//     at the transaction's signing date (see below);
//   - the JWS signature verifies with the leaf's public key;
//   - `bundleId` and the environment (`receiptType` in the JWS payload) match.
// Online OCSP revocation checks (Apple's `enableOnlineChecks`) are NOT done.
//
// Differences, all stricter: `alg` must be exactly ES256 (Apple's library lets
// `jsonwebtoken` accept any EC algorithm for the key); the chain's third
// certificate must be byte-identical to the pinned root (Apple's library
// ignores it and checks the intermediate against its configured roots — this
// code does that too).
//
// Certificate validity is checked at the same effective date Apple's library
// uses with online checks off: `verifyJWT` takes
// `effectiveDate = enableOnlineChecks ? new Date() : signedDateExtractor(payload)`,
// and for an AppTransaction the extractor is
// `t => t.receiptCreationDate === undefined ? new Date() : new Date(t.receiptCreationDate)`.
// So a cached AppTransaction signed while its leaf was valid still verifies
// after that leaf expires. One addition: a `receiptCreationDate` more than
// 60 s in the future is rejected (Apple's library does not check that).
//
// Apple's library skips signature verification entirely for the Xcode and
// LocalTesting environments ("Data is not signed by the App Store"). This code
// never skips it: `allowXcodeEnv` only widens the accepted environment values,
// so an Xcode-environment transaction is still rejected unless it chains to the
// pinned Apple root.

import { APPLE_ROOT_CA_G3 } from "./appleRoot";
import { b64Decode, b64urlDecode, buf, bytesEqual, fromUtf8, utf8 } from "./encoding";
import { OID, importEcKey, isCA, isSignedBy, parseCertificate, type Certificate } from "./x509";

/** Apple's receipt-signing marker on the leaf certificate. */
export const APPLE_LEAF_MARKER_OID = "1.2.840.113635.100.6.11.1";
/** Apple Worldwide Developer Relations marker on the intermediate. */
export const APPLE_WWDR_INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1";
/** Same skew allowance Apple's library uses (MAX_SKEW = 60000 ms). */
export const CERT_CLOCK_SKEW_MS = 60_000;
/** A real AppTransaction JWS is a few KB; anything far beyond is not one. */
export const MAX_JWS_LENGTH = 16_384;

/** The environment values Apple's library defines (`Environment` enum). */
const STORE_ENVIRONMENTS = new Set(["Production", "Sandbox"]);
const DEV_ENVIRONMENTS = new Set(["Xcode", "LocalTesting"]);

export interface AppTransactionPolicy {
  allowedBundleIds: ReadonlySet<string>;
  /** Also accept the Xcode / LocalTesting environments (still Apple-root-verified). */
  allowXcodeEnv: boolean;
}

/** The decoded payload fields this relay reads. Spellings per Apple's
 * JWSAppTransactionDecodedPayload and the library's AppTransaction model. */
export interface AppTransactionPayload {
  bundleId: string;
  /** Production | Sandbox | Xcode | LocalTesting. */
  receiptType: string;
  appTransactionId?: string;
  originalPurchaseDate?: number;
  deviceVerification?: string;
  [key: string]: unknown;
}

export class VerificationError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "VerificationError";
  }
}

function fail(reason: string): never {
  throw new VerificationError(reason);
}

function withinValidity(cert: Certificate, nowMs: number): boolean {
  return cert.notBefore <= nowMs + CERT_CLOCK_SKEW_MS && cert.notAfter >= nowMs - CERT_CLOCK_SKEW_MS;
}

function parseJsonObject(bytes: Uint8Array): Record<string, unknown> {
  const v: unknown = JSON.parse(fromUtf8(bytes));
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
  return v as Record<string, unknown>;
}

/**
 * Verifies `jws` and returns its payload, or throws `VerificationError`.
 *
 * `trustedRoot` exists only so tests can supply a self-generated chain. The
 * Worker never passes it, so production always verifies against the pinned
 * Apple Root CA - G3.
 */
export async function verifyAppTransaction(
  jws: string,
  policy: AppTransactionPolicy,
  trustedRoot: Uint8Array = APPLE_ROOT_CA_G3,
  nowMs: number = Date.now(),
): Promise<AppTransactionPayload> {
  if (typeof jws !== "string" || jws.length === 0 || jws.length > MAX_JWS_LENGTH) fail("malformed");
  const parts = jws.split(".");
  if (parts.length !== 3) fail("malformed");
  const [headerB64, payloadB64, sigB64] = parts;

  let header: Record<string, unknown>;
  let signature: Uint8Array;
  try {
    header = parseJsonObject(b64urlDecode(headerB64));
    signature = b64urlDecode(sigB64);
  } catch {
    fail("malformed");
  }
  if (header.alg !== "ES256") fail("alg");
  const x5c = header.x5c;
  if (!Array.isArray(x5c) || x5c.length !== 3 || !x5c.every((c) => typeof c === "string")) fail("chain_length");

  let leaf: Certificate, intermediate: Certificate, root: Certificate, anchor: Certificate;
  try {
    [leaf, intermediate, root] = (x5c as string[]).map((c) => parseCertificate(b64Decode(c)));
    anchor = parseCertificate(trustedRoot);
  } catch {
    fail("certificate_parse");
  }

  if (!bytesEqual(root.raw, anchor.raw)) fail("root_not_pinned");
  try {
    if (!(await isSignedBy(intermediate, anchor))) fail("intermediate_signature");
    if (!(await isSignedBy(leaf, intermediate))) fail("leaf_signature");
    if (!isCA(intermediate)) fail("intermediate_not_ca");
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    fail("chain");
  }
  if (!leaf.extensions.has(APPLE_LEAF_MARKER_OID)) fail("leaf_marker");
  if (!intermediate.extensions.has(APPLE_WWDR_INTERMEDIATE_OID)) fail("intermediate_marker");
  // ES256 (RFC 7518 §3.4): P-256 key, SHA-256, signature is the 64-byte r||s.
  if (leaf.namedCurve !== OID.p256 || signature.length !== 64) fail("jws_signature");
  try {
    const { key } = await importEcKey(leaf);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      buf(signature),
      buf(utf8(`${headerB64}.${payloadB64}`)),
    );
    if (!ok) fail("jws_signature");
  } catch (e) {
    if (e instanceof VerificationError) throw e;
    fail("jws_signature");
  }

  // Only now is the payload trusted.
  let payload: Record<string, unknown>;
  try {
    payload = parseJsonObject(b64urlDecode(payloadB64));
  } catch {
    fail("payload");
  }

  // Effective date for certificate validity: the transaction's signing date
  // (`receiptCreationDate`, epoch ms) when present, else now — as Apple's library.
  const signed = payload.receiptCreationDate;
  if (signed !== undefined && (typeof signed !== "number" || !Number.isFinite(signed))) fail("payload");
  if (typeof signed === "number" && signed > nowMs + CERT_CLOCK_SKEW_MS) fail("signed_in_future");
  const effectiveMs = typeof signed === "number" ? signed : nowMs;
  for (const cert of [leaf, intermediate, anchor]) {
    if (!withinValidity(cert, effectiveMs)) fail("certificate_expired");
  }
  const { bundleId, receiptType, appTransactionId, originalPurchaseDate, deviceVerification } = payload;
  if (typeof bundleId !== "string" || !policy.allowedBundleIds.has(bundleId)) fail("bundle_id");
  if (typeof receiptType !== "string") fail("environment");
  const envOk = STORE_ENVIRONMENTS.has(receiptType) || (policy.allowXcodeEnv && DEV_ENVIRONMENTS.has(receiptType));
  if (!envOk) fail("environment");
  if (appTransactionId !== undefined && typeof appTransactionId !== "string") fail("payload");
  if (originalPurchaseDate !== undefined && typeof originalPurchaseDate !== "number") fail("payload");
  if (deviceVerification !== undefined && typeof deviceVerification !== "string") fail("payload");
  return payload as AppTransactionPayload;
}
