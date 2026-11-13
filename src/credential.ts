// Per-install relay credentials: `v1.<b64url(payload)>.<b64url(sig)>`, where
// payload is UTF-8 JSON {v, kid, iid, bid, env, iat, exp} and sig is
// HMAC-SHA256 under the secret named by `kid`, over the exact b64url payload
// string. Stateless: the relay stores nothing — the HMAC is the record.

import type { AppTransactionPayload } from "./appTransaction";
import { b64urlDecode, b64urlEncode, buf, fromUtf8, utf8 } from "./encoding";

export const CREDENTIAL_VERSION = 1;
export const CREDENTIAL_LIFETIME_S = 180 * 24 * 3600;
export const CREDENTIAL_REFRESH_AFTER_S = 30 * 24 * 3600;
/** Tolerated clock skew for a credential's `iat` lying slightly in the future. */
export const CREDENTIAL_IAT_SKEW_S = 300;
/** Bound on Authorization header token length; real credentials are ~250 chars. */
export const MAX_CREDENTIAL_LENGTH = 2048;
export const DEFAULT_KID = "k1";

export interface CredentialClaims {
  v: number;
  kid: string;
  iid: string;
  bid: string;
  env: string;
  iat: number;
  exp: number;
}

/** The signing keys an operator has configured: current plus optional previous. */
export interface CredentialKeys {
  current: { kid: string; secret: string };
  previous?: { kid: string; secret: string };
}

const keyCache = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  let k = keyCache.get(secret);
  if (!k) {
    k = crypto.subtle.importKey("raw", buf(utf8(secret)), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    if (keyCache.size > 8) keyCache.clear();
    keyCache.set(secret, k);
  }
  return k;
}

async function hmac(secret: string, message: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), buf(utf8(message))));
}

/**
 * The stable identifier an install's iid is derived from. Prefers
 * `appTransactionId`; older OS versions may omit it, in which case it falls
 * back to bundleId + originalPurchaseDate + deviceVerification. Returns null
 * when neither form is available (issuance is then refused rather than
 * minting a shared iid for every such install).
 */
export function stableInstallIdentifier(tx: AppTransactionPayload): string | null {
  if (typeof tx.appTransactionId === "string" && tx.appTransactionId.length > 0) return tx.appTransactionId;
  if (
    typeof tx.bundleId === "string" &&
    typeof tx.originalPurchaseDate === "number" &&
    typeof tx.deviceVerification === "string" &&
    tx.deviceVerification.length > 0
  ) {
    return `fallback:${tx.bundleId}:${tx.originalPurchaseDate}:${tx.deviceVerification}`;
  }
  return null;
}

/** iid = b64url(first 16 bytes of HMAC-SHA256(secret, "iid:" + stable id)). */
export async function deriveInstallId(secret: string, stableId: string): Promise<string> {
  return b64urlEncode((await hmac(secret, `iid:${stableId}`)).subarray(0, 16));
}

export interface IssuedCredential {
  credential: string;
  install_id: string;
  expires_at: number;
  refresh_after: number;
}

export async function issueCredential(
  keys: CredentialKeys,
  fields: { iid: string; bid: string; env: string },
  nowS: number,
): Promise<IssuedCredential> {
  const claims: CredentialClaims = {
    v: CREDENTIAL_VERSION,
    kid: keys.current.kid,
    iid: fields.iid,
    bid: fields.bid,
    env: fields.env,
    iat: nowS,
    exp: nowS + CREDENTIAL_LIFETIME_S,
  };
  const payload = b64urlEncode(JSON.stringify(claims));
  const sig = b64urlEncode(await hmac(keys.current.secret, payload));
  return {
    credential: `v${CREDENTIAL_VERSION}.${payload}.${sig}`,
    install_id: fields.iid,
    expires_at: claims.exp,
    refresh_after: claims.iat + CREDENTIAL_REFRESH_AFTER_S,
  };
}

export type CredentialCheck =
  | { ok: true; claims: CredentialClaims }
  | { ok: false; reason: "malformed" | "unknown_kid" | "bad_signature" | "expired" | "revoked" };

/**
 * Verifies a credential. The signature is checked with
 * `crypto.subtle.verify` (constant-time) before any claim other than `kid`
 * is trusted; `kid` only selects which secret to verify with.
 */
export async function verifyCredential(
  token: string,
  keys: CredentialKeys,
  nowS: number,
  revokedIids: ReadonlySet<string> = new Set(),
): Promise<CredentialCheck> {
  if (token.length > MAX_CREDENTIAL_LENGTH) return { ok: false, reason: "malformed" };
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== `v${CREDENTIAL_VERSION}`) return { ok: false, reason: "malformed" };
  const [, payloadB64, sigB64] = parts;

  let raw: Record<string, unknown>;
  let sig: Uint8Array;
  try {
    const v: unknown = JSON.parse(fromUtf8(b64urlDecode(payloadB64)));
    if (typeof v !== "object" || v === null || Array.isArray(v)) return { ok: false, reason: "malformed" };
    raw = v as Record<string, unknown>;
    sig = b64urlDecode(sigB64);
  } catch {
    return { ok: false, reason: "malformed" };
  }

  const secret =
    raw.kid === keys.current.kid
      ? keys.current.secret
      : keys.previous && raw.kid === keys.previous.kid
      ? keys.previous.secret
      : null;
  if (secret === null) return { ok: false, reason: "unknown_kid" };

  const valid = await crypto.subtle.verify("HMAC", await hmacKey(secret), buf(sig), buf(utf8(payloadB64)));
  if (!valid) return { ok: false, reason: "bad_signature" };

  const { v, kid, iid, bid, env, iat, exp } = raw;
  if (
    v !== CREDENTIAL_VERSION ||
    typeof kid !== "string" ||
    typeof iid !== "string" ||
    iid.length === 0 ||
    typeof bid !== "string" ||
    typeof env !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number"
  ) {
    return { ok: false, reason: "malformed" };
  }
  if (exp <= nowS || iat > nowS + CREDENTIAL_IAT_SKEW_S) return { ok: false, reason: "expired" };
  if (revokedIids.has(iid)) return { ok: false, reason: "revoked" };
  return { ok: true, claims: { v, kid, iid, bid, env, iat, exp } };
}

/** The operator's configured keys, or null when credentials are disabled. */
export function credentialKeys(env: {
  RELAY_CREDENTIAL_SECRET?: string;
  RELAY_CREDENTIAL_KID?: string;
  RELAY_CREDENTIAL_SECRET_PREV?: string;
  RELAY_CREDENTIAL_KID_PREV?: string;
}): CredentialKeys | null {
  if (!env.RELAY_CREDENTIAL_SECRET) return null;
  const current = { kid: env.RELAY_CREDENTIAL_KID || DEFAULT_KID, secret: env.RELAY_CREDENTIAL_SECRET };
  const prevKid = env.RELAY_CREDENTIAL_KID_PREV;
  const prevSecret = env.RELAY_CREDENTIAL_SECRET_PREV;
  // A previous key needs both halves, and may not shadow the current kid.
  const previous = prevKid && prevSecret && prevKid !== current.kid ? { kid: prevKid, secret: prevSecret } : undefined;
  return { current, previous };
}

/** Parses a comma-separated var into a set of trimmed, non-empty entries. */
export function csvSet(value: string | undefined): Set<string> {
  return new Set((value ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0));
}
