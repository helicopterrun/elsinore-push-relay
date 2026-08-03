// Core relay logic, kept free of Worker bindings so it is unit-testable in
// plain Node: payload validation, the severity-keyed APNs body template, and
// ES256 provider-JWT signing via WebCrypto.
//
// Wire contract (implemented by frigate-sidecar's RelayTransport): POST
// /v1/relay/push with {device_token, environment, handle, server_id,
// severity, "apns-collapse-id"}. Deliberately content-free — no camera name,
// label, or imagery ever reaches this service; the iOS notification service
// extension redeems `handle` against the user's own sidecar for the real
// camera/thumbnail. See Elsinore's sidecar-push-notifications-spec.md §4.

export interface RelayRequest {
  device_token: string;
  environment: "production" | "sandbox";
  handle: string;
  server_id: string;
  severity: string;
  "apns-collapse-id": string;
}

const TOKEN_RE = /^[0-9a-fA-F]{16,200}$/;
const MAX_FIELD = 300;

/** Parse and validate an incoming body; returns an error string, or null. */
export function validate(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "body must be a JSON object";
  const b = body as Record<string, unknown>;
  for (const key of ["device_token", "environment", "handle", "server_id", "severity", "apns-collapse-id"]) {
    const v = b[key];
    if (typeof v !== "string" || v.length === 0) return `${key} must be a non-empty string`;
    if (v.length > MAX_FIELD) return `${key} too long`;
  }
  if (!TOKEN_RE.test(b.device_token as string)) return "device_token must be hex";
  if (b.environment !== "production" && b.environment !== "sandbox") {
    return "environment must be 'production' or 'sandbox'";
  }
  return null;
}

export function apnsHost(environment: RelayRequest["environment"]): string {
  return environment === "sandbox" ? "api.sandbox.push.apple.com" : "api.push.apple.com";
}

/**
 * The APNs payload. The alert text is a fixed template keyed by severity —
 * the relay composes it itself and cannot say anything scene-specific.
 * `mutable-content` lets the NSE rewrite title/body/attachment after
 * redeeming `handle` against the user's own server.
 */
export function apsPayload(req: RelayRequest): Record<string, unknown> {
  const body = req.severity === "alert" ? "New alert on your server" : "Activity on your server";
  return {
    aps: {
      alert: { title: "Elsinore", body },
      sound: req.severity === "alert" ? "default" : undefined,
      "mutable-content": 1,
      "thread-id": req.server_id,
    },
    handle: req.handle,
    server_id: req.server_id,
    severity: req.severity,
  };
}

// ---- Provider JWT -----------------------------------------------------------

/** Strips PEM armor if present; the p8 secret may be pasted either way. */
export function p8ToPkcs8Bytes(p8: string): Uint8Array {
  const base64 = p8
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function b64url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface JwtSigner {
  /** A provider JWT no older than ~45 min, re-signed on demand. */
  token(nowSeconds?: number): Promise<string>;
}

/**
 * Signs the APNs provider JWT (ES256, kid + iss + iat) and caches it —
 * Apple rejects tokens older than 60 min and throttles re-signing more often
 * than every 20, so the cache refreshes at 45.
 */
export function makeJwtSigner(p8: string, keyId: string, teamId: string): JwtSigner {
  let cached: { token: string; iat: number } | null = null;
  let keyPromise: Promise<CryptoKey> | null = null;

  function key(): Promise<CryptoKey> {
    keyPromise ??= crypto.subtle.importKey(
      "pkcs8",
      p8ToPkcs8Bytes(p8).buffer as ArrayBuffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    return keyPromise;
  }

  return {
    async token(nowSeconds = Math.floor(Date.now() / 1000)): Promise<string> {
      if (cached && nowSeconds - cached.iat < 45 * 60) return cached.token;
      const header = b64url(JSON.stringify({ alg: "ES256", kid: keyId }));
      const claims = b64url(JSON.stringify({ iss: teamId, iat: nowSeconds }));
      const signingInput = `${header}.${claims}`;
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        await key(),
        new TextEncoder().encode(signingInput),
      );
      const token = `${signingInput}.${b64url(new Uint8Array(sig))}`;
      cached = { token, iat: nowSeconds };
      return token;
    },
  };
}

// ---- APNs response mapping --------------------------------------------------

/**
 * Maps Apple's response onto the sidecar-facing status. 410 Unregistered and
 * 400 BadDeviceToken pass through so the sidecar prunes the dead token
 * (RelayTransport treats exactly those two as permanent); everything else
 * that fails becomes 502 so the sidecar logs and moves on without pruning.
 */
export function relayStatus(apnsStatus: number, apnsBody: string): { status: number; detail: string } {
  if (apnsStatus === 200) return { status: 200, detail: "ok" };
  if (apnsStatus === 410) return { status: 410, detail: "Unregistered" };
  if (apnsStatus === 400 && apnsBody.includes("BadDeviceToken")) {
    return { status: 400, detail: "BadDeviceToken" };
  }
  return { status: 502, detail: `apns ${apnsStatus}: ${apnsBody.slice(0, 200)}` };
}
