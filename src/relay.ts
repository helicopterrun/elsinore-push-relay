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
//
// Second route: POST /v1/relay/test with {device_token, environment} only.
// Backs the app's "Send test notification" button (spec §1, "Test push"). It
// cannot reuse /v1/relay/push, which requires `handle` — a test push carries
// no handle and no `mutable-content`, because there is nothing for the NSE to
// redeem and a tap should just open the app.

export interface RelayRequest {
  device_token: string;
  environment: "production" | "sandbox";
  handle: string;
  server_id: string;
  severity: string;
  "apns-collapse-id": string;
}

/** A test push needs only the two fields that decide *where* it goes. */
export interface TestRequest {
  device_token: string;
  environment: "production" | "sandbox";
}

/**
 * v2 situation push (Elsinore notification-experience-plan §8). The payload is
 * *sidecar-authored* — title/body/thread-id/interruption-level/sound and the
 * situation-shaped extras (situation_id, handle, actions_available) are all
 * decided at MQTT-match time — so the relay does no templating for this route.
 * It validates routing, forwards the payload verbatim to APNs, and returns.
 *
 * "Content-free" here still holds: the relay never persists or logs body
 * bytes — TLS-in-flight transit to APNs is unchanged from every other route.
 */
export interface SituationRelayRequest {
  device_token: string;
  environment: "production" | "sandbox";
  "apns-collapse-id": string;
  /** Full APNs payload, already assembled by the sidecar. */
  payload: Record<string, unknown>;
}

/** APNs standard-alert cap. Rejecting oversized payloads here is friendlier
 * than letting Apple 400 for `PayloadTooLarge` — same bound, clearer error. */
export const APNS_PAYLOAD_MAX_BYTES = 4096;

/** APNs' own cap on the `apns-collapse-id` header. The other route
 * (`/v1/relay/push`) silently truncates because its collapse id is a single
 * review id and truncation is harmless. This route's id is composite —
 * `<situation-id>:<track-id>` — and truncating from the right eats the
 * track id, silently collapsing two distinct tracks into one notification
 * and quietly violating the plan's "distinct tracks stay distinct" property.
 * So this route *rejects* oversized instead of trimming. */
export const APNS_COLLAPSE_ID_MAX_BYTES = 64;

/**
 * v2 Live Activity push (Elsinore Phase 2 plan). Same shape as the situation
 * route, but goes to a different push type + topic:
 *
 * - `apns-push-type: liveactivity` (not `alert`)
 * - `apns-topic: <bundle_id>.push-type.liveactivity`
 *
 * `event` echoes the `aps.event` inside the payload so we can 422 a payload
 * whose start-shape is missing `attributes` up front instead of letting Apple
 * do it later with a less helpful message.
 */
export interface LiveActivityRelayRequest {
  device_token: string;
  environment: "production" | "sandbox";
  "apns-collapse-id": string;
  event: "start" | "update" | "end";
  payload: Record<string, unknown>;
}

const TOKEN_RE = /^[0-9a-fA-F]{16,200}$/;
const MAX_FIELD = 300;

function checkField(b: Record<string, unknown>, key: string): string | null {
  const v = b[key];
  if (typeof v !== "string" || v.length === 0) return `${key} must be a non-empty string`;
  if (v.length > MAX_FIELD) return `${key} too long`;
  return null;
}

/** Shared by both routes: the token and the endpoint it is routed to. */
function checkRouting(b: Record<string, unknown>): string | null {
  for (const key of ["device_token", "environment"]) {
    const bad = checkField(b, key);
    if (bad) return bad;
  }
  if (!TOKEN_RE.test(b.device_token as string)) return "device_token must be hex";
  if (b.environment !== "production" && b.environment !== "sandbox") {
    return "environment must be 'production' or 'sandbox'";
  }
  return null;
}

/** Parse and validate an incoming body; returns an error string, or null. */
export function validate(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "body must be a JSON object";
  const b = body as Record<string, unknown>;
  for (const key of ["handle", "server_id", "severity", "apns-collapse-id"]) {
    const bad = checkField(b, key);
    if (bad) return bad;
  }
  return checkRouting(b);
}

/** Same, for /v1/relay/test — routing fields only, nothing content-bearing. */
export function validateTest(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "body must be a JSON object";
  return checkRouting(body as Record<string, unknown>);
}

/**
 * /v1/relay/situation: routing + collapse-id + a sidecar-authored payload
 * object. Rejects payloads that would 400 at APNs anyway (missing `aps`,
 * oversized). Everything scene-specific inside `payload` is opaque to the
 * relay by design.
 */
/**
 * /v1/relay/liveactivity: routing + collapse-id + event + a sidecar-authored
 * LA payload. Validates that the payload's `aps.event` matches the top-level
 * `event`, and that a `start` payload carries the required `attributes` +
 * `attributes-type` (Apple 400s a start without them).
 */
export function validateLiveActivity(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "body must be a JSON object";
  const b = body as Record<string, unknown>;
  const bad = checkField(b, "apns-collapse-id");
  if (bad) return bad;
  const collapseBytes = new TextEncoder().encode(b["apns-collapse-id"] as string).byteLength;
  if (collapseBytes > APNS_COLLAPSE_ID_MAX_BYTES) {
    return `apns-collapse-id too large (${collapseBytes} > ${APNS_COLLAPSE_ID_MAX_BYTES})`;
  }
  const routing = checkRouting(b);
  if (routing) return routing;
  if (b.event !== "start" && b.event !== "update" && b.event !== "end") {
    return "event must be 'start' | 'update' | 'end'";
  }
  if (typeof b.payload !== "object" || b.payload === null) {
    return "payload must be a JSON object";
  }
  const payload = b.payload as Record<string, unknown>;
  const aps = payload.aps;
  if (typeof aps !== "object" || aps === null) {
    return "payload.aps must be a JSON object";
  }
  const apsRecord = aps as Record<string, unknown>;
  if (apsRecord.event !== b.event) {
    return `payload.aps.event (${apsRecord.event}) must match top-level event (${b.event})`;
  }
  // A start needs the static attributes that let iOS create the activity.
  if (b.event === "start") {
    if (typeof apsRecord["attributes-type"] !== "string") {
      return "payload.aps.attributes-type is required for event='start'";
    }
    if (typeof apsRecord["attributes"] !== "object" || apsRecord["attributes"] === null) {
      return "payload.aps.attributes is required for event='start'";
    }
  }
  const size = new TextEncoder().encode(JSON.stringify(payload)).byteLength;
  if (size > APNS_PAYLOAD_MAX_BYTES) return `payload too large (${size} > ${APNS_PAYLOAD_MAX_BYTES})`;
  return null;
}

/**
 * The `apns-topic` for a Live Activity push — the app's own bundle id with
 * `.push-type.liveactivity` appended, per Apple. Derived rather than
 * env-configured so a wrong topic can't ship with the config.
 */
export function liveActivityTopic(baseTopic: string): string {
  return `${baseTopic}.push-type.liveactivity`;
}

export function validateSituation(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return "body must be a JSON object";
  const b = body as Record<string, unknown>;
  const bad = checkField(b, "apns-collapse-id");
  if (bad) return bad;
  // Strict cap on this route; see APNS_COLLAPSE_ID_MAX_BYTES for the reasoning.
  const collapseBytes = new TextEncoder().encode(b["apns-collapse-id"] as string).byteLength;
  if (collapseBytes > APNS_COLLAPSE_ID_MAX_BYTES) {
    return `apns-collapse-id too large (${collapseBytes} > ${APNS_COLLAPSE_ID_MAX_BYTES})`;
  }
  const routing = checkRouting(b);
  if (routing) return routing;
  if (typeof b.payload !== "object" || b.payload === null) {
    return "payload must be a JSON object";
  }
  const aps = (b.payload as Record<string, unknown>).aps;
  if (typeof aps !== "object" || aps === null) {
    return "payload.aps must be a JSON object";
  }
  // Size check on the serialized body — same limit APNs enforces itself, so
  // failing here means "will never work," not "might work depending on Apple."
  const size = new TextEncoder().encode(JSON.stringify(b.payload)).byteLength;
  if (size > APNS_PAYLOAD_MAX_BYTES) return `payload too large (${size} > ${APNS_PAYLOAD_MAX_BYTES})`;
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

/**
 * The test-push payload: a fixed literal alert, spelled out by the spec (§1).
 *
 * Three deliberate absences. No `handle` — there is nothing to redeem, so the
 * NSE passes this through unmodified and a tap just opens the app. No
 * `mutable-content` — with it set the NSE would run and find nothing to
 * enrich. No `thread-id`/collapse id — two presses of the button should show
 * two notifications; collapsing them would look like the second press failed.
 */
export function testPayload(): Record<string, unknown> {
  return {
    aps: {
      alert: { title: "Test notification", body: "Push notifications are working." },
      sound: "default",
    },
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
