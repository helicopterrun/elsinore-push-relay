// Cloudflare Worker entry: the one public endpoint every Marcellus's (frigate-sidecar's)
// RelayTransport posts to. Holds no state beyond per-isolate rate limiters
// and the cached provider JWT — no database, no per-user records, by design.

import { verifyAppTransaction, MAX_JWS_LENGTH, type AppTransactionPolicy } from "./appTransaction";
import {
  credentialKeys,
  csvSet,
  deriveInstallId,
  issueCredential,
  stableInstallIdentifier,
  verifyCredential,
} from "./credential";
import {
  ALERT_SENDS_PER_TOKEN_PER_HOUR,
  BEARER_SENDS_PER_IID_PER_HOUR,
  CREDENTIAL_ISSUES_PER_IP_PER_HOUR,
  LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR,
  atLimit,
  rateLimited as limited,
  record,
  type SendLog,
} from "./rateLimit";
import {
  apnsHost,
  apsPayload,
  hintHeaders,
  liveActivityTopic,
  makeJwtSigner,
  relayStatus,
  testPayload,
  validate,
  validateLiveActivity,
  validateSituation,
  validateTest,
  type JwtSigner,
  type LiveActivityRelayRequest,
  type RelayRequest,
  type SituationRelayRequest,
  type TestRequest,
} from "./relay";

export interface Env {
  /** Contents of the AuthKey_XXXXXXXXXX.p8 file (with or without PEM armor). */
  APNS_AUTH_KEY: string;
  APNS_KEY_ID: string;
  APNS_TEAM_ID: string;
  /** The app's bundle id — the APNs topic. */
  APNS_TOPIC: string;
  /** Legacy shared secret accepted in `x-relay-key`. Optional: when neither it
   * nor RELAY_CREDENTIAL_SECRET is set, send routes stay open (pre-auth
   * deployments); once either is set, unauthenticated sends get 401. */
  RELAY_KEY?: string;
  /** HMAC secret for per-install credentials. Unset = issuance returns 503
   * and Bearer credentials are not accepted. */
  RELAY_CREDENTIAL_SECRET?: string;
  /** Key id stamped into new credentials (default "k1"). */
  RELAY_CREDENTIAL_KID?: string;
  /** Previous secret + kid, still accepted for verification during rotation. */
  RELAY_CREDENTIAL_SECRET_PREV?: string;
  RELAY_CREDENTIAL_KID_PREV?: string;
  /** Comma-separated install ids whose credentials are refused (401). */
  REVOKED_IIDS?: string;
  /** Comma-separated bundle ids allowed to obtain credentials (default: APNS_TOPIC). */
  ALLOWED_BUNDLE_IDS?: string;
  /** "true" also accepts Xcode / LocalTesting app transactions (still Apple-root-verified). */
  ALLOW_XCODE_ENV?: string;
}

/** Constant-time-ish string compare; avoids an early-exit length oracle. */
export function keyMatches(expected: string, provided: string | null): boolean {
  if (provided === null) return false;
  const a = new TextEncoder().encode(expected);
  const b = new TextEncoder().encode(provided);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    diff |= (a[i % a.length] ?? 0) ^ (b[i % b.length] ?? 0);
  }
  return diff === 0;
}

const defaultSends: SendLog = new Map();

/** Per-device-token limiter for alert-shaped sends (60 per rolling hour). */
export function rateLimited(token: string, nowMs: number, sends: SendLog = defaultSends): boolean {
  return limited(token, nowMs, sends, ALERT_SENDS_PER_TOKEN_PER_HOUR);
}

/** Largest credential-request body accepted; a real one is a few KB. */
export const MAX_CREDENTIAL_REQUEST_BYTES = MAX_JWS_LENGTH + 1024;

export interface WorkerOptions {
  /** TEST ONLY: trust anchor for AppTransaction chains. The deployed Worker
   * (the default export) never sets it, so production always uses the pinned
   * Apple Root CA - G3. */
  trustedRoot?: Uint8Array;
  /** Clock override for tests (epoch ms). */
  now?: () => number;
  /** Outbound fetch override for tests (the APNs call). */
  fetch?: typeof fetch;
}

function bundlePolicy(env: Env): AppTransactionPolicy {
  const allowed = csvSet(env.ALLOWED_BUNDLE_IDS);
  return {
    allowedBundleIds: allowed.size > 0 ? allowed : new Set([env.APNS_TOPIC]),
    allowXcodeEnv: env.ALLOW_XCODE_ENV === "true",
  };
}

function isBadCredentialRequest(body: unknown): boolean {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return true;
  const b = body as Record<string, unknown>;
  const jws = b.app_transaction_jws;
  if (typeof jws !== "string" || jws.length === 0 || jws.length > MAX_JWS_LENGTH) return true;
  if (b.platform !== "ios" && b.platform !== "macos") return true;
  const v = b.app_version;
  return typeof v !== "string" || v.length === 0 || v.length > 64;
}

export function makeWorker(options: WorkerOptions = {}) {
  const now = options.now ?? Date.now;
  const outbound = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  // Per-isolate state (module scope in the deployed Worker).
  let signer: JwtSigner | null = null;
  const alertSends: SendLog = new Map();
  const liveActivitySends: SendLog = new Map();
  const iidSends: SendLog = new Map();
  const issueAttempts: SendLog = new Map();

  /**
   * Sign, forward to Apple, and map the reply. Shared by every send route so
   * the test push goes to the same host, with the same JWT and the same status
   * mapping as a real one — the point of the button is that a black-holed
   * token fails here exactly as it would in production.
   */
  async function forward(
    env: Env,
    req: { device_token: string; environment: TestRequest["environment"] },
    payload: Record<string, unknown>,
    extraHeaders: Record<string, string> = {},
  ): Promise<Response> {
    let jwt: string;
    try {
      signer ??= makeJwtSigner(env.APNS_AUTH_KEY, env.APNS_KEY_ID, env.APNS_TEAM_ID);
      jwt = await signer.token();
    } catch {
      // A malformed .p8 secret shouldn't surface as a bare Worker 500.
      return Response.json({ detail: "relay misconfigured: cannot sign provider JWT" }, { status: 502 });
    }

    // `extraHeaders` is spread last so a route that needs different `apns-topic`
    // or `apns-push-type` (the Live Activity route sends
    // `liveactivity` + `.push-type.liveactivity` topic) can override the
    // per-request defaults established for the historical `alert` shape.
    let apnsResponse: Response;
    try {
      apnsResponse = await outbound(`https://${apnsHost(req.environment)}/3/device/${req.device_token}`, {
        method: "POST",
        headers: {
          authorization: `bearer ${jwt}`,
          "apns-topic": env.APNS_TOPIC,
          "apns-push-type": "alert",
          "apns-priority": "10",
          ...extraHeaders,
        },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      return Response.json({ detail: `apns connection failed: ${String(e).slice(0, 200)}` }, { status: 502 });
    }

    const { status, detail } = relayStatus(apnsResponse.status, await apnsResponse.text());
    return Response.json({ detail }, { status });
  }

  /**
   * POST /v1/relay/credential — trade an Apple-signed AppTransaction for a
   * per-install credential. Nothing is stored; the client IP is used only as
   * an in-memory rate-limit key.
   */
  async function issue(request: Request, env: Env): Promise<Response> {
    const keys = credentialKeys(env);
    if (!keys) return Response.json({ error: "credentials_disabled" }, { status: 503 });

    const nowMs = now();
    const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
    if (limited(ip, nowMs, issueAttempts, CREDENTIAL_ISSUES_PER_IP_PER_HOUR)) {
      return Response.json({ error: "rate_limited" }, { status: 429 });
    }

    let body: unknown;
    try {
      const text = await request.text();
      if (text.length > MAX_CREDENTIAL_REQUEST_BYTES) throw new Error("too large");
      body = JSON.parse(text);
    } catch {
      return Response.json({ error: "bad_request" }, { status: 400 });
    }
    if (isBadCredentialRequest(body)) return Response.json({ error: "bad_request" }, { status: 400 });
    const jws = (body as { app_transaction_jws: string }).app_transaction_jws;

    const denied = () => Response.json({ error: "verification_failed" }, { status: 403 });
    let tx;
    try {
      tx = await verifyAppTransaction(jws, bundlePolicy(env), options.trustedRoot, nowMs);
    } catch {
      // Deliberately one answer for every failure: which check failed is not
      // the client's business.
      return denied();
    }
    const stable = stableInstallIdentifier(tx);
    if (stable === null) return denied();
    const iid = await deriveInstallId(stable);
    if (csvSet(env.REVOKED_IIDS).has(iid)) return denied();

    const issued = await issueCredential(
      keys,
      { iid, bid: tx.bundleId, env: tx.receiptType },
      Math.floor(nowMs / 1000),
    );
    return Response.json(issued, { status: 200 });
  }

  /**
   * Send-route auth. Accepts a valid `Authorization: Bearer <credential>` or
   * the legacy `x-relay-key`; either suffices, and a valid legacy key wins
   * over a bad Bearer. Returns the install id for Bearer-authenticated
   * requests (null otherwise), or a 401 response.
   */
  async function authenticate(request: Request, env: Env): Promise<{ iid: string | null } | Response> {
    const keys = credentialKeys(env);
    let iid: string | null = null;
    const authz = request.headers.get("authorization");
    if (keys && authz) {
      const m = /^Bearer[ \t]+(\S+)[ \t]*$/i.exec(authz);
      if (m) {
        const check = await verifyCredential(m[1], keys, Math.floor(now() / 1000), csvSet(env.REVOKED_IIDS));
        if (check.ok) iid = check.claims.iid;
      }
    }
    const legacyOk = !!env.RELAY_KEY && keyMatches(env.RELAY_KEY, request.headers.get("x-relay-key"));
    if (legacyOk || iid !== null) return { iid };
    // Follow-up ("fail closed"): with neither RELAY_KEY nor
    // RELAY_CREDENTIAL_SECRET configured the relay stays open, as it always
    // has. It should refuse instead once every deployment has a secret.
    if (env.RELAY_KEY || keys) return Response.json({ error: "unauthorized" }, { status: 401 });
    return { iid: null };
  }

  return {
    async fetch(request: Request, env: Env): Promise<Response> {
      const url = new URL(request.url);
      if (url.pathname === "/v1/relay/credential" && request.method === "POST") {
        return issue(request, env);
      }

      const isPush = url.pathname === "/v1/relay/push";
      const isTest = url.pathname === "/v1/relay/test";
      const isSituation = url.pathname === "/v1/relay/situation";
      const isLiveActivity = url.pathname === "/v1/relay/liveactivity";
      if (request.method !== "POST" || (!isPush && !isTest && !isSituation && !isLiveActivity)) {
        return Response.json({ error: "not found" }, { status: 404 });
      }

      const auth = await authenticate(request, env);
      if (auth instanceof Response) return auth;

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: "invalid JSON" }, { status: 400 });
      }

      const invalid = isTest
        ? validateTest(body)
        : isSituation
        ? validateSituation(body)
        : isLiveActivity
        ? validateLiveActivity(body)
        : validate(body);
      if (invalid) return Response.json({ error: invalid }, { status: 422 });

      // Per-token limits: Live Activity updates get their own, larger budget
      // (15 s cadence); push/situation/test share the alert budget — the test
      // button is hand-driven and should never come near it, and exempting it
      // would leave an unmetered path to Apple. Bearer-authenticated requests
      // also draw on a per-install budget across all routes. Nothing is
      // recorded unless every applicable limit has room.
      const nowMs = now();
      const token = (body as { device_token: string }).device_token;
      const tokenLog = isLiveActivity ? liveActivitySends : alertSends;
      const tokenLimit = isLiveActivity ? LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR : ALERT_SENDS_PER_TOKEN_PER_HOUR;
      if (
        atLimit(token, nowMs, tokenLog, tokenLimit) ||
        (auth.iid !== null && atLimit(auth.iid, nowMs, iidSends, BEARER_SENDS_PER_IID_PER_HOUR))
      ) {
        return Response.json({ error: "rate limited" }, { status: 429 });
      }
      record(token, nowMs, tokenLog);
      if (auth.iid !== null) record(auth.iid, nowMs, iidSends);

      if (isTest) {
        return forward(env, body as unknown as TestRequest, testPayload());
      }
      if (isSituation) {
        const req = body as unknown as SituationRelayRequest;
        // The sidecar has already assembled `payload` — including interruption
        // level, sound, thread-id, category, and the situation-shaped extras.
        // The relay contributes only routing and the collapse-id header.
        //
        // Deliberately no `.slice(0, 64)` here: `validateSituation` rejects
        // oversized collapse-ids up front, because truncating a composite
        // `<situation-id>:<track-id>` would silently collapse distinct tracks
        // into one notification. See APNS_COLLAPSE_ID_MAX_BYTES.
        return forward(env, req, req.payload, {
          "apns-collapse-id": req["apns-collapse-id"],
          ...hintHeaders(req),
        });
      }
      if (isLiveActivity) {
        const req = body as unknown as LiveActivityRelayRequest;
        // LA push shape overrides two headers vs the alert path: the topic gains
        // the `.push-type.liveactivity` suffix (Apple contract) and the push
        // type flips from `alert` to `liveactivity`. The sidecar sets
        // `apns_priority: 5` on silent updates (Apple's LA update budget) and
        // 10 on alerting ones; absent hints keep the historical priority 10.
        return forward(env, req, req.payload, {
          "apns-topic": liveActivityTopic(env.APNS_TOPIC),
          "apns-push-type": "liveactivity",
          "apns-collapse-id": req["apns-collapse-id"],
          ...hintHeaders(req),
        });
      }
      const req = body as unknown as RelayRequest;
      return forward(env, req, apsPayload(req), {
        "apns-collapse-id": req["apns-collapse-id"].slice(0, 64),
        ...hintHeaders(req),
      });
    },
  };
}

export default makeWorker();
