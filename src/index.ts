// Cloudflare Worker entry: the one public endpoint every frigate-sidecar's
// RelayTransport posts to. Holds no state beyond a per-isolate rate limiter
// and the cached provider JWT — no database, no per-user records, by design.

import {
  apnsHost,
  apsPayload,
  makeJwtSigner,
  relayStatus,
  testPayload,
  validate,
  validateSituation,
  validateTest,
  type JwtSigner,
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
}

// Module-scope caches survive across requests within an isolate.
let signer: JwtSigner | null = null;
const recentSends = new Map<string, number[]>();

/** Per-device-token limiter: 60 pushes per rolling hour. Per-isolate only —
 * a determined abuser can exceed it across isolates, but it bounds the cost
 * of a misbehaving sidecar, which is the realistic failure. */
export function rateLimited(token: string, nowMs: number, sends: Map<string, number[]> = recentSends): boolean {
  const hourAgo = nowMs - 3_600_000;
  const kept = (sends.get(token) ?? []).filter((t) => t > hourAgo);
  if (kept.length >= 60) {
    sends.set(token, kept);
    return true;
  }
  kept.push(nowMs);
  sends.set(token, kept);
  if (sends.size > 10_000) sends.clear(); // crude memory bound; limiter is best-effort
  return false;
}

/**
 * Sign, forward to Apple, and map the reply. Shared by both routes so the test
 * push goes to the same host, with the same JWT and the same status mapping as
 * a real one — the point of the button is that a black-holed token fails here
 * exactly as it would in production.
 */
async function forward(
  env: Env,
  req: { device_token: string; environment: TestRequest["environment"] },
  payload: Record<string, unknown>,
  extraHeaders: Record<string, string> = {},
): Promise<Response> {
  signer ??= makeJwtSigner(env.APNS_AUTH_KEY, env.APNS_KEY_ID, env.APNS_TEAM_ID);
  const jwt = await signer.token();

  const apnsResponse = await fetch(
    `https://${apnsHost(req.environment)}/3/device/${req.device_token}`,
    {
      method: "POST",
      headers: {
        authorization: `bearer ${jwt}`,
        "apns-topic": env.APNS_TOPIC,
        "apns-push-type": "alert",
        "apns-priority": "10",
        ...extraHeaders,
      },
      body: JSON.stringify(payload),
    },
  );

  const { status, detail } = relayStatus(apnsResponse.status, await apnsResponse.text());
  return Response.json({ detail }, { status });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const isPush = url.pathname === "/v1/relay/push";
    const isTest = url.pathname === "/v1/relay/test";
    const isSituation = url.pathname === "/v1/relay/situation";
    if (request.method !== "POST" || (!isPush && !isTest && !isSituation)) {
      return Response.json({ error: "not found" }, { status: 404 });
    }

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
      : validate(body);
    if (invalid) return Response.json({ error: invalid }, { status: 422 });

    // Rate limited on the same per-token budget as real pushes: the button is
    // hand-driven, so it should never come near 60/hour, and exempting it
    // would leave an unmetered path to Apple.
    const token = (body as { device_token: string }).device_token;
    if (rateLimited(token, Date.now())) {
      return Response.json({ error: "rate limited" }, { status: 429 });
    }

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
      });
    }
    const req = body as unknown as RelayRequest;
    return forward(env, req, apsPayload(req), {
      "apns-collapse-id": req["apns-collapse-id"].slice(0, 64),
    });
  },
};
