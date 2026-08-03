// Cloudflare Worker entry: the one public endpoint every frigate-sidecar's
// RelayTransport posts to. Holds no state beyond a per-isolate rate limiter
// and the cached provider JWT — no database, no per-user records, by design.

import { apnsHost, apsPayload, makeJwtSigner, relayStatus, validate, type JwtSigner, type RelayRequest } from "./relay";

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/v1/relay/push") {
      return Response.json({ error: "not found" }, { status: 404 });
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return Response.json({ error: "invalid JSON" }, { status: 400 });
    }
    const invalid = validate(body);
    if (invalid) return Response.json({ error: invalid }, { status: 422 });
    const req = body as unknown as RelayRequest;

    if (rateLimited(req.device_token, Date.now())) {
      return Response.json({ error: "rate limited" }, { status: 429 });
    }

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
          "apns-collapse-id": req["apns-collapse-id"].slice(0, 64),
        },
        body: JSON.stringify(apsPayload(req)),
      },
    );

    const { status, detail } = relayStatus(apnsResponse.status, await apnsResponse.text());
    return Response.json({ detail }, { status });
  },
};
