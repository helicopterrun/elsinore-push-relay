// Best-effort, per-isolate sliding-window limiters. A determined abuser can
// exceed them across isolates, but they bound the cost of a misbehaving
// sidecar or client, which is the realistic failure. No storage bindings.

export const RATE_WINDOW_MS = 3_600_000;
/** Alert-shaped sends (`/push`, `/situation`, `/test`) per device token per hour. */
export const ALERT_SENDS_PER_TOKEN_PER_HOUR = 60;
/** Live Activity sends per token per hour. Updates run at a 15 s cadence
 * (240/hour); the old shared 60/hour limit froze a long-running activity. */
export const LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR = 300;
/** All sends, across every route, per install id for Bearer-authenticated requests. */
export const BEARER_SENDS_PER_IID_PER_HOUR = 1200;
/** Credential issuance attempts per client IP per hour. */
export const CREDENTIAL_ISSUES_PER_IP_PER_HOUR = 10;
/** Crude memory bound: a limiter map larger than this is cleared. */
export const RATE_LIMIT_MAX_KEYS = 10_000;

export type SendLog = Map<string, number[]>;

function recent(key: string, nowMs: number, sends: SendLog): number[] {
  const windowStart = nowMs - RATE_WINDOW_MS;
  const kept = (sends.get(key) ?? []).filter((t) => t > windowStart);
  sends.set(key, kept);
  return kept;
}

/** True when `key` has already used its `limit` for the window. Records nothing. */
export function atLimit(key: string, nowMs: number, sends: SendLog, limit: number): boolean {
  return recent(key, nowMs, sends).length >= limit;
}

/** Records one use of `key`. */
export function record(key: string, nowMs: number, sends: SendLog): void {
  recent(key, nowMs, sends).push(nowMs);
  if (sends.size > RATE_LIMIT_MAX_KEYS) sends.clear();
}

/** Check-and-record in one step: true (and nothing recorded) when over the limit. */
export function rateLimited(key: string, nowMs: number, sends: SendLog, limit: number): boolean {
  if (atLimit(key, nowMs, sends, limit)) return true;
  record(key, nowMs, sends);
  return false;
}
