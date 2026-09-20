# elsinore-push-relay

The one shared APNs relay for [Elsinore] sidecars. Every self-hosted
Marcellus (the Frigate sidecar) posts content-free push requests here; the relay signs the
Apple provider JWT with the app team's `.p8` key and forwards a fixed,
severity-keyed alert to APNs. It exists because APNs keys are team-bound —
only the team that owns `com.houseofpaimon.Elsinore` can push to it, so
users cannot bring their own key.

Privacy scope (see Elsinore's `sidecar-push-notifications-spec.md` §4): the
relay receives `{device_token, environment, handle, server_id, severity,
apns-collapse-id}` plus optional delivery hints (`apns_priority`,
`apns_expiration`) and nothing else. No camera names, labels, or imagery —
the iOS notification extension redeems `handle` against the *user's own*
sidecar after delivery. The relay keeps no database and no per-user records.

## Auth

Every route requires an `x-relay-key` header matching the `RELAY_KEY` Worker
secret; a missing or wrong key is `401`. Enforcement only kicks in once the
secret is set, so an in-place deploy doesn't lock out an older sidecar — but
the production worker has it set. The sidecar sends the same value from its
`push.relay_key` config.

## API

`POST /v1/relay/push` with the JSON body above.

`POST /v1/relay/situation` and `POST /v1/relay/liveactivity` carry the
card-pipeline payloads (situation-style alert body, Live Activity
start/update/end respectively) — same privacy scope, same auth, same
response mapping.

All payload routes accept optional `apns_priority` (1, 5, or 10 — 5 for
silent Live Activity updates, 10 for alerts) and `apns_expiration` (Unix
seconds), forwarded to APNs as `apns-priority` / `apns-expiration` headers.

`POST /v1/relay/test` with `{device_token, environment}` — and nothing else
in the body.
Backs the app's "Send test notification" button (spec §1, "Test push"): a
fixed alert (`"Test notification"` / `"Push notifications are working."`,
`sound: default`) with **no `handle`** and **no `mutable-content`**, since
there is nothing for the notification extension to redeem and a tap should
just open the app. It is a separate route because `/v1/relay/push` requires
`handle`, which a test push does not have.

Both routes share the same JWT, the same APNs host selection, the same
per-token rate limit and the same response mapping — a test send has to fail
exactly the way a real one would, or it proves nothing.

| Response | Meaning for the sidecar |
|---|---|
| `200` | Delivered to APNs. |
| `401` | Missing/wrong `x-relay-key` — fix `push.relay_key`, don't prune. |
| `400` / `410` | Dead device token (`BadDeviceToken` / `Unregistered`) — prune the registration. |
| `422` | Malformed request. |
| `429` | Per-token rate limit (60/hour). |
| `502` | APNs or relay trouble — log, don't prune, try again on the next event. |

**`environment` is `"production"` or `"sandbox"`.** Note it is not `"prod"`,
which is the spelling the sidecar's own `/v1/push/devices` API and database
use — the sidecar translates at its relay boundary. A body carrying `"prod"`
is rejected `422` by both routes.

## Deploy (Cloudflare Workers)

1. `npm install`
2. `npx wrangler login`
3. Create an APNs auth key at developer.apple.com → Certificates → Keys
   (enable the APNs capability; download `AuthKey_<KEYID>.p8` — one chance).
4. ```
   npx wrangler secret put APNS_AUTH_KEY   # paste the .p8 file contents
   npx wrangler secret put APNS_KEY_ID     # the 10-char key id
   npx wrangler secret put APNS_TEAM_ID    # the Apple Developer team id
   npx wrangler secret put RELAY_KEY       # shared secret, e.g. `openssl rand -hex 32`
   ```
5. `npx wrangler deploy` — note the printed `*.workers.dev` URL.
6. Point sidecars at it:
   ```yaml
   push:
     enabled: true
     transport: relay
     relay_base_url: https://<worker>.workers.dev
     relay_key: <same value as the RELAY_KEY secret>
   ```

`npm test` runs the unit suite (validation, payload template, JWT signing,
status mapping, rate limiter). `npm run typecheck` for types.
