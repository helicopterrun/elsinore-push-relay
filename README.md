# elsinore-push-relay

The one shared APNs relay for [Elsinore] sidecars. Every self-hosted
`frigate-sidecar` posts content-free push requests here; the relay signs the
Apple provider JWT with the app team's `.p8` key and forwards a fixed,
severity-keyed alert to APNs. It exists because APNs keys are team-bound —
only the team that owns `com.houseofpaimon.Elsinore` can push to it, so
users cannot bring their own key.

Privacy scope (see Elsinore's `sidecar-push-notifications-spec.md` §4): the
relay receives `{device_token, environment, handle, server_id, severity,
apns-collapse-id}` and nothing else. No camera names, labels, or imagery —
the iOS notification extension redeems `handle` against the *user's own*
sidecar after delivery. The relay keeps no database and no per-user records.

## API

`POST /v1/relay/push` with the JSON body above.

| Response | Meaning for the sidecar |
|---|---|
| `200` | Delivered to APNs. |
| `400` / `410` | Dead device token (`BadDeviceToken` / `Unregistered`) — prune the registration. |
| `422` | Malformed request. |
| `429` | Per-token rate limit (60/hour). |
| `502` | APNs or relay trouble — log, don't prune, try again on the next event. |

## Deploy (Cloudflare Workers)

1. `npm install`
2. `npx wrangler login`
3. Create an APNs auth key at developer.apple.com → Certificates → Keys
   (enable the APNs capability; download `AuthKey_<KEYID>.p8` — one chance).
4. ```
   npx wrangler secret put APNS_AUTH_KEY   # paste the .p8 file contents
   npx wrangler secret put APNS_KEY_ID     # the 10-char key id
   npx wrangler secret put APNS_TEAM_ID    # the Apple Developer team id
   ```
5. `npx wrangler deploy` — note the printed `*.workers.dev` URL.
6. Point sidecars at it:
   ```yaml
   push:
     enabled: true
     transport: relay
     relay_base_url: https://<worker>.workers.dev
   ```

`npm test` runs the unit suite (validation, payload template, JWT signing,
status mapping, rate limiter). `npm run typecheck` for types.
