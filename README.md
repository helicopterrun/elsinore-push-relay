# elsinore-push-relay

The one shared APNs relay for [Elsinore] sidecars. Every self-hosted
Marcellus (the Frigate sidecar) posts push requests here; the relay signs the
Apple provider JWT with the app team's `.p8` key and forwards them to APNs.
It exists because APNs keys are team-bound — only the team that owns
`com.houseofpaimon.Elsinore` can push to it, so users cannot bring their
own key.

Privacy scope depends on the route:

- `POST /v1/relay/push` receives `{device_token, environment, handle,
  server_id, severity, apns-collapse-id}` plus optional delivery hints
  (`apns_priority`, `apns_expiration`) and sends a fixed, severity-keyed
  alert. No camera names, labels or imagery pass through this route.
- `POST /v1/relay/situation` and `POST /v1/relay/liveactivity` forward the
  sidecar-built payload verbatim. That payload **does** carry the alert's
  title and body text (e.g. "Person at Front Door"), camera and zone names,
  subject kind, severity, timestamps and the card key, and the Live Activity
  routes add the content state (zone names, a motion label, normalized path
  points). These are the card-pipeline routes current sidecars use.

On every route, images never pass through the relay: payloads carry at most a
handle or URL on the *user's own* sidecar, which the app's notification
extension fetches after delivery. The relay keeps no database and no
per-user records. Elsinore's public privacy page
(`docs/site/src/privacy.md`) describes the same scope.

## Auth

Every send route (`/v1/relay/push`, `/test`, `/situation`, `/liveactivity`)
accepts either of two credentials:

- `Authorization: Bearer <credential>` — a **per-install credential** the
  Elsinore app obtained from this relay and handed to the user's Marcellus
  (see [Per-install credentials](#per-install-credentials)).
- `x-relay-key: <RELAY_KEY>` — the **legacy shared key**. It keeps working
  unchanged; the sidecar sends it from its `push.relay_key` config.

Either one suffices. A request carrying a valid `x-relay-key` is accepted even
if its Bearer credential is invalid (the legacy key wins). When neither is
valid the request is `401` as soon as `RELAY_KEY` **or**
`RELAY_CREDENTIAL_SECRET` is configured. Only when both are unset do the send
routes stay open, as they always have, so an in-place deploy doesn't lock out
an older sidecar — the production worker has `RELAY_KEY` set. (Failing closed
in that last case is a planned follow-up.)

## API

`POST /v1/relay/push` with the JSON body above.

`POST /v1/relay/situation` and `POST /v1/relay/liveactivity` carry the
card-pipeline payloads (situation-style alert body, Live Activity
start/update/end respectively) — the wider privacy scope described above,
same auth, same response mapping.

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
| `401` | Missing/invalid credential or `x-relay-key` (including an expired or revoked credential) — fix the credential or `push.relay_key`, don't prune. |
| `400` / `410` | Dead device token (`BadDeviceToken` / `Unregistered`) — prune the registration. |
| `422` | Malformed request. |
| `429` | Rate limit: 60/hour per token for push/situation/test, 300/hour per token for Live Activity, 1200/hour per install across all routes for credential-authenticated sends. |
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
   npx wrangler secret put RELAY_CREDENTIAL_SECRET   # optional: enables per-install credentials
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
status mapping, rate limiters, AppTransaction verification, credentials, and
the fetch handler itself). `npm run typecheck` for types. The test certificate
chains in `test/fixtures/chain/` are self-generated and regenerate with
`test/fixtures/gen-test-chain.sh`; they chain to a throwaway test root, never to
Apple's.

## Per-install credentials

Anyone can install Marcellus, but nobody outside the operator can be handed
the shared `RELAY_KEY`. Per-install credentials fix that: the Elsinore app
proves to the relay that it is a genuine copy obtained from the App Store,
receives a credential bound to that install, and passes it to the user's own
Marcellus, which sends it as `Authorization: Bearer <credential>`.

### How it works

1. The app reads its StoreKit 2 `AppTransaction` (`AppTransaction.shared`)
   and sends the App Store-signed JWS (`jwsRepresentation`) to
   `POST /v1/relay/credential`.
2. The relay verifies that JWS against Apple's certificate chain (below). On
   success it derives a stable install id (`iid`) and returns an
   HMAC-signed credential. Nothing is written anywhere.
3. Marcellus sends the credential on every push. The relay checks the HMAC,
   the expiry and the revocation list; no lookup, no storage.

### Wire contract

`POST /v1/relay/credential`

```json
{"app_transaction_jws": "<compact JWS>", "platform": "ios" | "macos", "app_version": "<string>"}
```

`200`:

```json
{"credential": "v1.<b64url(payload)>.<b64url(sig)>", "install_id": "<iid>", "expires_at": <unix seconds>, "refresh_after": <unix seconds>}
```

Errors are JSON `{"error": "<code>"}`:

| Status | `error` | Meaning |
|---|---|---|
| `400` | `bad_request` | Body is not the JSON above. |
| `403` | `verification_failed` | The app transaction did not verify. Deliberately one code for every reason. |
| `429` | `rate_limited` | More than 10 issuance attempts from this client IP in the last hour. |
| `503` | `credentials_disabled` | `RELAY_CREDENTIAL_SECRET` is not set on this relay. |

The credential is `v1.<payload>.<sig>`. `payload` is b64url of the UTF-8 JSON
`{"v":1,"kid":"<key id>","iid":"<install id>","bid":"<bundle id>","env":"<Production|Sandbox|…>","iat":<s>,"exp":<s>}`;
`sig` is b64url of HMAC-SHA256, under the secret named by `kid`, over the exact
b64url payload string. Credentials live 180 days (`exp = iat + 180 d`); clients
should fetch a fresh one after `refresh_after` (`iat + 30 d`). `env` is the
transaction's own environment value.

`iid` is b64url of the first 16 bytes of
SHA-256(`"elsinore-relay-iid:v1:" + <stable id>`) — keyless on purpose: the
iid is not a secret (it is returned to the client and sits in the credential
payload), and keeping it independent of the signing secret means a rotation
changes no iid. The stable id is the transaction's `appTransactionId` when present, otherwise
`bundleId`, `originalPurchaseDate` and `deviceVerification` together. The same
transaction always yields the same `iid`. Apple documents `appTransactionId` as
one value per Apple Account per app (per family member with Family Sharing),
so in practice an `iid` identifies an account's copy of the app rather than a
single device.

### What the relay checks in the AppTransaction

Mirroring Apple's own `SignedDataVerifier` from
[app-store-server-library-node](https://github.com/apple/app-store-server-library-node)
(`jws_verification.ts`), on WebCrypto with no runtime dependencies:

- the JWS header `alg` is exactly `ES256`, and `x5c` holds exactly three
  certificates (leaf, intermediate, root);
- the third certificate is byte-identical to **Apple Root CA - G3**, pinned in
  `src/appleRoot.ts` (SHA-256
  `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179`, as
  published by Apple), and the intermediate is signed by that pinned root;
- the leaf is signed by the intermediate, each certificate names the next as
  its issuer, and the intermediate is a CA;
- the leaf carries Apple's marker extension `1.2.840.113635.100.6.11.1` and
  the intermediate carries `1.2.840.113635.100.6.2.1` (Apple Worldwide
  Developer Relations);
- all three certificates are within their validity period (±60 s) at the
  transaction's signing date, `receiptCreationDate` — the effective date
  Apple's library uses with online checks off (it falls back to the current
  time when the field is absent, and so does this relay). A cached
  AppTransaction signed while its leaf was valid therefore keeps verifying
  after that leaf expires. A `receiptCreationDate` more than 60 s in the
  future is rejected;
- the JWS signature verifies with the leaf's key;
- the payload's `bundleId` is in `ALLOWED_BUNDLE_IDS`, and its environment
  (`receiptType`) is `Production` or `Sandbox` (TestFlight builds are
  Sandbox). `Xcode` and `LocalTesting` are refused unless
  `ALLOW_XCODE_ENV = "true"` — and even then the transaction must still chain
  to Apple's root; this relay never skips signature verification.

**Not checked:** OCSP / revocation status of Apple's certificates (Apple's
library does this only in its optional online mode). That is out of scope; a
revoked Apple signing certificate would still be accepted until it expires.

### Configuration

| Name | Kind | Purpose |
|---|---|---|
| `RELAY_CREDENTIAL_SECRET` | secret | Signs credentials and derives `iid`s. Unset = issuance `503`, Bearer not accepted. |
| `RELAY_CREDENTIAL_KID` | var | Key id stamped into new credentials. Default `k1`. |
| `RELAY_CREDENTIAL_SECRET_PREV` | secret | Previous secret, still accepted for verification during a rotation. |
| `RELAY_CREDENTIAL_KID_PREV` | var | Key id of the previous secret. |
| `REVOKED_IIDS` | var | Comma-separated `iid`s whose credentials get `401` (and which cannot be re-issued). |
| `ALLOWED_BUNDLE_IDS` | var | Comma-separated bundle ids allowed to obtain credentials. Defaults to `APNS_TOPIC`. |
| `ALLOW_XCODE_ENV` | var | `"true"` also accepts the Xcode / LocalTesting environments. Leave `"false"`. |

Vars live in `wrangler.toml` and take effect on the next deploy (a deploy
replaces vars set in the dashboard).

Turning credentials on:

```
openssl rand -base64 48 | tr -d '\n' | npx wrangler secret put RELAY_CREDENTIAL_SECRET
npx wrangler deploy
```

**Rotation.** Pick a new kid (say `k2`). Copy the current secret into
`RELAY_CREDENTIAL_SECRET_PREV`, set `RELAY_CREDENTIAL_KID_PREV = "k1"` and
`RELAY_CREDENTIAL_KID = "k2"`, put a fresh `RELAY_CREDENTIAL_SECRET`, and
deploy. Old credentials keep verifying under `k1`; clients pick up `k2`
credentials at their next refresh. Once the old ones have expired (180 days)
or been refreshed, remove the `_PREV` pair. A rotation does not change any
install's `iid` (it does not depend on the secret), so `REVOKED_IIDS` entries
stay valid across it.

**Revocation.** Add the `iid` (the `install_id` from issuance, also visible in
the credential's payload) to `REVOKED_IIDS` and deploy. Its credentials get
`401`, and issuance to that install is refused.

### What the relay learns at issuance

The client IP (used only as an in-memory rate-limit key), the `platform` and
`app_version` the app reports (validated, then ignored), and the Apple-signed
app transaction: bundle id, app version, original purchase date and version,
environment, app transaction id and the opaque device-verification value. The
relay uses them to verify the request and derive the `iid`, then forgets them:
nothing is stored or logged. The issued credential itself carries only the
`iid`, bundle id and environment.

### Limits

Per isolate, in memory, best-effort (no storage bindings):

| Limit | Budget |
|---|---|
| Push / situation / test, per device token | 60 per hour |
| Live Activity, per device token | 300 per hour (updates run every 15 s = 240/hour) |
| All send routes, per `iid`, Bearer-authenticated only | 1200 per hour |
| Credential issuance, per client IP (`CF-Connecting-IP`) | 10 per hour, failed attempts included |

The legacy shared key keeps working exactly as before and is not subject to
the per-`iid` budget.

An AppTransaction JWS is a long-lived proof that the app was obtained from the
App Store, not a fresh one: its holder can replay it to get new credentials for
the same `iid` indefinitely, since certificate validity is judged at its
signing date. Replay
gains nothing beyond that install's own identity; the per-`iid` budget and
revocation bound what one install can do.
