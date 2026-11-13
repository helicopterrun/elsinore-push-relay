// Tests of the Worker's fetch handler itself: routing, issuance, the send-route
// auth matrix and the rate limits. APNs is stubbed; AppTransactions are signed
// with the self-generated test chain (test/fixtures/chain).

import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import worker, { makeWorker, type Env } from "../src/index";
import { issueCredential } from "../src/credential";
import {
  ALERT_SENDS_PER_TOKEN_PER_HOUR,
  BEARER_SENDS_PER_IID_PER_HOUR,
  CREDENTIAL_ISSUES_PER_IP_PER_HOUR,
  LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR,
} from "../src/rateLimit";
import { BUNDLE_ID, NOW_MS, TEST_ROOT, signJws, txPayload } from "./helpers";

const BASE = "https://relay.example";
const RELAY_KEY = "legacy-shared-key";
const SECRET = "credential-secret";

let p8 = "";
beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  p8 = Buffer.from((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).toString("base64");
});

function env(overrides: Partial<Env> = {}): Env {
  return {
    APNS_AUTH_KEY: p8,
    APNS_KEY_ID: "KEYID12345",
    APNS_TEAM_ID: "TEAMID1234",
    APNS_TOPIC: BUNDLE_ID,
    ALLOWED_BUNDLE_IDS: BUNDLE_ID,
    ...overrides,
  };
}

const CONFIGS = {
  neither: {},
  keyOnly: { RELAY_KEY },
  secretOnly: { RELAY_CREDENTIAL_SECRET: SECRET },
  both: { RELAY_KEY, RELAY_CREDENTIAL_SECRET: SECRET },
} satisfies Record<string, Partial<Env>>;

let clock = NOW_MS;
let apnsCalls: { url: string; headers: Record<string, string> }[] = [];
let app: ReturnType<typeof makeWorker>;

beforeEach(() => {
  clock = NOW_MS;
  apnsCalls = [];
  app = makeWorker({
    trustedRoot: TEST_ROOT,
    now: () => clock,
    fetch: async (input, init) => {
      apnsCalls.push({ url: String(input), headers: init?.headers as Record<string, string> });
      return new Response("", { status: 200 });
    },
  });
});

function token(i = 0): string {
  return i.toString(16).padStart(64, "0");
}

function post(path: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function credentialRequest(jws: string, ip = "198.51.100.7", extra: Record<string, unknown> = {}): Request {
  return post(
    "/v1/relay/credential",
    { app_transaction_jws: jws, platform: "ios", app_version: "1.2 (512)", ...extra },
    { "cf-connecting-ip": ip },
  );
}

async function bearer(iid = "test-install", nowS = Math.floor(NOW_MS / 1000), secret = SECRET): Promise<string> {
  const { credential } = await issueCredential(
    { current: { kid: "k1", secret } },
    { iid, bid: BUNDLE_ID, env: "Production" },
    nowS,
  );
  return `Bearer ${credential}`;
}

const testSend = (i = 0) => ({ device_token: token(i), environment: "production" });
const laSend = (i = 0) => ({
  device_token: token(i),
  environment: "production",
  "apns-collapse-id": "la-1",
  event: "update",
  payload: { aps: { event: "update", "content-state": {}, timestamp: 1 } },
  apns_priority: 5,
});

describe("routing", () => {
  it("404s unknown paths and non-POST methods", async () => {
    expect((await app.fetch(new Request(`${BASE}/`), env())).status).toBe(404);
    expect((await app.fetch(new Request(`${BASE}/v1/relay/credential`), env(CONFIGS.both))).status).toBe(404);
    expect((await app.fetch(post("/v1/relay/nope", {}), env())).status).toBe(404);
  });
});

describe("POST /v1/relay/credential", () => {
  it("503 credentials_disabled when the secret is unset", async () => {
    const res = await app.fetch(credentialRequest(await signJws(txPayload())), env(CONFIGS.keyOnly));
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "credentials_disabled" });
  });

  it("issues a credential for a valid app transaction", async () => {
    const res = await app.fetch(credentialRequest(await signJws(txPayload())), env(CONFIGS.secretOnly));
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const nowS = Math.floor(NOW_MS / 1000);
    expect(Object.keys(body).sort()).toEqual(["credential", "expires_at", "install_id", "refresh_after"]);
    expect(body.credential).toMatch(/^v1\./);
    expect(body.install_id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(body.expires_at).toBe(nowS + 180 * 86400);
    expect(body.refresh_after).toBe(nowS + 30 * 86400);
  });

  it("gives the same transaction the same iid, and different ones different iids", async () => {
    const e = env(CONFIGS.secretOnly);
    const iid = async (o: Record<string, unknown>) =>
      ((await (await app.fetch(credentialRequest(await signJws(txPayload(o))), e)).json()) as { install_id: string })
        .install_id;
    const a = await iid({});
    expect(await iid({ receiptCreationDate: NOW_MS - 5000 })).toBe(a); // re-signed, same appTransactionId
    expect(await iid({ appTransactionId: "999" })).not.toBe(a);
    // Fallback identity when appTransactionId is absent is just as stable.
    const f = await iid({ appTransactionId: undefined });
    expect(await iid({ appTransactionId: undefined })).toBe(f);
    expect(f).not.toBe(a);
  });

  it("keeps the same iid across a secret rotation", async () => {
    const jws = await signJws(txPayload());
    const iidUnder = async (e: Env, ip: string) =>
      ((await (await app.fetch(credentialRequest(jws, ip), e)).json()) as { install_id: string }).install_id;
    const before = await iidUnder(env(CONFIGS.secretOnly), "198.51.100.20");
    const after = await iidUnder(
      env({
        RELAY_CREDENTIAL_SECRET: "rotated-secret",
        RELAY_CREDENTIAL_KID: "k2",
        RELAY_CREDENTIAL_SECRET_PREV: SECRET,
        RELAY_CREDENTIAL_KID_PREV: "k1",
      }),
      "198.51.100.21",
    );
    expect(after).toBe(before);
  });

  it("the issued credential authenticates a send", async () => {
    const e = env(CONFIGS.secretOnly);
    const issued = (await (await app.fetch(credentialRequest(await signJws(txPayload())), e)).json()) as {
      credential: string;
    };
    const res = await app.fetch(post("/v1/relay/test", testSend(), { authorization: `Bearer ${issued.credential}` }), e);
    expect(res.status).toBe(200);
  });

  it("400 bad_request for malformed bodies", async () => {
    const e = env(CONFIGS.secretOnly);
    const jws = await signJws(txPayload());
    const bodies: unknown[] = [
      "not json",
      [],
      {},
      { app_transaction_jws: jws, platform: "android", app_version: "1" },
      { app_transaction_jws: jws, platform: "ios" },
      { app_transaction_jws: "", platform: "ios", app_version: "1" },
      { app_transaction_jws: jws, platform: "macos", app_version: "x".repeat(65) },
    ];
    for (const b of bodies) {
      const res = await app.fetch(post("/v1/relay/credential", b), e);
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: "bad_request" });
    }
  });

  it("403 verification_failed, with no detail, for every verification failure", async () => {
    const e = env(CONFIGS.secretOnly);
    const failures = [
      await signJws(txPayload({ bundleId: "com.example.Other" })),
      await signJws(txPayload({ receiptType: "Xcode" })),
      await signJws(txPayload(), { chain: ["rogue-leaf", "rogue-intermediate", "rogue-root"] }),
      await signJws(txPayload({ appTransactionId: undefined, deviceVerification: undefined })),
      "a.b.c",
    ];
    for (const jws of failures) {
      const res = await app.fetch(credentialRequest(jws, `203.0.113.${failures.indexOf(jws)}`), e);
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({ error: "verification_failed" });
    }
  });

  it("ALLOW_XCODE_ENV=true accepts the Xcode environment", async () => {
    const jws = await signJws(txPayload({ receiptType: "Xcode" }));
    const res = await app.fetch(credentialRequest(jws), env({ ...CONFIGS.secretOnly, ALLOW_XCODE_ENV: "true" }));
    expect(res.status).toBe(200);
  });

  it("refuses to issue to a revoked install id", async () => {
    const e = env(CONFIGS.secretOnly);
    const { install_id } = (await (await app.fetch(credentialRequest(await signJws(txPayload())), e)).json()) as {
      install_id: string;
    };
    const res = await app.fetch(
      credentialRequest(await signJws(txPayload()), "198.51.100.8"),
      env({ ...CONFIGS.secretOnly, REVOKED_IIDS: `other, ${install_id}` }),
    );
    expect(res.status).toBe(403);
  });

  it("the deployed worker verifies against the pinned Apple root, not a test root", async () => {
    const res = await worker.fetch(credentialRequest(await signJws(txPayload()), "192.0.2.99"), env(CONFIGS.secretOnly));
    expect(res.status).toBe(403);
  });

  it(`limits issuance to ${CREDENTIAL_ISSUES_PER_IP_PER_HOUR} attempts per client IP per hour`, async () => {
    const e = env(CONFIGS.secretOnly);
    const jws = await signJws(txPayload());
    for (let i = 0; i < CREDENTIAL_ISSUES_PER_IP_PER_HOUR; i++) {
      expect((await app.fetch(credentialRequest(jws, "198.51.100.1"), e)).status).toBe(200);
    }
    const limited = await app.fetch(credentialRequest(jws, "198.51.100.1"), e);
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ error: "rate_limited" });
    // Failed attempts count too, so the limit also caps verification work.
    expect((await app.fetch(credentialRequest("a.b.c", "198.51.100.1"), e)).status).toBe(429);
    expect((await app.fetch(credentialRequest(jws, "198.51.100.2"), e)).status).toBe(200);
    clock += 3_600_001;
    expect((await app.fetch(credentialRequest(jws, "198.51.100.1"), e)).status).toBe(200);
  });
});

describe("send-route auth", () => {
  type Case = { name: string; headers: () => Promise<Record<string, string>> };
  const cases: Case[] = [
    { name: "bearer only", headers: async () => ({ authorization: await bearer() }) },
    { name: "key only", headers: async () => ({ "x-relay-key": RELAY_KEY }) },
    { name: "both", headers: async () => ({ authorization: await bearer(), "x-relay-key": RELAY_KEY }) },
    { name: "neither", headers: async () => ({}) },
    {
      name: "invalid bearer + valid key",
      headers: async () => ({ authorization: await bearer("x", undefined, "wrong-secret"), "x-relay-key": RELAY_KEY }),
    },
    { name: "valid bearer + wrong key", headers: async () => ({ authorization: await bearer(), "x-relay-key": "nope" }) },
    { name: "wrong key", headers: async () => ({ "x-relay-key": "nope" }) },
    { name: "garbage bearer", headers: async () => ({ authorization: "Bearer v1.garbage" }) },
    { name: "non-Bearer scheme", headers: async () => ({ authorization: (await bearer()).replace("Bearer", "Basic") }) },
  ];
  const expected: Record<keyof typeof CONFIGS, Record<string, number>> = {
    neither: Object.fromEntries(cases.map((c) => [c.name, 200])),
    keyOnly: {
      "bearer only": 401,
      "key only": 200,
      both: 200,
      neither: 401,
      "invalid bearer + valid key": 200,
      "valid bearer + wrong key": 401,
      "wrong key": 401,
      "garbage bearer": 401,
      "non-Bearer scheme": 401,
    },
    secretOnly: {
      "bearer only": 200,
      "key only": 401,
      both: 200,
      neither: 401,
      "invalid bearer + valid key": 401,
      "valid bearer + wrong key": 200,
      "wrong key": 401,
      "garbage bearer": 401,
      "non-Bearer scheme": 401,
    },
    both: {
      "bearer only": 200,
      "key only": 200,
      both: 200,
      neither: 401,
      "invalid bearer + valid key": 200,
      "valid bearer + wrong key": 200,
      "wrong key": 401,
      "garbage bearer": 401,
      "non-Bearer scheme": 401,
    },
  };

  for (const [config, overrides] of Object.entries(CONFIGS) as [keyof typeof CONFIGS, Partial<Env>][]) {
    for (const c of cases) {
      it(`${config}: ${c.name} → ${expected[config][c.name]}`, async () => {
        const res = await app.fetch(post("/v1/relay/test", testSend(), await c.headers()), env(overrides));
        expect(res.status).toBe(expected[config][c.name]);
        if (res.status === 401) expect(await res.json()).toEqual({ error: "unauthorized" });
      });
    }
  }

  it("applies to every send route", async () => {
    for (const path of ["/v1/relay/push", "/v1/relay/test", "/v1/relay/situation", "/v1/relay/liveactivity"]) {
      expect((await app.fetch(post(path, {}), env(CONFIGS.secretOnly))).status).toBe(401);
    }
  });

  it("401s a revoked or expired credential", async () => {
    const revoked = env({ ...CONFIGS.secretOnly, REVOKED_IIDS: "test-install" });
    expect((await app.fetch(post("/v1/relay/test", testSend(), { authorization: await bearer() }), revoked)).status).toBe(401);
    const old = await bearer("test-install", Math.floor(NOW_MS / 1000) - 181 * 86400);
    expect((await app.fetch(post("/v1/relay/test", testSend(), { authorization: old }), env(CONFIGS.secretOnly))).status).toBe(401);
  });

  it("accepts credentials signed with the previous key during rotation", async () => {
    const e = env({
      RELAY_CREDENTIAL_SECRET: "new-secret",
      RELAY_CREDENTIAL_KID: "k2",
      RELAY_CREDENTIAL_SECRET_PREV: SECRET,
      RELAY_CREDENTIAL_KID_PREV: "k1",
    });
    expect((await app.fetch(post("/v1/relay/test", testSend(), { authorization: await bearer() }), e)).status).toBe(200);
  });
});

describe("send-route rate limits", () => {
  const keyAuth = { "x-relay-key": RELAY_KEY };

  it("Live Activity sends have their own, larger per-token budget than alerts", async () => {
    const e = env(CONFIGS.keyOnly);
    expect(ALERT_SENDS_PER_TOKEN_PER_HOUR).toBe(60);
    expect(LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR).toBe(300);
    for (let i = 0; i < ALERT_SENDS_PER_TOKEN_PER_HOUR; i++) {
      expect((await app.fetch(post("/v1/relay/test", testSend(), keyAuth), e)).status).toBe(200);
    }
    expect((await app.fetch(post("/v1/relay/test", testSend(), keyAuth), e)).status).toBe(429);
    // The same token's Live Activity budget is untouched by the alert sends…
    for (let i = 0; i < LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR; i++) {
      expect((await app.fetch(post("/v1/relay/liveactivity", laSend(), keyAuth), e)).status).toBe(200);
    }
    // …and runs out at its own limit.
    const res = await app.fetch(post("/v1/relay/liveactivity", laSend(), keyAuth), e);
    expect(res.status).toBe(429);
    expect(await res.json()).toEqual({ error: "rate limited" });
    // A 15 s cadence for a full hour (240 updates) fits.
    expect(3600 / 15).toBeLessThanOrEqual(LIVE_ACTIVITY_SENDS_PER_TOKEN_PER_HOUR);
  });

  it("push, situation and test share the alert budget", async () => {
    const e = env(CONFIGS.keyOnly);
    const push = { ...testSend(), handle: "h", server_id: "s", severity: "alert", "apns-collapse-id": "c" };
    const situation = { ...testSend(), "apns-collapse-id": "c", payload: { aps: {} } };
    for (let i = 0; i < ALERT_SENDS_PER_TOKEN_PER_HOUR; i++) {
      const [path, body] = [["/v1/relay/push", push], ["/v1/relay/situation", situation], ["/v1/relay/test", testSend()]][i % 3];
      expect((await app.fetch(post(path as string, body, keyAuth), e)).status).toBe(200);
    }
    expect((await app.fetch(post("/v1/relay/push", push, keyAuth), e)).status).toBe(429);
  });

  it(`Bearer sends share a per-install budget of ${BEARER_SENDS_PER_IID_PER_HOUR}/hour across routes and tokens`, async () => {
    const e = env(CONFIGS.both);
    const auth = { authorization: await bearer("busy-install") };
    for (let i = 0; i < BEARER_SENDS_PER_IID_PER_HOUR; i++) {
      // A fresh token per send so only the per-install budget can bind.
      const res = i % 2 ? post("/v1/relay/liveactivity", laSend(i), auth) : post("/v1/relay/test", testSend(i), auth);
      expect((await app.fetch(res, e)).status).toBe(200);
    }
    expect((await app.fetch(post("/v1/relay/test", testSend(99_999), auth), e)).status).toBe(429);
    // Another install is unaffected, and so is the legacy key.
    const other = { authorization: await bearer("quiet-install") };
    expect((await app.fetch(post("/v1/relay/test", testSend(99_999), other), e)).status).toBe(200);
    expect((await app.fetch(post("/v1/relay/test", testSend(99_998), keyAuth), e)).status).toBe(200);
    // The window rolls.
    clock += 3_600_001;
    expect((await app.fetch(post("/v1/relay/test", testSend(99_997), auth), e)).status).toBe(200);
  });

  it("a send refused by one limit does not consume the other", async () => {
    const e = env(CONFIGS.secretOnly);
    const auth = { authorization: await bearer("limit-install") };
    for (let i = 0; i < ALERT_SENDS_PER_TOKEN_PER_HOUR; i++) {
      await app.fetch(post("/v1/relay/test", testSend(), auth), e);
    }
    for (let i = 0; i < 50; i++) {
      expect((await app.fetch(post("/v1/relay/test", testSend(), auth), e)).status).toBe(429);
    }
    // 60 recorded against the install, not 110: 1140 more fit.
    for (let i = 0; i < BEARER_SENDS_PER_IID_PER_HOUR - ALERT_SENDS_PER_TOKEN_PER_HOUR; i++) {
      expect((await app.fetch(post("/v1/relay/liveactivity", laSend(i + 1), auth), e)).status).toBe(200);
    }
    expect((await app.fetch(post("/v1/relay/liveactivity", laSend(5000), auth), e)).status).toBe(429);
  });
});

describe("forwarding", () => {
  it("sends Live Activity pushes to the liveactivity topic and push type", async () => {
    const res = await app.fetch(post("/v1/relay/liveactivity", laSend(), { authorization: await bearer() }), env(CONFIGS.secretOnly));
    expect(res.status).toBe(200);
    expect(apnsCalls).toHaveLength(1);
    expect(apnsCalls[0].url).toBe(`https://api.push.apple.com/3/device/${token()}`);
    expect(apnsCalls[0].headers["apns-topic"]).toBe(`${BUNDLE_ID}.push-type.liveactivity`);
    expect(apnsCalls[0].headers["apns-push-type"]).toBe("liveactivity");
    expect(apnsCalls[0].headers["apns-priority"]).toBe("5");
    expect(apnsCalls[0].headers.authorization).toMatch(/^bearer ey/);
  });
  it("still validates bodies after auth (422) and maps APNs errors", async () => {
    const e = env(CONFIGS.keyOnly);
    const bad = await app.fetch(post("/v1/relay/test", { device_token: "zz", environment: "production" }, { "x-relay-key": RELAY_KEY }), e);
    expect(bad.status).toBe(422);
    const gone = makeWorker({ fetch: async () => new Response("Unregistered", { status: 410 }) });
    expect((await gone.fetch(post("/v1/relay/test", testSend(), { "x-relay-key": RELAY_KEY }), e)).status).toBe(410);
  });
});
