# diabeto_server

Meal-photo analysis backend for the [diabeto](https://github.com/Zenyi1/diabeto) iOS app.
Holds the API keys the app must not ship, runs the two-step pipeline (vision decompose →
USDA nutrition lookup), and gates access three ways.

**Live:** https://diabetoserver.vercel.app · **Health:** [`/health`](https://diabetoserver.vercel.app/health)

```
iOS app ──POST /analyze──► Vercel Function (Hono, Node 24)
                             ├─ session JWT      (Sign in with Apple or Google)
                             ├─ App Attest       (assertion over the raw body)
                             ├─ subscription     (StoreKit 2 JWS)
                             ├─ rate limit       (Upstash Redis)
                             ├─ OpenAI vision  → foods + grams
                             └─ USDA (parallel) → macros
```

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/analyze` | session + attest + subscription | `{"image":"<base64 jpeg>"}` → `{"foods":[…]}` |
| `POST` | `/auth/apple` | none (IP rate-limited) | identity token + nonce → `{"sessionToken"}` |
| `POST` | `/auth/google` | none (IP rate-limited) | Google ID token + nonce → `{"sessionToken"}` |
| `GET` | `/attest/challenge` | session | one-time challenge for key registration |
| `POST` | `/attest/register` | session | verifies an attestation, stores the public key |
| `GET` | `/usage` | session | this month's requests, tokens, spend, and limits |
| `DELETE` | `/account` | session | erases user, device keys and usage; revokes tokens |
| `GET` | `/health` | none | gate state and config problems |
| `GET` | `/admin` | token | operator dashboard: users, subscriptions, spend |

Errors are **plain text**, because the client shows the response body verbatim
(`Request failed (500). <body>`). The one exception is `429`, which returns
`{"error":"quota_exceeded"}` — the client renders its own message there, so that body is
for machines. Upstream errors are logged, never returned.

## Getting macros right

A silent zero is the dangerous failure here: "pad thai → 0g carbs" reads to the app as
"no insulin needed". Three things guard against it, in order:

1. **USDA is the authority**, queried on the head noun (`"red apple, whole, medium"` →
   `red apple`) because a verbose name dilutes the search.
2. **Candidates are scored, not trusted.** USDA's top hit for `red apple` was
   *Apple-flavored whey protein powder* — which reported an apple as 0g carbs and 45.9g
   protein. Five candidates are fetched and ranked by an F1 over content words, so a
   description padded with words nobody asked for loses to *Apples, raw, with skin*.
   Below 0.45 nothing is trusted.
3. **Anything unresolved goes to a cheap model** (`gpt-5-nano`, ~25× cheaper than the
   vision pass) in one batched call, cached per food name. A food only ever reports zero
   if that fails too.

USDA's edge also returns intermittent nginx 400s for requests that succeed on retry, so
lookups retry once, and an outage is **never** cached — otherwise a one-second blip would
serve zero carbs for that food for a day.

## The three gates

Each defaults to **on**. A gate whose dependency is missing records a config problem and
makes the route answer `503` — it never degrades into serving ungated traffic. `/health`
reports exactly what's missing.

- **Session** — Sign in with Apple *or* Google, each verified against its own JWKS, plus
  the **nonce** that stops a captured token being replayed. The two are not
  interchangeable: Apple echoes `SHA256(rawNonce)` into the token, Google echoes the nonce
  verbatim, so they have separate comparison helpers and a test that keeps them apart.
  Session subjects are namespaced (`apple:…` / `google:…`) so providers can never collide.
  Google needs no Apple entitlement, so it works on a free Personal Team today.
- **App Attest** — attested once per install, then every `/analyze` carries an assertion
  over `SHA256(rawBody)`. The raw bytes are hashed *before* JSON parsing; re-serialising
  would invalidate every genuine signature. Replay is blocked by a strictly-increasing
  counter applied with `ZADD … GT CH`, a single atomic Redis primitive, so two concurrent
  replays cannot both win.
- **Subscription** — the app's `Transaction.jwsRepresentation`, verified against Apple's
  root certificate. Self-contained: no App Store Connect API key, no linking table, and
  fresh on every call, so a lapse or refund takes effect immediately.

`DEV_BYPASS_TOKEN` skips all three for local testing. It is **structurally ignored when
`VERCEL_ENV=production`**, so forgetting to remove it cannot expose `/analyze`.

## Development

```bash
npm install
cp .env.example .env      # fill in OPENAI_API_KEY at minimum
npm test                  # 105 tests, no network, no credentials needed
npm run typecheck
vercel dev                # bypass token works here; it does not in production
```

The suite runs the **real** app against fake upstreams: an in-memory server speaking
Upstash's REST protocol, and stand-in OpenAI/USDA HTTP servers. No module mocking and no
test-only branches in `src/`.

App Attest fixtures are synthesised with a locally-generated CA (`tests/helpers/attest-fixtures.ts`),
which is why `verifyAttestation` takes an optional `trustedRootPem` — a chain pinned to
Apple's real root would fail at step 1 and leave steps 2–9 untested. Production callers
omit it and get the pinned root.

**What the tests cannot cover:** a genuine Apple-signed attestation or subscription
receipt. Those paths are exercised only for rejection (forged chain, self-signed receipt,
unsigned JWT). First real-device sign-in is the remaining unknown.

## Where the data lives

There is **no SQL database and no health data on the server**. The diary — glucose
readings, meals, food items — stays in SwiftData on the device. All the server keeps is
identity and metering, in Redis:

| Key | Holds |
|---|---|
| `user:<userId>` | account record: created/last-seen, name + email. `userId` is `apple:…` or `google:…` |
| `attest:<keyId>` | one device's App Attest public key |
| `attestkeys:<userId>` | that user's set of device key ids |
| `attest:counters` | sorted set of last-seen signature counter per key — the replay defence |
| `usage:<userId>:<YYYY-MM>` | requests, tokens, spend (daily rows too, 90-day TTL) |
| `challenge:` `revoked:` `rl:` `usda:` | one-time challenges, session revocations, quota counters, nutrition cache |

**[`/admin`](https://diabetoserver.vercel.app/admin)** shows all of it — users, subscribed
count, analyses and spend — after you paste `ADMIN_TOKEN` once. The raw store is also
browsable in the Upstash console via the Vercel dashboard (Storage → `diabeto-redis`).

For revenue, churn and subscriber counts, use **App Store Connect** — it is authoritative
and sees purchases this server never does. What only this server can tell you is the
per-user AI cost, which is what the dashboard is for.

A user row is created only by a sign-in. Apple needs a paid Developer Program membership;
**Google does not**, so setting `GOOGLE_CLIENT_ID` is the fastest way to get a real account
and a real `/analyze` call on a device today.

## Deploying

```bash
vercel env add SOME_VAR production
vercel deploy --prod
```

Redis is already provisioned (Upstash, free tier) and injects `KV_REST_API_*`
automatically. `vercel.json` caps `maxDuration` at 90s to match the client's hard timeout —
anything longer bills for a result nobody receives.

## Still to do

**Blocked on enrolling in the Apple Developer Program** (the app is on a free Personal
Team, which cannot use Sign in with Apple, App Attest, or In-App Purchase):

1. Set `APPLE_TEAM_ID`, then `REQUIRE_ATTEST=true` and `APP_ATTEST_ENV` to match.
2. Create the subscription products, set `APP_STORE_APP_APPLE_ID`, then
   `REQUIRE_SUBSCRIPTION=true` and `APP_STORE_ENV=production`.

**Needed from the client:**

- `/analyze` must send `X-Subscription-Jws` — the current `AccountStore` verifies the
  subscription only locally, so the server has nothing to check and
  `REQUIRE_SUBSCRIPTION=true` would reject every request. Roughly:

  ```swift
  for await entitlement in Transaction.currentEntitlements {
      if case .verified(let t) = entitlement,
         AppConfig.subscriptionProductIDs.contains(t.productID), t.revocationDate == nil {
          headers["X-Subscription-Jws"] = entitlement.jwsRepresentation
      }
  }
  ```

**Other:**

- `USDA_API_KEY` is unset, so every food currently reports 0 carbs. Free, instant, no card:
  <https://fdc.nal.usda.gov/api-key-signup>. In a dosing app a silent zero is the dangerous
  failure — worth flagging zero-carb rows in the UI regardless.
- `OPENAI_*_USD_PER_MTOK` are 0, so `/usage` reports tokens but no spend.
- Publish privacy policy and terms at real URLs; the paywall links to them and App Review
  follows both. The policy must disclose that meal photos go to a third-party model.

## Pre-launch checklist

- [ ] `DEV_BYPASS_TOKEN` removed (already inert in production)
- [ ] `REQUIRE_ATTEST=true`, `REQUIRE_SUBSCRIPTION=true`, `/health` shows `ok: true`
- [ ] `APP_ATTEST_ENV=production`, `APP_STORE_ENV=production`, `APP_STORE_APP_APPLE_ID` set
- [ ] `SESSION_SECRET` rotated off any development value
- [ ] Nonce verification proven against a replayed identity token on a real device
- [ ] Assertion counter proven monotonic from a real device
- [ ] `USDA_API_KEY` set
