# diabeto-server — implementation & security recommendations

Written after auditing the iOS client (2026-09-03). The client is done and hardened; this
file is what the server still has to do. `docs/backend-contract.md` in the **client** repo
is the wire contract — this is the *why*, the ordering, and the things that will bite.

## Where this repo stands

`api/` is empty. What exists is good: `src/certs.ts` embeds the Apple App Attest root and
Apple Root CA G3 with published fingerprints in comments (correct — don't fetch roots at
runtime), the dependency set is well chosen (`hono`, `jose`, `cbor-x`, `@peculiar/x509`,
`@apple/app-store-server-library`, `@upstash/ratelimit`), and `.env.example` already
describes gates that fail closed and a deadline under the client's timeout.

Secrets are handled correctly: `.env` holds a live OpenAI key, is covered by `.gitignore`
(`.env`, `.env.*`, `*.p8`), and `git log --all -- .env` confirms it was never committed.

**The thing to internalise:** every security control the client relies on lives in the file
that isn't written yet. The client cannot enforce any of them — a patched build can claim
to be signed in, subscribed, and attested. Treat all three as server-side facts.

---

## Build in this order

Each step is independently shippable and unblocks something concrete.

| # | Step | Unblocks |
|---|------|----------|
| 1 | `POST /analyze` with the two-step pipeline, `DEV_BYPASS_TOKEN` only | End-to-end photo → macros in the Simulator |
| 2 | `POST /auth/apple` with JWT + **nonce** verification, session issuing | Real sign-in; kills the bypass path |
| 3 | Usage logging keyed on Apple `sub`, then rate limits | You stop paying for unbounded use |
| 4 | `GET /attest/challenge` + `POST /attest/register` + per-request assertions | Blocks non-app clients |
| 5 | Subscription verification via App Store Server API | Revenue actually gated |
| 6 | `DELETE /account` | App Review 5.1.1(v) — required to ship |
| 7 | `GET /usage` | The "see their expenditure" gap |

Steps 2, 5 and 6 are **blocked on enrolling in the Apple Developer Program** — the client's
team is currently a free Personal Team, which cannot use Sign in with Apple, App Attest, or
In-App Purchase at all.

---

## Non-negotiables

### 1. Verify the Sign in with Apple nonce

The client now generates a random 32-byte nonce per sign-in, sends Apple `SHA256(nonce)`,
and posts the **raw** nonce in the `/auth/apple` body. You must close the loop:

```ts
const claims = await jwtVerify(identityToken, appleJWKS, {
  issuer: 'https://appleid.apple.com',
  audience: process.env.APPLE_BUNDLE_ID,          // com.zenyi.diabeto
})
const expected = createHash('sha256').update(body.nonce).digest('hex')
if (claims.payload.nonce !== expected) throw unauthorized()
```

Without this, a captured identity token can be replayed to mint a session for that user
inside the token's validity window. Also check `email_verified` if you act on the email,
and reject tokens whose `sub` you can't read.

### 2. Never trust the client's subscription claim

`isSubscribed` in the app is a UX gate, not a security boundary. Verify server-side with
the App Store Server API before serving `/analyze`, and cache the result briefly (60s) so
you're not making an Apple call per photo. `REQUIRE_SUBSCRIPTION=true` must fail closed if
the Apple call errors — degrade to "reject", never to "allow".

### 3. App Attest: the counter is the whole point

Registration verifies the attestation once. **Per request**, verify the assertion against
`clientDataHash = SHA256(rawBody)` — the raw bytes, before any JSON re-serialisation, or
the hash won't match — and require the counter to be **strictly greater** than the stored
value, then persist the new one. Skipping the counter makes assertions replayable and the
whole mechanism decorative.

Two client behaviours to accommodate:

- **Re-registration is normal.** The client stores its key id device-only and discards it
  if it ever stops producing assertions, then registers a fresh key. Accept a new `keyId`
  for a user who already has one. Keep rejecting a `keyId` already bound to a *different*
  user.
- **Unattested requests happen.** The Simulator reports App Attest as unsupported and sends
  no attest headers. Decide explicitly: reject, or allow with much tighter rate limits.
  `REQUIRE_ATTEST=true` should mean reject in production.

### 4. Make the bypass token fail closed

`DEV_BYPASS_TOKEN` skips the session, subscription **and** attest gates together. Its
comment says "DELETE BEFORE LAUNCH", which makes total compromise depend on remembering.
Make it structurally impossible instead:

```ts
const bypass = process.env.VERCEL_ENV === 'production' ? null : process.env.DEV_BYPASS_TOKEN
```

Same idea for `APP_ATTEST_ENV` and `APP_STORE_ENV`: assert they are `production` when
`VERCEL_ENV === 'production'` and refuse to boot otherwise. A misconfigured environment
should be a startup failure, not a silent downgrade.

---

## Config corrections

**`vercel.json` `maxDuration: 120` → `90`.** The client's `URLSession` gives up at 90s with
no retry. Anything between 90 and 120 seconds bills you for compute and OpenAI tokens for a
result nobody will ever receive. `ANALYZE_DEADLINE_MS=78000` is correctly under the cutoff;
`maxDuration` should be too.

**`SESSION_TTL_DAYS=365`.** A year-long bearer token in the Keychain with no rotation. The
client now handles 401/403 by signing out cleanly, so shortening this is safe and
recoverable — 30–90 days with silent re-auth is a better default. Keep a server-side
revocation list (or a `tokenVersion` per user you bump on delete/sign-out) so
`DELETE /account` genuinely invalidates outstanding tokens rather than waiting a year.

**`MAX_IMAGE_BYTES=6291456`.** Enforce it on the decoded base64 length *before* decoding,
and reject early — don't buffer 6 MB of body then check.

---

## Usage & spend tracking — the open gap

The contract says "log usage per Apple user id" three times but never defines a record, and
there's no endpoint to read it back. This is the "see their expenditure" question, unbuilt
on both sides. Concretely:

**Decide the unit.** Requests are easy but don't track cost (a 2-food photo and a 12-food
photo differ a lot). Recommend recording all three and billing decisions on cents:

```ts
// key: usage:{appleSub}:{YYYY-MM}
{ requests: 42, inputTokens: 84_000, outputTokens: 6_100, usdMicros: 51_300, updatedAt }
```

Take token counts from the OpenAI response's `usage` object, multiply by the model's rates
held in one constant, and increment atomically in Redis. Also write a per-day key so daily
limits and a simple chart are possible later.

**Expose it.** `GET /usage` (Bearer session) returning the current period's usage and the
limit lets the app show "12 of 50 analyses left this month" on the paywall and next to the
analyze button — which is also the honest thing to show someone paying a subscription.

**Return structured limit errors.** The client special-cases **429** into a proper
rate-limit message; every other non-2xx surfaces the raw body text to the user. So return
`429` with `{"error":"quota_exceeded"}` rather than a 500 with a stack trace.

**Rate-limit in a shared store.** An in-memory limiter resets on cold start and is
per-instance, which on serverless means effectively no limit. `@upstash/ratelimit` is
already a dependency — use it, keyed on the Apple `sub`, not on IP.

---

## Not covered above: storing the diary on the server

**Today the server never sees a single glucose reading, meal, or food item.** The whole
diary lives in SwiftData on the device. What crosses the network is only:

| Endpoint | Body |
|----------|------|
| `POST /auth/apple` | identity token, nonce, name + email (first sign-in only) |
| `GET /attest/challenge` | *(bearer only)* |
| `POST /attest/register` | key id, attestation, challenge |
| `POST /analyze` | `{"image": "<base64 jpeg>"}` — one photo, transient, never stored |
| `DELETE /account` | *(bearer only)* |

So the server's data model is identity and metering: Apple `sub`, optional name/email,
session state, attest public key + counter, usage records. **No health data.** Everything
above in this file assumes that shape.

This matters now that the app requires sign-in before the diary opens. App Review
guideline 5.1.1(v) says that if an app *doesn't* include significant account-based
features, it must let people use it without a login — and a diary that is entirely local
is exactly that. Two ways to make the gate defensible:

**Option A — leave storage local, justify the account another way.** Cheapest. The account
carries the subscription and AI quota, which is a real account-based feature, but a
reviewer may still object because the diary works fine without it. Expect to argue it in
review notes.

**Option B — move the diary to the server.** Makes the gate obviously correct, and closes
the "no backup, no sync" gap in one move. This is **not specced above** and is real work:

- Storage that can hold health data — Postgres/Neon, not Redis. Upstash is fine for rate
  limits and usage counters; it is not where a medical diary belongs.
- `GET /diary?since=<cursor>` and `POST /diary` with per-row `updatedAt` and a
  last-write-wins or vector-clock merge. The client is offline-first today and must stay
  that way — a glucose log has to work with no signal.
- Soft deletes (tombstones), or deleting on one device won't propagate.
- `DELETE /account` must then also erase the diary, and you inherit a real data-deletion
  obligation (GDPR Art. 17, and Apple's own account-deletion rule).
- Encryption at rest, a defined retention policy, and access logging. Once glucose
  readings are on your server you are holding health data about identifiable people, and
  in several jurisdictions that carries duties a meal-photo proxy does not.
- The client's SwiftData store becomes a cache rather than the source of truth, which is
  a meaningful refactor on the app side too.

**A third option worth weighing:** turn on CloudKit instead. It gives sync and backup with
no server-side health data, no new endpoints, and no compliance burden — but it does not
justify a mandatory account, because CloudKit uses the user's iCloud identity rather than
yours. Sequence-wise, if Option B is likely, do it before shipping; migrating a populated
local diary to a server later is materially harder than starting there.

---

## Error contract the client expects

| Status | Client behaviour |
|--------|------------------|
| 401 / 403 | **Signs the user out** — clears session token and attest key id, shows sign-in again |
| 429 | Shows "You've hit today's analysis limit. Try again later." |
| other non-2xx | Shows `Request failed (<code>). <first 300 chars of body>` to the user |

That last row means **your response body is user-visible UI**. Return short, human
`{"error":"..."}` strings; never leak stack traces, upstream OpenAI errors, or internal
identifiers. And don't return 401 for anything that isn't genuinely an auth failure — it
will sign people out.

The client also clamps what you return (non-finite and negative → 0, grams ≤ 5000, macros
≤ 2000, `confidence` ≤ 1, first 30 foods only). That's defence in depth, not permission to
emit junk — a model can hallucinate a 4000 g portion and the user will see it.

---

## Operational

- **Don't log the image, the identity token, or the session token.** Log the Apple `sub`,
  the attest key id, timing and token counts. Photos of someone's meals plus glucose data
  is health-adjacent — treat logs as regulated data and keep retention short.
- **Pin outbound egress** to `api.openai.com`, `api.nal.usda.gov`, `appleid.apple.com`,
  `api.storekit.itunes.apple.com`.
- **Cache Apple's JWKS** (they rotate, but not per request) with a short TTL and a fallback.
- **Run USDA lookups in parallel** with a per-lookup timeout (`USDA_TIMEOUT_MS=4000` is
  already there) and never fail the whole request on a nutrition miss — return zeros for
  that item, as the contract says.
- **`OPENAI_BASE_URL` is configurable**, which is good for switching providers — but make
  sure a non-Apple provider never sees anything beyond the image. Don't forward the Apple
  `sub` or email into prompts.

---

## Pre-launch checklist

- [ ] `DEV_BYPASS_TOKEN` unset **and** structurally disabled in production
- [ ] `APP_ATTEST_ENV=production`, `APP_STORE_ENV=production`, `APP_STORE_APP_APPLE_ID` set
- [ ] `REQUIRE_ATTEST=true`, `REQUIRE_SUBSCRIPTION=true`, both failing closed
- [ ] `SESSION_SECRET` rotated off any value used in development
- [ ] `maxDuration` ≤ 90
- [ ] Nonce verification on `/auth/apple` proven with a replayed token
- [ ] Assertion counter proven monotonic with a replayed request
- [ ] `DELETE /account` removes user, attest keys, and usage; invalidates live sessions
- [ ] Rate limits verified against a shared store across two instances
- [ ] Privacy policy and terms published at real URLs — the app links to them from the
      paywall and Settings, and App Review follows both
- [ ] Privacy policy discloses that meal photos go to a third-party model provider
