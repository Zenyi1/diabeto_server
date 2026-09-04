# Setting up Google sign-in

> **Status: the client ID is set on both sides and `/auth/google` is live.**
> Steps 1 and 2 below are done. What remains is step 3 — signing in on a real device —
> plus confirming the consent-screen **Test users** list, which is the one thing that can
> still silently fail.

Both sides of the code are written and deployed. The one value from Google Cloud Console —
an **iOS OAuth client ID** — goes in two places.

Once it's set, sign-in → session → `/analyze` works on a real device **without a paid Apple
Developer Program membership**. That's the point of doing this first: it's the only way to
test the full auth path today, since Sign in with Apple, App Attest and In-App Purchase all
require the $99 enrolment and Google requires none of it.

**Time:** ~10 minutes. **Cost:** free.

---

## What you're creating

| | |
|---|---|
| Type | OAuth 2.0 Client ID, application type **iOS** |
| Bundle ID | `com.zenyi.diabeto` — must match exactly |
| Looks like | `123456789012-abc123def456.apps.googleusercontent.com` |
| Secret? | **No.** Native OAuth clients are public; PKCE replaces the secret |

There is **no redirect URI to register and no URL scheme to add to Info.plist.** The app
uses `ASWebAuthenticationSession`, which intercepts the redirect itself, and iOS OAuth
clients automatically accept the reversed-client-id scheme. The app derives that redirect
from the client ID on its own (`MealAI.swift` → `googleRedirectURI`), so the one value is
genuinely all that's needed.

---

## 1. Google Cloud Console  ✅ *client created*

1. Go to <https://console.cloud.google.com/> and **create a project** (or pick an existing
   one). Name it anything — `diabeto` is fine.

2. **APIs & Services → OAuth consent screen.**
   - User type: **External**
   - App name: `Diabeto`, and fill in the required support + developer contact emails
   - **Scopes: add none.** `openid`, `email` and `profile` are granted by default and are
     non-sensitive, so this app never needs Google's verification review.

3. **Add yourself as a test user.** Still on the consent screen, under **Test users**, add
   the Google account you'll sign in with on the device.

   > ⚠️ **This is the step people skip.** While the consent screen is in *Testing*, only
   > listed test users can sign in — everyone else gets `access_denied` with no useful
   > explanation. Add every account that will test the app.

4. **APIs & Services → Credentials → Create Credentials → OAuth client ID.**
   - Application type: **iOS**
   - Bundle ID: `com.zenyi.diabeto`
   - Create, then **copy the Client ID**.

You do not need to enable any APIs. Sign-in works off the consent screen alone.

---

## 2. Put the value in two places  ✅ *done*

**a) The server** — from this repo:

```bash
vercel env add GOOGLE_CLIENT_ID production
vercel env add GOOGLE_CLIENT_ID preview
vercel env add GOOGLE_CLIENT_ID development
vercel deploy --prod
```

Paste the client ID when prompted. Env changes only take effect on a new deployment, so the
deploy is required, not optional.

**b) The app** — `diabeto/diabeto/MealAI.swift`, line 48:

```swift
// before
static let googleClientID = "YOUR-CLIENT-ID.apps.googleusercontent.com"

// after
static let googleClientID = "123456789012-abc123def456.apps.googleusercontent.com"
```

Nothing else in the app changes. `isGoogleConfigured` flips to `true` on its own once the
placeholder is gone, which is what reveals the Google button.

---

## 3. Verify  ← *you are here*

**Server** — already confirmed:

```console
$ curl -s -X POST https://diabetoserver.vercel.app/auth/google \
    -H 'content-type: application/json' -d '{}'
Sign in did not include an identity token.        # 400 — route is live

$ curl -s -X POST https://diabetoserver.vercel.app/auth/google \
    -H 'content-type: application/json' \
    -d '{"idToken":"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhIn0.","nonce":"x"}'
That sign-in could not be verified.               # 401 — forgery rejected
```

A `404` here would mean `GOOGLE_CLIENT_ID` is unset or the deploy didn't happen.

**On device** — build to a real iPhone, tap Sign in with Google, complete the Google sheet.
Then confirm the account exists:

Open <https://diabetoserver.vercel.app/admin>, paste the `ADMIN_TOKEN` (in this repo's
local `.env`), and the user should appear with id `google:<numeric-google-sub>`.

A meal photo should then analyze end to end, because `REQUIRE_ATTEST` and
`REQUIRE_SUBSCRIPTION` are both currently `false`.

---

## If it fails

| Symptom | Cause |
|---|---|
| `access_denied` on the Google sheet | The signing-in account isn't in **Test users** (step 3) |
| `redirect_uri_mismatch` | The OAuth client isn't type **iOS**, or the bundle ID doesn't match `com.zenyi.diabeto` |
| Server returns `404` | `GOOGLE_CLIENT_ID` unset, or set but not redeployed |
| Server returns `401` on a real sign-in | Client ID differs between the app and the server — they must be byte-identical |
| Google button doesn't appear | `googleClientID` still starts with `YOUR-` |

The server logs the reason for every rejection (`vercel logs`), but never returns it to the
app — error bodies are shown to users verbatim, so they stay generic on purpose.

---

## Notes for whoever picks this up

- The client ID is **not a secret**. It ships in the app binary by design; it's an
  identifier, not a credential. No need to treat it like the OpenAI key.
- The app has **zero third-party dependencies** and this doesn't add one — no Google Sign-In
  SDK, just `ASWebAuthenticationSession` + PKCE against Google's standard OAuth endpoints.
- The app performs the code→token exchange itself and sends only the resulting **ID token
  plus the raw nonce** to `/auth/google`, which is why the endpoint has the same shape as
  `/auth/apple`.
- One asymmetry worth knowing if you touch the auth code: **Apple echoes `SHA256(nonce)`
  into its token; Google echoes the nonce verbatim.** They have separate comparison helpers
  for that reason, and a test that fails if one is used for the other.
