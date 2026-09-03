# Adding `/auth/google`

The client already sends everything needed (committed on the app's `audit-fixes` branch).
It exchanges the authorization code for an ID token itself, so this endpoint has the same
shape as `/auth/apple`: verify a JWT, check the nonce, mint a session.

**The one trap:** Apple echoes `SHA256(rawNonce)` into the token; **Google echoes the nonce
verbatim.** Reusing `appleNonceMatches` here rejects every valid sign-in and looks like a
JWKS problem. Everything else is a near-copy.

---

## 1. `src/config.ts`

```ts
const googleClientId = str('GOOGLE_CLIENT_ID', '');
```

and in the exported object, beside `apple`:

```ts
  google: {
    /** iOS OAuth client id. Public by design — native clients use PKCE, not a secret. */
    clientId: googleClientId,
    enabled: Boolean(googleClientId),
  },
```

## 2. `src/session.ts`

```ts
const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

export interface GoogleIdentity {
  googleUserId: string;
  /** Google echoes the nonce back unchanged, unlike Apple's SHA-256 of it. */
  nonce?: string;
  email?: string;
  fullName?: string;
}

export async function verifyGoogleIdToken(idToken: string): Promise<GoogleIdentity> {
  if (!config.google.enabled) throw new Error('Google sign-in is not configured');
  const { payload } = await jwtVerify(idToken, googleKeys, {
    // Google mints tokens under both spellings; both are legitimate.
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    // The OAuth client id, NOT the bundle id.
    audience: config.google.clientId,
  });
  if (!payload.sub) throw new Error('Google ID token has no subject');
  return {
    googleUserId: payload.sub,
    nonce: typeof payload.nonce === 'string' ? payload.nonce : undefined,
    email: typeof payload.email === 'string' && payload.email_verified === true
      ? payload.email
      : undefined,
    fullName: typeof payload.name === 'string' ? payload.name : undefined,
  };
}

/**
 * Google returns the nonce exactly as the app supplied it, so this is a direct
 * comparison. `appleNonceMatches` hashes first and must not be used here.
 */
export function googleNonceMatches(rawNonce: string, claim: string): boolean {
  const expected = Buffer.from(rawNonce, 'utf8');
  const actual = Buffer.from(claim, 'utf8');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
```

Namespace the subject so two providers can never collide on one `userId`. Two lines, and
it costs nothing while there are no users:

```ts
export async function issueSessionToken(provider: 'apple' | 'google', providerUserId: string) {
  // ...unchanged, but:
  .setSubject(`${provider}:${providerUserId}`)
```

Update the existing `/auth/apple` call site to `issueSessionToken('apple', identity.appleUserId)`
and use that same namespaced id for its `user:` key.

## 3. `api/index.ts`

The user upsert is now identical for both providers, so lift it out:

```ts
async function upsertUser(userId: string, fullName?: string, email?: string): Promise<void> {
  const key = `user:${userId}`;
  const existing = await redis().get<{ createdAt?: number; fullName?: string; email?: string }>(key);
  const createdAt = existing?.createdAt ?? Date.now();
  await indexUser(userId, createdAt);
  await redis().set(key, {
    createdAt,
    lastSeenAt: Date.now(),
    // Apple sends these only on first authorization, so an existing value is
    // never overwritten by a later sign-in's nulls. Google sends them every time,
    // but keeping the same rule costs nothing.
    fullName: existing?.fullName ?? fullName,
    email: existing?.email ?? email,
  });
}
```

Then the route, mirroring `/auth/apple` including its IP rate limit:

```ts
app.post('/auth/google', async (c) => {
  assertConfigured();
  if (!config.google.enabled) throw new HttpError(404, 'Google sign-in is not enabled.');

  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const limit = await limitIp(ip);
  if (!limit.ok) throw new HttpError(429, 'Too many sign-in attempts. Please try again shortly.');

  const body = (await c.req.json().catch(() => null)) as { idToken?: unknown; nonce?: unknown } | null;
  const idToken = body?.idToken;
  if (typeof idToken !== 'string' || !idToken) {
    throw new HttpError(400, 'Sign in did not include an identity token.');
  }

  let identity;
  try {
    identity = await verifyGoogleIdToken(idToken);
  } catch (error) {
    console.warn('[auth] Google ID token rejected:', error);
    throw new HttpError(401, 'That sign-in could not be verified.');
  }

  // Enforced whenever the token carries the claim, so it cannot be stripped to skip.
  if (identity.nonce) {
    const rawNonce = body?.nonce;
    if (typeof rawNonce !== 'string' || !rawNonce) {
      throw new HttpError(400, 'Sign in did not include its nonce.');
    }
    if (!googleNonceMatches(rawNonce, identity.nonce)) {
      console.warn('[auth] Google nonce mismatch');
      throw new HttpError(401, 'That sign-in could not be verified.');
    }
  }

  const userId = `google:${identity.googleUserId}`;
  await upsertUser(userId, identity.fullName, identity.email);
  return c.json({ sessionToken: await issueSessionToken('google', identity.googleUserId) });
});
```

Nothing downstream changes: `limitUser`, `recordUsage`, `attestkeys:${userId}` and revocation
already take an opaque `userId`.

## 4. `.env.example`

```
# ---- Identity ----
# iOS OAuth client id from Google Cloud Console. Public, not a secret.
# Empty disables /auth/google and hides the button in the app.
GOOGLE_CLIENT_ID=
```

## 5. Google Cloud Console

Create an **iOS** OAuth client with bundle id `com.zenyi.diabeto`. It returns
`<number>-<hash>.apps.googleusercontent.com`. Put it in `GOOGLE_CLIENT_ID` here and in
`AppConfig.googleClientID` in the app. iOS clients auto-accept the reversed-client-id
redirect scheme, so there is no redirect URI to register.

## 6. Tests

Mirror `tests/subscription.test.ts`. All four should be `401`, and none need network:

- unsigned JWT (`alg: none`)
- token signed by a key not in Google's JWKS
- correct signature, wrong `aud`
- valid token, nonce that doesn't match the body

Plus one `400` for a body with no `idToken`, and one asserting `googleNonceMatches` returns
`true` for the raw value and `false` for its SHA-256 hex — that last one is what stops the
Apple helper being copied here by mistake later.

## Why this is worth doing before enrolling

Google sign-in needs **no Apple entitlement**. With `REQUIRE_ATTEST=false` and
`REQUIRE_SUBSCRIPTION=false`, and the `applesignin` key removed from the app's entitlements
file so it will provision on a Personal Team, you can run auth → session → `/analyze` on a
real device today. That closes the session half of "first real-device sign-in is the
remaining unknown" without the $99.
