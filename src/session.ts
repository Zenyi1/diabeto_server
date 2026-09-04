import { SignJWT, createRemoteJWKSet, jwtVerify } from 'jose';
import { createHash, timingSafeEqual } from 'node:crypto';
import { config } from './config.js';
import { redis } from './redis.js';

/**
 * Module-level so the fetched key set survives warm invocations — Apple's JWKS is
 * otherwise refetched on every sign-in.
 */
const appleKeys = createRemoteJWKSet(new URL('https://appleid.apple.com/auth/keys'));
const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));

let secretBytes: Uint8Array | null = null;
function secret(): Uint8Array {
  secretBytes ??= new TextEncoder().encode(config.session.secret);
  return secretBytes;
}

export interface AppleIdentity {
  /** Stable Apple user id — the identity all usage is attributed to. */
  appleUserId: string;
  /**
   * The `nonce` claim, if the client requested one. Apple echoes back the
   * SHA-256 hex of the raw nonce the app generated, which is what lets the
   * server prove this token was minted for this sign-in and is not a replay.
   */
  nonce?: string;
}

/**
 * Verifies a Sign in with Apple identity token.
 *
 * For a native app the audience is the bundle id, not a Services ID.
 */
export async function verifyAppleIdentityToken(identityToken: string): Promise<AppleIdentity> {
  const { payload } = await jwtVerify(identityToken, appleKeys, {
    issuer: 'https://appleid.apple.com',
    audience: config.apple.bundleId,
  });
  if (!payload.sub) throw new Error('Apple identity token has no subject');
  return {
    appleUserId: payload.sub,
    nonce: typeof payload.nonce === 'string' ? payload.nonce : undefined,
  };
}

export interface GoogleIdentity {
  googleUserId: string;
  /** Google echoes the nonce back unchanged, unlike Apple's SHA-256 of it. */
  nonce?: string;
  email?: string;
  fullName?: string;
}

/**
 * Verifies a Google ID token. The audience is the OAuth client id, not the
 * bundle id — that difference is the usual cause of a mystifying rejection.
 */
export async function verifyGoogleIdToken(idToken: string): Promise<GoogleIdentity> {
  if (!config.google.enabled) throw new Error('Google sign-in is not configured');
  const { payload } = await jwtVerify(idToken, googleKeys, {
    // Google mints tokens under both spellings; both are legitimate.
    issuer: ['https://accounts.google.com', 'accounts.google.com'],
    audience: config.google.clientId,
  });
  if (!payload.sub) throw new Error('Google ID token has no subject');
  return {
    googleUserId: payload.sub,
    nonce: typeof payload.nonce === 'string' ? payload.nonce : undefined,
    // Only trust an address Google says it verified.
    email:
      typeof payload.email === 'string' && payload.email_verified === true ? payload.email : undefined,
    fullName: typeof payload.name === 'string' ? payload.name : undefined,
  };
}

/**
 * Google returns the nonce exactly as the app supplied it, so this is a direct
 * comparison. `appleNonceMatches` hashes first and must never be used here — it
 * would reject every valid Google sign-in and look like a JWKS problem.
 */
export function googleNonceMatches(rawNonce: string, claim: string): boolean {
  const expected = Buffer.from(rawNonce, 'utf8');
  const actual = Buffer.from(claim, 'utf8');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * Whether an identity token's `nonce` claim was produced from this raw nonce.
 *
 * Sign in with Apple hashes the nonce the app supplied and echoes the SHA-256
 * hex back in the token, so recomputing it proves the token was minted for this
 * sign-in attempt rather than captured from another one.
 */
export function appleNonceMatches(rawNonce: string, claim: string): boolean {
  const expected = Buffer.from(createHash('sha256').update(rawNonce).digest('hex'), 'utf8');
  const actual = Buffer.from(claim, 'utf8');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * The app has no refresh flow — it stores this in the Keychain and treats its mere
 * presence as "signed in" — so the lifetime is deliberately long. Rotating
 * SESSION_SECRET invalidates every outstanding token.
 */
export async function issueSessionToken(
  provider: 'apple' | 'google',
  providerUserId: string,
): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: 'HS256' })
    // Namespaced so two providers can never collide on one userId. Everything
    // downstream — quota, attest keys, usage, revocation — treats it as opaque.
    .setSubject(`${provider}:${providerUserId}`)
    .setIssuer(config.session.issuer)
    .setAudience(config.session.audience)
    .setIssuedAt()
    .setExpirationTime(`${config.session.ttlDays}d`)
    .sign(secret());
}

/**
 * Invalidates every session token issued to this user up to now.
 *
 * Account deletion has to take effect immediately rather than whenever the
 * outstanding token happens to expire. The marker outlives the longest possible
 * token and then removes itself, so this never grows unbounded.
 */
export async function revokeSessions(appleUserId: string): Promise<void> {
  await redis().set(`revoked:${appleUserId}`, Date.now(), {
    ex: config.session.ttlDays * 24 * 60 * 60,
  });
}

export async function verifySessionToken(token: string): Promise<string> {
  const { payload } = await jwtVerify(token, secret(), {
    issuer: config.session.issuer,
    audience: config.session.audience,
  });
  if (!payload.sub) throw new Error('session token has no subject');

  const revokedAt = await redis().get<number>(`revoked:${payload.sub}`);
  if (revokedAt && typeof payload.iat === 'number' && payload.iat * 1000 <= revokedAt) {
    throw new Error('session token was revoked');
  }

  return payload.sub;
}
