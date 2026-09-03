/**
 * diabeto meal-photo analysis backend.
 *
 * One Hono app behind a catch-all rewrite, so every route shares a single warm
 * Fluid Compute instance instead of cold-starting per endpoint.
 *
 * Errors are returned as **plain text**, not JSON: the iOS client surfaces the
 * response body verbatim to the user (`MealAI.swift` → "Request failed (401).
 * <body>"), so a bare sentence reads far better than a JSON envelope. Machine
 * decisions on the client key off the status code, never the body.
 */

import { Hono } from 'hono';
import { getRequestListener } from '@hono/node-server';
import type { ContentfulStatusCode } from 'hono/utils/http-status';
import { randomBytes, timingSafeEqual } from 'node:crypto';

import { config, configProblems, configWarnings } from '../src/config.js';
import { bumpAttestCounter, initAttestCounter, redis } from '../src/redis.js';
import {
  appleNonceMatches,
  issueSessionToken,
  revokeSessions,
  verifyAppleIdentityToken,
  verifySessionToken,
} from '../src/session.js';
import {
  deleteUsage,
  indexUser,
  listUsers,
  readGlobalStats,
  readUsage,
  recordUsage,
  unindexUser,
} from '../src/usage.js';
import { AttestError, verifyAssertion, verifyAttestation, type AttestKeyRecord } from '../src/attest.js';
import { SubscriptionError, verifySubscriptionJws } from '../src/subscription.js';
import { DecomposeError, decompose } from '../src/openai.js';
import { macrosFor, scaleMacros } from '../src/usda.js';
import { estimateMacros, normalize } from '../src/macro-fallback.js';
import { limitIp, limitUser } from '../src/ratelimit.js';

class HttpError extends Error {
  readonly status: ContentfulStatusCode;

  constructor(status: ContentfulStatusCode, message: string) {
    super(message);
    this.status = status;
  }
}

const app = new Hono();

/** A half-configured deploy must not serve traffic as if it were fully gated. */
function assertConfigured(): void {
  if (configProblems.length > 0) {
    console.error('[config] refusing to serve:', configProblems.join('; '));
    throw new HttpError(503, 'The server is not fully configured yet.');
  }
}

/** Constant-time compare for secrets, so response timing can't be used to guess them. */
function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

function bearer(request: Request): string | null {
  const header = request.headers.get('authorization');
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

interface Principal {
  userId: string;
  /** True when DEV_BYPASS_TOKEN was used, which skips attest and subscription. */
  bypassed: boolean;
}

async function authenticate(request: Request): Promise<Principal> {
  assertConfigured();
  const token = bearer(request);
  if (!token) throw new HttpError(401, 'Please sign in to use meal analysis.');

  if (config.devBypassToken && timingSafeEqualString(token, config.devBypassToken)) {
    return { userId: 'dev-bypass', bypassed: true };
  }

  try {
    return { userId: await verifySessionToken(token), bypassed: false };
  } catch {
    throw new HttpError(401, 'Your session has expired. Please sign in again.');
  }
}

// ---------------------------------------------------------------- health

app.get('/health', (c) =>
  c.json({
    ok: configProblems.length === 0,
    gates: {
      attest: config.gates.requireAttest,
      subscription: config.gates.requireSubscription,
    },
    devBypass: Boolean(config.devBypassToken),
    attestEnvironment: config.apple.attestEnv,
    appStoreEnvironment: config.subscription.env,
    model: config.openai.model,
    // Only present when the server is already refusing to serve, so this leaks
    // nothing an attacker could act on.
    ...(configProblems.length > 0 ? { problems: configProblems } : {}),
    ...(configWarnings.length > 0 ? { warnings: configWarnings } : {}),
  }),
);

// ---------------------------------------------------------------- auth

app.post('/auth/apple', async (c) => {
  assertConfigured();

  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
  const limit = await limitIp(ip);
  if (!limit.ok) throw new HttpError(429, 'Too many sign-in attempts. Please try again shortly.');

  const body = (await c.req.json().catch(() => null)) as {
    identityToken?: unknown;
    nonce?: unknown;
    fullName?: unknown;
    email?: unknown;
  } | null;

  const identityToken = body?.identityToken;
  if (typeof identityToken !== 'string' || !identityToken) {
    throw new HttpError(400, 'Sign in did not include an identity token.');
  }

  let identity;
  try {
    identity = await verifyAppleIdentityToken(identityToken);
  } catch (error) {
    console.warn('[auth] identity token rejected:', error);
    throw new HttpError(401, 'That sign-in could not be verified.');
  }

  // Apple echoes SHA-256(rawNonce) into the token. Recomputing it from the raw
  // nonce the app just generated is what makes a captured token useless to
  // replay. Enforced whenever the token carries the claim, so an attacker cannot
  // strip the nonce to bypass the check.
  if (identity.nonce) {
    const rawNonce = body?.nonce;
    if (typeof rawNonce !== 'string' || !rawNonce) {
      throw new HttpError(400, 'Sign in did not include its nonce.');
    }
    if (!appleNonceMatches(rawNonce, identity.nonce)) {
      console.warn('[auth] nonce mismatch');
      throw new HttpError(401, 'That sign-in could not be verified.');
    }
  }

  const key = `user:${identity.appleUserId}`;
  const existing = await redis().get<{ createdAt?: number; fullName?: string; email?: string }>(key);
  const createdAt = existing?.createdAt ?? Date.now();
  await indexUser(identity.appleUserId, createdAt);
  await redis().set(key, {
    createdAt,
    lastSeenAt: Date.now(),
    // Apple returns these only on the very first authorization, so an existing
    // value is never overwritten by the nulls of later sign-ins.
    fullName: existing?.fullName ?? (typeof body?.fullName === 'string' ? body.fullName : undefined),
    email: existing?.email ?? (typeof body?.email === 'string' ? body.email : undefined),
  });

  return c.json({ sessionToken: await issueSessionToken(identity.appleUserId) });
});

/** Account deletion, which the App Store requires for any app with sign-in. */
app.delete('/account', async (c) => {
  const { userId, bypassed } = await authenticate(c.req.raw);
  if (bypassed) throw new HttpError(400, 'A bypass token has no account to delete.');

  const keyIds = await redis().smembers(`attestkeys:${userId}`);
  if (keyIds.length > 0) {
    await Promise.all(keyIds.map((keyId) => redis().del(`attest:${keyId}`)));
    await redis().zrem('attest:counters', ...keyIds);
  }
  await redis().del(`attestkeys:${userId}`, `user:${userId}`);
  await unindexUser(userId);
  await deleteUsage(userId);
  // Outstanding tokens must die now, not whenever they happen to expire.
  await revokeSessions(userId);

  return c.json({ ok: true });
});

/** Lets the app show "12 of 50 analyses left" instead of guessing. */
app.get('/usage', async (c) => {
  const { userId } = await authenticate(c.req.raw);
  const usage = await readUsage(userId);
  return c.json({
    month: usage.month,
    today: usage.today,
    limits: { perDay: config.limits.perDay, perMinute: config.limits.perMinute },
  });
});

// ----------------------------------------------------------------- admin

/**
 * Read-only operator views. Absent entirely unless ADMIN_TOKEN is set, and a
 * wrong token 404s rather than 401s so the routes don't advertise themselves.
 */
function requireAdmin(request: Request): void {
  const token = bearer(request);
  if (!config.adminToken || !token || !timingSafeEqualString(token, config.adminToken)) {
    throw new HttpError(404, 'Not found.');
  }
}

app.get('/admin/stats', async (c) => {
  requireAdmin(c.req.raw);
  assertConfigured();
  const stats = await readGlobalStats();
  return c.json({
    users: stats.users,
    period: stats.period,
    month: { ...stats.month, usd: stats.month.usdMicros / 1_000_000 },
    today: { ...stats.today, usd: stats.today.usdMicros / 1_000_000 },
    model: config.openai.model,
  });
});

app.get('/admin/users', async (c) => {
  requireAdmin(c.req.raw);
  assertConfigured();

  const limit = Math.min(Number(c.req.query('limit') ?? 50) || 50, 200);
  const offset = Math.max(Number(c.req.query('offset') ?? 0) || 0, 0);
  const ids = await listUsers(limit, offset);

  const users = await Promise.all(
    ids.map(async (id) => {
      const [record, devices, usage] = await Promise.all([
        redis().get<{ createdAt?: number; lastSeenAt?: number; email?: string; fullName?: string }>(`user:${id}`),
        redis().scard(`attestkeys:${id}`),
        readUsage(id),
      ]);
      return {
        id,
        email: record?.email ?? null,
        fullName: record?.fullName ?? null,
        createdAt: record?.createdAt ?? null,
        lastSeenAt: record?.lastSeenAt ?? null,
        devices,
        month: { ...usage.month, usd: usage.month.usdMicros / 1_000_000 },
      };
    }),
  );

  return c.json({ users, limit, offset });
});

// ---------------------------------------------------------------- attest

app.get('/attest/challenge', async (c) => {
  const { userId } = await authenticate(c.req.raw);
  // base64url: the client hashes these exact characters, so it must survive JSON
  // and header transport unchanged.
  const challenge = randomBytes(32).toString('base64url');
  await redis().set(`challenge:${challenge}`, { userId }, { ex: 300 });
  return c.json({ challenge });
});

async function evictOldestKeyIfFull(userId: string): Promise<void> {
  const keyIds = await redis().smembers(`attestkeys:${userId}`);
  if (keyIds.length < config.limits.maxAttestKeysPerUser) return;

  const records = await Promise.all(
    keyIds.map(async (keyId) => ({ keyId, record: await redis().get<AttestKeyRecord>(`attest:${keyId}`) })),
  );
  // A key whose record has already vanished is the best thing to drop.
  const oldest = records.sort((a, b) => (a.record?.createdAt ?? 0) - (b.record?.createdAt ?? 0))[0];
  if (!oldest) return;

  await redis().del(`attest:${oldest.keyId}`);
  await redis().srem(`attestkeys:${userId}`, oldest.keyId);
  await redis().zrem('attest:counters', oldest.keyId);
}

app.post('/attest/register', async (c) => {
  const { userId, bypassed } = await authenticate(c.req.raw);
  if (bypassed) throw new HttpError(400, 'Attestation cannot be registered with a bypass token.');

  const body = (await c.req.json().catch(() => null)) as {
    keyId?: unknown;
    attestation?: unknown;
    challenge?: unknown;
  } | null;
  const { keyId, attestation, challenge } = body ?? {};
  if (typeof keyId !== 'string' || typeof attestation !== 'string' || typeof challenge !== 'string') {
    throw new HttpError(400, 'Attestation registration was incomplete.');
  }

  // One-time: consuming and checking ownership in one step stops a challenge
  // issued to one account being spent by another.
  const claimed = await redis().getdel<{ userId?: string }>(`challenge:${challenge}`);
  if (!claimed || claimed.userId !== userId) {
    throw new HttpError(400, 'That verification challenge is no longer valid.');
  }

  const existing = await redis().get<AttestKeyRecord>(`attest:${keyId}`);
  if (existing && existing.userId !== userId) {
    throw new HttpError(403, 'That device key is already registered to another account.');
  }
  // Re-registration is normal — the client discards its key id whenever it stops
  // working — so a full slate evicts the oldest key instead of locking the
  // account out of analysis forever.
  if (!existing) await evictOldestKeyIfFull(userId);

  let verified;
  try {
    verified = verifyAttestation({ attestationBase64: attestation, keyId, challenge });
  } catch (error) {
    if (error instanceof AttestError) {
      console.warn('[attest] registration rejected:', error.message);
      throw new HttpError(401, 'This device could not be verified.');
    }
    throw error;
  }

  const record: AttestKeyRecord = {
    userId,
    publicKeyPem: verified.publicKeyPem,
    environment: verified.environment,
    createdAt: Date.now(),
  };
  await redis().set(`attest:${keyId}`, record);
  await redis().sadd(`attestkeys:${userId}`, keyId);
  await initAttestCounter(keyId);

  return c.json({ ok: true });
});

// ---------------------------------------------------------------- analyze

/**
 * Every numeric field the client decodes is non-optional, so a null or NaN here
 * fails the whole decode and the user sees a generic error. Clamped as well as
 * sanitised — these numbers drive an insulin dose.
 */
function finite(value: number, digits: number, max: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Number(Math.min(value, max).toFixed(digits));
}

async function enforceAttestation(request: Request, rawBody: Buffer, userId: string): Promise<void> {
  const keyId = request.headers.get('x-attest-key-id');
  const assertion = request.headers.get('x-attest-assertion');
  if (!keyId || !assertion) {
    throw new HttpError(401, 'This device could not be verified.');
  }

  const record = await redis().get<AttestKeyRecord>(`attest:${keyId}`);
  // 401, not 409: the client already treats 401/403 as "clear the session and the
  // stored attest key id, sign in again", which is exactly the recovery an
  // unknown key needs. A bespoke status would just surface a raw error string.
  if (!record) throw new HttpError(401, 'This device needs to be verified again.');
  if (record.userId !== userId) throw new HttpError(403, 'This device is registered to another account.');

  let counter: number;
  try {
    ({ counter } = verifyAssertion({ assertionBase64: assertion, rawBody, publicKeyPem: record.publicKeyPem }));
  } catch (error) {
    if (error instanceof AttestError) {
      console.warn('[attest] assertion rejected:', error.message);
      throw new HttpError(401, 'This request could not be verified.');
    }
    throw error;
  }

  // Strictly increasing, applied atomically: two concurrent replays cannot both win.
  if (!(await bumpAttestCounter(keyId, counter))) {
    console.warn('[attest] replayed or stale counter for key', keyId);
    throw new HttpError(401, 'This request could not be verified.');
  }
}

app.post('/analyze', async (c) => {
  const request = c.req.raw;
  const { userId, bypassed } = await authenticate(request);

  const declared = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > config.limits.maxImageBytes * 2) {
    throw new HttpError(413, 'That photo is too large.');
  }

  // Read the bytes exactly as sent: App Attest signs these, so re-serializing the
  // parsed JSON would invalidate every genuine assertion.
  const rawBody = Buffer.from(await request.arrayBuffer());
  if (rawBody.length > config.limits.maxImageBytes * 2) {
    throw new HttpError(413, 'That photo is too large.');
  }

  if (config.gates.requireAttest && !bypassed) {
    await enforceAttestation(request, rawBody, userId);
  }

  if (config.gates.requireSubscription && !bypassed) {
    const jws = request.headers.get('x-subscription-jws');
    if (!jws) throw new HttpError(402, 'Diabeto Pro is required for photo analysis.');
    try {
      await verifySubscriptionJws(jws);
    } catch (error) {
      if (error instanceof SubscriptionError) throw new HttpError(402, 'Your Diabeto Pro subscription is not active.');
      throw error;
    }
  }

  const limit = await limitUser(userId);
  if (!limit.ok) {
    // The client renders its own message for 429, so this body is for machines.
    return c.json({ error: 'quota_exceeded', retryAfterSeconds: limit.retryAfterSeconds }, 429);
  }

  let parsed: { image?: unknown; scaleHint?: unknown };
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    throw new HttpError(400, "That photo couldn't be read.");
  }
  if (typeof parsed.image !== 'string' || !parsed.image) {
    throw new HttpError(400, "That photo couldn't be read.");
  }

  // Decoded size is derivable from the base64 length, so an oversized image is
  // rejected before allocating a buffer for it.
  const padding = parsed.image.endsWith('==') ? 2 : parsed.image.endsWith('=') ? 1 : 0;
  if (Math.floor((parsed.image.length * 3) / 4) - padding > config.limits.maxImageBytes) {
    throw new HttpError(413, 'That photo is too large.');
  }

  const bytes = Buffer.from(parsed.image, 'base64');
  if (bytes.length === 0) throw new HttpError(400, "That photo couldn't be read.");
  if (bytes.length > config.limits.maxImageBytes) throw new HttpError(413, 'That photo is too large.');
  if (!(bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff)) {
    throw new HttpError(400, "That photo couldn't be read.");
  }
  // Re-encode so what we validated is exactly what goes upstream.
  const imageBase64 = bytes.toString('base64');
  const scaleHint = typeof parsed.scaleHint === 'string' && parsed.scaleHint.trim() ? parsed.scaleHint.trim() : null;

  const controller = new AbortController();
  let timedOut = false;
  const deadline = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, config.limits.analyzeDeadlineMs);

  try {
    const { foods, usage } = await decompose(imageBase64, scaleHint, controller.signal);

    // Parallel, order-preserving: the response array must line up with the
    // decomposed foods the model returned.
    const entries = await Promise.all(
      foods.map(async (food) => ({
        food,
        macros: await macrosFor(food.name, food.grams, controller.signal),
      })),
    );

    // USDA stays the authority; the cheap model only fills the gaps it leaves.
    // Without this a food USDA can't match reports 0g carbs, which in a dosing
    // app reads as "no insulin needed" rather than "unknown".
    const gaps = entries.filter((entry) => !entry.macros.resolved);
    let fallbackUsage: { inputTokens: number; cachedInputTokens: number; outputTokens: number } | null = null;
    if (gaps.length > 0) {
      const estimate = await estimateMacros(
        gaps.map((entry) => entry.food.name),
        controller.signal,
      );
      fallbackUsage = estimate.usage;
      for (const entry of gaps) {
        const per100g = estimate.per100g.get(normalize(entry.food.name));
        if (per100g) entry.macros = { ...scaleMacros(per100g, entry.food.grams), resolved: true };
      }
    }

    // Metered on the tokens actually spent across both models, not just the
    // request, so a 12-food plate isn't accounted the same as a 2-food one.
    void recordUsage(userId, [
      { usage },
      ...(fallbackUsage ? [{ usage: fallbackUsage, rates: config.fallback }] : []),
    ]);

    return c.json({
      foods: entries.map(({ food, macros }) => ({
        name: food.name,
        grams: finite(food.grams, 1, config.limits.maxGramsPerFood),
        carbs: finite(macros.carbs, 1, config.limits.maxMacroGrams),
        protein: finite(macros.protein, 1, config.limits.maxMacroGrams),
        fat: finite(macros.fat, 1, config.limits.maxMacroGrams),
        confidence: finite(food.confidence, 2, 1),
      })),
    });
  } catch (error) {
    if (timedOut) throw new HttpError(504, 'That took too long to analyze. Please try again.');
    if (error instanceof DecomposeError) throw new HttpError(error.retryable ? 503 : 422, error.message);
    throw error;
  } finally {
    clearTimeout(deadline);
  }
});

// ---------------------------------------------------------------- plumbing

app.get('/', (c) => c.text('diabeto meal analysis backend'));

app.notFound((c) => c.text('Not found.', 404));

app.onError((error, c) => {
  if (error instanceof HttpError) return c.text(error.message, error.status);
  console.error('[unhandled]', error);
  return c.text('Something went wrong. Please try again.', 500);
});

// Vercel's Node runtime invokes functions with (req, res), not a web Request, so
// the Hono app is adapted to a Node request listener. hono/vercel's handle() is
// for Next.js route handlers and would hang here without ever writing a response.
export default getRequestListener(app.fetch);
export { app };
