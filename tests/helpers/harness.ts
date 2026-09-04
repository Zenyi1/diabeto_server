/**
 * Boots the real app against fake upstreams.
 *
 * Config is read once at module load, so anything that needs a different gate
 * configuration belongs in its own test file — `node --test` gives each file its
 * own process, which is exactly the isolation this needs.
 */

import { createHash, generateKeyPairSync, createPublicKey } from 'node:crypto';
import { SignJWT } from 'jose';
import type { Hono } from 'hono';
import { FakeUpstash } from './upstash-fake.js';
import { FakeOpenAi, FakeUsda } from './upstream-fake.js';

export const TEAM_ID = 'ABCDE12345';
export const BUNDLE_ID = 'com.zenyi.diabeto';
export const APP_ID = `${TEAM_ID}.${BUNDLE_ID}`;
export const DEV_BYPASS = 'dev-bypass-token-for-tests-only';
export const SESSION_SECRET = 'test-session-secret-at-least-32-chars-long';
export const PRODUCT_ID = 'com.zenyi.diabeto.pro.monthly';
export const ADMIN_TOKEN = 'admin-token-for-tests-at-least-32-chars';
export const GOOGLE_CLIENT_ID = '1234567890-testclient.apps.googleusercontent.com';

/** Smallest thing that passes the JPEG magic-byte check. */
export const JPEG = Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
  Buffer.alloc(64, 0x7f),
  Buffer.from([0xff, 0xd9]),
]);
export const IMAGE_BASE64 = JPEG.toString('base64');

export interface Harness {
  app: Hono;
  upstash: FakeUpstash;
  openai: FakeOpenAi;
  usda: FakeUsda;
  sessionFor(userId: string): Promise<string>;
  /** Registers a device key straight into the store, as if attestation had run. */
  seedKey(userId: string): Promise<{ keyId: string; privateKeyPem: string }>;
  reset(): void;
  stop(): Promise<void>;
}

export async function boot(overrides: Record<string, string> = {}): Promise<Harness> {
  const upstash = new FakeUpstash();
  const openai = new FakeOpenAi();
  const usda = new FakeUsda();

  const [redisUrl, openaiUrl, usdaUrl] = await Promise.all([upstash.start(), openai.start(), usda.start()]);

  Object.assign(process.env, {
    KV_REST_API_URL: redisUrl,
    KV_REST_API_TOKEN: 'test-token',
    OPENAI_API_KEY: 'sk-test-secret-key-do-not-leak',
    OPENAI_BASE_URL: openaiUrl,
    OPENAI_MODEL: 'test-model',
    OPENAI_FALLBACK_MODEL: 'test-fallback-model',
    OPENAI_REASONING_EFFORT: '',
    USDA_API_KEY: 'usda-test-key',
    USDA_BASE_URL: usdaUrl,
    APPLE_TEAM_ID: TEAM_ID,
    APPLE_BUNDLE_ID: BUNDLE_ID,
    SESSION_SECRET,
    SUBSCRIPTION_PRODUCT_IDS: PRODUCT_ID,
    APP_ATTEST_ENV: 'development',
    APP_STORE_ENV: 'sandbox',
    REQUIRE_ATTEST: 'true',
    REQUIRE_SUBSCRIPTION: 'false',
    DEV_BYPASS_TOKEN: DEV_BYPASS,
    ADMIN_TOKEN,
    GOOGLE_CLIENT_ID,
    RATE_LIMIT_PER_MIN: '5',
    RATE_LIMIT_PER_DAY: '1000',
    ...overrides,
  });

  // Imported only after env is in place — config evaluates at module load.
  const { app } = await import('../../api/index.js');
  const { redis, initAttestCounter } = await import('../../src/redis.js');

  return {
    app,
    upstash,
    openai,
    usda,

    async sessionFor(userId: string) {
      return new SignJWT({})
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject(userId)
        .setIssuer('diabeto-server')
        .setAudience('diabeto-app')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(new TextEncoder().encode(SESSION_SECRET));
    },

    async seedKey(userId: string) {
      const { privateKey, publicKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });
      const jwk = createPublicKey(privateKey).export({ format: 'jwk' }) as { x: string; y: string };
      const point = Buffer.concat([
        Buffer.from([0x04]),
        Buffer.from(jwk.x, 'base64url'),
        Buffer.from(jwk.y, 'base64url'),
      ]);
      const keyId = createHash('sha256').update(point).digest('base64');

      await redis().set(`attest:${keyId}`, {
        userId,
        publicKeyPem: publicKey,
        environment: 'development',
        createdAt: Date.now(),
      });
      await redis().sadd(`attestkeys:${userId}`, keyId);
      await initAttestCounter(keyId);
      return { keyId, privateKeyPem: privateKey };
    },

    reset() {
      openai.reset();
      usda.reset();
      // Also clears the USDA negative cache, which is keyed by food name and
      // would otherwise leak a miss from one test into the next.
      upstash.reset();
    },

    async stop() {
      await Promise.all([upstash.stop(), openai.stop(), usda.stop()]);
    },
  };
}

/** Unique per test so per-user rate limits never bleed between cases. */
let counter = 0;
export function freshUser(): string {
  return `user-${process.pid}-${counter++}`;
}
