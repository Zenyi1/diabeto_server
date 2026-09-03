/**
 * Fixed-window rate limiting on plain INCR/EXPIRE.
 *
 * The window is encoded in the key, so the counter and its expiry can never drift
 * apart and there is no read-modify-write to race. A fixed window can admit up to
 * 2x the limit across a boundary; for a "50 analyses a day" spend cap that is a
 * fine trade for having no Lua and no extra dependency.
 */

import { config } from './config.js';
import { redis } from './redis.js';

export interface RateLimitVerdict {
  ok: boolean;
  retryAfterSeconds: number;
}

const OK: RateLimitVerdict = { ok: true, retryAfterSeconds: 0 };

async function hit(prefix: string, id: string, limit: number, windowSeconds: number): Promise<RateLimitVerdict> {
  const windowMs = windowSeconds * 1000;
  const bucket = Math.floor(Date.now() / windowMs);
  const key = `${prefix}:${id}:${bucket}`;

  const count = await redis().incr(key);
  if (count === 1) {
    // Twice the window so a clock skew can't strand the key without a TTL.
    await redis().expire(key, windowSeconds * 2);
  }
  if (count > limit) {
    const msUntilNextBucket = (bucket + 1) * windowMs - Date.now();
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil(msUntilNextBucket / 1000)) };
  }
  return OK;
}

/**
 * Two windows per user: a burst cap and the daily quota that actually bounds the
 * OpenAI bill. Both are consumed on every call.
 */
export async function limitUser(userId: string): Promise<RateLimitVerdict> {
  const [minute, day] = await Promise.all([
    hit('rl:min', userId, config.limits.perMinute, 60),
    hit('rl:day', userId, config.limits.perDay, 86_400),
  ]);
  return minute.ok ? day : minute;
}

/** Guards /auth/apple, which is unauthenticated by nature. */
export async function limitIp(ip: string): Promise<RateLimitVerdict> {
  return hit('rl:ip', ip, 20, 3_600);
}
