import { Redis } from '@upstash/redis';
import { config } from './config.js';

let client: Redis | null = null;

/**
 * Lazy so a missing Upstash binding surfaces as a 503 from the route rather than
 * a module-load crash that turns every response into an opaque 500.
 */
export function redis(): Redis {
  client ??= new Redis({ url: config.redis.url, token: config.redis.token });
  return client;
}

/** Sorted set holding the last-seen App Attest signature counter per key id. */
const COUNTER_SET = 'attest:counters';

/**
 * Apple's replay defence is a strictly increasing counter, which only holds if
 * two concurrent requests can't both read the same value and both win.
 *
 * `ZADD ... GT CH` is that compare-and-set as a single Redis primitive: it moves
 * the score only when the new value is greater, and reports whether it did. No
 * Lua, no read-modify-write race.
 *
 * @returns true when `next` beat the stored counter and was persisted
 */
export async function bumpAttestCounter(keyId: string, next: number): Promise<boolean> {
  const changed = await redis().zadd(COUNTER_SET, { gt: true, ch: true }, { score: next, member: keyId });
  return changed === 1;
}

/**
 * Seeds a newly registered key at zero. Uses GT so re-registering an existing key
 * id can never rewind its counter and reopen the replay window.
 */
export async function initAttestCounter(keyId: string): Promise<void> {
  await redis().zadd(COUNTER_SET, { gt: true, ch: true }, { score: 0, member: keyId });
}
