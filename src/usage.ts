/**
 * Per-user metering.
 *
 * Requests alone don't track cost — a two-food photo and a twelve-food photo
 * differ a lot — so token counts are recorded alongside, and turned into spend
 * when per-token rates are configured. Counters are incremented with INCRBY so
 * concurrent requests can't lose a write.
 */

import { config } from './config.js';
import { redis } from './redis.js';

export interface TokenUsage {
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
}

export interface UsagePeriod {
  requests: number;
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  /** Millionths of a dollar, so spend accumulates as an exact integer. */
  usdMicros: number;
}

const EMPTY: UsagePeriod = {
  requests: 0,
  inputTokens: 0,
  cachedInputTokens: 0,
  outputTokens: 0,
  usdMicros: 0,
};

/**
 * Sorted set of every registered user, scored by signup time.
 *
 * Exists so the admin views can count and page users with ZCARD/ZRANGE instead
 * of SCANning the keyspace — the difference between an instant answer and one
 * that degrades with every signup.
 */
export const USER_INDEX = 'users:index';

/** Registers a user in the index. Idempotent. */
export async function indexUser(userId: string, createdAt: number): Promise<void> {
  await redis().zadd(USER_INDEX, { score: createdAt, member: userId });
}

export async function unindexUser(userId: string): Promise<void> {
  await redis().zrem(USER_INDEX, userId);
}

/** Most recent signups first. */
export async function listUsers(limit: number, offset: number): Promise<string[]> {
  return redis().zrange<string[]>(USER_INDEX, offset, offset + limit - 1, { rev: true });
}

function monthKey(now: Date): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

function dayKey(now: Date): string {
  return `${monthKey(now)}-${String(now.getUTCDate()).padStart(2, '0')}`;
}

export interface TokenRates {
  inputUsdPerMillion: number;
  outputUsdPerMillion: number;
  cachedInputUsdPerMillion: number;
}

/**
 * Rates are passed in rather than read from config, because a single analysis can
 * bill against two models — the vision pass and the cheap macro fallback.
 */
export function usdMicrosFor(usage: TokenUsage, rates: TokenRates = config.pricing): number {
  // OpenAI reports cached tokens as a subset of prompt_tokens, so the uncached
  // remainder is what bills at the full input rate.
  const uncached = Math.max(0, usage.inputTokens - usage.cachedInputTokens);
  const dollars =
    (uncached / 1_000_000) * rates.inputUsdPerMillion +
    (usage.cachedInputTokens / 1_000_000) * rates.cachedInputUsdPerMillion +
    (usage.outputTokens / 1_000_000) * rates.outputUsdPerMillion;
  return Math.round(dollars * 1_000_000);
}

/**
 * Records one completed analysis, against the user and against a global roll-up.
 *
 * The roll-up is the part that scales: total spend is one HGETALL no matter how
 * many users exist, instead of a scan that gets slower every signup.
 *
 * Never throws — losing a counter must not cost a result already paid for.
 */
export async function recordUsage(
  userId: string,
  calls: { usage: TokenUsage; rates?: TokenRates }[],
  now = new Date(),
): Promise<void> {
  const total = calls.reduce(
    (sum, call) => ({
      inputTokens: sum.inputTokens + call.usage.inputTokens,
      cachedInputTokens: sum.cachedInputTokens + call.usage.cachedInputTokens,
      outputTokens: sum.outputTokens + call.usage.outputTokens,
      usdMicros: sum.usdMicros + usdMicrosFor(call.usage, call.rates ?? config.pricing),
    }),
    { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0, usdMicros: 0 },
  );

  const fields: [string, number][] = [
    // One analysis, however many model calls it took.
    ['requests', 1],
    ['inputTokens', total.inputTokens],
    ['cachedInputTokens', total.cachedInputTokens],
    ['outputTokens', total.outputTokens],
    ['usdMicros', total.usdMicros],
  ];

  const perUserDay = `usage:${userId}:${dayKey(now)}`;
  const targets = [`usage:${userId}:${monthKey(now)}`, perUserDay, `stats:${monthKey(now)}`, `stats:${dayKey(now)}`];

  try {
    const client = redis();
    await Promise.all(
      targets.flatMap((key) => fields.map(([field, amount]) => client.hincrby(key, field, amount))),
    );
    // Daily rows are only interesting for a while; monthly rows are the record.
    await Promise.all([
      client.expire(perUserDay, 60 * 60 * 24 * 90),
      client.expire(`stats:${dayKey(now)}`, 60 * 60 * 24 * 400),
    ]);
  } catch (error) {
    console.warn('[usage] failed to record:', error);
  }
}

function toPeriod(raw: Record<string, unknown> | null): UsagePeriod {
  if (!raw) return EMPTY;
  const read = (field: keyof UsagePeriod) => Number(raw[field] ?? 0) || 0;
  return {
    requests: read('requests'),
    inputTokens: read('inputTokens'),
    cachedInputTokens: read('cachedInputTokens'),
    outputTokens: read('outputTokens'),
    usdMicros: read('usdMicros'),
  };
}

/**
 * Whole-service totals plus the registered-user count.
 *
 * Deliberately O(1): four key reads regardless of how many users exist, so this
 * stays a live number rather than a scan that degrades as the app grows.
 */
export async function readGlobalStats(now = new Date()): Promise<{
  users: number;
  month: UsagePeriod;
  today: UsagePeriod;
  period: string;
}> {
  const client = redis();
  const [users, month, today] = await Promise.all([
    client.zcard(USER_INDEX),
    client.hgetall<Record<string, unknown>>(`stats:${monthKey(now)}`),
    client.hgetall<Record<string, unknown>>(`stats:${dayKey(now)}`),
  ]);
  return { users, month: toPeriod(month), today: toPeriod(today), period: monthKey(now) };
}

export async function readUsage(
  userId: string,
  now = new Date(),
): Promise<{ month: UsagePeriod; today: UsagePeriod }> {
  try {
    const client = redis();
    const [month, today] = await Promise.all([
      client.hgetall<Record<string, unknown>>(`usage:${userId}:${monthKey(now)}`),
      client.hgetall<Record<string, unknown>>(`usage:${userId}:${dayKey(now)}`),
    ]);
    return { month: toPeriod(month), today: toPeriod(today) };
  } catch (error) {
    console.warn('[usage] failed to read:', error);
    return { month: EMPTY, today: EMPTY };
  }
}

/** Wipes every usage row for a user, for account deletion. */
export async function deleteUsage(userId: string, now = new Date()): Promise<void> {
  const keys = [`usage:${userId}:${monthKey(now)}`, `usage:${userId}:${dayKey(now)}`];
  // Previous months age out on their own; the current period is what a deletion
  // must not leave behind.
  try {
    await redis().del(...keys);
  } catch (error) {
    console.warn('[usage] failed to delete:', error);
  }
}
