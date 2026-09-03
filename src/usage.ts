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
  outputTokens: number;
}

export interface UsagePeriod {
  requests: number;
  inputTokens: number;
  outputTokens: number;
  /** Millionths of a dollar; zero unless OPENAI_*_USD_PER_MTOK are configured. */
  usdMicros: number;
}

const EMPTY: UsagePeriod = { requests: 0, inputTokens: 0, outputTokens: 0, usdMicros: 0 };

function monthKey(now: Date): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

function dayKey(now: Date): string {
  return `${monthKey(now)}-${String(now.getUTCDate()).padStart(2, '0')}`;
}

function usdMicrosFor(usage: TokenUsage): number {
  const input = (usage.inputTokens / 1_000_000) * config.pricing.inputUsdPerMillion;
  const output = (usage.outputTokens / 1_000_000) * config.pricing.outputUsdPerMillion;
  return Math.round((input + output) * 1_000_000);
}

/**
 * Records one completed analysis. Never throws — losing a usage counter must not
 * cost the user a result they already paid for in tokens.
 */
export async function recordUsage(userId: string, usage: TokenUsage, now = new Date()): Promise<void> {
  const cost = usdMicrosFor(usage);
  const fields: [string, number][] = [
    ['requests', 1],
    ['inputTokens', usage.inputTokens],
    ['outputTokens', usage.outputTokens],
    ['usdMicros', cost],
  ];

  try {
    const client = redis();
    await Promise.all(
      [`usage:${userId}:${monthKey(now)}`, `usage:${userId}:${dayKey(now)}`].flatMap((key) =>
        fields.map(([field, amount]) => client.hincrby(key, field, amount)),
      ),
    );
    // Daily rows are only interesting for a while; monthly rows are the record.
    await client.expire(`usage:${userId}:${dayKey(now)}`, 60 * 60 * 24 * 90);
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
    outputTokens: read('outputTokens'),
    usdMicros: read('usdMicros'),
  };
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
