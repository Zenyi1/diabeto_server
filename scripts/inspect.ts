/**
 * Reads the live datastore and prints what is actually in it.
 *
 * There is no SQL database — identity and metering live in Redis, so this is the
 * "users table". Run it against production with `npm run users`.
 *
 * Usage:
 *   npm run users            # summary + one row per user
 *   npm run users -- --keys  # also list every attest key and raw key namespace
 */

import { readFileSync } from 'node:fs';

for (const file of ['.env.local', '.env']) {
  try {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^"|"$/g, '');
    }
  } catch {
    // Optional: whichever file exists is enough.
  }
}

const { redis } = await import('../src/redis.js');
const client = redis();

async function scanAll(pattern: string): Promise<string[]> {
  const found: string[] = [];
  let cursor = '0';
  do {
    const [next, batch] = await client.scan(cursor, { match: pattern, count: 500 });
    cursor = String(next);
    found.push(...batch);
  } while (cursor !== '0');
  return found;
}

function isoDay(value: unknown): string {
  const ms = Number(value);
  return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString().slice(0, 10) : '—';
}

const month = new Date().toISOString().slice(0, 7);
const userKeys = await scanAll('user:*');

console.log(`\nstore: ${process.env.KV_REST_API_URL?.replace(/https:\/\//, '').slice(0, 30) ?? 'unknown'}…`);
console.log(`users: ${userKeys.length}\n`);

if (userKeys.length === 0) {
  console.log('No users yet. /auth/apple is the only thing that creates one, and Sign in');
  console.log('with Apple needs a paid Apple Developer Program membership to work at all.\n');
} else {
  const rows = await Promise.all(
    userKeys.map(async (key) => {
      const appleSub = key.slice('user:'.length);
      const [record, devices, usage] = await Promise.all([
        client.get<Record<string, unknown>>(key),
        client.smembers(`attestkeys:${appleSub}`),
        client.hgetall<Record<string, unknown>>(`usage:${appleSub}:${month}`),
      ]);
      return {
        'apple sub': appleSub.length > 28 ? `${appleSub.slice(0, 25)}…` : appleSub,
        email: (record?.email as string) ?? '—',
        created: isoDay(record?.createdAt),
        'last seen': isoDay(record?.lastSeenAt),
        devices: devices.length,
        [`requests (${month})`]: Number(usage?.requests ?? 0),
        tokens: Number(usage?.inputTokens ?? 0) + Number(usage?.outputTokens ?? 0),
        'usd': (Number(usage?.usdMicros ?? 0) / 1_000_000).toFixed(4),
      };
    }),
  );
  console.table(rows);
}

if (process.argv.includes('--keys')) {
  const namespaces: Record<string, string> = {
    'user:*': 'account record (apple sub, name, email, timestamps)',
    'attest:*': 'App Attest public key per device',
    'attestkeys:*': "each user's set of device key ids",
    'challenge:*': 'one-time attest challenges (5 min TTL)',
    'revoked:*': 'session revocation markers from account deletion',
    'usage:*': 'per-user monthly and daily metering',
    'rl:*': 'rate-limit counters',
    'usda:*': 'cached nutrition lookups',
  };
  console.log('key namespaces:\n');
  for (const [pattern, description] of Object.entries(namespaces)) {
    const keys = await scanAll(pattern);
    console.log(`  ${pattern.padEnd(14)} ${String(keys.length).padStart(5)}  ${description}`);
  }
  console.log();
}
