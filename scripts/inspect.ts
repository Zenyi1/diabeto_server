/**
 * Prints who is registered and what they have cost.
 *
 * Reads the same O(1) roll-up counters the /admin routes serve, so it stays fast
 * no matter how many users exist — there is no scan over the keyspace.
 *
 *   npm run users              # totals + the 25 most recent signups
 *   npm run users -- --all     # every user, paged
 */

import { readFileSync } from 'node:fs';

for (const file of ['.env.local', '.env']) {
  try {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const match = line.match(/^([A-Z0-9_]+)=(.*)$/);
      if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^"|"$/g, '');
    }
  } catch {
    // Whichever of the two exists is enough.
  }
}

const { readGlobalStats, listUsers, readUsage } = await import('../src/usage.js');
const { redis } = await import('../src/redis.js');

const usd = (micros: number) => `$${(micros / 1_000_000).toFixed(4)}`;
const day = (value: unknown) => {
  const ms = Number(value);
  return Number.isFinite(ms) && ms > 0 ? new Date(ms).toISOString().slice(0, 10) : '—';
};

const stats = await readGlobalStats();

console.log(`\n  users            ${stats.users}`);
console.log(`  period           ${stats.period}\n`);
console.log(`  this month       ${stats.month.requests} analyses · ${usd(stats.month.usdMicros)}`);
console.log(`  today            ${stats.today.requests} analyses · ${usd(stats.today.usdMicros)}`);
if (stats.month.requests > 0) {
  console.log(`  avg per analysis ${usd(Math.round(stats.month.usdMicros / stats.month.requests))}`);
}
console.log();

if (stats.users === 0) {
  console.log('  No users yet. Only POST /auth/apple creates one, and Sign in with Apple');
  console.log('  needs a paid Apple Developer Program membership to work at all.\n');
} else {
  const pageSize = process.argv.includes('--all') ? 200 : 25;
  const ids = await listUsers(pageSize, 0);
  const rows = await Promise.all(
    ids.map(async (id) => {
      const [record, devices, usage] = await Promise.all([
        redis().get<Record<string, unknown>>(`user:${id}`),
        redis().scard(`attestkeys:${id}`),
        readUsage(id),
      ]);
      return {
        user: id.length > 26 ? `${id.slice(0, 23)}…` : id,
        email: (record?.email as string) ?? '—',
        joined: day(record?.createdAt),
        seen: day(record?.lastSeenAt),
        devices,
        analyses: usage.month.requests,
        cost: usd(usage.month.usdMicros),
      };
    }),
  );
  console.table(rows);
  if (stats.users > ids.length) {
    console.log(`  showing ${ids.length} of ${stats.users}${pageSize < 200 ? ' — pass --all for more' : ''}\n`);
  }
}
