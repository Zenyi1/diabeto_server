/**
 * An in-memory server that speaks Upstash's REST protocol.
 *
 * Tests point UPSTASH_REDIS_REST_URL at this, so the real `@upstash/redis` client
 * and the real production code paths are exercised end to end — no module
 * mocking, no test seams in src/, and no network.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/** Distinct subclasses so a sorted set and a hash can't be confused for each other. */
class ZSet extends Map<string, number> {}
class HashMap extends Map<string, number> {}

interface Entry {
  value: string | Set<string> | ZSet | HashMap;
  expiresAt?: number;
}

export class FakeUpstash {
  private readonly store = new Map<string, Entry>();
  private server: Server | null = null;

  /** Every command the server received, for asserting on access patterns. */
  readonly commands: string[][] = [];

  private live(key: string): Entry | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt !== undefined && entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return entry;
  }

  private run(command: unknown[]): unknown {
    const parts = command.map((part) => String(part));
    this.commands.push(parts);
    const [name, key, ...rest] = parts;

    switch (name.toLowerCase()) {
      case 'get': {
        const entry = this.live(key);
        return typeof entry?.value === 'string' ? entry.value : null;
      }
      case 'set': {
        const value = rest[0];
        let expiresAt: number | undefined;
        for (let i = 1; i < rest.length - 1; i++) {
          if (rest[i].toLowerCase() === 'ex') expiresAt = Date.now() + Number(rest[i + 1]) * 1000;
          if (rest[i].toLowerCase() === 'px') expiresAt = Date.now() + Number(rest[i + 1]);
        }
        this.store.set(key, { value, expiresAt });
        return 'OK';
      }
      case 'getdel': {
        const entry = this.live(key);
        this.store.delete(key);
        return typeof entry?.value === 'string' ? entry.value : null;
      }
      case 'del': {
        let removed = 0;
        for (const target of [key, ...rest]) if (this.store.delete(target)) removed++;
        return removed;
      }
      case 'incr': {
        const entry = this.live(key);
        const next = (entry && typeof entry.value === 'string' ? Number(entry.value) : 0) + 1;
        this.store.set(key, { value: String(next), expiresAt: entry?.expiresAt });
        return next;
      }
      case 'expire': {
        const entry = this.live(key);
        if (!entry) return 0;
        entry.expiresAt = Date.now() + Number(rest[0]) * 1000;
        return 1;
      }
      case 'ttl': {
        const entry = this.live(key);
        if (!entry) return -2;
        if (entry.expiresAt === undefined) return -1;
        return Math.ceil((entry.expiresAt - Date.now()) / 1000);
      }
      case 'sadd': {
        const entry = this.live(key);
        const set = entry?.value instanceof Set ? entry.value : new Set<string>();
        let added = 0;
        for (const member of rest) if (!set.has(member)) (set.add(member), added++);
        this.store.set(key, { value: set, expiresAt: entry?.expiresAt });
        return added;
      }
      case 'scard': {
        const entry = this.live(key);
        return entry?.value instanceof Set ? entry.value.size : 0;
      }
      case 'smembers': {
        const entry = this.live(key);
        return entry?.value instanceof Set ? [...entry.value] : [];
      }
      case 'zrem': {
        const entry = this.live(key);
        if (!(entry?.value instanceof ZSet)) return 0;
        let removed = 0;
        for (const member of rest) if (entry.value.delete(member)) removed++;
        return removed;
      }
      case 'srem': {
        const entry = this.live(key);
        if (!(entry?.value instanceof Set)) return 0;
        let removed = 0;
        for (const member of rest) if (entry.value.delete(member)) removed++;
        return removed;
      }
      case 'hincrby': {
        const entry = this.live(key);
        const hash = entry?.value instanceof HashMap ? entry.value : new HashMap();
        const next = (hash.get(rest[0]) ?? 0) + Number(rest[1]);
        hash.set(rest[0], next);
        this.store.set(key, { value: hash, expiresAt: entry?.expiresAt });
        return next;
      }
      case 'hgetall': {
        const entry = this.live(key);
        if (!(entry?.value instanceof HashMap)) return null;
        // Redis answers with a flat field/value list; the client pairs it up.
        return [...entry.value].flatMap(([field, value]) => [field, String(value)]);
      }
      case 'zadd': {
        const entry = this.live(key);
        const zset = entry?.value instanceof ZSet ? entry.value : new ZSet();

        let index = 0;
        let gt = false;
        let ch = false;
        while (index < rest.length && /^(gt|lt|nx|xx|ch|incr)$/i.test(rest[index])) {
          const flag = rest[index].toLowerCase();
          if (flag === 'gt') gt = true;
          if (flag === 'ch') ch = true;
          index++;
        }

        let changed = 0;
        let added = 0;
        for (; index + 1 < rest.length; index += 2) {
          const score = Number(rest[index]);
          const member = rest[index + 1];
          const current = zset.get(member);
          if (current === undefined) {
            zset.set(member, score);
            added++;
            changed++;
          } else if (!gt || score > current) {
            if (current !== score) changed++;
            zset.set(member, score);
          }
        }
        this.store.set(key, { value: zset, expiresAt: entry?.expiresAt });
        return ch ? changed : added;
      }
      case 'zscore': {
        const entry = this.live(key);
        if (!(entry?.value instanceof ZSet)) return null;
        const score = entry.value.get(rest[0]);
        return score === undefined ? null : String(score);
      }
      case 'flushall': {
        this.store.clear();
        return 'OK';
      }
      default:
        throw new Error(`FakeUpstash: unsupported command ${name}`);
    }
  }

  /** Upstash base64-encodes string results when the client asks for it. */
  private encode(result: unknown, base64: boolean): unknown {
    if (!base64 || result === null) return result;
    if (typeof result === 'string') return Buffer.from(result, 'utf8').toString('base64');
    if (Array.isArray(result)) return result.map((item) => this.encode(item, true));
    return result;
  }

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        const base64 = req.headers['upstash-encoding'] === 'base64';
        const respond = (payload: unknown) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify(payload));
        };
        try {
          const parsed = JSON.parse(body || '[]');
          if (req.url?.includes('pipeline') || req.url?.includes('multi-exec')) {
            respond((parsed as unknown[][]).map((cmd) => ({ result: this.encode(this.run(cmd), base64) })));
          } else {
            respond({ result: this.encode(this.run(parsed as unknown[]), base64) });
          }
        } catch (error) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: (error as Error).message }));
        }
      });
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    const { port } = this.server!.address() as AddressInfo;
    return `http://127.0.0.1:${port}`;
  }

  reset(): void {
    this.store.clear();
    this.commands.length = 0;
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise((resolve) => this.server!.close(resolve));
    this.server = null;
  }
}
