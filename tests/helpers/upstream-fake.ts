/**
 * Stand-ins for OpenAI and USDA.
 *
 * Real HTTP servers rather than stubbed functions, so the production fetch paths
 * — timeouts, aborts, non-2xx handling, JSON parsing — are all genuinely
 * exercised. Tests point OPENAI_BASE_URL / USDA_BASE_URL at these.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface OpenAiBehaviour {
  status?: number;
  /** Raw body to return, bypassing the canned success shape. */
  body?: string;
  /** Foods the model "sees". Sent through the strict-schema content envelope. */
  foods?: unknown[];
  refusal?: string;
  /** Delay before responding, for deadline tests. */
  delayMs?: number;
  /** Token counts, as OpenAI reports them. Defaults to a realistic pair. */
  usage?: { prompt_tokens: number; completion_tokens: number };
  /**
   * Answer for the cheap macro-fallback call, matched by model name. Per-100g
   * rows: `[{ name, carbs, protein, fat }]`. Empty means the rescue finds nothing.
   */
  fallbackFoods?: unknown[];
  /** Token counts for the fallback call specifically. */
  fallbackUsage?: { prompt_tokens: number; completion_tokens: number };
}

export class FakeOpenAi {
  private server: Server | null = null;
  behaviour: OpenAiBehaviour = { foods: [] };

  /** Model name that should be answered with macro estimates rather than foods. */
  fallbackModel = 'test-fallback-model';

  /** Bodies of every request received, for asserting on prompt construction. */
  readonly requests: Record<string, unknown>[] = [];

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        let parsed: Record<string, unknown> = {};
        try {
          parsed = JSON.parse(body);
          this.requests.push(parsed);
        } catch {
          this.requests.push({ unparseable: body.slice(0, 200) });
        }

        // The macro rescue hits the same endpoint with a different model.
        if (parsed.model === this.fallbackModel) {
          res.writeHead(200, { 'content-type': 'application/json' });
          return res.end(
            JSON.stringify({
              choices: [{ message: { content: JSON.stringify({ foods: this.behaviour.fallbackFoods ?? [] }) } }],
              usage: this.behaviour.fallbackUsage ?? { prompt_tokens: 40, completion_tokens: 30 },
            }),
          );
        }

        const behaviour = this.behaviour;
        if (behaviour.delayMs) await new Promise((resolve) => setTimeout(resolve, behaviour.delayMs));
        if (res.destroyed) return;

        const status = behaviour.status ?? 200;
        res.writeHead(status, { 'content-type': 'application/json' });

        if (behaviour.body !== undefined) return res.end(behaviour.body);
        if (status !== 200) return res.end(JSON.stringify({ error: { message: 'upstream failure' } }));

        res.end(
          JSON.stringify({
            choices: [
              {
                message: behaviour.refusal
                  ? { refusal: behaviour.refusal }
                  : { content: JSON.stringify({ foods: behaviour.foods ?? [] }) },
              },
            ],
            usage: behaviour.usage ?? { prompt_tokens: 308, completion_tokens: 121 },
          }),
        );
      });
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}/v1`;
  }

  reset(): void {
    this.behaviour = { foods: [] };
    this.requests.length = 0;
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise((resolve) => this.server!.close(resolve));
    this.server = null;
  }
}

export class FakeUsda {
  private server: Server | null = null;

  /**
   * Single-hit shortcut: per-100g macros keyed by lowercase query, described by
   * the query itself so it scores as an exact match. Absent = a USDA miss.
   */
  readonly foods = new Map<string, { protein: number; fat: number; carbs: number }>();

  /**
   * Full search results, for exercising the match scorer — USDA's top hit is
   * often a different food that merely shares a word.
   */
  readonly candidates = new Map<
    string,
    { description: string; protein: number; fat: number; carbs: number }[]
  >();

  status = 200;
  delayMs = 0;
  queries: string[] = [];

  async start(): Promise<string> {
    this.server = createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const query = (url.searchParams.get('query') ?? '').toLowerCase();
      this.queries.push(query);

      if (this.delayMs) await new Promise((resolve) => setTimeout(resolve, this.delayMs));
      if (res.destroyed) return;

      if (this.status !== 200) {
        res.writeHead(this.status, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: 'usda failure' }));
      }

      const simple = this.foods.get(query);
      const rows =
        this.candidates.get(query) ?? (simple ? [{ description: query, ...simple }] : []);

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          foods: rows.map((row) => ({
            description: row.description,
            foodNutrients: [
              { nutrientId: 1003, nutrientName: 'Protein', value: row.protein },
              { nutrientId: 1004, nutrientName: 'Total lipid (fat)', value: row.fat },
              { nutrientId: 1005, nutrientName: 'Carbohydrate, by difference', value: row.carbs },
            ],
          })),
        }),
      );
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}/fdc/v1`;
  }

  reset(): void {
    this.foods.clear();
    this.candidates.clear();
    this.status = 200;
    this.delayMs = 0;
    this.queries = [];
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise((resolve) => this.server!.close(resolve));
    this.server = null;
  }
}
