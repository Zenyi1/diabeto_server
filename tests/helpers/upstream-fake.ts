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
}

export class FakeOpenAi {
  private server: Server | null = null;
  behaviour: OpenAiBehaviour = { foods: [] };

  /** Bodies of every request received, for asserting on prompt construction. */
  readonly requests: Record<string, unknown>[] = [];

  async start(): Promise<string> {
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', async () => {
        try {
          this.requests.push(JSON.parse(body));
        } catch {
          this.requests.push({ unparseable: body.slice(0, 200) });
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

  /** Per-100g macros keyed by lowercase query. Absent = a USDA miss. */
  readonly foods = new Map<string, { protein: number; fat: number; carbs: number }>();
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

      const match = this.foods.get(query);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          foods: match
            ? [
                {
                  foodNutrients: [
                    { nutrientId: 1003, nutrientName: 'Protein', value: match.protein },
                    { nutrientId: 1004, nutrientName: 'Total lipid (fat)', value: match.fat },
                    { nutrientId: 1005, nutrientName: 'Carbohydrate, by difference', value: match.carbs },
                  ],
                },
              ]
            : [],
        }),
      );
    });

    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}/fdc/v1`;
  }

  reset(): void {
    this.foods.clear();
    this.status = 200;
    this.delayMs = 0;
    this.queries = [];
  }

  async stop(): Promise<void> {
    if (this.server) await new Promise((resolve) => this.server!.close(resolve));
    this.server = null;
  }
}
