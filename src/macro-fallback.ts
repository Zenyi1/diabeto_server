/**
 * Rescue macros for foods USDA cannot price.
 *
 * A silent zero is the dangerous failure in a dosing app: "pad thai → 0g carbs"
 * reads as "no insulin needed". USDA stays the authority, and this only fills the
 * gaps it leaves — in one batched call to a model ~25x cheaper than the vision
 * pass, with results cached per food name so a repeat meal costs nothing.
 */

import { config } from './config.js';
import { redis } from './redis.js';
import type { Macros } from './usda.js';

export interface MacroEstimates {
  /** Per-100g values keyed by the normalized food name. */
  per100g: Map<string, Macros>;
  usage: { inputTokens: number; cachedInputTokens: number; outputTokens: number };
}

const NO_USAGE = { inputTokens: 0, cachedInputTokens: 0, outputTokens: 0 };

const SYSTEM_PROMPT =
  'You are a nutrition reference. For each food name, give the macronutrients per 100 g of ' +
  'edible portion, as prepared and typically eaten. Use your best estimate of a standard ' +
  'preparation. Return grams per 100 g, never per serving.';

const SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['foods'],
  properties: {
    foods: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'carbs', 'protein', 'fat'],
        properties: {
          name: { type: 'string', description: 'Echo the food name exactly as given' },
          carbs: { type: 'number', description: 'Grams of carbohydrate per 100g' },
          protein: { type: 'number', description: 'Grams of protein per 100g' },
          fat: { type: 'number', description: 'Grams of fat per 100g' },
        },
      },
    },
  },
} as const;

export function normalize(name: string): string {
  return name.toLowerCase().replace(/\s+/g, ' ').trim();
}

const cacheKey = (name: string) => `est:${normalize(name)}`;

function clean(value: unknown): number {
  const number = Number(value);
  // Nothing edible exceeds 100g of one macro per 100g.
  return Number.isFinite(number) && number >= 0 ? Math.min(number, 100) : 0;
}

/** Never throws: an unrescued food simply keeps its zeros. */
export async function estimateMacros(names: string[], signal: AbortSignal): Promise<MacroEstimates> {
  const per100g = new Map<string, Macros>();
  const wanted = [...new Set(names.map(normalize))].filter(Boolean);
  if (wanted.length === 0) return { per100g, usage: NO_USAGE };

  const missing: string[] = [];
  await Promise.all(
    wanted.map(async (name) => {
      try {
        const cached = await redis().get<Macros>(cacheKey(name));
        if (cached && typeof cached.carbs === 'number') per100g.set(name, cached);
        else missing.push(name);
      } catch {
        missing.push(name);
      }
    }),
  );
  if (missing.length === 0) return { per100g, usage: NO_USAGE };

  let response: Response;
  try {
    response = await fetch(`${config.openai.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.openai.apiKey}` },
      body: JSON.stringify({
        model: config.fallback.model,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: `Macronutrients per 100 g for:\n${missing.join('\n')}` },
        ],
        response_format: {
          type: 'json_schema',
          json_schema: { name: 'macros', strict: true, schema: SCHEMA },
        },
      }),
      signal: AbortSignal.any([signal, AbortSignal.timeout(config.openai.timeoutMs)]),
    });
  } catch (error) {
    console.warn('[macro-fallback] request failed:', error);
    return { per100g, usage: NO_USAGE };
  }

  if (!response.ok) {
    console.warn('[macro-fallback] HTTP', response.status, (await response.text()).slice(0, 200));
    return { per100g, usage: NO_USAGE };
  }

  const payload = (await response.json()) as {
    choices?: { message?: { content?: string } }[];
    usage?: { prompt_tokens?: number; completion_tokens?: number; prompt_tokens_details?: { cached_tokens?: number } };
  };
  const usage = {
    inputTokens: Number(payload.usage?.prompt_tokens) || 0,
    cachedInputTokens: Number(payload.usage?.prompt_tokens_details?.cached_tokens) || 0,
    outputTokens: Number(payload.usage?.completion_tokens) || 0,
  };

  let parsed: { foods?: unknown };
  try {
    parsed = JSON.parse(payload.choices?.[0]?.message?.content ?? '');
  } catch {
    console.warn('[macro-fallback] unparseable content');
    return { per100g, usage };
  }
  if (!Array.isArray(parsed.foods)) return { per100g, usage };

  await Promise.all(
    parsed.foods.map(async (raw) => {
      const item = raw as { name?: unknown; carbs?: unknown; protein?: unknown; fat?: unknown };
      if (typeof item.name !== 'string') return;
      const key = normalize(item.name);
      // Only accept names we actually asked about, so a stray row can't inject a
      // food the user never photographed.
      if (!missing.includes(key)) return;

      const macros: Macros = { carbs: clean(item.carbs), protein: clean(item.protein), fat: clean(item.fat) };
      per100g.set(key, macros);
      try {
        await redis().set(cacheKey(key), macros, { ex: config.usda.cacheTtlSeconds });
      } catch {
        // Cache is an optimisation; the estimate is already in hand.
      }
    }),
  );

  return { per100g, usage };
}
