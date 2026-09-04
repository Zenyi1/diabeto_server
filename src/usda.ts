/**
 * Step 2 of the pipeline: per-100g macros from USDA FoodData Central.
 *
 * A lookup failure returns zeros rather than failing the whole analysis — losing
 * one item's macros is better than losing the meal. Results are cached per
 * normalized food name, which is what keeps the N lookups off the critical path
 * on repeat meals.
 */

import { config } from './config.js';
import { redis } from './redis.js';

export interface Macros {
  carbs: number;
  protein: number;
  fat: number;
}

export interface MacroLookup extends Macros {
  /** False when USDA had no match or was unreachable — the caller should rescue it. */
  resolved: boolean;
}

const ZERO: Macros = { carbs: 0, protein: 0, fat: 0 };

/** All-zero means USDA gave us nothing usable, whatever the HTTP status said. */
function isEmpty(macros: Macros): boolean {
  return macros.carbs === 0 && macros.protein === 0 && macros.fat === 0;
}

/** Words that describe preparation or portion rather than the food itself. */
const NOISE = new Set([
  'raw', 'whole', 'medium', 'large', 'small', 'fresh', 'cooked', 'prepared', 'plain',
  'serving', 'piece', 'slice', 'slices', 'with', 'and', 'the', 'without', 'skin',
  'boiled', 'steamed', 'grilled', 'roasted', 'baked', 'fried', 'unsalted', 'salted',
  'includes', 'varieties', 'all', 'ns', 'as', 'to', 'form', 'type',
]);

/** Crude singularisation is enough to make "apples" match "apple". */
function contentWords(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .replace(/[^a-z0-9 ]/g, ' ')
      .split(/\s+/)
      .map((word) => (word.length > 3 && word.endsWith('s') ? word.slice(0, -1) : word))
      .filter((word) => word.length > 2 && !NOISE.has(word)),
  );
}

/**
 * How well a USDA description answers the food we asked about, as an F1 over
 * content words.
 *
 * Recall alone is not enough: "apple" appears in both "Apples, raw" and
 * "Apple-flavored whey protein powder", and only precision separates them. That
 * distinction is the difference between 14g of carbs and 0.
 */
function matchScore(query: Set<string>, description: string): number {
  const candidate = contentWords(description);
  if (query.size === 0 || candidate.size === 0) return 0;
  let shared = 0;
  for (const word of query) if (candidate.has(word)) shared++;
  if (shared === 0) return 0;
  const precision = shared / candidate.size;
  const recall = shared / query.size;
  return (2 * precision * recall) / (precision + recall);
}

/**
 * Model names are verbose ("red apple, whole, medium"); USDA searches better on
 * the head noun phrase, and the qualifiers only dilute the query.
 */
function searchTerm(name: string): string {
  const head = name.split(',')[0]?.trim();
  return head && head.length >= 3 ? head : name;
}

/**
 * Below this the top hit is a different food, and a wrong match is worse than
 * none — it produces confident, wrong carbs instead of an honest gap.
 *
 * Tuned so "Apple-flavored whey protein powder" loses to "Apples, raw, with
 * skin" for the query "red apple" (0.29 vs 0.50). This catches candidates padded
 * with words nobody asked for, which is the failure mode actually observed. It
 * cannot catch a short description that shares a modifier — "Thai basil" for
 * "pad thai" still scores 0.50 — because a bag of words has no notion of which
 * word is the head noun. Genuine misses fall through to the macro fallback.
 */
const MIN_MATCH_SCORE = 0.45;

/** Per-100g values, which is what USDA returns and what we cache. */
type Per100g = Macros;

function cacheKey(name: string): string {
  return `usda:${name.toLowerCase().replace(/\s+/g, ' ').trim()}`;
}

export function scaleMacros(per100g: Per100g, grams: number): Macros {
  const factor = grams / 100;
  return {
    carbs: per100g.carbs * factor,
    protein: per100g.protein * factor,
    fat: per100g.fat * factor,
  };
}

interface UsdaNutrient {
  nutrientId?: number;
  nutrientName?: string;
  value?: number;
}

function readNutrients(nutrients: UsdaNutrient[]): Per100g {
  const result: Per100g = { carbs: 0, protein: 0, fat: 0 };
  for (const nutrient of nutrients) {
    const value = Number(nutrient.value);
    if (!Number.isFinite(value)) continue;
    switch (nutrient.nutrientId) {
      case 1003:
        result.protein = value;
        continue;
      case 1004:
        result.fat = value;
        continue;
      case 1005:
        result.carbs = value;
        continue;
      default:
        break;
    }
    const name = (nutrient.nutrientName ?? '').toLowerCase();
    if (name.includes('protein')) result.protein ||= value;
    else if (name.includes('carbohydrate')) result.carbs ||= value;
    else if (name.includes('total lipid')) result.fat ||= value;
  }
  return result;
}

/**
 * `unavailable` and "no match" are deliberately different outcomes.
 *
 * USDA's edge intermittently answers 400 with an nginx error page for a request
 * that succeeds on retry. Treating that as "this food has no carbs" — and then
 * caching it — would put a zero in front of an insulin decision for a day.
 */
type Lookup = { matched: true; per100g: Per100g } | { matched: false } | { unavailable: true };

async function lookupOnce(name: string, signal: AbortSignal): Promise<Lookup> {
  const url = new URL(`${config.usda.baseUrl}/foods/search`);
  url.searchParams.set('api_key', config.usda.apiKey);
  url.searchParams.set('query', searchTerm(name));
  // Several candidates, because the top hit for a descriptive name is often a
  // different food that merely shares a word.
  url.searchParams.set('pageSize', '5');
  url.searchParams.set('dataType', 'Foundation,SR Legacy,Survey (FNDDS)');

  let response: Response;
  try {
    response = await fetch(url, {
      signal: AbortSignal.any([signal, AbortSignal.timeout(config.usda.timeoutMs)]),
    });
  } catch (error) {
    console.warn('[usda] request failed for', name, error);
    return { unavailable: true };
  }

  if (!response.ok) {
    console.warn('[usda] HTTP', response.status, 'for', name);
    return { unavailable: true };
  }

  let payload: { foods?: { description?: string; foodNutrients?: UsdaNutrient[] }[] };
  try {
    payload = (await response.json()) as typeof payload;
  } catch {
    return { unavailable: true };
  }

  const candidates = payload.foods;
  if (!Array.isArray(candidates) || candidates.length === 0) return { matched: false };

  const query = contentWords(searchTerm(name));
  let best: { score: number; food: (typeof candidates)[number] } | null = null;
  for (const food of candidates) {
    const score = matchScore(query, food.description ?? '');
    if (!best || score > best.score) best = { score, food };
  }

  // A wrong match is worse than no match: it produces confident, wrong carbs.
  // Falling through to `matched: false` sends this food to the macro fallback.
  if (!best || best.score < MIN_MATCH_SCORE) {
    console.warn('[usda] no confident match for', name, '- best was', best?.food.description, best?.score.toFixed(2));
    return { matched: false };
  }

  const nutrients = best.food.foodNutrients;
  if (!Array.isArray(nutrients)) return { matched: false };
  return { matched: true, per100g: readNutrients(nutrients) };
}

/** One retry, because the failures observed are transient edge errors. */
async function lookupPer100g(name: string, signal: AbortSignal): Promise<Lookup> {
  const first = await lookupOnce(name, signal);
  if (!('unavailable' in first)) return first;
  if (signal.aborted) return first;
  return lookupOnce(name, signal);
}

/**
 * Macros for one food, scaled to the estimated portion. Never throws — every
 * failure path degrades to zeros.
 */
export async function macrosFor(name: string, grams: number, signal: AbortSignal): Promise<MacroLookup> {
  if (!config.usda.apiKey) return { ...ZERO, resolved: false };

  const key = cacheKey(name);
  try {
    const cached = await redis().get<Per100g>(key);
    if (cached && typeof cached.carbs === 'number') {
      return { ...scaleMacros(cached, grams), resolved: !isEmpty(cached) };
    }
  } catch (error) {
    console.warn('[usda] cache read failed:', error);
  }

  let result: Lookup;
  try {
    result = await lookupPer100g(name, signal);
  } catch (error) {
    console.warn('[usda] lookup failed for', name, error);
    return { ...ZERO, resolved: false };
  }

  // An outage is never cached: the next attempt must be free to succeed rather
  // than serve a zero that a blip invented.
  if ('unavailable' in result) return { ...ZERO, resolved: false };

  const per100g = result.matched ? result.per100g : ZERO;
  const resolved = result.matched && !isEmpty(per100g);
  try {
    await redis().set(key, per100g, {
      // A real "no such food" is stable, but not permanent — USDA adds entries.
      ex: result.matched ? config.usda.cacheTtlSeconds : 60 * 60 * 24,
    });
  } catch (error) {
    console.warn('[usda] cache write failed:', error);
  }

  return { ...scaleMacros(per100g, grams), resolved };
}
