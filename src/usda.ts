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

const ZERO: Macros = { carbs: 0, protein: 0, fat: 0 };

/** Per-100g values, which is what USDA returns and what we cache. */
type Per100g = Macros;

function cacheKey(name: string): string {
  return `usda:${name.toLowerCase().replace(/\s+/g, ' ').trim()}`;
}

function scale(per100g: Per100g, grams: number): Macros {
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

async function lookupPer100g(name: string, signal: AbortSignal): Promise<Per100g> {
  const url = new URL(`${config.usda.baseUrl}/foods/search`);
  url.searchParams.set('api_key', config.usda.apiKey);
  url.searchParams.set('query', name);
  url.searchParams.set('pageSize', '1');
  url.searchParams.set('dataType', 'Foundation,SR Legacy,Survey (FNDDS)');

  const response = await fetch(url, {
    signal: AbortSignal.any([signal, AbortSignal.timeout(config.usda.timeoutMs)]),
  });
  if (!response.ok) {
    console.warn('[usda] HTTP', response.status, 'for', name);
    return ZERO;
  }

  const payload = (await response.json()) as { foods?: { foodNutrients?: UsdaNutrient[] }[] };
  const nutrients = payload.foods?.[0]?.foodNutrients;
  if (!Array.isArray(nutrients)) return ZERO;
  return readNutrients(nutrients);
}

/**
 * Macros for one food, scaled to the estimated portion. Never throws — every
 * failure path degrades to zeros.
 */
export async function macrosFor(name: string, grams: number, signal: AbortSignal): Promise<Macros> {
  if (!config.usda.apiKey) return ZERO;

  const key = cacheKey(name);
  try {
    const cached = await redis().get<Per100g>(key);
    if (cached && typeof cached.carbs === 'number') return scale(cached, grams);
  } catch (error) {
    console.warn('[usda] cache read failed:', error);
  }

  let per100g: Per100g;
  try {
    per100g = await lookupPer100g(name, signal);
  } catch (error) {
    console.warn('[usda] lookup failed for', name, error);
    return ZERO;
  }

  // Misses are cached too, on a shorter TTL, so a plate of unmatched foods doesn't
  // re-query USDA on every retry.
  const isMiss = per100g.carbs === 0 && per100g.protein === 0 && per100g.fat === 0;
  try {
    await redis().set(key, per100g, {
      ex: isMiss ? 60 * 60 * 24 : config.usda.cacheTtlSeconds,
    });
  } catch (error) {
    console.warn('[usda] cache write failed:', error);
  }

  return scale(per100g, grams);
}
