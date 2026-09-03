/**
 * Step 1 of the pipeline: decompose a meal photo into foods and masses.
 *
 * Deliberately kept to plain fetch against an OpenAI-compatible Chat Completions
 * endpoint, so switching model or provider is an env change (OPENAI_BASE_URL /
 * OPENAI_MODEL) rather than a code change.
 *
 * The model is kept off nutrients on purpose — masses are what vision is good at,
 * macros come from USDA.
 */

import { config } from './config.js';

const SYSTEM_PROMPT =
  "You identify the foods in a photo of a meal and estimate each item's edible mass in grams. " +
  'Decompose the plate into individual foods (for example, separate the rice from the chicken ' +
  'from the vegetables). Do not estimate calories or nutrients — only name each food and its ' +
  'mass in grams. Give a per-item confidence from 0 to 1 reflecting how sure you are of both ' +
  'the identification and the portion size.';

function userPrompt(scaleHint: string | null): string {
  const opening = 'List the foods in this meal with an estimated mass in grams for each. ';
  return scaleHint
    ? `${opening}Scale reference: ${scaleHint}.`
    : `${opening}If a common object (fork, spoon, credit card, or a standard ~27cm dinner plate) ` +
        'is visible, use it to calibrate portion sizes.';
}

const FOOD_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['foods'],
  properties: {
    foods: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'grams', 'confidence'],
        properties: {
          name: {
            type: 'string',
            description: "Concise food name suitable for a nutrition-database lookup, e.g. 'grilled chicken breast'",
          },
          grams: { type: 'number', description: 'Estimated edible mass in grams' },
          confidence: { type: 'number', description: 'Confidence 0 to 1 in the item and its portion' },
        },
      },
    },
  },
} as const;

export interface DecomposedFood {
  name: string;
  grams: number;
  confidence: number;
}

export class DecomposeError extends Error {
  readonly retryable: boolean;

  constructor(message: string, retryable: boolean) {
    super(message);
    this.retryable = retryable;
  }
}

export interface DecomposeResult {
  foods: DecomposedFood[];
  usage: { inputTokens: number; outputTokens: number };
}

export async function decompose(
  imageBase64: string,
  scaleHint: string | null,
  signal: AbortSignal,
): Promise<DecomposeResult> {
  const body: Record<string, unknown> = {
    model: config.openai.model,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      {
        role: 'user',
        content: [
          { type: 'text', text: userPrompt(scaleHint) },
          { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${imageBase64}` } },
        ],
      },
    ],
    response_format: {
      type: 'json_schema',
      json_schema: { name: 'meal_foods', strict: true, schema: FOOD_SCHEMA },
    },
  };
  // Omitted entirely when unset, so non-OpenAI providers don't reject the field.
  if (config.openai.reasoningEffort) body.reasoning_effort = config.openai.reasoningEffort;

  const timeout = AbortSignal.timeout(config.openai.timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${config.openai.baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.openai.apiKey}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.any([signal, timeout]),
    });
  } catch (error) {
    console.error('[openai] request failed:', error);
    throw new DecomposeError('The analysis service did not respond in time.', true);
  }

  if (!response.ok) {
    // Logged in full, never returned — upstream errors can echo prompt or key fragments.
    console.error('[openai] HTTP', response.status, (await response.text()).slice(0, 500));
    if (response.status === 429) {
      throw new DecomposeError('The analysis service is busy. Please try again in a moment.', true);
    }
    throw new DecomposeError('The analysis service is unavailable right now.', response.status >= 500);
  }

  const payload = (await response.json()) as {
    choices?: { message?: { content?: string; refusal?: string } }[];
    usage?: { prompt_tokens?: number; completion_tokens?: number };
  };
  const usage = {
    inputTokens: Number(payload.usage?.prompt_tokens) || 0,
    outputTokens: Number(payload.usage?.completion_tokens) || 0,
  };
  const message = payload.choices?.[0]?.message;
  if (message?.refusal) {
    throw new DecomposeError("That photo couldn't be analyzed. Try a clearer picture of the plate.", false);
  }
  if (!message?.content) {
    console.error('[openai] response had no content');
    throw new DecomposeError('The analysis service returned an empty result.', true);
  }

  let parsed: { foods?: unknown };
  try {
    parsed = JSON.parse(message.content);
  } catch {
    console.error('[openai] content was not JSON:', message.content.slice(0, 300));
    throw new DecomposeError('The analysis service returned an unreadable result.', true);
  }

  if (!Array.isArray(parsed.foods)) return { foods: [], usage };

  // The schema is strict, but a swapped-in provider may not honour it — so the
  // shape is re-checked here rather than trusted.
  const foods = parsed.foods.slice(0, config.limits.maxFoodsPerMeal).flatMap((raw): DecomposedFood[] => {
    const food = raw as { name?: unknown; grams?: unknown; confidence?: unknown };
    const name = typeof food.name === 'string' ? food.name.trim() : '';
    const grams = Number(food.grams);
    const confidence = Number(food.confidence);
    if (!name || !Number.isFinite(grams) || grams <= 0) return [];
    return [
      {
        // A hallucinated 40kg portion would otherwise drive a real insulin dose.
        name,
        grams: Math.min(grams, config.limits.maxGramsPerFood),
        confidence: Number.isFinite(confidence) ? Math.min(1, Math.max(0, confidence)) : 0,
      },
    ];
  });

  return { foods, usage };
}
