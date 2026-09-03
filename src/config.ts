/**
 * Environment configuration.
 *
 * Gates default to ON. A gate whose dependency is missing records a problem here
 * and makes the affected route answer 503 — it never silently degrades into
 * serving unauthenticated traffic. `/health` reports the problems so a
 * half-configured deploy is obvious rather than mysterious.
 */

const problems: string[] = [];
const warnings: string[] = [];

function str(name: string, fallback = ''): string {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const trimmed = raw.trim();
  return trimmed === '' ? fallback : trimmed;
}

function need(name: string, why: string): string {
  const value = str(name);
  if (!value) problems.push(`${name} is not set — ${why}`);
  return value;
}

/**
 * First of several accepted names. The Vercel Marketplace injects Upstash
 * credentials as KV_REST_API_*, while the Upstash SDK's own convention is
 * UPSTASH_REDIS_REST_*; accept either so the deploy works untouched and local
 * runs can use whichever is at hand.
 */
function needOneOf(names: string[], why: string): string {
  for (const name of names) {
    const value = str(name);
    if (value) return value;
  }
  problems.push(`${names.join(' or ')} is not set — ${why}`);
  return '';
}

function flag(name: string, fallback: boolean): boolean {
  const value = str(name).toLowerCase();
  if (!value) return fallback;
  return value === '1' || value === 'true' || value === 'yes' || value === 'on';
}

function num(name: string, fallback: number): number {
  const value = Number(str(name));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

const requireAttest = flag('REQUIRE_ATTEST', true);
const requireSubscription = flag('REQUIRE_SUBSCRIPTION', true);

const attestEnv = str('APP_ATTEST_ENV', 'development') === 'production' ? 'production' : 'development';
const appStoreEnv = str('APP_STORE_ENV', 'sandbox') === 'production' ? 'production' : 'sandbox';

const bundleId = str('APPLE_BUNDLE_ID', 'com.zenyi.diabeto');
const teamId = requireAttest
  ? need('APPLE_TEAM_ID', 'App Attest verifies the app id <APPLE_TEAM_ID>.' + bundleId)
  : str('APPLE_TEAM_ID');

const appAppleId =
  requireSubscription && appStoreEnv === 'production'
    ? need('APP_STORE_APP_APPLE_ID', 'Apple requires the numeric app id to verify production transactions')
    : str('APP_STORE_APP_APPLE_ID');

const sessionSecret = need('SESSION_SECRET', 'session tokens cannot be signed');
if (sessionSecret && sessionSecret.length < 32) {
  problems.push('SESSION_SECRET is shorter than 32 characters — generate one with `openssl rand -base64 32`');
}

const usdaApiKey = str('USDA_API_KEY');
if (!usdaApiKey) {
  warnings.push('USDA_API_KEY is not set — every food will report 0 carbs, 0 protein, 0 fat');
}

/**
 * Vercel sets this to production/preview/development on the deployment itself, so
 * it cannot be spoofed by a stray env var the way a hand-rolled flag could.
 */
const isProductionDeployment = str('VERCEL_ENV') === 'production';

/**
 * The bypass token skips the session, subscription AND attest gates at once.
 * Rather than depending on someone remembering to delete it, it is structurally
 * inert on a production deployment — the worst case becomes a broken test, not a
 * silently ungated /analyze.
 */
const configuredBypassToken = str('DEV_BYPASS_TOKEN');
const devBypassToken = isProductionDeployment ? '' : configuredBypassToken;
if (configuredBypassToken && isProductionDeployment) {
  warnings.push('DEV_BYPASS_TOKEN is set but ignored: bypass is disabled on production deployments');
} else if (devBypassToken) {
  warnings.push('DEV_BYPASS_TOKEN is set — it skips every auth gate and must be removed before launch');
}

/**
 * A gate that is switched on in production must be pointed at production Apple
 * infrastructure. Otherwise `REQUIRE_ATTEST=true` with a development aaguid is a
 * gate anyone with Xcode can walk through — a silent downgrade rather than a
 * visible failure.
 */
if (isProductionDeployment && requireAttest && attestEnv !== 'production') {
  problems.push('APP_ATTEST_ENV must be "production" when REQUIRE_ATTEST is on in production');
}
if (isProductionDeployment && requireSubscription && appStoreEnv !== 'production') {
  problems.push('APP_STORE_ENV must be "production" when REQUIRE_SUBSCRIPTION is on in production');
}

export const config = {
  openai: {
    apiKey: need('OPENAI_API_KEY', 'the vision call cannot run'),
    /** Any OpenAI-compatible endpoint: OpenRouter, Groq, Vercel AI Gateway, ... */
    baseUrl: str('OPENAI_BASE_URL', 'https://api.openai.com/v1').replace(/\/+$/, ''),
    model: str('OPENAI_MODEL', 'gpt-5.1'),
    /** Omitted from the request body when empty, so non-OpenAI models don't choke on it. */
    reasoningEffort: str('OPENAI_REASONING_EFFORT'),
    timeoutMs: num('OPENAI_TIMEOUT_MS', 60_000),
  },
  usda: {
    apiKey: usdaApiKey,
    baseUrl: str('USDA_BASE_URL', 'https://api.nal.usda.gov/fdc/v1').replace(/\/+$/, ''),
    timeoutMs: num('USDA_TIMEOUT_MS', 4_000),
    cacheTtlSeconds: 60 * 60 * 24 * 30,
  },
  apple: {
    bundleId,
    teamId,
    /** What App Attest actually signs over. */
    appId: `${teamId}.${bundleId}`,
    attestEnv,
  },
  session: {
    secret: sessionSecret,
    /**
     * Short enough that a stolen Keychain token ages out, long enough that the
     * app rarely has to re-prompt. Revocation on account deletion is handled
     * explicitly (see `revokeSessions`) rather than by waiting for expiry.
     */
    ttlDays: num('SESSION_TTL_DAYS', 60),
    issuer: 'diabeto-server',
    audience: 'diabeto-app',
  },
  subscription: {
    productIds: str('SUBSCRIPTION_PRODUCT_IDS', 'com.zenyi.diabeto.pro.monthly,com.zenyi.diabeto.pro.yearly')
      .split(',')
      .map((id) => id.trim())
      .filter(Boolean),
    env: appStoreEnv,
    appAppleId: appAppleId ? Number(appAppleId) : undefined,
    /**
     * OCSP revocation checks on Apple's signing chain. Off by default: it adds a
     * network round trip to every /analyze, and the offline chain verification is
     * what actually establishes trust.
     */
    onlineChecks: flag('APP_STORE_ONLINE_CHECKS', false),
  },
  gates: {
    requireAttest,
    requireSubscription,
  },
  devBypassToken,
  isProductionDeployment,
  /**
   * Per-million-token rates for the configured model, used to turn the usage
   * numbers OpenAI returns into a spend figure. Left at zero by default — a
   * guessed price is worse than none. Token counts are recorded either way.
   */
  pricing: {
    inputUsdPerMillion: Number(str('OPENAI_INPUT_USD_PER_MTOK', '0')) || 0,
    outputUsdPerMillion: Number(str('OPENAI_OUTPUT_USD_PER_MTOK', '0')) || 0,
  },
  limits: {
    perMinute: num('RATE_LIMIT_PER_MIN', 10),
    perDay: num('RATE_LIMIT_PER_DAY', 50),
    maxImageBytes: num('MAX_IMAGE_BYTES', 6 * 1024 * 1024),
    /** Must stay below the client's 90s cutoff so the user sees a real message. */
    analyzeDeadlineMs: num('ANALYZE_DEADLINE_MS', 78_000),
    /**
     * Caps attest-key farming by a single compromised account. Re-registration
     * is a normal client behaviour, so reaching this evicts the oldest key
     * rather than locking the account out.
     */
    maxAttestKeysPerUser: 5,
    /**
     * Mirrors the clamps the client already applies, so obviously-wrong model
     * output never reaches a dosing decision in the first place.
     */
    maxFoodsPerMeal: 30,
    maxGramsPerFood: 5_000,
    maxMacroGrams: 2_000,
  },
  redis: {
    url: needOneOf(
      ['KV_REST_API_URL', 'UPSTASH_REDIS_REST_URL'],
      'attest keys, challenges and rate limits need a shared store',
    ),
    token: needOneOf(
      ['KV_REST_API_TOKEN', 'UPSTASH_REDIS_REST_TOKEN'],
      'attest keys, challenges and rate limits need a shared store',
    ),
  },
} as const;

/** Fatal misconfigurations. Non-empty means authed routes answer 503. */
export const configProblems: readonly string[] = problems;

/** Non-fatal, but worth shouting about on /health. */
export const configWarnings: readonly string[] = warnings;
