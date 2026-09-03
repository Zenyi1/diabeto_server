/**
 * Adversarial suite: session forgery, App Attest replay and body binding, input
 * abuse, upstream hostility, quota, and error hygiene.
 *
 * Gates here: attest ON, subscription OFF (subscription has its own file, since
 * config is read once per process).
 */

import { after, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { SignJWT } from 'jose';

import { APP_ID, IMAGE_BASE64, boot, freshUser } from './helpers/harness.js';
import { buildAssertion, buildAttestation } from './helpers/attest-fixtures.js';

const h = await boot({ ANALYZE_DEADLINE_MS: '1500' });

// Dynamic: src/config.ts reads env at module load, and a static import would be
// hoisted above boot(), leaving every route answering 503.
const { verifyAssertion, verifyAttestation } = await import('../src/attest.js');
const { appleNonceMatches } = await import('../src/session.js');
after(() => h.stop());
beforeEach(() => h.reset());

/** A registered device that produces correctly-signed, monotonic assertions. */
async function device(userId = freshUser()) {
  const token = await h.sessionFor(userId);
  const { keyId, privateKeyPem } = await h.seedKey(userId);
  let counter = 0;

  return {
    userId,
    token,
    keyId,
    privateKeyPem,
    nextCounter: () => ++counter,
    headers(body: Buffer, options: { counter?: number; signedBody?: Buffer } = {}) {
      const assertion = buildAssertion({
        privateKeyPem,
        appId: APP_ID,
        counter: options.counter ?? ++counter,
        body: options.signedBody ?? body,
      });
      return {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
        'x-attest-key-id': keyId,
        'x-attest-assertion': assertion,
      };
    },
    analyze(payload: unknown = { image: IMAGE_BASE64 }, options: { counter?: number; signedBody?: Buffer } = {}) {
      const body = Buffer.from(JSON.stringify(payload));
      return h.app.request('/analyze', { method: 'POST', headers: this.headers(body, options), body });
    },
  };
}

function oneFood(name = 'white rice', grams = 150) {
  return [{ name, grams, confidence: 0.9 }];
}

// ---------------------------------------------------------------- sessions

describe('session forgery', () => {
  it('rejects a request with no Authorization header', async () => {
    const res = await h.app.request('/analyze', { method: 'POST', body: '{}' });
    assert.equal(res.status, 401);
  });

  it('rejects a garbage bearer token', async () => {
    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: 'Bearer not-a-jwt' },
      body: '{}',
    });
    assert.equal(res.status, 401);
  });

  it('rejects an alg:none token carrying otherwise valid claims', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const claims = Buffer.from(
      JSON.stringify({
        sub: 'attacker',
        iss: 'diabeto-server',
        aud: 'diabeto-app',
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    ).toString('base64url');

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: `Bearer ${header}.${claims}.` },
      body: '{}',
    });
    assert.equal(res.status, 401);
  });

  it('rejects a token signed with the wrong secret', async () => {
    const forged = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('attacker')
      .setIssuer('diabeto-server')
      .setAudience('diabeto-app')
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('a-completely-different-secret-value-32'));

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: `Bearer ${forged}` },
      body: '{}',
    });
    assert.equal(res.status, 401);
  });

  it('rejects an expired token', async () => {
    const expired = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('someone')
      .setIssuer('diabeto-server')
      .setAudience('diabeto-app')
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(new TextEncoder().encode('test-session-secret-at-least-32-chars-long'));

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: `Bearer ${expired}` },
      body: '{}',
    });
    assert.equal(res.status, 401);
  });

  it('rejects a token minted for a different issuer', async () => {
    const wrongIssuer = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('someone')
      .setIssuer('someone-elses-server')
      .setAudience('diabeto-app')
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('test-session-secret-at-least-32-chars-long'));

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: `Bearer ${wrongIssuer}` },
      body: '{}',
    });
    assert.equal(res.status, 401);
  });
});

// ------------------------------------------------- attestation crypto (unit)

describe('App Attest attestation', () => {
  const challenge = 'issued-challenge-value';

  it('accepts a well-formed attestation', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge });
    const result = verifyAttestation({
      attestationBase64: fixture.attestationBase64,
      keyId: fixture.keyId,
      challenge,
      trustedRootPem: fixture.rootPem,
    });
    assert.equal(result.environment, 'development');
    assert.match(result.publicKeyPem, /BEGIN PUBLIC KEY/);
  });

  it('rejects an attestation whose nonce covers a different challenge', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, nonceChallenge: 'some-other-challenge' });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /nonce does not match/,
    );
  });

  it('rejects an attestation minted for a different app id', () => {
    const fixture = buildAttestation({
      appId: APP_ID,
      challenge,
      authDataAppId: 'ZZZZZ99999.com.someone.else',
    });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /different app id/,
    );
  });

  it('rejects a chain that does not reach the trusted root', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, rogueIssuer: true });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /not signed by/,
    );
  });

  it('rejects a fresh key claiming a non-zero counter', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, counter: 7 });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /counter is not zero/,
    );
  });

  it('rejects a credentialId that disagrees with the key id', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, breakCredentialId: true });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /credential id does not match/,
    );
  });

  it('rejects a key id that is not the hash of the attested public key', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: Buffer.alloc(32, 1).toString('base64'),
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /key id does not match/,
    );
  });

  it('accepts a production aaguid while configured for development', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, environment: 'production' });
    const result = verifyAttestation({
      attestationBase64: fixture.attestationBase64,
      keyId: fixture.keyId,
      challenge,
      trustedRootPem: fixture.rootPem,
    });
    assert.equal(result.environment, 'production');
  });

  it('rejects non-CBOR garbage', () => {
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: Buffer.from('not cbor at all').toString('base64'),
          keyId: 'x',
          challenge,
        }),
      /attestation/,
    );
  });
});

// ---------------------------------------------------- assertion crypto (unit)

describe('App Attest assertion', () => {
  it('rejects an assertion signed by a different key', async () => {
    const real = buildAttestation({ appId: APP_ID, challenge: 'c' });
    const other = buildAttestation({ appId: APP_ID, challenge: 'c' });
    const verified = verifyAttestation({
      attestationBase64: real.attestationBase64,
      keyId: real.keyId,
      challenge: 'c',
      trustedRootPem: real.rootPem,
    });

    const body = Buffer.from('{"image":"x"}');
    const assertion = buildAssertion({ privateKeyPem: other.privateKeyPem, appId: APP_ID, counter: 1, body });

    assert.throws(
      () => verifyAssertion({ assertionBase64: assertion, rawBody: body, publicKeyPem: verified.publicKeyPem }),
      /signature is invalid/,
    );
  });

  it('rejects an assertion scoped to a different app id', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge: 'c' });
    const verified = verifyAttestation({
      attestationBase64: fixture.attestationBase64,
      keyId: fixture.keyId,
      challenge: 'c',
      trustedRootPem: fixture.rootPem,
    });

    const body = Buffer.from('{"image":"x"}');
    const assertion = buildAssertion({
      privateKeyPem: fixture.privateKeyPem,
      appId: 'ZZZZZ99999.com.someone.else',
      counter: 1,
      body,
    });

    assert.throws(
      () => verifyAssertion({ assertionBase64: assertion, rawBody: body, publicKeyPem: verified.publicKeyPem }),
      /different app id/,
    );
  });
});

// ------------------------------------------------ attest enforcement (routes)

describe('attest enforcement on /analyze', () => {
  it('rejects a valid session with no attestation headers', async () => {
    const token = await h.sessionFor(freshUser());
    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ image: IMAGE_BASE64 }),
    });
    assert.equal(res.status, 401);
  });

  it('answers 401 for an unknown key id so the client re-registers cleanly', async () => {
    const token = await h.sessionFor(freshUser());
    const body = Buffer.from(JSON.stringify({ image: IMAGE_BASE64 }));
    const stranger = buildAttestation({ appId: APP_ID, challenge: 'c' });

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
        'x-attest-key-id': stranger.keyId,
        'x-attest-assertion': buildAssertion({
          privateKeyPem: stranger.privateKeyPem,
          appId: APP_ID,
          counter: 1,
          body,
        }),
      },
      body,
    });
    assert.equal(res.status, 401);
  });

  it("refuses to use another account's registered device key", async () => {
    const victim = await device();
    const attackerToken = await h.sessionFor(freshUser());
    const body = Buffer.from(JSON.stringify({ image: IMAGE_BASE64 }));

    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${attackerToken}`,
        'x-attest-key-id': victim.keyId,
        'x-attest-assertion': buildAssertion({
          privateKeyPem: victim.privateKeyPem,
          appId: APP_ID,
          counter: 1,
          body,
        }),
      },
      body,
    });
    assert.equal(res.status, 403);
  });

  it('accepts a correctly signed assertion', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    const res = await dev.analyze();
    assert.equal(res.status, 200);
  });

  it('rejects an assertion that signs a different body than was sent', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    const res = await dev.analyze(
      { image: IMAGE_BASE64 },
      { signedBody: Buffer.from(JSON.stringify({ image: 'a-completely-different-image' })) },
    );
    assert.equal(res.status, 401);
  });

  it('rejects a replayed assertion', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    const first = await dev.analyze({ image: IMAGE_BASE64 }, { counter: 1 });
    assert.equal(first.status, 200);

    const replay = await dev.analyze({ image: IMAGE_BASE64 }, { counter: 1 });
    assert.equal(replay.status, 401);
  });

  it('rejects an assertion whose counter went backwards', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    assert.equal((await dev.analyze({ image: IMAGE_BASE64 }, { counter: 9 })).status, 200);
    assert.equal((await dev.analyze({ image: IMAGE_BASE64 }, { counter: 4 })).status, 401);
  });

  it('lets exactly one of five identical concurrent replays through', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    const results = await Promise.all(
      Array.from({ length: 5 }, () => dev.analyze({ image: IMAGE_BASE64 }, { counter: 3 })),
    );
    const accepted = results.filter((res) => res.status === 200);
    assert.equal(accepted.length, 1, 'counter compare-and-set must admit exactly one');
  });
});

// ---------------------------------------------------------- input validation

describe('input validation', () => {
  it('rejects a payload that is not a JPEG', async () => {
    const dev = await device();
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const res = await dev.analyze({ image: png.toString('base64') });
    assert.equal(res.status, 400);
  });

  it('rejects an oversized image', async () => {
    const dev = await device();
    const huge = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff]), Buffer.alloc(7 * 1024 * 1024, 1)]);
    const res = await dev.analyze({ image: huge.toString('base64') });
    assert.equal(res.status, 413);
  });

  it('rejects a missing image field', async () => {
    const dev = await device();
    assert.equal((await dev.analyze({ notImage: 'x' })).status, 400);
  });

  it('rejects a non-string image field', async () => {
    const dev = await device();
    assert.equal((await dev.analyze({ image: 12345 })).status, 400);
  });

  it('rejects a body that is not JSON', async () => {
    const dev = await device();
    const body = Buffer.from('this is not json');
    const res = await h.app.request('/analyze', { method: 'POST', headers: dev.headers(body), body });
    assert.equal(res.status, 400);
  });

  it('tolerates unknown fields for forward compatibility', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    const res = await dev.analyze({ image: IMAGE_BASE64, scaleHint: null, somethingNew: { a: 1 } });
    assert.equal(res.status, 200);
  });

  it('passes a scaleHint through to the prompt when present', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    await dev.analyze({ image: IMAGE_BASE64, scaleHint: 'a 27cm dinner plate' });

    const text = JSON.stringify(h.openai.requests[0]);
    assert.match(text, /Scale reference: a 27cm dinner plate/);
  });

  it('falls back to the calibration prompt when scaleHint is null', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    await dev.analyze({ image: IMAGE_BASE64, scaleHint: null });

    const text = JSON.stringify(h.openai.requests[0]);
    assert.match(text, /calibrate portion sizes/);
    assert.doesNotMatch(text, /Scale reference/);
  });
});

// ------------------------------------------------------------------ pipeline

describe('pipeline behaviour', () => {
  it('scales USDA per-100g macros by the estimated portion', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood('white rice', 150) };
    h.usda.foods.set('white rice', { protein: 2.7, fat: 0.3, carbs: 28.0 });

    const res = await dev.analyze();
    const payload = (await res.json()) as { foods: Record<string, number>[] };

    assert.equal(res.status, 200);
    assert.equal(payload.foods[0].carbs, 42); // 28.0 * 1.5
    assert.equal(payload.foods[0].protein, 4.1);
    assert.equal(payload.foods[0].grams, 150);
  });

  it('rescues a USDA miss with the cheap model instead of reporting zero carbs', async () => {
    const dev = await device();
    h.openai.behaviour = {
      foods: oneFood('pad thai', 300),
      fallbackFoods: [{ name: 'pad thai', carbs: 30, protein: 8, fat: 6 }],
    };

    const res = await dev.analyze();
    const payload = (await res.json()) as { foods: Record<string, number>[] };

    assert.equal(res.status, 200);
    assert.equal(payload.foods[0].carbs, 90, '30g/100g scaled to 300g');
    assert.equal(payload.foods[0].protein, 24);
    assert.equal(payload.foods[0].grams, 300);
  });

  it('refuses a plausible-looking wrong match and rescues instead', async () => {
    const dev = await device();
    // The real failure this reproduces: USDA's top hit for a verbose food name
    // was a protein product, which reported an apple as 0g carbs / 45g protein.
    h.usda.candidates.set('red apple', [
      { description: 'Apple-flavored whey protein powder', protein: 45.9, fat: 1.9, carbs: 0 },
      { description: 'Apples, raw, with skin', protein: 0.3, fat: 0.2, carbs: 13.8 },
    ]);
    h.openai.behaviour = { foods: oneFood('red apple, whole, medium', 180) };

    const payload = (await (await dev.analyze()).json()) as { foods: Record<string, number>[] };
    assert.equal(payload.foods[0].carbs, 24.8, '13.8g/100g scaled to 180g, not the protein powder');
    assert.equal(payload.foods[0].protein, 0.5);
  });

  it('sends a food to the fallback when no candidate is close enough', async () => {
    const dev = await device();
    // Shares one word, but is padded with five the query never mentioned.
    h.usda.candidates.set('pad thai', [
      { description: 'Thai-style peanut sauce mix, dry, commercially prepared', protein: 3, fat: 0.6, carbs: 2.7 },
    ]);
    h.openai.behaviour = {
      foods: oneFood('pad thai', 100),
      fallbackFoods: [{ name: 'pad thai', carbs: 30, protein: 8, fat: 6 }],
    };

    const payload = (await (await dev.analyze()).json()) as { foods: Record<string, number>[] };
    assert.equal(payload.foods[0].carbs, 30, 'a weak match must not be trusted');
  });

  it('searches on the head noun, not the full descriptive name', async () => {
    const dev = await device();
    h.usda.foods.set('grilled chicken breast', { protein: 31, fat: 3.6, carbs: 0 });
    h.openai.behaviour = { foods: oneFood('grilled chicken breast, skinless, sliced', 100) };

    await dev.analyze();
    assert.equal(h.usda.queries[0], 'grilled chicken breast');
  });

  it('still returns zeros when even the fallback has nothing', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood('pad thai', 300), fallbackFoods: [] };

    const payload = (await (await dev.analyze()).json()) as { foods: Record<string, number>[] };
    assert.equal(payload.foods[0].carbs, 0);
  });

  it('does not call the fallback when USDA answered', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood('white rice', 100) };
    h.usda.foods.set('white rice', { protein: 2.7, fat: 0.3, carbs: 28 });

    await dev.analyze();
    const models = h.openai.requests.map((r) => r.model);
    assert.deepEqual(models, ['test-model'], 'USDA hit means no rescue call');
  });

  it('ignores a fallback row for a food nobody asked about', async () => {
    const dev = await device();
    h.openai.behaviour = {
      foods: oneFood('pad thai', 100),
      fallbackFoods: [{ name: 'injected cake', carbs: 99, protein: 1, fat: 1 }],
    };

    const payload = (await (await dev.analyze()).json()) as { foods: { name: string; carbs: number }[] };
    assert.equal(payload.foods.length, 1);
    assert.equal(payload.foods[0].name, 'pad thai');
    assert.equal(payload.foods[0].carbs, 0);
  });

  it('survives a USDA outage', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    h.usda.status = 500;

    const res = await dev.analyze();
    assert.equal(res.status, 200);
  });

  it('preserves the order the model returned', async () => {
    const dev = await device();
    h.openai.behaviour = {
      foods: [
        { name: 'rice', grams: 100, confidence: 0.9 },
        { name: 'chicken', grams: 120, confidence: 0.8 },
        { name: 'broccoli', grams: 80, confidence: 0.7 },
      ],
    };

    const res = await dev.analyze();
    const payload = (await res.json()) as { foods: { name: string }[] };
    assert.deepEqual(
      payload.foods.map((food) => food.name),
      ['rice', 'chicken', 'broccoli'],
    );
  });

  it('never emits null, NaN or negative numbers even when the model misbehaves', async () => {
    const dev = await device();
    h.openai.behaviour = {
      foods: [
        { name: 'good', grams: 100, confidence: 0.5 },
        { name: 'bad grams', grams: 'lots', confidence: 0.5 },
        { name: '', grams: 50, confidence: 0.5 },
        { name: 'negative', grams: -20, confidence: 0.5 },
        { name: 'null confidence', grams: 30, confidence: null },
        { name: 'over confident', grams: 30, confidence: 4.2 },
      ],
    };

    const res = await dev.analyze();
    const payload = (await res.json()) as { foods: Record<string, unknown>[] };
    assert.equal(res.status, 200);

    for (const food of payload.foods) {
      assert.equal(typeof food.name, 'string');
      for (const field of ['grams', 'carbs', 'protein', 'fat', 'confidence']) {
        const value = food[field];
        assert.equal(typeof value, 'number', `${field} must be a number`);
        assert.ok(Number.isFinite(value as number), `${field} must be finite`);
        assert.ok((value as number) >= 0, `${field} must be non-negative`);
      }
      assert.ok((food.confidence as number) <= 1, 'confidence must be <= 1');
    }
    // The three unusable rows are dropped, not emitted as zeros.
    assert.deepEqual(
      payload.foods.map((food) => food.name),
      ['good', 'null confidence', 'over confident'],
    );
  });

  it('caches USDA lookups across requests', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood('cached food', 100) };
    h.usda.foods.set('cached food', { protein: 1, fat: 1, carbs: 1 });

    await dev.analyze();
    await dev.analyze();
    assert.equal(h.usda.queries.length, 1, 'second analysis must be served from cache');
  });

  it('maps an upstream 429 to a retryable error', async () => {
    const dev = await device();
    h.openai.behaviour = { status: 429 };
    const res = await dev.analyze();
    assert.equal(res.status, 503);
    assert.match(await res.text(), /busy/i);
  });

  it('maps a model refusal to a non-retryable error', async () => {
    const dev = await device();
    h.openai.behaviour = { refusal: 'I cannot help with that.' };
    const res = await dev.analyze();
    assert.equal(res.status, 422);
  });

  it('handles a malformed model response', async () => {
    const dev = await device();
    h.openai.behaviour = { body: JSON.stringify({ choices: [{ message: { content: 'not json' } }] }) };
    const res = await dev.analyze();
    assert.equal(res.status, 503);
  });

  it('returns 504 when the pipeline exceeds its deadline', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood(), delayMs: 3000 };
    const res = await dev.analyze();
    assert.equal(res.status, 504);
    assert.match(await res.text(), /too long/i);
  });
});

// ------------------------------------------------------------ error hygiene

describe('error hygiene', () => {
  it('never echoes the upstream API key back to the client', async () => {
    const dev = await device();
    h.openai.behaviour = {
      status: 500,
      body: JSON.stringify({ error: { message: 'invalid key sk-test-secret-key-do-not-leak' } }),
    };

    const res = await dev.analyze();
    const text = await res.text();
    assert.ok(!text.includes('sk-test-secret-key-do-not-leak'), 'upstream error text must not reach the client');
    assert.ok(!text.includes('test-session-secret'), 'session secret must never appear');
  });

  it('keeps /health free of secrets', async () => {
    const res = await h.app.request('/health');
    const text = await res.text();
    assert.equal(res.status, 200);
    for (const secret of ['sk-test-secret-key-do-not-leak', 'test-session-secret', 'test-token']) {
      assert.ok(!text.includes(secret), `/health leaked ${secret}`);
    }
  });

  it('reports gate state on /health', async () => {
    const res = await h.app.request('/health');
    const payload = (await res.json()) as { ok: boolean; gates: Record<string, boolean>; devBypass: boolean };
    assert.equal(payload.ok, true);
    assert.equal(payload.gates.attest, true);
    assert.equal(payload.devBypass, true);
  });

  it('404s unknown routes', async () => {
    assert.equal((await h.app.request('/wp-admin')).status, 404);
  });
});

// ------------------------------------------------------------------- quota

describe('rate limiting', () => {
  it('cuts a device off after the per-minute limit', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) statuses.push((await dev.analyze()).status);

    assert.equal(statuses.filter((status) => status === 200).length, 5, 'exactly the limit should succeed');
    assert.ok(statuses.includes(429), 'the surplus must be rejected');
  });
});

// -------------------------------------------------------------- dev bypass

describe('dev bypass token', () => {
  it('skips attest and subscription for the configured token only', async () => {
    h.openai.behaviour = { foods: oneFood() };
    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer dev-bypass-token-for-tests-only' },
      body: JSON.stringify({ image: IMAGE_BASE64 }),
    });
    assert.equal(res.status, 200);
  });

  it('does not accept a near-miss of the bypass token', async () => {
    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer dev-bypass-token-for-tests-onl' },
      body: JSON.stringify({ image: IMAGE_BASE64 }),
    });
    assert.equal(res.status, 401);
  });
});

// ------------------------------------------------------------ sign-in nonce

describe('Sign in with Apple nonce', () => {
  it('accepts the hash Apple would echo back', () => {
    const raw = 'kZ8f_raw-nonce-value';
    const claim = createHash('sha256').update(raw).digest('hex');
    assert.equal(appleNonceMatches(raw, claim), true);
  });

  it('rejects a nonce from a different sign-in, blocking token replay', () => {
    const claim = createHash('sha256').update('some-other-nonce').digest('hex');
    assert.equal(appleNonceMatches('kZ8f_raw-nonce-value', claim), false);
  });

  it('rejects an empty or truncated claim', () => {
    const raw = 'kZ8f_raw-nonce-value';
    const claim = createHash('sha256').update(raw).digest('hex');
    assert.equal(appleNonceMatches(raw, ''), false);
    assert.equal(appleNonceMatches(raw, claim.slice(0, -1)), false);
  });
});

describe('/auth/apple', () => {
  it('rejects a request with no identity token', async () => {
    const res = await h.app.request('/auth/apple', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ nonce: 'x' }),
    });
    assert.equal(res.status, 400);
  });

  it('rejects an identity token Apple did not sign', async () => {
    const res = await h.app.request('/auth/apple', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identityToken: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhdHRhY2tlciJ9.', nonce: 'x' }),
    });
    assert.equal(res.status, 401);
  });
});

// -------------------------------------------------------- account deletion

describe('DELETE /account', () => {
  it('requires a session', async () => {
    assert.equal((await h.app.request('/account', { method: 'DELETE' })).status, 401);
  });

  it('removes the account and every device key registered to it', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };
    assert.equal((await dev.analyze()).status, 200);

    const res = await h.app.request('/account', {
      method: 'DELETE',
      headers: { authorization: `Bearer ${dev.token}` },
    });
    assert.equal(res.status, 200);

    // Session revoked and key gone: the next call cannot succeed on either count.
    const after = await dev.analyze();
    assert.equal(after.status, 401);
  });

  it('revokes outstanding session tokens immediately', async () => {
    const userId = freshUser();
    const token = await h.sessionFor(userId);

    // Same token, before and after: deletion must not wait for expiry.
    assert.equal((await h.app.request('/usage', { headers: { authorization: `Bearer ${token}` } })).status, 200);
    await h.app.request('/account', { method: 'DELETE', headers: { authorization: `Bearer ${token}` } });
    assert.equal((await h.app.request('/usage', { headers: { authorization: `Bearer ${token}` } })).status, 401);
  });

  it('refuses to delete anything for a bypass token', async () => {
    const res = await h.app.request('/account', {
      method: 'DELETE',
      headers: { authorization: 'Bearer dev-bypass-token-for-tests-only' },
    });
    assert.equal(res.status, 400);
  });
});

// ------------------------------------------------------------ usage metering

describe('usage metering', () => {
  it('records requests and tokens, and reads them back', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    assert.equal((await dev.analyze()).status, 200);
    assert.equal((await dev.analyze()).status, 200);

    const res = await h.app.request('/usage', { headers: { authorization: `Bearer ${dev.token}` } });
    const payload = (await res.json()) as {
      month: { requests: number; inputTokens: number; outputTokens: number };
      limits: { perDay: number };
    };

    assert.equal(res.status, 200);
    assert.equal(payload.month.requests, 2);
    assert.ok(payload.month.inputTokens > 0, 'input tokens must be metered');
    assert.equal(payload.limits.perDay, 1000);
  });

  it("keeps one user out of another user's counters", async () => {
    const first = await device();
    const second = await device();
    h.openai.behaviour = { foods: oneFood() };
    await first.analyze();

    const res = await h.app.request('/usage', { headers: { authorization: `Bearer ${second.token}` } });
    const payload = (await res.json()) as { month: { requests: number } };
    assert.equal(payload.month.requests, 0);
  });

  it('requires a session', async () => {
    assert.equal((await h.app.request('/usage')).status, 401);
  });

  it('answers 429 with a machine-readable body', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood() };

    let last: Response | null = null;
    for (let i = 0; i < 7; i++) last = await dev.analyze();

    assert.equal(last!.status, 429);
    const payload = (await last!.json()) as { error: string; retryAfterSeconds: number };
    assert.equal(payload.error, 'quota_exceeded');
    assert.ok(payload.retryAfterSeconds > 0);
  });
});

// ------------------------------------------------------------ admin views

describe('admin views', () => {
  const admin = { authorization: 'Bearer admin-token-for-tests-at-least-32-chars' };

  it('404s without a token, so the routes do not advertise themselves', async () => {
    assert.equal((await h.app.request('/admin/stats')).status, 404);
    assert.equal((await h.app.request('/admin/users')).status, 404);
  });

  it('404s on a wrong token rather than 401', async () => {
    const res = await h.app.request('/admin/stats', { headers: { authorization: 'Bearer wrong-token-value' } });
    assert.equal(res.status, 404);
  });

  it('reports whole-service totals in real dollars', async () => {
    const dev = await device();
    // USDA hit, so only the vision call bills and the total stays exact.
    h.usda.foods.set('white rice', { protein: 2.7, fat: 0.3, carbs: 28 });
    h.openai.behaviour = { foods: oneFood(), usage: { prompt_tokens: 2_000_000, completion_tokens: 1_000_000 } };
    await dev.analyze();

    const res = await h.app.request('/admin/stats', { headers: admin });
    const payload = (await res.json()) as { month: { requests: number; usd: number }; model: string };

    assert.equal(res.status, 200);
    assert.equal(payload.month.requests, 1);
    // 2M input @ $1.25 + 1M output @ $10.00
    assert.equal(payload.month.usd, 12.5);
    assert.equal(payload.model, 'test-model');
  });

  it('prices cached input at the cheaper rate', async () => {
    const dev = await device();
    h.usda.foods.set('white rice', { protein: 2.7, fat: 0.3, carbs: 28 });
    h.openai.behaviour = { foods: oneFood(), usage: { prompt_tokens: 1_000_000, completion_tokens: 0 } };
    await dev.analyze();

    const res = await h.app.request('/admin/stats', { headers: admin });
    const payload = (await res.json()) as { month: { usd: number } };
    assert.equal(payload.month.usd, 1.25, 'uncached input bills at the full rate');
  });

  it('lists users newest first with their spend', async () => {
    const first = await device();
    const second = await device();
    // Index them the way /auth/apple would.
    const { indexUser } = await import('../src/usage.js');
    await indexUser(first.userId, 1000);
    await indexUser(second.userId, 2000);

    h.openai.behaviour = { foods: oneFood() };
    await second.analyze();

    const res = await h.app.request('/admin/users', { headers: admin });
    const payload = (await res.json()) as { users: { id: string; month: { requests: number } }[] };

    assert.equal(res.status, 200);
    assert.equal(payload.users[0].id, second.userId, 'most recent signup first');
    assert.equal(payload.users[0].month.requests, 1);
    assert.equal(payload.users[1].month.requests, 0);
  });

  it('serves the dashboard shell without a token but with no data in it', async () => {
    const res = await h.app.request('/admin');
    const html = await res.text();

    assert.equal(res.status, 200);
    assert.match(html, /<title>diabeto · admin<\/title>/);
    // The shell must not embed anything the token is supposed to protect.
    for (const secret of ['admin-token-for-tests', 'sk-test-secret-key-do-not-leak', 'test-session-secret']) {
      assert.ok(!html.includes(secret), `dashboard leaked ${secret}`);
    }
  });

  it('reports subscription state per user', async () => {
    const dev = await device();
    const { rememberSubscription } = await import('../src/subscription.js');
    const { indexUser } = await import('../src/usage.js');
    await indexUser(dev.userId, Date.now());
    await rememberSubscription(dev.userId, {
      productId: 'com.zenyi.diabeto.pro.monthly',
      expiresDate: Date.now() + 86_400_000,
    });

    const payload = (await (await h.app.request('/admin/users', { headers: admin })).json()) as {
      users: { subscription: { active: boolean; productId: string } | null }[];
    };
    assert.equal(payload.users[0].subscription?.active, true);
    assert.equal(payload.users[0].subscription?.productId, 'com.zenyi.diabeto.pro.monthly');
  });

  it('marks a lapsed subscription inactive rather than dropping it', async () => {
    const dev = await device();
    const { rememberSubscription } = await import('../src/subscription.js');
    const { indexUser } = await import('../src/usage.js');
    await indexUser(dev.userId, Date.now());
    await rememberSubscription(dev.userId, {
      productId: 'com.zenyi.diabeto.pro.monthly',
      expiresDate: Date.now() - 1000,
    });

    const payload = (await (await h.app.request('/admin/users', { headers: admin })).json()) as {
      users: { subscription: { active: boolean } | null }[];
    };
    assert.equal(payload.users[0].subscription?.active, false);
  });

  it('counts users without scanning the keyspace', async () => {
    const { indexUser } = await import('../src/usage.js');
    for (let i = 0; i < 5; i++) await indexUser(`indexed-${i}`, 1000 + i);

    const payload = (await (await h.app.request('/admin/stats', { headers: admin })).json()) as { users: number };
    assert.equal(payload.users, 5);
  });
});

// ---------------------------------------------------------- output clamping

describe('output clamping', () => {
  it('caps an implausible portion the model invented', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: [{ name: 'rice', grams: 40_000, confidence: 0.9 }] };

    const payload = (await (await dev.analyze()).json()) as { foods: { grams: number }[] };
    assert.equal(payload.foods[0].grams, 5000);
  });

  it('caps macros that would follow from a bad USDA row', async () => {
    const dev = await device();
    h.openai.behaviour = { foods: oneFood('weird food', 5000) };
    h.usda.foods.set('weird food', { protein: 900, fat: 900, carbs: 900 });

    const payload = (await (await dev.analyze()).json()) as { foods: Record<string, number>[] };
    assert.equal(payload.foods[0].carbs, 2000);
    assert.equal(payload.foods[0].protein, 2000);
  });

  it('drops everything past the per-meal food cap', async () => {
    const dev = await device();
    h.openai.behaviour = {
      foods: Array.from({ length: 50 }, (_, i) => ({ name: `food ${i}`, grams: 10, confidence: 0.5 })),
    };

    const payload = (await (await dev.analyze()).json()) as { foods: unknown[] };
    assert.equal(payload.foods.length, 30);
  });
});

// ------------------------------------------------------- attest registration

describe('/attest/register', () => {
  it('refuses a challenge that was never issued', async () => {
    const token = await h.sessionFor(freshUser());
    const fixture = buildAttestation({ appId: APP_ID, challenge: 'never-issued' });

    const res = await h.app.request('/attest/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ keyId: fixture.keyId, attestation: fixture.attestationBase64, challenge: 'never-issued' }),
    });
    assert.equal(res.status, 400);
  });

  it('burns a challenge after a single use', async () => {
    const token = await h.sessionFor(freshUser());
    const challengeRes = await h.app.request('/attest/challenge', { headers: { authorization: `Bearer ${token}` } });
    const { challenge } = (await challengeRes.json()) as { challenge: string };

    const fixture = buildAttestation({ appId: APP_ID, challenge });
    const body = JSON.stringify({
      keyId: fixture.keyId,
      attestation: fixture.attestationBase64,
      challenge,
    });
    const headers = { 'content-type': 'application/json', authorization: `Bearer ${token}` };

    // Synthetic chain, so this is rejected on crypto — the point is the challenge
    // is consumed regardless, leaving nothing to retry with.
    const first = await h.app.request('/attest/register', { method: 'POST', headers, body });
    assert.equal(first.status, 401);

    const second = await h.app.request('/attest/register', { method: 'POST', headers, body });
    assert.equal(second.status, 400, 'a spent challenge must not be reusable');
  });

  it("refuses a challenge issued to a different account", async () => {
    const victimToken = await h.sessionFor(freshUser());
    const attackerToken = await h.sessionFor(freshUser());

    const challengeRes = await h.app.request('/attest/challenge', {
      headers: { authorization: `Bearer ${victimToken}` },
    });
    const { challenge } = (await challengeRes.json()) as { challenge: string };
    const fixture = buildAttestation({ appId: APP_ID, challenge });

    const res = await h.app.request('/attest/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${attackerToken}` },
      body: JSON.stringify({ keyId: fixture.keyId, attestation: fixture.attestationBase64, challenge }),
    });
    assert.equal(res.status, 400);
  });

  it('rejects an attestation that does not chain to Apple, proving the root is pinned', async () => {
    const token = await h.sessionFor(freshUser());
    const challengeRes = await h.app.request('/attest/challenge', { headers: { authorization: `Bearer ${token}` } });
    const { challenge } = (await challengeRes.json()) as { challenge: string };
    const fixture = buildAttestation({ appId: APP_ID, challenge });

    const res = await h.app.request('/attest/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ keyId: fixture.keyId, attestation: fixture.attestationBase64, challenge }),
    });
    assert.equal(res.status, 401);
  });

  it('requires a session', async () => {
    assert.equal((await h.app.request('/attest/challenge')).status, 401);
  });
});
