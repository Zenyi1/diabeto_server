/**
 * A half-configured deploy must refuse traffic, not serve it ungated.
 *
 * The failure mode this guards against is the expensive one: attest is switched
 * on, APPLE_TEAM_ID was never set, and the server happily answers /analyze
 * because the check silently could not run.
 */

import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { IMAGE_BASE64, boot } from './helpers/harness.js';

const h = await boot({ SESSION_SECRET: '', APPLE_TEAM_ID: '', REQUIRE_ATTEST: 'true' });
after(() => h.stop());

describe('fail-closed configuration', () => {
  it('refuses /analyze rather than serving it ungated', async () => {
    const res = await h.app.request('/analyze', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer anything' },
      body: JSON.stringify({ image: IMAGE_BASE64 }),
    });
    assert.equal(res.status, 503);
  });

  it('refuses sign-in too', async () => {
    const res = await h.app.request('/auth/apple', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identityToken: 'x' }),
    });
    assert.equal(res.status, 503);
  });

  it('will not even hand out an attest challenge', async () => {
    assert.equal((await h.app.request('/attest/challenge')).status, 503);
  });

  it('says exactly what is missing on /health', async () => {
    const payload = (await (await h.app.request('/health')).json()) as { ok: boolean; problems: string[] };
    assert.equal(payload.ok, false);
    assert.ok(payload.problems.some((problem) => problem.startsWith('SESSION_SECRET')));
    assert.ok(payload.problems.some((problem) => problem.startsWith('APPLE_TEAM_ID')));
  });

  it('never leaks a secret value in the problem list', async () => {
    const text = await (await h.app.request('/health')).text();
    assert.ok(!text.includes('sk-test-secret-key-do-not-leak'));
  });
});
