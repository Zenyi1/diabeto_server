/**
 * APP_ATTEST_ENV=production.
 *
 * A development attestation is trivially obtainable — anyone who can run the app
 * from Xcode can mint one. In production that must not be accepted, or the whole
 * gate is decorative.
 */

import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { APP_ID, boot } from './helpers/harness.js';
import { buildAttestation } from './helpers/attest-fixtures.js';

const h = await boot({ APP_ATTEST_ENV: 'production' });
after(() => h.stop());

const { verifyAttestation } = await import('../src/attest.js');

describe('production attest environment', () => {
  const challenge = 'prod-challenge';

  it('rejects a development attestation', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, environment: 'development' });
    assert.throws(
      () =>
        verifyAttestation({
          attestationBase64: fixture.attestationBase64,
          keyId: fixture.keyId,
          challenge,
          trustedRootPem: fixture.rootPem,
        }),
      /development attestation rejected/,
    );
  });

  it('accepts a production attestation', () => {
    const fixture = buildAttestation({ appId: APP_ID, challenge, environment: 'production' });
    const result = verifyAttestation({
      attestationBase64: fixture.attestationBase64,
      keyId: fixture.keyId,
      challenge,
      trustedRootPem: fixture.rootPem,
    });
    assert.equal(result.environment, 'production');
  });

  it('reports the environment on /health', async () => {
    const payload = (await (await h.app.request('/health')).json()) as { attestEnvironment: string };
    assert.equal(payload.attestEnvironment, 'production');
  });
});
