/**
 * Subscription gate, with REQUIRE_SUBSCRIPTION=true.
 *
 * A genuinely valid receipt can only be signed by Apple, so the success path is
 * not reachable here. What is reachable — and what actually matters — is that a
 * forged one is refused: the interesting attack is a jailbroken client asserting
 * entitlement it does not have.
 */

import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPrivateKey } from 'node:crypto';
import { SignJWT } from 'jose';

import { APP_ID, BUNDLE_ID, IMAGE_BASE64, PRODUCT_ID, boot, freshUser } from './helpers/harness.js';
import { buildAssertion } from './helpers/attest-fixtures.js';

const h = await boot({ REQUIRE_SUBSCRIPTION: 'true' });
after(() => h.stop());

async function attestedRequest(headers: Record<string, string> = {}) {
  const userId = freshUser();
  const token = await h.sessionFor(userId);
  const { keyId, privateKeyPem } = await h.seedKey(userId);
  const body = Buffer.from(JSON.stringify({ image: IMAGE_BASE64 }));

  return h.app.request('/analyze', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      'x-attest-key-id': keyId,
      'x-attest-assertion': buildAssertion({ privateKeyPem, appId: APP_ID, counter: 1, body }),
      ...headers,
    },
    body,
  });
}

describe('subscription gate', () => {
  it('refuses an otherwise perfect request with no receipt', async () => {
    const res = await attestedRequest();
    assert.equal(res.status, 402);
    assert.match(await res.text(), /Diabeto Pro/);
  });

  it('refuses a garbage receipt', async () => {
    const res = await attestedRequest({ 'x-subscription-jws': 'not-a-jws' });
    assert.equal(res.status, 402);
  });

  it('refuses a self-signed receipt claiming an active subscription', async () => {
    // Everything a real receipt has — correct bundle id, a known product, an
    // expiry a year out — signed by a key that is not Apple's.
    const { privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    const forged = await new SignJWT({
      bundleId: BUNDLE_ID,
      productId: PRODUCT_ID,
      expiresDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
      type: 'Auto-Renewable Subscription',
      environment: 'Sandbox',
    })
      .setProtectedHeader({ alg: 'ES256', x5c: ['ZmFrZQ=='] })
      .sign(createPrivateKey(privateKey));

    const res = await attestedRequest({ 'x-subscription-jws': forged });
    assert.equal(res.status, 402, 'a receipt not signed by Apple must never be honoured');
  });

  it('refuses an unsigned receipt', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
    const claims = Buffer.from(
      JSON.stringify({ bundleId: BUNDLE_ID, productId: PRODUCT_ID, expiresDate: Date.now() + 1e9 }),
    ).toString('base64url');

    const res = await attestedRequest({ 'x-subscription-jws': `${header}.${claims}.` });
    assert.equal(res.status, 402);
  });

  it('reports the gate as on', async () => {
    const payload = (await (await h.app.request('/health')).json()) as { gates: { subscription: boolean } };
    assert.equal(payload.gates.subscription, true);
  });
});
