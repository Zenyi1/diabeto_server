/**
 * StoreKit 2 subscription verification.
 *
 * The app sends the `jwsRepresentation` of its current entitlement. Apple signs
 * that blob, so everything needed to trust it is inside the JWS plus Apple's root
 * certificate — no App Store Connect API key, and no linking table between the
 * Apple sign-in id and the App Store account. Because the client re-reads
 * `Transaction.currentEntitlements` each time, a lapse or refund takes effect on
 * the very next call.
 */

import { Environment, SignedDataVerifier } from '@apple/app-store-server-library';
import { APPLE_ROOT_CA_G3_DER } from './certs.js';
import { config } from './config.js';
import { redis } from './redis.js';

let verifier: SignedDataVerifier | null = null;

function signedDataVerifier(): SignedDataVerifier {
  verifier ??= new SignedDataVerifier(
    [APPLE_ROOT_CA_G3_DER],
    config.subscription.onlineChecks,
    config.subscription.env === 'production' ? Environment.PRODUCTION : Environment.SANDBOX,
    config.apple.bundleId,
    config.subscription.appAppleId,
  );
  return verifier;
}

export class SubscriptionError extends Error {}

export interface ActiveSubscription {
  productId: string;
  expiresDate: number;
}

export interface SubscriptionRecord extends ActiveSubscription {
  checkedAt: number;
}

/**
 * Remembers the last verified entitlement so the admin views can answer "who is
 * subscribed" without an Apple round trip. Verification itself still happens on
 * every request — this is a read model, never the gate.
 */
export async function rememberSubscription(userId: string, active: ActiveSubscription): Promise<void> {
  try {
    const record: SubscriptionRecord = { ...active, checkedAt: Date.now() };
    await redis().set(`subscription:${userId}`, record);
  } catch (error) {
    console.warn('[subscription] failed to record status:', error);
  }
}

export async function readSubscription(userId: string): Promise<SubscriptionRecord | null> {
  try {
    return await redis().get<SubscriptionRecord>(`subscription:${userId}`);
  } catch {
    return null;
  }
}

/** Throws SubscriptionError unless the JWS proves a currently-active entitlement. */
export async function verifySubscriptionJws(jws: string): Promise<ActiveSubscription> {
  let payload;
  try {
    payload = await signedDataVerifier().verifyAndDecodeTransaction(jws);
  } catch (error) {
    console.warn('[subscription] JWS verification failed:', error);
    throw new SubscriptionError('subscription receipt could not be verified');
  }

  if (payload.bundleId !== config.apple.bundleId) {
    throw new SubscriptionError('subscription receipt is for a different app');
  }
  if (!payload.productId || !config.subscription.productIds.includes(payload.productId)) {
    throw new SubscriptionError('subscription product is not recognised');
  }
  if (payload.revocationDate) {
    throw new SubscriptionError('subscription was refunded or revoked');
  }
  if (!payload.expiresDate || payload.expiresDate <= Date.now()) {
    throw new SubscriptionError('subscription has expired');
  }

  return { productId: payload.productId, expiresDate: payload.expiresDate };
}
