/**
 * App Attest verification.
 *
 * Implements Apple's "Validating apps that connect to your server" steps for both
 * the one-time attestation (key registration) and the per-request assertion.
 *
 * Two details are easy to get wrong and are load-bearing here:
 *
 *  - The signature is ECDSA **over SHA256 of the nonce**, and the nonce is itself a
 *    SHA256. So verification hashes twice: `verify('sha256', nonce, ...)`, not a raw
 *    digest verify. Getting this wrong rejects every genuine request.
 *  - `clientDataHash` for registration is SHA256 of the challenge **string bytes**
 *    (the client does `SHA256(Data(challenge.utf8))`), not of its decoded base64.
 */

import { decode as cborDecode } from 'cbor-x';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { X509Certificate, createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { APP_ATTEST_ROOT_CA_PEM } from './certs.js';
import { config } from './config.js';

/** Apple's nonce extension on the credential certificate. */
const NONCE_OID = '1.2.840.113635.100.8.2';

const AAGUID_DEVELOPMENT = Buffer.from('appattestdevelop');
const AAGUID_PRODUCTION = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);

export type AttestEnvironment = 'development' | 'production';

/**
 * The signature counter deliberately lives in a sorted set, not here — see
 * `bumpAttestCounter`. Keeping one source of truth for it is what makes the
 * replay check atomic.
 */
export interface AttestKeyRecord {
  userId: string;
  publicKeyPem: string;
  environment: AttestEnvironment;
  createdAt: number;
}

export class AttestError extends Error {}

function fail(message: string): never {
  throw new AttestError(message);
}

function toBuffer(value: unknown, what: string): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return fail(`${what} is not a byte string`);
}

/** SHA256 of "<teamId>.<bundleId>", which is what authData's rpIdHash commits to. */
function appIdHash(): Buffer {
  return createHash('sha256').update(config.apple.appId).digest();
}

interface AuthenticatorData {
  rpIdHash: Buffer;
  counter: number;
  aaguid: Buffer;
  credentialId: Buffer;
}

function parseAuthData(authData: Buffer, withCredential: boolean): AuthenticatorData {
  const minimum = withCredential ? 55 : 37;
  if (authData.length < minimum) fail('authenticator data is truncated');

  const base = {
    rpIdHash: authData.subarray(0, 32),
    counter: authData.readUInt32BE(33),
  };
  if (!withCredential) {
    return { ...base, aaguid: Buffer.alloc(0), credentialId: Buffer.alloc(0) };
  }

  const credentialIdLength = authData.readUInt16BE(53);
  if (authData.length < 55 + credentialIdLength) fail('authenticator data is truncated');
  return {
    ...base,
    aaguid: authData.subarray(37, 53),
    credentialId: authData.subarray(55, 55 + credentialIdLength),
  };
}

/**
 * Collects every OCTET STRING in a parsed ASN.1 tree.
 *
 * The nonce lives at a fixed path (SEQUENCE → [1] → OCTET STRING), but searching
 * rather than indexing keeps this working if Apple ever pads the structure. It
 * stays safe because the caller compares the full 32-byte nonce for equality and
 * the whole certificate is signed by Apple — a wrong pick fails closed.
 */
function collectOctetStrings(node: asn1js.AsnType, into: Buffer[] = []): Buffer[] {
  if (node instanceof asn1js.OctetString) {
    into.push(Buffer.from(node.valueBlock.valueHexView));
  }
  const children = (node as { valueBlock?: { value?: unknown } }).valueBlock?.value;
  if (Array.isArray(children)) {
    for (const child of children) collectOctetStrings(child as asn1js.AsnType, into);
  }
  return into;
}

/**
 * Verifies an attestation object and returns the public key to store for this
 * install, plus the environment it was produced in.
 *
 * @param attestationBase64 the raw `attestKey` output, base64 encoded
 * @param keyId             base64 key id from `DCAppAttestService.generateKey()`
 * @param challenge         the exact challenge string this server issued
 */
export function verifyAttestation(params: {
  attestationBase64: string;
  keyId: string;
  challenge: string;
  /**
   * Trust anchor override. Only the test suite passes this — it lets a synthetic
   * chain exercise steps 2-9, which a chain pinned to Apple's root could never
   * reach. Production callers omit it and get the pinned root below.
   */
  trustedRootPem?: string;
}): { publicKeyPem: string; environment: AttestEnvironment } {
  let decoded: { fmt?: string; attStmt?: { x5c?: unknown[]; receipt?: unknown }; authData?: unknown };
  try {
    decoded = cborDecode(Buffer.from(params.attestationBase64, 'base64'));
  } catch {
    return fail('attestation is not valid CBOR');
  }

  if (decoded?.fmt !== 'apple-appattest') fail('unexpected attestation format');
  const x5c = decoded.attStmt?.x5c;
  if (!Array.isArray(x5c) || x5c.length !== 2) fail('attestation certificate chain is malformed');

  const authData = toBuffer(decoded.authData, 'authData');

  // 1. Chain the credential certificate to Apple's App Attest root.
  let leaf: X509Certificate;
  let intermediate: X509Certificate;
  try {
    leaf = new X509Certificate(toBuffer(x5c[0], 'credential certificate'));
    intermediate = new X509Certificate(toBuffer(x5c[1], 'intermediate certificate'));
  } catch {
    return fail('attestation certificates are not valid X.509');
  }
  const root = new X509Certificate(params.trustedRootPem ?? APP_ATTEST_ROOT_CA_PEM);

  const now = Date.now();
  for (const [cert, label] of [
    [leaf, 'credential certificate'],
    [intermediate, 'intermediate certificate'],
  ] as const) {
    if (now < cert.validFromDate.getTime() || now > cert.validToDate.getTime()) {
      fail(`${label} is outside its validity window`);
    }
  }
  if (!intermediate.verify(root.publicKey)) fail('intermediate certificate is not signed by the Apple App Attest root');
  if (!leaf.verify(intermediate.publicKey)) fail('credential certificate is not signed by the Apple intermediate');

  // 2-3. nonce = SHA256(authData || SHA256(challenge)).
  const clientDataHash = createHash('sha256').update(params.challenge).digest();
  const nonce = createHash('sha256').update(Buffer.concat([authData, clientDataHash])).digest();

  // 4. The credential certificate must carry that exact nonce.
  const parsedLeaf = new pkijs.Certificate({ schema: asn1js.fromBER(leaf.raw).result });
  const nonceExtension = parsedLeaf.extensions?.find((extension) => extension.extnID === NONCE_OID);
  if (!nonceExtension) fail('credential certificate has no App Attest nonce extension');

  const extensionBody = asn1js.fromBER(nonceExtension.extnValue.valueBlock.valueHexView);
  if (extensionBody.offset === -1) fail('App Attest nonce extension is not valid DER');
  const candidates = collectOctetStrings(extensionBody.result);
  if (!candidates.some((candidate) => candidate.length === nonce.length && candidate.equals(nonce))) {
    fail('attestation nonce does not match the issued challenge');
  }

  // 5. The key id must be the SHA256 of the certificate's raw public key point.
  const publicKeyPoint = Buffer.from(parsedLeaf.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
  const derivedKeyId = createHash('sha256').update(publicKeyPoint).digest('base64');
  if (derivedKeyId !== params.keyId) fail('key id does not match the attested public key');

  // 6. The app id this key was minted for must be ours.
  const authenticator = parseAuthData(authData, true);
  if (!authenticator.rpIdHash.equals(appIdHash())) {
    fail('attestation was issued for a different app id');
  }

  // 7. A freshly attested key has never signed anything.
  if (authenticator.counter !== 0) fail('attestation counter is not zero');

  // 8. Environment must match how this server is configured.
  let environment: AttestEnvironment;
  if (authenticator.aaguid.equals(AAGUID_PRODUCTION)) {
    environment = 'production';
  } else if (authenticator.aaguid.equals(AAGUID_DEVELOPMENT)) {
    environment = 'development';
    if (config.apple.attestEnv === 'production') {
      fail('development attestation rejected while APP_ATTEST_ENV=production');
    }
  } else {
    return fail('unrecognised attestation environment');
  }

  // 9. And the embedded credential id must be the same key id again.
  if (authenticator.credentialId.toString('base64') !== params.keyId) {
    fail('credential id does not match the key id');
  }

  return {
    publicKeyPem: leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    environment,
  };
}

const publicKeyCache = new Map<string, KeyObject>();

/**
 * Verifies a per-request assertion over the raw body bytes and returns the
 * counter it carries. The caller must persist that counter with a
 * compare-and-set — this function deliberately does not decide replay on its own.
 */
export function verifyAssertion(params: {
  assertionBase64: string;
  rawBody: Buffer;
  publicKeyPem: string;
}): { counter: number } {
  let decoded: { signature?: unknown; authenticatorData?: unknown };
  try {
    decoded = cborDecode(Buffer.from(params.assertionBase64, 'base64'));
  } catch {
    return fail('assertion is not valid CBOR');
  }

  const signature = toBuffer(decoded.signature, 'assertion signature');
  const authenticatorData = toBuffer(decoded.authenticatorData, 'assertion authenticator data');

  const clientDataHash = createHash('sha256').update(params.rawBody).digest();
  const nonce = createHash('sha256').update(Buffer.concat([authenticatorData, clientDataHash])).digest();

  let key = publicKeyCache.get(params.publicKeyPem);
  if (!key) {
    key = createPublicKey(params.publicKeyPem);
    publicKeyCache.set(params.publicKeyPem, key);
  }

  // 'sha256', not a raw digest verify — see the note at the top of this file.
  if (!verifySignature('sha256', nonce, key, signature)) fail('assertion signature is invalid');

  const authenticator = parseAuthData(authenticatorData, false);
  if (!authenticator.rpIdHash.equals(appIdHash())) fail('assertion was signed for a different app id');

  return { counter: authenticator.counter };
}
