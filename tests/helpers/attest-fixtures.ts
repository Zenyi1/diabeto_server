/**
 * Synthetic App Attest fixtures.
 *
 * Apple's attestations can only be produced by a real Secure Enclave, so the
 * suite mints its own chain (root → intermediate → credential certificate) with a
 * correctly-computed nonce extension. `verifyAttestation` accepts a trust-anchor
 * override purely so these can reach steps 2-9; a chain pinned to Apple's real
 * root would fail at step 1 and leave every later check untested.
 *
 * Assertions need no such override — they verify against a stored public key, so
 * these are byte-for-byte what a real device produces.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, createPublicKey, randomBytes, sign as cryptoSign } from 'node:crypto';
import { encode as cborEncode } from 'cbor-x';

const AAGUID = {
  development: Buffer.from('appattestdevelop'),
  production: Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]),
} as const;

function openssl(args: string[]): void {
  execFileSync('openssl', args, { stdio: 'pipe' });
}

function pemToDer(pem: string): Buffer {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

interface Authority {
  dir: string;
  rootPem: string;
  intermediatePem: string;
  intermediateDer: Buffer;
  rootPath: string;
  rootKeyPath: string;
  intPath: string;
  intKeyPath: string;
}

const authorities = new Map<string, Authority>();

/** Builds (and caches) a root + intermediate pair. `name` gives independent CAs. */
function authority(name = 'default'): Authority {
  const cached = authorities.get(name);
  if (cached) return cached;

  const dir = mkdtempSync(join(tmpdir(), `attest-${name}-`));
  const rootKeyPath = join(dir, 'root.key');
  const rootPath = join(dir, 'root.pem');
  const intKeyPath = join(dir, 'int.key');
  const intPath = join(dir, 'int.pem');
  const intCsr = join(dir, 'int.csr');
  const intExt = join(dir, 'int.ext');

  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', rootKeyPath]);
  openssl([
    'req', '-new', '-x509', '-key', rootKeyPath, '-out', rootPath, '-days', '3650',
    '-subj', `/CN=Test App Attest Root ${name}`, '-addext', 'basicConstraints=critical,CA:TRUE',
  ]);

  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', intKeyPath]);
  openssl(['req', '-new', '-key', intKeyPath, '-out', intCsr, '-subj', '/CN=Apple App Attestation CA 1']);
  writeFileSync(intExt, 'basicConstraints=critical,CA:TRUE\n');
  openssl([
    'x509', '-req', '-in', intCsr, '-CA', rootPath, '-CAkey', rootKeyPath,
    '-out', intPath, '-days', '3650', '-extfile', intExt, '-set_serial', '2',
  ]);

  const intermediatePem = readFileSync(intPath, 'utf8');
  const built: Authority = {
    dir,
    rootPem: readFileSync(rootPath, 'utf8'),
    intermediatePem,
    intermediateDer: pemToDer(intermediatePem),
    rootPath,
    rootKeyPath,
    intPath,
    intKeyPath,
  };
  authorities.set(name, built);
  return built;
}

/** Raw uncompressed EC point (0x04 ‖ X ‖ Y) — what Apple hashes to make a key id. */
function publicKeyPoint(privateKeyPem: string): Buffer {
  const jwk = createPublicKey(privateKeyPem).export({ format: 'jwk' }) as { x: string; y: string };
  return Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, 'base64url'),
    Buffer.from(jwk.y, 'base64url'),
  ]);
}

export interface AttestationFixture {
  keyId: string;
  attestationBase64: string;
  privateKeyPem: string;
  /** Pass to verifyAttestation as trustedRootPem. */
  rootPem: string;
}

export interface AttestationOptions {
  appId: string;
  challenge: string;
  /** Bake a different challenge into the certificate to simulate a nonce mismatch. */
  nonceChallenge?: string;
  /** rpIdHash is computed from this; differs from appId to fake a foreign app. */
  authDataAppId?: string;
  environment?: 'development' | 'production';
  counter?: number;
  /** Corrupt the credentialId so it no longer equals the key id. */
  breakCredentialId?: boolean;
  /** Sign the leaf with an unrelated CA while still presenting the real root. */
  rogueIssuer?: boolean;
}

export function buildAttestation(options: AttestationOptions): AttestationFixture {
  const trusted = authority('default');
  const issuer = options.rogueIssuer ? authority('rogue') : trusted;

  const id = randomBytes(8).toString('hex');
  const keyPath = join(trusted.dir, `${id}.key`);
  const csrPath = join(trusted.dir, `${id}.csr`);
  const extPath = join(trusted.dir, `${id}.ext`);
  const certPath = join(trusted.dir, `${id}.pem`);

  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', keyPath]);
  const privateKeyPem = readFileSync(keyPath, 'utf8');

  const credentialId = createHash('sha256').update(publicKeyPoint(privateKeyPem)).digest();
  const keyId = credentialId.toString('base64');
  const embeddedCredentialId = options.breakCredentialId ? randomBytes(32) : credentialId;

  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(options.counter ?? 0);
  const credentialIdLength = Buffer.alloc(2);
  credentialIdLength.writeUInt16BE(embeddedCredentialId.length);

  const authData = Buffer.concat([
    createHash('sha256').update(options.authDataAppId ?? options.appId).digest(),
    Buffer.from([0x00]),
    counter,
    AAGUID[options.environment ?? 'development'],
    credentialIdLength,
    embeddedCredentialId,
  ]);

  const clientDataHash = createHash('sha256').update(options.nonceChallenge ?? options.challenge).digest();
  const nonce = createHash('sha256').update(Buffer.concat([authData, clientDataHash])).digest();

  // SEQUENCE { [1] { OCTET STRING(32) } } — Apple's nonce extension shape.
  writeFileSync(extPath, `1.2.840.113635.100.8.2=DER:3024A1220420${nonce.toString('hex')}\n`);
  openssl(['req', '-new', '-key', keyPath, '-out', csrPath, '-subj', '/CN=test credential']);
  openssl([
    'x509', '-req', '-in', csrPath, '-CA', issuer.intPath, '-CAkey', issuer.intKeyPath,
    '-out', certPath, '-days', '3650', '-extfile', extPath, '-set_serial', String(Date.now() % 100000),
  ]);

  const attestation = cborEncode({
    fmt: 'apple-appattest',
    attStmt: {
      x5c: [pemToDer(readFileSync(certPath, 'utf8')), issuer.intermediateDer],
      receipt: Buffer.from('synthetic-receipt'),
    },
    authData,
  });

  return {
    keyId,
    attestationBase64: Buffer.from(attestation).toString('base64'),
    privateKeyPem,
    // Always the trusted root: a rogue-issuer fixture must still be checked
    // against the root the server pins, which is the point of that test.
    rootPem: trusted.rootPem,
  };
}

export interface AssertionOptions {
  privateKeyPem: string;
  appId: string;
  counter: number;
  body: Buffer;
}

/** Byte-identical to what DCAppAttestService.generateAssertion produces. */
export function buildAssertion(options: AssertionOptions): string {
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(options.counter);
  const authenticatorData = Buffer.concat([
    createHash('sha256').update(options.appId).digest(),
    Buffer.from([0x00]),
    counter,
  ]);

  const clientDataHash = createHash('sha256').update(options.body).digest();
  const nonce = createHash('sha256').update(Buffer.concat([authenticatorData, clientDataHash])).digest();
  const signature = cryptoSign('sha256', nonce, options.privateKeyPem);

  return Buffer.from(cborEncode({ signature, authenticatorData })).toString('base64');
}
