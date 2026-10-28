/**
 * Writes the seals of tests/fixtures/seal/: containers made by the Node.js
 * library ezxmldsig-js, a creator apart from the PHP library, and checked by
 * its verifySeal(). Run by bin/gen-seal-fixtures, from a clone of
 * ezxmldsig-js (whose test helpers build the time-stamps, the CRLs and the
 * OCSP responses), with the output directory as argument.
 *
 * The times are relative to the run: the seal is signed a minute before it,
 * time-stamped 50 seconds before, and its CRLs and OCSP responses are issued
 * 40 seconds before, after the time-stamp. Data issued after the time-stamp
 * keep proving the status of the signer at that time: the seals of levels T
 * and LT stay valid as long as their certificates (2036). A seal of level B
 * needs current CRLs, which the PHP tests issue when they run.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { RSA_PSS_SHA512, RSA_SHA256, SHA512 } from './dist/core/index.js';
import { addSignatureTimestamp, addValidationData, createSeal, timestampRequest, verifySeal } from './dist/seal/index.js';
import { timestampResponse } from './test/helpers/tsa.ts';
import { makeCrl } from './test/helpers/crl.ts';
import { makeOcspResponse } from './test/helpers/ocsp.ts';

const out = process.argv[2] as string;
const CERTS = 'test/fixtures/seal/certs';
// The P-521 signer is issued by bin/gen-seal-fixtures, under the same intermediate CA.
const dir = (name: string) => (name === 'p521' ? join(out, 'p521') : CERTS);
const cert = (name: string) => `${dir(name)}/${name}.cert.pem`;
const key = (name: string) => `${dir(name)}/${name}.key.pem`;
const ROOT = cert('root');
const TSA_ROOT = cert('tsa-root');
const NOW = Date.now();
const ago = (seconds: number) => new Date(NOW - seconds * 1000);

mkdirSync(join(out, 'containers'), { recursive: true });
mkdirSync(join(out, 'revocation'), { recursive: true });

const files = [
  { name: 'contract.txt', content: Buffer.from('The contract, sealed.\n') },
  { name: 'annexes/résumé 1.md', content: Buffer.from('# Résumé\n\nOf the contract.\n') },
  { name: 'data.bin', content: Buffer.from(Array.from({ length: 2048 }, (_, i) => (i * 7) % 256)) },
];
const signingTime = ago(60);
const seal = (signer: string, options: Record<string, unknown> = {}) =>
  createSeal(files, key(signer), cert(signer), 'signKeyPassword', { chain: [cert(signer === 'offline' ? 'intermediate-offline' : 'intermediate')], signingTime, ...options });
const timestamped = (container: Buffer) =>
  addSignatureTimestamp(container, timestampResponse(timestampRequest(container), { time: ago(50) }), { tsaCertPath: TSA_ROOT });

// The CRLs and OCSP responses, issued after the time-stamp.
const after = ago(40);
const revocation = {
  'intermediate.crl': makeCrl({ issuer: 'intermediate', thisUpdate: after, revoked: [{ cert: 'revoked', date: ago(55) }] }),
  'root.crl': makeCrl({ issuer: 'root', thisUpdate: after }),
  'tsa-root.crl': makeCrl({ issuer: 'tsa-root', thisUpdate: after }),
  'rsa3072.ocsp': makeOcspResponse({ cert: 'rsa3072', signer: 'ocsp', thisUpdate: after }),
  'tsa.ocsp': makeOcspResponse({ cert: 'tsa', issuer: 'tsa-root', thisUpdate: after }),
};
for (const [name, der] of Object.entries(revocation)) {
  writeFileSync(join(out, 'revocation', name), der);
}
const crls = [revocation['intermediate.crl'], revocation['root.crl'], revocation['tsa-root.crl']];

const b = seal('rsa3072');
const t = timestamped(b);
const containers: Record<string, Buffer> = {
  // Level B, each signature algorithm the seals accept.
  'b-rsa-pss-sha256': b,
  'b-rsa-sha256': seal('rsa3072', { signatureAlgorithm: RSA_SHA256 }),
  'b-rsa2048-pss-sha512': seal('rsa2048', { signatureAlgorithm: RSA_PSS_SHA512, digestAlgorithm: SHA512 }),
  'b-ecdsa-p256': seal('p256'),
  'b-ecdsa-p384': seal('p384'),
  'b-ecdsa-p521': seal('p521'),
  'b-revoked': seal('revoked'),
  'b-rsa1024': (() => { try { return seal('rsa1024'); } catch { return null; } })() as Buffer,
  'b-no-chain': createSeal(files, key('rsa3072'), cert('rsa3072'), 'signKeyPassword', { signingTime }),
  // Level T, then LT with CRLs, and with OCSP responses for the signer and the authority.
  't-rsa-pss-sha256': t,
  'lt-crl': addValidationData(t, { caCertPath: ROOT, tsaCertPath: TSA_ROOT, crls }),
  'lt-ocsp': addValidationData(t, { caCertPath: ROOT, tsaCertPath: TSA_ROOT, crls: [revocation['root.crl']], ocspResponses: [revocation['rsa3072.ocsp'], revocation['tsa.ocsp']] }),
};

// What verifySeal() of the Node.js library says of each, now.
const verdicts: Record<string, unknown> = {};
for (const [name, container] of Object.entries(containers)) {
  if (container === null) {
    continue;
  }
  writeFileSync(join(out, 'containers', `${name}.asice`), container);
  const options = { caCertPath: ROOT, tsaCertPath: TSA_ROOT, crls: Object.values(revocation).filter((_, i) => i < 3) };
  const result = verifySeal(container, name.startsWith('b-') ? { ...options, crls: [makeCrl({ issuer: 'intermediate', revoked: [{ cert: 'revoked', date: ago(55) }] }), makeCrl({ issuer: 'root' })] } : options);
  verdicts[name] = {
    valid: result.isValid(),
    error: result.getError(),
    level: result.getLevel(),
    files: result.getFiles(),
    signingTime: result.getSigningTime()?.toISOString() ?? null,
    timestampTime: result.getTimestampTime()?.toISOString() ?? null,
    signer: result.getSigningCertificate()?.getDN() ?? null,
  };
}
writeFileSync(join(out, 'verdicts.json'), `${JSON.stringify(verdicts, null, 2)}\n`);
console.log(JSON.stringify(Object.fromEntries(Object.entries(verdicts).map(([name, v]) => [name, (v as { level: string; error: string }).level ?? (v as { error: string }).error]))));
