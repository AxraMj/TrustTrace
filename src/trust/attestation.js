// Shared attestation primitives (no secrets here).
//
// Scheme: Ed25519 (RFC 8032) via Node's built-in crypto (crypto.sign / crypto.verify with a null
// algorithm, per the Node.js crypto docs). Chosen over HMAC-SHA256 on purpose: with HMAC every
// party that can VERIFY can also FORGE (Agent B would hold the signing secret). With Ed25519 only
// the verification authority holds the private key; Agent B holds a public key and cannot mint
// evidence even if it is compromised.
//
// What is signed (canonical, fixed field order, domain-separated):
//   v, iss (issuer), kid (key id), caseId, accountId, kind, method (verification method),
//   statementSha256 (hash of the canonical memory statement), iat, exp (ms epoch), nonce.
import { createHash, createPublicKey } from 'node:crypto';

export const ATTESTATION_VERSION = 1;
export const DOMAIN_PREFIX = 'TRUSTTRACE-ATTESTATION-v1\n';
export const DEFAULT_ISSUER = 'trusttrace-verification-authority';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

/** Maximum validity per evidence kind. Unknown kinds can neither be issued nor accepted. */
export const MAX_TTL_MS = Object.freeze({
  callback_verified: 15 * MIN,
  identity_verified: 15 * MIN,
  device_verified: DAY,
  confirmed_attack_pattern: 90 * DAY,
});
/** Identity evidence authorises ONE sensitive action; replaying it for another event is rejected. */
export const SINGLE_USE_KINDS = new Set(['callback_verified', 'identity_verified']);

export class AttestationFormatError extends Error {}

export const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

export function keyIdOf(publicKeyPem) {
  const der = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').slice(0, 16);
}

const PAYLOAD_FIELDS = ['v', 'iss', 'kid', 'caseId', 'accountId', 'kind', 'method', 'statementSha256', 'iat', 'exp', 'nonce'];

/** The exact bytes that are signed. Field order is fixed so signer and verifier always agree. */
export function signingInput(p) {
  const ordered = {};
  for (const f of PAYLOAD_FIELDS) ordered[f] = p[f];
  return Buffer.from(DOMAIN_PREFIX + JSON.stringify(ordered), 'utf8');
}

export function encodeEnvelope(payload, sigBuffer) {
  return Buffer.from(JSON.stringify({ p: payload, s: sigBuffer.toString('base64url') }), 'utf8').toString('base64url');
}

/** Strictly decode an envelope; any deviation from the expected shape is a format error. */
export function decodeEnvelope(str) {
  let obj;
  try {
    obj = JSON.parse(Buffer.from(String(str), 'base64url').toString('utf8'));
  } catch {
    throw new AttestationFormatError('not valid base64url JSON');
  }
  const p = obj?.p;
  if (!p || typeof p !== 'object' || typeof obj.s !== 'string') throw new AttestationFormatError('missing payload/signature');
  const keys = Object.keys(p).sort().join(',');
  if (keys !== [...PAYLOAD_FIELDS].sort().join(',')) throw new AttestationFormatError('unexpected payload fields');
  for (const f of ['iss', 'kid', 'caseId', 'accountId', 'kind', 'method', 'statementSha256', 'nonce']) {
    if (typeof p[f] !== 'string' || !p[f]) throw new AttestationFormatError(`bad field ${f}`);
  }
  for (const f of ['v', 'iat', 'exp']) if (!Number.isInteger(p[f])) throw new AttestationFormatError(`bad field ${f}`);
  if (p.v !== ATTESTATION_VERSION) throw new AttestationFormatError('unsupported version');
  return { payload: p, sig: Buffer.from(obj.s, 'base64url') };
}
