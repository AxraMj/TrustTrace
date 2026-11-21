// THE VERIFICATION AUTHORITY - the only component that can create VERIFIED evidence.
//
// It holds the Ed25519 PRIVATE key. Ordinary agents (src/agents/*) and the Meko layer (src/meko/*)
// must never import this module; a test enforces that boundary statically. Be honest about the limit:
// in this proof of concept the authority is an in-process object, so the boundary is architectural
// (code structure), not an OS/process boundary. Production needs a separate service or HSM with
// authenticated issuance - see the security assessment.
import { createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { TrustViolationError } from '../errors.js';
import { canonicalStatement } from '../labels.js';
import { DEFAULT_ISSUER, ATTESTATION_VERSION, MAX_TTL_MS, encodeEnvelope, keyIdOf, sha256Hex, signingInput } from './attestation.js';

export const AUTHORITY_AGENT_ID = 'trusttrace_verification_authority';

export function generateTrustKeys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

export class VerificationAuthority {
  #privateKey;

  /**
   * @param {{privateKeyPem:string, issuer?:string, clock?:()=>number}} opts
   */
  constructor({ privateKeyPem, issuer = DEFAULT_ISSUER, clock = Date.now, onIssued = null }) {
    this.#privateKey = createPrivateKey(privateKeyPem);
    this.issuer = issuer;
    this.clock = clock;
    this.onIssued = onIssued; // async hook receiving the NON-SECRET attestation payload (persisted to the replay ledger / audit log)
    this.publicKeyPem = createPublicKey(this.#privateKey).export({ type: 'spki', format: 'pem' });
    this.kid = keyIdOf(this.publicKeyPem);
    this.agentId = AUTHORITY_AGENT_ID;
  }

  /** Authority with a fresh in-memory key (tests, demos). */
  static ephemeral(opts = {}) {
    return new VerificationAuthority({ privateKeyPem: generateTrustKeys().privateKeyPem, ...opts });
  }

  /** Authority from a key file the agents never read (e.g. secrets/verifier-private.pem). */
  static fromKeyFile(path, opts = {}) {
    return new VerificationAuthority({ privateKeyPem: readFileSync(path, 'utf8'), ...opts });
  }

  /** Trust anchor to hand to Agent B: PUBLIC material only. */
  get trustAnchor() {
    return { publicKeyPem: this.publicKeyPem, issuer: this.issuer };
  }

  /** Sign evidence that an independent verification succeeded. Returns the attestation envelope. */
  issue({ caseId, accountId, kind, method, statement, ttlMs }) {
    const max = MAX_TTL_MS[kind];
    if (!max) throw new TrustViolationError(`Authority refuses to attest unknown evidence kind "${kind}".`);
    const ttl = ttlMs ?? max;
    if (!(ttl > 0) || ttl > max) throw new TrustViolationError(`ttlMs for ${kind} must be in (0, ${max}].`);
    if (!method) throw new TrustViolationError('A verification method is required.');
    const now = this.clock();
    const payload = {
      v: ATTESTATION_VERSION, iss: this.issuer, kid: this.kid, caseId, accountId, kind, method,
      statementSha256: sha256Hex(canonicalStatement(statement)),
      iat: now, exp: now + ttl, nonce: randomBytes(16).toString('hex'),
    };
    const sig = sign(null, signingInput(payload), this.#privateKey);
    return { attestation: encodeEnvelope(payload, sig), payload };
  }

  /** Issue + store a VERIFIED memory. The store only needs save(); it never sees the key. */
  async record(store, { caseId, accountId, runId, kind, method, statement, ttlMs }) {
    const { attestation, payload } = this.issue({ caseId, accountId, kind, method, statement, ttlMs });
    // Persist the issuance BEFORE the evidence exists in Meko: if the ledger is unavailable, no evidence is created (fail closed).
    if (this.onIssued) await this.onIssued(payload);
    return store.save({ agentId: this.agentId, caseId, accountId, runId, label: 'VERIFIED', kind, statement, verifiedBy: method, attestation });
  }
}
