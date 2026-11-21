// Agent B's side: verifies attestations with PUBLIC keys only. Cannot sign anything.
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalStatement } from '../labels.js';
import { AttestationFormatError, MAX_TTL_MS, SINGLE_USE_KINDS, decodeEnvelope, keyIdOf, sha256Hex, signingInput } from './attestation.js';

/** Rejection reasons that indicate tampering/forgery (the record claims to be authentic but is not). */
export const FORGERY_REASONS = new Set([
  'missing_attestation', 'malformed_attestation', 'unknown_issuer_or_key', 'bad_signature', 'content_modified',
  'account_mismatch', 'case_mismatch', 'kind_mismatch', 'method_mismatch', 'ttl_policy_violation', 'issued_in_future',
]);

/** Remembers which single-use verifications were spent on which event. In-process only (see risks). */
export class ReplayGuard {
  #spent = new Map(); // nonce -> { eventId, exp }
  isReplay(nonce, eventId) {
    const s = this.#spent.get(nonce);
    return Boolean(s) && s.eventId !== eventId;
  }
  consume(nonce, eventId, exp) {
    if (!this.#spent.has(nonce)) this.#spent.set(nonce, { eventId, exp });
    const now = Date.now();
    for (const [n, s] of this.#spent) if (s.exp < now - 3_600_000) this.#spent.delete(n); // prune long-expired
  }
  get size() {
    return this.#spent.size;
  }
}

export class AttestationVerifier {
  #keys = new Map(); // kid -> { publicKey, issuer }

  /**
   * @param {{trustAnchors: {publicKeyPem:string, issuer:string}[], clock?:()=>number, skewMs?:number}} opts
   */
  constructor({ trustAnchors, clock = Date.now, skewMs = 5 * 60_000 }) {
    for (const a of trustAnchors) this.#keys.set(keyIdOf(a.publicKeyPem), { publicKey: createPublicKey(a.publicKeyPem), issuer: a.issuer });
    this.clock = clock;
    this.skewMs = skewMs;
  }

  /** Key ids of the trust anchors (public information; stored with each decision). */
  get keyIds() {
    return [...this.#keys.keys()];
  }

  /**
   * Check a parsed VERIFIED memory. Never throws on bad evidence: returns { ok:false, reason }.
   * An invalid record is REJECTED - it is never downgraded to a trusted observation.
   */
  verify(memory, { replay, eventId } = {}) {
    const bad = (reason, detail) => ({ ok: false, reason, detail });
    if (!memory.attestation) return bad('missing_attestation', 'memory claims VERIFIED but carries no signed attestation');

    let env;
    try {
      env = decodeEnvelope(memory.attestation);
    } catch (e) {
      return bad('malformed_attestation', e instanceof AttestationFormatError ? e.message : 'undecodable');
    }
    const p = env.payload;

    const key = this.#keys.get(p.kid);
    if (!key || key.issuer !== p.iss) return bad('unknown_issuer_or_key', `kid ${p.kid} / issuer ${p.iss} is not a trust anchor`);

    let sigOk = false;
    try {
      sigOk = cryptoVerify(null, signingInput(p), key.publicKey, env.sig);
    } catch {
      sigOk = false;
    }
    if (!sigOk) return bad('bad_signature', 'signature does not match the signed payload');

    // Signature is authentic. Now check it is bound to THIS memory.
    if (p.accountId !== memory.accountId) return bad('account_mismatch', `attested for ${p.accountId}, presented for ${memory.accountId}`);
    if (p.caseId !== memory.caseId) return bad('case_mismatch', `attested for case ${p.caseId}, presented for ${memory.caseId}`);
    if (p.kind !== memory.kind) return bad('kind_mismatch', `attested kind ${p.kind}, memory kind ${memory.kind}`);
    if (p.method !== memory.verifiedBy) return bad('method_mismatch', `attested method ${p.method}, memory method ${memory.verifiedBy}`);
    if (p.statementSha256 !== sha256Hex(canonicalStatement(memory.statement))) {
      return bad('content_modified', 'memory text differs from what the authority attested');
    }

    const now = this.clock();
    if (p.iat > now + this.skewMs) return bad('issued_in_future', 'attestation is dated in the future');
    if (now >= p.exp) return bad('expired', `expired ${Math.round((now - p.exp) / 1000)}s ago`);
    const max = MAX_TTL_MS[p.kind];
    if (!max || p.exp - p.iat > max) return bad('ttl_policy_violation', 'validity window exceeds policy for this kind');

    if (SINGLE_USE_KINDS.has(p.kind)) {
      // Fail closed: if the persistent replay ledger cannot be read we cannot prove the evidence is unspent, so it is not trusted.
      if (replay?.unavailable) return bad('replay_ledger_unavailable', 'the replay ledger could not be consulted, so single-use evidence cannot be trusted');
      if (replay?.isReplay(p.nonce, eventId)) return bad('replayed', 'this single-use verification was already spent on a different event');
    }
    return { ok: true, payload: p };
  }
}
