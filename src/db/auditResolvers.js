import { decisionHashes } from './decisionRepo.js';
import { consumedHashes, issuedHashes } from './replayGuard.js';

/** record_type -> async (pool, refIds) => Map(refId -> payloadHash). Used by verifyChain() to re-hash every audited row. */
export const AUDIT_RESOLVERS = Object.freeze({
  decision: decisionHashes,
  attestation_issued: issuedHashes,
  attestation_consumed: consumedHashes,
});
