import { existsSync } from 'node:fs';
import { AUDIT_RESOLVERS } from '../db/auditResolvers.js';
import { verifyChain } from '../db/auditChain.js';
import { migrationStatus } from '../db/migrate.js';
import { pingDb } from '../db/pool.js';
import { createUserStore } from '../db/userRepo.js';
import { createInvestigationStore } from '../db/investigationRepo.js';
import { EXTRACTOR_VERSION, MODEL_VERSION, POLICY_VERSION } from '../versions.js';

/**
 * Dependencies of the REST API, backed by the real PostgreSQL pool. Nothing in the health view contains a credential:
 * only booleans and counters (the Meko API key and the signing key are never read here).
 */
export function buildDeps({ pool, config, getServerStats = () => ({}), getActivityStats = () => null }) {
  return {
    users: createUserStore(pool),
    data: createInvestigationStore(pool), // read-only investigation queries (Phase 2)
    ping: () => pingDb(pool),
    audit: { verify: () => verifyChain(pool, { resolvers: AUDIT_RESOLVERS }) },
    health: async () => {
      const db = await pingDb(pool);
      const out = { status: db.ok ? 'ok' : 'degraded', db, versions: { model: MODEL_VERSION, extractor: EXTRACTOR_VERSION, policy: POLICY_VERSION } };
      if (!db.ok) return out;
      const mig = await migrationStatus(pool);
      const head = (await pool.query('SELECT seq, record_hash, created_at FROM audit_records ORDER BY seq DESC LIMIT 1')).rows[0];
      const counts = (await pool.query(
        `SELECT (SELECT count(*) FROM decisions) AS decisions, (SELECT count(*) FROM agent_events) AS agent_events,
                (SELECT count(*) FROM attestation_nonces) AS nonces, (SELECT count(*) FROM attestation_nonces WHERE consumed_event_id IS NOT NULL) AS nonces_consumed,
                (SELECT max(at) FROM agent_events) AS last_agent_event, (SELECT max(created_at) FROM decisions) AS last_decision`)).rows[0];
      return {
        ...out,
        migrations: { applied: mig.applied.length, pending: mig.pending.length, modified: mig.modified.length, upToDate: mig.upToDate },
        audit: { headSeq: head?.seq ?? 0, headHash: head?.record_hash ?? null, headAt: head?.created_at ?? null },
        counts: { decisions: counts.decisions, agentEvents: counts.agent_events, attestationNonces: counts.nonces, attestationNoncesConsumed: counts.nonces_consumed },
        lastDecisionAt: counts.last_decision, lastAgentEventAt: counts.last_agent_event,
        activityRecorder: getActivityStats(),
        server: getServerStats(),
        replayLedger: 'postgresql',
        mekoConfigured: config.mekoConfigured, // boolean only: the key is never exposed
        trustAnchorPresent: existsSync('config/trust-anchor.pem'),
      };
    },
  };
}
