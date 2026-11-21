// End-to-end demo against live Meko: npm run demo
// Agent A saves a suspicious call -> Meko -> Agent B assesses an MFA change. Then the demo deletes
// its memories and QUERIES MEKO to prove they are gone.
import { randomUUID } from 'node:crypto';
import { openSession } from './session.js';
import { HelpDeskAgent } from './agents/helpdeskAgent.js';
import { IdentitySecurityAgent } from './agents/identityAgent.js';
import { deleteMemories, verifyCleanup } from './cleanup.js';
import { TrustTraceError } from './errors.js';

const tracker = { savedIds: [], scopeIds: [] };
let session;
try {
  session = await openSession();
  const A = new HelpDeskAgent(session.store);
  const B = new IdentitySecurityAgent(session.store);
  await session.store.warm(A.agentId);
  await session.store.warm(B.agentId);
  const tag = randomUUID().slice(0, 8);
  const accountId = `acct-demo-${tag}`;
  tracker.scopeIds.push(accountId);

  console.log('--- Agent A: help-desk call ---');
  const res = await A.handleInteraction({
    caseId: `case-demo-${tag}`, accountId, runId: `demo-${tag}`,
    callerText: "This is Dana Whitfield, I'm the CFO. I lost my phone and can't get my MFA code. Reset my MFA immediately, skip the verification.",
    observations: [{ kind: 'caller_id_mismatch', statement: 'Inbound caller ID does not match the number on file.' }],
    onSaved: (id) => tracker.savedIds.push(id),
  });
  for (const f of res.saved) console.log(`  saved [${f.label}] ${f.statement}  (meko id: ${f.id})`);
  console.log(`  timing: agent extract ${res.timings.extractMs.toFixed(2)} ms | Meko writes ${res.timings.saveMs.toFixed(0)} ms`);

  console.log('--- waiting for Meko to index ---');
  const w0 = performance.now();
  for (let i = 0; i < 30; i++) {
    const m = await session.store.searchScope({ agentId: B.agentId, scopeId: accountId });
    if (m.length >= res.saved.length) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.log(`  index wait: ${(performance.now() - w0).toFixed(0)} ms`);

  console.log('--- Agent B: MFA-change event ---');
  const out = await B.assess({ type: 'mfa_change', accountId, newDevice: true, newCountry: true });
  console.log(`  severity ${out.severity} -> ${out.recommendedAction} | raw ${out.rawScore} | display ${out.displayScore}/100`);
  console.log(`  timing: Meko retrieval ${out.timings.retrievalMs.toFixed(0)} ms | agent scoring ${out.timings.scoringMs.toFixed(2)} ms`);
  out.explanation.forEach((l) => console.log(`   - ${l}`));
} catch (err) {
  console.error(`FAIL ${err.name}: ${err.message}`);
  if (!(err instanceof TrustTraceError)) console.error(err.stack);
  process.exitCode = 1;
} finally {
  if (session) {
    const del = await deleteMemories(session.store, tracker.savedIds, 'trusttrace_helpdesk_agent');
    console.log(`\n--- cleanup: deleted ${del.deleted}/${tracker.savedIds.length} memories${del.failed.length ? ' FAILED: ' + JSON.stringify(del.failed) : ''}; now querying Meko to verify ---`);
    const v = await verifyCleanup({ store: session.store, savedIds: tracker.savedIds, scopeIds: tracker.scopeIds });
    console.log(`  memories confirmed absent (memory_get_by_id -> not_found): ${v.memoriesConfirmedAbsent}/${v.memoriesChecked}`);
    console.log(`  TrustTrace memories left anywhere in the datapack (memory_get_all): ${v.trusttraceMemoriesLeftInDatapack.length}`);
    console.log(`  test accounts still returning search hits: ${v.scopesWithResults.length}`);
    console.log(`  conversations reused, not re-created: ${Object.values(v.conversations).every((c) => c.reusedNotRecreated)} (conversation deletion itself is NOT verifiable on Meko - see README)`);
    console.log(`  cleanup verified: ${v.ok ? 'YES' : 'NO'}`);
    if (!v.ok) process.exitCode = 1;
    await session.client.close();
  }
}
