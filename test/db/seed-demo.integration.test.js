// PostgreSQL integration: the reduced demo seeding against REAL tables (decisions, activity, replay ledger, hash-chained audit) in a throw-away schema.
// Meko is a datapack-aware fake here: nothing in this file contacts Meko or any remote database.
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { DB_SKIP, createTestDb } from './helpers.js';
import { seedDemo, PLAN_IDS } from '../../scripts/seed-demo.mjs';
import { FakeDatapackMeko } from '../helpers/fakeDatapackMeko.js';
import { loadAuthority } from '../../src/trustSetup.js';
import { verifyChain } from '../../src/db/auditChain.js';
import { AUDIT_RESOLVERS } from '../../src/db/auditResolvers.js';

const quiet = { print() {} };
const fast = { pollMs: 5, indexTimeoutMs: 1500, cleanupPauseMs: 1, sleep: async () => {} };
const count = async (pool, table) => (await pool.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n;

describe('seed-demo on real PostgreSQL', { skip: DB_SKIP }, () => {
  let db; let first; let fake;
  before(async () => { db = await createTestDb(); });
  after(async () => { await db?.cleanup(); });

  test('the first execution records five decisions, activity, attestations and an intact audit chain', async () => {
    fake = new FakeDatapackMeko();
    first = await seedDemo({ client: fake, pool: db.pool, authority: loadAuthority().authority, execute: true, io: quiet, ...fast });
    assert.equal(first.ok, true, JSON.stringify({ refused: first.refused, err: first.runError?.message }));
    assert.equal(first.results.length, PLAN_IDS.length);
    assert.ok(first.results.every((r) => r.pass));
    assert.equal(await count(db.pool, 'decisions'), PLAN_IDS.length);
    assert.ok((await count(db.pool, 'agent_events')) >= first.counts.memory_add, 'every memory write was recorded as agent activity');
    const chain = await verifyChain(db.pool, { resolvers: AUDIT_RESOLVERS });
    assert.equal(chain.ok, true);
    assert.ok(chain.checked > PLAN_IDS.length);
  });

  test('the decisions carry the expected outcomes (allow, step-up, and blocks) and Meko is left empty', async () => {
    const rows = (await db.pool.query('SELECT recommended_action AS a FROM decisions')).rows.map((r) => r.a).sort();
    assert.deepEqual(rows, ['allow', 'block', 'block', 'block', 'step_up']);
    assert.equal(fake.memories.length, 0);
  });

  test('a second execution is refused before anything is written to Meko or PostgreSQL', async () => {
    const fake2 = new FakeDatapackMeko();
    await assert.rejects(
      seedDemo({ client: fake2, pool: db.pool, authority: loadAuthority().authority, execute: true, io: quiet, ...fast }),
      /already holds 5 decisions/,
    );
    assert.equal(fake2.tally().memory_add ?? 0, 0);
    assert.equal(await count(db.pool, 'decisions'), PLAN_IDS.length);
  });

  test('a dry run against the migrated database writes nothing', async () => {
    const fake3 = new FakeDatapackMeko();
    const before = await count(db.pool, 'decisions');
    const r = await seedDemo({ client: fake3, pool: db.pool, authority: loadAuthority().authority, execute: false, io: quiet, allowExistingDecisions: true, ...fast });
    assert.equal(r.dryRun, true);
    assert.equal(fake3.tally().memory_add ?? 0, 0);
    assert.equal(await count(db.pool, 'decisions'), before);
  });
});
