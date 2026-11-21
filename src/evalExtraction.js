// Score Agent A's extraction on a labelled set: npm run eval:extraction [-- --set heldout|validation]
// Verifies each set file still matches the hash recorded when it was frozen.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { HELDOUT } from '../test/fixtures/heldout.js';
import { VALIDATION } from '../test/fixtures/validation.js';
import { VALIDATION2 } from '../test/fixtures/validation2.js';
import { extractFacts } from './agents/extraction.js';
import { evaluateExtraction } from './evaluateExtraction.js';

const SETS = {
  heldout: { file: 'test/fixtures/heldout.js', hash: 'test/fixtures/heldout.sha256', cases: HELDOUT, note: 'batch A: written before the rules, but later seen while fixing -> now a DEVELOPMENT set' },
  validation: { file: 'test/fixtures/validation.js', hash: 'test/fixtures/validation.sha256', cases: VALIDATION, note: 'batch B: first shot was 43/60; later used to drive general fixes -> now a DEVELOPMENT set' },
  validation2: { file: 'test/fixtures/validation2.js', hash: 'test/fixtures/validation2.sha256', cases: VALIDATION2, note: 'batch C: written after ALL fixes, scored once (first shot)' },
};
const arg = process.argv.includes('--set') ? process.argv[process.argv.indexOf('--set') + 1] : 'heldout';
const set = SETS[arg];
if (!set) { console.error(`unknown set ${arg}`); process.exit(2); }

const actual = createHash('sha256').update(readFileSync(set.file)).digest('hex');
const frozen = existsSync(set.hash) ? readFileSync(set.hash, 'utf8').trim() : null;
if (!frozen) { writeFileSync(set.hash, actual + '\n'); console.log(`froze ${set.file} sha256 ${actual}`); }
const res = evaluateExtraction((t) => extractFacts(t).map((f) => f.kind), set.cases);
console.log(`[${arg}] ${set.note}`);
console.log(`file hash ${frozen === null || actual === frozen ? 'OK' : 'DOES NOT MATCH the frozen hash'} (${actual.slice(0, 12)}...)`);
console.log(`cases ${res.cases} | exact match ${res.exactMatch}/${res.cases} (${res.exactMatchRate}) | precision ${res.precision} | recall ${res.recall} | tp ${res.tp} fp ${res.fp} fn ${res.fn}`);
console.log('by group:', JSON.stringify(res.perGroup));
console.log('per kind:');
for (const [k, v] of Object.entries(res.perKind)) console.log(`  ${k.padEnd(28)} R=${v.recall} P=${v.precision} (tp ${v.tp} fp ${v.fp} fn ${v.fn})`);
console.log(`misses (${res.misses.length}):`);
for (const m of res.misses) console.log(`  ${m.id} [${m.group}] missing=[${m.missing}] extra=[${m.extra}]  "${m.text.slice(0, 95)}"`);
mkdirSync('reports', { recursive: true });
writeFileSync(`reports/extraction-${arg}-latest.json`, JSON.stringify({ set: arg, sha256: actual, ...res }, null, 2));
process.exitCode = frozen === null || actual === frozen ? 0 : 1;
