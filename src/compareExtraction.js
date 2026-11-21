// Compare the Phase-3 regex baseline with the Phase-4 concept matcher on every labelled set: npm run eval:compare
import { writeFileSync, mkdirSync } from 'node:fs';
import { HELDOUT } from '../test/fixtures/heldout.js';
import { VALIDATION } from '../test/fixtures/validation.js';
import { VALIDATION2 } from '../test/fixtures/validation2.js';
import { legacyKinds } from '../test/helpers/legacyExtractor.js';
import { extractFacts } from './agents/extraction.js';
import { evaluateExtraction } from './evaluateExtraction.js';

const sets = [
  ['A (written first; later used for fixes: DEV)', HELDOUT],
  ['B (first shot 43/60; later used for fixes: DEV)', VALIDATION],
  ['C (written after all fixes; scored once: CLEAN)', VALIDATION2],
];
const rows = [];
for (const [name, cases] of sets) {
  for (const [who, fn] of [['phase-3 regex', legacyKinds], ['phase-4 matcher', (t) => extractFacts(t).map((f) => f.kind)]]) {
    const r = evaluateExtraction(fn, cases);
    rows.push({ set: name, extractor: who, cases: r.cases, exact: `${r.exactMatch}/${r.cases}`, exactRate: r.exactMatchRate, precision: r.precision, recall: r.recall, fp: r.fp, fn: r.fn });
  }
}
console.table(rows);
mkdirSync('reports', { recursive: true });
writeFileSync('reports/extraction-comparison.json', JSON.stringify(rows, null, 2));
