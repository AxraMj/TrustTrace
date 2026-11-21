// Produces the PUBLISHABLE evidence files in reports/evidence/ from the raw, git-ignored reports in reports/.
//
//   node scripts/sanitize-evidence.mjs        (or: npm run reports:sanitize)
//
// What is removed: Meko memory ids (every UUID becomes a stable pseudonym "mem-NN", so cross-references between records still line up)
// and the random per-run tag appended to scenario account ids (acct-H7-H1f2a5b8a -> acct-H7). Measurements, scenario results and
// explanations are untouched. The script then REFUSES to write anything that still contains an id-shaped string, a token, a database
// URL, a local path, an email address or key material.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

const SRC = 'reports/';
const OUT = 'reports/evidence/';
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const RUN_TAG = /-H[0-9a-f]{8}\b/g;
const FORBIDDEN = [
  ['uuid', /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i], ['run tag', /-H[0-9a-f]{8}\b/], ['meko token', /mko_tkn_/],
  ['database url', /postgres(ql)?:\/\//i], ['windows path', /[A-Za-z]:[\\/]+(Users|Windows|Program)/i], ['unix home path', /\/(Users|home)\/[A-Za-z0-9._-]+/],
  ['email address', /[\w.+-]+@[\w-]+\.[a-z]{2,}/i], ['key material', /BEGIN [A-Z ]*(PRIVATE )?KEY/], ['bearer token', /Bearer\s+\S{12,}/],
];

const ids = new Map();
const pseudonym = (id) => { const k = id.toLowerCase(); if (!ids.has(k)) ids.set(k, `mem-${String(ids.size + 1).padStart(2, '0')}`); return ids.get(k); };
const clean = (v) => {
  if (typeof v === 'string') return v.replace(UUID, pseudonym).replace(RUN_TAG, '');
  if (Array.isArray(v)) return v.map(clean);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, clean(x)]));
  return v;
};

// raw file -> published file (the extraction reports contain no identifiers; they still pass through the same checks)
const FILES = {
  'scenario-results.json': 'scenario-results.json',
  'extraction-comparison.json': 'extraction-comparison.json',
  'extraction-validation2-FIRST-SHOT.json': 'extraction-validation2-FIRST-SHOT.json',
};

mkdirSync(OUT, { recursive: true });
let failed = false;
for (const [from, to] of Object.entries(FILES)) {
  if (!existsSync(SRC + from)) { console.error(`missing ${SRC + from} (run the scenario/eval command that produces it first)`); failed = true; continue; }
  const text = JSON.stringify(clean(JSON.parse(readFileSync(SRC + from, 'utf8'))), null, 2) + '\n';
  const bad = FORBIDDEN.filter(([, re]) => re.test(text)).map(([name]) => name);
  if (bad.length) { console.error(`REFUSING to write ${OUT + to}: still contains ${bad.join(', ')}`); failed = true; continue; }
  writeFileSync(OUT + to, text);
  console.log(`wrote ${OUT + to}  (${(text.length / 1024).toFixed(1)} KB)`);
}
console.log(`memory ids pseudonymised: ${ids.size}`);
process.exit(failed ? 1 : 0);
