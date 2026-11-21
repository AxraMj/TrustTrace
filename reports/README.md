# Evidence reports

Raw reports and test logs written to this folder are **git-ignored** (logs contain local file paths and the raw scenario report contains
Meko memory ids). The publishable copies live in [`evidence/`](evidence/) and are produced by `npm run reports:sanitize`
([`scripts/sanitize-evidence.mjs`](../scripts/sanitize-evidence.mjs)).

**What the sanitizer changes:** every Meko memory id becomes a stable pseudonym (`mem-01`, `mem-02`, …, consistent across the file so
cross-references still line up) and the random per-run tag on scenario account ids is removed. Measurements, results and explanations
are untouched. The script refuses to write a file that still contains an id-shaped string, token, database URL, local path, email
address or key material. The files contain no credentials, personal data or caller transcripts, only synthetic scenario ids.

| File in `evidence/` | What it shows | Regenerate (raw) → publish |
|---|---|---|
| `scenario-results.json` | 23 scenarios (core and hardening) run through the real agents against **live Meko**: expected vs actual action and severity, which memories influenced the score, rejected evidence, policy, counterfactuals, per-step timings, Meko call latencies. Last run: 23/23 pass, no false positives, no false negatives, all 83 test memories deleted and confirmed absent. | `npm run scenarios` (needs `MEKO_API_KEY`, ~3 min) → `npm run reports:sanitize` |
| `extraction-comparison.json` | Agent A language extraction, old regex rules vs the concept matcher, on three frozen labelled sets (A and B were used to develop the rules; **C was written afterwards and scored once**). | `npm run eval:compare` (offline) → `npm run reports:sanitize` |
| `extraction-validation2-FIRST-SHOT.json` | The honest estimate: set C, scored once after all fixes. Exact match 23/35 (66%), precision 0.90, recall 0.61. Misses are listed, not hidden. | `npm run eval:extraction -- --set validation2` (offline; the set is hash-checked) → `npm run reports:sanitize` |

All data is synthetic and written by the same author as the rules. It is **not** a measurement of real-world detection accuracy.
