// Build the work QUEUE: one row per (package, version, os) in the full matrix.
//
// THE QUEUE IS THE SPEC. A corpus run is not "the worklist, on whatever platforms happened to be
// dispatched" — it is exactly the rows in this file, and anything absent from it will never be
// measured. That makes coverage checkable by reading one artifact instead of reconciling shard
// dispatches against CI history, which is how the previous approach lost track of what had actually
// been covered (measured: 175 packages duplicated across two Linux boxes while 349 were unmeasured).
//
// FORMAT: NDJSON, one row per line, so a slice can be claimed and rewritten without re-serialising
// the whole file and without a merge conflict on every concurrent run. A single JSON array would
// make every commit touch every byte.
//
//   {"pkg":"sharp","version":"0.34.5","os":"linux","status":"pending"}
//
// STATUS is the claim mechanism:
//   pending  — nobody has taken it
//   claimed  — a run has taken it; carries `run` (the CI run id) and `at`
//   done     — measured; the record is committed alongside
//   failed   — the runner itself failed (NOT a package that measured as broken, which is `done`
//              with a BROKEN-* verdict — that is a real measurement)
//
// ⛔ A CLAIM IS ONLY REAL ONCE COMMITTED. The workflow claims a slice, runs it, then commits the
// results AND the queue update in ONE commit, so a run that dies mid-slice leaves its rows `claimed`
// with a run id — recoverable by `--reclaim-stale`, and never silently lost or double-counted.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const WORKLIST = opt('--worklist', path.join(here, '..', 'inputs', 'worklist-macos-final.txt'));
const OUT = opt('--out', path.join(here, '..', 'queue.ndjson'));
// ⛔ THE OS SET IS PART OF THE MATRIX, NOT A RUNTIME CHOICE. A package's grant can genuinely differ
// per OS — that is why the catalog has per-OS overlays — so a row is (pkg, version, os) and a
// package measured on only two platforms is INCOMPLETE, not done.
const OS_SET = (opt('--os', 'macos,linux,windows')).split(',').map((s) => s.trim()).filter(Boolean);

const specs = fs.readFileSync(WORKLIST, 'utf8')
  .split('\n')
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#'));

// `name@version`, where the name may itself be scoped (`@scope/name@1.2.3`) — so split on the LAST
// `@`, and reject anything without one rather than guessing a version.
const rows = [];
const malformed = [];
for (const spec of specs) {
  const at = spec.lastIndexOf('@');
  if (at <= 0) { malformed.push(spec); continue; }
  const pkg = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (!version) { malformed.push(spec); continue; }
  for (const os of OS_SET) rows.push({ pkg, version, os, status: 'pending' });
}

if (malformed.length) {
  console.error(`REFUSING TO WRITE: ${malformed.length} worklist entries have no \`@version\`:`);
  for (const m of malformed.slice(0, 5)) console.error(`  ${m}`);
  console.error('A queue built from a partly-unparsed worklist silently under-covers the corpus.');
  process.exit(2);
}

// ⛔ SHUFFLE, DETERMINISTICALLY. A worklist sorted by name or downloads makes every early slice
// structurally similar — all the scoped packages, or all the heavy native builds, land together, so
// an early failure looks like a platform verdict rather than one unlucky neighbourhood. Seeded so a
// rebuild produces the same queue, which is what makes the file reviewable in a diff.
let seed = 0x9e3779b9;
const rand = () => (((seed = (seed * 1664525 + 1013904223) >>> 0)) / 0x100000000);
for (let i = rows.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [rows[i], rows[j]] = [rows[j], rows[i]];
}

fs.writeFileSync(OUT, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);

const byOs = {};
for (const r of rows) byOs[r.os] = (byOs[r.os] || 0) + 1;
console.log(`wrote ${rows.length} rows to ${path.relative(process.cwd(), OUT)}`);
console.log(`  ${specs.length} package-versions x ${OS_SET.length} os = ${rows.length}`);
for (const [os, n] of Object.entries(byOs)) console.log(`    ${os.padEnd(8)} ${n}`);
