// Recover a slice's records from a CI run log when the runner died without committing them.
//
// ⛔ WHY THIS IS POSSIBLE AT ALL. run-batch.sh echoes each finished record to stdout as one line of
// JSON, so a GitHub Actions log contains the COMPLETE record — not a summary of it. Measured on a
// real lost Linux slice: 100 record lines, one 2,357 chars long, parsing to all 23 fields including
// `cells`, `grant`, `provenance` and `writePaths`. Nothing is abbreviated.
//
// That makes the log a genuine second copy, and it is the only copy when a slice measures
// successfully and then loses the commit — which is exactly what happened when the harness wrote
// records to a path the commit step did not stage and the ephemeral runner was torn down. Two hours
// of runner time and 100 real measurements sat recoverable in a log nobody was reading.
//
// The workflow now uploads records as an artifact (`if: always()`), so this should be the SECOND
// line of defence rather than the first. It is kept because it recovers slices measured before that
// existed, and because an artifact expires while a log persists longer.
//
//   gh run view <id> -R nubjs/build-jail-corpus --log > /tmp/run.log
//   node harness/salvage-from-log.mjs --log /tmp/run.log --records records
//
// The destination path is taken from each record's own `provenance.platform`, which already carries
// the `<platform>-<arch>` spelling the layout uses. Deriving it from the record rather than from a
// flag means a log containing several platforms cannot be filed under one wrong directory.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const KNOWN = new Set(['--log', '--records', '--dry-run']);
const unknown = argv.filter((a, i) => a.startsWith('--') && !KNOWN.has(a)
  && !(i > 0 && KNOWN.has(argv[i - 1])));
if (unknown.length) {
  console.error(`SALVAGE REFUSED: unknown flag(s): ${unknown.join(', ')}`);
  console.error(`  known flags: ${[...KNOWN].join(', ')}`);
  process.exit(2);
}

const LOG = opt('--log');
const RECORDS = opt('--records', path.join(here, '..', 'records'));
const DRY = argv.includes('--dry-run');
if (!LOG) { console.error('SALVAGE REFUSED: --log <file> is required'); process.exit(2); }

const text = fs.readFileSync(LOG, 'utf8');

// A log line carries a timestamp prefix, so anchor on the record's opening key rather than on the
// start of the line. Records are single-line by construction.
const candidates = text.split('\n')
  .map((l) => { const i = l.indexOf('{"pkg":"'); return i < 0 ? null : l.slice(i); })
  .filter(Boolean);

let written = 0; let skipped = 0; let unparsed = 0;
const byVerdict = new Map();
const seen = new Set();

for (const c of candidates) {
  let r;
  try { r = JSON.parse(c); } catch { unparsed++; continue; }
  if (!r.pkg || !r.version || !r.verdict) { unparsed++; continue; }

  const platform = r.provenance?.platform;
  if (!platform) {
    // Refuse rather than guess: a record filed under the wrong platform is worse than a missing one,
    // because collation would then attribute its capability to an OS that never measured it.
    console.error(`  SKIP ${r.pkg}@${r.version}: no provenance.platform, cannot place it`);
    skipped++;
    continue;
  }

  const key = `${platform}/${r.pkg}@${r.version}`;
  if (seen.has(key)) { skipped++; continue; }
  seen.add(key);

  byVerdict.set(r.verdict, (byVerdict.get(r.verdict) ?? 0) + 1);

  const dir = path.join(RECORDS, 'runs', platform, r.pkg.replace('/', '+'), r.version);
  const dest = path.join(dir, 'results.json');
  // Never overwrite a record that already exists — a committed record came from a run that finished
  // properly, and it carries its per-cell logs alongside, which a salvaged one does not.
  if (fs.existsSync(dest)) { skipped++; continue; }
  if (!DRY) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(dest, `${JSON.stringify(r, null, 2)}\n`);
  }
  written++;
}

console.error(`\nrecord lines found: ${candidates.length}  (unparsable: ${unparsed})`);
for (const [v, n] of [...byVerdict].sort((a, b) => b[1] - a[1])) console.error(`  ${String(n).padStart(4)}  ${v}`);
console.error(DRY
  ? `\n--dry-run: would write ${written}, skip ${skipped}`
  : `\nwrote ${written} record(s); skipped ${skipped} (already present or unplaceable)`);

// ⛔ THE PER-CELL LOGS ARE NOT IN THE RUN LOG. A salvaged record carries its verdict, grant and
// cells, but not the control.log / s13-write-project.log files a normal run writes beside it. Say so
// rather than letting a later reader assume a salvaged directory is a complete one.
if (written > 0) {
  console.error('\nNOTE: salvaged records carry no per-cell log files — only the record itself.');
  console.error('  When a verdict here is surprising, re-measure rather than trying to read logs');
  console.error('  that were never recovered.');
}
