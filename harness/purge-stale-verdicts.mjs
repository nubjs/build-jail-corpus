// Drop failure verdicts that a NEWER nub may have already fixed, so they get re-measured.
//
// ⛔ THE HOLE THIS CLOSES. `search.mjs` is resumable by design: it skips any package that already has
// a record. That is right for a MINIMUM — a measured floor does not change because nub changed — and
// WRONG for a failure verdict, because a failure is frequently a nub bug, and fixing that bug is
// exactly what makes the old verdict a lie. Nothing else notices: `--stale-harness` keys on a hash of
// the HARNESS, so a nub-side fix invalidates nothing at all.
//
// MEASURED: 99 Linux records were committed carrying 19 BROKEN-WITHOUT-JAIL-TOO verdicts, all
// measured with a nub that predated `1c545975db` — a fix for bundled dependency bins being linked
// only into the CONSUMER's `.bin` and not the bundling package's own, which breaks any package whose
// install script invokes a bundled node-pre-gyp. Those 19 would have sat in the corpus permanently,
// re-reported as defects, never re-run.
//
// SCOPE IS DELIBERATELY NARROW — failure verdicts only:
//   BROKEN-WITHOUT-JAIL-TOO      a nub PM/linker bug by definition; a nub fix is exactly what changes it
//   BROKEN-EVEN-WITH-EVERYTHING  the jail IS implicated; a jail fix is exactly what changes it
//   BROKEN-IN-ENVIRONMENT        reference PMs failed too, but the comparison is nub-version-dependent
//   NO-STATE-PASSED              nothing worked; a fix is what makes something work
//
// A MINIMUM is NEVER purged. Re-measuring the whole corpus on every nub commit would make the corpus
// unfinishable, and the ascending walk's answer does not move because an unrelated linking bug was
// fixed. HARNESS-* verdicts are also left alone: those are instrument failures, and `--stale-harness`
// already owns them.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const KNOWN = new Set(['--records', '--nub', '--dry-run']);
const unknown = argv.filter((a, i) => a.startsWith('--') && !KNOWN.has(a)
  && !(i > 0 && KNOWN.has(argv[i - 1])));
if (unknown.length) {
  console.error(`PURGE REFUSED: unknown flag(s): ${unknown.join(', ')}`);
  console.error(`  known flags: ${[...KNOWN].join(', ')}`);
  process.exit(2);
}

const RECORDS = opt('--records', path.join(here, '..', 'records'));
const NUB = opt('--nub');
const DRY = argv.includes('--dry-run');
if (!NUB) {
  console.error('PURGE REFUSED: --nub <path to the nub binary> is required.');
  console.error('  The binary IS the comparison — a record is stale relative to a specific nub, and');
  console.error('  taking that on trust from a flag is how a corpus ends up silently unpurged.');
  process.exit(2);
}

const sha = crypto.createHash('sha256').update(fs.readFileSync(NUB)).digest('hex');
console.error(`current nub: ${path.basename(NUB)}  sha256 ${sha.slice(0, 16)}`);

const STALEABLE = new Set([
  'BROKEN-WITHOUT-JAIL-TOO',
  'BROKEN-EVEN-WITH-EVERYTHING',
  'BROKEN-IN-ENVIRONMENT',
  'NO-STATE-PASSED',
]);

const files = [];
(function walk(d) {
  let e; try { e = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const x of e) {
    const f = path.join(d, x.name);
    if (x.isDirectory()) walk(f);
    else if (x.name === 'results.json') files.push(f);
  }
})(RECORDS);

let purged = 0; let current = 0; let kept = 0; let noProvenance = 0;
const byVerdict = new Map();

for (const f of files) {
  let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
  if (!STALEABLE.has(r.verdict)) { kept++; continue; }

  const recorded = r.provenance?.nubSha256;
  if (!recorded) {
    // A failure verdict that cannot name the nub that produced it cannot be shown to be current, and
    // a failure verdict is the kind worth re-running. Purge it rather than trusting it.
    noProvenance++;
  } else if (recorded === sha) {
    current++;
    continue;
  }

  byVerdict.set(r.verdict, (byVerdict.get(r.verdict) ?? 0) + 1);
  if (!DRY) fs.rmSync(path.dirname(f), { recursive: true, force: true });
  purged++;
}

console.error(`\nrecords scanned: ${files.length}`);
console.error(`  kept (not a failure verdict): ${kept}`);
console.error(`  kept (failure, but measured by THIS nub): ${current}`);
for (const [v, n] of [...byVerdict].sort((a, b) => b[1] - a[1])) console.error(`  ${DRY ? 'would purge' : 'purged'} ${String(n).padStart(4)}  ${v}`);
if (noProvenance) console.error(`  (${noProvenance} of those carried no provenance.nubSha256 and could not be shown current)`);
console.error(DRY
  ? `\n--dry-run: would purge ${purged}; the queue rows are untouched either way`
  : `\npurged ${purged} record(s) — those packages will be re-measured on the next slice that claims them`);
