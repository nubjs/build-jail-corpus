#!/usr/bin/env node
// THE METRIC: fraction of MINIMUM records at `write:"disk"`, per platform, by record and at-latest.
//
// ⛔ WHY THIS IS A SCRIPT AND NOT A ONE-LINER. It was hand-written each cycle, and hand-writing it
// produced a silently doubled disk rate: a crash on a record with no `grant` was "fixed" by adding
// `|| !r.grant` to the filter, which excludes every record whose grant is NULL. `grant: null` is not
// a malformed record — it is a package that needs NO GRANT AT ALL, the BEST possible outcome, and it
// is HALF the corpus. Dropping those took win32 from 22.3% to 42.7% and would have read as a
// catastrophic regression on the exact cycle the fixes started landing.
//
// So the two rules are enforced here rather than remembered:
//   1. A MINIMUM record with `grant: null` COUNTS, in the denominator, as not-disk.
//   2. The `grant: null` share is PRINTED as a control. If it ever reads 0%, the reader is broken —
//      it cannot be 0% in a healthy corpus.
//
// ⛔ PLATFORM COMES FROM THE RECORD PATH, NOT `provenance.platform`. A run that fails partway never
// finishes writing provenance: 70 of 109 HARNESS-* records have no platform field, so any per-platform
// split taken from provenance undercounts failures by ~2/3. The path is present on every record.
//
// Usage:  node harness/metric.mjs [--records records]

import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const i = argv.indexOf('--records');
const recordsDir = i >= 0 && argv[i + 1] ? argv[i + 1] : 'records';

const records = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name === 'results.json') {
      try {
        const r = JSON.parse(fs.readFileSync(p, 'utf8'));
        r._plat = (p.match(/records\/runs\/([^/]+)\//) || [, '?'])[1];
        records.push(r);
      } catch {
        /* a half-written record during a live publish is expected */
      }
    }
  }
})(recordsDir);

// `null` is the BEST outcome, not a missing value. Only an explicit write:"disk" counts.
const isDisk = (r) => !!(r.grant && r.grant.write === 'disk');

// Semver-ish compare, tolerating prerelease tails like `0.0.0-next-16573`.
const cmp = (a, b) => {
  const pa = String(a).split(/[.-]/).map(Number);
  const pb = String(b).split(/[.-]/).map(Number);
  for (let k = 0; k < 3; k++) if ((pa[k] || 0) !== (pb[k] || 0)) return (pa[k] || 0) - (pb[k] || 0);
  return 0;
};

const minimum = records.filter((r) => r.verdict === 'MINIMUM');
const byPlat = {};
for (const r of minimum) (byPlat[r._plat] = byPlat[r._plat] || []).push(r);

const nullGrants = minimum.filter((r) => !r.grant).length;
const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : '   - ');
console.log(
  `CONTROL  grant:null = ${nullGrants}/${minimum.length} (${pct(nullGrants, minimum.length)}) — the BEST outcome, and it MUST be counted in the denominator`,
);
if (nullGrants === 0) console.log('⛔ grant:null is 0% — impossible in a healthy corpus; the reader is broken');
console.log();

for (const p of Object.keys(byPlat).sort()) {
  const rs = byPlat[p];
  const d = rs.filter(isDisk).length;
  // at-latest: each package's HIGHEST measured version, because what SHIPS is the entry's `default`,
  // which the generator takes from the highest measured version. The record metric over-weights
  // ancient versions; report both, they cut in opposite directions.
  const top = {};
  for (const r of rs) if (!top[r.pkg] || cmp(r.version, top[r.pkg].version) > 0) top[r.pkg] = r;
  const tv = Object.values(top);
  const td = tv.filter(isDisk).length;
  console.log(
    `  ${p.padEnd(13)} record ${String(d).padStart(3)}/${String(rs.length).padStart(4)} = ${pct(d, rs.length).padStart(6)}   at-latest ${String(td).padStart(3)}/${String(tv.length).padStart(3)} = ${pct(td, tv.length).padStart(6)}`,
  );
  // ⛔⛔ THE RATE ABOVE IS CONFOUNDED BY THE BINARY, and that confound is LARGE enough to invert the
  // reading. A corpus accumulates over days while nub is being fixed underneath it, so the two figures
  // answer "what did we COLLECT" -- a mix of binaries -- not "what will SHIP", which only records on a
  // fixed binary can answer.
  //
  // MEASURED, which is what forced this line into existence: of the 18 win32 at-latest disk packages,
  // 13 had never been measured on a binary carrying any of today's fixes, and every single POSIX disk
  // record (13 linux, 16 darwin) was likewise pre-fix. Two of them -- lefthook@1.13.6 and
  // mathlive@0.66.1 -- were re-measured and BOTH narrowed from write:"disk" to write.project. Reading
  // the mixed rate as the current rate had already produced one wrong conclusion ("a distinct linux
  // cause"), because a stale record is indistinguishable from a real residual without the sha.
  //
  // FIXES is the same hand-maintained ancestry list as fix-coverage.mjs, and a sha absent from it is
  // treated as PRE-FIX -- so a NEW fix that is not listed here makes this line PESSIMISTIC, never
  // optimistic. That is the safe direction for a security metric: it can under-claim, not over-claim.
  //
  // ⛔⛔ DO NOT READ THIS AS THE SHIPPING RATE -- ITS SAMPLE IS SELECTION-BIASED, UPWARD. Records land
  // on a fixed binary by two routes: natural queue drain (unbiased) and TARGETED RE-MEASURES, which
  // deliberately pick packages that were already at write:"disk". Where the second route dominates,
  // this line reads HIGHER than the truth. Measured on the day it was written: win32 at-latest was
  // 8.1% mixed but 14.7% "on fixes" -- not a regression, just 34 packages of which many were chosen
  // BECAUSE they were disk. Nothing in a record distinguishes the two routes, so the bias cannot be
  // divided out here; it has to be remembered when reading.
  //
  // WHERE IT IS TRUSTWORTHY: a platform whose ON-FIXES sample came from ordinary drain. darwin read
  // 0/84 the same day -- 84 naturally-drained records, ZERO at disk -- which is real evidence that
  // the darwin tail was stale rather than residual. A large unbiased zero means something; a small
  // targeted non-zero does not.
  const FIXED = new Set(['8f7d5adb67', '0d9c2c575b', '00daf3b67a', '9c73c07337', 'ec15074bc2', 'b9a5201217', 'db9e4367c2']);
  const onFix = (r) => FIXED.has(String(r.provenance?.nubGitSha || '').slice(0, 10));
  const fr = rs.filter(onFix);
  const ft = tv.filter(onFix);
  console.log(
    `  ${' '.repeat(13)} ON FIXES ONLY  record ${String(fr.filter(isDisk).length).padStart(3)}/${String(fr.length).padStart(4)} = ${pct(fr.filter(isDisk).length, fr.length).padStart(6)}   at-latest ${String(ft.filter(isDisk).length).padStart(3)}/${String(ft.length).padStart(3)} = ${pct(ft.filter(isDisk).length, ft.length).padStart(6)}   ${fr.length === 0 ? '⛔ ZERO records on a fixed binary — this platform has measured NOTHING since the fixes landed' : ''}`,
  );
}
