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
}
