// Gate the corpus against the failure class that cost this project a day: output that LOOKS fine
// and carries nothing.
//
// ⛔ WHAT THIS EXISTS TO CATCH. Six defects shipped while the measurement layer was correct
// throughout. Each produced records that parsed, collated, and reported success — and a catalog with
// ZERO capabilities. No test caught any of them because every test asserted the hand-maintained
// compiled-in table; nothing asserted that the PIPELINE's own output carried what it measured.
//
// So the assertions here are deliberately about SUBSTANCE, not validity:
//   - records must carry a machine-readable `grant`, not just a human label
//   - a collated catalog must carry real capabilities
//   - a package measured as needing egress must still say so after collation
//   - junk names must never reach the catalog
//
// Run it after every slice. A green run that produces nothing is the thing to be afraid of.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const RECORDS = opt('--records', path.join(here, '..', 'records'));

const failures = [];
const notes = [];

// ── records ───────────────────────────────────────────────────────────────────
const files = [];
(function walk(d) {
  let e; try { e = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const x of e) {
    const f = path.join(d, x.name);
    if (x.isDirectory()) walk(f);
    else if (x.name === 'results.json') files.push(f);
  }
})(RECORDS);

// ⛔ "NO RECORDS" IS ONLY OK IF NOTHING WAS CLAIMED. This exited 0 unconditionally, which is right
// for a fresh repo and WRONG after a slice claimed work — and that is exactly how the first live
// macOS slice went green having measured nothing: `timeout` is absent on macOS, the fixture canary
// refused, `|| true` swallowed it, and this gate waved through 100 claimed rows and 0 records.
//
// So the question is not "are there records" but "does the corpus have records for the work that was
// claimed". `--expect <n>` is how the runner states what it just claimed.
const EXPECT = Number(opt('--expect', '0'));
if (files.length === 0) {
  if (EXPECT > 0) {
    console.error('CORPUS VERIFY FAILED:');
    console.error(`  - ${EXPECT} row(s) were claimed but the corpus has NO records at all. The slice`);
    console.error('    produced nothing. Check the measure step: a refusal there is swallowed by');
    console.error('    `|| true`, so the job goes green while measuring nothing.');
    process.exit(1);
  }
  console.log('no records yet — nothing to verify');
  process.exit(0);
}

let measured = 0;
let missingGrant = 0;
const junkNames = [];
const JUNK = /^(\.|node_modules$)/;

for (const f of files) {
  let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
  if (JUNK.test(r.pkg ?? '')) junkNames.push(r.pkg);
  if (r.verdict !== 'MINIMUM') continue;
  measured++;
  // A MINIMUM whose state is not "(nothing)" MUST carry a structured grant. This is exactly the
  // `grantFor` returning `undefined` bug — records looked complete and were unusable.
  if (r.state && r.state !== '(nothing)' && !r.grant) missingGrant++;
}

if (missingGrant > 0) {
  failures.push(
    `${missingGrant} of ${measured} MINIMUM records carry a non-empty state but NO \`grant\` object. ` +
    `The collator keys on \`grant\`, so these collate into an empty catalog. This is the ` +
    `\`grantFor\` regression — check that it returns \`g?.default\`, not \`g[0]\`.`
  );
}
if (junkNames.length) {
  failures.push(
    `${junkNames.length} record(s) name something that is not a package (${[...new Set(junkNames)].slice(0, 3).join(', ')}). ` +
    `\`.store\` bookkeeping directories are leaking into the measured set.`
  );
}

// ── collation ─────────────────────────────────────────────────────────────────
// Collate to a temp file and assert the OUTPUT carries substance. Doing this here rather than
// trusting the collator's own summary is the point: its summary counted packages, which stayed
// correct while every capability silently vanished.
const tmp = path.join(process.env.RUNNER_TEMP || '/tmp', `corpus-verify-${process.pid}.json`);
const { spawnSync } = await import('node:child_process');
const col = spawnSync(process.execPath, [path.join(here, 'collate.mjs'), '--runs', RECORDS, '--out', tmp], {
  encoding: 'utf8',
});
if (col.status !== 0) {
  failures.push(`collate.mjs exited ${col.status}: ${(col.stderr || '').slice(-300)}`);
} else {
  let cat; try { cat = JSON.parse(fs.readFileSync(tmp, 'utf8')); } catch (e) {
    failures.push(`the collated catalog is not valid JSON: ${e.message}`);
  }
  if (cat) {
    const pkgs = Object.entries(cat.packages ?? {});
    const hasCaps = (b) => b && typeof b === 'object' && (b.write || b.read || b.network);
    const withCaps = pkgs.filter(([, e]) => Object.values(e).some(hasCaps));
    const withNet = pkgs.filter(([, e]) => Object.values(e).some((b) => b && b.network === true));

    notes.push(`catalog: ${pkgs.length} packages, ${withCaps.length} with capabilities, ${withNet.length} with egress`);

    // ⛔ THE LOAD-BEARING ASSERTION. A catalog of N packages and ZERO capabilities is the exact
    // artifact this project shipped for its whole first corpus. It parses, it validates, it is
    // useless — and nothing else notices.
    if (pkgs.length > 0 && withCaps.length === 0) {
      failures.push(
        `the collated catalog has ${pkgs.length} packages and ZERO capabilities. Every measurement ` +
        `has been discarded somewhere between the record and the catalog.`
      );
    }
    // Cross-check against the records: a package measured as needing egress must still say so.
    const netInRecords = new Set();
    for (const f of files) {
      let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
      if (r.verdict === 'MINIMUM' && /network/.test(String(r.state ?? ''))) netInRecords.add(r.pkg);
    }
    const lostEgress = [...netInRecords].filter((n) => !withNet.some(([name]) => name === n));
    if (lostEgress.length) {
      failures.push(
        `${lostEgress.length} package(s) measured as needing egress but carry no network grant after ` +
        `collation (${lostEgress.slice(0, 3).join(', ')}). Egress is being dropped in collation.`
      );
    }
  }
  try { fs.unlinkSync(tmp); } catch { /* best effort */ }
}

// ── report ────────────────────────────────────────────────────────────────────
console.log(`records: ${files.length} (${measured} MINIMUM)`);
for (const n of notes) console.log(n);
if (failures.length === 0) {
  console.log('CORPUS VERIFY: ok');
  process.exit(0);
}
console.error('\nCORPUS VERIFY FAILED:');
for (const f of failures) console.error(`  - ${f}`);
process.exit(1);
