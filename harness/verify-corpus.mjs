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
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

// ⛔ AN UNKNOWN FLAG IS A HARD ERROR, BECAUSE THIS GATE FAILS OPEN WITHOUT IT. `opt` reads only the
// flags it is asked for and ignores the rest, so a misspelled `--record` silently leaves RECORDS at
// its DEFAULT — and the gate then verifies a directory the caller never meant, and passes.
//
// MEASURED on this very script: `verify-corpus.mjs --catalog <file>` (a flag that does not exist)
// printed "no records yet — nothing to verify" and exited 0. That is the failure this file was
// written to catch, occurring inside the file itself.
//
// Silently-ignored input is the whole failure class here: a switch that stopped being read
// (`dependenciesMeta.sandbox`), a grant that stopped being serialised, a canary whose refusal was
// swallowed. A gate that tolerates unrecognised input cannot be trusted to report on anything.
const KNOWN = new Set(['--records', '--expect', '--expect-specs', '--since']);
const unknown = argv.filter((a, i) => a.startsWith('--') && !KNOWN.has(a)
  // a VALUE that merely looks like a flag belongs to the preceding known flag, not to this check
  && !(i > 0 && KNOWN.has(argv[i - 1])));
if (unknown.length) {
  console.error(`CORPUS VERIFY REFUSED: unknown flag(s): ${unknown.join(', ')}`);
  console.error(`  known flags: ${[...KNOWN].join(', ')}`);
  console.error('  Refusing rather than ignoring them: an ignored flag leaves --records at its');
  console.error('  default, so the gate would check the wrong directory and report success.');
  process.exit(2);
}

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

// ⛔⛔ `--expect <n>` ONLY FIRES WHEN THE CORPUS IS COMPLETELY EMPTY, so it cannot see the failure it
// most needs to: a run asked for 15 specs, wrote 3, and went green because the other 6,000 records
// were already there. That gap is the whole point of a TARGETED re-measure, whose purpose is to
// REPLACE named records — the queue skips anything already holding one, so a spec that silently
// produced nothing keeps its stale value forever and no one is told.
//
// `--expect-specs <file>` names exactly what was claimed (one `name@version` per line, the same
// slice file the runner already writes) and `--since <iso>` says when the run began. A spec passes
// only if it holds a record STAMPED AFTER THAT INSTANT.
//
// ⛔ THE `--since` GATE IS THE LOAD-BEARING HALF, not presence. Presence alone is satisfied by the
// PRE-EXISTING record the re-measure was supposed to overwrite, which reads as success while
// measuring nothing. MEASURED 2026-08-05: comparing 49 busybox-arm specs against a captured baseline
// BEFORE the runs had published reported "49 of 49 identical, zero escalations" — indistinguishable
// from a genuine refutation of a divergence that grants installs LESS than they need. A comparison
// that cannot tell a fresh record from an old one is not a comparison.
const EXPECT_SPECS = opt('--expect-specs', '');
const SINCE = opt('--since', '');
if (EXPECT_SPECS) {
  let want = [];
  try {
    want = fs.readFileSync(EXPECT_SPECS, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  } catch (e) {
    console.error(`CORPUS VERIFY REFUSED: --expect-specs ${EXPECT_SPECS} is unreadable: ${e.message}`);
    console.error('  Refusing rather than skipping: an unreadable list would silently verify nothing.');
    process.exit(2);
  }
  if (!want.length) {
    console.error(`CORPUS VERIFY REFUSED: --expect-specs ${EXPECT_SPECS} is empty`);
    process.exit(2);
  }
  const seen = new Map();
  for (const f of files) {
    let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
    if (r && r.pkg) seen.set(`${r.pkg}@${r.version}`, String((r.provenance || {}).at || ''));
  }
  const missing = want.filter((s) => !seen.has(s));
  const stale = SINCE ? want.filter((s) => seen.has(s) && !(seen.get(s) > SINCE)) : [];
  if (missing.length) {
    failures.push(
      `${missing.length} of ${want.length} claimed spec(s) produced NO record at all: ${missing.slice(0, 8).join(', ')}${missing.length > 8 ? ' …' : ''}`,
    );
  }
  if (stale.length) {
    failures.push(
      `${stale.length} of ${want.length} claimed spec(s) still carry a record OLDER than the run (${SINCE}) — the re-measure did not replace them, so any before/after read on these is comparing a record to ITSELF: ${stale.slice(0, 8).join(', ')}${stale.length > 8 ? ' …' : ''}`,
    );
  }
  if (!missing.length && !stale.length) {
    notes.push(`all ${want.length} claimed spec(s) hold a record${SINCE ? ` newer than ${SINCE}` : ''}`);
  }
}
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

// The state vocabulary, read from the single definition rather than re-spelled here — a second
// spelling would let this gate and the collator disagree about what is recoverable.
const { STATES } = await import('./states.mjs');
const STATE_LABELS = new Set(STATES.map((s) => s.label));

let measured = 0;
let missingGrant = 0;
let recoverableGrant = 0;
const junkNames = [];
// ⛔ A COMMA OR WHITESPACE IS STRUCTURALLY IMPOSSIBLE IN AN NPM PACKAGE NAME, and catching it here
// is what would have caught the `packages` comma bug on the day it shipped. The old pattern matched
// only `.`-prefixed and `node_modules` — leaking `.store` bookkeeping dirs — so a record naming
// "@a/b@1.0.0,@c/d@2.0.0" passed every check and read as a real measurement. See the corpus commit
// that split that input on commas; this is the OTHER half, because a parser fix protects the input
// it knows about while this refuses the impossible name however it got there.
const JUNK = /^(\.|node_modules$)|[,\s]/;

for (const f of files) {
  let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
  if (JUNK.test(r.pkg ?? '')) junkNames.push(r.pkg);
  if (r.verdict !== 'MINIMUM') continue;
  measured++;
  // A MINIMUM whose state is not "(nothing)" MUST carry a grant that is either SERIALISED or
  // RECOVERABLE. Recoverable means the state label names a real state, which is what lets
  // `collate.mjs` backfill it exactly — `STATES` is an exhaustive product and each label is built
  // deterministically from its cost atoms, so a label identifies exactly one state.
  //
  // ⛔ THIS USED TO FAIL ON ANY MISSING `grant`, WHICH FALSE-ALARMS ON THE WHOLE LEGACY CORPUS.
  // 2,443 records were written while `grantFor` returned `undefined`; every one of them carries a
  // state label, so collation recovers all of them (measured: 261 of 261 on the macOS corpus, 0
  // genuinely lost, and the resulting catalog carries 132 packages with capabilities). Failing on
  // those would block the gate on data that is completely fine.
  //
  // What is a REAL defect is a record whose grant is neither present NOR reconstructable — that one
  // is genuinely unusable, and it is what this now reports.
  if (r.state && r.state !== '(nothing)' && !r.grant) {
    if (STATE_LABELS.has(r.state)) recoverableGrant++;
    else missingGrant++;
  }
}

if (missingGrant > 0) {
  failures.push(
    `${missingGrant} of ${measured} MINIMUM records carry a non-empty state, NO \`grant\` object, and ` +
    `a state label that matches no known state — so the grant can be neither read nor reconstructed. ` +
    `These records are unusable. This is the \`grantFor\` regression (check it returns \`g?.default\`, ` +
    `not \`g[0]\`) combined with a state vocabulary that has drifted from \`states.mjs\`.`
  );
}
if (recoverableGrant > 0) {
  notes.push(
    `${recoverableGrant} record(s) predate the grant fix and carry no \`grant\` field, but their state ` +
    `labels all resolve, so collation reconstructs them exactly — not a defect`
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
// ⛔ `os.tmpdir()`, never `RUNNER_TEMP || '/tmp'`: the fallback is a POSIX path that does not exist on
// Windows, so this line worked on a GitHub runner (which sets RUNNER_TEMP) and threw ENOENT on any
// other Windows box. `os.tmpdir()` already honours TMPDIR/TEMP/TMP, so it covers the runner too.
const tmp = path.join(os.tmpdir(), `corpus-verify-${process.pid}.json`);
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

    // ⛔ AN ENTRY IS `{default, versions}` AND `versions` IS A MAP OF BANDS, NOT A GRANT. This walked
    // `Object.values(entry)`, so it inspected `default` (a grant — correct) and `versions` (a map,
    // whose `.network`/`.write` are undefined). A package whose capability lives ONLY in a version
    // band was therefore counted as having NONE.
    //
    // MEASURED on the legacy macOS corpus: @sentry/cli, bcrypt and better-sqlite3 each carry egress
    // solely in a band (`<3.6.0`, `<6.0.0`, `<13.0.1`) because latest no longer needs it — exactly
    // the shape the band rule PRODUCES, since a band is written only when an older version needs
    // MORE than latest. The gate reported all nine such packages as "measured as needing egress but
    // carry no network grant after collation", which is false; the full catalog grants every one.
    //
    // Both symptoms were false ALARMS rather than false passes, which is the safe direction — but a
    // gate that cries wolf gets ignored, and that is how the real signal eventually gets missed.
    const grantsOf = (e) => [e?.default, ...Object.values(e?.versions ?? {})].filter(Boolean);
    const withCaps = pkgs.filter(([, e]) => grantsOf(e).some(hasCaps));
    const withNet = pkgs.filter(([, e]) => grantsOf(e).some((b) => b.network === true));

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

// ── every DONE row must still have its record ─────────────────────────────────
//
// ⛔ THE CHECK THAT WOULD HAVE CAUGHT RECORDS BEING DELETED. `git add <dir>` is `git add -A <dir>`,
// so a publish that keeps its own records/ dir rather than resetting to origin stages a DELETION for
// every record another runner pushed since its checkout. One publish commit was measured removing 14
// other runners' records while adding one of its own; 146 record paths were gone from the tree by the
// time anyone looked, 107 of them MINIMUM measurements.
//
// Nothing was permanently lost — git keeps every blob, and harness/restore-deleted-records.mjs brings
// them back — but the corpus is what the TREE says, so a deleted record is a measurement the catalog
// no longer has. The queue is the tell: a row marked `done` asserts a measurement exists. If the
// record is gone, the queue is claiming coverage the corpus cannot show.
//
// This is deliberately a check on the QUEUE against the RECORDS rather than a count of either. Both
// numbers looked healthy the whole time this was happening.
//
// ⛔ RUN IT WHERE THE RECORDS ARE COMPLETE. In the workflow this runs on the runner's own `records/`
// after its batch, so it sees every record that batch produced and the answer is authoritative.
// Pointed at a freshly-cloned origin WHILE SLICES ARE IN FLIGHT it will report orphans that are
// merely early: `--reconcile` marks a row done the moment its record exists on the measuring runner's
// disk, and that record reaches origin on the next publish or at the end-of-slice commit. A handful
// of orphans against a live origin is that window; the same rows persisting across several slices is
// the real defect.
{
  const queuePath = path.join(here, '..', 'queue.ndjson');
  if (fs.existsSync(queuePath)) {
    const osOf = (p) => (p.startsWith('darwin') ? 'macos'
      : p.startsWith('linux') ? 'linux' : p.startsWith('win') ? 'windows' : null);
    const have = new Set();
    for (const f of files) {
      let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
      const os = osOf(r.provenance?.platform ?? '');
      if (os && r.pkg && r.version) have.add(`${r.pkg}@${r.version}\t${os}`);
    }
    const rows = fs.readFileSync(queuePath, 'utf8').split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    // A row closed on an instrument failure carries no provenance-bearing record by design, so it
    // cannot be expected here.
    const orphans = rows.filter((r) => r.status === 'done'
      && !String(r.verdict ?? '').startsWith('HARNESS-')
      && !have.has(`${r.pkg}@${r.version}\t${r.os}`));
    if (orphans.length) {
      // ⛔ A NOTE, NOT A FAILURE — and making it a failure STOPPED THE WHOLE CORPUS FOR 3.5 HOURS.
      //
      // A runner's `records/` is its checkout plus its OWN new records. Under a parallel fleet it
      // structurally CANNOT see the records other runners are still holding, so every runner sees
      // hundreds of rows that look done-without-a-record and none of them is real. Measured: 529
      // false orphans on a macOS runner, which failed this step, which meant `Dispatch the next
      // slice` never ran, which killed every chain on every platform at once.
      //
      // The check is still worth making — it is what caught the record-deletion bug — but its
      // authoritative home is a reader with the WHOLE corpus (a local clone), not a runner holding
      // one slice of it. A gate may only fail a run on something that run can actually observe.
      notes.push(
        `note: ${orphans.length} queue row(s) look done-without-a-record from HERE `
        + `(e.g. ${orphans.slice(0, 3).map((r) => `${r.pkg}@${r.version} [${r.os}]`).join(', ')}). `
        + 'Expected under a parallel fleet — this runner cannot see other runners\' in-flight records. '
        + 'Check it against a full clone; if it persists there, run harness/restore-deleted-records.mjs.'
      );
    } else {
      notes.push(`every done row has its record (${rows.filter((r) => r.status === 'done').length} checked)`);
    }
  }
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
