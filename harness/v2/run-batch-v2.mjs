// Drive a worklist of pkg@version specs through the v2 measurement pipeline and write one record
// each. The v2 counterpart of `run-batch.sh`, and deliberately the same shape: resume by default,
// per-package budget, a per-record hook, and a deadline that STOPS STARTING packages rather than
// letting the job cap kill a slice that has already measured 40 of them.
//
// ⛔ THE THREE PLATFORM DRIVERS ARE NOT INTERCHANGEABLE AND THIS FILE IS THE ONLY PLACE THAT KNOWS
// IT. `measure.sh` takes `<pkg> <ver> [nub]` and needs strace; `measure-macos.sh` takes the same but
// must run as uid 0 (dtrace) while dropping the measured processes back to the invoking user;
// `measure-windows.mjs` takes `--nub`/`--root` flags and needs no elevation. Keeping the dispatch
// here means the workflow does not carry three near-identical steps that drift apart.
//
// ⛔ IT NEVER EDITS A DRIVER. `measure.sh` is under concurrent development; the contract this file
// depends on is its ARGV and its `=>` terminal vocabulary, both of which are stable and neither of
// which this file may change.
//
//   usage: node run-batch-v2.mjs --file <worklist> --nub <bin> [--runs <dir>] [--force]

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { driverInvocation } from './driver-invocation.mjs';
import { computeHarnessIdentity, loadInstrumentConfig, loadInvalidationPolicy } from './instrument.mjs';
import { recordValidity } from './record-validity.mjs';
import { collectRuntimeProvenance, fileIdentity } from './runtime-provenance.mjs';
import { fetchPackageStanding } from './package-standing.mjs';
import { provisionMatrix } from './provision-node-matrix.mjs';
import { sweepDecision } from './scratch-sweep.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const FORCE = argv.includes('--force');
const NUB = opt('--nub', '');
const RUNS = path.resolve(opt('--runs', path.join(HERE, '..', '..', 'records-v2', 'runs')));
const PLATFORM = `${process.platform}-${process.arch}`;
const BUDGET_MS = Number(opt('--budget', process.env.NUB_CORPUS_PKG_BUDGET ?? '2400')) * 1000;
// Keep every driver scratch root instead of sweeping it after the record is written. For debugging a
// single package by hand; a slice run with this on will fill the disk — see the sweep's own note.
const KEEP_ROOTS = argv.includes('--keep-roots') || process.env.NUB_V2_KEEP_ROOTS === '1';
const DEADLINE = Number(process.env.NUB_CORPUS_DEADLINE ?? '0');
const ON_RECORD = process.env.NUB_CORPUS_ON_RECORD ?? '';

const specs = fs.readFileSync(opt('--file'), 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);

// `@scope/name@version` — the LAST `@` is the separator, and splitting on the first one silently
// produces a package that does not exist while still yielding a well-formed record.
const splitSpec = (s) => {
  const at = s.lastIndexOf('@');
  if (at <= 0) return null;
  return [s.slice(0, at), s.slice(at + 1)];
};

const sh = (cmd, args, ms) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 28, timeout: ms });

const gitSha = (dir) => {
  try { return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); }
  catch { return ''; }
};
const cleanCorpusSha = (dir) => {
  try {
    const status = execFileSync('git', ['-C', dir, 'status', '--porcelain', '--untracked-files=all', '--',
      ...loadInstrumentConfig(dir).inputs], { encoding: 'utf8' }).trim();
    return status ? '' : gitSha(dir);
  } catch { return ''; }
};
const nubVersion = () => {
  if (!NUB) return '';
  const r = sh(NUB, ['--version'], 60_000);
  return (r.stdout ?? '').trim().split('\n').pop() ?? '';
};

const CORPUS_SHA = cleanCorpusSha(path.join(HERE, '..', '..'));
const NUB_VERSION = nubVersion();
const NUB_SHA = process.env.NUB_GIT_SHA ?? '';
const INSTRUMENT = computeHarnessIdentity();
const INVALIDATION = loadInvalidationPolicy();
const RUNTIME = collectRuntimeProvenance();
const NUB_BINARY = fileIdentity(NUB);
if (INVALIDATION.currentEpoch !== INSTRUMENT.harnessEpoch) {
  console.error(`instrument policy epoch ${INVALIDATION.currentEpoch} does not match current epoch `
    + `${INSTRUMENT.harnessEpoch}; refusing to measure`);
  process.exit(2);
}
console.log(`instrument: epoch ${INSTRUMENT.harnessEpoch} ${INSTRUMENT.harnessSha256.slice(0, 16)} `
  + `(${INSTRUMENT.inputCount} inputs)`);
console.log(`runtime: ${process.version} ${RUNTIME.node.sha256?.slice(0, 16) ?? 'unhashed'}; `
  + `nub ${NUB_BINARY?.sha256?.slice(0, 16) ?? 'unidentified'}`);

// ── ERA-NODE PRE-FLIGHT ───────────────────────────────────────────────────────────────────────
//
// The drivers pin each package to the Node its author targeted, but only for versions ALREADY
// provisioned: they READ the provisioned tree and never write it, because `NUB_CACHE_DIR` is per-run
// and an install there would refetch ~20 MB per package. So an unprovisioned box measures everything
// on the ambient Node — precisely the state the pin exists to end. Measured across 45 real records,
// 93% ran on a Node the era rule would not have chosen, in BOTH directions.
//
// ⛔ REPORTED ON EVERY PATH, INCLUDING THE FULLY-PROVISIONED ONE, for the same reason the falsification
// block below says so: a reader of a slice log must be able to tell "pinned" from "the pin never
// engaged", and those look identical if the good case is quiet.
//
// ⛔ WARNS BY DEFAULT, REFUSES ONLY ON REQUEST. Refusing outright would break every existing caller on
// a box that has not provisioned, and the records stay honest either way — each carries `pinned` and the
// version it wanted. A run that MUST be pinned (the clean fresh corpus pass) sets
// `NUB_V2_REQUIRE_ERA_NODE=1` and gets a hard gate instead.
{
  const { rows, root } = provisionMatrix({ check: true });
  const missing = rows.filter((r) => !r.present);
  const label = `era-node: ${rows.length - missing.length}/${rows.length} Node versions provisioned under ${root}`;
  if (!missing.length) {
    console.log(`${label} — every package can be pinned to its era`);
  } else {
    console.log(`${label}; MISSING majors ${missing.map((r) => r.major).join(', ')} — a package whose era `
      + 'wants one of those falls back to the ambient Node and records pinned: false. Fix with '
      + '`node harness/v2/provision-node-matrix.mjs`.');
    if (process.env.NUB_V2_REQUIRE_ERA_NODE) {
      console.error('era-node: refusing to start — NUB_V2_REQUIRE_ERA_NODE is set and the matrix is incomplete');
      process.exit(2);
    }
  }
}

// Extra argv appended to whichever driver the dispatch below selects, as a JSON array.
//
// ⛔ THIS EXISTS SO THERE STAYS EXACTLY ONE COPY OF THE DISPATCH. The dispatch below is the only
// place that knows the three drivers are not interchangeable, and a caller needing a driver MODE
// this file does not model (`--at-grant`, `--at-catalog`) would otherwise have to fork it — at
// which point the two copies can select different drivers, or pass `--nub` where the driver wants
// a positional, and produce different verdicts for the same package. `e2e.mjs` is that caller, and
// it exists so a single-package debugging loop is one command rather than four. Unset is the normal
// case and changes nothing.
const DRIVER_ARGS = process.env.NUB_V2_DRIVER_ARGS ? JSON.parse(process.env.NUB_V2_DRIVER_ARGS) : [];

// ── FALSIFICATION PRE-FLIGHT ──────────────────────────────────────────────────────────────────
//
// ⛔ A SWEEP IS EXACTLY WHEN A SILENT WRONG ANSWER IS CHEAPEST TO PRODUCE AND MOST EXPENSIVE TO
// UNWIND, so the one check that can go red for the right reason runs BEFORE the first package
// rather than after the last. `falsify.mjs` installs a real package under a grant the corpus's own
// records say is insufficient and requires the driver to reject it — see FALSIFICATION.md.
//
// Refusing on INCONCLUSIVE (rc 2) as well as FAIL (rc 1) is deliberate, and the bring-up case is the
// argument: a nub binary built without `build-jail-catalog-override` makes EVERY arm VOID, which is
// not a harness defect but does mean a whole slice would have measured nothing. Both are "do not
// start". `--no-falsify` is the escape hatch for someone who already knows why.
//
// ⛔ EVERY PATH THROUGH THIS BLOCK PRINTS ITS OUTCOME, INCLUDING THE SKIPS. A gate that can be
// silently absent is not a gate: a reader of a slice log has to be able to tell "the control passed"
// from "the control never ran", and the two look identical if the skip is quiet.
// ⛔ ASK `falsify.mjs` WHETHER IT HAS A CASE; DO NOT KEEP A SECOND LIST HERE. This was
// `process.platform !== 'linux'`, and it went stale the moment win32 gained a case: the case was
// grounded on measured arms and verified in both directions, and this line skipped it anyway while
// printing "no case table for win32 yet" — a message that had become false. The one platform gated
// on the control was the one silently not running it.
//
// The probe needs no binary and no driver, so a platform with no evidence still SKIPS loudly rather
// than refusing, and a platform gains coverage the instant its case lands — with no edit here.
const hasCase = spawnSync(process.execPath, [path.join(HERE, 'falsify.mjs'), '--has-case'],
  { encoding: 'utf8' });
if (hasCase.status !== 0) {
  console.log(`falsify: SKIPPED — ${(hasCase.stdout ?? '').trim() || `no case is grounded on ${process.platform}`}`
    + ', so this slice is NOT covered by the falsification control');
} else if (argv.includes('--no-falsify')) {
  console.log('falsify: SKIPPED by --no-falsify — this slice is NOT covered by the falsification control');
} else if (!NUB) {
  // ⛔ REFUSE, DO NOT SKIP. Without `--nub` the driver falls back to its own default path, so the
  // control would be exercising a different binary from the one about to measure the slice — and a
  // control that passes for a binary you are not using is worse than none.
  console.log('⛔ falsify: no --nub given, so the control cannot pin the binary the slice will use.');
  console.log('   Name the binary, or pass --no-falsify to measure without the control.');
  process.exit(2);
} else {
  // ⛔ THE FULL RUN, NOT `--quick`. `--quick` drops the `wrong-warm` arm, which is the only check on
  // whether warm state left by a previous arm can satisfy an operation the grant forbids — and a
  // sweep is exactly where that matters. MEASURED on the corpus VM: six arms took 55s total, against
  // a slice budget of ~13 min PER PACKAGE. There is nothing to save here.
  //
  // No timeout here on purpose: `falsify.mjs` already caps each arm, and a `spawnSync` timeout
  // surfaces as `status === null`, which would otherwise be reported with the P0 exit code.
  const f = spawnSync(process.execPath, [path.join(HERE, 'falsify.mjs'), '--nub', NUB],
    { stdio: 'inherit' });
  if (f.status !== 0) {
    const rc = f.status ?? 2;
    console.log(`\n⛔ falsification control did not pass (rc=${rc}) — refusing to start the batch.`);
    console.log('   Run `node falsify.mjs --nub <bin>` directly for the per-arm detail.');
    process.exit(rc);
  }
}

let attempted = 0; let recorded = 0; let skipped = 0; let deadlineStopped = 0;
const standingByPackage = new Map();
// Sized from the SLOWEST package seen, not the mean: a native rebuild and a JS postinstall differ by
// an order of magnitude, so an average-sized reservation routinely starts a package that cannot
// finish and loses the whole slice to the job cap.
let slowestMs = 0;

for (const spec of specs) {
  const parts = splitSpec(spec);
  if (!parts) { console.log(`SKIP  ${spec} — not a name@version spec`); continue; }
  const [pkg, version] = parts;
  const dir = path.join(RUNS, PLATFORM, pkg.replace(/\//g, '+'), version);

  if (!FORCE && fs.existsSync(path.join(dir, 'results.json'))) {
    // Resume only when the existing answer names this exact instrument, runtime and Nub binary.
    // Compatibility across an epoch is possible solely through invalidation.json; an undeclared
    // mismatch is stale, never "probably close enough".
    let prior = null;
    try { prior = JSON.parse(fs.readFileSync(path.join(dir, 'results.json'), 'utf8')); } catch { /* re-measure */ }
    const validity = recordValidity(prior, INSTRUMENT, INVALIDATION, {
      platform: PLATFORM,
      nodeVersion: process.version,
      nodeSha256: RUNTIME.node.sha256,
      nubSha256: NUB_BINARY?.sha256,
      nubGitSha: NUB_SHA || null,
    });
    if (validity.reusable) {
      console.log(`SKIP  ${spec} — current record (${prior.verdict}; ${validity.via})`);
      skipped++;
      continue;
    }
    if (prior) console.log(`STALE ${spec} — ${validity.reason}; re-measuring`);
  }

  if (DEADLINE > 0) {
    const leftMs = DEADLINE * 1000 - Date.now();
    const need = Math.max(slowestMs, 300_000);
    if (leftMs < need) {
      console.log(`DEADLINE: stopping before ${spec} — ${Math.round(leftMs / 60000)} min left, `
        + `${Math.round(need / 60000)} min needed`);
      deadlineStopped = specs.length - attempted - skipped;
      break;
    }
  }

  attempted++;
  let standing;
  try {
    if (!standingByPackage.has(pkg)) standingByPackage.set(pkg, fetchPackageStanding(pkg));
    standing = await standingByPackage.get(pkg);
  } catch (error) {
    standingByPackage.delete(pkg);
    console.log(`FAIL  ${spec} — package standing unavailable: ${error.message}; no lifecycle arm ran`);
    continue;
  }
  // ⛔ THE RECORD DIR HAS TO EXIST BEFORE THE DRIVER RUNS, because the driver writes the retained
  // event log straight into it. `record.mjs` also mkdirs it later; both are `recursive: true`.
  //
  // ⛔ AND THE NAME MAY NOT END IN `.log`. The repo's `.gitignore` carries a bare `*.log`, so a file
  // named that is dropped silently at `git add` while looking perfectly present on the runner's
  // disk — the same trap `record.mjs` documents for `driver.out`. `.ndjson.gz` is tracked.
  fs.mkdirSync(dir, { recursive: true });
  // ⛔ THE PLATFORM GATE IS ABOUT WHICH DRIVER HAS A RETENTION PATH, NOT ABOUT WHICH OS DESERVES
  // ONE — and as of now ALL THREE DRIVERS HAVE ONE, so the gate below only decides whether this
  // file ALSO hands the driver an explicit destination. macOS is excluded on purpose rather than
  // for want of a retention step: `measure-macos.sh` publishes through its stdout markers, which
  // `record.mjs` copies from, and so needs no variable. `measure.sh` now does both, and its marker
  // path is the primary — which is what makes a STANDALONE driver run (every probe branch, every
  // manual re-measure) retain as much as a batched one, where previously it retained nothing.
  //
  // ⛔ WINDOWS RETAINS TWO ARTIFACTS AND THEY ARE NOT PEERS. `etw-raw.xml.gz` is the ARTIFACT OF
  // RECORD — tracerpt's XML byte-for-byte, so a decoder bug is a re-parse; `events.ndjson.gz` is a
  // queryable convenience regenerable from it. The raw is a separate variable rather than implied
  // by the derived one so the two can be turned off independently, and so a reader of this file can
  // see that the archive is not just "the Linux thing, on Windows".
  if (process.platform === 'linux') {
    process.env.NUB_V2_EVENTS_OUT = path.join(dir, 'events.ndjson.gz');
    delete process.env.NUB_V2_ETW_RAW_OUT;
  } else if (process.platform === 'win32') {
    process.env.NUB_V2_EVENTS_OUT = path.join(dir, 'events.ndjson.gz');
    process.env.NUB_V2_ETW_RAW_OUT = path.join(dir, 'etw-raw.xml.gz');
  } else {
    delete process.env.NUB_V2_EVENTS_OUT;
    delete process.env.NUB_V2_ETW_RAW_OUT;
  }
  const t0 = Date.now();
  let r;
  // ⛔ THE INVOCATION COMES FROM `driver-invocation.mjs`. This file's copy was the CORRECT one — it
  // has always known darwin needs `sudo -E` — and the two callers that grew their own copies each
  // omitted it, so `falsify.mjs` reported "the harness cannot detect a bad grant" about a driver that
  // never ran. Being right is not a reason to keep a private copy; being the only right one is how
  // the others drifted unnoticed.
  //
  // What stays here is the ARGV SHAPE, which genuinely differs: win32 names the binary with `--nub`,
  // the POSIX drivers take it positionally.
  const { cmd, pre, file } = driverInvocation();
  const nubArgs = NUB ? (process.platform === 'win32' ? ['--nub', NUB] : [NUB]) : [];
  r = sh(cmd, [...pre, file, pkg, version, ...nubArgs, ...DRIVER_ARGS], BUDGET_MS);
  const ms = Date.now() - t0;
  slowestMs = Math.max(slowestMs, ms);

  const log = (r.stdout ?? '') + (r.stderr ?? '');
  // A deadline kill leaves `status === null`; `record.mjs` reads rc 124 as the timeout convention
  // that `portable-timeout.sh` and GNU `timeout` both use, so the two lanes agree on the spelling.
  const rc = r.error?.code === 'ETIMEDOUT' || (r.status === null && r.signal) ? 124 : (r.status ?? 1);
  fs.mkdirSync(dir, { recursive: true });
  const tmpLog = path.join(dir, '.driver.out');
  fs.writeFileSync(tmpLog, log);

  const w = sh(process.execPath, [path.join(HERE, 'record.mjs'),
    '--log', tmpLog, '--pkg', pkg, '--version', version, '--out', RUNS,
    '--rc', String(rc), '--platform', PLATFORM, '--duration-ms', String(ms),
    '--nub-sha', NUB_SHA, '--nub-version', NUB_VERSION, '--corpus-sha', CORPUS_SHA,
    '--expected-harness-epoch', String(INSTRUMENT.harnessEpoch),
    '--expected-harness-sha', INSTRUMENT.harnessSha256,
    ...(NUB_BINARY?.sha256 ? ['--expected-nub-sha256', NUB_BINARY.sha256] : []),
    '--runtime-json', JSON.stringify(RUNTIME),
    '--standing-json', JSON.stringify(standing),
    '--driver', process.platform === 'win32' ? 'measure-windows.mjs'
      : process.platform === 'darwin' ? 'measure-macos.sh' : 'measure.sh'], 120_000);
  // ⛔⛔ THE DRIVER LOG IS THE ONLY PLACE A NON-MEASUREMENT VERDICT'S *REASON* EXISTS, AND DELETING
  // IT UNCONDITIONALLY THREW THAT AWAY. A record carries `verdict: "HARNESS-ERROR"` or `"VOID"` and
  // nothing about WHY; the driver's stdout — which said `=> HARNESS-ERROR: Nub could not materialize
  // the tree with --ignore-scripts` or `=> VOID -- the override did not engage` — was written here and
  // `rmSync`'d two lines later.
  //
  // MEASURED COST: five `HARNESS-ERROR` records were investigated as a per-package budget problem and
  // re-run at a 90-minute budget before anyone read a driver log. They were nub REFUSALS (exit 23
  // trust-policy, exit 21 age-gate) that failed in 5-41 s, so the budget could not have mattered. One
  // retained log would have answered it immediately. Separately `unicode@0.6.1` VOIDs on win32 and the
  // reason is still unknown, because both attempts deleted their own evidence.
  //
  // Kept for the verdicts whose reason is NOT recoverable from the record, and for a `record.mjs`
  // failure — where the log is all that survives. A MINIMUM keeps nothing: its grant, minimality and
  // provenance are all in the record, and retaining ~7k logs would dwarf the records themselves.
  //
  // ⛔ `BROKEN-WITHOUT-JAIL-TOO` ADDED 2026-08-16 AFTER CHECKING WHAT ITS RECORD ACTUALLY HOLDS. It
  // was excluded here on the grounds that "the record already explains it" — asserted, not checked,
  // and false. A BWJT record carries `notes: []`, `eventLog: null`, `grantSourceReason: null`,
  // `driverRc: 0`: every field that could name a cause is empty, because the verdict is decided
  // before any grant descent runs and so nothing populates them.
  //
  // WHY IT MATTERS MOST OF THE SET: BWJT is the LARGEST failure bucket in the corpus — 457 of 2,569
  // linux records (17.8%) and 138 of 448 win32 (30.8%) — and it means nub cannot install the package
  // with the jail OFF, i.e. a nub PM/linker bug rather than a jail finding. It is therefore the
  // bucket that decides the "virtually all packages still install" claim. `purge-stale-verdicts.mjs`
  // deliberately purges BWJT so that a nub fix triggers a re-measure, but with no recorded cause
  // nobody can tell WHICH nub bug to fix; the evidence was deleted one line after being produced.
  //
  // COST IS AN ORDER OF MAGNITUDE BELOW THE FIGURE THAT JUSTIFIED EXCLUDING MINIMUM: ~600 BWJT logs
  // against ~6,100 MINIMUM. MINIMUM stays out for exactly that reason.
  const KEEP_LOG_VERDICTS = new Set(['VOID', 'NO-STATE-PASSED', 'BROKEN-WITHOUT-JAIL-TOO']);
  const keepLog = (verdict) => !verdict
    || String(verdict).startsWith('HARNESS-') || KEEP_LOG_VERDICTS.has(String(verdict));

  if (w.status !== 0) {
    // record.mjs itself failed, so there is no verdict to consult and no record to read: the log is
    // the entire evidence. Reported by path so the next reader does not have to guess it exists.
    console.log(`FAIL  ${spec} — record.mjs rc=${w.status} (driver log kept: ${tmpLog})\n${w.stderr}`);
    continue;
  }

  const rec = JSON.parse(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'));
  recorded++;
  if (keepLog(rec.verdict)) {
    console.log(`      driver log kept for ${rec.verdict}: ${tmpLog}`);
  } else {
    fs.rmSync(tmpLog, { force: true });
  }

  // ⛔⛔ SWEEP THE DRIVER'S SCRATCH ROOT, OR A LONG SLICE FILLS THE DISK AND DIES MID-RUN.
  //
  // MEASURED, and it killed both lanes of a 25% linux run: `measure.sh` creates
  // `ROOT="$(mktemp -d "$HOME/v2-XXXXXX")"` per invocation and never removes it — no `trap`, no
  // cleanup — and nothing here removed it either. A descent runs ~9 arms per package, each with its
  // own root holding a full npm cache and node_modules, so 75 packages left **658 roots and 193 GB**,
  // and lane 1 died `ENOSPC: no space left on device` inside this very file's `writeFileSync`.
  //
  // ⛔ IT IS SWEPT HERE, NOT IN THE DRIVER, AND THAT PLACEMENT IS THE WHOLE CORRECTNESS OF IT.
  // A `trap ... rm -rf "$ROOT"` in `measure.sh` would be the obvious fix and would silently break
  // `falsify.mjs`, which parses the root out of the driver's header and reads
  // `verify-at-grant/{i,a}.log` from it AFTER the driver has exited — with no logs, `refusalSeen` and
  // `scriptRan` are false and it reports refusal failures about arms that were fine. Only this file
  // knows the root's true end of life: `record.mjs` has returned and the record has been read.
  //
  // ⛔ AND ONLY ONCE THE ARTIFACT OF RECORD IS SAFELY OUT. `record.mjs` COPIES `trace.txt.gz` and
  // `capture.json` into the record dir (its `copyFileSync`), and notes `rawlog-copy-failed` /
  // `capture-copy-failed` / `eventlog-copy-failed` when it cannot. The raw trace is the ARCHIVE — a
  // decoder bug is a re-parse with it and a permanent hole without it — so a root whose copy failed
  // is KEPT, deliberately trading disk for evidence. Deleting it would be strictly worse than a full
  // disk: a full disk stops the run loudly, a lost archive is invisible.
  // Every condition lives in `scratch-sweep.mjs` so it is testable; this file only acts on the verdict.
  const sweep = sweepDecision({ log, notes: rec.notes ?? [], runs: RUNS, keepRoots: KEEP_ROOTS });
  if (sweep.sweep) {
    // A failure here must never cost a measured record: the record is already on disk, and the worst
    // case is the disk pressure this sweep exists to relieve.
    try { fs.rmSync(sweep.root, { recursive: true, force: true }); } catch { /* nothing to do but continue */ }
  } else if (sweep.root && !KEEP_ROOTS) {
    console.log(`      root KEPT (${sweep.root}) — ${sweep.reason}`);
  }
  console.log(`REC   ${spec} [${Math.round(ms / 1000)}s] ${rec.verdict}`
    + `${rec.grant ? ` ${JSON.stringify(rec.grant)}` : ''}`
    + `${rec.verifiedBy ? ` via=${rec.verifiedBy}` : ''}`);

  if (ON_RECORD) {
    // Best effort by design: a record that does not publish stays on disk for the end-of-slice
    // commit and the artifact. Killing a measuring run over a rejected push trades the thing being
    // protected for the protection.
    spawnSync(ON_RECORD, [dir], { stdio: 'inherit' });
  }
}

console.log(`\nv2 batch: ${attempted} attempted, ${recorded} recorded, ${skipped} skipped (already measured)`);
if (deadlineStopped > 0) {
  console.log(`DEADLINE: stopped before ${deadlineStopped} package(s) — the job cap would have killed the run`);
}
