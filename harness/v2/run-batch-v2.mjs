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

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const FORCE = argv.includes('--force');
const NUB = opt('--nub', '');
const RUNS = path.resolve(opt('--runs', path.join(HERE, '..', '..', 'records-v2', 'runs')));
const PLATFORM = `${process.platform}-${process.arch}`;
const BUDGET_MS = Number(opt('--budget', process.env.NUB_CORPUS_PKG_BUDGET ?? '2400')) * 1000;
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
const nubVersion = () => {
  if (!NUB) return '';
  const r = sh(NUB, ['--version'], 60_000);
  return (r.stdout ?? '').trim().split('\n').pop() ?? '';
};

const CORPUS_SHA = gitSha(path.join(HERE, '..', '..'));
const NUB_VERSION = nubVersion();
const NUB_SHA = process.env.NUB_GIT_SHA ?? '';

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
if (process.platform !== 'linux') {
  console.log(`falsify: SKIPPED — no case table for ${process.platform} yet (linux-only for now)`);
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
    // ⛔ RESUME SKIPS A MEASUREMENT, NEVER AN INSTRUMENT FAILURE. A `HARNESS-*` record is the
    // harness saying it could not measure — exactly the package a later fix needs to reach — so
    // treating it as answered is how a defect becomes permanent.
    let prior = null;
    try { prior = JSON.parse(fs.readFileSync(path.join(dir, 'results.json'), 'utf8')); } catch { /* re-measure */ }
    if (prior && !String(prior.verdict ?? '').startsWith('HARNESS-')) {
      console.log(`SKIP  ${spec} — already recorded (${prior.verdict})`);
      skipped++;
      continue;
    }
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
  if (process.platform === 'win32') {
    r = sh(process.execPath, [path.join(HERE, 'measure-windows.mjs'), pkg, version,
      ...(NUB ? ['--nub', NUB] : [])], BUDGET_MS);
  } else if (process.platform === 'darwin') {
    // ⛔ `sudo -E`, AND THE `-E` IS LOAD-BEARING. dtrace needs uid 0, and the driver reads
    // `SUDO_USER` to drop every measured process back to the invoking user — but it also needs the
    // ambient PATH to find npm, which a bare `sudo` strips.
    r = sh('sudo', ['-E', 'bash', path.join(HERE, 'measure-macos.sh'), pkg, version,
      ...(NUB ? [NUB] : [])], BUDGET_MS);
  } else {
    r = sh('bash', [path.join(HERE, 'measure.sh'), pkg, version, ...(NUB ? [NUB] : [])], BUDGET_MS);
  }
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
    '--driver', process.platform === 'win32' ? 'measure-windows.mjs'
      : process.platform === 'darwin' ? 'measure-macos.sh' : 'measure.sh'], 120_000);
  fs.rmSync(tmpLog, { force: true });
  if (w.status !== 0) { console.log(`FAIL  ${spec} — record.mjs rc=${w.status}\n${w.stderr}`); continue; }

  const rec = JSON.parse(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'));
  recorded++;
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
