// THE FALSIFICATION CONTROL. Every other check in this harness is a check that PASSES; this is the
// only one whose job is to prove the harness can still return the WRONG-ANSWER verdict at all.
//
//   usage: node falsify.mjs --nub <bin> [--driver <measure.sh>] [--case <name>] [--quick] [--json <f>]
//   exit 0 = the harness detected every deliberately-narrowed grant AND accepted every correct one
//   exit 1 = ⛔ the harness reported a KNOWN-INSUFFICIENT grant as sufficient, or failed a control
//   exit 2 = INCONCLUSIVE — the venue could not run the case (registry down, VOID arm, no binary)
//
// ── WHY THIS EXISTS ───────────────────────────────────────────────────────────────────────────
//
// Over-granting is safe; UNDER-granting breaks a stranger's install. So the only harness failure
// that matters is one where a too-narrow grant comes back sufficient — and by construction that
// failure is SILENT: it does not crash, it does not warn, it raises the agreement rate. Every
// precondition assertion already in `measure.sh` (override engaged, jail stated, unique name, store
// evicted, `running build scripts` present) guards a route to that failure, and each was added
// after it had already produced a wrong record. What none of them do is DEMONSTRATE, on a real
// package, that the assembled pipeline still says NO when the answer is no.
//
// Three separate "checks" in this project turned out to be structurally unable to fail:
//   * an arm passed that should have failed, because a warm cache satisfied a download the jailed
//     run was supposed to be denied — the record then called a needed capability unnecessary;
//   * a package's artifact gate could never go red, because the package ships its build output
//     prebuilt, so the gate's reference set was just the tarball contents;
//   * a guard asserting an uppercase letter matched a lowercase name, because bash 3.2 under
//     `en_US.UTF-8` range-collates `*[A-Z]*`.
//
// All three share one shape: a predicate that was never watched going red for the right reason.
// This file is the standing answer, and it is worth running before a large sweep precisely because
// a large sweep is when a silent wrong answer is cheapest to produce and most expensive to unwind.
//
// ── THE CONSTRUCTION ──────────────────────────────────────────────────────────────────────────
//
// Per case, three REAL end-to-end driver runs — not a unit test of a predicate, because the three
// failures above all hid in the seams between jail, install, artifact gate and exit code, and a
// predicate test steps over exactly those seams. Each run is one `measure.sh … --at-grant '<json>'`
// invocation, and the arms differ in NOTHING BUT THE GRANT JSON. `--at-grant` is the right
// primitive here for the same reason its own header gives: it runs ONE arm at a stated grant with
// no synthesis and no ladder, so nothing OBSERVE missed and nothing the ladder recovered can enter
// the verdict.
//
//   1. wrong-cold   the minimum MINUS one capability, run first, on a cold store  -> must be INSUFFICIENT
//   2. right        the known-sufficient minimum                                  -> must be SUFFICIENT
//   3. wrong-warm   the SAME narrowed grant again, now that (2) has populated
//                   every cache in the venue                                      -> must be INSUFFICIENT
//
// ⛔ (2) IS NOT OPTIONAL AND IS NOT CEREMONY. Without a passing control, (1) failing proves nothing:
// a broken venue, an unreachable registry, or a nub binary built without the override feature fails
// every arm, and "the wrong grant failed" then reads as a working oracle when the harness is dead.
//
// ⛔ (3) IS THE WARM-STATE TRAP, TESTED RATHER THAN AVOIDED. `measure.sh` evicts a great deal per
// arm — the store entries for the package and its whole observed closure, the side-effects memo,
// `jail-home/<pkg>-*`, the `ms-playwright` and `electron-cache` redirect leaves — and every one of
// those evictions was added after a warm artifact had already masked a denial. Ordering (1) first
// gives it the coldest venue available; running the identical grant AGAIN after (2) has downloaded
// the binary, materialised the store and filled the private home asks whether any surviving warm
// state can satisfy the operation the grant is supposed to forbid. A `wrong-warm` that passes while
// `wrong-cold` failed is not a flake — it is the harness's independence-between-arms guarantee
// failing, which is the same defect that produced a false `OVER-PREDICTED` on `playwright-chromium`.
//
// ── WHY A NEGATIVE VERDICT IS NOT ENOUGH, AND WHAT IS ─────────────────────────────────────────
//
// A wrong arm that comes back INSUFFICIENT has told you the driver said no. It has NOT told you the
// driver said no for the right reason — and a no for the wrong reason is how the corpus acquires a
// spuriously wide grant. So each case names the OS-level refusal its removed capability must
// produce, and the arm's own logs must carry it:
//
//   write.deps -> `EACCES` on the exact directory the script tries to create
//   network    -> `EAI_AGAIN` / `ENETUNREACH` / `ECONNREFUSED` on the exact URL it tries to fetch
//
// That is the positive control the prompt for this file asks for: proof the fatal operation was
// ATTEMPTED and DENIED, rather than skipped because something upstream had already satisfied it. A
// case whose arm fails with no refusal in its logs is reported as a FAILURE of this control, not as
// a detection — because that arm may well have failed for an unrelated reason.
//
// ── AND WHICH DETECTOR FIRED, BECAUSE THEY ARE NOT INTERCHANGEABLE ────────────────────────────
//
// MEASURED, and it is the reason one case would not have been enough:
//
//   @apollo/rover@0.4.8 at {"network":true}   rc=1  artifacts=6/6  missing=0   -> caught by rc ONLY
//   hugo-extended@0.141.0 at {}               rc=1  artifacts=9/12 missing=3   -> caught by rc AND the gate
//
// rover's postinstall writes into a SIBLING package (`node_modules/binary-install/bin`), and
// `artifact-gate.mjs` is scoped to the measured package's own directory by deliberate design — so
// the gate passes that arm 6/6 and the ONLY thing standing between a narrowed grant and a
// `SUFFICIENT` verdict is the install exit code. If a future change makes the driver tolerant of a
// non-zero rc, hugo would still be caught by the gate and the regression would go unnoticed. Each
// case therefore declares the detectors that MUST fire, and the observed set is always printed so a
// change in the detection story is visible even when it does not fail the run.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { driverInvocation } from './driver-invocation.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const NUB = opt('--nub', '');
// A path rather than a hardcoded sibling so this file can be pointed at a DELIBERATELY BROKEN copy
// of the driver. That is how the oracle itself is shown capable of going red — `falsify-selftest.sh`
// generates that copy, runs this file against it, and asserts it goes red for BOTH of its two
// mechanisms. See FALSIFICATION.md, "proving the oracle can fail". Not a knob for ordinary runs.
//
// ⛔ THE DEFAULT IS PER-PLATFORM, and defaulting to `measure.sh` everywhere made this file silently
// linux-only. The three drivers are not interchangeable — `run-batch-v2.mjs` already carries the
// same dispatch and says why — and on Windows there is no `bash` at ALL: MEASURED on the corpus VM,
// `where bash` finds nothing and Git-for-Windows is absent. So the one platform whose records are
// gated on this control was the one platform where it could not run.
// ⛔ AND THE DEFAULT NOW COMES FROM `driver-invocation.mjs` RATHER THAN A COPY OF THE MAP. `--driver`
// still overrides the FILE, which is what it always meant; `cmd`/`pre` come from the module either
// way, because a caller pointing at an alternate darwin script still needs `sudo -E` to run it.
const { cmd: DRIVER_CMD, pre: DRIVER_PRE, file: DEFAULT_DRIVER } = driverInvocation();
const DRIVER = path.resolve(opt('--driver', DEFAULT_DRIVER));
const ONLY = opt('--case', '');
const JSON_OUT = opt('--json', '');
// Drops the `wrong-warm` arm. Halves the cost and gives up the one check that no amount of eviction
// discipline can replace, so it is for an inner loop and never for a pre-sweep gate.
const QUICK = argv.includes('--quick');
// Every arm's `$ROOT` is deleted once its case passes; see the sweep at the foot of the case loop.
const KEEP_ROOTS = argv.includes('--keep-roots');
const BUDGET_MS = Number(opt('--budget', '900')) * 1000;

// ⛔ EVERY GRANT AND EVERY MINIMALITY CLAIM BELOW IS READ OFF A COMMITTED RECORD, NEVER ASSUMED.
// `records-v2/runs/linux-x64/<slug>/<ver>/results.json` carries `verdict: MINIMUM` with
// `minimality: MINIMAL`, and MINIMAL is the descent having tested the removal of each capability
// individually and found it necessary. So `insufficient` here is not a guess about what a package
// needs — it is the corpus's own answer with one term deleted.
//
// ⛔ AND EVERY CASE DECLARES THE PLATFORM ITS EVIDENCE CAME FROM. A case is grounded in one
// platform's measured arms — the refusal errno, the path shape and which detector fires all differ
// across them — so running a linux-grounded case on another platform would be asserting a
// correspondence nobody measured. The selector below filters on this and refuses to run at all
// rather than falling back to another platform's table.
const CASES = [
  {
    name: 'write.deps',
    platform: 'linux',
    pkg: '@apollo/rover',
    version: '0.4.8',
    // records-v2/runs/linux-x64/@apollo+rover/0.4.8/results.json — MINIMUM, MINIMAL
    sufficient: { write: { deps: true }, network: true },
    insufficient: { network: true },
    removed: 'write.deps',
    // The postinstall delegates to the `binary-install` package and writes into THAT package's
    // directory, which resolves through a symlink out of rover's own store entry.
    // `preset.rs::store_entry_write_root` grants the measured package's entry root only, so without
    // `write.deps` the sibling's `bin/` cannot be created.
    //
    // ⛔ A CONJUNCTION, AND EVERY TERM IS AN ANCHOR. A bare errno is not evidence of a jail refusal —
    // it is evidence that SOMETHING failed, and plenty of things fail in an install log for reasons
    // that have nothing to do with the grant under test. Each case must name both the failure KIND
    // and the SUBJECT it must have failed on, so a transient unrelated error cannot satisfy it.
    refusal: [/EACCES/, /binary-install/],
    // Output only rover's own postinstall can produce, in EITHER shape: the download line when the
    // write is permitted, the `binary-install` require-stack when it is not.
    ranEvidence: /Downloading release from|binary-install[/\\]index\.js/,
    mustDetect: ['rc'],
  },
  {
    name: 'network',
    platform: 'linux',
    pkg: 'hugo-extended',
    version: '0.141.0',
    // records-v2/runs/linux-x64/hugo-extended/0.141.0/results.json — MINIMUM, MINIMAL
    sufficient: { network: true },
    insufficient: {},
    removed: 'network',
    // The postinstall fetches the release tarball from github.com. With no network grant the
    // resolver and the connect both fail, and which errno lands depends on how the jail's network
    // denial surfaces to libuv — they are all the same refusal, so the first term is an alternation.
    //
    // ⛔ THE `github.com` TERM IS LOAD-BEARING AND ITS ABSENCE WAS A REAL HOLE. nub's own REGISTRY
    // fetch runs OUTSIDE the jail, so a transient `ECONNREFUSED` from anywhere in the install would
    // have satisfied a bare-errno regex — and reported a clean detection of a denial that never
    // happened. Naming the host the script actually reaches for closes that.
    refusal: [/EAI_AGAIN|ENETUNREACH|ECONNREFUSED|EHOSTUNREACH|EPERM[^]{0,200}connect/, /github\.com/],
    // The install script's own closing line, in either shape.
    ranEvidence: /Hugo install(ed successfully|ation failed)/,
    mustDetect: ['rc', 'gate'],
  },
  // ── win32 ────────────────────────────────────────────────────────────────────────────────────
  //
  // ⛔ THIS CASE REPLACES THE R1 "TEETH CONTROL" IN `win-evict-probe.yml`, WHICH WAS MEASURED
  // NON-DISCRIMINATING ON THIS PLATFORM. R1 required a SHALLOW (root-only) store eviction to produce
  // a false PASS, so that deep eviction could be shown to be what prevents one. MEASURED on both
  // venues — win-evict-probe run 31132145179 on `windows-latest`, and the same rows re-run on the
  // corpus VM — it did not: R1 and R2 came back identical at `rc=1 artifacts=6/6`, differing only in
  // `EVICT 1` vs `EVICT 30`. The reason is mechanical rather than a gap in the experiment: both arms
  // fail on a WRITE refused at the grant boundary (`EPERM … mkdir …\bin`), which fires whether or
  // not the entry was evicted, so eviction depth is not the discriminating variable here and no
  // amount of retrying could have made it one. What actually needs proving is not "deep eviction is
  // load-bearing" but "the win32 verify arm can detect an under-grant", which is this file's job and
  // is grounded in measured arms rather than a synthetic eviction manipulation.
  //
  // ⛔ VERSION 0.2.1, NOT THE 0.4.8 THE LINUX CASE USES, AND DELIBERATELY SO. The grant is not read
  // off a committed win32 record because there are none yet — this case is part of what unblocks the
  // first ones. It is grounded instead on REAL ARMS, which is the stronger of the two anyway: the
  // sufficient and insufficient verdicts below were each produced twice, independently, on
  // `windows-latest` (run 31132145179 rows R0/R3 and R1/R2) and again on the corpus VM.
  //
  // ⛔ `EPERM`, NOT `EACCES`. Same refusal, different spelling — Windows reports a denied create as
  // EPERM. Verbatim from the two insufficient arms of run 31132145179, which failed at DIFFERENT
  // points depending on how far the previous arm had got, which is why the regex names the errno and
  // the subject rather than the operation:
  //
  //   EPERM: operation not permitted, mkdir  '…\binary-install@0.1.1-<hash>\node_modules\binary-install\bin'
  //   EPERM: operation not permitted, unlink '…\binary-install@0.1.1-<hash>\node_modules\binary-install\bin\LICENSE'
  //
  // ⛔ CAUGHT BY `rc` ALONE, exactly as rover is on Linux and for the same structural reason: the
  // postinstall delegates to `binary-install` and writes into THAT package's directory, while the
  // artifact gate is scoped to the measured package's own. The insufficient arms read
  // `artifacts=6/6 missing=0` — a full manifest — so the install exit code is the only thing between
  // a narrowed grant and a `SUFFICIENT` verdict on this platform.
  {
    name: 'write.deps',
    platform: 'win32',
    pkg: '@apollo/rover',
    version: '0.2.1',
    sufficient: { write: { deps: true }, network: true },
    insufficient: { network: true },
    removed: 'write.deps',
    refusal: [/EPERM/, /binary-install/],
    // Identical to the Linux case: the download line when the write is permitted, the
    // `binary-install` require-stack when it is not. Both shapes were observed on win32 —
    // `Downloading release from https://github.com/apollographql/rover/…` on the sufficient arm,
    // `binary-install\index.js:48:7` on the insufficient one.
    ranEvidence: /Downloading release from|binary-install[/\\]index\.js/,
    mustDetect: ['rc'],
  },
  // ⛔ THE ONLY CASE GROUNDED ON DARWIN, AND ITS SCOPE IS PRINTED WITH EVERY VERDICT. See the
  // scope-limit block near the bottom: hugo is caught by rc AND the gate, so a green darwin control
  // proves at least one detector is live and CANNOT say which. The rover axis — an artifact landing
  // in a SIBLING package the gate deliberately does not walk, catchable by the exit code alone — is
  // uncovered here. A one-case control is worth far more than none, but only if its limit travels
  // with its verdict rather than living in a report nobody re-reads.
  {
    name: 'network',
    platform: 'darwin',
    pkg: 'hugo-extended',
    version: '0.141.0',
    // records-v2/runs/darwin-arm64/hugo-extended/0.141.0/results.json — MINIMUM, MINIMAL.
    // MINIMAL means the descent removed each capability in turn and found it necessary, so
    // `insufficient` is this corpus's own darwin answer with its one term deleted, not a guess.
    sufficient: { network: true },
    insufficient: {},
    removed: 'network',
    // ⛔ MEASURED on darwin-arm64: the nar-no-network arm returned rc=1 with
    // `artifacts=9/12 missing=3` — vendor/hugo, vendor/LICENSE, vendor/README.md, i.e. exactly the
    // three files the download produces — and shortfall digest 219cbefac624. Both detectors fired,
    // which is what `mustDetect` below records and what the scope limit is about.
    //
    // ⛔ INFERRED, NOT MEASURED: the refusal TEXT. The published record carries the arm's verdict
    // line, not its install log, and I have no darwin arm log to read. The terms below are the Linux
    // case's, which is defensible because the postinstall is platform-independent JS fetching the
    // same host — but it is an inference. If the first darwin run FAILS on the refusal terms
    // specifically, that is this pattern being wrong, NOT the harness losing the ability to detect;
    // the per-term hit/MISS breakdown in the failure message is what tells them apart. Failing
    // closed here is the right direction: it blocks a batch rather than passing one.
    refusal: [/EAI_AGAIN|ENETUNREACH|ECONNREFUSED|EHOSTUNREACH|EPERM[^]{0,200}connect/, /github\.com/],
    ranEvidence: /Hugo install(ed successfully|ation failed)/,
    mustDetect: ['rc', 'gate'],
  },
];

// ── driver invocation + output parsing ────────────────────────────────────────────────────────
//
// ⛔ THIS FILE PARSES `measure.sh`'S STDOUT AND NEVER EDITS IT. The driver is under concurrent
// development; the contract depended on here is its ARGV, its `###  <pkg>@<ver>   (<root>)` header,
// its `VERIFY[...]` line and its `=>` terminal vocabulary — the same surface `run-batch-v2.mjs`
// already relies on, all of it stable.
const runArm = (kase, grant, label) => {
  const t0 = Date.now();
  // ⛔ THE WIN32 DRIVER IS NODE, TAKES FLAGS RATHER THAN POSITIONALS, AND THERE IS NO `bash` TO RUN
  // IT WITH. Same dispatch `run-batch-v2.mjs` carries, and the same reason it lives in one place:
  // `measure.sh`/`measure-macos.sh` take `<pkg> <ver> [nub]`, `measure-windows.mjs` takes
  // `--nub`. The `--root` default stays `C:\jail` — deliberately NOT under `C:\Users\<user>`, whose
  // inheritable AppContainer package SIDs make every jailed arm there fail on token construction
  // before a script runs, which a reader would mistake for a grant result.
  // ⛔ THE DARWIN DRIVER NEEDS ROOT AND THIS FILE WAS NOT GIVING IT ANY. dtrace requires uid 0, so
  // `bash measure-macos.sh …` unprivileged dies before it traces anything — MEASURED locally,
  // reproducing the runner exactly: rc=1 in 3s, ZERO verdict lines, `dtrace: DTrace requires
  // additional privileges`. falsify then reported `UNPARSED … detectors=none` and FAILED the case,
  // which reads as "the harness cannot detect a bad grant" when the truth is "the driver never ran".
  // An instrument failure wearing the costume of the finding it exists to make.
  //
  // ⛔ THE `sudo -E` REASONING NOW LIVES IN `driver-invocation.mjs` AND IS NO LONGER MIRRORED HERE.
  // Mirroring is what produced this defect: three callers each carried the invocation, and the copy
  // in this file omitted `sudo` entirely. One module, one copy, and its test asserts both terms by
  // name. Only the ARGV SHAPE stays here, because it genuinely differs — win32 names the binary with
  // `--nub`, the POSIX drivers take it positionally.
  // ⛔ `DRIVER`, NOT the module's file: `--driver` overrides it, and a flag that is parsed, validated
  // for existence and then ignored is the exact defect that shipped a driver's parser with no
  // dispatch this morning. `cmd`/`pre` still come from the module — an alternate darwin script needs
  // `sudo -E` just as much as the default one does.
  const opts = { encoding: 'utf8', maxBuffer: 1 << 28, timeout: BUDGET_MS };
  const args = process.platform === 'win32'
    ? [...DRIVER_PRE, DRIVER, kase.pkg, kase.version, '--nub', NUB, '--at-grant', JSON.stringify(grant)]
    : [...DRIVER_PRE, DRIVER, kase.pkg, kase.version, NUB, '--at-grant', JSON.stringify(grant)];
  const r = spawnSync(DRIVER_CMD, args, opts);
  const out = (r.stdout ?? '') + (r.stderr ?? '');
  const rc = r.status ?? (r.error ? -1 : 1);
  const grab = (re, i = 1) => { const m = out.match(re); return m ? m[i] : null; };

  // ⛔ THE HEADER IS NOT ANCHORED TO END-OF-LINE, BECAUSE THE DRIVERS DISAGREE ON WHAT FOLLOWS THE
  // ROOT. `measure.sh` ends the line at the closing paren; `measure-macos.sh` appends ` nub=<path>`.
  // Anchoring made `root` null on darwin, which empties `armLogs` — and with no logs, `refusalSeen`,
  // `scriptRan` and `evidenceIsSound` are all false, so this file reports "the arm may have REPLAYED
  // a previous arm's build" about a run that was fine. A parser reading three drivers has to accept
  // all three dialects, or it fabricates alarms on the two it was not written against.
  const root = grab(/^###\s+\S+\s+\((\S+)\)/m);
  const slurp = (...p) => { try { return fs.readFileSync(path.join(...p), 'utf8'); } catch { return ''; } };
  // The arm's own install/approve logs, which is where an OS refusal actually lands — the driver's
  // stdout carries only the verdict lines. `verify-at-grant` is the label DIRECT mode passes.
  const armLogs = root ? ['i.log', 'a.log'].map((f) => slurp(root, 'verify-at-grant', f)).join('') : '';
  // OBSERVE's `npm install --ignore-scripts` log: the same package, the same run, with the lifecycle
  // script provably NOT executed. That makes it a real NEGATIVE CONTROL for `ranEvidence` — see the
  // `evidenceIsSound` note below.
  const fetchLog = root ? slurp(root, 'observe', 'fetch.log') : '';

  const verify = out.match(
    // ⛔ `shortfall=` IS OPTIONAL BECAUSE ONLY THE POSIX DRIVERS EMIT IT. `measure-windows.mjs`
    // prints `artifacts=6/6 missing=0 (tree 78/250)` with no shortfall term, so the required form
    // fell through to the `|\S+` alternative and matched `artifacts=6/6` as one opaque token —
    // leaving `artifacts`, `reference` and `missing` null on every win32 arm while `rc` still
    // parsed. A win32 case declaring `mustDetect: ['gate']` would then have been unsatisfiable for
    // a PARSING reason, and silently: the driver prints `missing`, this file just never read it.
    // Optional rather than a second alternative so the capture-group numbering — and therefore
    // OVERRIDDEN/REJECTED at 6 and 7 — is unchanged for the POSIX lanes.
    /VERIFY\[at-grant\] rc=(\d+) (?:artifacts=(\d+|ABSENT)\/(\d+) missing=(\d+)(?:\s+shortfall=(\S+))?|\S+)[^\n]*OVERRIDDEN=(\d+) REJECTED=(\d+)/,
  );

  return {
    label,
    grant,
    driverRc: rc,
    timedOut: r.error?.code === 'ETIMEDOUT',
    durationMs: Date.now() - t0,
    root,
    // The driver's own terminal word. Read from its vocabulary rather than re-derived, so this file
    // cannot disagree with the thing it is auditing.
    verdict: /^\s*=> SUFFICIENT /m.test(out) ? 'SUFFICIENT'
      : /^\s*=> INSUFFICIENT /m.test(out) ? 'INSUFFICIENT'
        : /VOID/.test(out) ? 'VOID'
          : /BROKEN-WITHOUT-JAIL-TOO/.test(out) ? 'BROKEN-WITHOUT-JAIL-TOO'
            : 'UNPARSED',
    // ⛔ THE SINGLE MOST LIKELY CAUSE OF AN ALL-VOID RUN. nub refuses `NUB_BUILD_JAIL_CATALOG`
    // outright when the binary was built without `nub-cli/build-jail-catalog-override`. MEASURED:
    // the shared corpus-VM binary was rebuilt mid-session without the flag and turned four passing
    // arms into four VOIDs, which read as a harness defect until an arm log was opened.
    //
    // Two routes, and BOTH are matched because they surface in different places. `measure.sh` now
    // probes the binary before OBSERVE and aborts rc=3 on its own stdout — that is the primary
    // detector and this is a backstop for it. But a binary that passes that probe and still fails
    // per-arm puts the refusal only in the arm's `i.log`, where the driver never looks: it sees
    // `OVERRIDDEN=0` and reports VOID with no cause at all.
    featureMissing: /was not built with (the )?`?build-jail-catalog-override`?/.test(armLogs + out),
    installRc: verify ? Number(verify[1]) : null,
    artifacts: verify ? verify[2] : null,
    reference: verify ? (verify[3] ?? null) : null,
    missing: verify && verify[4] != null ? Number(verify[4]) : null,
    overridden: verify ? Number(verify[6]) : null,
    rejected: verify ? Number(verify[7]) : null,
    // Same dialect problem: `measure.sh` prints `EVICT     <n> store entries removed`,
    // `measure-macos.sh` prints `EVICT[<label>] <n> …`. The optional bracketed label is what makes
    // this match both; without it darwin reported `evicted=-1` and the eviction judge failed a run
    // whose eviction had in fact happened.
    evicted: Number(grab(/EVICT(?:\[[^\]]*\])?\s+(\d+) store entries removed/) ?? -1),
    // ⛔ REPORTED, NOT FAILED, AND THE REASON IS A MEASURED DEFECT IN THE DRIVER'S OWN PREDICATE.
    // `measure.sh` warns `REPLAY SUSPECTED` when no arm log matches `running build scripts for`. nub
    // prints that line only for a package on its DEFAULT-TRUST list, where the script runs during
    // `install`. For every other package `install` prints `WARN ignored build scripts for N
    // package(s)` and the script runs later under `approve-builds --all`, which prints neither — so
    // the warning fires on every arm of every untrusted package regardless of whether anything
    // replayed. MEASURED both sides in one run: `@apollo/rover@0.4.8` (trusted) never trips it, while
    // `hugo-extended@0.141.0` trips it on an arm whose log says `✔ Hugo installed successfully!` with
    // a full 12/12 artifact manifest. 10 of the 45 committed linux-x64 `driver.out` files carry it.
    //
    // Treating it as a failure would make this file unusable as a pre-flight; treating it as proof
    // the script ran would be trusting a predicate that cannot distinguish the two cases. So it is
    // neither: it is printed, and `scriptRan` below answers the question directly instead.
    replaySuspected: /REPLAY SUSPECTED/.test(out),
    // Per-term, not just the conjunction: when a refusal check fails, which HALF failed is the whole
    // diagnosis — a missing errno means the operation was skipped, a missing subject means something
    // unrelated failed instead.
    refusalTerms: kase.refusal.map((re) => ({ re: String(re), hit: re.test(armLogs) })),
    refusalSeen: kase.refusal.every((re) => re.test(armLogs)),
    // ⛔ THE POSITIVE CONTROL ON "THE LIFECYCLE SCRIPT ACTUALLY RAN", asked of the PACKAGE'S OWN
    // OUTPUT rather than of nub's install summary. A replayed arm materialises from the store and
    // never spawns the script, so none of this can appear.
    scriptRan: kase.ranEvidence.test(armLogs),
    // ⛔ AND THE NEGATIVE CONTROL ON THE CONTROL, because a `ranEvidence` regex loose enough to match
    // ordinary install chatter would be a check that cannot fail — the exact defect this whole file
    // exists to catch, reintroduced one level up. `observe/fetch.log` is an `npm install
    // --ignore-scripts` of the same package in the same run, i.e. an install where the script
    // provably did NOT execute. The regex must be silent there.
    evidenceIsSound: fetchLog.length > 0 && !kase.ranEvidence.test(fetchLog),
    armLogBytes: armLogs.length,
    out,
  };
};

// Which of the two independent detectors actually said no. Recorded per arm even when the run
// passes, because a silent change from "both fired" to "only rc fired" is the tell that the gate
// stopped being able to fail for this package.
//
// ⛔ `artifacts=ABSENT` IS DELIBERATELY **NOT** COUNTED AS THE GATE FIRING, AND COUNTING IT WOULD
// COLLAPSE THE TWO DETECTORS INTO ONE. `artifact-gate.mjs` reports `ABSENT` with `missing=1
// <package absent>` when the package directory is not in the arm tree at all — which is what a
// WHOLESALE install failure looks like. That is the same event that made `rc` non-zero, so a case
// asking for two independent detectors would get one signal counted twice and never notice that the
// per-file manifest had stopped discriminating. The gate has only genuinely fired when it found the
// package present and some of its files short or missing.
const detectorsThatFired = (arm) => {
  const d = [];
  if (arm.installRc != null && arm.installRc !== 0) d.push('rc');
  if (arm.artifacts !== 'ABSENT' && arm.missing > 0 && arm.reference != null
      && arm.missing < Number(arm.reference)) d.push('gate');
  return d;
};

// ── per-arm judgement ─────────────────────────────────────────────────────────────────────────
//
// ⛔ TWO OUTCOMES, NOT ONE, AND COLLAPSING THEM IS THE SAME MISTAKE `measure.sh` DOCUMENTS FOR VOID.
// `fail` means the harness was shown UNABLE to detect a wrong answer; `inconclusive` means the venue
// could not put the question. Both exit non-zero — an unanswered falsification control is never a
// green light — but only one of them is a finding about the harness, and reporting a broken binary
// as "the harness cannot detect under-granting" would burn the alarm this file exists to raise.
const noteVoid = (arm) => `arm was VOID — the catalog override did not engage, so nothing was measured`
  + (arm.featureMissing
    ? '. CAUSE FOUND IN THE ARM LOG: this nub binary was built without `nub-cli/build-jail-catalog-override`,'
      + ' so it REFUSES `NUB_BUILD_JAIL_CATALOG` rather than honouring it. Rebuild with'
      + ' `cargo build --release -p nub-cli --features nub-cli/build-jail-catalog-override`.'
    : '');

const judgeWrong = (kase, arm) => {
  const fail = []; const inconclusive = [];
  if (arm.verdict === 'SUFFICIENT') {
    // The headline failure this whole file exists to surface. Worded so it cannot be skimmed past.
    fail.push(`⛔⛔ P0: the harness reported a KNOWN-INSUFFICIENT grant as SUFFICIENT. `
      + `${kase.pkg}@${kase.version} needs '${kase.removed}' and installed without it. `
      + `The harness cannot detect under-granting; NO record produced by it is trustworthy until this is explained.`);
    return { fail, inconclusive };
  }
  if (arm.verdict === 'VOID') { inconclusive.push(noteVoid(arm)); return { fail, inconclusive }; }
  if (arm.verdict !== 'INSUFFICIENT') {
    inconclusive.push(`arm did not reach a verdict (${arm.verdict}${arm.timedOut ? ', timed out' : ''})`);
    return { fail, inconclusive };
  }
  // INSUFFICIENT reached. Now: for the right reason?
  if (!arm.refusalSeen) {
    fail.push(`arm failed but its logs do not carry the full refusal — `
      + `${arm.refusalTerms.map((t) => `${t.re}:${t.hit ? 'hit' : 'MISS'}`).join(' AND ')} `
      + `(${arm.armLogBytes}B of arm logs read). The fatal operation may never have been attempted, `
      + `so this is not evidence the grant was enforced.`);
  }
  const fired = detectorsThatFired(arm);
  for (const d of kase.mustDetect) {
    if (!fired.includes(d)) {
      fail.push(`detector '${d}' did not fire (fired: ${fired.join('+') || 'none'}) — `
        + `${d === 'gate' ? 'the artifact gate' : 'the install exit code'} has stopped being able to catch this case`);
    }
  }
  if (arm.overridden != null && arm.overridden < 1) fail.push('OVERRIDDEN=0 — the arm measured the compiled-in catalog, not the stated grant');
  if (arm.rejected) fail.push(`REJECTED=${arm.rejected} — nub refused the override catalog`);
  fail.push(...judgeScriptRan(kase, arm));
  // `wrong-cold` runs first on a deliberately cold venue, so an empty store is expected there.
  if (arm.label !== 'wrong-cold') fail.push(...judgeEviction(arm));
  return { fail, inconclusive };
};

// ⛔ THE EVICTION IS THE HARNESS'S OWN ARM-INDEPENDENCE MECHANISM, AND IT HAS SILENTLY NO-OPPED
// BEFORE. `measure.sh` records that the first revision of its store eviction used a slug that
// matched nothing for SCOPED packages — `@babel/core` became `-babel-core` — so it removed zero
// entries for a large share of the corpus while looking perfectly healthy. `@apollo/rover` is
// scoped, so this oracle's own write-axis case sits squarely in that blast radius. The driver prints
// the count; nothing was reading it.
//
// Applied to `right` and `wrong-warm` only. `wrong-cold` runs first by design and may legitimately
// find an empty store, so requiring an eviction there would fail on a genuinely cold venue.
const judgeEviction = (arm) => (arm.evicted >= 1 ? [] : [
  `EVICT removed ${arm.evicted} store entries — the arm may have REPLAYED a previous arm's build `
  + `rather than rebuilding, which makes its verdict unattributable. The store eviction has silently `
  + `no-opped before (a slug that matched no scoped package).`,
]);

// Applies to every arm, whatever its grant: an arm whose script never spawned measured nothing, and
// on a WRONG arm it would masquerade as a detection.
const judgeScriptRan = (kase, arm) => {
  const fail = [];
  if (!arm.scriptRan) {
    fail.push(`no evidence the lifecycle script ran — nothing matching ${kase.ranEvidence} in `
      + `${arm.armLogBytes}B of arm logs. A replayed arm materialises from the store without spawning `
      + `the script, and on a wrong-grant arm that is indistinguishable from a detection.`);
  }
  if (!arm.evidenceIsSound) {
    fail.push(`the ran-evidence regex ${kase.ranEvidence} is UNSOUND for this run: it matched (or `
      + `could not be checked against) OBSERVE's own --ignore-scripts fetch log, so a match in the arm `
      + `logs is not evidence the script ran. Tighten the regex.`);
  }
  return fail;
};

const judgeRight = (kase, arm) => {
  const fail = []; const inconclusive = [];
  if (arm.verdict === 'SUFFICIENT') {
    fail.push(...judgeScriptRan(kase, arm));
    // ⛔ THE NEGATIVE CONTROL ON THE REFUSAL REGEX, AND WITHOUT IT THE REGEX IS UNFALSIFIABLE.
    // `refusalSeen` was previously only ever read on a WRONG arm, where it is required to be true.
    // A regex that matched everything — `/./`, or an errno so generic it appears in any install —
    // would satisfy every wrong arm and be read nowhere else, leaving the whole oracle green while
    // proving nothing about enforcement. The control arm installs successfully under the full grant,
    // so the refusal MUST be absent there. Asserting both directions is what makes the regex a
    // measurement rather than a decoration.
    if (arm.refusalSeen) {
      fail.push(`the control arm installed successfully but its logs ALSO match the refusal pattern `
        + `${kase.refusal.map(String).join(' AND ')} — the pattern does not discriminate, so its `
        + `presence on a wrong arm is not evidence of a denial. Tighten it.`);
    }
    fail.push(...judgeEviction(arm));
    return { fail, inconclusive };
  }
  if (arm.verdict === 'VOID') { inconclusive.push(`control ${noteVoid(arm)}`); return { fail, inconclusive }; }
  if (arm.verdict === 'BROKEN-WITHOUT-JAIL-TOO' || arm.timedOut) {
    inconclusive.push(`control could not run (${arm.verdict}${arm.timedOut ? ', timed out' : ''})`);
    return { fail, inconclusive };
  }
  // ⛔ A FAILING CONTROL INVALIDATES THE WHOLE CASE, IT DOES NOT MERELY FAIL IT. Everything failing
  // is the signature of a broken venue, and the wrong arm's INSUFFICIENT then carries no information.
  // Kept as a FAIL rather than an inconclusive: a known-minimal grant that stopped installing is
  // either a real regression or a stale record, and both need a human before any sweep starts.
  fail.push(`⛔ CONTROL FAILED: the known-sufficient grant ${JSON.stringify(kase.sufficient)} did NOT `
    + `install (${arm.verdict}, rc=${arm.installRc}, missing=${arm.missing}). Every result for this case is `
    + `UNATTRIBUTABLE — fix the venue or the record before reading the wrong-grant arms.`);
  return { fail, inconclusive };
};

// ── run ───────────────────────────────────────────────────────────────────────────────────────

// ⛔ A CAPABILITY PROBE, AND IT EXISTS BECAUSE THE ANSWER WAS BEING KEPT IN TWO PLACES.
// `run-batch-v2.mjs` has to decide whether to run this control before it starts a slice. It decided
// with its own hardcoded `process.platform !== 'linux'`, which went stale the moment win32 gained a
// case here: the case was grounded on measured arms, verified in BOTH directions, wired in — and
// then skipped by a batch runner still printing "no case table for win32 yet". A second copy of a
// list is a copy that drifts, and this one drifted silently while reading as deliberate.
//
// Deliberately ABOVE the `--nub`/`--driver` checks: the question is "does a case EXIST for this
// platform", not "can it run right now". A caller deciding whether to bother must not need a binary.
if (argv.includes('--has-case')) {
  const n = CASES.filter((c) => c.platform === process.platform).length;
  console.log(`${n} falsification case(s) grounded on ${process.platform}`);
  process.exit(n > 0 ? 0 : 1);
}

if (!NUB) { console.error('falsify.mjs: --nub <binary> is required'); process.exit(2); }
if (!fs.existsSync(NUB)) { console.error(`falsify.mjs: no such nub binary: ${NUB}`); process.exit(2); }
if (!fs.existsSync(DRIVER)) { console.error(`falsify.mjs: no such driver: ${DRIVER}`); process.exit(2); }

// ⛔ REFUSES rather than silently running another platform's table. A case is grounded in the arms
// of ONE platform, so an empty selection means this platform has no falsification evidence — which
// is a hard stop, not a pass. Exit 2 (INCONCLUSIVE) because the question was never put.
const forPlatform = CASES.filter((c) => c.platform === process.platform);
if (!forPlatform.length) {
  console.error(`falsify.mjs: no case is grounded on ${process.platform} — this platform has no`);
  console.error('  falsification evidence, so the harness cannot be shown able to reject a bad grant here.');
  process.exit(2);
}
const selected = forPlatform.filter((c) => !ONLY || c.name === ONLY);
if (!selected.length) { console.error(`falsify.mjs: no ${process.platform} case named '${ONLY}'`); process.exit(2); }

console.log(`falsify: ${selected.length} case(s) on ${process.platform}, driver=${DRIVER}, nub=${NUB}${QUICK ? ', --quick (no warm arm)' : ''}`);
// ⛔ ONE CASE PROVES AT LEAST ONE DETECTOR IS LIVE; IT DOES NOT ISOLATE WHICH. The measured reason
// this matters is in the header: rover is caught by `rc` ALONE while hugo is caught by `rc` AND the
// artifact gate, so a single rc-detected case leaves the gate entirely unattested — a later change
// that made the driver tolerant of a non-zero rc would pass this control while detecting nothing.
// Printed on every run rather than only when short, so a green one-case platform can never be read
// as equivalent to a green two-case one.
if (!ONLY && forPlatform.length < 2) {
  console.log(`  ⚠ ${process.platform} has ONE case, covering detector(s): `
    + `${[...new Set(forPlatform.flatMap((c) => c.mustDetect))].join(', ')}. A green run proves at least`);
  console.log('    one detector is live; it does not isolate which, and it leaves the others unattested.');
}

const results = [];
let failed = 0; let inconclusive = 0;

for (const kase of selected) {
  console.log(`\n── ${kase.name}: ${kase.pkg}@${kase.version} — drop '${kase.removed}' from ${JSON.stringify(kase.sufficient)}`);
  const arms = [];
  const fails = []; const inconclusives = [];
  const absorb = (label, j) => {
    fails.push(...j.fail.map((m) => `[${label}] ${m}`));
    inconclusives.push(...j.inconclusive.map((m) => `[${label}] ${m}`));
    return j;
  };

  // ⛔ ORDER IS LOAD-BEARING: the wrong arm runs FIRST, on the coldest venue available. Running the
  // control first would hand the wrong arm a store, a private home and a downloaded artifact that
  // the control's own success created — which is precisely the state that can satisfy the operation
  // the narrowed grant is supposed to forbid.
  const cold = runArm(kase, kase.insufficient, 'wrong-cold');
  arms.push(cold);
  absorb('wrong-cold', judgeWrong(kase, cold));

  const right = runArm(kase, kase.sufficient, 'right');
  arms.push(right);
  const control = absorb('right', judgeRight(kase, right));

  // The warm arm is only meaningful once the control has actually populated the caches it is meant
  // to probe, so a failed control skips it rather than reporting a second unattributable result.
  if (!QUICK && !control.fail.length && !control.inconclusive.length) {
    const warm = runArm(kase, kase.insufficient, 'wrong-warm');
    arms.push(warm);
    absorb('wrong-warm', judgeWrong(kase, warm));
  }

  for (const a of arms) {
    console.log(`   ${a.label.padEnd(11)} ${String(a.verdict).padEnd(13)} `
      + `installRc=${a.installRc} artifacts=${a.artifacts}/${a.reference} missing=${a.missing} `
      + `evicted=${a.evicted} refusal=${a.refusalSeen ? 'seen' : '—'} ranEvidence=${a.scriptRan ? 'seen' : '—'} `
      + `detectors=${detectorsThatFired(a).join('+') || 'none'} [${Math.round(a.durationMs / 1000)}s]`);
    // Printed, never failed — see the note beside `replaySuspected`. Kept visible because a trusted
    // package that suddenly starts tripping it WOULD mean something.
    if (a.replaySuspected) {
      console.log(`   ·  [${a.label}] driver printed REPLAY SUSPECTED; its predicate only matches `
        + `default-trust packages, and ranEvidence=${a.scriptRan ? 'seen' : '—'} answers it directly`);
    }
  }

  // ⛔ EACH ARM IS A SEPARATE `measure.sh` RUN, SO EACH BUILDS ITS OWN OBSERVE REFERENCE — AND IF
  // THOSE DIVERGE THE ARMS WERE NOT GATED AGAINST THE SAME THING. The artifact gate compares against
  // whatever that arm's own unjailed install produced, so a registry change, a partial fetch, or a
  // platform-conditional file mid-run would silently move the goalposts between `wrong` and `right`
  // — and the comparison this whole construction rests on would be between two different questions.
  // Cheap to check: the reference count is printed on every VERIFY line.
  const refs = [...new Set(arms.map((a) => a.reference).filter((r) => r != null))];
  if (refs.length > 1) {
    fails.push(`the arms did not share an OBSERVE reference (${refs.join(' vs ')} files) — each arm `
      + `gated against a different unjailed install, so their verdicts are not comparable`);
  }

  // A real FAIL outranks an inconclusive: a `SUFFICIENT` wrong arm is a finding no matter what else
  // in the venue also went wrong.
  const verdict = fails.length ? 'FAIL' : inconclusives.length ? 'INCONCLUSIVE' : 'PASS';
  if (verdict === 'FAIL') failed++;
  if (verdict === 'INCONCLUSIVE') inconclusive++;
  for (const p of fails) console.log(`   ⛔ ${p}`);
  for (const p of inconclusives) console.log(`   ·  ${p}`);
  console.log(`   => ${verdict}`);

  // ⛔ SWEEP THIS CASE'S ROOTS WHEN IT PASSED, KEEP THEM WHEN IT DID NOT. `measure.sh` deliberately
  // never removes `$ROOT` — for a MEASUREMENT that tree is the artifact of record. These are not
  // measurements, and at 3-6 full install trees per invocation (hugo alone pulls a ~40 MB binary) a
  // per-batch pre-flight would fill the runner's disk over a long sweep. That is not hypothetical on
  // this fleet: a corpus box was found at 100% with 166 GB of abandoned harness fixture roots, and
  // a full disk is indistinguishable from a dead machine. A FAILED case keeps everything, because
  // its roots are the only evidence of the failure.
  if (verdict === 'PASS' && !KEEP_ROOTS) {
    for (const a of arms) if (a.root) fs.rmSync(a.root, { recursive: true, force: true });
  } else {
    for (const a of arms) if (a.root) console.log(`   ·  kept for inspection: ${a.root}`);
  }

  results.push({
    case: kase.name,
    pkg: kase.pkg,
    version: kase.version,
    removed: kase.removed,
    sufficient: kase.sufficient,
    insufficient: kase.insufficient,
    verdict,
    failures: fails,
    inconclusive: inconclusives,
    arms: arms.map(({ out, ...rest }) => ({ ...rest, detectors: detectorsThatFired(rest) })),
  });
}

const overall = failed ? 'FAIL' : inconclusive ? 'INCONCLUSIVE' : 'PASS';
console.log(`\nfalsify: ${overall} — ${selected.length - failed - inconclusive}/${selected.length} case(s) detected their wrong grant`
  + `${failed ? `, ${failed} FAILED` : ''}${inconclusive ? `, ${inconclusive} inconclusive` : ''}`);
// ⛔ THE SCOPE OF A GREEN CONTROL, PRINTED WITH EVERY VERDICT AND NEVER ONLY IN A REPORT. A control
// whose limits live somewhere else becomes, within days, a control that "passed" — and the limit
// that matters is not how MANY cases ran but which DETECTOR each one isolates.
//
// A case listing a single detector in `mustDetect` ISOLATES it: that detector alone stood between a
// narrowed grant and a false SUFFICIENT, so its liveness is proven independently. A case listing two
// proves at least one of them is live and cannot say which — if the exit-code detector were broken
// and only the gate were working, such a case still passes, and every rover-shaped under-grant (an
// artifact landing in a sibling package the gate does not walk) would go unnoticed. That asymmetry
// is exactly why validating this control on a single case was refused on linux, and it binds here.
const DETECTORS = ['rc', 'gate'];
const isolated = DETECTORS.filter((d) => selected.some((c) => c.mustDetect.length === 1 && c.mustDetect[0] === d));
const jointOnly = DETECTORS.filter((d) => !isolated.includes(d) && selected.some((c) => c.mustDetect.includes(d)));
const untouched = DETECTORS.filter((d) => !isolated.includes(d) && !jointOnly.includes(d));
console.log(`   scope: ${selected.length} case(s) on ${process.platform} — `
  + selected.map((c) => `${c.pkg}@${c.version} [${c.mustDetect.join('+')}]`).join(', '));
console.log(`   isolated detector(s): ${isolated.join(', ') || 'NONE'}`
  + `${jointOnly.length ? `; proven only JOINTLY: ${jointOnly.join(', ')}` : ''}`
  + `${untouched.length ? `; UNCOVERED: ${untouched.join(', ')}` : ''}`);
if (!isolated.length) {
  console.log('   ⛔ NO detector is isolated here: a green verdict proves at least one is live and');
  console.log('      cannot say which. A broken rc detector would still pass, and the class only rc');
  console.log('      catches — an artifact written into a SIBLING package — would go undetected.');
}
if (failed) {
  console.log('⛔ The harness could not be shown capable of rejecting a known-insufficient grant.');
  console.log('   Do NOT start a sweep. A silent under-grant is the one error this corpus may not make.');
} else if (inconclusive) {
  console.log('·  The question was never put — the venue, not the harness, is what failed. Fix it and re-run;');
  console.log('   an unanswered falsification control is not a green one.');
}

if (JSON_OUT) {
  // ⛔ `mkdirSync(..., {recursive:true})` THROWS ON A WINDOWS DRIVE ROOT, and the crash lands AFTER
  // the verdict has already been decided — so it converts a PASS into a non-zero exit. MEASURED:
  // `--json C:\falsify.json` gives a dirname of `C:\`, and Node raises
  // `EPERM: operation not permitted, mkdir 'C:\'` even though the directory plainly exists and
  // `recursive` is supposed to make an existing directory a no-op. The run that found this printed
  // `falsify: PASS — 1/1 case(s) detected their wrong grant` and then exited 1.
  //
  // That is the worst possible shape for THIS file in particular: it is the pre-sweep gate, so a
  // spurious red trains a reader to discount its exit code, which is the one signal it exists to
  // provide. Existence check first; the recursive create is only for a genuinely absent directory.
  const outDir = path.dirname(path.resolve(JSON_OUT));
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(JSON_OUT, `${JSON.stringify({
    at: new Date().toISOString(),
    platform: `${process.platform}-${process.arch}`,
    driver: DRIVER,
    nub: NUB,
    quick: QUICK,
    overall,
    results,
  }, null, 2)}\n`);
  console.log(`wrote ${JSON_OUT}`);
}

process.exit(overall === 'PASS' ? 0 : overall === 'FAIL' ? 1 : 2);
