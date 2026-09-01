// Harness v2 driver, Windows: OBSERVE -> SYNTHESIZE -> VERIFY -> (bounded ladder).
//
// The mirror of measure.sh. It is Node rather than PowerShell on purpose: the driver has to spawn
// npm, nub and the capture script, and PowerShell quoting through those three is where this
// platform's bring-up cost has historically gone. Node's spawnSync passes an argv array straight
// to CreateProcess, so there is no re-parse to get wrong -- provided nothing is invoked through a
// shell, which is why npm is run as `node npm-cli.js` (see NPM below) and the capture script is
// invoked as `powershell.exe -File`.
//
//   usage: node measure-windows.mjs <pkg> <version> [--nub C:\nub.exe] [--root C:\jail]
//          node measure-windows.mjs <pkg> <version> --at-grant '{"network":true}'
import fs from 'node:fs';
import { fetchArgs } from './era-resolution.mjs';
import { pythonForEra, candidatePythons, resolveInterpreter } from './era-python.mjs';
import { chooseMake, MAKE_CANDIDATES } from './arm-make.mjs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
// The digest is defined once, beside the predicate that compares digests across arms. Importing that
// module does NOT run its CLI -- its main-module guard resolves the invoked script's path to a URL and
// compares it against its own, and under this import that path is THIS file.
//
// ⛔⛔ THIS COMMENT USED TO CLAIM THE SHARED DIGEST MEANT THIS DRIVER'S INLINE GATE AND
// `artifact-gate.mjs` "CANNOT DRIFT APART". THEY DID. A shared digest makes two shortfalls
// COMPARABLE; it says nothing about which files each side counts as shortfall in the first place.
// This driver's `missingArtifacts` had NO toolchain excusal while both POSIX drivers had one, so
// every Windows record counted the node-gyp output family and every regenerated lockfile as a real
// shortfall -- which is what published the corpus's only `write:"disk"` grant. The excusal now lives
// in `artifact-excusal.mjs` and both sides import it; `artifact-excusal.test.mjs` fails if either
// grows its own again. A reassuring comment is not a mechanism.
//
// ⛔ THE EXPRESSION IS DESCRIBED RATHER THAN QUOTED, AND THAT IS NOT PEDANTRY. `cli-guard.test.mjs`
// scans for files that CALL the URL-resolving form and requires each to carry the import-safety guard
// beside it. Quoting the call in prose puts a file with no CLI guard at all on that list, and the test
// then fails naming a defect that does not exist. Measured twice while writing this comment.
import { shortfallDigest } from './shortfall-invariance.mjs';
// The off-switch assertion and the verdict vocabulary come from the module that owns them, shared with
// both POSIX drivers, so three drivers cannot drift apart on what a jail-off control proved.
import { classify, offSwitchEngaged } from './unjailed-nub.mjs';
import { buildCatalog } from './dep-scaffold.mjs';
// The arm PATH's tool bin lives in the OBSERVE tree, which a jailed arm's project does not contain.
// Shared with both POSIX drivers so the three cannot drift on where a scaffolded tool has to sit.
import { stageArmTools, stagedArmPath } from './stage-arm-tools.mjs';
// The wide-but-confined probe: its path set, its never-a-root-glob guard, and the ONE marker spelling
// `record.mjs` reads. Shared with both POSIX drivers so the three cannot drift on what the probe is.
import { confinedWideBaseline, interpretation, marker as confinedWideMarker } from './confined-wide.mjs';
// The descent's variant vocabulary and its per-platform support rule, shared with both POSIX drivers.
// It is what decides that `write:"disk"` yields no write term (every narrower reach the catalog can
// spell was already refuted by a failed rung) and that win32 yields no NETWORK term either, because
// this platform drops the net axis together with the AppContainer token at that rung.
import { descentTerms, narrow as narrowGrant, verdictLines } from './descent-terms.mjs';
// The promotion probe's vocabulary and scoring, shared with the two shell drivers through the same
// module they call over its CLI — so all three ask the identical question and spell the answer once.
import {
  observeHome, probeArms, probePlan, scoreProbe, verdictLines as probeVerdictLines,
} from './promotion-probe.mjs';
import { excusesSizeDifference } from './artifact-excusal.mjs';
// ⛔ SAME REASON, SAME SHAPE: the gyp sub-target phantom is arithmetic on paths, and a driver that
// re-derives it is a driver that will one day disagree. Windows has no sighting of this class today --
// MSBuild emits `.vcxproj`, not `.target.mk`, and all 243 archived sightings are darwin/linux -- so
// this import buys the win32 driver nothing it can measure. It is here because the copy that DID NOT
// import `artifact-excusal.mjs` is the reason that module exists.
import { gypSubtargetSpill, gypSubtargetRelocations } from './gyp-subtarget-spill.mjs';
// ONE implementation of nub's 20.6 `--import` threshold, shared with falsify's waiver. Recomputing it
// here is how the same constant drifts into two answers — the npm-shim bug appeared three times that way.
import { supportsImport } from './stamp-waiver.mjs';
import { neverSpawned } from './never-spawned.mjs';
// Same one-definition-three-consumers reason: the override probe's predicate is shared with the two
// shell drivers rather than restated here. `override-probe.mjs` is data and pure functions with no
// CLI, so importing it runs nothing.
import { overrideProbeSaysHonoured } from './override-probe.mjs';
// IMPORTED rather than shelled out to. This driver is already JS, so it shares the SAME selector the
// two shell drivers reach through `era-node.mjs`'s CLI. A second implementation would be invisible in
// the data: records would simply disagree about which Node an era means, with nothing to flag it.
import { chooseEraNode, enginesAndDate } from './era-node.mjs';
import { npmArgv } from './npm-cli.mjs';
import { provisionEraNode } from './era-provision.mjs';
import { loadNodeMatrix } from './node-matrix.mjs';
import { isProvisioned, nodeBinDir } from './provision-node-matrix.mjs';

// ⛔ THE PLATFORM THIS DRIVER MEASURES, NAMED ONCE AND PASSED EXPLICITLY TO `descent-terms.mjs`.
// That module defaults to `process.platform`, which is right on a Windows runner and silently wrong
// anywhere else; the note beside `descentTerms(g0, WIN32)` has the under-grant that costs. All three
// drivers now name their own rather than asking the host.
const WIN32 = 'win32';

const argv = process.argv.slice(2);
const flag = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const [PKG, VER] = positional;
if (!PKG || !VER) { console.error('usage: measure-windows.mjs <pkg> <version> [--nub exe] [--root dir]'); process.exit(2); }

// ── ERA-NODE PIN ──────────────────────────────────────────────────────────────
// Same selector and the same pin mechanism as the two shell drivers, so a record cannot mean
// different things on two platforms. Resolved HERE, before any arm runs, because the pin has to be on
// PATH for the measurement; the `VENUE-NODE-SELECTION` marker later reuses this object rather than
// recomputing it, so the record cannot disagree with what actually ran.
//
// ⛔ READS the provisioned tree, never writes it — the drivers scope `NUB_CACHE_DIR` per run, so a
// `nub node install` here would refetch ~20 MB per package. `provision-node-matrix.mjs` does it once
// per box. Self-enabling on the directory's existence, so provisioning is the only switch.
//
// ⛔ `bin` on Windows, NOT `bin/node.exe`'s parent by another name: nub lays a provisioned version out
// as `<root>/node/<version>/bin/`, verified against a real install rather than assumed, and `node.exe`
// is checked alongside `node` because that is the Windows spelling.
const ERA_NODE = (() => {
  const root = process.env.NUB_ERA_NODE_ROOT || path.join(os.homedir(), '.cache', 'nub');
  let selection;
  try {
    const { matrix } = loadNodeMatrix();
    // ⛔ `npmArgv`, NOT THE DEFAULT. This is the THIRD copy of the same mistake. `enginesAndDate`
    // defaults to a bare `npm`, which on Windows is an unspawnable `.cmd` shim — and its failure path
    // returns {engines: null, published: null}, indistinguishable from a package that declares
    // neither. In the observe lane that silence cost every win32 record its era across two complete
    // sweeps: all 570 carried eraMajor null and before null while the ledger read a confident pin
    // that was really the harness default. This driver is the JAIL lane and had exactly the same
    // call. npm-cli.mjs is the one implementation; `why` is why it failed.
    const { engines, published, why } = enginesAndDate(PKG, VER, { spawnSync, npmArgv: npmArgv() });
    if (why) process.stderr.write(`  ERA-NODE LOOKUP FAILED: ${why}\n`);
    selection = { pkg: PKG, packageVersion: VER, lookupFailure: why ?? null,
                  ...chooseEraNode({ engines, publishedAt: published, matrix }) };
  } catch (e) {
    return { root, selection: { error: `era-node selection failed: ${e?.message ?? e}` }, bin: null };
  }
  // ⛔ THE SHARED HELPER, NEVER A LOCAL PATH JOIN. The Windows archive is FLAT — `node.exe` sits at the
  // version ROOT with no `bin/` — so a hand-rolled `…/bin` here reads MISSING for every version even
  // straight after a successful install, the pin silently never engages, and the gate blocks forever.
  // That is not hypothetical: the provisioner reported `0/9 provisioned` while nub printed
  // "Installed in 6.6s" nine times. One helper means the provisioner and the driver cannot disagree
  // about where a provisioned Node lives.
  // Only pin when the selector says so — see `pinnable` in era-node.mjs for the measured reason.
  const wanted = selection.pinnable !== false;
  let bin = nodeBinDir(root, selection.version);
  let present = wanted && isProvisioned(root, selection.version);
  // ⛔ PROVISION IT RATHER THAN GIVING UP, exactly as both POSIX drivers now do. Checking
  // `isProvisioned` and stopping there means a lane that has never provisioned an era Node silently
  // runs every arm on the HARNESS's Node while the record names an era — which is what the jail
  // runner did for every record it has ever measured. era-provision.mjs downloads it, unpacks it
  // with the per-platform extractor, and RUNS it to confirm the version, so a pin here is a pin.
  if (wanted && !present && selection.version) {
    const p = provisionEraNode(selection.version);
    if (p.binDir) { bin = p.binDir; present = true; }
    else selection.eraProvisionFailure = p.status;
  }
  // ⛔ NOT `process.env.PATH`. Mutating this process's PATH moves the HARNESS onto the era Node too —
  // record.mjs, the capture post-processing, every helper — and the harness is modern JS by assumption.
  // Measured on a 25-package Linux pilot: 7 of 8 records HARNESS-ERROR, all 7 pinned, all on 18.20.8.
  // `armPath` is threaded into the ARM child envs only, so the harness keeps the Node it started with.
  const armPath = present ? `${bin}${path.delimiter}${process.env.PATH ?? ''}` : (process.env.PATH ?? '');
  // ⛔ ANNOUNCE THE PIN, IN THE SAME SHAPE THE TWO SHELL DRIVERS DO. They both print
  // `ERA-NODE <status> (arms will run: …)`; this one printed only its FAILURE path, so a successful
  // Windows pin was invisible to anything reading the driver's output. That silence is not cosmetic:
  // falsify's win32 network case may waive a refusal line the arm's Node cannot emit, and it decides
  // that from this marker — with no marker the era reads UNKNOWN, the waiver is (correctly) refused,
  // and the case fails on evidence it could never have obtained. Observed on run 32659741248.
  //
  // stderr because falsify concatenates BOTH streams of the driver, and this file already reports
  // the lookup failure there — one stream for one concern.
  const status = present && selection.version ? `PINNED ${selection.version}`
    : selection.pinnable === false ? `NOT PINNED (selector declined: ${selection.pkg}@${selection.packageVersion})`
    : `NOT PINNED (${selection.eraProvisionFailure ?? selection.error ?? selection.lookupFailure ?? 'no era resolved'})`;
  process.stderr.write(`  ERA-NODE ${status} (arms will run: ${present ? `v${selection.version}` : 'the harness Node'})\n`);
  // ⛔⛔ SAY UP FRONT WHEN THIS ERA CANNOT CARRY THE JAIL'S SHIMS, BECAUSE THE FAILURE IT CAUSES IS A
  // HANG AND A HANG EXPLAINS NOTHING ABOUT ITSELF. nub stamps both Windows build-jail preloads into
  // `NODE_OPTIONS` as `--import` terms, and `build_jail.rs` gates that on the interpreter supporting
  // `--import` (20.6+), REMOVING `NODE_OPTIONS` below it — deliberately, since an unrecognised option
  // there aborts Node at startup. One of those preloads is the `child_process` stdio shim, and nub's
  // own comment says what its absence costs: "a piped spawn under the AppContainer does not fail, it
  // SPINS — libuv retries the refused named pipe forever inside `uv_spawn`, before any timeout can
  // arm — and every `node-gyp` configure pipes", leaving "the same piped-spawn hang as before".
  //
  // MEASURED: `mozjpeg@6.0.1` (era Node 10.24, node-gyp install) reported `deadline + ~35 s` at BOTH
  // a 600 s and a 900 s deadline — killed at the deadline, not slow. No deadline can pass it.
  //
  // A WARNING, NOT A SKIP, AND THAT IS THE POINT. The hang needs a piped spawn, so a package on the
  // same old era whose install does not pipe measures perfectly well. Refusing the whole era up front
  // would discard those, and pinning a NEWER Node to dodge the hang would measure a grant that is not
  // this package's — the silent-wrong-answer class this corpus exists to avoid. So: run it, and if it
  // times out, this line is the explanation sitting a few lines above in the same log.
  const [eraMajor, eraMinor] = String(selection.version ?? '').split('.').map(Number);
  if (present && Number.isFinite(eraMajor) && !supportsImport({ major: eraMajor, minor: eraMinor })) {
    process.stderr.write(`  ⛔ ERA-NODE ${selection.version} PREDATES THE JAIL'S SHIMS (needs 20.6+ for `
      + `\`--import\`). nub delivers NEITHER the child_process stdio shim NOR the net gate to this `
      + `interpreter. A lifecycle script that PIPES a spawn (node-gyp configure does) will HANG `
      + `forever under the jail, and no --arm-timeout value can rescue it — a TIMED-OUT arm below `
      + `this line is structural, not a slow venue. A script that does not pipe is unaffected.\n`);
  }
  return { root, selection, bin: present ? bin : null, armPath };
})();

// ── THE `NUB_V2_WINDOWS_EVICTION_VERIFIED` HARD STOP WAS LIFTED 2026-08-07. ────────────────────
//
// It blocked every jailed arm because every jailed arm failed at every grant on a read of the
// package's OWN entry point — `EPERM: operation not permitted, open '…\@apollo\rover\install.js'`.
// Both halves of that are now settled, so the guard is deleted rather than defaulted.
//
// 1. THE READ DENIAL IS FIXED, in nub. `4bd4687521` makes the linker COPY instead of hardlinking for
//    a Windows-jailed install: a hard link is a second name for an existing file OBJECT and Windows
//    attaches the security descriptor to the object, so a store file linked into the jail kept the
//    descriptor it was born with and the jail's inheritable grant never reached it. MEASURED
//    red→green on two venues. On `windows-latest` (`win-jail-copy-verify` runs 31128469258 and
//    31127907595): pre-fix `658e49ac36` gives rc=1 with that EPERM and 5 hard-link names; the fix
//    gives rc=0 and ONE name, i.e. a private copy. Independently on the corpus VM, interleaved to
//    rule out ordering, with the binaries identified by sha256 rather than by path or mtime:
//    pre-fix rc=1 6/7 artifacts HARDLINKED, `sandbox/integration` rc=0 7/7 COPY, twice each.
//
// 2. THE PROOF OBLIGATION MOVED, because the experiment it named was measured non-discriminating
//    here. The old text required `win-evict-probe`'s R1 to produce a FALSE PASS under a root-only
//    eviction. It never does on win32 — R1 and R2 come back identical at `rc=1 artifacts=6/6`,
//    differing only in `EVICT 1` vs `EVICT 30`, because both fail on a WRITE refused at the grant
//    boundary and that refusal fires whether or not the entry was evicted. Eviction DEPTH is simply
//    not the discriminating variable on this platform, so no amount of retrying could have satisfied
//    the criterion. R1 is retired in the workflow with the measurement recorded there.
//
//    What replaced it is stronger and is the instrument the other two platforms already use:
//    `falsify.mjs` now carries a win32 case, and it is verified in BOTH directions — against the
//    real driver `wrong-cold` is INSUFFICIENT with the refusal and the ran-evidence both seen while
//    `right` is SUFFICIENT (exit 0), and against a driver deliberately mutated to report every arm
//    ok it raises the P0 and exits 1. Plus `501c11d2`, which turns the side-effects memo off in each
//    arm's `.npmrc` as both POSIX drivers already did — measured masking a refused artifact into a
//    too-narrow arm at `7/6`, identical to the wide-grant arm, with only `rc` between it and a false
//    pass.
//
// ⛔ WHAT IS STILL OPEN, AND IT GATES PUBLISHING RATHER THAN RUNNING: the Python-bytecode
// suppression `measure.sh` carries is still absent here, and whether win32 needs it is UNRESOLVED —
// see the note in the arm environment below. Run the driver freely; do not publish a native-build
// record until that is settled.
//
// Historical note, kept because it is the reason this file was blocked for so long: the transitive
// closure sweep is ported
// (see `evictClosure`) and MEASURED ACTIVE on a real runner: win-evict-probe run 31107020153 logged
// `EVICT   30 store entries removed, 5 spared as nub tooling` per arm, against a 20-entry node-gyp
// tool closure of which ZERO declare a lifecycle script. What is missing is the PROOF, and the
// reason it is missing is its own defect:
//
// ⛔ EVERY WINDOWS ARM FAILS AT EVERY GRANT, ON A READ OF THE PACKAGE'S OWN ENTRY POINT. Verbatim,
// from four `@apollo/rover@0.2.1` arms spanning `{"network":true}` to
// `{"write":{"deps":true},"network":true}`:
//
//   Error: EPERM: operation not permitted, open
//   'C:\jail\...\verify-at-grant\node_modules\.store\@apollo+rover@0.2.1\node_modules\@apollo\rover\install.js'
//
// and from `@pulumi/datadog@0.18.9`'s synth arm, on `...\.store\grpc@1.24.2\...\node-pre-gyp\bin\node-pre-gyp`.
// No grant on the ladder widens a read of the package's own store entry, so the verdict is the same
// at every rung.
//
// ⇒ THE NEGATIVE CONTROL CANNOT BE RUN UNTIL THAT IS FIXED, and without it the eviction is unproven
// in the only direction that matters. If no arm can PASS, no arm can FALSELY pass — so the teeth
// control (the same arm under a root-only eviction, which must falsely pass) came back INSUFFICIENT
// too, and agreement between the two eviction modes is evidence of nothing. A green positive control
// alone would be exactly the shape this project treats as inadmissible: an eviction that is too
// narrow passes every positive control there is.
//
// `--observe-only` was always outside the guard's scope and still needs no special handling: it
// walks no ladder and produces no verify arm, so its output is explicitly a hypothesis
// (`OBSERVE-ONLY`, which `collate.mjs` keeps out of the catalog).
const OBSERVE_ONLY = argv.includes('--observe-only');

/// Every nub arm's project `.npmrc`. ONE definition because there is ONE file: a second
/// `writeFileSync` to the same path TRUNCATES the first, which is exactly how the epoch-29
/// attempt at this became a silent no-op.
const ARM_NPMRC = 'side-effects-cache=false\ntrust-policy=off\nminimum-release-age=0\nblockExoticSubdeps=false\n';

// DIRECT mode, the POSIX driver's `--at-grant`: one arm at the caller's grant, no synthesis and no
// ladder. Its verdict vocabulary is deliberately NOT the ladder's — SUFFICIENT/INSUFFICIENT answers
// "does this ONE grant suffice", where MINIMUM answers "what is the least that does", and reporting
// a wider-than-expected MINIMUM as an under-grant is exactly the conflation the split prevents.
const AT_GRANT = flag('--at-grant', '');
if (AT_GRANT && !/^\{[\s\S]*\}$/.test(AT_GRANT.trim())) {
  console.error(`⛔ --at-grant needs a JSON object, got: ${AT_GRANT}`); process.exit(2);
}

const NUB = flag('--nub', 'C:\\nub-ci.exe');
// `import.meta.dirname` rather than the hand-rolled `pathname.replace(/^\/([A-Za-z]:)/, ...)`
// this used to carry: that strips the leading slash Windows adds but not the URL
// percent-encoding, so a checkout under a path containing a space still resolved to `%20`.
const HERE = import.meta.dirname;
const HOME = process.env.USERPROFILE;

// ⛔ NOT UNDER %TEMP%. That path is inside the jail's own private-temp redirect, so a fixture
// placed there cannot test a filesystem-denial claim at all.
const BASE = flag('--root', 'C:\\jail');

// A verify arm that never returns is a real, MEASURED outcome here, not a hypothetical: a jailed
// `nub install` was seen burning a core for 13+ minutes with no output. Bare spawnSync has no
// deadline, so one such arm blocks the whole driver forever and the lane produces nothing at all.
// TIMED-OUT is recorded as its own verdict -- it is NOT a failure, and must never be read as one:
// a failure says the grant was insufficient, a timeout says nothing about the grant.
//
// ⛔⛔ 600_000 WAS TOO LOW AND COST 8.9% OF WIN32 COVERAGE. Raised to 1_800_000 on 2026-08-16.
//
// The deadline's job is to cut a HUNG arm, but 600 s sat BELOW the 13-minute (780 s) hang that
// motivated it, so it could not tell a hung arm from a merely slow one -- and on Windows a great
// many arms are merely slow. MEASURED over the 25% win32 run: 40 of 448 records came back
// HARNESS-TIMEOUT, against 1 of 2,569 on Linux. Their durations cluster in a 637-819 s band, which
// is the tell -- unrelated packages do not fail inside a 180 s window by chance, they fail because
// ONE arm hit a fixed 600 s ceiling and the driver gave up. A per-package cause would spread out.
//
// PROVEN RECOVERABLE, not assumed: `redis-memory-server@0.17.1` times out at 600 s and returns
// `rc=0 artifacts=42/42` at 1800 s. And a timeout yields NO measurement (see above), so every one
// of the 40 is a package the catalog must fall back to a base profile for.
//
// SAFE because this is not the only bound: `run-batch-v2.mjs` caps the whole driver at a 2400 s
// per-package budget (`BUDGET_MS`), so a genuinely infinite arm is still killed -- rc 124, the
// convention `record.mjs` already reads. 1800 s < 2400 s, so ONE slow arm now fits inside the
// package budget where it previously could not. The flag stays so a lane can lower it.
const ARM_TIMEOUT_MS = Number(flag('--arm-timeout', '1800000'));
const ROOT = path.join(BASE, `m-${PKG.replace(/[^a-z0-9]/gi, '')}-${Date.now().toString(36)}`);
fs.mkdirSync(ROOT, { recursive: true });

// ⛔⛔ EACH ARM GETS ITS OWN VIRTUAL STORE; THE CAS STAYS SHARED. This replaced the per-arm
// `evictClosure()` sweep, and the reason is a defect that sweep produced rather than a tidy-up.
//
// MEASURED: a `falsify.mjs` POSITIVE arm — the KNOWN-SUFFICIENT grant — came back INSUFFICIENT, so
// the control declared every result unattributable and refused to start the batch. The install
// itself succeeded (`rover.exe has been installed!`); `approve-builds` then died `MODULE_NOT_FOUND`
// requiring `…\pm\store\tar@6.2.1-<hash>\node_modules\tar\lib\mkdir.js`. The sweep had removed a
// DEPENDENCY's store entry while a DEPENDENT's entry survived and still linked to it, leaving a
// partially-evicted store graph.
//
// ⛔ AND THE `keep` SPARING CANNOT BE PATCHED INTO CORRECTNESS. It already covered node-gyp's
// tooling closure — the `Cannot find module 'semver'` case — and did NOT cover
// `binary-install` → `tar`. That is not one missing entry; it is an exception list that needs a new
// entry per gap, and every gap presents as an unattributable control at best and a wrong verdict at
// worst. A fresh virtual store cannot be partially evicted, so the failure class is gone by
// CONSTRUCTION rather than by a graph traversal that has to be got right.
//
// ⛔ THE COST WAS MEASURED, NOT ASSUMED, because the premise for choosing this over a
// reverse-dependency walk is that the CAS is the expensive part and the virtual store is only
// links. `@apollo/rover@0.2.1`, three reps each, same box, CAS warmed first so neither condition
// pays the download:
//
//   shared virtual store + eviction (before)   median 25.7 s/arm
//   fresh virtual store per arm (now)          median 35.7 s/arm     1.39x, +10 s
//   the same arm with a COLD CAS, for scale            82.3 s/arm     3.2x the isolated arm
//
// So an isolated arm pays linking and not fetching, which is the claim. +39% per arm buys the
// removal of an entire failure class.
//
// `XDG_CACHE_HOME` is the lever, and the split it produces is MEASURED: it relocates
// `<cache>/nub/pm` — the virtual store, `tools/`, the side-effects memo — while the
// content-addressed store stays at `%LOCALAPPDATA%\nub\store\v1\files`, shared and warm. Exactly
// isolate-the-links, share-the-bytes. It also keeps the GLOBAL virtual-store LAYOUT a real user
// gets, where `enable_global_virtual_store=false` would have silently switched every arm to the
// project-local layout and changed what was being measured.
//
// ⛔ `--cache-home` EXISTS FOR THE ONE ARM WHOSE SUBJECT IS SHARING. `falsify.mjs`'s `wrong-warm`
// asks whether state left by a PREVIOUS arm satisfies an operation the current grant forbids, so it
// must reuse the prior arm's store rather than get a fresh one — isolating it would delete the very
// thing it tests. That arm is safe from the defect above for a different reason: it inherits a
// WHOLE store, never a partially-evicted one.
const CACHE_HOME = flag('--cache-home', '');
// ⛔ PER-ARM ISOLATION COSTS DISK, WHICH THE WALL-CLOCK COST MEASUREMENT DID NOT COVER. Each arm now
// materialises its own virtual store, and they accumulate: MEASURED on the corpus VM, free space went
// 62 GB -> 38 GB over one session of driver work. A sweep that discovers this at package 60 has
// already lost the run, so the arm cache is swept as the arm finishes rather than at the end.
// `--keep-arm-cache` retains them for forensics on a specific package. The SHARED cache passed via
// `--cache-home` is never swept here — it lives outside the arm directory and its owner
// (`falsify.mjs`'s wrong-warm pair) decides its lifetime.
const KEEP_ARM_CACHE = argv.includes('--keep-arm-cache');

// ⛔ A STRAY nub.jsonc ABOVE THE FIXTURE poisons every run under it -- nub walks UP from the cwd,
// so a file three directories up silently supplies an `install.buildJail` the driver never chose.
for (let d = ROOT; ; d = path.dirname(d)) {
  for (const f of ['nub.jsonc', 'nub.json']) {
    if (fs.existsSync(path.join(d, f))) { console.error(`FATAL stray ${f} at ${d} -- it would poison every run`); process.exit(1); }
  }
  if (path.dirname(d) === d) break;
}

// ⛔ npm/npx/pnpm are .cmd shims: spawnSync gives ENOENT on the bare name and EINVAL on the .cmd
// spelling (Node has refused to CreateProcess a batch file since CVE-2024-27980), and `shell:true`
// concatenates rather than escapes, so cmd.exe re-parses a spec like `@scope/pkg@1.0.0`. Run the
// bundled JS directly.
const NODE = process.execPath;
const NPM = path.join(path.dirname(NODE), 'node_modules', 'npm', 'bin', 'npm-cli.js');
if (!fs.existsSync(NPM)) { console.error(`FATAL npm-cli.js not found at ${NPM}`); process.exit(1); }

const run = (exe, args, opts = {}) =>
  spawnSync(exe, args, { encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, ...opts });

const SECURITY_CACHE = path.join(ROOT, 'security', 'clearances');
const securityScreen = (kind, inputArgs) => {
  const out = path.join(ROOT, 'security', `${kind}.json`);
  const r = run(NODE, [path.join(HERE, '..', 'osv-screen.mjs'), ...inputArgs,
    '--kind', kind, '--cache-dir', SECURITY_CACHE, '--out', out]);
  const output = `${r.stdout ?? ''}${r.stderr ?? ''}`.trimEnd();
  if (output) console.log(output);
  if (r.status === 0) return;
  if (r.status === 42) process.exit(0); // terminal REFUSED-MALICIOUS marker is in the output above
  console.log(`  => HARNESS-ERROR: fail-closed OSV ${kind} screen did not complete (rc=${r.status}); no lifecycle script ran`);
  process.exit(1);
};

// A spawnSync deadline surfaces as `error.code === 'ETIMEDOUT'`, but a killed child also reports
// status null with a signal, so both spellings are treated as the deadline firing. Distinguishing a
// timeout from a non-zero exit is what keeps a hung arm out of the "grant insufficient" bucket.
const timedOut = (r) => r.error?.code === 'ETIMEDOUT' || (r.status === null && r.signal != null);

// ⛔ DOES NUB INSTALL THIS PACKAGE WITH THE JAIL ENTIRELY OFF? WINDOWS COULD NOT ASK.
//
// The control at the top of this driver keys on OBSERVE's rc, and OBSERVE runs `npm rebuild` — while
// every verify arm runs `nub install` + `nub approve-builds`. So a package npm installs fine but nub
// cannot install even unjailed climbs the whole ladder, fails every rung, and is recorded
// `NO-STATE-PASSED`: a verdict that reads as "the jail refused this" about a defect the jail had no
// part in. `measure.sh` grew this arm on 2026-08-07 and `measure-macos.sh` received it in this same
// series; Windows was the last driver without it, which is why a Windows failure was the one failure
// this corpus could not attribute.
//
// THAT MATTERED MORE HERE THAN ON EITHER POSIX PLATFORM: 45 of the 62 `write:"disk"` grants in the
// catalog are justified by a win32 record ALONE, so the widest capability the jail hands out rested
// on the one platform that could not tell "the jail blocked it" from "nub cannot install it here".
let nspSeq = 0;
const unjailedNubOk = () => {
  const d = path.join(ROOT, `nsp-${nspSeq++}`);
  fs.mkdirSync(d, { recursive: true });
  // A UNIQUE ROOT PACKAGE NAME, for the same reason every verify arm uses one: nub memoises a
  // lifecycle outcome keyed on package identity, so a reused name REPLAYS an earlier result with
  // every precondition green — indistinguishable from a real pass by exit code alone.
  fs.writeFileSync(
    path.join(d, 'package.json'),
    `${JSON.stringify({ name: `nsp${nspSeq}${Date.now().toString(36)}`, version: '1.0.0', dependencies: { [PKG]: VER } })}\n`,
  );
  fs.writeFileSync(path.join(d, 'nub.jsonc'), `${JSON.stringify({ install: { buildJail: false } })}\n`);
  // The memo off at SOURCE, not merely swept afterwards — the same single point of failure the
  // verify arms in this driver already close.
  fs.writeFileSync(path.join(d, '.npmrc'), ARM_NPMRC);
  // Resolve WITHOUT running anything, screen the tree while it is still inert, and only then install:
  // a known-malicious dependency is refused before a single lifecycle script executes.
  //
  // ⛔ THE OUTCOME IS AN OBJECT, NOT A BOOLEAN, BECAUSE `false` CANNOT CARRY WHY. Three things this arm
  // can report are not the same, and a boolean collapses them all into the one that reads as a package
  // fact: it failed, it never finished, and it RAN WITH THE JAIL STILL ON. The last is the dangerous
  // one — a control whose off-switch silently stopped working produces unanimous agreement rather than
  // an error, which reads as a confident exoneration of the jail, and v1 shipped exactly that for
  // months. `engaged` is three-state on purpose: `null` means UNKNOWABLE, never disproven.
  // ⛔ `logs` ESCAPES ON THE OBJECT, because a caller that is about to accuse nub needs to be able
  // to say WHY. It was local here and died with the call, so this driver's accusation branch printed
  // nothing at all about the control -- the other half of epoch 15, which landed that fix only in
  // `unjailed-nub.mjs`. Mutated in place below; the reference sees every update.
  const logs = {};
  const out = { ok: false, engaged: null, timedOut: false, logs };
  // ⛔ THE CONTROL MUST HOLD THE SAME TOOLCHAIN AS THE ARM IT IS COMPARED AGAINST, OR IT MANUFACTURES
  // A NUB DEFECT. This arm decides BROKEN-UNJAILED-NUB ("npm installs it, nub cannot") versus
  // BROKEN-WITHOUT-JAIL-TOO ("nothing installs it"), and it decides it by comparison with npm_ok.
  // Every other arm in this driver — the OBSERVE/npm reference and every verify rung — already runs
  // on `PATH: ARM_PATH` with the era `PYTHON`; this one alone passed no env at all, so its lifecycle
  // scripts ran node/node-gyp from the RUNNER's Node and an ambient Python while npm ran the
  // package's era toolchain. When that difference alone makes nub fail, the record accuses nub of an
  // install defect the harness created.
  //
  // This is epochs 13 and 15 reaching win32 at last. Both fixes were scoped to the POSIX drivers and
  // both said so: epoch 15's reason records "WIN32 IS NOT FIXED ... measure-windows.mjs runs its
  // control in-process ... and never calls this module", because this driver has its own
  // `unjailedNubOk` rather than `unjailed-nub.mjs`'s. Stated rather than hidden then; closed now.
  //
  // It matters more here than on either POSIX platform, for the reason this arm's own header gives:
  // 45 of the 62 `write:"disk"` grants in the catalog rest on a win32 record ALONE, so the widest
  // capability the jail hands out was justified by the platform least able to attribute a failure.
  //
  // PATH and PYTHON only, mirroring `unjailed-nub.mjs`'s post-epoch-15 child env exactly. The verify
  // rungs additionally set NUB_BUILD_JAIL_CATALOG and a per-arm XDG_CACHE_HOME; neither belongs here
  // (this arm runs with the jail OFF and has no catalog), and widening beyond the measured reference
  // would change more than the asymmetry being closed.
  const ARM_ENV = { ...process.env, PATH: ARM_PATH, ...(ERA_PYTHON ? { PYTHON: ERA_PYTHON } : {}) };
  const resolve = run(NUB, ['install', '--ignore-scripts'], { cwd: d, env: ARM_ENV, timeout: ARM_TIMEOUT_MS });
  if (timedOut(resolve)) { out.timedOut = true; return out; }
  // No lifecycle script has spawned yet, so nothing could have printed the claim — `engaged` stays
  // `null` rather than `false`, or a fetch failure would be filed as a broken off-switch.
  // Captured even on the failing path: a resolve failure is exactly a case where the record would
  // otherwise carry no explanation of what the control did.
  logs['security-resolve.log'] = `${resolve.stdout ?? ''}${resolve.stderr ?? ''}`;
  if (resolve.status !== 0) return out;
  securityScreen('nub-unjailed-resolved', ['--tree', d]);

  for (const [key, args] of [['i', ['install']], ['a', ['approve-builds', '--all']]]) {
    const r = run(NUB, args, { cwd: d, env: ARM_ENV, timeout: ARM_TIMEOUT_MS });
    logs[key] = `${r.stdout ?? ''}${r.stderr ?? ''}`;
    if (timedOut(r)) { out.timedOut = true; return out; }
    if (r.status !== 0) {
      // `approve-builds` is the step that actually RUNS the scripts under nub — a plain install ignores
      // them pending approval — so it is the first step whose silence about the claim means anything.
      if (key === 'a') out.engaged = offSwitchEngaged(logs);
      return out;
    }
  }
  out.engaged = offSwitchEngaged(logs);
  out.ok = true;
  return out;
};

// ⛔ "NUB CANNOT INSTALL IT" IS NOT YET "NUB IS AT FAULT" — ASK npm BEFORE NAMING A CULPRIT. On Linux
// this caught `@aws-amplify/cli@2.0.0`: the arm came back nub-broken, but plain `npm install` fails
// too (gyp rejects Python 3.12), so a verdict naming nub would be true and still misleading. The
// top-of-file control cannot answer it either — that one keys on OBSERVE, and OBSERVE runs `npm
// rebuild` against an already-materialized tree, which succeeds where a fresh `npm install` fails.
// ⛔⛔ THE REFERENCE ARM MUST MATCH THE ARM IT IS A REFERENCE FOR. It answers "does npm install this
// where nub did not", so `ok` means the nub failure is a NUB DEFECT and a failure here means nothing
// installs the package. The error is one-directional and invisible: a spurious npm failure
// EXONERATES nub, filing a candidate nub defect as a dead package that nobody re-reads.
//
// It ran UNDATED and with the ambient environment while the observe arm above ran `eraResolution`
// under `obsEnv`. Undated resolution pulls TODAY's dependency versions into a tree pinned to
// nothing, which is exactly what dated resolution was added to stop. Reusing `eraResolution.args`
// verbatim is the point — one resolution, so the two arms cannot drift.
// ⛔ `dated: false` DROPS THE `--before`, which is the only variable the nub arm cannot match — the
// full argument is at the `npmUndated` clause in `unjailed-nub.mjs`. nub has no `--before`, so the
// nub arm always resolves TODAY's dependency tree onto an ERA Node; asking npm to do the same is the
// only way to tell a nub defect from that asymmetry.
const npmOk = ({ dated = true } = {}) => {
  const d = path.join(ROOT, `nsp-npm-${nspSeq++}`);
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), `${JSON.stringify({ name: 'nspnpm', version: '1.0.0' })}\n`);
  const args = dated ? eraResolution.args : eraResolution.args.filter((a) => !String(a).startsWith('--before'));
  const fetched = run(NODE, [NPM, ...args], { cwd: d, env: obsEnv });
  if (fetched.status !== 0) {
    // The log survives: the arm that decides nub is innocent must leave evidence in the record.
    console.log(`  NPM-REFERENCE fetch FAILED rc=${fetched.status} for ${PKG}@${VER}`);
    console.log(String((fetched.stdout ?? '') + (fetched.stderr ?? '')).split('\n').slice(-20)
      .map((l) => `    | ${l}`).join('\n'));
    return false;
  }
  securityScreen('npm-fallback-resolved', ['--tree', d]);
  // Rebuild the WHOLE cleared tree: an ordinary npm install runs dependency lifecycle scripts as
  // well as the target's, so targeting only PKG would change the reference arm.
  const rebuilt = run(NODE, [NPM, 'rebuild', '--no-audit', '--no-fund'], { cwd: d, env: obsEnv });
  if (rebuilt.status !== 0) {
    console.log(`  NPM-REFERENCE rebuild rc=${rebuilt.status} for ${PKG}@${VER}`);
    console.log(String((rebuilt.stdout ?? '') + (rebuilt.stderr ?? '')).split('\n').slice(-20)
      .map((l) => `    | ${l}`).join('\n'));
  }
  return rebuilt.status === 0;
};

const countFiles = (dir, skip = () => false) => {
  let n = 0;
  const walk = (d) => {
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = path.join(d, e.name);
      if (skip(p)) continue;
      // withFileTypes reports a junction as neither file nor directory; nub's isolated layout is
      // built from them, so counting only isFile() under-reports the artifact set on Windows.
      if (e.isDirectory()) walk(p); else n++;
    }
  };
  walk(dir);
  return n;
};

// ⛔ A WHOLE-TREE FILE COUNT IS NOT COMPARABLE ACROSS THE TWO LAYOUTS, AND GATING ON ONE FAILED
// EVERY WINDOWS PACKAGE. MEASURED 2026-08-06 on iedriver@4.0.0, a run whose lifecycle script
// demonstrably succeeded (both IEDriverServer downloads + extractions + `Success!` in its stdout):
//
//   observe/       countFiles=887   887 real files, 22.1 MB   -- npm's flat tree, all content local
//   verify-synth/  countFiles=203    31 real files + 172 JUNCTIONS, 17.2 MB
//
// nub's isolated layout puts every dependency at `node_modules/.store/<pkg>@<ver>` as a JUNCTION
// into the machine-global content store (`%LOCALAPPDATA%\nub\pm\store\<pkg>@<ver>-<hash>`), so the
// dependency bytes are not inside the fixture at all and `countFiles` scores each dependency as 1.
// `files >= OBS_FILES` therefore cannot be satisfied by ANY successful install of a package with
// more than a handful of transitive deps -- it fails on layout, never on the grant. The package
// then walks the whole ladder and is recorded at a wider grant than it needs, up to `write:"disk"`.
//
// ⛔ AND THE OBVIOUS FIX -- follow junctions when counting the whole tree -- IS ALSO WRONG. It makes
// the number depend on the machine-global store's contents, which is shared, evicted per arm, and
// not part of the fixture, so it is neither reproducible nor attributable to this install.
//
// The gate below compares the ONE universe both layouts genuinely share: the MEASURED package's own
// directory, resolved through the junction and enumerated with links followed. That is also exactly
// the universe the grant is a claim about -- OBSERVE traces `npm rebuild <PKG>` and nothing else.
// MEASURED on the same iedriver run: observe 15 files / 17,184,827 B vs verify 16 files /
// 17,184,988 B (the extra file is nub's own `.nub-side-effects-cache`), and every lifecycle
// artifact -- lib/iedriver{,64}/IEDriverServer.exe, both zips, the tmp/ extractions -- is present
// in both. TRADE: transitive dependencies' artifacts are no longer file-checked, only `rc`. That is
// accepted deliberately: the synthesized grant is derived from PKG's trace alone, so PKG's artifact
// set is the thing the verdict is actually about, and the previous whole-tree count checked the
// transitive set in name only -- it could never pass.
const pkgDir = (base, pkg, ver) => {
  for (const c of [
    path.join(base, 'node_modules', pkg),
    path.join(base, 'node_modules', '.store', `${pkg}@${ver}`, 'node_modules', pkg),
    path.join(base, 'node_modules', '.store', `${pkg}@${ver}`),
  ]) if (fs.existsSync(c)) return c;
  return null;
};

// ⛔ AND A COUNT ALONE IS TOO LOOSE -- gate on the per-file MANIFEST. MEASURED on the arms already
// on disk: dprint@0.14.1 produced 10 artifact files under both npm and the jail, so a count gate
// PASSES it, while the verify tree held 6,306 B against npm's 11,071,650 B -- the install script's
// `dprint.exe` download had been blocked and only the placeholder tree remained. Comparing the
// manifest catches that by NAME with no threshold to tune, and a byte-total gate would have needed
// one (the succeeding iedriver arms clear their reference total by as little as 1 byte).
//
// The gate: every file the unjailed OBSERVE arm produced must exist in the arm at >= its size.
// Extra files are ignored -- nub's layout legitimately adds `.nub-side-effects-cache`.
//
// Follows junctions/symlinks (statSync, not lstat) and de-dupes by realpath so a self-referential
// link cannot spin. Returns null when the package is absent -- an absent package is a FAILED arm,
// never a passing one.
const pkgManifest = (base, pkg, ver) => {
  const root = pkgDir(base, pkg, ver);
  if (!root) return null;
  const seen = new Set();
  const m = new Map();
  const walk = (d) => {
    let rp; try { rp = fs.realpathSync(d); } catch { return; }
    if (seen.has(rp)) return; seen.add(rp);
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = path.join(d, e.name);
      if (isLog(p)) continue;
      // ⛔ A NESTED `node_modules` IS SOMEONE ELSE'S ARTIFACTS AND MUST NOT ENTER THIS MANIFEST.
      // npm parks a dependency it cannot hoist INSIDE the package directory, while nub's isolated
      // layout puts it behind a `.store` junction instead. Walking into it therefore loads the
      // OBSERVE manifest with thousands of files that are legitimately absent from the nub arm, and
      // every one is then reported missing -- a false FAILURE, in the direction that manufactures a
      // wider grant. MEASURED on the Linux lane: an arm read `artifacts=26/13206 missing=13181`,
      // where 13,181 of the 13,206 were a nested `node_modules` and exactly 25 were the package.
      // Skipping it is also what the gate already claims to do -- the comment above states that
      // transitive dependencies are checked by `rc` alone, not file-by-file.
      if (e.name === 'node_modules') continue;
      let st; try { st = fs.statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p); else m.set(path.relative(root, p).replace(/\\/g, '/'), st.size);
    }
  };
  walk(root);
  // ⛔ THE WALK ONLY DESCENDS, AND SOME OF THE BUILD'S OUTPUT IS ABOVE THE ROOT. See
  // `gyp-subtarget-spill.mjs`: gyp resolves an included `.gyp` file through symlinks, so the
  // sub-target makefiles land inside the package under a hoisted tree and two levels above it under
  // an isolated store. Adds keys, never removes one.
  for (const [k, v] of gypSubtargetSpill(root, pkg)) if (!m.has(k)) m.set(k, v);
  m.root = root;
  return m;
};

// Returns the artifacts OBSERVE produced that this arm did not. Empty => the arm reproduced the
// unjailed result. Naming them is what makes a failing arm self-debugging: the corpus log says
// `lib/iedriver64/IEDriverServer.exe` rather than a bare number.
const missingArtifacts = (obs, got) => {
  if (!got) return ['<package absent>'];
  // ⛔ THE OTHER HALF OF THE SUB-TARGET SPILL, AND IT LIVES HERE RATHER THAN IN `pkgManifest`
  // BECAUSE IT NEEDS BOTH TREES. `gypSubtargetSpill` walks the arm alone and finds the sub-targets
  // that escaped the package; the ones that merely MOVED inside `build/` cannot be keyed from the
  // arm at all, because the path components gyp ate survive only in the reference key. See
  // `gyp-subtarget-spill.mjs` for the measurement. `artifact-gate.mjs` does the same thing at the
  // same point, and the two must not drift.
  for (const [k, v] of gypSubtargetRelocations(obs, got, PKG)) if (!got.has(k)) got.set(k, v);
  const out = [];
  for (const [f, size] of obs) {
    // ⛔ ABSENCE IS CHECKED FIRST AND FOR EVERY FILE, TOOLCHAIN-GENERATED INCLUDED. A generator
    // difference can change a file's CONTENTS; it can never fail to write the file at all. Only the
    // "shorter but NON-EMPTY" comparison is excusable, and `artifact-excusal.mjs` owns that decision
    // for this driver and `artifact-gate.mjs` alike -- see the note at the head of this file for the
    // drift that cost the corpus its only `write:"disk"` grant.
    if (!got.has(f)) { out.push(f); continue; }
    const armSize = got.get(f);
    if (excusesSizeDifference(f, armSize)) continue;
    if (armSize < size) out.push(`${f} (${armSize}B < ${size}B)`);
  }
  return out;
};

console.log(`### ${PKG}@${VER}   (${ROOT})`);

// ── THE CI-DETECTION SCRUB ────────────────────────────────────────────────────────────────────
//
// ⛔ A PACKAGE THAT BRANCHES ON `CI` RUNS LESS CODE ON A RUNNER, SO A CI-MEASURED RECORD OMITS
// CAPABILITIES A DEVELOPER HITS — an under-grant, the one direction this project forbids. The v1
// harness has scrubbed this family since its own sweeps; v2 did not.
//
// MEASURED: `core-js@3.50.0` writes `$TMPDIR/core-js-banners` with `CI` unset and writes NOTHING
// with `CI=1`. SCRUBBED rather than forced to a value, because the value semantics are inconsistent
// — `ci-info` reads `CI=0` as CI-ON while `core-js` reads it as CI-OFF, so only ABSENCE means "not
// CI" to everyone.
//
// ⛔ KEPT IDENTICAL TO `ci-env-scrub.sh`, WHICH THE POSIX DRIVERS SOURCE. `ci-env-scrub.test.mjs`
// asserts the two lists agree; a family that drifts apart per-driver is the defect class this
// duplication would otherwise create. Windows cannot source a shell file, so the list is mirrored
// and the test is what keeps the mirror honest.
//
// ⛔ THE AXIS STAYS MEASURABLE: `NUB_CORPUS_CI_ENV=inherit` disables the scrub and measures the real
// CI path. The two states UNION rather than one replacing the other.
const CI_KEYS = ['CI', 'CONTINUOUS_INTEGRATION', 'BUILD_NUMBER', 'RUN_ID', 'GITHUB_ACTIONS',
  'GITLAB_CI', 'CIRCLECI', 'TRAVIS', 'JENKINS_URL', 'TEAMCITY_VERSION', 'BUILDKITE', 'DRONE',
  'APPVEYOR', 'CODEBUILD_BUILD_ID', 'TF_BUILD'];
// Captured BEFORE the scrub: `passedThrough` must report what the VENUE had, or a real CI run files
// `CI: null` and claims it was not CI precisely because we removed the proof.
const CI_INHERITED = Object.fromEntries(
  CI_KEYS.filter((k) => process.env[k] != null).map((k) => [k, process.env[k]]));
const CI_SCRUBBED = [];
if ((process.env.NUB_CORPUS_CI_ENV ?? 'unset') === 'inherit') {
  console.log('  CI-ENV inherit -- the CI-detection family is NOT scrubbed (measuring the real CI path)');
} else {
  for (const k of CI_KEYS) if (process.env[k] != null) { delete process.env[k]; CI_SCRUBBED.push(k); }
  if (CI_SCRUBBED.length) console.log(`  CI-ENV scrubbed: ${CI_SCRUBBED.join(' ')}`);
}

// ── 1. OBSERVE ────────────────────────────────────────────────────────────────────────────────
// Query the direct target before fetching it. The resolved-tree screen below remains mandatory:
// a clean target can resolve a compromised transitive package.
securityScreen('direct', ['--spec', `${PKG}@${VER}`]);
// ⛔ THE FETCH IS NOT TRACED, AND THAT IS THE POINT. Tracing `npm install` traces NPM: its registry
// TLS and its cache writes under the user profile land in the same event stream as the lifecycle
// script's, so every package synthesizes network + write:userHome no matter what its script does.
// Fetch with --ignore-scripts outside the trace, then trace `npm rebuild`, which runs the
// lifecycle scripts and nothing else. (The subtree filter in classify.mjs is the second, finer
// defence; both are needed -- rebuild still opens the registry for its own bookkeeping.)
const OBS = path.join(ROOT, 'observe');
fs.mkdirSync(OBS, { recursive: true });
fs.writeFileSync(path.join(OBS, 'package.json'), JSON.stringify({ name: 'o', version: '1.0.0' }) + '\n');

// ⛔ THE OBSERVE ARM MUST NOT SHARE THE HOST'S npm CACHE, OR IT UNDER-PREDICTS `network` SILENTLY.
// A lifecycle script that fetches its payload finds it already present when npm's cache is warm, so
// the trace records NO connect events and the synthesized grant omits `network` -- correct for that
// run, and wrong for the cold machine a real user installs on. An under-prediction breaks installs,
// which is the direction that matters.
//
// MEASURED on purescript@0.15.9: `purs.bin` was WRITTEN at 60,475,904 B during OBSERVE while the
// whole trace held 15 Kernel-Network records (5 send / 7 recv) and ZERO connect events with the
// subtree filter removed, npm's `cacache` get/read modules loaded, and
// `%LOCALAPPDATA%\npm-cache\_cacache` populated. The synthesized grant was `{"write":{"deps":true}}`
// -- no network -- and every jailed arm then failed to produce that file.
//
// The verify arms already evict the nub store per arm for exactly this reason; OBSERVE had no
// equivalent. A per-run cache directory gives the arm the same cold start a user gets, and is
// passed to the traced rebuild as well as the fetch since the lifecycle script runs under rebuild.
const NPM_CACHE = path.join(ROOT, 'npm-cache');

// ⛔ THE PRIVATE TEMP, WHICH REPRODUCES WHAT THE JAIL DOES TO A CONFINED SCRIPT — not a convenience,
// and not an attempt to make two venues agree. GROUNDED IN NUB: the build-jail preset sets
// `fs["$tmp"] = "rw"` unconditionally (`compiler/preset.rs`), which is `TmpMode::Private`, so
// `backend/mod.rs::make_private_tmp` creates a fresh per-run directory and `set_tmp_env` points
// `TMPDIR`/`TMP`/`TEMP` at it while the shared host temp stays hidden. Linux and macOS reproduce
// both halves; this driver reproduced neither.
//
// ⛔ WHAT THAT COST, AND THE DIRECTION. On Windows `%TEMP%` is `%USERPROFILE%\AppData\Local\Temp` —
// INSIDE the home — so a script's temp write classified as `userHome` and billed `write.userHome`
// for a directory the jail hands it for free. An over-grant, the safe direction, but it silently
// widened every Windows package that touches temp.
//
// ⛔ AND IT ONLY WORKS WITH THE CLASSIFIER HALF. Redirecting alone moves those writes out of
// `userHome` and into `outside`, which is REPORTED and never granted — an under-grant, the forbidden
// direction. `classify.mjs` keys a `jailTmp` bucket on the `temp` root declared in `capture.json`
// and excludes it from the grant, so the two land together or not at all. All three variables are
// set because the jail sets all three: Windows tools read `TMP`/`TEMP`, cross-platform ones read
// `TMPDIR`, and a script that reads the one we skipped would land somewhere neither of us declared.
// ⛔ AND IT GIVES OBSERVE A COLD TEMP, WHICH IS A REAL CHANGE TO THE ENVIRONMENT UNDER TEST AND IS
// RECORDED RATHER THAN ASSUMED HARMLESS (VENUE-PORTABILITY R6, and the same treatment the spec
// demands for a throwaway `$HOME`). MEASURED on iedriver@4.0.0, same package, same box, same
// declared-root method on both archives:
//
//   before the redirect   0 writes under the real %TEMP%   (the script found its payload already
//                                                           staged from an earlier run on this box)
//   after                10 writes under the private temp  (it re-downloaded and re-extracted)
//
// So the private temp removes temp cache warmth a long-lived machine accumulates, and the script
// takes its download path instead of its cached path. That direction is SAFE — it over-predicts,
// and it is the path a real user on a clean machine takes — and it matches what the jail does, which
// hands every run a fresh directory. The grant was unchanged either way
// (`{"write":{"deps":true},"network":true}`), because those writes bill nothing.
//
// ⛔ IT ALSO MOVED THE 8.3 AXIS OUT OF THIS ARM. With temp under the run root, a GitHub runner's
// `C:\Users\RUNNER~1\AppData\Local\Temp` no longer appears in the stream at all — measured, the
// recorded short-name map is empty on both runner cells. The 8.3 machinery is still correct and
// still unit-tested; it is simply no longer exercised end-to-end by a package that only touches
// temp and its own package directory.
const OBS_TMP = path.join(ROOT, 'tmp');
fs.mkdirSync(OBS_TMP, { recursive: true });

// ⛔ THE PRIVATE HOME, WHICH IS WHAT MAKES `writePaths` DERIVABLE ON THIS PLATFORM AT ALL. Same
// construction as the private temp above and for the same reason: the jail gives a confined script a
// per-package private home (`compiler/preset.rs::private_home_dir`, exported as `jail_private_home`
// and RW-granted by the base profile) and repoints the home variables at it, so OBSERVE has to
// reproduce that or it traces an environment no confined script ever sees.
//
// ⛔ WHAT ITS ABSENCE COST, AND IT WAS NOT ONLY THE TOLERABLE DIRECTION. Without the redirect every
// home write bucketed `userHome`, which over-grants (safe) — but it also made the PROMOTABLE bucket
// unreachable, so this lane derived NO `writePaths` at all: 0 of 2,270 win32 records against 284 on
// POSIX. Deriving one from the `userHome` bucket instead is an UNDER-GRANT and `write-paths.mjs::
// refuseUserHome` refuses it by name — the two buckets have opposite answers, so the only honest fix
// is to produce the split by measurement, which is what this does.
//
// ⛔ `APPDATA` GOES TO `AppData\Roaming` UNDER THE PRIVATE HOME, NOT TO THE HOME ROOT. That is what
// `preset.rs` does (`home.join("AppData").join("Roaming")`, materialized there for the same reason it
// is materialized here — a redirect onto a path that does not exist trades one failure for another),
// and it has to move at all because npm on Windows resolves its cache to `%APPDATA%\npm-cache` rather
// than to `$HOME/.npm`. It sits INSIDE the private home, so the single `jailHome` root covers both.
//
// ⛔ `LOCALAPPDATA` IS DELIBERATELY NOT REDIRECTED, matching `preset.rs`: the Windows LowBox launch
// resolves its AppContainer profile directory from it, so repointing it breaks process creation
// rather than a cache path. It is also what this driver reads to locate nub's own cache below, and
// that read is the DRIVER's, never the child's.
const OBS_HOME = path.join(ROOT, 'jailhome');
const OBS_APPDATA = path.join(OBS_HOME, 'AppData', 'Roaming');
fs.mkdirSync(OBS_APPDATA, { recursive: true });

// ⛔ PRESENCE-GATED, AND MATCHED ON THE SPELLING THE AMBIENT ACTUALLY CARRIES. `preset.rs` only
// REPLACES a home variable the environment already had — it never introduces one — and it compares
// case-insensitively on Windows because the ambient may spell it `Userprofile`. Both properties are
// reproduced here: introducing a variable the jailed child would not have is a SECOND divergence
// where the contract allows exactly one (enforcement), and spreading `HOME:` onto an object that
// already carries `Home:` would hand the child BOTH.
const OBS_HOME_ENV = Object.fromEntries(
  Object.entries({ HOME: OBS_HOME, USERPROFILE: OBS_HOME, APPDATA: OBS_APPDATA })
    .map(([name, value]) => [Object.keys(process.env)
      .find((k) => k.toLowerCase() === name.toLowerCase()), value])
    .filter(([key]) => key),
);

// ⛔⛔ ONE DEFINITION, FOUR CONSUMERS, AND THAT IS THE POINT RATHER THAN TIDINESS. The apparatus and
// parity rewrites this driver applies to the OBSERVE side reach the measured install through FOUR
// separate vectors — the untraced fetch and the npm reference arm (`obsEnv`), the two scaffold
// installs, and the `rebuild.cmd` wrapper that is the only thing in scope for the TRACED rebuild —
// and every one of them has to carry every rewrite. A redirect present in three of the four is not a
// partial fix: `capture.json` would declare a `jailHome` root the traced run never wrote to, and an
// empty bucket reads as a measured zero rather than as a gap. `dep-scaffold.mjs` records what
// happened the last time this harness grew a second spelling of one rule.
//
// The two PROVENANCE emissions — `capture.json`'s `observeEnv` and the `VENUE-OVERRIDES` marker (R6)
// — are derived from this same object for the same reason. Hand-maintained, `observeEnv` had already
// stopped being true: it named `npm_config_cache` alone while the driver was also redirecting all
// three temp variables.
const OBS_ENV = {
  npm_config_cache: NPM_CACHE,
  // All three, because the jail sets all three: Windows tools read `TMP`/`TEMP`, cross-platform ones
  // read `TMPDIR`, and a script reading the one we skipped lands somewhere neither of us declared.
  TMP: OBS_TMP, TEMP: OBS_TMP, TMPDIR: OBS_TMP,
  ...OBS_HOME_ENV,
};

// ⛔ `PYTHONDONTWRITEBYTECODE` IS DELIBERATELY *NOT* SET HERE YET, AND THE ABSENCE IS A MEASUREMENT
// RATHER THAN AN OVERSIGHT. `measure.sh` sets it in 8 places and `measure-macos.sh` in 4, because on
// macOS 39 of 39 `userHome` writes on a native build were `__pycache__`/`.pyc` beside node-gyp's
// bundled gyp — so the synthesized grant carried `write.userHome`, the PERSISTENCE capability,
// manufactured entirely by CPython. Mirroring that here was the obvious move.
//
// MEASURED on win32 instead, by re-parsing a retained archive (win-bytecode-probe run 31134429426,
// `@pulumi/datadog@0.18.9` on `windows-latest`):
//
//   events touching `__pycache__` or `.pyc` anywhere in the trace   0
//   writes under the home root                                      all `C:\Users\runneradmin\.pulumi\…`
//     — `plugins\resource-datadog-v0.18.9\pulumi-resource-datadog.exe`, `logs\…`, `.cachedVersionInfo`
//
// So this package's `write.userHome` is its install script fetching its own plugin payload into
// `~/.pulumi`. A REAL need, not a bytecode artefact, and suppressing bytecode would not narrow it by
// one capability.
//
// The macOS MECHANISM also cannot arise here as stated, for a layout reason: node-gyp's `gyp/pylib`
// sits at `C:\hostedtoolcache\windows\node\<ver>\x64\…` on the runner and `C:\Program Files\nodejs\…`
// on the corpus VM. Neither is under the home, so bytecode written beside it classifies
// `outside`/`systemfs` and can never reach the `userHome` bucket that made this a security finding.
//
// ⇒ SETTLED 2026-08-07 by win-bytecode-probe run 31135495106, WITH THE POSITIVE CONTROL THE FIRST
// ROUND LACKED. Round 1 was a non-answer wearing the shape of an answer: it found zero bytecode, but
// its package never ran Python, so the zero meant nothing. This round traced `npm rebuild` through
// the adapters directly rather than through this driver — which exits at `BROKEN-WITHOUT-JAIL-TOO`
// before the retention hook, discarding exactly the failed-build population the question lives in —
// and forced `npm_config_build_from_source`, since a package that downloads a prebuild never invokes
// node-gyp at all.
//
//   package                   python spawned   bytecode events   op       under the home
//   cpu-features@0.0.10       YES              12                ALL read      0
//   segfault-handler@1.3.0    YES              12                ALL read      0
//   deasync@0.1.30            no                0                —             0
//   integer@4.0.3            no                0                —             0
//
// The two YES rows spawned `python.exe` AND `py.exe` alongside `cl.exe`/`csc.exe`/`cvtres.exe`, so a
// real node-gyp configure and a real MSVC toolchain both ran. That is the control: a zero-write
// result now means something.
//
// ⛔ AND THE DECISIVE DETAIL IS THE OP COLUMN, NOT THE COUNT. All 24 bytecode events across both
// rows are READS. CPython is reading PRE-BUILT stdlib `.pyc` out of
// `C:\hostedtoolcache\windows\Python\3.x\x64\Lib\…\__pycache__\`; it writes none. There are
// ZERO bytecode WRITES anywhere in either trace, so there is nothing for `PYTHONDONTWRITEBYTECODE`
// to suppress and nothing for a classifier drop to drop.
//
// Two independent reasons the macOS mechanism cannot transfer, either sufficient on its own: the
// runner's Python ships its stdlib already compiled, so nothing needs caching; and gyp's own
// `pylib` sits outside the home, so bytecode written beside it could only ever bucket
// `outside`/`systemfs`, never `userHome`.
//
// ⛔ THE ONE VENUE CAVEAT WORTH CARRYING, because it is where this could stop being true: a
// DEVELOPER's Windows box commonly installs Python under `%LOCALAPPDATA%\Programs\Python`, i.e.
// INSIDE the home, and a stdlib there whose `__pycache__` is not pre-built would put these writes
// straight into `userHome`. This corpus measures on runners, so its records describe the runner. If
// a win32 venue ever ships a home-local Python, re-run that probe before trusting a record from it —
// do not assume this result carries.
//
// Both native builds FAILED here (capture `exit=1`) despite the full toolchain running, which is a
// second finding worth knowing before planning a win32 sweep: the successfully-compiling native
// population on `windows-latest` is thin.
// -- ERA PYTHON. node-gyp's Python requirement INVERTS across the matrix range: 3.4.0 (Node 4/6)
// rejects Python 3 outright, 9+ requires it. So this is era-conditional, never a constant -- an
// unconditional python2 would fix the old native records and break every modern arm. The marker is
// emitted whether or not a candidate was found, because a silently-unset PYTHON is how these
// failures came to be filed against the package rather than the toolchain.
const ERA_PYTHON = (() => {
  const probe = (nameOrPath) => {
    // An INJECTED candidate is an absolute path the workflow installed off the PATH, and `where`
    // searches only the PATH -- so resolving it needs the other branch. See `resolveInterpreter`.
    const p = resolveInterpreter(nameOrPath, (n) => {
      const where = run('where', [n]);
      return (where.stdout ?? '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0];
    }, fs.existsSync);
    if (!p) return null;
    // Python 2 prints --version to STDERR, Python 3 to stdout: read BOTH or every python2 looks
    // version-less and the box appears to have none.
    const v = run(p, ['--version']);
    const version = ((v.stdout ?? '') + (v.stderr ?? '')).trim();
    return version ? { path: p, version } : null;
  };
  const chosen = pythonForEra(ERA_NODE.selection?.eraMajor ?? null, candidatePythons(probe));
  console.log(`  ${chosen.marker}`);
  return chosen.path;
})();

// -- ARM MAKE. Recorded for the same reason as on POSIX: a record that cannot name its make cannot
// tell a package defect from a provisioning gap. Windows rarely has GNU make at all, and saying so
// is itself the useful outcome.
const ARM_MAKE = (() => {
  const cands = MAKE_CANDIDATES.map((n) => {
    const w = run('where', [n]);
    const p = (w.stdout ?? '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0];
    if (!p) return null;
    const v = run(p, ['--version']);
    return { path: p, version: ((v.stdout ?? '') + (v.stderr ?? '')).split(/\r?\n/)[0].trim() };
  }).filter(Boolean);
  const chosen = chooseMake(cands);
  console.log(`  ${chosen.marker}`);
  return chosen.path;
})();

const obsEnv = {
  ...process.env,
  // Only when a candidate was found: an EMPTY PYTHON is worse than none, because node-gyp reads it
  // as an explicit empty path rather than falling back to its own search.
  ...(ERA_PYTHON ? { PYTHON: ERA_PYTHON } : {}),
  // The era pin applies to the measured install, never to the harness — see ERA_NODE above.
  //
  // ⛔ THE FETCH USES THE ERA PATH, NOT THE PREPARED ARM PATH, AND IT MUST. Arm preparation reads the
  // package's INSTALLED manifest to learn which binaries its lifecycle scripts invoke, so it cannot
  // run until this fetch has landed the tree. Referencing ARM_PATH here is not merely early, it is a
  // temporal dead zone on its `let` below — a ReferenceError that would fail every win32 record.
  PATH: ERA_NODE.armPath,
  ...OBS_ENV,
};
// ⛔ Dated resolution — see the long note in `measure.sh`. This driver imports the module directly
// because it is already JS; the shell drivers shell out to the same file's CLI, so there is one
// implementation and one marker vocabulary.
const eraResolution = fetchArgs({ spec: `${PKG}@${VER}`, publishedAt: ERA_NODE.selection?.publishedAt ?? null });
console.log(`  ${eraResolution.marker}`);
const fetch = run(NODE, [NPM, ...eraResolution.args], { cwd: OBS, env: obsEnv });
fs.writeFileSync(path.join(OBS, 'fetch.log'), (fetch.stdout ?? '') + (fetch.stderr ?? ''));
// ⛔ PRINT WHY WHEN THE FETCH FAILS, and keep the exit COMPACT while doing it. This arm already
// had the rc and already wrote the log, then dropped it on the floor: MEASURED corpus-wide
// 2026-08-28, 165 of 1409 BROKEN-WITHOUT-JAIL-TOO records exit here with a ~18-line driver.out
// carrying no reason at all. "The package is gone from the registry" and "our dated fetch asked
// for something that never existed" are the two halves this corpus exists to tell apart, and
// neither is visible without npm's own words.
//
// ⛔ THE TAIL GOES AFTER emitBinaryProvenance() AND STAYS ON ONE LINE. `venue-provenance-on-exit
// .test.mjs` scans only five lines past the verdict announcement for that call, so a multi-line
// block here pushes it out of the window and the guard goes red — measured, not guessed.
//
// ⛔ THIS TAIL STAYS INLINE AND IS NOT ROUTED THROUGH `emitFailureTail`, DESPITE THE REBUILD EXIT
// BELOW USING IT. `fetch-diagnosis.test.mjs` scopes every assertion to THIS BLOCK and requires the
// `slice(-20)` bound to be visible inside it, because a file-wide search for the idiom also matches
// `npm_ok`'s long-standing tail and so passes with the fix deleted. Hoisting this into the helper
// moves the bound out of the guarded block and makes that guard green-either-way — the exact
// failure its header records. The rebuild exit needs the helper for a different reason: it reads two
// files that may be absent. Two spellings, one output shape, both guarded in their own block.
if (fetch.status !== 0) {
  console.log(`  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed rc=${fetch.status}; nothing to measure)`);
  emitBinaryProvenance();
  for (const l of ((fetch.stdout ?? '') + (fetch.stderr ?? '')).trimEnd().split('\n').slice(-20)) if (l.trim()) console.log(`    | ${l}`);
  process.exit(0);
}
securityScreen('npm-observe-resolved', ['--tree', OBS]);

// ── ARM PREPARATION — see the long note in `measure.sh`; the mechanism is identical and the CLI is
// ── shared so this driver cannot drift from it. `arm-prepare.test.mjs` asserts all three call it.
//
// ⛔ THIS DRIVER IS THE ONE THAT COULD SHARE THE MODULE DIRECTLY, AND DELIBERATELY DOES NOT. Importing
// `prepareArm()` here while the two shell drivers shell out to the CLI is exactly how the harness
// grew three spellings of the same rule before — `dep-scaffold.mjs` records the two v2 fixes that
// landed in one driver and were mistaken for done. One process, one output shape, one guard test.
const armPrep = (() => {
  const r = run(NODE, [path.join(HERE, 'arm-prepare.mjs'), '--observe', OBS, '--pkg', PKG,
    ...(ERA_NODE.bin ? ['--era-bin', ERA_NODE.bin] : [])]);
  if (r.status !== 0) return null;
  try { return JSON.parse(r.stdout ?? ''); } catch { return null; }
})();
let ARM_PATH = ERA_NODE.armPath;
if (!armPrep) {
  // Fail LOUD, never open — the era pin's silent fail-open is the precedent this must not repeat.
  console.log('  ARM-PREPARE FAILED (falling back to the era path; this record\'s PATH axis is UNCOVERED)');
} else {
  ARM_PATH = armPrep.armPath || ERA_NODE.armPath;
  for (const m of armPrep.markers ?? []) console.log(`  ${m}`);
  const scaffold = armPrep.scaffold?.install ?? [];
  if (scaffold.length) {
    // Non-fatal by design: a scaffold that will not resolve leaves the arm exactly as badly off as
    // it is today, so it must never turn a measurable package into a harness error.
    //
    // ⛔ DATED, like the fetch above and for the reason `observe-only.mjs:330` already records:
    // undated, this pulls TODAY's build tools into a tree pinned to the package's own era, and the
    // era Node cannot parse them. `eraResolution.before` is the SAME value the fetch used, so the
    // two installs cannot disagree about the date.
    const si = run(NODE, [NPM, 'install', '--no-audit', '--no-fund', '--ignore-scripts',
      ...(eraResolution.before ? [`--before=${eraResolution.before}`] : []), ...scaffold],
      // ⛔ THE ERA PYTHON, like `obsEnv` above. Every arm that can run node-gyp must hold the
      // SAME interpreter or a Python failure in one is read as a defect in what the other blames.
      // See `unjailed-nub.mjs`'s `asIdentity` for the node-sass@9.0.0 measurement behind this.
      { cwd: OBS, env: { ...process.env, PATH: ARM_PATH, ...(ERA_PYTHON ? { PYTHON: ERA_PYTHON } : {}), ...OBS_ENV } });
    console.log(`  ARM-SCAFFOLD-INSTALL rc=${si.status}`);
    // ⛔⛔ THE SCAFFOLD INSTALL SOMETIMES REMOVES THE SUBJECT — the long note is at the matching branch
    // in `measure.sh`. Measured over all 6,880 records, `ARM-FALSIFIABILITY`'s `manifestFiles: null`
    // (no layout for the subject exists at all) occurs in 51 records, EVERY one of them with a
    // scaffold and none of the 5,279 without one, and all 51 attributed zero lifecycle pids.
    //
    // ⛔ WIN32 HAS EXACTLY ONE SCAFFOLDED RECORD IN THE WHOLE CORPUS AND IT IS CLEAN, so this branch
    // is written from the other two platforms' evidence rather than from win32's own. That is the
    // point: the win32 lane has barely run, its 2,265 rows are almost entirely unmeasured, and the
    // scaffold rate there is not yet knowable. Landing the guard before the lane runs is the whole
    // saving — the alternative is discovering it in 51 records' worth of win32 non-answers later.
    //
    // The invariant, which needs no mechanism: the subject is the thing under measurement, so it is
    // the LAST thing written into the observe tree. A no-op when nothing was evicted.
    run(NODE, [NPM, 'install', '--no-audit', '--no-fund', '--ignore-scripts',
      ...(eraResolution.before ? [`--before=${eraResolution.before}`] : []), `${PKG}@${VER}`],
      { cwd: OBS, env: { ...process.env, PATH: ARM_PATH, ...(ERA_PYTHON ? { PYTHON: ERA_PYTHON } : {}), ...OBS_ENV } });
    // ⛔ `pkgDir`, NOT A HAND-BUILT JOIN — it is what every other read of the installed package in
    // this driver goes through, and it already handles the layout and short-name resolution a literal
    // `node_modules/<pkg>` join gets wrong on Windows.
    if (!pkgDir(OBS, PKG, VER)) {
      // REFUSE, NEVER MEASURE. An arm on a tree without the subject synthesizes `{}`, which is
      // byte-identical to a package that genuinely needs nothing, so it lands MINIMUM — an
      // under-prediction asserted from a run that never happened.
      console.log(`  ARM-SUBJECT-EVICTED the scaffold install removed ${PKG} from the observe tree and a`);
      console.log('     re-install did not restore it. There is nothing to measure.');
      const tail = `${si.stdout ?? ''}${si.stderr ?? ''}`.trimEnd().split('\n').slice(-15);
      for (const line of tail) console.log(`    | ${line}`);
      console.log('  => UNKNOWN (the subject is not in the observe tree; no measurement was possible)');
      process.exit(0);
    }
  }
}

// ⛔ TAKEN NOW, BECAUSE NOW IS THE ONLY MOMENT IT EXISTS. The fetch above ran `--ignore-scripts`, so
// the package directory at this instant is exactly what the tarball shipped. Once the lifecycle
// script runs that state is unrecoverable — and it is what decides whether the artifact gate could
// ever have FAILED for this package. A package that ships its build output prebuilt has every file
// present at full size before any script runs, so a green arm carries no evidence about the grant.
// `|| true` in spirit: a detector fault must never cost a record.
const PRE_MANIFEST = path.join(OBS, 'pre-manifest.json');
run(NODE, [path.join(HERE, 'arm-falsifiability.mjs'), '--snapshot', OBS,
  '--pkg', PKG, '--ver', VER, '--out', PRE_MANIFEST]);

const CAP = path.join(ROOT, 'cap');
// ⛔ THE TRACED COMMAND GOES THROUGH `cmd /c`, WHICH STRIPS THE OUTER QUOTE PAIR when the string
// both starts and ends with a quote. `"C:\Program Files\nodejs\node.exe" "...npm-cli.js" rebuild`
// therefore degrades to `C:\Program Files\nodejs\node.exe" "...` and dies with
// `'C:\Program' is not recognized as an internal or external command` -- measured here, and it
// reads as a PATH problem rather than a quoting one. Rather than counter-quote, hand cmd a single
// SPACE-FREE path to a wrapper: a string with no spaces cannot be mis-split however it is re-parsed.
// `cmd /c foo.cmd` also runs the wrapper in that same cmd.exe, so this adds no process level and
// the "lifecycle shell = a cmd.exe that is not rootPid" rule is unaffected.
const WRAP = path.join(ROOT, 'rebuild.cmd');
// `set` inside the wrapper rather than an env option on the powershell call: the capture script
// spawns the command through its own cmd.exe, so this is the one place guaranteed to be in scope
// for the lifecycle script itself.
// ⛔ THE REWRITES ARE REPEATED HERE, NOT ONLY IN `obsEnv`, AND THEY ARE GENERATED FROM `OBS_ENV`
// RATHER THAN RETYPED. `obsEnv` reaches the untraced FETCH; the traced rebuild runs under the capture
// script's OWN cmd.exe, and this wrapper is the one place guaranteed to be in scope for the lifecycle
// script itself. This is therefore the ONE vector whose contents `capture.json`'s declared roots
// describe — a rewrite that reached the other three and missed this one would declare a `jailHome`
// root nothing ever wrote to, and the empty bucket would read as a measured zero. `cmd`'s `set` is
// case-insensitive, so the ambient spelling `OBS_HOME_ENV` preserved costs nothing here and matters
// on the JS side.
// ⛔⛔ `npm rebuild <BARE NAME>` MATCHES NOTHING ON npm 6 WHEN THE INSTALLED VERSION IS A
// PRERELEASE — rc=0, no output, no script, so the arm traces a process that did nothing and the
// empty syscall set is read as a measurement. npm 6 resolves a bare name to the range `*`, which
// semver excludes prereleases from. The 2x2 isolating the version and the three-major control are
// at the identical block in `measure.sh`. No win32 record is in the affected set today, so this
// edit is written from the other two platforms' evidence — but the win32 lane is 2,265 rows
// unmeasured, and era npm 6 is exactly what its 2016-2018 packages will select.
//
// ⛔ THE INSTALLED VERSION, NOT `VER`. `pkgDir` is the same resolver the falsifiability gate uses,
// so a subject it cannot find is one the arm was never going to measure anyway; that case falls
// back to the bare name, which is today's behaviour and correct for every unscoped package.
const rebuildDir = pkgDir(OBS, PKG, VER);
let rebuildSpec = PKG;
if (rebuildDir) {
  try {
    const m = JSON.parse(fs.readFileSync(path.join(rebuildDir, 'package.json'), 'utf8'));
    if (typeof m.version === 'string' && m.version) rebuildSpec = `${PKG}@${m.version}`;
  } catch { /* unreadable manifest -> bare name, as before */ }
}
console.log(`  ARM-REBUILD-SPEC ${rebuildSpec}`);
const WRAP_SETS = Object.entries(OBS_ENV).map(([k, v]) => `set "${k}=${v}"\r\n`).join('');
fs.writeFileSync(WRAP, `@echo off\r\n${WRAP_SETS}"${NODE}" "${NPM}" rebuild --no-audit --no-fund ${rebuildSpec}\r\n`, 'ascii');
// ⛔ THE ETW SESSION NAME MUST BE UNIQUE PER RUN. windows.ps1 defaults to the fixed name `nubobs`
// and unconditionally `logman stop`s it before creating it, so a second concurrent driver SILENTLY
// KILLS the first one's live trace -- the victim reports a short or empty capture with no error.
// A per-run name is what makes the lane parallelisable at all.
const SESSION = `nubobs_${process.pid}_${Date.now().toString(36)}`;
const cap = run('powershell.exe', [
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(HERE, 'adapters', 'windows.ps1'),
  '-OutDir', CAP,
  '-Command', WRAP,
  '-WorkDir', OBS,
  '-Session', SESSION,
]);
const capOut = (cap.stdout ?? '') + (cap.stderr ?? '');
fs.writeFileSync(path.join(ROOT, 'capture.log'), capOut);
console.log('  ' + capOut.trim().split('\n').slice(-3).join('\n  '));
if (!fs.existsSync(path.join(CAP, 'meta.json'))) { console.log('  => CAPTURE FAILED (no meta.json)'); process.exit(1); }
const meta = JSON.parse(fs.readFileSync(path.join(CAP, 'meta.json'), 'utf8'));

// ── R7: OBSERVE RAN AS A REAL USER, AND THE RUN ASSERTS IT RATHER THAN INTENDING IT ────────────
//
// ⛔ A LESS-PRIVILEGED OBSERVE MEASURES A SCRIPT'S FALLBACK PATH. A script that tries its primary
// path, is refused, and falls back gets measured on the fallback — while a real user with the
// permission takes the primary path and needs a capability the trace never saw. That is an
// under-grant, the one direction this project forbids, and nothing in the record would show it.
// The converse is safe: a MORE-privileged OBSERVE measures a path a real user cannot take, which
// over-grants. So the requirement is an ordinary user and erring toward more privilege is tolerable.
//
// ⛔ SYSTEM IS THE CONCRETE FAILURE ON THIS PLATFORM AND IT HAS ALREADY PRODUCED ONE FALSE
// VALIDATION HERE. A Windows scheduled task runs as `NT AUTHORITY\SYSTEM`, which holds
// `SeCreateSymbolicLinkPrivilege` an ordinary account does not, and whose `os.homedir()` is
// `C:\Windows\system32\config\systemprofile` — so every home-relative path in the trace is a
// directory no user has. That is why measurements go through an interactive session and never
// through `schtasks`; a scheduled task is fine for a BUILD and never for a measurement.
//
// ⛔ THIS IS THE TRACED PROCESS, NOT THE TRACER. The tracer needs an elevated token because ETW
// kernel providers are administrator-only (`windows.ps1` throws without one). What must be an
// ordinary user is the process under test. `windows.ps1` removes SeBackup/SeRestore/SeTakeOwnership
// from the token before spawning it, so the DACL checks the script meets are the ones a real user
// meets — recorded in `meta.privDropped` and asserted below rather than assumed to have worked.
const OBSERVE_USER = meta.whoami ?? '';
if (/^nt authority\\(system|local service|network service)$/i.test(OBSERVE_USER)) {
  console.log(`  => VOID: captured as ${OBSERVE_USER} — a service account, not a real user.`);
  console.log('     Its privileges and its home directory are both wrong, so the trace measures a');
  console.log('     path no developer takes. Run the measurement through an interactive session.');
  process.exit(1);
}
if (!OBSERVE_USER) { console.log('  => VOID: the capture recorded no identity, so R7 cannot be asserted'); process.exit(1); }
// The DACL-bypass privileges must be gone, or a refused-then-fallback script is measured on the
// primary path it only reached by bypassing an ACL a real user cannot bypass. `windows.ps1` reports
// `removed` or `already-absent` per privilege; anything else means the drop silently failed.
const badPriv = Object.entries(meta.privDropped ?? {})
  .filter(([, v]) => v !== 'removed' && v !== 'already-absent');
if (badPriv.length) {
  console.log(`  => VOID: privilege drop failed — ${badPriv.map(([k, v]) => `${k}=${v}`).join(', ')}`);
  console.log('     libuv opens every file with FILE_FLAG_BACKUP_SEMANTICS, so a retained');
  console.log('     SeBackupPrivilege bypasses the DACL outright and the trace measures accesses an');
  console.log('     ordinary user would be refused.');
  process.exit(1);
}
// R7 is a claim about the run, so it goes in the record rather than only in this log. `record.mjs`
// learns it from this one stdout line, the same two-line contract the retention markers use.
console.log(`  VENUE-OBSERVE-USER ${OBSERVE_USER} elevated=${meta.elevated} privDropped=${JSON.stringify(meta.privDropped ?? null)}`);

if (meta.eventsLost > 0) console.log(`  !! ${meta.eventsLost} events LOST -- exact-set claims are not supported by this trace`);
if (meta.exitCode !== 0) {
  // ⛔ THE TAIL GOES AFTER emitBinaryProvenance() AND STAYS ON ONE LINE, for the reason the fetch
  // exit above records: `venue-provenance-on-exit.test.mjs` scans only five lines past the verdict
  // for that call, so a multi-line block here pushes it out of the window and the guard goes red.
  console.log(`  => BROKEN-WITHOUT-JAIL-TOO (unjailed rebuild rc=${meta.exitCode})`);
  emitBinaryProvenance();
  emitFailureTail(readTracedLog(path.join(CAP, 'run.out')) + readTracedLog(path.join(CAP, 'run.err')));
  process.exit(0);
}

const isLog = (p) => /\.(log|xml|etl|txt)$|meta\.json$|cat\.json$/i.test(p);
// `.harness-tools` is the instrument, not the install — see the staging block in `verify`. Counting
// it would inflate `files/OBS_FILES` by roughly the whole observe tree and make the printed ratio
// incomparable with every record taken before staging existed. `countFiles` skips a directory whole,
// so matching the directory itself prunes the subtree rather than filtering it entry by entry.
const isArmNoise = (p) => isLog(p) || /[\\/]\.harness-tools([\\/]|$)/.test(p);
const OBS_FILES = countFiles(OBS, isLog);
const OBS_PKG = pkgManifest(OBS, PKG, VER);
if (!OBS_PKG || OBS_PKG.size === 0) {
  // The unjailed reference produced no artifacts for the package we are measuring. Nothing
  // downstream can be gated against that, and falling back to the whole-tree count would
  // reinstate the layout bug, so refuse rather than emit a verdict.
  console.log(`  => HARNESS-ERROR: no artifacts for ${PKG}@${VER} under ${OBS} -- cannot gate`);
  process.exit(1);
}
console.log(`  OBSERVE artifacts: ${OBS_PKG.size} files  (${OBS_PKG.root})`);

// ⛔ FLAG, NEVER FAIL — and the LINE IS PRINTED UNCONDITIONALLY, which is the load-bearing part.
// `record.mjs` decides whether a passing narrow arm is evidence by looking for this line: absence of
// the flag is NOT evidence of falsifiability, it is usually evidence the check never ran, so the
// line itself is what says the question was asked. Without it every descended grant on this platform
// would be filed as "predates the falsifiability check" and kept wide.
{
  const af = run(NODE, [path.join(HERE, 'arm-falsifiability.mjs'), '--obs', OBS,
    '--pre', PRE_MANIFEST, '--pkg', PKG, '--ver', VER]);
  const afOut = ((af.stdout ?? '') + (af.stderr ?? '')).trimEnd();
  if (afOut) console.log(afOut.split('\n').map((l) => '  ' + l).join('\n'));
}

// The dependency closure npm actually installed to run this lifecycle script, read off the OBSERVE
// arm's own hoisted `node_modules` — MEASURED, not guessed from the manifest. Consumed by the
// per-arm store eviction in `verify()`; the long note there is why evicting `$PKG` alone leaves a
// live replay path.
const CLOSURE = (() => {
  const nm = path.join(OBS, 'node_modules');
  const out = [];
  let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    if (e.name.startsWith('@')) for (const s of fs.readdirSync(path.join(nm, e.name))) out.push(`${e.name}/${s}`);
    else out.push(e.name);
  }
  return out;
})();
console.log(`  CLOSURE ${CLOSURE.length} packages evicted per arm`);

// ── 1c. capture.json — THE ONE PLACE A PATH'S MEANING IS DEFINED (PORTABILITY R1) ──────────────
//
// ⛔ EVERY ROOT THE CLASSIFIER COULD KEY ON IS DECLARED HERE AND NOWHERE ELSE. Before this the
// Windows lane passed `--project`/`--home` on the command line and `--home` came from
// `process.env.USERPROFILE` — read from the AMBIENT environment of whatever machine happened to be
// classifying. `classify.mjs` now refuses to run without this file, so a root can never be silently
// re-derived from ambient state on a second machine. That is the whole of R2: a fallback is what
// makes a venue difference silent, because it produces a plausible answer on the machine that
// happens to match and a wrong one everywhere else.
//
// ⛔ AN ABSENT KEY AND AN INAPPLICABLE ROOT READ THE SAME DOWNSTREAM, so `null` is written wherever
// this platform genuinely has no such root and a key is NEVER omitted. `classify.mjs` treats an
// absent key as fatal and an explicit `null` as an answer.
//
// ⛔ ROOTS ARE DECLARED WHETHER OR NOT THEY ARE KEYED ON — twelve are declared, five are keyed on
// (`project`, `home`, `jailHome`, `temp`, `npmCache`; `project` answers both `deps` and `project`).
// That is deliberate, and matches the Linux and macOS lanes. A root re-derived later is a root
// re-derived from ambient state, which is the exact failure this file exists to prevent; changing
// WHICH bucket a path lands in is a grant-semantics change and needs its own evidence.
const CACHE = path.join(process.env.XDG_CACHE_HOME || process.env.LOCALAPPDATA, 'nub', 'pm');
const STORE = path.join(CACHE, 'store');
const TOOLS = path.join(CACHE, 'tools');
const CAPTURE = path.join(CAP, 'capture.json');
const sha256File = (p) => {
  try { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); } catch { return null; }
};
const decoderSha = (rel) => ({ path: `harness/v2/${rel}`, sha256: sha256File(path.join(HERE, rel)) });
fs.writeFileSync(CAPTURE, `${JSON.stringify({
  v: 1,
  kind: 'capture',
  platform: `win32-${process.arch}`,
  pkg: PKG,
  version: VER,
  tracer: 'etw',
  invocation: 'powershell -File adapters/windows.ps1 -Command "npm rebuild --no-audit --no-fund <pkg>"',
  // ⛔ THE KEYWORD MASK IS A SILENT FILTER AND MUST TRAVEL WITH THE TRACE. `logman update trace`
  // exits 0 whatever the mask is, and an event whose keyword bit is clear is simply never written —
  // so "no hardlink destinations in this trace" means "none happened" at 0x1FF0 and "they were
  // never subscribed" at 0x11F0, and nothing in the byte stream tells them apart.
  subscribes: { providers: meta.providers ?? null, fileMask: meta.fileMask ?? null, session: meta.session ?? null },
  // Hashed by CONTENT rather than by a version number someone must remember to bump. `windows.mjs`
  // + `classify.mjs` produced the GRANT; `adapters/windows-retain.mjs` produced the derived view.
  // A re-parse needs to know which revision of each answered, and they move independently.
  decoders: {
    adapter: decoderSha('adapters/windows.mjs'),
    classifier: decoderSha('classify.mjs'),
    derived: decoderSha('adapters/windows-retain.mjs'),
    shortnames: decoderSha('adapters/windows-shortnames.mjs'),
  },
  os: { version: meta.os ?? null, host: meta.host ?? null, arch: process.arch },
  // R7, in the archive rather than only in the driver log.
  identity: {
    whoami: meta.whoami ?? null, sid: meta.sid ?? null,
    elevated: meta.elevated ?? null, privDropped: meta.privDropped ?? null,
  },
  // ⛔ `rootPid` IS A CLASSIFIER INPUT, NOT DECORATION, SO IT BELONGS IN THE ARCHIVE. Attribution is
  // structural on Windows: a lifecycle shell is every `cmd.exe` that is NOT the traced root, and the
  // attributed set is the union of the subtrees rooted at them. Re-decode this archive without the
  // root pid and the root's OWN cmd.exe counts as a lifecycle shell, so npm's registry TLS and its
  // cache writes under the user profile enter the grant — a 100% over-prediction that looks entirely
  // plausible. A capture must carry every input the grant depends on, or a re-parse is not
  // reproducing the measurement, it is making a different one.
  run: {
    command: meta.command ?? null, workDir: meta.workDir ?? null,
    rootPid: meta.rootPid ?? null, launcherPid: meta.launcherPid ?? null,
    exitCode: meta.exitCode ?? null,
    startedUtc: meta.startedUtc ?? null, endedUtc: meta.endedUtc ?? null,
  },
  roots: {
    project: OBS,
    home: HOME,
    // ⛔ THE PRIVATE HOME THIS DRIVER CREATED AND EXPORTED — not the user's `%USERPROFILE%`. What
    // nub does: `compiler/preset.rs::private_home_dir()` (exported as `jail_private_home`) creates a
    // persistent PER-PACKAGE private home, and `compile_build_jail` redirects `HOME`, `USERPROFILE`
    // **and** `APPDATA` at it for the jailed child — `APPDATA` to the `AppData\Roaming` leaf inside
    // it, because npm on Windows caches to `%APPDATA%\npm-cache` rather than `$HOME/.npm`.
    // `build_jail.rs::persist_declared_home_writes` then promotes the declared `writePaths` out of
    // it, and states in its own header that "WINDOWS PROMOTES THROUGH THIS SAME BODY". `OBS_ENV`
    // reproduces all three rewrites; see the long note at its definition.
    //
    // ⛔ THIS DECLARATION IS WHAT MAKES THE `jailHome` BUCKET SAFE, exactly as the `temp` root below
    // makes `jailTmp` safe. `classify.mjs` drops a write from the grant only when it is under THIS
    // EXACT PATH, never because a path looks home-shaped. A script that hardcodes
    // `C:\Users\<user>\.pulumi` is writing somewhere the jail does NOT grant, so that write still
    // bills `userHome` and still earns the scope.
    //
    // ⛔ AND THE TWO HOME BUCKETS HAVE OPPOSITE ANSWERS FOR `writePaths`. `jailHome` is the promotable
    // one — the write succeeded and was then discarded with the throwaway home, so what is lost is
    // the artefact and a declaration is what keeps it. `userHome` is not: promotion moves things OUT
    // of the private home and nothing of that write's is in it, so substituting a `writePaths` entry
    // for the scope is an UNDER-GRANT, refused by name in `write-paths.mjs::refuseUserHome`. This
    // root is what lets the classifier tell them apart by MEASUREMENT rather than by guessing
    // provenance. Until it was declared this lane derived NO `writePaths` at all — 0 of 2,270 win32
    // records against 284 on POSIX — because the promotable bucket did not exist.
    jailHome: OBS_HOME,
    globalStore: STORE,
    projectStore: path.join(OBS, 'node_modules', '.store'),
    interpreter: NODE,
    toolsDir: TOOLS,
    // ⛔ THE PRIVATE TEMP THIS DRIVER CREATED AND EXPORTED — not the user's `%TEMP%`. The jail gives
    // a confined script a fresh per-run temp (`preset.rs` `$tmp`=rw -> `TmpMode::Private` ->
    // `backend/mod.rs::set_tmp_env`) and hides the shared one, so tracing against the real `%TEMP%`
    // measured an environment no confined script ever sees.
    //
    // ⛔ THIS DECLARATION IS WHAT MAKES THE `jailTmp` BUCKET SAFE. `classify.mjs` drops a write from
    // the grant only when it is under THIS EXACT PATH, never because a path looks temp-shaped. A
    // script that hardcodes `C:\\Windows\\Temp\\foo` is writing somewhere the jail does NOT grant, so
    // that write is a real capability need and still bills. Keying on the declared root rather than
    // on a heuristic is the difference between dropping noise and manufacturing an under-grant.
    temp: OBS_TMP,
    // Null because this driver sets no `npm_config_prefix`, so there is no separate npm prefix root
    // for a path to land in. An inapplicable root, which is an ANSWER — distinct from an absent key.
    npmPrefix: null,
    // ⛔ THE PER-RUN npm CACHE THIS DRIVER CREATED AND EXPORTED — and the root that was MISSING while
    // the redirect it describes was live. `OBS_ENV` has set `npm_config_cache` at `NPM_CACHE` since
    // the OBSERVE arm was given a cold cache (see the long note there: a warm host cache makes a
    // fetching script record no `connect` at all, and the grant then omits `network`). `NPM_CACHE`
    // is a SIBLING of `observe`, `tmp` and `jailhome`, so it sits under no other declared root and
    // every write npm made there could only fall through to `outside`. MEASURED on the committed
    // corpus: 135 win32 records carry an `outside` WRITES row, and 728 of the 805 outside paths
    // those records print are under this directory — so the bucket that exists to surface a
    // genuinely unaccounted write was ~90% this driver's own apparatus, and a real one could not be
    // seen in it. Redirecting somewhere and not declaring it is the one shape `classify.mjs` cannot
    // recover from: it bills the harness as if it were the package.
    //
    // ⛔ IT IS BASE-COVERED THERE, ON NUB'S BEHAVIOUR RATHER THAN ON BEING A REDIRECT. nub sets no
    // `npm_config_cache` at all, and `preset.rs` repoints `APPDATA` at the `AppData\Roaming` leaf of
    // the read-write private jail home FOR THIS EXACT REASON — its own comment names
    // `%APPDATA%\npm-cache` and the `EPERM` it used to cause. So the confined script's npm cache
    // lands in granted space and costs no scope; the full argument is at `classify.mjs`'s
    // `BASE_COVERED`.
    npmCache: NPM_CACHE,
    ownPkg: path.join(OBS, 'node_modules', ...PKG.split('/')),
    // ⛔ NULL, AND THE NULL IS THE POINT. No path in this stream is ever resolved against a working
    // directory, so there is no cwd to declare and inventing one would be the macOS defect in
    // reverse. Kernel-File reports fully-resolved NT paths; the one relative case is a rename
    // destination arriving as a bare leaf, which `windows.mjs` anchors to the SOURCE path's own
    // directory — an observed absolute, never an inherited cwd.
    cwd: null,
  },
  // ⛔ R6, IN THE ARCHIVE. Every variable this driver set, unset or redirected, with its value —
  // and `CI` listed with its INHERITED value precisely because touching `CI` is the one override
  // that would invalidate the whole venue/CI acceptance test. Recording it unchanged is a claim a
  // reader can check. The harness normalises its own APPARATUS and never the environment under
  // test: `CI`, `GITHUB_ACTIONS` and `NODE_ENV` pass through verbatim, because an install script
  // reads them and changes what it downloads or whether it builds from source.
  // ⛔ DERIVED FROM `OBS_ENV`, NEVER RETYPED. Hand-maintained, this named `npm_config_cache` alone
  // while the driver was already redirecting all three temp variables — so the archive's own account
  // of what it changed had stopped being true, silently, which is the one failure R6 exists to
  // prevent.
  observeEnv: { set: OBS_ENV, unset: [] },
  rawBytes: (() => { try { return fs.statSync(path.join(CAP, 'trace.xml')).size; } catch { return null; } })(),
  at: new Date().toISOString(),
}, null, 2)}\n`);

// ── 2. SYNTHESIZE ─────────────────────────────────────────────────────────────────────────────
const NDJSON = path.join(CAP, 'events.ndjson');
// ⛔ `--resolve-shortnames` IS THE CAPTURE-HOST PASS AND ONLY THE DRIVER MAY ASK FOR IT. Here, and
// only here, we know we are on the machine that captured the trace with its tree still on disk. The
// pass resolves every 8.3 component against the live filesystem and writes `shortnames.json` into
// the capture directory; every later decode, on any machine, reads that map and touches no
// filesystem. Before this the decoders re-derived it whenever `COMPUTERNAME` matched, which made
// their output depend on where they RAN rather than on what they READ (PORTABILITY R2).
const parse = run(NODE, [path.join(HERE, 'adapters', 'windows.mjs'), CAP, '--out', NDJSON, '--resolve-shortnames']);
if (!fs.existsSync(NDJSON)) { console.log(`  => PARSE FAILED\n${parse.stdout}${parse.stderr}`); process.exit(1); }

// ⛔ THE MAP IS FOLDED INTO `capture.json` BECAUSE THAT IS THE ONLY FILE THE PUBLISHER KEEPS.
// `record.mjs` copies the raw trace, `capture.json` and the derived log — a sidecar left in the
// driver's run root is GONE when the runner ends. Without the map in the archive, a published
// record could never be re-decoded with expansion on, which is most of what R2 buys.
const SHORTNAMES = path.join(CAP, 'shortnames.json');
if (fs.existsSync(SHORTNAMES)) {
  const cap = JSON.parse(fs.readFileSync(CAPTURE, 'utf8'));
  cap.shortNames = JSON.parse(fs.readFileSync(SHORTNAMES, 'utf8'));
  fs.writeFileSync(CAPTURE, `${JSON.stringify(cap, null, 2)}\n`);
  console.log(`  8.3 MAP ${Object.keys(cap.shortNames.entries).length} components resolved on ${cap.shortNames.host}, folded into capture.json`);
}

const cls = run(NODE, [
  path.join(HERE, 'classify.mjs'), NDJSON,
  // ⛔ ROOTS ARE NOT PASSED AS ARGUMENTS ANY MORE — the classifier takes them from `capture.json`
  // and from nothing else (PORTABILITY R2). Two lists that had to stay in step were themselves a
  // drift hazard: the driver and the capture could disagree about what a path meant, and the
  // capture is the artifact a re-parse actually has.
  //
  // ⛔ `--platform win32` IS NODE'S `process.platform`, NOT THE `win32-x64` CORPUS PLATFORM ID.
  // `classify.mjs` derives `WIN` and `FOLD` from it to pick separator handling, case folding and
  // the kernelfs/systemfs predicates, so passing the corpus id here would silently disable all
  // three. The corpus id is a different field and `run-batch-v2.mjs` passes it to `record.mjs`.
  '--capture', CAPTURE, '--platform', 'win32',
  '--root-pid', String(meta.rootPid), '--json', path.join(ROOT, 'observed.json'),
]);
const clsOut = (cls.stdout ?? '') + (cls.stderr ?? '');
fs.writeFileSync(path.join(ROOT, 'observed.txt'), clsOut);
console.log(clsOut.trimEnd().split('\n').map((l) => '  ' + l).join('\n'));
const observed = JSON.parse(fs.readFileSync(path.join(ROOT, 'observed.json'), 'utf8'));
const GRANT = observed.grant;

// ⛔⛔ AN EMPTY GRANT IS A REAL ANSWER; AN UNATTRIBUTED RUN IS NOT. When `classify.mjs`'s subtree
// filter matches nothing it still emits `grant: {}`, which is byte-identical to the grant for a
// package that genuinely needs nothing — so the ladder ran against it, the package passed because it
// exercises nothing at verify time, and the record landed MINIMUM: "needs no permissions", asserted
// from a measurement that never happened. That is an UNDER-PREDICTION, the direction that breaks
// real installs.
//
// `classify.mjs:275` prints `NO LIFECYCLE SHELL FOUND ... Treat it as UNKNOWN`, and it has always
// been right — but it was addressed to a human reader and nothing consumed it.
//
// MEASURED 2026-08-31 over the committed corpus, cross-tabulating that warning against the verdict
// recorded beside it: darwin 65 failures -> 65 UNKNOWN (it has had this branch all along); linux 134
// -> 100 MINIMUM; **win32 28 -> 26 MINIMUM**. The non-MINIMUM ones are unaffected, because those
// verdicts do not rest on the grant being a real measurement.
//
// ⛔ BRANCHES ON `lifecyclePids`, NOT ON A SENTINEL STRING. `classify.mjs:245` already publishes the
// count in the JSON this driver parses, so the fact is read from structured output rather than by
// re-deriving it from prose — the POSIX drivers use a token only because they scrape stdout.
// ⛔⛔ ZERO ATTRIBUTION HAS TWO CAUSES AND THEY NEED OPPOSITE VERDICTS — the long note is at the
// matching branch in `measure.sh`. Either the package RUNS NOTHING at install (`{}` is then a real
// measurement and MINIMUM is right), or it runs something the filter missed (`{}` is then a
// non-measurement and MINIMUM is an under-prediction). Refusing BOTH turns correct MINIMUM records
// into non-answers; refusing NEITHER is the under-prediction. So ask the installed manifest.
//
// `binding.gyp` counts — npm runs `node-gyp rebuild` with no explicit install script, and those are
// the packages whose grants matter most. `prepare` does not: the OBSERVE arm is `npm rebuild`.
if (observed.lifecyclePids === 0) {
  // ⛔ `pkgDir`, NOT A HAND-BUILT JOIN. It is what every other read of the installed package in this
  // driver goes through, and it already handles the layout and short-name resolution that a literal
  // `node_modules/<pkg>` join gets wrong on Windows.
  let declares = 'unreadable';
  try {
    const own = pkgDir(OBS, PKG, VER);
    const s = JSON.parse(fs.readFileSync(path.join(own, 'package.json'), 'utf8')).scripts || {};
    const named = ['preinstall', 'install', 'postinstall']
      .some((k) => typeof s[k] === 'string' && s[k].trim());
    // ⛔⛔ THE INSTALLED MANIFEST, NEVER THE REGISTRY. `npm view <pkg> scripts` IS NOT AN ORACLE FOR
    // THIS, AND USING IT AS ONE WILL "PROVE" THIS BRANCH WRONG WHEN IT IS RIGHT. The registry's
    // `versions[v].scripts` comes from the DEVELOPMENT package.json at publish time; the tarball
    // carries what `npm pack` produced, and pipelines routinely strip an install-time script before
    // packing (`postinstall: husky` above all). Only the tarball's copy can execute. Measured
    // 2026-08-31: `@stdlib/math-base-special-erfc@0.1.0` advertises `install: node-gyp rebuild` and
    // ships neither that script nor a binding.gyp; same for `eslint-plugin-diff@1.0.9` and
    // `@react-hookz/deep-equal@3.0.2`. An audit trusting `npm view` flagged 16 correct records as
    // false MINIMUMs on this basis. Read the tree — which `own` already is.
    declares = named || fs.existsSync(path.join(own, 'binding.gyp')) ? 'yes' : 'no';
  } catch { /* fail closed below */ }

  if (declares === 'no') {
    console.log('  ATTRIBUTION EMPTY BY MEASUREMENT — the manifest declares no preinstall/install/postinstall');
    console.log('     and ships no binding.gyp, so `npm rebuild` ran no script. {} is the answer, not a gap.');
  } else {
    // `unreadable` fails CLOSED: a manifest we cannot read cannot prove the package runs nothing.
    //
    // ⛔ THE `ATTRIBUTION-GAP-EVIDENCE` DUMP THE TWO POSIX DRIVERS NOW EMIT IS DELIBERATELY ABSENT
    // HERE, AND THIS NOTE IS THE HONEST VERSION OF THAT. They print the tail of `$OBS/npm.log`, npm's
    // own account of the traced rebuild, because 139 records reach this branch corpus-wide (28 of them
    // win32) and three hypotheses for the cause have already been falsified against records that were
    // never instrumented for the question. This driver traces through an ETW capture script rather
    // than a redirect, so it has no `npm.log` in scope at this point — and guessing at an artifact is
    // exactly the failure that produced those three dead hypotheses. Find the capture's own stdout
    // sink and dump it here; do not substitute a file that looks similar.
    console.log(`  => UNKNOWN (attribution failed — the package declares an install-time script (${declares})`);
    console.log('     but no lifecycle shell was identified, so there is no measurement here. This is NOT a');
    console.log('     package that needs nothing.)');
    process.exit(0);
  }
}

// ── 2b. RETAIN the capture, when the batch driver asked for it. ────────────────────────────────
//
// ⛔ THIS IS THE ONLY THING IN THE PIPELINE THAT SURVIVES `$ROOT`. The capture directory lives under
// the run root on an ephemeral runner and the publisher only ever copies `driver.out` plus the
// extracted verdict, so every path a package touched has been discarded at the end of every Windows
// run this corpus has ever done. That is why a harness fix has always meant RE-MEASURING rather
// than re-parsing — and it is why the raw ETW XML, not this harness's reading of it, is what gets
// kept.
//
// ⛔ IT RUNS AFTER SYNTHESIS AND FEEDS NOTHING BACK. `windows.mjs` + `classify.mjs` above have
// already produced the grant; this is a second, INDEPENDENT decode whose output no arm reads.
// Retention must not be able to move a verdict, and the cheapest way to guarantee that is for the
// verdict to be computed first and by a different decoder. A failure here is deliberately non-fatal
// for the same reason — losing an archive is bad, losing a measurement over an archive is worse.
//
// ⛔ AND IT IS THE WINDOWS LANE'S OWN PATH. `measure.sh` carries the Linux hook and this driver has
// never used `measure.sh`, so wiring retention on Linux left Windows with none.
if (process.env.NUB_V2_EVENTS_OUT || process.env.NUB_V2_ETW_RAW_OUT) {
  // The standalone header rides with the RAW, not with the derived view: it is what makes
  // `etw-raw.xml.gz` re-parseable on its own, so it is derived from the raw path and is absent
  // whenever the raw is.
  const RAW = process.env.NUB_V2_ETW_RAW_OUT;
  const rr = run(NODE, [path.join(HERE, 'adapters', 'windows-retain.mjs'), CAP,
    ...(RAW ? ['--raw-out', RAW, '--header-out', path.join(path.dirname(RAW), 'etw-header.json')] : []),
    ...(process.env.NUB_V2_EVENTS_OUT ? ['--out', process.env.NUB_V2_EVENTS_OUT] : []),
    // One definition of what a path means: the same capture.json the classifier read.
    '--capture', CAPTURE, '--pkg', PKG, '--version', VER]);
  const rrOut = ((rr.stdout ?? '') + (rr.stderr ?? '')).trimEnd();
  if (rrOut) console.log(rrOut.split('\n').map((l) => '  ' + l.replace(/^ {2}/, '')).join('\n'));
  if (rr.status !== 0) console.log(`  !! RETAIN failed rc=${rr.status} — the measurement stands, the archive does not`);
}

// ── 2c. THE VENUE MARKERS (PORTABILITY R3 + R6) ────────────────────────────────────────────────
//
// ⛔ TWO STDOUT LINES PER FACT IS THE WHOLE ADOPTION COST OF THIS CONTRACT. The driver MEASURES;
// `record.mjs` only learns. That keeps `record.mjs` platform-agnostic — it has never had to know a
// trace format and it does not have to know a store layout either — and it is why a platform adopts
// venue provenance by printing rather than by editing the shared recorder.
//
// ⛔ THE ARCHIVE IS COPIED BY PATH OFF THESE LINES. `record.mjs` copies `capture.json` from
// `RAWLOG-CAPTURE`; without this marker the Windows lane's roots — and the folded 8.3 map — would
// sit in the driver's run root and vanish with the runner, which is exactly the state R1 and R2
// exist to end. The Windows raw trace is published separately by `windows-retain.mjs` through
// `NUB_V2_ETW_RAW_OUT`, so only the capture header is announced here.
console.log(`  RAWLOG-CAPTURE ${CAPTURE}`);
// ⛔ WHICH BINARY ANSWERED THIS RECORD — the identity `nubGitSha` provably cannot give, and which
// win32 was not emitting at all. MEASURED across the corpus before adding this: linux-x64 carries
// `provenance.nubBinary` on 119/119 records, darwin-arm64 on 0/120, win32-x64 on 0/1, because only
// `measure.sh` emitted the marker `record.mjs` learns it from. `provenance.nubGitSha` is null on all
// 240 besides, so a win32 record named NOTHING about the binary that produced it.
//
// That is not bookkeeping. `corpus-v2-runner.yml` argued its prefix cache fallback was safe because
// "each record names the binary that answered it" — true on one lane, false on this one — and a
// pre-fix binary then measured a whole Windows run into unattributability (run 31145732202).
//
// ⛔ THE OVERRIDE FEATURE IS PROBED BY EXERCISING IT, NEVER BY GREPPING FOR ITS NAME, and
// `measure.sh` records why in full: Rust does not embed feature names, and the literal
// `build-jail-catalog-override` appears only in the error a binary built WITHOUT the feature prints.
// A content search therefore matches the BROKEN binary and misses the WORKING one — strictly worse
// than no check. Same inversion trap this lane has already been bitten by twice.
//
// The bytecode env name IS a real string constant (`BUILD_JAIL_BASELINE_ENV` in `preset.rs`), so a
// content search answers that one honestly.

// ⛔ THE TRACED CHILD'S OWN WORDS, WHICH THIS DRIVER ALREADY CAPTURED AND THEN THREW AWAY.
// `windows.ps1` spawns the traced process with `-RedirectStandardOutput (Join-Path $OutDir
// 'run.out')` and `-RedirectStandardError ... 'run.err'`, and this driver passes `-OutDir CAP`. So
// npm's own diagnosis is on disk for every run — and the rebuild-failure exit below never read it.
//
// MEASURED corpus-wide: 562 win32 `BROKEN-WITHOUT-JAIL-TOO` records carry a driver.out under 1200
// bytes with NO error output at all, just `rc=1`. "node-gyp cannot find MSVC", "the tarball 404s"
// and "the postinstall crashed" are exactly the distinctions this corpus exists to draw, and all
// 562 are unclassifiable without those words. darwin has never had the hole because
// `measure-macos.sh:687` tails `npm.log` on the same failure; this is the back-port, not a new idea.
//
// ⛔ HOISTED `function` DECLARATIONS, AND THE BOUNDS ARE INLINE LITERALS RATHER THAN `const`s BESIDE
// THEM — for the reason spelt out at `emitBinaryProvenance` below. The only call site is the
// rebuild exit ~360 lines ABOVE this point; a `const` here is in the temporal dead zone until this
// line executes, so naming the bounds would throw `ReferenceError` on precisely the early-exit path
// these functions exist to serve, and never on the normal path.
function readTracedLog(p) {
  // A capture that died before spawning leaves no `run.*` at all. Throwing here would convert a
  // clean BROKEN-WITHOUT-JAIL-TOO into a HARNESS-ERROR — trading a classifiable record for an
  // unclassifiable one, which is the exact direction this change exists to reverse.
  try { return fs.readFileSync(p, 'utf8'); } catch { return ''; }
}

// ⛔ A FUNCTION HERE, AND AN INLINE LOOP AT THE FETCH EXIT — THE ASYMMETRY IS DELIBERATE, so do not
// "unify" them. `fetch-diagnosis.test.mjs` scopes its assertions to the fetch block and requires the
// `slice(-20)` bound to appear INSIDE it, because a file-wide search for that idiom also matches
// `npm_ok`'s long-standing tail and would pass with the fix deleted. This exit cannot be inline: it
// reads two files that may not exist, so it needs the guarded read below, and the whole call must
// still fit on ONE line for `venue-provenance-on-exit.test.mjs`. Same prefix (`    | `) and same
// depth as that site, and as `measure-macos.sh`'s two tails, so the output shape is identical.
//
// ⛔ CALLERS APPEND STDERR LAST, AND THAT ORDERING IS LOAD-BEARING rather than an accident of
// concatenation: npm puts progress on stdout and its diagnosis on stderr, so a 20-line tail lands on
// the CAUSE instead of on twenty `npm http fetch GET 200` lines.
function emitFailureTail(text) {
  for (const l of String(text ?? '').trimEnd().split('\n').slice(-20)) {
    // ⛔ BOUNDED ON BOTH AXES. Twenty lines is not a bounded excerpt when one of them is a megabyte,
    // and on THIS platform that is the ordinary case rather than the pathological one — a node-gyp
    // failure prints the entire MSBuild invocation as a single line. The cap is what keeps the
    // reason legible in driver.out, which is the artifact the corpus actually retains.
    if (l.trim()) console.log(`    | ${l.length > 500 ? `${l.slice(0, 500)}…` : l}`);
  }
}

// ⛔ A HOISTED, IDEMPOTENT FUNCTION, BECAUSE THE EARLY EXITS NEED THIS TOO. This was an inline block
// here — which is AFTER both `BROKEN-WITHOUT-JAIL-TOO` exits — so every record taking one of those
// paths named NO binary at all. MEASURED on win32 shakeout round 1: `react-signature-pad-wrapper@1.3.1`
// and `@intlify/vue-router-bridge@0.1.0` both carry `nubGitSha: null` and no `nubBinary` key, while
// the control `ref-napi@3.0.3` (MINIMUM, full path) carries a full sha256.
//
// ⛔ AND THIS IS THE VERDICT WHERE ATTRIBUTION MATTERS MOST, which is what makes it worse than
// bookkeeping. `BROKEN-WITHOUT-JAIL-TOO` asserts "nub cannot build this at all" — true only OF A
// PARTICULAR BINARY. `ctrlc-windows@0.1.9` sat in exactly this bucket until the tarball symlink fix
// and installs cleanly after it. Without the hash you cannot tell which side of a fix a record was
// taken on, so the records most likely to FLIP were the ones least able to say what produced them.
//
// Only the binary identity is hoisted. `RAWLOG-CAPTURE` stays at its original site because `CAPTURE`
// is not defined until the arms have run, and an early-exit record has no capture to name.
// ⛔ THE FLAG LIVES ON THE FUNCTION, NOT IN A `let` BESIDE IT. A `function` declaration hoists
// fully, but a `let` in the same scope does NOT — it stays in the temporal dead zone until this
// line executes, which is ~370 lines BELOW the first call site. A module-scope `let` guard here
// would therefore throw `ReferenceError` on exactly the early-exit path this function exists to
// serve, and never on the normal path — a fix that breaks only the case it was written for.
function emitBinaryProvenance() {
  if (emitBinaryProvenance.done) return;
  emitBinaryProvenance.done = true;
  const probeCat = path.join(ROOT, 'nub-binary-probe.json');
  fs.writeFileSync(probeCat, '{"packages":{"__override_probe__":{"default":{"network":true}}}}');
  const pr = run(NUB, ['--version'], { env: { ...process.env, NUB_BUILD_JAIL_CATALOG: probeCat } });
  // ⛔⛔ POSITIVE EVIDENCE, NEVER SILENCE — the same predicate the two shell drivers carry, kept
  // identical on purpose (`override-probe-parity.test.mjs` asserts all three agree). This read
  // `pr.status === 0`, which infers the capability from the ABSENCE of an error and so reports
  // "present" for any binary that has never heard of the variable. MEASURED 2026-08-06 on eleven
  // binaries: a feature-ON nub prints `…catalog OVERRIDDEN from …` at rc=0, an aware-but-disabled
  // one exits 1 naming the feature, and nine binaries predating the seam exit 0 byte-identically to
  // a run with NO variable set. Only the marker separates the first from the last.
  //
  // A REJECTED banner counts as proof too: the file read fails before any schema parsing, so it
  // proves the feature is COMPILED IN without coupling this check to the catalog grammar. On this
  // driver the answer is provenance rather than a gate, but a false `true` here is what lets a
  // record claim it measured under an override it never had.
  const hasOverride = overrideProbeSaysHonoured(`${pr.stdout ?? ''}${pr.stderr ?? ''}`);
  let sha256 = null; let bytes = null; let hasBytecodeEnv = false;
  try {
    const b = fs.readFileSync(NUB);
    sha256 = crypto.createHash('sha256').update(b).digest('hex');
    bytes = b.length;
    hasBytecodeEnv = b.includes('PYTHONDONTWRITEBYTECODE');
  } catch { /* an identity we cannot read is reported as null, never guessed */ }
  console.log(`  VENUE-NUB-BINARY ${JSON.stringify({
    path: NUB,
    sha256,
    bytes,
    features: { buildJailCatalogOverride: hasOverride, pythonDontWriteBytecodeEnv: hasBytecodeEnv },
  })}`);
  console.log(`  VENUE-INTERPRETER ${NODE}`);
  // ⛔ WHICH NODE THIS VERSION *SHOULD* RUN ON, recorded while the pin is NOT yet binding. Paired with
  // `VENUE-INTERPRETER` above — the Node the arm actually used — a record carries both, which is the
  // only way to learn how often the era pick and the ambient Node DIFFER, and on which packages,
  // BEFORE the pin changes any verdict.
  //
  // ⛔ ALWAYS EMITS, EVEN ON FAILURE. An absent marker leaves `nodeSelection: null`, indistinguishable
  // from a deliberate no-pin — the ambiguity that let a v1 Linux run ship with `pinnedTo: null` on
  // every record. A registry hiccup must not silently become "no pin was intended".
  // ⛔ REUSES the module-scope selection computed before the arms ran; never recomputes it. A second
  // lookup could answer differently and the record would then name a Node the measurement did not
  // use. `pinned` is what distinguishes a pinned run from an unprovisioned box.
  console.log(`  VENUE-NODE-SELECTION ${JSON.stringify({
    ...ERA_NODE.selection,
    pinned: ERA_NODE.bin !== null,
    pinnedBin: ERA_NODE.bin,
    eraNodeRoot: ERA_NODE.root,
  })}`);
}
emitBinaryProvenance();
// ⛔ WHERE THE JAILED ARMS RAN, BECAUSE ON THIS PLATFORM THE ROOT PATH CAN DECIDE THE OUTCOME BY
// ITSELF. Any jail root under `C:\Users\<user>` fails before a single script runs — "could not
// evaluate ALL APPLICATION PACKAGES rights on …: The access control list (ACL) structure is
// invalid. (os error 1336)" — because that home carries seven inheritable `S-1-15-2-…` AppContainer
// package SIDs. MEASURED: only the root path changed between a failing and a passing run, and the
// pre-fix binary fails identically, so it is not a regression. A record that does not name its root
// cannot tell "this package needs more" from "this run could not build a token at all", and a
// venue comparison would read the second as the first.
console.log(`  VENUE-JAIL-ROOT ${ROOT}`);

// ⛔ R6: EVERY VARIABLE THIS DRIVER SET, UNSET OR REDIRECTED, WITH ITS VALUE — and `CI` listed with
// its INHERITED value precisely because touching `CI` is the one override that would invalidate the
// whole venue/CI acceptance test. Recording it unchanged is a claim a reader can check, where
// silence is a bet nobody can audit.
//
// ⛔ THE HARNESS NORMALISES ITS OWN APPARATUS AND NEVER THE ENVIRONMENT UNDER TEST. `npm_config_cache`
// is apparatus: a per-run npm cache gives OBSERVE the cold start a real user gets, without which a
// script that fetches its payload finds it already present and the trace records no `connect` at
// all — an under-predicted `network`, measured on purescript@0.15.9. `CI`, `GITHUB_ACTIONS` and
// `NODE_ENV` pass through verbatim, because an install script reads them and changes what it
// downloads or whether it builds from source; flattening them would produce a catalog that
// under-grants every CI user.
//
// ⛔ `set` IS THE `OBS_ENV` OBJECT ITSELF, NOT A LIST RETYPED BESIDE IT. Every value is recorded so a
// reader can check that the paths OBSERVE exported are the same ones `capture.json` declares as the
// `temp` and `jailHome` roots — if a pair ever disagrees, that bucket silently stops matching and its
// writes fall to `outside` or `userHome`, which is an under-grant in the first case and a lost
// `writePaths` derivation in the second. Retyping is how they come to disagree, and both hand-kept
// accounts had already drifted: `capture.json`'s `observeEnv` named `npm_config_cache` alone, and the
// paragraph that stood here said `TMP`/`TEMP` were NOT redirected while the object below set them.
//
// ⛔ `LOCALAPPDATA` IS THE ONE HOME-ADJACENT VARIABLE STILL NOT REDIRECTED, AND THAT MATCHES THE
// JAIL rather than diverging from it: `preset.rs` leaves it alone because the Windows LowBox launch
// resolves its AppContainer profile directory from it. Recorded with its inherited value so the
// choice is auditable rather than assumed.
console.log(`  VENUE-OVERRIDES ${JSON.stringify({
  set: OBS_ENV,
  // The CI-detection scrub is a NORMALISATION and is declared (R6).
  unset: CI_SCRUBBED,
  notRedirected: {
    LOCALAPPDATA: process.env.LOCALAPPDATA ?? null,
    why: 'LOCALAPPDATA is left alone deliberately, matching `compiler/preset.rs`: the Windows LowBox'
      + ' launch resolves its AppContainer profile directory from it, so repointing it breaks process'
      + ' creation rather than a cache path. HOME, USERPROFILE and APPDATA ARE redirected, to the'
      + ' `jailHome` root capture.json declares, exactly as compile_build_jail redirects them for a'
      + ' confined child.',
  },
  // Captured BEFORE the scrub; see CI_INHERITED.
  passedThrough: {
    CI: null, GITHUB_ACTIONS: null,
    NODE_ENV: process.env.NODE_ENV ?? null,
    ...CI_INHERITED,
  },
})}`);

// ── OBSERVE-ONLY: stop before any jailed arm. ──────────────────────────────────────────────────
//
// ⛔ THIS IS A HYPOTHESIS, NOT A MEASUREMENT, AND THE VERDICT SAYS SO. `record.mjs` files an
// `OBSERVE-ONLY` under `synthesized` with `grant` left null, so the collator cannot mistake it for
// a verified minimum. The mode exists because the venue-portability acceptance test compares what
// the OBSERVE half produces — the synthesized grant and the roots it was classified against — and
// on this platform every jailed arm currently fails at every grant on a read of the package's own
// store entry (see the note at the top of this file), so requiring a verified arm would make the
// portability question unanswerable for a reason that has nothing to do with portability.
if (OBSERVE_ONLY) {
  console.log(`  => OBSERVE-ONLY ${JSON.stringify(GRANT)}   (synthesized; this is a HYPOTHESIS, not a verified minimum)`);
  process.exit(0);
}

// ── 3. VERIFY — the real, UNPRIVILEGED jail. The only arm whose result may enter the catalog. ─
//
// `CACHE`/`STORE`/`TOOLS` are defined once, at 1c, because `capture.json` has to DECLARE the store
// and tools roots and the eviction here has to USE them. Two definitions of the same path is the
// drift hazard R1 exists to close: a capture and a driver that disagree about where the store is
// would produce a record whose roots do not describe the run it came from.
//
// The cache root mirrors `aube_store::dirs::cache_dir()`: `XDG_CACHE_HOME` wins on EVERY platform
// including Windows, and only then does `%LOCALAPPDATA%` apply. Reading LOCALAPPDATA alone would
// point the eviction at a directory the linker is not using the moment that variable is set, and it
// would no-op in silence — the failure shape this whole file is a monument to.

// ⛔⛔ EVICTING `PKG` ALONE IS NOT ENOUGH — THE REPLAY ALSO ARRIVES THROUGH A TRANSITIVE DEPENDENCY'S
// STORE ENTRY. A package already materialized in the machine-global store is RELINKED rather than
// reinstalled, so its lifecycle script never runs, and the arm then PASSES at whatever grant is
// under test — including one NARROWER than the package needs. That is an UNDER-GRANT, the one
// direction that breaks real users' installs.
//
// MEASURED on Linux, on `@apollo/rover@0.2.1`, whose postinstall writes into a SIBLING package's
// directory (`binary-install/bin/`, because it delegates to `binary-install`). In the jail that path
// resolves through a link out of rover's own store entry into `binary-install@0.1.1-<hash>`'s, which
// `preset.rs`'s `store_entry_write_root` deliberately does NOT grant. Three runs on one binary
// differing only in what was evicted:
//
//   evict rover only              {"network":true}                rc=0  bin/ EMPTY   -> false PASS
//   evict rover + binary-install  {"network":true}                rc=1  bin/ absent  -> correct FAIL
//   evict rover + binary-install  {"write":{"deps":true},...}     rc=0  bin/ rover,README.md,LICENSE
//
// ⛔ THE REPLAY IS A PROPERTY OF THE STORE LAYOUT, AND CI SILENTLY PICKS THE OTHER ONE. Under
// `is_ci()` nub resolves the linker to a PROJECT-LOCAL `.store` inside each arm directory
// (`install_report.rs` `layout_row`), so on a hosted runner there is no machine-global store, the
// eviction below skips in silence, and arms are independent by accident rather than by design.
// MEASURED in run 31106248877: four arms, zero EVICT lines, root-only and transitive
// indistinguishable. A real user is not in CI, so that is the layout this eviction is FOR — and it
// is also why a probe of this code has to set `enableGlobalVirtualStore` explicitly to measure
// anything at all.
//
// ⛔⛔ AND THE STORE IS SHARED WITH nub'S OWN TOOLING, SO A NAME-WILDCARD EVICTION AMPUTATES THE TOOL
// THE PACKAGE IS ABOUT TO BUILD WITH. nub bootstraps node-gyp lazily into a project under
// `<cache>/tools/node-gyp/<bucket>/` that links against THIS SAME store, and `semver`, `tar`,
// `which`, `graceful-fs` are ordinary members of a native package's own closure. MEASURED on
// `@pulumi/datadog@0.18.9` against the pre-fix Linux harness: every rung failed with `gyp ERR! stack
// Error: Cannot find module 'semver'` and ZERO jail refusals — a harness failure that reads as
// INSUFFICIENT, so the ladder climbs and the package lands WIDER than it needs.
//
// ⇒ Spare the entries nub's own tool projects resolve through, and read them by FOLLOWING THE LINKS
// under `tools/` rather than by matching the link directory's NAME: that name is `.store` on one
// binary and `.nub` on another, so a name match silently stops matching. Junctions are what Windows
// uses where Linux uses symlinks, so every entry is resolved with `realpathSync` and classified by
// WHERE it lands rather than by its dirent type, which reports a junction inconsistently.
//
// ⛔ SPARING CANNOT MANUFACTURE THE FALSE PASS THIS EVICTION EXISTS TO PREVENT. A spared entry could
// mask a refusal only if it carried build output from a prior arm, and nub's tool closure is pure-JS
// library code that declares no lifecycle scripts (re-verified on this platform — see
// `.github/workflows/win-evict-probe.yml`). The overlap is narrow besides: an entry is spared only at
// the exact `<name>@<version>-<hash>` nub's tooling pinned, so any other version of the same name is
// still evicted.
// ⛔ `evictClosure()` WAS DELETED, NOT DISABLED, when each arm gained its own virtual store. It is
// recorded here because the thing it was built for is real and a future reader will otherwise
// rebuild it: a package already materialized in a SHARED store is relinked rather than
// reinstalled, its lifecycle script never runs, and the arm then passes at whatever grant is under
// test — including one NARROWER than the package needs, which is an under-grant. MEASURED on Linux
// on `@apollo/rover@0.2.1`: evicting rover alone gave a false PASS at `{"network":true}` with an
// EMPTY `bin/`, while evicting rover plus `binary-install` correctly FAILED.
//
// Per-arm isolation answers that same hazard without a sweep — a fresh virtual store has nothing to
// relink — and without the partial-graph failure the sweep itself caused. Do not reintroduce it
// alongside isolation: it would evict entries from a store that is already empty and the only
// effect would be the `EVICT` log line.

// One `rc:shortfall-digest:ok|abs:missing-count` entry per grant-widening arm, appended by `verify`.
// Read once, at the foot of the ladder, to decide whether a shortfall responded to widening. Same
// field order and same reader as `measure.sh` and `measure-macos.sh` — the ledger is a cross-driver
// format, and this driver joins it rather than inventing a Windows-shaped one.
const ARM_LEDGER = [];

let armSeq = 0;
let storeLayoutReported = false;
// ⛔ SET FOR EXACTLY ONE ARM AND CLEARED IMMEDIATELY AFTER — the wide-but-confined probe below the
// ladder. It adds a catalog `baseline`, which is a DOCUMENT-level key, so an arm that carried it by
// accident would be running a different experiment from every other arm while reporting under the same
// rung. A module-scoped latch rather than a `verify` parameter, so this driver's shape matches the two
// shell drivers' `$ARM_CONFINED_WIDE` and every other arm's call site is untouched.
let armBaseline = null;
// `realHome` repoints the arm's REAL home — the directory `build_jail.rs::persist_declared_home_writes`
// promotes a declared `writePaths` entry INTO. Only the promotion probe passes it; every other arm
// leaves it undefined and inherits the ambient profile exactly as before.
const verify = (grant, label, { realHome = null } = {}) => {
  const v = path.join(ROOT, `verify-${label}`);
  fs.mkdirSync(v, { recursive: true });
  // The arm opts out of nub's resolve-time supply-chain gates. Full reasoning at the same point in
  // `measure.sh`; the short version is that they refuse during RESOLUTION, before any lifecycle
  // script exists to confine, so when they fire the jail question cannot be asked at all. A project
  // `.npmrc` rather than an env var, because the env form reaches npm and makes it warn on stderr.
  // ⛔ A UNIQUE PACKAGE NAME PER ARM. nub memoises a lifecycle script's outcome keyed on package
  // identity, so a reused name REPLAYS the previous arm's result with every precondition green.
  fs.writeFileSync(path.join(v, 'package.json'),
    JSON.stringify({ name: `r${armSeq++}${Date.now().toString(36)}`, version: '1.0.0', dependencies: { [PKG]: VER } }) + '\n');
  // ⛔ THE SIDE-EFFECTS MEMO IS TURNED OFF AT SOURCE, NOT ONLY SWEPT AFTERWARDS. Both POSIX drivers
  // have written this since their own bring-up (`measure.sh:647`, `measure-macos.sh:560`); this
  // driver had only the `rmSync` below, so the memo was its SINGLE point of failure.
  //
  // ⛔ AND THAT `rmSync` IS LOAD-BEARING, NOT BELT-AND-BRACES — MEASURED, by disabling it in a
  // mutated copy of this driver and re-running `@apollo/rover@0.2.1` at the too-narrow
  // `{"network":true}`:
  //
  //   memo purged (this driver today)   rc=1  artifacts=6/6
  //   memo KEPT                          rc=1  artifacts=7/6   <- the refused artifact came BACK
  //
  // The memo restored into a jailed arm the very file the grant had refused to let the script
  // produce. Only the non-zero `rc` stopped that arm being scored a pass, so the artifact gate on
  // its own was already fooled — a one-signal margin, and on a package whose script exits 0 despite
  // a refused write it would be a false PASS at a grant narrower than the package needs. That is an
  // under-grant, the direction this project forbids.
  //
  // Both defences are kept deliberately: the `.npmrc` stops an entry being written at all, the
  // `rmSync` clears anything a prior arm or another lane on this box already left.
  fs.writeFileSync(path.join(v, '.npmrc'), ARM_NPMRC);
  const cat = path.join(v, 'cat.json');
  // ⛔⛔ AN EMPTY GRANT CANNOT BE WRITTEN AS AN ENTRY, AND GETTING THIS WRONG SILENTLY DESTROYS THE
  // MODAL CASE. nub REJECTS a catalog entry that widens nothing -- "`default` widens nothing and
  // there are no version bands, so the entry grants exactly the base profile; drop it" -- and then
  // falls back to the COMPILED-IN catalog, so the arm trips the override assertion and comes back
  // VOID. VOID is not "insufficient", and a caller that cannot tell them apart ladders upward from
  // a hypothesis it never tested and publishes a spuriously WIDE minimum.
  //
  // MEASURED on Windows 2026-08-06: `husky@4.3.8` synthesizes `{}` and came back
  // `OVERRIDDEN=0 REJECTED=2` -- while husky's COMPILED-IN entry is `{"write":{"project":true}}`,
  // so the fallback arm measured that rather than the base profile and the record was unusable.
  // The POSIX driver already carried this fix (`yorkie@2.0.0`,
  // `@progress/kendo-licensing@1.9.1`: reported
  // `{"write":{"deps","project","userHome"},"network":true}`, verified `{}`); this driver never got
  // it. Roughly half the corpus synthesizes the empty grant, so unfixed this turns the modal case
  // into a near-total grant -- on Windows precisely the packages the junction gate fix was meant
  // to rescue.
  //
  // The fix follows from what the base profile already IS: nothing. The override REPLACES the
  // compiled-in table wholesale rather than merging into it (`compiler/curated.rs` `curated_table()`
  // returns a table built entirely from the override; `catalog_override.rs` `v2_grant_for()` is
  // `packages.get(package)?`, so an ABSENT package yields `None` and runs at the base profile). So
  // express the empty grant by OMITTING the package under test, and carry a sentinel entry under an
  // unrelated name purely so the override still engages and the assertion below stays meaningful.
  // ⛔ SHARED WITH THE OTHER TWO DRIVERS — see `dep-scaffold.mjs`. This driver carried the
  // target-only construction while `measure.sh` had already been fixed, so the dependency-grant
  // confound stayed live here.
  const { catalog, scaffolded } = buildCatalog(PKG, grant, OBS, armBaseline);
  fs.writeFileSync(cat, JSON.stringify(catalog));
  if (scaffolded) console.log(`  scaffold: ${scaffolded} dependency package(s) with lifecycle scripts granted a fixed wide grant`);

  // ⛔ A UNIQUE ROOT PACKAGE NAME IS NOT ENOUGH, AND NEITHER IS DROPPING THE SIDE-EFFECTS MEMO.
  // Both were tried and both FAILED to stop an arm replaying its predecessor's result. There are
  // three distinct carry-overs between arms and they must ALL be cleared, or an arm reports a
  // verdict it never measured while every precondition (OVERRIDDEN>=1, REJECTED==0) reads green:
  //
  //   1. the side-effects memo, keyed on the DEPENDENCY -- identical across arms by construction,
  //      so a unique ROOT name does not perturb it;
  //   2. the GLOBAL VIRTUAL STORE -- a package already built there is `materialized` by the linker
  //      and its lifecycle script is never re-run, which is the replay the memo drop did not catch;
  //   3. `pm/tools/npm-prefix` -- once any run creates it, a later arm's `mkdir` of it succeeds, so
  //      a first-run denial silently stops reproducing.
  //
  // MEASURED 2026-08-06 on iedriver@4.0.0: an arm that had produced rc=1 with an EPERM on that
  // mkdir replayed as rc=0 in 2.4s, twice, with the memo drop in place.
  //
  // ⛔ `NUB_CACHE_DIR` DOES NOT FIX THIS AND MUST NOT BE USED FOR IT. It was the obvious candidate
  // and it is wrong: under the nub embedder profile that variable is read via
  // `config_env("CACHE_DIR")` and governs the RESOLVER PRIMER cache only -- it does not relocate
  // the content-addressed store. MEASURED: with it set per arm, the arm dir ended with 0 files
  // while `%LOCALAPPDATA%\nub\pm\store` still served the package, so the arm looked isolated and
  // was not. Evict the store entries themselves, which are the only thing the linker consults --
  // PKG's and its whole measured closure's, per the note above `evictClosure`.
  // ⛔ NO `evictClosure()` AND NO MEMO SWEEP: this arm gets a FRESH virtual store instead, so both
  // are structurally unnecessary here. See the long note beside `CACHE_HOME` for the defect the
  // sweep produced and the measured cost of replacing it. `--cache-home` opts an arm back into a
  // SHARED store — `falsify.mjs`'s `wrong-warm`, whose whole subject is what a previous arm left
  // behind.
  const armCache = CACHE_HOME || path.join(v, '.cache');
  fs.mkdirSync(armCache, { recursive: true });
  // ⛔ THE INDEPENDENCE CLAIM, PRINTED, because a consumer has to be able to CHECK it and the old
  // `EVICT n` line no longer exists. `falsify.mjs` refused a run the moment isolation landed —
  // `evicted=-1`, "the store eviction has silently no-opped" — which was the right instinct keyed on
  // a mechanism that had been replaced. Same two-line contract the venue markers use: the driver
  // states the fact, the consumer learns it, and neither has to know the other's internals.
  // ⛔ REPORTS WHAT IS TRUE, NOT WHICH FLAG WAS PASSED. `--cache-home` is how `right` and
  // `wrong-warm` are pointed at the SAME directory, but `right` runs first and finds it EMPTY — so
  // keying the word on the flag would label `right` shared and fail it. The honest predicate is
  // whether this arm starts from an empty virtual store, which is also exactly what a consumer
  // wants to know.
  const armStore = path.join(armCache, 'nub', 'pm', 'store');
  let priorEntries = 0;
  try { priorEntries = fs.readdirSync(armStore).length; } catch { priorEntries = 0; }
  console.log(`  STORE   ${priorEntries === 0 ? 'isolated' : `shared (${priorEntries} entries carried in)`}`
    + ` virtual store at ${armCache}`);
  // Swept once the arm has a verdict, never before: the arm's own logs and artifact tree stay for
  // inspection, only the materialised store goes. Skipped entirely for a shared cache, whose next
  // reader is another arm.
  //
  // ⛔ A TIMED-OUT ARM IS DELIBERATELY NOT SWEPT. `spawnSync`'s deadline kills the direct child only,
  // so a jailed grandchild can still be running and holding handles under this directory — deleting
  // it would race a live process, and a hang is exactly the case whose leftovers someone needs to
  // look at. Those return paths skip the sweep for that reason, not by omission.
  const sweepArmCache = () => {
    if (KEEP_ARM_CACHE || CACHE_HOME) return;
    try { fs.rmSync(armCache, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }); } catch { /* a sweep failure must never cost a verdict */ }
  };
  // ⛔ `RUST_LOG=debug` IS LOAD-BEARING, NOT VERBOSITY — same reason `measure.sh` sets it.
  // `side-effects-cache: restored` is a `tracing::debug!` (`install/side_effects_cache.rs`) and is
  // the ONLY line that distinguishes a built arm from a replayed one. Without it the replay
  // assertion below cannot observe what it asserts on, which is why this lane was still running the
  // predicate `measure.sh` had already measured to be wrong.
  // ⛔ THE ERA PYTHON REACHES THE VERIFY ARMS TOO — see `unjailed-nub.mjs`'s `asIdentity`.
  const env = { ...process.env, PATH: ARM_PATH, ...(ERA_PYTHON ? { PYTHON: ERA_PYTHON } : {}), NUB_BUILD_JAIL_CATALOG: cat,
    XDG_CACHE_HOME: armCache, RUST_LOG: 'debug' };
  // ⛔ BOTH SPELLINGS, BECAUSE `sandbox_homes` READS `HOME` FIRST AND `USERPROFILE` ONLY AS A
  // FALLBACK. Setting one on a box where the other is present would leave nub promoting into the
  // ambient profile while this driver looked in the fresh directory — both arms would read ABSENT,
  // which scores UNPROVEN-CONTROL: safe, and a silent instrument failure reported as a package
  // property. The cache is untouched: `XDG_CACHE_HOME` is already per-arm above, and it is what the
  // jail derives its private home from, so the two roots move independently by construction here.
  if (realHome) { env.HOME = realHome; env.USERPROFILE = realHome; }
  // Resolve and materialize this arm's exact Nub tree with all lifecycle hooks disabled. The npm
  // OBSERVE tree is not interchangeable: the two resolvers may select different transitive versions.
  //
  // ⛔⛔ THIS PRE-STEP RUNS WITHOUT `RUST_LOG=debug`, UNLIKE THE ARMS BELOW. Debug is load-bearing
  // for them and pure noise here: the replay predicate reads `i.log` + `a.log` only, and nothing
  // reads this log except the failure dump beneath it. Under debug that dump is engine trace instead
  // of nub's error -- MEASURED on run 33299339164, where filtering ` DEBUG ` still left 30 lines of
  // hickory-resolver DNS records, because the CONTINUATION lines of a multi-line debug record carry
  // no level prefix. `measure-macos.sh` has never set it on this call. `delete` rather than a spread
  // of `RUST_LOG: undefined` -- both were measured to leave the key absent in the child, so this is
  // for the reader: the intent is removal, and it does not rest on how a runtime treats undefined.
  const resolveEnv = { ...env };
  delete resolveEnv.RUST_LOG;
  const safeResolve = run(NUB, ['install', '--ignore-scripts'],
    { cwd: v, env: resolveEnv, timeout: ARM_TIMEOUT_MS });
  fs.writeFileSync(path.join(v, 'security-resolve.log'),
    (safeResolve.stdout ?? '') + (safeResolve.stderr ?? ''));
  if (timedOut(safeResolve)) {
    console.log(`  => TIMED-OUT in safe Nub resolution after ${ARM_TIMEOUT_MS} ms -- no lifecycle script ran`);
    process.exit(3);
  }
  if (safeResolve.status !== 0) {
    console.log(`  => HARNESS-ERROR: Nub could not materialize the tree with --ignore-scripts (rc=${safeResolve.status}); no lifecycle script ran`);
    // ⛔ PRINT NUB'S OWN WORDS. This branch used to exit having said only the line above, which
    // names a symptom and no cause — the darwin blocker sat unexplained for a day on exactly that,
    // with the answer in a file on a runner that was torn down before anyone read it. Nub is
    // specific when it fails here, so the tail is the difference between a diagnosis and another
    // CI round. Kept identical in all three drivers on purpose.
    console.log("  ── nub's own words (tail of security-resolve.log) ──");
    // Drop the RUST_LOG=debug spew first; see the same dump in `measure.sh` for what it cost.
    console.log(((safeResolve.stdout ?? '') + (safeResolve.stderr ?? ''))
      .split(/\r?\n/).filter((l) => !/(^|\s)DEBUG\s/.test(l))
      .slice(-30).map((l) => '     ' + l).join('\n'));
    process.exit(1);
  }
  // Record the SUBJECT arm's materialized layout, never OBSERVE's npm layout and never a value
  // inferred from CI. The old Windows marker unconditionally said `hoisted` before any Nub arm ran,
  // while every arm actually uses Nub's isolated linker; it made the provenance field a confident
  // description of the wrong resolver. Latch only after a successful safe resolution so an early
  // failed arm cannot suppress the first real answer.
  if (!storeLayoutReported) {
    let targetIsLink = false;
    try { targetIsLink = fs.lstatSync(path.join(v, 'node_modules', ...PKG.split('/'))).isSymbolicLink(); }
    catch { /* `.store` below is the primary signal */ }
    const isolated = fs.existsSync(path.join(v, 'node_modules', '.store')) || targetIsLink;
    console.log(`  VENUE-STORE-LAYOUT ${isolated ? 'isolated' : 'hoisted'}`);
    storeLayoutReported = true;
  }
  securityScreen(`nub-${label}-resolved`, ['--tree', v]);
  // ⛔ THE ARM PATH'S TOOL BIN LIVES IN THE OBSERVE TREE, WHICH THIS ARM'S JAIL DOES NOT GRANT.
  // `OBS` is a SIBLING of `v`, and the jail grants `<project>\node_modules` — so a scaffolded tool
  // on `ARM_PATH` is refused at exec and the ladder repairs it with whichever rung happens to cover
  // the tree's location, not with the capability the package needs. Staged AFTER the tree exists and
  // BEFORE the measured install, which is the window measured to survive nub's prune.
  // `stage-arm-tools.mjs` carries the measurement and the two fixes that do NOT work.
  const staged = stageArmTools({ observeDir: OBS, armDir: v });
  if (staged.binDir) {
    env.PATH = stagedArmPath(env.PATH ?? '', OBS, staged.binDir);
    console.log(`  ${staged.marker}`);
  }
  const i = run(NUB, ['install'], { cwd: v, env, timeout: ARM_TIMEOUT_MS });
  fs.writeFileSync(path.join(v, 'i.log'), (i.stdout ?? '') + (i.stderr ?? ''));
  // spawnSync's timeout kills the DIRECT child only; a jailed grandchild can survive it. Report the
  // stage so the leak is visible rather than showing up later as a mystery CPU hog.
  if (timedOut(i)) {
    console.log(`  VERIFY[${label}] TIMED-OUT in \`install\` after ${ARM_TIMEOUT_MS} ms -- no verdict; check for surviving children`);
    return { ok: false, void: false, timedOut: true, stage: 'install', files: countFiles(v, isArmNoise), rc: null };
  }
  const a = run(NUB, ['approve-builds', '--all'], { cwd: v, env, timeout: ARM_TIMEOUT_MS });
  fs.writeFileSync(path.join(v, 'a.log'), (a.stdout ?? '') + (a.stderr ?? ''));
  if (timedOut(a)) {
    console.log(`  VERIFY[${label}] TIMED-OUT in \`approve-builds\` after ${ARM_TIMEOUT_MS} ms -- no verdict; check for surviving children`);
    return { ok: false, void: false, timedOut: true, stage: 'approve-builds', files: countFiles(v, isArmNoise), rc: null };
  }

  // ⛔ A MALFORMED OVERRIDE WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  // assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  const logs = ['i.log', 'a.log'].map((f) => fs.readFileSync(path.join(v, f), 'utf8')).join('\n');
  const ovr = (logs.match(/catalog OVERRIDDEN/g) ?? []).length;
  const rej = (logs.match(/REJECTED/g) ?? []).length;
  const files = countFiles(v, isArmNoise);
  const got = pkgManifest(v, PKG, VER);
  const missing = missingArtifacts(OBS_PKG, got);
  const rc = i.status === 0 ? (a.status ?? 0) : i.status;
  // ⛔ THE ARM MUST PROVE THE SCRIPT ACTUALLY RAN, because a replayed arm is indistinguishable from
  // a real one by rc and by every other precondition. A genuine first touch runs the lifecycle
  // script; a replay materializes from cache and never spawns it.
  //
  // ⛔⛔ THIS CHECK USED TO FALSE-FIRE, AND THE WAY IT FAILED IS INSTRUCTIVE. It required
  // `installed \d+ package` in `i.log`, and was wrong on two counts:
  //
  //   1. THAT IS ONE OF TWO SUMMARY SHAPES, NOT THE SUMMARY. nub prints
  //      `✓ installed N packages in Xs` for a small install and
  //      `✓ resolved N · reused N · downloaded N … in Xs` for a larger one, so the predicate held
  //      or failed on which shape the package COUNT happened to produce rather than on whether
  //      anything ran. MEASURED on this box: `iedriver` (1 dep) printed `✓ installed 1 package in
  //      6.5s` and passed; `electron-chromedriver` (70 deps) printed the resolved/reused form and
  //      was flagged — while its install had demonstrably run (`downloaded 34`, and a
  //      `running build scripts for electron-chromedriver@33.4.9` line).
  //   2. IT READ ONLY `i.log`. Lifecycle scripts also run under `approve-builds`, whose output is
  //      `a.log`, so evidence sitting there was invisible.
  //
  // ⛔ THE FALSE POSITIVE WAS NOT HARMLESS: it flagged the ONE arm in that batch whose verified
  // result refuted a standing prediction, and a reader trusting the warning would have discarded
  // exactly the measurement that mattered. Keying on a summary line was always indirect; the fix
  // keys on the line that DIRECTLY evidences a script being invoked, across both logs.
  //
  // ⛔⛔ AND THAT FIX WAS ALSO WRONG — MEASURED ON THE LINUX LANE, WHICH HAD ALREADY RETIRED IT.
  // `running build scripts for` comes from `install/lifecycle.rs` and is printed ONLY for a
  // DEFAULT-TRUSTED package. Everything else prints `ignored build scripts for N package(s)` and
  // runs later under `approve-builds`, which prints NEITHER line. `measure.sh` records both
  // directions measured: `es5-ext@0.10.64` (cold, approved, genuinely rebuilt) produced 0
  // occurrences and FALSE-FIRED, while `msgpackr-extract@3.0.4` (genuinely RESTORED from cache)
  // produced 1 and STAYED QUIET. A predicate that is both noisy and blind is worse than none — it
  // trains a reader to ignore the one warning that would have mattered. It fired on all four arms
  // of `postman-code-generators@0.2.4`, which is how this was noticed.
  //
  // The predicate below is the one `measure.sh` kept, and it is an ASSERTION ON AN EXISTING GUARD
  // rather than a discovery instrument: every arm writes `side-effects-cache=false` into its own
  // `.npmrc`, so this line should NEVER appear. It fires only if that guard regresses. Its green is
  // correspondingly narrow — it means "the side-effects cache did not restore", not "no replay
  // happened"; the store-eviction and unique-root paths have their own guards.
  if (/side-effects-cache: restored/.test(logs)) {
    console.log('     ⛔ REPLAY CONFIRMED -- nub restored this package\'s build output from the');
    console.log('        side-effects cache, so the script did NOT run in this arm and its result');
    console.log('        is not a measurement. side-effects-cache=false did not take effect here.');
  }
  // `files/OBS_FILES` stays printed for continuity with the existing corpus logs, but it is
  // DIAGNOSTIC ONLY -- see the pkgManifest comment for why those two numbers are incomparable.
  // The shortfall's IDENTITY, over the full missing list including the sizes rather than the count:
  // two arms each missing one DIFFERENT file both read `missing=1`, which is a varying shortfall
  // reported as an invariant one. Printed as well as recorded so a corpus log is auditable against
  // the ledger, and in the position `falsify.mjs`'s `VERIFY[at-grant]` regex already allows for it.
  const shortfall = shortfallDigest(missing);
  console.log(`  VERIFY[${label}] rc=${rc} artifacts=${got ? got.size : 'ABSENT'}/${OBS_PKG.size} missing=${missing.length} shortfall=${shortfall} (tree ${files}/${OBS_FILES}) OVERRIDDEN=${ovr} REJECTED=${rej} grant=${JSON.stringify(grant)}`);

  // A failing arm prints its INSTALLER errors, because `v` is swept and the driver's stdout is what
  // survives as `driver.out` beside the record. An audit of 1963 failing records found only 448 that
  // could say WHY they failed, and all 448 were darwin — because that driver alone happened to tail an
  // observe log. This makes the same evidence deliberate and identical on all three drivers.
  //
  // ⛔ FILTERED, NOT TAILED: these arms run under `RUST_LOG=debug`, so a blind tail returns engine trace
  // and buries the installer's own message. Verified against a debug-heavy log — a tail gave 12 lines of
  // linker noise where the filter gave the `command not found` and `gyp ERR!` lines that explain it.
  // Bounded on purpose: a record is evidence, not an archive, and this runs for every failing arm.
  if (rc !== 0) {
    for (const f of ['i.log', 'a.log']) {
      let text;
      try { text = fs.readFileSync(path.join(v, f), 'utf8'); } catch { continue; }
      const hits = text.split(/\r?\n/).filter((l) =>
        /npm ERR!|gyp ERR!|command not found|No such file or directory|Error:|EACCES|EPERM|ENOTFOUND|ETIMEDOUT/.test(l));
      for (const l of hits.slice(0, 12)) console.log(`     [${label}/${f}] ${l}`);
    }
  }
  if (missing.length) console.log(`     missing artifacts: ${missing.slice(0, 6).join(', ')}${missing.length > 6 ? ` (+${missing.length - 6})` : ''}`);
  // ── Ledger for the grant-INDEPENDENCE test at the foot of the ladder. See the ARTIFACT-GATE-SUSPECT
  // block there for what it decides. Only the arms that actually WIDEN the grant are recorded, and
  // `at-grant` is excluded because DIRECT mode never reaches the ladder. (There is no `diag` arm on
  // this driver; the POSIX exclusion lists carry one because they re-run the failing grant under a
  // tracer, which would let a repeated point pose as corroboration.)
  //
  // ⛔ A TIMED-OUT ARM CONTRIBUTES NOTHING, AND THAT IS CORRECT RATHER THAN AN OVERSIGHT. Both
  // timeout paths return above this line, before a manifest exists — and a hang is not evidence about
  // the grant, which is why the ladder abandons on one instead of continuing. `classify` would refuse
  // the short ledger anyway; this just means it never sees a fabricated arm.
  //
  // ⛔ `abs` IS ITS OWN STATE AND MUST NOT COLLAPSE INTO `ok`. `missingArtifacts` returns
  // `['<package absent>']` when the package is not installed at all, so an absent package would
  // otherwise look like a stable one-file shortfall repeated at every rung — "invariant" only in the
  // sense that nothing happened four times. `classify`'s safety clause refuses it by this field.
  if (label !== 'at-grant') {
    ARM_LEDGER.push(`${rc}:${shortfall}:${got ? 'ok' : 'abs'}:${missing.length}`);
  }
  // ⛔ A SCRIPT THAT NEVER LAUNCHED MEASURED NOTHING — the same outcome as a non-engaging override.
  // Its tree is byte-identical to one whose script spawned and died on its first statement, so
  // without this the two are indistinguishable downstream. MEASURED on `postman-code-generators`:
  // fb0 (ran, died on its first `shell.exec`) and fb1 (never spawned -- the `read:"disk"` rung
  // fails the launch with ERROR_INVALID_PARAMETER) both reported shortfall `f648aa40f798`, and the
  // grant-independence test read that agreement as signal. Shared predicate in `never-spawned.mjs`.
  if (neverSpawned(logs)) {
    console.log('     !! the lifecycle script never LAUNCHED -- arm is VOID (nothing was measured)');
    sweepArmCache(); return { ok: false, void: true, files, rc };
  }
  if (!(ovr >= 1 && rej === 0)) { console.log('     !! override did not engage -- arm is VOID'); sweepArmCache(); return { ok: false, void: true, files, rc }; }
  sweepArmCache();
  // Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  // failure mode. Compare the MEASURED PACKAGE's artifact manifest against what the unjailed
  // OBSERVE arm produced for that same package.
  return { ok: rc === 0 && missing.length === 0, void: false, files, rc };
};

// ── DIRECT MODE: one arm at the caller's grant, no synthesis and no ladder. ───────────────────
// OBSERVE still had to run, and must: the artifact gate needs its file manifest as the reference
// for "did this arm produce what an unjailed install produces". Only OBSERVE's synthesized GRANT is
// bypassed here, which is the point — nothing the tracer missed can enter this verdict.
if (AT_GRANT) {
  const g = JSON.parse(AT_GRANT);
  console.log(`  -- DIRECT: does ${PKG}@${VER} install under EXACTLY ${JSON.stringify(g)} ?`);
  const r = verify(g, 'at-grant');
  if (r.void) {
    console.log('  => VOID -- the override did not engage; NOTHING was measured.');
    console.log('     Not a result. Do NOT record it, and do NOT read it as insufficient.');
    process.exit(3);
  }
  if (r.timedOut) { console.log(`  => TIMED-OUT (${r.stage}); no verdict -- a hang says nothing about the grant`); process.exit(3); }
  if (r.ok) { console.log(`  => SUFFICIENT ${JSON.stringify(g)}   (installed, artifacts matched OBSERVE)`); process.exit(0); }
  console.log(`  => INSUFFICIENT ${JSON.stringify(g)}   (the package needs MORE than this grant)`);
  process.exit(1);
}

// ── 3a. DESCEND — is the VERIFIED grant MINIMAL, or was it wider than the package needs? ──────
//
// ⛔⛔ CALLED FROM THE LADDER PATH TOO, AND THAT IS THE POINT OF EXTRACTING IT. This ran only under
// `if (synth.ok)`, so a record reached via the LADDER was published at whichever rung happened to
// pass, with `minimality` unproven by construction. The ladder rungs are BUNDLES — rung 0 is
// `write:{deps,project,userHome}` — so that record granted three capabilities on the strength of
// one arm that could not say which of them was needed. MEASURED on the first win32 record ever
// produced, `iedriver@4.0.0`: synth `{"write":{"deps":true},"network":true}` failed 9/11 artifacts,
// rung 0 passed 15/11, and the record carried `write.userHome` — the PERSISTENCE capability — with
// nothing in the run saying whether it was one of the three.
//
// ⛔ AND EXCLUDING SUCH A RECORD IS THE WRONG REPAIR, in the direction this project forbids. A
// ladder grant is WIDE; publishing it means the install works with minimality unproven, while
// dropping it leaves the package with no entry at all, running at the base profile — a BROKEN
// install, and precisely for the packages OBSERVE cannot predict. Over-granting is safe;
// under-granting breaks installs. So the ladder descends instead of being withheld.
//
// `verifiedBy` stays the discriminator between the two provenances: `record.mjs` reads
// `ladder fallback` off the verdict line, and `applyGrantSourceRule` narrows from `out.grant` —
// which for a ladder record IS the rung, not the synthesized value — so the recomputation is
// already correct for this path with no change on that side.
const descend = (g0, provenance) => {
  // The word the fall-back messages use for "the grant we keep when a narrowing is unproven". On the
  // synth path that is the synthesized value; on the ladder path it is the RUNG, and calling a rung
  // "synthesized" in a log a reader is using to audit a `write.userHome` grant would misdescribe
  // where it came from.
  const kept = provenance === 'ladder' ? 'ladder-rung' : 'synthesized';
  // ── 3a. DESCEND — is the verified grant MINIMAL, or did OBSERVE over-predict? ────────────────
  //
  // ⛔ THE DESCENT MATTERS MORE ON WINDOWS THAN ANYWHERE ELSE, because win32 OBSERVE is the least
  // trustworthy of the three tracers: Kernel-File's Create carries no DesiredAccess, so read-vs-write
  // intent is inferred from the disposition, and a non-filesystem, non-network denial is invisible to
  // the session entirely. The verify-side descent is therefore not parity garnish — it is the
  // compensating evidence that makes a win32 record mean anything. Synthesis-only is weakest exactly
  // where synthesis is weakest.
  //
  // ⛔ DROP ONE CAPABILITY AND RE-VERIFY IN THE SAME REAL JAIL. That is the only honest
  // over-prediction measurement available and it needs no oracle: comparing against a v1 record
  // answers nothing, because v1 is a blind pass/fail ladder that can only say "insufficient", never
  // WHAT was missing, and it carries every defect live when it was taken. One leave-one-out level,
  // deliberately NOT a lattice search — the point is to characterise the synthesis, not to re-derive
  // a minimum by searching, which is what v1 did.
  //
  // ⛔ EACH ARM IS A FULL `verify()` CALL, so it inherits the store eviction, the unique root package
  // name, the catalog override and the override assertion. An arm run any cheaper than the verdict
  // arm would not be comparable to the verdict arm.
  //
  // ⛔ THE VARIANT NAMES ARE `no-network` / `no-write-<scope>` AND THE SPELLING IS A CONTRACT, not a
  // label. `record.mjs`'s `applyGrantSourceRule` recomputes the descended grant by matching exactly
  // these names against `overPredictedBy`; a name it cannot parse yields a "descended" grant
  // identical to the synthesized one, so the record would claim it narrowed while publishing the wide
  // value.
  //
  // ⛔⛔ AND THE LIST IS NO LONGER BUILT HERE. `descent-terms.mjs` owns the vocabulary for all three
  // drivers — three inline copies of this generator is how `measure.sh` came to emit the bare
  // `network` / `write.deps` names for the life of its descent while this file spelled them `no-*`.
  //
  // ⛔ IT IS ALSO WHERE win32's TERMINAL-RUNG ANSWER LIVES, AND THAT ANSWER IS `UNSUPPORTED`. At
  // `write:"disk"` this platform takes `windows.rs`'s `if policy.build_jail && !confine_fs` branch:
  // no LowBox token, `Degradation::full()`, and `net` pushed onto `lost` — "egress is an AppContainer
  // CAPABILITY here (`internetClient`), so declining the token declines the net axis with it". So a
  // `no-network` arm here could not go RED for a network reason: the child holds unrestricted egress
  // whether the grant admits it or not. It would go green, the record would narrow to
  // `{"write":"disk"}`, and the catalog would then state that a package which used the network freely
  // does not need it — a vacuous pass turned into an under-grant. The module refuses to run it and
  // prints why.
  //
  // ⛔⛔ `'win32'` IS PASSED RATHER THAN LEFT TO `process.platform`, AND OF THE THREE DRIVERS THIS IS
  // THE ONE WHERE IT MATTERS. The other two, asked the wrong platform, lose an arm and publish a
  // wider grant — the safe direction. This one asked `darwin` or `linux` would GAIN a `no-network`
  // arm that cannot go red, pass it vacuously, and narrow the record to `{"write":"disk"}` for a
  // package that used the network freely: an under-grant, arrived at through the instrument that
  // exists to prevent one. The grant is enforced by the WINDOWS backend on every run of this driver,
  // so the platform is a property of the driver rather than of the host executing it.
  const variants = descentTerms(g0, WIN32).terms.map((t) => [t]);
  // Shadows the imported applier to keep this function's call sites unchanged. `narrowGrant` THROWS
  // on a drop it cannot genuinely apply rather than returning a grant that merely looks narrowed —
  // the old local closure did `delete g.write[k]`, which on a STRING `write` silently changes nothing
  // and would have run the UNNARROWED grant as the arm.
  const narrow = (drop) => narrowGrant(g0, drop);

  const dropped = [];
  const inconclusive = [];
  if (!variants.length) {
    // ⛔ TWO EMPTY CASES, TWO SENTENCES. `record.mjs` reads "grant is already empty" as
    // `minimality: MINIMAL`, which is honest for a grant with no capabilities and a fabrication for
    // `{"write":"disk","network":true}` — the widest grant in the corpus, published as PROVEN MINIMAL
    // off a descent that ran zero arms. `verdictLines` picks the right one and carries the per-axis
    // reason in a JSON marker.
    for (const l of verdictLines(g0, WIN32)) console.log(l);
  } else {
    for (const [name] of variants) {
      const sub = narrow([name]);
      const r = verify(sub, `nar-${name}`);
      // ⛔⛔ THREE OUTCOMES, AND COLLAPSING THEM TO TWO IS THE BUG. A VOID arm measured NOTHING — the
      // override did not engage, so nub silently ran the COMPILED-IN catalog — and an
      // `if (ok) … else NECESSARY` reads that as necessity. That manufactures evidence a capability
      // is needed out of an arm that measured nothing, in the direction that HIDES over-prediction,
      // which is the direction we are least able to detect by other means. A TIMEOUT is the same
      // shape: a hang says nothing about the grant.
      if (r.void) {
        console.log(`     ⛔ INCONCLUSIVE for '${name}' — the arm was VOID, so nothing was measured; NOT evidence of necessity`);
        inconclusive.push(name);
      } else if (r.timedOut) {
        console.log(`     ⛔ INCONCLUSIVE for '${name}' — the arm TIMED OUT in ${r.stage}; a hang says nothing about the grant`);
        inconclusive.push(name);
      } else if (r.ok) {
        console.log(`     ⛔ OVER-PREDICTED — the strictly narrower ${JSON.stringify(sub)} also verifies; '${name}' was not needed`);
        dropped.push(name);
      } else {
        console.log(`     '${name}' is NECESSARY — dropping it fails to verify`);
      }
    }
    // ⛔ WITHOUT THIS LINE A FULLY-MINIMAL RECORD CANNOT SAY SO. `record.mjs` sets `minimality` from
    // `=> MINIMAL`; a driver that printed nothing when every narrowing failed recorded the STRONGEST
    // possible descent result — every capability independently proven necessary — as `null`,
    // indistinguishable from a descent that never ran. That already bit the macOS port.
    if (!dropped.length && inconclusive.length) {
      console.log(`  => DESCENT INCOMPLETE — no capability dropped, but ${inconclusive.join(' ')} was never measured; MINIMALITY IS UNPROVEN`);
    } else if (!dropped.length) {
      console.log(`  => MINIMAL — every capability in ${JSON.stringify(g0)} is independently necessary`);
    }
  }

  // ⛔ THE JOINT ARM. The descent is LEAVE-ONE-OUT, so N droppable capabilities give N arms proving
  // each drops ON ITS OWN and nothing proving they drop TOGETHER. The joint grant is strictly
  // narrower than any arm that ran, so publishing it off the individual results would be an
  // INFERENCE dressed as a measurement — in the under-grant direction. One extra arm converts it
  // into a real one, and only when there is something to convert: N<2 needs no joint arm, because
  // the single leave-one-out arm IS the joint case. `record.mjs` keeps the wider synthesized value
  // for N>=2 unless it sees `JOINT-NARROW VERIFIED`.
  if (dropped.length >= 2) {
    const joint = narrow(dropped);
    const r = verify(joint, 'joint-narrow');
    if (r.void || r.timedOut) {
      console.log(`  => JOINT-NARROW INCONCLUSIVE — the arm was ${r.void ? 'VOID' : 'TIMED-OUT'}, so the joint drop is unmeasured;`);
      console.log(`     the record keeps the wider ${kept} grant, which is the safe direction.`);
    } else if (r.ok) {
      console.log(`  => JOINT-NARROW VERIFIED ${JSON.stringify(joint)} — all ${dropped.length} capabilities drop TOGETHER, measured`);
    } else {
      console.log(`  => JOINT-NARROW FAILED ${JSON.stringify(joint)} — each capability drops alone but not together;`);
      console.log(`     the leave-one-out results stand and the record keeps the ${kept} grant.`);
    }
  }
};

// ── THE PROMOTION PROBE — the one axis the descent above structurally cannot ask about. ───────
//
// ⛔⛔ `writePaths` GRANTS NOTHING, SO NO ARM ABOVE THIS LINE COULD EVER HAVE GONE RED ON IT.
// `catalog_v2.rs`: `write_paths` "cannot decide whether a write SUCCEEDS, only whether the result is
// KEPT". `rc` cannot fail for a dropped entry, `artifact-gate.mjs` only walks the package's own
// directory, and this platform takes no jailed trace at all so there is no denial witness either. A
// `{"writePaths":[…]}` grant flattens to ZERO capability tokens in `publish-guard.mjs`, so
// `hasRedArm` is false by construction and every narrowing to such a grant is withheld.
//
// ⛔ AND THIS IS THE PLATFORM WHERE THAT BITES HARDEST, BECAUSE THE PRIVATE HOME ONLY JUST ARRIVED
// HERE. Until this driver declared it, the lane derived NO `writePaths` at all — 0 of 2,270 win32
// records against 284 on POSIX — so every home write bucketed `userHome` and the records carry the
// whole-home grant. The narrowings that declaration unlocks are exactly the ones the guard withholds.
//
// ⛔ THE PROBE IS RUN HERE, NOT DECLARED UNSUPPORTED. `persist_declared_home_writes` says "WINDOWS
// PROMOTES THROUGH THIS SAME BODY … What was actually missing was a call site", and that call site
// now exists — but the binary a given run measured may predate it, and a hardcoded platform list
// would be a claim about the binary rather than a measurement of it. The control arm IS that
// measurement: on a nub that does not promote here it comes back ABSENT and the pair scores
// UNPROVEN-CONTROL, which licenses nothing.
const promotionProbe = (grant) => {
  const plan = probePlan(grant);
  if (!plan.supported) {
    for (const l of probeVerdictLines('win32', grant, plan, scoreProbe(plan, {}))) console.log(l);
    return;
  }
  let arms;
  // The drop grant comes from `descent-terms.mjs`'s shared applier, which THROWS rather than
  // returning a grant that merely looks narrowed. A refusal means no probe, never a guessed one.
  try { arms = probeArms(grant, narrowGrant); } catch (e) {
    console.log(`  !! PROMOTION PROBE SKIPPED — ${e.message}`);
    return;
  }
  console.log('  probing the promotion: the same grant with and without its `writePaths` declaration');
  const observed = {};
  for (const [label, g] of arms) {
    const home = path.join(ROOT, `promo-${label}-home`);
    fs.rmSync(home, { recursive: true, force: true });
    fs.mkdirSync(home, { recursive: true });
    // ⛔ THE ARM'S rc IS DELIBERATELY NOT READ. A failed control arm produces no directory and the
    // gate reports UNPROVEN-CONTROL on its own; reading rc here would add a second, differently
    // scoped verdict for the same fact, and the two would eventually disagree.
    verify(g, `promo-${label}`, { realHome: home });
    observed[label] = observeHome(home, plan.entries, { fs, path });
  }
  for (const l of probeVerdictLines('win32', grant, plan, scoreProbe(plan, observed))) console.log(l);
};

const synth = verify(GRANT, 'synth');
// ⛔⛔ THE VERDICT ARM'S VOID CASE MUST ABORT, NOT LADDER. A VOID synth arm measured the COMPILED-IN
// catalog, so falling through to the ladder walks upward from a hypothesis that was never tested and
// publishes whichever rung happens to pass as this package's MINIMUM.
if (synth.void) {
  console.log('  => VOID -- the override did not engage on the verdict arm; NOTHING was measured.');
  console.log('     Not a result. Do NOT record it, and do NOT read the absence of a verdict as a wide grant.');
  process.exit(1);
}
// A timeout is not evidence that the grant was too narrow, so the ladder must NOT be walked from
// here -- widening after a hang would manufacture a wider "minimum" than the package really needs.
if (synth.timedOut) { console.log(`  => TIMED-OUT at the synthesized grant (${synth.stage}); no verdict, and the ladder is NOT walked`); process.exit(3); }
if (synth.ok) {
  console.log(`  => MINIMUM ${JSON.stringify(GRANT)}   (observed, then verified)`);
  descend(GRANT, 'synth');
  promotionProbe(GRANT);
  process.exit(0);
}

// ── 4. FALL BACK — the ladder, walked UPWARD FROM the synthesized grant. ──────────────────────
// ⛔ On Windows the last rung is not a wider grant. `write:"disk"` DECLINES the AppContainer/LowBox
// token altogether, which drops the filesystem axis and the network axis together (egress is the
// `internetClient` AppContainer capability). So a package that only passes at `write:"disk"` may be
// failing for a TOKEN-compatibility reason no path grant can fix -- the ladder cannot tell those
// apart, which is why the per-rung file counts are printed rather than only the verdict.
// A single-variable A/B between two BINARIES needs only the synthesized arm; walking the ladder
// afterwards costs three more full installs and answers a different question.
if (argv.includes('--synth-only')) { console.log('  => SYNTH-ONLY: stopping before the ladder'); process.exit(4); }
console.log('  synthesized grant did not verify -- falling back to a bounded ladder');
const LADDER = [
  { write: { deps: true, project: true, userHome: true }, network: true },
  { write: { deps: true, project: true, userHome: true }, read: 'disk', network: true },
  { write: 'disk', network: true },
];

// ── THE WIDE-BUT-CONFINED PROBE — the measurement the note above says the ladder cannot make. ──
//
// The last confined rung's grant, widened by a catalog `baseline` of concrete read-write directories.
// A baseline entry compiles to an ordinary ALLOW under the build jail's `default_effect = Deny`
// (`preset.rs`, `build_jail_surface`), so `fs_confines(fs) = default_effect != Allow ||
// !entries.is_empty()` -- the SAME predicate in all three backends (`windows.rs`) -- stays TRUE and the
// LowBox token is NOT declined. Only `write:"disk"` reaches `relax_fs_to_full_disk`, which is what
// sets `default_effect = Allow` and takes the token, the fs axis and the net axis together.
//
// ⛔⛔ THE WINDOWS ANSWER IS BOUNDED, AND THE BOUND IS OWNERSHIP RATHER THAN THE TOKEN. `.frizz/
// sandbox-MECHANISM-FACTS.md` §5l (2026-08-01, runs 30688900451 / 30689267117 / 30689583039, both
// images, FAILURES=0) measured an AppContainer holding a BROAD filesystem grant: the token SURVIVES a
// wide grant, so "a wide grant kills the LowBox token" is false. What bounds the grant is what the
// unprivileged caller can install an ACE on -- `C:\`, `C:\ProgramData`, `C:\Users` and
// `C:\Users\Public` all return ERR 5 on the DACL write, and `C:\Program Files` and `C:\Windows` refuse
// it even ELEVATED because TrustedInstaller owns them. The measured ceiling is `%USERPROFILE%` and
// below plus anything nub creates, and the last confined rung's `write.userHome` already covers most
// of it. So on win32 a PASS still proves the package is confinable, while a FAIL does NOT separate a
// token problem from a path problem -- the paths that would settle it were never grantable. That is
// carried in the marker as `interpretation: "bounded"` rather than left for a reader to infer.
//
// ⛔ A PROBE, NOT A RUNG, WHICH IS WHAT MAKES IT FAIL-CLOSED. Its widening comes from a GLOBAL
// baseline and the shipped per-package grant vocabulary has no spelling for one (`catalog_v2::Reach`
// is `None | Scopes | Disk`), so publishing a grant it passed at would hand the catalog an entry
// NARROWER than the package was measured to need. It records and returns; the terminal rung below
// still decides the published grant, exactly as it did before this existed.
const confinedWideProbe = () => {
  const baseline = confinedWideBaseline();
  // A platform with no probe set records nothing rather than a fabricated verdict.
  if (!baseline) return;
  console.log(`  probing the widest write scope that still CONFINES (${interpretation()} on this platform)`);
  armBaseline = baseline;
  let r;
  try { r = verify(LADDER[1], 'cw'); } finally { armBaseline = null; }
  // ⛔ VOID IS ITS OWN ANSWER AND MUST NOT COLLAPSE INTO `fail`. A VOID arm measured the COMPILED-IN
  // catalog, so it says nothing about a wide confined grant; reading it as `fail` would publish "this
  // package cannot run confined" off an arm that never ran the experiment. A TIMEOUT is the same
  // shape -- no evidence either way -- and is likewise not a `fail`.
  console.log(confinedWideMarker(r.void || r.timedOut ? 'void' : r.ok ? 'pass' : 'fail'));
};

for (const [i, g] of LADDER.entries()) {
  // Between the last confined rung and the unconfined one -- i.e. only once every confined rung has
  // already failed, so the probe costs an install exactly on the packages whose grant is in question.
  if (g.write === 'disk') confinedWideProbe();
  const r = verify(g, `fb${i}`);
  // ⛔ A VOID RUNG IS NOT A FAILED RUNG, AND `continue` IS THE BUG. Collapsing the two makes the
  // ladder CLIMB PAST a grant it never tested and publish the NEXT one as the minimum -- an
  // over-grant on the strength of no measurement, in the direction we are least able to detect by
  // other means. The empty-grant construction above removes the commonest route to a VOID arm but
  // not the others (a malformed grant, a binary built without the override feature, a crash before
  // the log line), so the ladder still has to refuse to continue rather than assume.
  if (r.void) {
    console.log(`  => VOID rung ${i} -- the override did not engage, so NOTHING was measured here.`);
    console.log('     The ladder cannot continue honestly; not a result, and not evidence of a wider need.');
    process.exit(3);
  }
  if (r.timedOut) { console.log(`  => TIMED-OUT on ladder rung ${i} (${r.stage}); the ladder is abandoned rather than continued`); process.exit(3); }
  if (r.ok) {
    console.log(`  => MINIMUM ${JSON.stringify(g)}   (ladder fallback; synthesized grant was insufficient)`);
    console.log(`  !! OBSERVE UNDER-PREDICTED -- the gap between ${JSON.stringify(GRANT)} and this is what the trace missed`);
    if (g.write === 'disk') console.log('  !! last rung is write:"disk" = NO CONFINEMENT on Windows; a token problem and a path problem look identical here');
    // ⛔ THE RUNG IS A BUNDLE, SO IT MUST BE DESCENDED — this is where a ladder record used to be
    // published un-narrowed. Rung 0 alone grants `deps` + `project` + `userHome`, and `userHome` is
    // the persistence capability; without a descent the record hands out all three because ONE arm
    // passed. The descent is what says which of them the package actually needs.
    //
    // ⛔⛔ `write:"disk"` IS DESCENDED TOO NOW — this call used to be guarded by `g.write !== 'disk'`.
    // The guard hid a real distinction behind an unconditional skip: on POSIX that rung still has one
    // droppable term (`no-network`, which `linux.rs` and `macos.rs` both keep enforcing once the fs
    // axis is relaxed), while on win32 it has none, because declining the AppContainer token drops
    // the net axis with it. Two different answers, and the old guard printed neither. `descend` now
    // runs on every rung and `descent-terms.mjs` decides what it can ask, so win32 emits an explicit
    // `DESCENT-UNSUPPORTED` marker naming the backend reason instead of a silent nothing. A reader of
    // a win32 record can now tell "not measured because untestable here" from "not measured".
    descend(g, 'ladder');
    // A LADDER rung never carries a `writePaths` declaration — the rungs are literal grant objects
    // and none of them has the key — so the probe declines on `no-declaration` and costs nothing but
    // its marker. Called anyway rather than made conditional on the grant's shape: a driver where the
    // probe runs on one path and not another is how a marker comes to be present for synthesized
    // records and silently absent for ladder ones.
    promotionProbe(g);
    process.exit(0);
  }
}
// ── 5. BEFORE DECLARING NOTHING PASSED: DID THE SHORTFALL EVER RESPOND TO THE GRANT? ──────────
//
// ⛔ A SHORTFALL INVARIANT UNDER WIDENING IS NOT A CAPABILITY GAP, and everything above this line
// assumes the opposite. The ladder reads one boolean per rung, so four arms that each exited 0 and
// each fell short by the SAME files are indistinguishable from four arms that failed for four
// different reasons -- and without this stage both land on `NO-STATE-PASSED`, which discards the
// record. `measure.sh` has asked this question since `windows-foreground-love@0.6.1` was thrown away
// with a correct narrow grant already in hand; this driver and `measure-macos.sh` did not, and the
// cost of that asymmetry is a TRIAGE gap: neither could tell "needs a wider grant" from "no grant
// will ever help", which is the distinction that manufactures false under-grant findings.
//
// ⛔ THE TOP RUNG MEANS SOMETHING WEAKER ON WINDOWS, AND THE VERDICT STILL HOLDS. `write:"disk"`
// DECLINES the AppContainer/LowBox token altogether rather than widening a path grant, so it drops
// the filesystem and network axes together. That makes it a WIDER state than the rungs below it, not
// a narrower one, which is all grant-independence needs: a shortfall unchanged from the synthesized
// grant up to a state with no confinement at all cannot have been caused by confinement. It does
// mean a token-compatibility failure and a path failure look identical here -- but that is an
// argument for reading the shortfall against the toolchain, which is exactly what this verdict says.
//
// ⛔ THE VERDICT IS `SUSPECT`, NOT `VERIFIED`, AND THE DIFFERENCE IS THE POINT. Grant-independence
// proves the shortfall is not a capability gap; it does not prove the install was good, and this is
// the ONLY path in this driver that publishes a grant without a leave-one-out DESCENT behind it --
// the synth and ladder paths both descend, so minimality here is unproven and the grant is a
// CANDIDATE. The record keeps it so the package is triageable instead of discarded; `collate.mjs`
// keeps it out of the catalog, because publishing an unverified NARROW grant is the under-granting
// direction and that is the one that breaks a real install.
const inv = run(NODE, [path.join(HERE, 'shortfall-invariance.mjs'), '--arms', '4'],
  { input: ARM_LEDGER.join('\n') + '\n' });
const invOut = (inv.stdout ?? '').trim();
// ⛔⛔ AN EXIT CODE ALONE DOES NOT SAY THE PREDICATE RAN. The CLI block below `classify` prints
// `GRANT-INDEPENDENT ...` or `NOT-ESTABLISHED ...` on every path it takes, so EMPTY stdout means it
// never executed -- and the failure that produces that exits 0, so a bare `status === 0` reads a
// script that did nothing as the strongest verdict this stage can issue. The count would then render
// empty and the verdict would be published off no evidence at all.
//
// ⛔ AND THE TRIGGER IS A WINDOWS DEFECT ORIGINALLY. That main-module guard resolves the invoked
// script's path to a URL, rather than string-concatenating it, precisely because the STRING form never
// matches on Windows -- argv carries a backslash path while `import.meta.url` is `file:///C:/...` --
// the exact silent-exit-0 shape this guard refuses. A spawn failure (`inv.error`) lands here too,
// which is right: no stdout, no answer.
//
// ⛔ `HARNESS-ERROR`, NOT A NEW NOUN AND NOT `NO-STATE-PASSED`. `record.mjs` already parses this
// spelling from this driver, and `claim-slice.mjs` returns a `HARNESS-*` row to `pending` instead of
// closing it -- which is right, because a re-run would answer the question. Falling through would
// instead record "nothing installed this package" as a MEASUREMENT, when the rescue never got to run.
if (!invOut) {
  console.log(`  => HARNESS-ERROR: shortfall-invariance.mjs printed nothing (rc=${inv.status}) -- the predicate`);
  console.log('     never ran, so grant-independence is UNANSWERED and no verdict here would rest on evidence.');
  process.exit(1);
}
if (inv.status === 0) {
  const missN = invOut.split(' ')[1];
  console.log(`  => ARTIFACT-GATE-SUSPECT ${JSON.stringify(GRANT)}   (every arm rc=0 and the SAME ${missN}-artifact shortfall at`);
  console.log('     every grant up to write:"disk" -- invariant under widening, so it is not a capability gap)');
  // `->`, never `=>`: `record.mjs` keys every verdict on a leading `=>`, so a continuation line that
  // opens with one is a verdict token waiting to be matched by the next pattern someone adds.
  console.log('     -> The grant is the SYNTHESIZED one and is UNVERIFIED -- minimality was never descended.');
  console.log("        Triage the shortfall against the arm's toolchain, not against the jail.");
  process.exit(0);
}
console.log(`  NOT-GRANT-INDEPENDENT ${invOut.replace(/^NOT-ESTABLISHED /, '')}`);

// ⛔ ASK WHETHER NUB CAN INSTALL THIS AT ALL BEFORE BLAMING THE JAIL. Every rung failed, but the
// ladder only ever varied the GRANT — it never asked whether nub installs this package with the jail
// switched off. If it does not, none of those failures say anything about capabilities, and the
// verdict below would name the jail for a defect it had no part in.
//
// ⛔ RUN IT HERE, LAZILY. This is the only path that would otherwise file the terminal verdict, so the
// common case pays nothing; hoisting it would add two installs to every package in the corpus to
// answer a question almost none of them ask.
const NUB_ARM = unjailedNubOk();
// ⛔ SOUNDNESS OUTRANKS THE rc, AND IT IS CHECKED FIRST. A control whose off-switch never engaged ran
// JAILED, so its exit code describes the jail rather than its absence — and rc=0 would then be read as
// "installs fine unjailed", exonerating the jail using a jailed run as the evidence. A timeout is
// likewise not a package fact. Both are HARNESS-* verdicts, which `claim-slice.mjs` returns to
// `pending` rather than closing, so a re-run off a fixed harness answers the question.
//
// This matters most on THIS platform: 45 of the 62 `write:"disk"` grants in the catalog rest on a win32
// record alone, so the widest capability the jail hands out is the one whose control most needs to be
// provably sound.
if (NUB_ARM.timedOut || NUB_ARM.engaged === false) {
  const { verdict, why } = classify({ nub: { rc: NUB_ARM.ok ? 0 : 1, ...NUB_ARM } });
  console.log(`  jail-off control: ${why}`);
  console.log(`  => ${verdict}`);
  emitBinaryProvenance();
  process.exit(0);
}
if (!NUB_ARM.ok) {
  // ⛔ PRINT WHAT NUB ACTUALLY SAID, AND PRINT IT HERE. This branch is the one that goes on to accuse
  // nub, and it accused it SILENTLY: the arm's output was captured and discarded with the call, so a
  // real nub defect and a harness asymmetry left byte-identical records. That is epoch 15's second
  // half, which reached `unjailed-nub.mjs` and not this driver.
  //
  // ⛔ BEFORE THE VERDICT LINE, NEVER BETWEEN IT AND THE EXIT. `venue-provenance-on-exit.test.mjs`
  // scans FORWARD from the `=>` to `emitBinaryProvenance()` inside a FIVE-LINE window; anything
  // inserted below pushes the call out of it, which a comment block parked there has already done
  // once. The tail bound matches the POSIX control's.
  // The echo is FAITHFUL: `record.mjs` drops quoted lines before matching verdicts, so package
  // output can no longer be read as one and does not need mangling to be safe.
  for (const line of Object.values(NUB_ARM.logs ?? {}).join('\n').trimEnd().split('\n').slice(-20)) {
    if (line.trim()) console.log(`    | ${line}`);
  }
  // ⛔ ONE `=>` LINE PER PATH — `record.mjs` walks the log and the LAST match wins, so emitting a
  // second verdict after either branch would silently overwrite it and the stage would be inert.
  // ⛔ NAME THE BINARY BEFORE EXITING. Both of these publish a record, and a record that cannot say
  // which nub produced it is unattributable — `venue-provenance-on-exit.test.mjs` enforces it on the
  // `BROKEN-WITHOUT-JAIL-TOO` path and caught this branch missing it. The emitter is idempotent, so
  // calling it in both arms is free.
  // ⛔ NAME THE BINARY BEFORE EXITING, AND KEEP IT TIGHT AGAINST THE VERDICT. Both branches publish a
  // record, and one that cannot say which nub produced it is unattributable —
  // `venue-provenance-on-exit.test.mjs` caught this branch missing the call. Its predicate scans
  // FORWARD from the verdict line to the exit within a FIVE-LINE window, so the call must sit after
  // the `console.log` and nothing verbose may come between: a comment block parked here pushed both
  // the call and the `process.exit` out of the window and tripped a second guard.
  // The module owns both spellings, so three drivers cannot drift on the tokens `record.mjs` matches,
  // and it puts the REASON on its own line — which also keeps the verdict tight against the provenance
  // call the five-line window guard above requires.
  // ⛔ COMPUTED ABOVE THE VERDICT LINE ON PURPOSE. The guard scans FORWARD from the verdict to the
  // exit in a five-line window, so the second npm arm cannot go between them.
  const npmDated = npmOk();
  const hasDate = eraResolution.args.some((a) => String(a).startsWith('--before'));
  let npmUndated;
  if (npmDated && hasDate) {
    // The dating axis — see the `npmUndated` clause in `unjailed-nub.mjs`. Only asked when there is a
    // date to drop and npm succeeded WITH it; otherwise the two runs are the same run.
    npmUndated = { rc: npmOk({ dated: false }) ? 0 : 1 };
    console.log(npmUndated.rc === 0
      ? '  NPM-REFERENCE-UNDATED ok — undated resolution installs this too, so the date is not the difference'
      : `  NPM-REFERENCE-UNDATED FAILED — undated resolution alone breaks ${PKG}@${VER} on this era Node, which is the condition the nub arm ran under. Not a nub defect.`);
  }
  const { verdict, why } = classify({ nub: { rc: 1, engaged: true }, npm: { rc: npmDated ? 0 : 1 }, npmUndated });
  console.log(`  jail-off control: ${why}`);
  console.log(`  => ${verdict}`);
  emitBinaryProvenance();
  process.exit(0);
}
console.log('  jail-off control: nub installs this package unjailed (rc=0), so the jail IS the difference');

// ⛔ ONLY NOW, AND ONLY IN THIS BRANCH. `record.mjs` walks the log line by line and the LAST matching
// `=>` wins, so printing both verdicts would silently overwrite `ARTIFACT-GATE-SUSPECT` with
// `NO-STATE-PASSED` and this whole stage would have no effect on any record.
console.log('  => NO-STATE-PASSED even at write:disk -- investigate; do not widen the catalog blindly');
