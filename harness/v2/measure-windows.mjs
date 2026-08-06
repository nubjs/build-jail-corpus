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
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
const flag = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const [PKG, VER] = positional;
if (!PKG || !VER) { console.error('usage: measure-windows.mjs <pkg> <version> [--nub exe] [--root dir]'); process.exit(2); }

const NUB = flag('--nub', 'C:\\nub-ci.exe');
const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const HOME = process.env.USERPROFILE;

// ⛔ NOT UNDER %TEMP%. That path is inside the jail's own private-temp redirect, so a fixture
// placed there cannot test a filesystem-denial claim at all.
const BASE = flag('--root', 'C:\\jail');

// A verify arm that never returns is a real, MEASURED outcome here, not a hypothetical: a jailed
// `nub install` was seen burning a core for 13+ minutes with no output. Bare spawnSync has no
// deadline, so one such arm blocks the whole driver forever and the lane produces nothing at all.
// TIMED-OUT is recorded as its own verdict -- it is NOT a failure, and must never be read as one:
// a failure says the grant was insufficient, a timeout says nothing about the grant.
const ARM_TIMEOUT_MS = Number(flag('--arm-timeout', '600000'));
const ROOT = path.join(BASE, `m-${PKG.replace(/[^a-z0-9]/gi, '')}-${Date.now().toString(36)}`);
fs.mkdirSync(ROOT, { recursive: true });

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

// A spawnSync deadline surfaces as `error.code === 'ETIMEDOUT'`, but a killed child also reports
// status null with a signal, so both spellings are treated as the deadline firing. Distinguishing a
// timeout from a non-zero exit is what keeps a hung arm out of the "grant insufficient" bucket.
const timedOut = (r) => r.error?.code === 'ETIMEDOUT' || (r.status === null && r.signal != null);

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
  m.root = root;
  return m;
};

// Returns the artifacts OBSERVE produced that this arm did not. Empty => the arm reproduced the
// unjailed result. Naming them is what makes a failing arm self-debugging: the corpus log says
// `lib/iedriver64/IEDriverServer.exe` rather than a bare number.
const missingArtifacts = (obs, got) => {
  if (!got) return ['<package absent>'];
  const out = [];
  for (const [f, size] of obs) {
    if (!got.has(f)) out.push(f);
    else if (got.get(f) < size) out.push(`${f} (${got.get(f)}B < ${size}B)`);
  }
  return out;
};

console.log(`### ${PKG}@${VER}   (${ROOT})`);

// ── 1. OBSERVE ────────────────────────────────────────────────────────────────────────────────
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
const obsEnv = { ...process.env, npm_config_cache: NPM_CACHE };
const fetch = run(NODE, [NPM, 'install', '--no-audit', '--no-fund', '--ignore-scripts', `${PKG}@${VER}`], { cwd: OBS, env: obsEnv });
fs.writeFileSync(path.join(OBS, 'fetch.log'), (fetch.stdout ?? '') + (fetch.stderr ?? ''));
if (fetch.status !== 0) {
  console.log(`  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed rc=${fetch.status}; nothing to measure)`);
  process.exit(0);
}

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
fs.writeFileSync(WRAP, `@echo off\r\nset "npm_config_cache=${NPM_CACHE}"\r\n"${NODE}" "${NPM}" rebuild --no-audit --no-fund ${PKG}\r\n`, 'ascii');
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

// The capture must be the real security context and a complete trace, or nothing downstream means
// anything. SYSTEM holds privileges an ordinary account does not; a lossy trace cannot support the
// "no more than this" half of a minimum-grant claim.
if (/^nt authority\\system$/i.test(meta.whoami)) { console.log(`  => VOID: captured as ${meta.whoami}`); process.exit(1); }
if (meta.eventsLost > 0) console.log(`  !! ${meta.eventsLost} events LOST -- exact-set claims are not supported by this trace`);
if (meta.exitCode !== 0) { console.log(`  => BROKEN-WITHOUT-JAIL-TOO (unjailed rebuild rc=${meta.exitCode})`); process.exit(0); }

const isLog = (p) => /\.(log|xml|etl|txt)$|meta\.json$|cat\.json$/i.test(p);
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

// ── 2. SYNTHESIZE ─────────────────────────────────────────────────────────────────────────────
const NDJSON = path.join(CAP, 'events.ndjson');
const parse = run(NODE, [path.join(HERE, 'adapters', 'windows.mjs'), CAP, '--out', NDJSON]);
if (!fs.existsSync(NDJSON)) { console.log(`  => PARSE FAILED\n${parse.stdout}${parse.stderr}`); process.exit(1); }

const cls = run(NODE, [
  path.join(HERE, 'classify.mjs'), NDJSON,
  '--project', OBS, '--home', HOME, '--platform', 'win32',
  '--root-pid', String(meta.rootPid), '--json', path.join(ROOT, 'observed.json'),
]);
const clsOut = (cls.stdout ?? '') + (cls.stderr ?? '');
fs.writeFileSync(path.join(ROOT, 'observed.txt'), clsOut);
console.log(clsOut.trimEnd().split('\n').map((l) => '  ' + l).join('\n'));
const observed = JSON.parse(fs.readFileSync(path.join(ROOT, 'observed.json'), 'utf8'));
const GRANT = observed.grant;

// ── 3. VERIFY — the real, UNPRIVILEGED jail. The only arm whose result may enter the catalog. ─
let armSeq = 0;
const verify = (grant, label) => {
  const v = path.join(ROOT, `verify-${label}`);
  fs.mkdirSync(v, { recursive: true });
  // ⛔ A UNIQUE PACKAGE NAME PER ARM. nub memoises a lifecycle script's outcome keyed on package
  // identity, so a reused name REPLAYS the previous arm's result with every precondition green.
  fs.writeFileSync(path.join(v, 'package.json'),
    JSON.stringify({ name: `r${armSeq++}${Date.now().toString(36)}`, version: '1.0.0', dependencies: { [PKG]: VER } }) + '\n');
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
  const catalog = Object.keys(grant).length
    ? { packages: { [PKG]: { default: grant } } }
    : { packages: { __v2_empty_grant_sentinel__: { default: { network: true } } } };
  fs.writeFileSync(cat, JSON.stringify(catalog));

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
  // was not. Evict the store entry itself, which is the only thing the linker consults.
  const STORE = path.join(process.env.LOCALAPPDATA, 'nub', 'pm', 'store');
  for (const d of (fs.existsSync(STORE) ? fs.readdirSync(STORE) : [])) {
    // Store dirs are `<name>@<version>-<hash>`; the hash is not predictable, so match the prefix.
    if (d.startsWith(`${PKG}@${VER}-`) || d.startsWith(`${PKG}@`)) {
      fs.rmSync(path.join(STORE, d), { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    }
  }
  // The memo drop stays: it is necessary but, on its own, was measured to be insufficient.
  fs.rmSync(path.join(process.env.LOCALAPPDATA, 'nub', 'pm', 'side-effects-v1'),
    { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  const env = { ...process.env, NUB_BUILD_JAIL_CATALOG: cat };
  const i = run(NUB, ['install'], { cwd: v, env, timeout: ARM_TIMEOUT_MS });
  fs.writeFileSync(path.join(v, 'i.log'), (i.stdout ?? '') + (i.stderr ?? ''));
  // spawnSync's timeout kills the DIRECT child only; a jailed grandchild can survive it. Report the
  // stage so the leak is visible rather than showing up later as a mystery CPU hog.
  if (timedOut(i)) {
    console.log(`  VERIFY[${label}] TIMED-OUT in \`install\` after ${ARM_TIMEOUT_MS} ms -- no verdict; check for surviving children`);
    return { ok: false, void: false, timedOut: true, stage: 'install', files: countFiles(v, isLog), rc: null };
  }
  const a = run(NUB, ['approve-builds', '--all'], { cwd: v, env, timeout: ARM_TIMEOUT_MS });
  fs.writeFileSync(path.join(v, 'a.log'), (a.stdout ?? '') + (a.stderr ?? ''));
  if (timedOut(a)) {
    console.log(`  VERIFY[${label}] TIMED-OUT in \`approve-builds\` after ${ARM_TIMEOUT_MS} ms -- no verdict; check for surviving children`);
    return { ok: false, void: false, timedOut: true, stage: 'approve-builds', files: countFiles(v, isLog), rc: null };
  }

  // ⛔ A MALFORMED OVERRIDE WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  // assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  const logs = ['i.log', 'a.log'].map((f) => fs.readFileSync(path.join(v, f), 'utf8')).join('\n');
  const ovr = (logs.match(/catalog OVERRIDDEN/g) ?? []).length;
  const rej = (logs.match(/REJECTED/g) ?? []).length;
  const files = countFiles(v, isLog);
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
  if (!/running build scripts for/.test(logs)) {
    console.log("     !! REPLAY SUSPECTED -- no 'running build scripts' line in either log; the script may not have run");
  }
  // `files/OBS_FILES` stays printed for continuity with the existing corpus logs, but it is
  // DIAGNOSTIC ONLY -- see the pkgManifest comment for why those two numbers are incomparable.
  console.log(`  VERIFY[${label}] rc=${rc} artifacts=${got ? got.size : 'ABSENT'}/${OBS_PKG.size} missing=${missing.length} (tree ${files}/${OBS_FILES}) OVERRIDDEN=${ovr} REJECTED=${rej} grant=${JSON.stringify(grant)}`);
  if (missing.length) console.log(`     missing artifacts: ${missing.slice(0, 6).join(', ')}${missing.length > 6 ? ` (+${missing.length - 6})` : ''}`);
  if (!(ovr >= 1 && rej === 0)) { console.log('     !! override did not engage -- arm is VOID'); return { ok: false, void: true, files, rc }; }
  // Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  // failure mode. Compare the MEASURED PACKAGE's artifact manifest against what the unjailed
  // OBSERVE arm produced for that same package.
  return { ok: rc === 0 && missing.length === 0, void: false, files, rc };
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
for (const [i, g] of LADDER.entries()) {
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
    process.exit(0);
  }
}
console.log('  => NO-STATE-PASSED even at write:disk -- investigate; do not widen the catalog blindly');
