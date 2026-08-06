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
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
const flag = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const [PKG, VER] = positional;
if (!PKG || !VER) { console.error('usage: measure-windows.mjs <pkg> <version> [--nub exe] [--root dir]'); process.exit(2); }

// ⛔⛔ STILL HARD-STOPPED — BUT NO LONGER FOR THE EVICTION. The transitive closure sweep is ported
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
// TO LIFT THIS: fix the read denial, then re-run `.github/workflows/win-evict-probe.yml` on
// `probe/win-evict` and require R1 SUFFICIENT (false pass under root-only), R2 INSUFFICIENT, R3
// SUFFICIENT. The workflow already asserts all three and fails otherwise. ⛔ Setting this variable
// to get a green run defeats the only thing it is for.
//
// ⛔ THE GUARD IS ABOUT JAILED ARMS, SO `--observe-only` IS OUT OF ITS SCOPE — and narrowing it is
// not a way round it. Everything above is a statement about a VERIFY arm falsely passing because a
// store entry replayed. An observe-only run walks no ladder, evicts nothing and produces no verify
// arm at all; its output is explicitly a hypothesis (`OBSERVE-ONLY`, which `collate.mjs` keeps out
// of the catalog). There is no verdict for a stale store to corrupt, so there is nothing here for
// the guard to protect. Any run that CAN reach a jailed arm still stops.
const OBSERVE_ONLY = argv.includes('--observe-only');
if (!OBSERVE_ONLY && !process.env.NUB_V2_WINDOWS_EVICTION_VERIFIED) {
  console.error('!! measure-windows.mjs is DISABLED: the transitive store eviction is ported and');
  console.error('   measured active, but UNPROVEN -- every Windows arm fails at every grant on an');
  console.error('   EPERM reading the package\'s own install script, so no arm can falsely pass and');
  console.error('   the negative control has nothing to detect. See the note above this check. Any');
  console.error('   win32-x64 v2 record produced before this guard is SUSPECT and must be re-measured.');
  process.exit(3);
}

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
// ⛔ ROOTS ARE DECLARED WHETHER OR NOT THEY ARE KEYED ON — ten are declared, three are keyed on.
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
    // ⛔ NULL BECAUSE THE JAIL DOES NOT MAKE ONE, NOT BECAUSE THE DRIVER FORGOT. Grounded in nub:
    // `build_jail.rs` `sandbox_homes()` takes `home` from the ambient `HOME`/`USERPROFILE`, and
    // `compiler/defaults.rs` `BASELINE_ENV_EXACT` passes `HOME` through. There is no private jail
    // home on any platform, so the confined script sees the real one and so does OBSERVE.
    jailHome: null,
    globalStore: STORE,
    projectStore: path.join(OBS, 'node_modules', '.store'),
    interpreter: NODE,
    toolsDir: TOOLS,
    // ⛔ THE REAL `%TEMP%`, AND THAT IS A KNOWN DIVERGENCE FROM THE JAIL — recorded rather than
    // quietly left to be rediscovered. The build-jail preset sets `fs["$tmp"]="rw"`
    // (`compiler/preset.rs`), which is `TmpMode::Private`, so `backend/mod.rs` `make_private_tmp()`
    // + `set_tmp_env()` give a CONFINED script a fresh per-run temp on Windows and hide the shared
    // one. This OBSERVE arm reproduces none of that: it traces against the user's real temp.
    //
    // DIRECTION OF THE ERROR, which is why it is recorded rather than urgent: on Windows `%TEMP%`
    // is INSIDE `%USERPROFILE%`, so a script's temp write classifies as `userHome` and bills
    // `write.userHome` for a write the jail grants unconditionally. That over-grants, which is the
    // safe direction. Fixing it needs BOTH a driver redirect and a `temp` scope in `classify.mjs`
    // that maps to no capability — landing only the first would move these writes into `outside`,
    // which is reported and never granted, i.e. an under-grant.
    temp: meta.temp ?? process.env.TEMP ?? null,
    // Null for the same reason as `jailHome`: this driver sets no `npm_config_prefix`, so there is
    // no separate npm prefix root for a path to land in.
    npmPrefix: null,
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
  observeEnv: { set: { npm_config_cache: NPM_CACHE }, unset: [] },
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
console.log(`  VENUE-INTERPRETER ${NODE}`);
// ⛔ WHERE THE JAILED ARMS RAN, BECAUSE ON THIS PLATFORM THE ROOT PATH CAN DECIDE THE OUTCOME BY
// ITSELF. Any jail root under `C:\Users\<user>` fails before a single script runs — "could not
// evaluate ALL APPLICATION PACKAGES rights on …: The access control list (ACL) structure is
// invalid. (os error 1336)" — because that home carries seven inheritable `S-1-15-2-…` AppContainer
// package SIDs. MEASURED: only the root path changed between a failing and a passing run, and the
// pre-fix binary fails identically, so it is not a regression. A record that does not name its root
// cannot tell "this package needs more" from "this run could not build a token at all", and a
// venue comparison would read the second as the first.
console.log(`  VENUE-JAIL-ROOT ${ROOT}`);

// ⛔ OBSERVED, NEVER INFERRED FROM `CI`. Deriving the layout from the env var would encode the very
// rule this field exists to let us CHECK, and would then agree with itself forever. What `CI`
// actually moves is not the node-linker — that stays `Isolated` either way — it is WHERE the
// isolated store lives: `install_report.rs` reaches `Source::Ci`, rendered as "global virtual store
// auto-disabled in CI", which relocates every dependency's materialised directory from the user's
// cache into the project. That relocation is why the same write can classify differently between
// the two `CI` states, so it is read off the ARM TREE rather than off the variable.
//
// ⛔ AND THIS ARM IS NEITHER OF THOSE LAYOUTS. OBSERVE is `npm rebuild` in a flat HOISTED tree,
// always — so a grant synthesized here has to hold in both nub layouts, neither of which it was
// measured in. Saying `hoisted` is therefore a statement about the OBSERVE arm and not a prediction
// about the verify arms, and a reader who conflates them will read this field as the wrong claim.
console.log('  VENUE-STORE-LAYOUT hoisted');

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
// ⛔ `TMP`/`TEMP` ARE LISTED AS *NOT* REDIRECTED, WHICH IS A DIVERGENCE FROM THE JAIL AND IS
// RECORDED RATHER THAN LEFT TO BE REDISCOVERED. See the `temp` root in `capture.json` for the
// grounding and the direction of the error.
console.log(`  VENUE-OVERRIDES ${JSON.stringify({
  set: { npm_config_cache: NPM_CACHE },
  unset: [],
  notRedirected: {
    TMP: process.env.TMP ?? null, TEMP: process.env.TEMP ?? null,
    USERPROFILE: process.env.USERPROFILE ?? null,
    why: 'the jail gives a confined script a private per-run tmp (preset.rs `$tmp`=rw -> TmpMode::Private) and leaves HOME alone; this OBSERVE arm reproduces neither redirect',
  },
  passedThrough: {
    CI: process.env.CI ?? null,
    GITHUB_ACTIONS: process.env.GITHUB_ACTIONS ?? null,
    NODE_ENV: process.env.NODE_ENV ?? null,
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
const evictClosure = () => {
  if (!fs.existsSync(STORE)) return;
  let storeReal; try { storeReal = fs.realpathSync(STORE); } catch { storeReal = STORE; }
  const keep = new Set();
  const walk = (dir, depth) => {
    if (depth > 6) return;
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = path.join(dir, e.name);
      let t; try { t = fs.realpathSync(p); } catch { continue; }
      const rel = path.relative(storeReal, t);
      if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) { keep.add(rel.split(path.sep)[0]); continue; }
      let st; try { st = fs.statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p, depth + 1);
    }
  };
  walk(TOOLS, 0);
  // Store dirs are `<name, with `/` as `+`>@<version>-<hash>`. Anchoring on `<slug>@` keeps the
  // eviction TARGETED — the store is machine-global and a sibling runner may be measuring on the
  // same box, so a bare `*yorkie*` would take out an unrelated `yorkie-foo` alongside it.
  const prefixes = [...new Set([PKG, ...CLOSURE].map((n) => n.replace(/\//g, '+') + '@'))];
  let removed = 0, spared = 0;
  let entries; try { entries = fs.readdirSync(STORE); } catch { entries = []; }
  for (const e of entries) {
    if (!prefixes.some((n) => e.startsWith(n))) continue;
    if (keep.has(e)) { spared++; continue; }
    fs.rmSync(path.join(STORE, e), { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
    removed++;
  }
  console.log(`  EVICT   ${removed} store entries removed, ${spared} spared as nub tooling`);
};

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
  // was not. Evict the store entries themselves, which are the only thing the linker consults --
  // PKG's and its whole measured closure's, per the note above `evictClosure`.
  evictClosure();
  // The memo drop stays: it is necessary but, on its own, was measured to be insufficient.
  fs.rmSync(path.join(CACHE, 'side-effects-v1'),
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
