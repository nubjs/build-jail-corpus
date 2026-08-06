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

const fetch = run(NODE, [NPM, 'install', '--no-audit', '--no-fund', '--ignore-scripts', `${PKG}@${VER}`], { cwd: OBS });
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
fs.writeFileSync(WRAP, `@echo off\r\n"${NODE}" "${NPM}" rebuild --no-audit --no-fund ${PKG}\r\n`, 'ascii');
const cap = run('powershell.exe', [
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(HERE, 'adapters', 'windows.ps1'),
  '-OutDir', CAP,
  '-Command', WRAP,
  '-WorkDir', OBS,
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
  fs.writeFileSync(cat, JSON.stringify({ packages: { [PKG]: { default: grant } } }));

  const env = { ...process.env, NUB_BUILD_JAIL_CATALOG: cat };
  const i = run(NUB, ['install'], { cwd: v, env });
  fs.writeFileSync(path.join(v, 'i.log'), (i.stdout ?? '') + (i.stderr ?? ''));
  const a = run(NUB, ['approve-builds', '--all'], { cwd: v, env });
  fs.writeFileSync(path.join(v, 'a.log'), (a.stdout ?? '') + (a.stderr ?? ''));

  // ⛔ A MALFORMED OVERRIDE WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  // assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  const logs = ['i.log', 'a.log'].map((f) => fs.readFileSync(path.join(v, f), 'utf8')).join('\n');
  const ovr = (logs.match(/catalog OVERRIDDEN/g) ?? []).length;
  const rej = (logs.match(/REJECTED/g) ?? []).length;
  const files = countFiles(v, isLog);
  const rc = i.status === 0 ? (a.status ?? 0) : i.status;
  console.log(`  VERIFY[${label}] rc=${rc} files=${files}/${OBS_FILES} OVERRIDDEN=${ovr} REJECTED=${rej} grant=${JSON.stringify(grant)}`);
  if (!(ovr >= 1 && rej === 0)) { console.log('     !! override did not engage -- arm is VOID'); return { ok: false, void: true, files, rc }; }
  // Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  // failure mode. Compare against what the unjailed OBSERVE arm produced.
  return { ok: rc === 0 && files >= OBS_FILES, void: false, files, rc };
};

const synth = verify(GRANT, 'synth');
if (synth.void) { console.log('  => VOID (override never engaged; binary lacks the feature or the catalog was rejected)'); process.exit(1); }
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
console.log('  synthesized grant did not verify -- falling back to a bounded ladder');
const LADDER = [
  { write: { deps: true, project: true, userHome: true }, network: true },
  { write: { deps: true, project: true, userHome: true }, read: 'disk', network: true },
  { write: 'disk', network: true },
];
for (const [i, g] of LADDER.entries()) {
  const r = verify(g, `fb${i}`);
  if (r.void) continue;
  if (r.ok) {
    console.log(`  => MINIMUM ${JSON.stringify(g)}   (ladder fallback; synthesized grant was insufficient)`);
    console.log(`  !! OBSERVE UNDER-PREDICTED -- the gap between ${JSON.stringify(GRANT)} and this is what the trace missed`);
    if (g.write === 'disk') console.log('  !! last rung is write:"disk" = NO CONFINEMENT on Windows; a token problem and a path problem look identical here');
    process.exit(0);
  }
}
console.log('  => NO-STATE-PASSED even at write:disk -- investigate; do not widen the catalog blindly');
