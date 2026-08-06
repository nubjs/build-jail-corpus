// Harness v2 driver, Windows: OBSERVE -> SYNTHESIZE -> VERIFY -> bounded-ladder fallback.
// The port of measure.sh. A .mjs rather than a .ps1 because the ETW adapter's parse half
// (windows.mjs) and the classifier are already Node, PowerShell-over-SSH quoting is a documented
// loop-waster, and argv arrives intact.
//
// Every safety property of the Linux original is carried over, and Windows adds four more that
// the Linux driver has no analogue for. Each is annotated where it is enforced.
//
//   usage: node measure-windows.mjs <pkg> <version> [--root DIR] [--nub PATH] [--grant JSON]
//                                   [--ab]  A/B the ancestor-repair kill switch at --grant
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : d; };
const PKG = argv[0], VER = argv[1];
const ROOT = flag('--root', 'C:\\m');
const NUB = flag('--nub', 'C:\\nub-ci.exe');
const HERE = flag('--harness', 'C:\\corpus\\harness');
const AB = argv.includes('--ab');
const GRANT_ARG = flag('--grant', null);
if (!PKG || !VER) { console.error('usage: measure-windows.mjs <pkg> <version> [--root D] [--nub P] [--grant J] [--ab]'); process.exit(2); }

// ⛔ THE GLOBAL FLOOR. `baseline` and `env` are TOP-LEVEL catalog arrays, not package-keyed: they
// are the profile every jailed script starts from. A cell that omits them measures a package
// against a floor it will never run under, and attributes the gap to the package.
const BASELINE = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(HERE, 'baseline.json'), 'utf8')); }
  catch { return { baseline: [], env: [] }; }
})();
const WIDE = { write: 'disk', network: true };   // ⛔ NOT `read:'disk'` too - the parser REJECTS the
                                                 // redundancy ("write:disk already grants every read")
                                                 // and a rejected catalog falls back to the compiled-in
                                                 // one SILENTLY.

const PATH_PREFIX = flag('--path-prefix',
  'C:\\Program Files\\Git\\mingw64\\bin;C:\\Program Files\\Git\\usr\\bin;') ;

const rmrf = (p) => { try { fs.rmSync(p, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 }); } catch {} };

/** Sorted relative path+size list under `root`. Artifacts, not exit codes, decide a cell. */
function scan(root, prefix = '') {
  const out = [];
  let ents; try { ents = fs.readdirSync(root, { withFileTypes: true }); } catch { return out; }
  for (const e of ents.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (!prefix && (e.name === 'cat.json' || e.name.endsWith('.log'))) continue;
    if (e.name === '.git' && e.isDirectory()) { out.push(...scan(path.join(root, e.name, 'hooks'), `${rel}/hooks`)); continue; }
    if (e.isDirectory()) out.push(...scan(path.join(root, e.name), rel));
    else { let sz = 0; try { sz = fs.statSync(path.join(root, e.name)).size; } catch {} out.push(rel + ':' + sz); }
  }
  return out;
}
const digest = (list) => crypto.createHash('sha256').update(list.join('\n')).digest('hex').slice(0, 16);

// ⛔ `HOME` REDIRECTS NOTHING ON WINDOWS. nub resolves its store through `dirs_next::home_dir()`,
// which reads USERPROFILE; npm follows the same convention and keeps its cache under APPDATA.
// Redirect only HOME and the store lands in the REAL profile, outside the fixture -- every arm then
// shares state and the scan cannot see the tree it is supposed to be comparing.
// This, not NUB_CACHE_DIR, is the per-arm isolation: NUB_CACHE_DIR is the PM cache knob and does
// NOT relocate the store.
const homeEnv = (home) => ({
  HOME: home, USERPROFILE: home,
  LOCALAPPDATA: path.join(home, 'AppData', 'Local'),
  APPDATA: path.join(home, 'AppData', 'Roaming'),
});

/** A catalog holding ONE package at `grant`, EVERY OTHER package at full grant, plus the floor.
 *  ⛔ Holding the rest of the tree wide is not optional: a catalog naming only the package under
 *  test silently strips every sibling's grant, so the control and the cell differ by more than the
 *  one variable and a dependency's missing artifact reads as "no grant helps this package".
 *  ⛔ A NULL grant is spelled as NO ENTRY. An entry with no capabilities is a different thing and
 *  the parser rejects it -- which would make the cell VOID rather than a measurement of nothing. */
function catalogFor(grant, others) {
  const packages = {};
  for (const o of others) if (o !== PKG) packages[o] = { default: { ...WIDE, notes: 'held at full grant: not the variable' } };
  if (grant && Object.keys(grant).length) packages[PKG] = { default: { ...grant } };
  return { packages, baseline: BASELINE.baseline ?? [], env: BASELINE.env ?? [] };
}

/** Every installed package name in a materialized tree - the `others` list. */
function treePackages(nm) {
  const out = [];
  let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    if (!e.isDirectory()) continue;
    if (e.name.startsWith('@')) { for (const s of fs.readdirSync(path.join(nm, e.name), { withFileTypes: true })) if (s.isDirectory()) out.push(`${e.name}/${s.name}`); }
    else if (!e.name.startsWith('.')) out.push(e.name);
  }
  return out;
}

let CONTROL = null;
function cell(label, grant, others, extraEnv = {}) {
  // ⛔ FIXTURE ROOT OUTSIDE THE JAIL'S PRIVATE-TEMP REDIRECT. A fixture under %TEMP% is inside the
  // redirect and cannot test a filesystem-denial claim at all.
  const base = path.join(ROOT, label);
  const proj = path.join(base, 'proj'), home = path.join(base, 'home');
  rmrf(base); fs.mkdirSync(proj, { recursive: true }); fs.mkdirSync(path.join(home, 'AppData', 'Local'), { recursive: true }); fs.mkdirSync(path.join(home, 'AppData', 'Roaming'), { recursive: true });
  // A unique fixture identity per arm: nub memoises a lifecycle outcome on package identity, so a
  // reused one REPLAYS the previous arm's result with every precondition still green.
  fs.writeFileSync(path.join(proj, 'package.json'),
    JSON.stringify({ name: 'fx' + label.toLowerCase().replace(/[^a-z0-9]/g, ''), version: '1.0.0', dependencies: { [PKG]: VER } }) + '\n');
  const cat = path.join(proj, 'cat.json');
  fs.writeFileSync(cat, JSON.stringify(catalogFor(grant, others)));
  // The v1 records were measured with Git-for-Windows' unix tools on PATH
  // (provenance.toolchain.pathPrefix). Without them a package whose postinstall is `chmod ...`
  // exits 1 at EVERY rung including the widest, and reads as BROKEN-WITHOUT-JAIL-TOO for a reason
  // that has nothing to do with the jail. MEASURED on @ffmpeg-installer/linux-x64@4.1.0.
  const env = { ...process.env, ...homeEnv(home), PATH: PATH_PREFIX + process.env.PATH, NUB_BUILD_JAIL_CATALOG: cat, ...extraEnv };
  const t0 = Date.now();
  const i = spawnSync(NUB, ['install'], { cwd: proj, encoding: 'utf8', env, timeout: 1500000 });
  fs.writeFileSync(path.join(proj, 'i.log'), (i.stdout || '') + (i.stderr || ''));
  const a = spawnSync(NUB, ['approve-builds', '--all'], { cwd: proj, encoding: 'utf8', env, timeout: 1500000 });
  fs.writeFileSync(path.join(proj, 'a.log'), (a.stdout || '') + (a.stderr || ''));
  const logs = fs.readFileSync(path.join(proj, 'i.log'), 'utf8') + fs.readFileSync(path.join(proj, 'a.log'), 'utf8');
  // ⛔ A MALFORMED OVERRIDE WARNS AND FALLS BACK TO THE COMPILED-IN CATALOG SILENTLY. Without this
  // assertion a cell can measure the SHIPPED policy while you believe it measured yours.
  const ovr = (logs.match(/catalog OVERRIDDEN/g) || []).length;
  const rej = (logs.match(/REJECTED/g) || []).length;
  const list = scan(base);
  const rc = i.status === 0 ? (a.status ?? 0) : i.status;
  const isVoid = !(ovr >= 1 && rej === 0);
  const files = list.length, dg = digest(list);
  const materialized = list.some((p) => p.includes('node_modules/'));
  const pass = !isVoid && rc === 0 && CONTROL != null && files >= CONTROL.files;
  console.log(`  ${label.padEnd(16)} rc=${rc} files=${files} digest=${dg} mat=${materialized} OVR=${ovr} REJ=${rej}` +
    `${isVoid ? '  VOID' : CONTROL ? (pass ? '  PASS' : '  FAIL') : ''}  (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
  return { label, rc, files, digest: dg, materialized, ovr, rej, void: isVoid, pass, logs, base, proj, home };
}

console.log(`### ${PKG}@${VER}   nub=${NUB}  root=${ROOT}`);
// ── CONTROL: the widest grant. Every arm is judged against ITS artifacts, never an exit code. ──
const c0 = cell('control', WIDE, []);
if (c0.void || c0.rc !== 0) { console.log('=> BROKEN-WITHOUT-JAIL-TOO (control failed; nothing to measure)'); process.exit(0); }
CONTROL = c0;
const OTHERS = treePackages(path.join(c0.proj, 'node_modules'));
console.log(`  control: files=${c0.files} others=${OTHERS.length}`);

if (AB) {
  // Task 1: one variable, the ancestor-repair kill switch, at a fixed grant.
  const g = GRANT_ARG ? JSON.parse(GRANT_ARG) : null;
  console.log(`\n--- A/B at grant ${JSON.stringify(g)} ---`);
  const A = cell('ab-repairON', g, OTHERS, {});
  const B = cell('ab-repairOFF', g, OTHERS, { NUB_SANDBOX_WIN_NO_ANCESTOR_REPAIR: '1' });
  console.log('\n=== A/B RESULT ===');
  console.log(`repair ON : ${A.void ? 'VOID' : A.pass ? 'PASS' : 'FAIL'}`);
  console.log(`repair OFF: ${B.void ? 'VOID' : B.pass ? 'PASS' : 'FAIL'}`);
  if (!A.void && !B.void) {
    if (A.pass && !B.pass) console.log('VERDICT: FIX NARROWS at this grant (the one-variable control failed, as required)');
    else if (A.pass && B.pass) console.log('VERDICT: passes with the repair DISABLED too - this is NOT evidence for the fix');
    else console.log('VERDICT: fix does NOT narrow at this grant');
  }
  for (const r of [A, B]) {
    const errs = r.logs.split(/\r?\n/).filter((l) => /EPERM|EACCES|denied|realpath|lstat|ENOENT|Error:/i.test(l)).slice(0, 8);
    if (errs.length) { console.log(`--- ${r.label} ---`); errs.forEach((l) => console.log('   ' + l.trim().slice(0, 190))); }
  }
  process.exit(0);
}

// ── The bounded ladder, walked upward. On Windows this is the fallback AND, until the ETW
//    OBSERVE step is wired in below, the discovery step. ─────────────────────────────────────
const LADDER = [
  null,
  { write: { deps: true } },
  { network: true },
  { write: { deps: true }, network: true },
  { write: { deps: true, project: true }, network: true },
  { write: { deps: true, project: true, userHome: true }, network: true },
  { write: 'disk', network: true },
];
for (const g of LADDER) {
  const r = cell('L' + LADDER.indexOf(g), g, OTHERS);
  if (r.void) { console.log('     override did not engage - cell VOID, not a measurement'); continue; }
  if (r.pass) { console.log(`=> MINIMUM ${JSON.stringify(g)}`); process.exit(0); }
}
console.log('=> NO-STATE-PASSED even at write:disk - investigate; do not widen the catalog blindly');
