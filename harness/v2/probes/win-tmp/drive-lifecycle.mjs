// ARM B DRIVER — the REAL interposed build jail, reached the only way a real one is reached: an
// `nub install` whose dependencies have a `postinstall`.
//
// ⛔ WHY THIS ARM EXISTS AT ALL, GIVEN ARM A. `--sandbox build-jail` and the lifecycle
// interposition share `build_jail_surface`, so they share the tmp MODE -- but only the lifecycle
// path goes through `compile_build_jail`, which replaces the strip-all env floor with the scrubbed
// lifecycle env. Question 4 is a question about that env. Arm A cannot answer it, and reporting
// arm A's env dump as though it were a postinstall's would be answering a different question in
// the right format.
//
// ⛔ TWO PACKAGES, INSTALLED IN ONE `nub install`. That is the "does it differ per package" axis,
// and it only means anything if both ran in the same session against the same host state -- which
// is why they are two dependencies of one project rather than two installs.
//
// Local tarballs, not directory deps: a `file:` DIRECTORY is a link, and a linked dependency's
// lifecycle script is not the spawn under test. `npm pack` first, depend on the `.tgz`.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const flag = (n, d = '') => {
  const i = process.argv.indexOf(n);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : d;
};

const NUB = flag('--nub');
const BASE = flag('--root', 'C:\\jail\\wintmpB');
const OUT = flag('--out', path.join(BASE, 'out'));
const TIMEOUT = Number(flag('--timeout', '600000'));
if (!NUB || !fs.existsSync(NUB)) {
  console.error(`FATAL --nub must point at an existing nub.exe (got ${NUB || '<unset>'})`);
  process.exit(2);
}

const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const FIXTURE = path.join(HERE, 'probe-tmp.mjs');
const NODE = process.execPath;
const NPM = path.join(path.dirname(NODE), 'node_modules', 'npm', 'bin', 'npm-cli.js');
const HOME = process.env.USERPROFILE;
const LOCALAPPDATA = process.env.LOCALAPPDATA;
const PACKAGES = path.join(LOCALAPPDATA, 'Packages');
const HOST_TEMP = process.env.TEMP;

fs.rmSync(BASE, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
fs.mkdirSync(OUT, { recursive: true });
fs.mkdirSync('C:\\Temp', { recursive: true });

const STAMP = Date.now().toString(36);
const specs = [
  { dir: 'one', name: `nub-wintmp-one-${STAMP}`, label: 'B1' },
  { dir: 'two', name: `nub-wintmp-two-${STAMP}`, label: 'B2' },
];

const run = (exe, args, opts = {}) =>
  spawnSync(exe, args, { encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, timeout: TIMEOUT, ...opts });

const tarballs = [];
for (const s of specs) {
  s.marker = `nubtmp${s.label}-${STAMP}`;
  const d = path.join(BASE, s.dir);
  fs.mkdirSync(d, { recursive: true });
  fs.copyFileSync(FIXTURE, path.join(d, 'probe-tmp.mjs'));
  const cmd = [
    'node probe-tmp.mjs',
    `--label ${s.label}`,
    `--marker ${s.marker}`,
    `--negctl "${path.join(HOME, `${s.marker}-negctl.txt`)}"`,
    `--hunt "${[PACKAGES, HOST_TEMP].join(';')}"`,
  ].join(' ');
  fs.writeFileSync(
    path.join(d, 'package.json'),
    JSON.stringify({ name: s.name, version: '1.0.0', scripts: { postinstall: cmd }, files: ['probe-tmp.mjs'] }, null, 2),
  );
  const p = run(NODE, [NPM, 'pack', '--pack-destination', BASE], { cwd: d });
  if (p.status !== 0) {
    console.error(`FATAL npm pack failed for ${s.name}: ${p.stdout}${p.stderr}`);
    process.exit(2);
  }
  const tgz = path.join(BASE, `${s.name}-1.0.0.tgz`);
  if (!fs.existsSync(tgz)) {
    console.error(`FATAL packed tarball missing at ${tgz}`);
    process.exit(2);
  }
  tarballs.push({ ...s, tgz });
}

const proj = path.join(BASE, 'proj');
fs.mkdirSync(proj, { recursive: true });
fs.writeFileSync(
  path.join(proj, 'package.json'),
  JSON.stringify(
    {
      name: `wintmp-lifecycle-${STAMP}`,
      version: '1.0.0',
      private: true,
      dependencies: Object.fromEntries(tarballs.map((t) => [t.name, `file:${t.tgz.replace(/\\/g, '/')}`])),
    },
    null,
    2,
  ),
);

console.log(`packed ${tarballs.map((t) => t.name).join(', ')}; project at ${proj}`);
console.log('running `nub install` ...');
const i = run(NUB, ['install'], { cwd: proj });
fs.writeFileSync(path.join(OUT, 'install.log'), (i.stdout ?? '') + (i.stderr ?? ''));
console.log(`install rc=${i.status}${i.error ? ` error=${i.error.message}` : ''}`);
console.log('running `nub approve-builds --all` ...');
const a = run(NUB, ['approve-builds', '--all'], { cwd: proj });
fs.writeFileSync(path.join(OUT, 'approve.log'), (a.stdout ?? '') + (a.stderr ?? ''));
console.log(`approve rc=${a.status}${a.error ? ` error=${a.error.message}` : ''}`);

const logs = (i.stdout ?? '') + (i.stderr ?? '') + (a.stdout ?? '') + (a.stderr ?? '');

// ⛔ THE ARM MUST PROVE A SCRIPT ACTUALLY RAN. nub replays a cached side-effect tree without
// spawning anything, and a replayed arm is indistinguishable from a real one by exit code.
const ranScripts = /running build scripts for/.test(logs);
// ⛔ AND IT MUST PROVE THE SCRIPT WAS CONFINED. `confines()` announces an UNCONFINED lifecycle
// spawn in the install output; if that warning is present the jail stood aside and every path
// below is a property of an ordinary `node`.
const unconfined = /running without the build sandbox/.test(logs);

// ⛔ THE SENTINELS ARE ASSEMBLED, AND A FRAME THAT DOES NOT PARSE IS DROPPED. `probe-tmp.mjs`
// splits its own literals so an echo of a command line carrying the fixture source cannot pass for
// a run of it; matching on an assembled pattern is the other half of that. A `{parseError}` object
// would be truthy and would let the frame count toward the gate while carrying nothing.
const FRAME = new RegExp(`@@PRO${'BE'}@@([\\s\\S]*?)@@E${'ND'}@@`, 'g');
const parseErrors = [];
const frames = [...logs.matchAll(FRAME)]
  .map((m) => {
    try {
      return JSON.parse(m[1]);
    } catch (e) {
      parseErrors.push(String(e.message));
      return null;
    }
  })
  .filter(Boolean);

// Per-root depth and entry caps, for the reason spelled out in `drive.mjs`: an unbounded walk of a
// hosted runner's `%TEMP%` is minutes of I/O, and a marker written into temp sits at depth 1 or 2.
const SCAN = [
  [HOST_TEMP, 3, 20000],
  [PACKAGES, 6, 20000],
  ['C:\\Windows\\Temp', 2, 5000],
  ['C:\\Temp', 2, 5000],
  [BASE, 6, 20000],
];
const scanOutside = (marker) => {
  const out = {};
  for (const [root, maxDepth, cap] of SCAN) {
    const hits = [];
    let seen = 0;
    const walk = (dir, depth) => {
      if (depth > maxDepth || seen > cap) return;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (seen++ > cap) return;
        const full = path.join(dir, e.name);
        if (e.name.includes(marker)) hits.push(full);
        if (e.isDirectory()) walk(full, depth + 1);
      }
    };
    walk(root, 0);
    if (hits.length) out[root] = hits;
  }
  return out;
};

const leaks = frames.filter((f) => f.negativeControl?.write?.ok === true).map((f) => f.label);
const verdict = {
  installRc: i.status,
  approveRc: a.status,
  scriptsRan: ranScripts,
  announcedUnconfined: unconfined,
  framesRecovered: frames.map((f) => f.label),
  frameParseErrors: parseErrors,
  jailedArmsThatBreachedTheControl: leaks,
  valid: ranScripts && !unconfined && frames.length === specs.length && leaks.length === 0,
};

const detail = frames.map((f) => ({ label: f.label, outsideScan: scanOutside(f.marker), probe: f }));
fs.writeFileSync(path.join(OUT, 'arm-b.json'), JSON.stringify({ verdict, detail }, null, 2));

console.log('='.repeat(100));
console.log('ARM B — the real interposed lifecycle build jail (`nub install` + `approve-builds`)');
console.log('='.repeat(100));
console.log(`GATE: install rc=${i.status} approve rc=${a.status}`);
console.log(`GATE: 'running build scripts for' present: ${ranScripts}`);
console.log(`GATE: 'running without the build sandbox' announced: ${unconfined}  (must be false)`);
console.log(`GATE: probe frames recovered: ${frames.length}/${specs.length} -> ${verdict.framesRecovered.join(',')}`);
console.log(`GATE: negative-control breaches: ${leaks.length ? leaks.join(',') : 'none'}`);
console.log(`GATE: arm B valid: ${verdict.valid}`);
console.log('');

for (const d of detail) {
  const p = d.probe;
  const mk = p.mkdtemp?.ok ? p.mkdtemp.value : null;
  console.log(`${p.label}  (package postinstall)`);
  console.log(`     cwd              = ${JSON.stringify(p.cwd)}`);
  console.log(`     os.tmpdir()      = ${JSON.stringify(p.osTmpdir)}`);
  console.log(`     tmpdir source    = ${p.tmpdirSource}  (replay matches: ${p.tmpdirReplayMatches})`);
  console.log(`     env.TEMP         = ${JSON.stringify(p.env.TEMP)}`);
  console.log(`     env.TMP          = ${JSON.stringify(p.env.TMP)}`);
  console.log(`     env.USERPROFILE  = ${JSON.stringify(p.env.USERPROFILE)}`);
  console.log(`     env.LOCALAPPDATA = ${JSON.stringify(p.env.LOCALAPPDATA)}`);
  console.log(`     os.homedir()     = ${JSON.stringify(p.osHomedir?.ok ? p.osHomedir.value : p.osHomedir)}`);
  console.log(`     env var count    = ${p.envCount}`);
  console.log(`     env keys         = ${JSON.stringify(p.envKeys)}`);
  console.log(`     mkdtemp          = ${mk ? JSON.stringify(mk.dir) : JSON.stringify(p.mkdtemp)}`);
  console.log(`     mkdtemp realpath = ${mk ? JSON.stringify(mk.realpathNative?.ok ? mk.realpathNative.value : mk.realpathNative) : '-'}`);
  console.log(`     write inside     = ${mk ? (mk.write.ok ? `ok roundTrip=${mk.write.value.roundTrip}` : mk.write.code) : '-'}`);
  console.log(`     C:\\Windows\\Temp  = ${p.hardcoded.windowsTemp.ok ? 'ok' : p.hardcoded.windowsTemp.code}`);
  console.log(`     C:\\Temp          = ${p.hardcoded.cTemp.ok ? 'ok' : p.hardcoded.cTemp.code}`);
  console.log(`     NEG CTL (home)   = ${p.negativeControl.write?.ok ? '⛔ SUCCEEDED (arm void)' : `refused ${p.negativeControl.write?.code}`}`);
  console.log(`     home readable    = ${p.homeReadable?.ok ? `yes (${p.homeReadable.value} entries)` : `no ${p.homeReadable?.code}`}`);
  for (const h of p.hunts ?? []) {
    console.log(`     in-jail hunt ${h.root} exists=${h.exists} hits=${h.hits.length}${h.hits.length ? ` -> ${h.hits.slice(0, 4).join(' | ')}` : ''}`);
  }
  for (const [root, hits] of Object.entries(d.outsideScan)) {
    console.log(`     post-run scan ${root} -> ${hits.slice(0, 4).join(' | ')}`);
  }
  console.log('');
}

if (!verdict.valid) {
  console.log('⛔ ARM B IS VOID — the rows above are not evidence about the lifecycle jail.');
  process.exit(1);
}
