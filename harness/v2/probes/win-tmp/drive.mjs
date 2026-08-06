// ARM A DRIVER — `nub run --sandbox build-jail`, the static build-jail skeleton, run against the
// fixture repeatedly so the STABILITY question has something to be stable across.
//
// ⛔ WHAT THIS ARM IS AND IS NOT. `--sandbox build-jail` compiles the same `build_jail_surface`
// the lifecycle interposition does, so the tmp MODE and the AppContainer backend are identical --
// but it passes no `package_dir` and no `private_home`, and it does not go through
// `compile_build_jail`'s scrubbed lifecycle env. So it answers "what does the jail do to temp"
// and it does NOT answer "what env does a real postinstall see". `drive-lifecycle.mjs` is the arm
// that answers the second, and the two are reported separately for exactly that reason.
//
// ⛔ THE NEGATIVE CONTROL GATES EVERY OTHER ROW. A jailed arm whose write into the user profile
// SUCCEEDS is an arm where the jail did not engage, and every temp path it reported is then a
// property of an unconfined `node` -- indistinguishable from a real measurement by exit code.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const flag = (n, d = '') => {
  const i = process.argv.indexOf(n);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : d;
};

const NUB = flag('--nub');
const BASE = flag('--root', 'C:\\jail\\wintmp');
const OUT = flag('--out', path.join(BASE, 'out'));
const TIMEOUT = Number(flag('--timeout', '180000'));
if (!NUB || !fs.existsSync(NUB)) {
  console.error(`FATAL --nub must point at an existing nub.exe (got ${NUB || '<unset>'})`);
  process.exit(2);
}
const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const FIXTURE = path.join(HERE, 'probe-tmp.mjs');
const HOME = process.env.USERPROFILE;
const LOCALAPPDATA = process.env.LOCALAPPDATA;
const PACKAGES = path.join(LOCALAPPDATA, 'Packages');
const HOST_TEMP = process.env.TEMP;

fs.mkdirSync(OUT, { recursive: true });
// Created HERE, outside the jail, so the hardcoded-`C:\Temp` row measures PERMISSION and not
// existence -- a jailed ENOENT and a jailed EPERM are different answers to question 6.
fs.mkdirSync('C:\\Temp', { recursive: true });

// A stray nub.jsonc above the fixture supplies an `install.buildJail` nobody chose.
for (let d = BASE; ; d = path.dirname(d)) {
  for (const f of ['nub.jsonc', 'nub.json']) {
    if (fs.existsSync(path.join(d, f))) {
      console.error(`FATAL stray ${f} at ${d}`);
      process.exit(1);
    }
  }
  if (path.dirname(d) === d) break;
}

const listProfiles = () => {
  try {
    return fs.readdirSync(PACKAGES).filter((n) => n.startsWith('nub_sbx_'));
  } catch {
    return [];
  }
};

// The OUTSIDE half of "where did it land": run after each arm, with the driver's full rights, over
// the places a jailed write could plausibly have gone. An EMPTY result is a finding in its own
// right -- it says the scratch did not survive the run.
const scanOutside = (marker) => {
  const roots = [HOST_TEMP, PACKAGES, 'C:\\Windows\\Temp', 'C:\\Temp', BASE];
  const out = {};
  for (const root of roots) {
    const hits = [];
    let seen = 0;
    const walk = (dir, depth) => {
      if (depth > 6 || seen > 60000) return;
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (seen++ > 60000) return;
        const full = path.join(dir, e.name);
        if (e.name.includes(marker)) hits.push(full);
        if (e.isDirectory()) walk(full, depth + 1);
      }
    };
    walk(root, 0);
    out[root] = hits;
  }
  return out;
};

const extract = (stdout) => {
  const m = /@@PROBE@@([\s\S]*?)@@END@@/.exec(stdout ?? '');
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch (e) {
    return { parseError: String(e.message) };
  }
};

const NODE = process.execPath;
const SRC = fs.readFileSync(FIXTURE, 'utf8');

const probeArgs = (label, marker) => [
  '--label', label,
  '--marker', marker,
  '--negctl', path.join(HOME, `${marker}-negctl.txt`),
  '--hunt', [PACKAGES, HOST_TEMP].join(';'),
];

// ⛔ THE FIXTURE IS PASSED AS SOURCE, NOT AS A PATH, AND THAT IS NOT A STYLE CHOICE. With no
// `package_dir`, `build_jail_surface` emits an fs allowlist consisting of the OS minimal-root
// closure and the dependency-tree reads -- the GitHub workspace is not in it, so a jailed
// `node <path-to-fixture>` would die on a READ refusal that reads exactly like a temp finding and
// is not one. `--input-type=module -e <source>` needs no file at all. The driver reads the file
// with its own rights and hands the bytes over on the command line.
//
// ⛔ THREE SPELLINGS, TRIED IN ORDER, because `nub run --sandbox <shape> <cmd> [args]` reaches
// `run_sandboxed` through either the `script` positional or the trailing args depending on whether
// a `--` separator is present, and guessing wrong yields a clap usage error that looks nothing like
// a sandbox failure. The last form is the file spelling, kept only so a failure there is
// DISTINGUISHABLE from a quoting failure in the first two.
const runJailed = (cwd, label, marker, envPatch = {}) => {
  const env = { ...process.env, ...envPatch };
  for (const k of Object.keys(envPatch)) if (envPatch[k] === undefined) delete env[k];
  const p = probeArgs(label, marker);
  const forms = [
    ['run', '--sandbox', 'build-jail', '--', NODE, '--input-type=module', '-e', SRC, '--', ...p],
    ['run', '--sandbox', 'build-jail', NODE, '--input-type=module', '-e', SRC, '--', ...p],
    ['run', '--sandbox', 'build-jail', '--', NODE, FIXTURE, ...p],
  ];
  let last = null;
  for (const argv of forms) {
    const r = spawnSync(NUB, argv, { cwd, env, encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, timeout: TIMEOUT });
    last = { argv: argv.map((a) => (a === SRC ? '<fixture source>' : a)), r };
    if (extract(r.stdout)) return last;
  }
  return last;
};

const arms = [];
const record = (label, cwd, spawned, marker, note) => {
  const rec = extract(spawned.r.stdout);
  const row = {
    label,
    note,
    cwd,
    argv: spawned.argv,
    rc: spawned.r.status,
    signal: spawned.r.signal ?? null,
    spawnError: spawned.r.error ? String(spawned.r.error.message) : null,
    stderrTail: (spawned.r.stderr ?? '').slice(-1200),
    stdoutTail: (spawned.r.stdout ?? '').slice(-600),
    profilesDuringScan: listProfiles(),
    outsideScan: scanOutside(marker),
    probe: rec,
  };
  fs.writeFileSync(path.join(OUT, `${label}.stdout.txt`), spawned.r.stdout ?? '');
  fs.writeFileSync(path.join(OUT, `${label}.stderr.txt`), spawned.r.stderr ?? '');
  arms.push(row);
  return row;
};

const mkcwd = (name) => {
  const d = path.join(BASE, name);
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: `wintmp-${name}`, version: '1.0.0', private: true }, null, 2));
  return d;
};

const profilesBefore = listProfiles();

// ── U1: the unjailed reference, and the positive half of the negative control. ────────────────
{
  const marker = `nubtmpU1-${Date.now().toString(36)}`;
  const cwd = mkcwd('u1');
  const argv = [FIXTURE, ...probeArgs('U1', marker)];
  const r = spawnSync(NODE, argv, { cwd, encoding: 'utf8', maxBuffer: 1 << 28, timeout: TIMEOUT });
  record('U1', cwd, { argv: [NODE, ...argv], r }, marker, 'unjailed reference');
}

// ── J1/J2: the same command, the same cwd, twice. This is the "two runs of the same package"
//    axis: if the temp path differs between these two it is per-run, full stop. ───────────────
for (const label of ['J1', 'J2']) {
  const marker = `nubtmp${label}-${Date.now().toString(36)}`;
  const cwd = mkcwd('same');
  record(label, cwd, runJailed(cwd, label, marker), marker, 'jailed, identical command and cwd');
}

// ── J3: a different cwd / project identity. The "two different packages" axis for this arm. ──
{
  const marker = `nubtmpJ3-${Date.now().toString(36)}`;
  const cwd = mkcwd('other');
  record('J3', cwd, runJailed(cwd, 'J3', marker), marker, 'jailed, different cwd/project');
}

// ── J4/J5: perturb the PARENT's TEMP/TMP. Node's Windows `os.tmpdir()` consults TEMP then TMP
//    then `<SystemRoot>\temp`; knocking them out one at a time is what turns "TEMP is what it
//    read" from a claim about Node's source into a measurement. J5's fallback also lands on
//    `C:\Windows\temp`, which is the same target question 6 asks about. ────────────────────────
{
  const marker = `nubtmpJ4-${Date.now().toString(36)}`;
  const cwd = mkcwd('same');
  record('J4', cwd, runJailed(cwd, 'J4', marker, { TEMP: undefined }), marker, 'jailed, parent TEMP unset');
}
{
  const marker = `nubtmpJ5-${Date.now().toString(36)}`;
  const cwd = mkcwd('same');
  record('J5', cwd, runJailed(cwd, 'J5', marker, { TEMP: undefined, TMP: undefined }), marker, 'jailed, parent TEMP and TMP unset');
}

const profilesAfter = listProfiles();

// ── The gate. Printed FIRST in the summary because it decides whether anything below is real. ──
const u1 = arms.find((a) => a.label === 'U1');
const jailed = arms.filter((a) => a.label.startsWith('J'));
const u1Neg = u1?.probe?.negativeControl?.write?.ok === true;
const leaks = jailed.filter((a) => a.probe?.negativeControl?.write?.ok === true).map((a) => a.label);
const noRecord = jailed.filter((a) => !a.probe).map((a) => a.label);

const verdict = {
  negativeControlUnjailedSucceeded: u1Neg,
  jailedArmsThatBreachedTheControl: leaks,
  jailedArmsWithNoRecord: noRecord,
  valid: u1Neg && leaks.length === 0 && noRecord.length < jailed.length,
  profilesBefore,
  profilesAfter,
};

fs.writeFileSync(path.join(OUT, 'arm-a.json'), JSON.stringify({ verdict, arms }, null, 2));

const show = (a) => {
  const p = a.probe;
  if (!p) {
    return [
      `${a.label.padEnd(3)} rc=${a.rc} NO RECORD (${a.spawnError ?? 'no @@PROBE@@ frame'})`,
      `     last argv  = ${JSON.stringify(a.argv)}`,
      `     stderr tail= ${JSON.stringify(a.stderrTail)}`,
      `     stdout tail= ${JSON.stringify(a.stdoutTail)}`,
    ].join('\n');
  }
  const mk = p.mkdtemp.ok ? p.mkdtemp.value : null;
  const lines = [
    `${a.label.padEnd(3)} rc=${a.rc}  ${a.note}`,
    `     os.tmpdir()      = ${JSON.stringify(p.osTmpdir)}`,
    `     tmpdir source    = ${p.tmpdirSource}  (replay matches os.tmpdir(): ${p.tmpdirReplayMatches})`,
    `     env.TEMP         = ${JSON.stringify(p.env.TEMP)}`,
    `     env.TMP          = ${JSON.stringify(p.env.TMP)}`,
    `     env.USERPROFILE  = ${JSON.stringify(p.env.USERPROFILE)}`,
    `     env.LOCALAPPDATA = ${JSON.stringify(p.env.LOCALAPPDATA)}`,
    `     os.homedir()     = ${JSON.stringify(p.osHomedir.ok ? p.osHomedir.value : p.osHomedir)}`,
    `     env var count    = ${p.envCount}`,
    `     mkdtemp          = ${mk ? JSON.stringify(mk.dir) : JSON.stringify(p.mkdtemp)}`,
    `     mkdtemp realpath = ${mk ? JSON.stringify(mk.realpathNative.ok ? mk.realpathNative.value : mk.realpathNative) : '-'}`,
    `     write inside     = ${mk ? (mk.write.ok ? `ok roundTrip=${mk.write.value.roundTrip}` : `${mk.write.code}`) : '-'}`,
    `     C:\\Windows\\Temp  = ${p.hardcoded.windowsTemp.ok ? 'ok' : p.hardcoded.windowsTemp.code}`,
    `     C:\\Temp          = ${p.hardcoded.cTemp.ok ? 'ok' : p.hardcoded.cTemp.code}`,
    `     NEG CTL (home)   = ${p.negativeControl.write?.ok ? '⛔ SUCCEEDED (arm void)' : `refused ${p.negativeControl.write?.code}`}`,
    `     home readable    = ${p.homeReadable.ok ? `yes (${p.homeReadable.value} entries)` : `no ${p.homeReadable.code}`}`,
  ];
  for (const h of p.hunts ?? []) {
    lines.push(`     in-jail hunt ${h.root} exists=${h.exists} hits=${h.hits.length}${h.hits.length ? ` -> ${h.hits.slice(0, 4).join(' | ')}` : ''}`);
  }
  for (const [root, hits] of Object.entries(a.outsideScan)) {
    if (hits.length) lines.push(`     post-run scan ${root} -> ${hits.slice(0, 4).join(' | ')}`);
  }
  return lines.join('\n');
};

console.log('='.repeat(100));
console.log('ARM A — `nub run --sandbox build-jail`');
console.log('='.repeat(100));
console.log(`GATE: unjailed negative control succeeded: ${u1Neg}`);
console.log(`GATE: jailed arms that BREACHED the control: ${leaks.length ? leaks.join(',') : 'none'}`);
console.log(`GATE: jailed arms with no record: ${noRecord.length ? noRecord.join(',') : 'none'}`);
console.log(`GATE: arm A valid: ${verdict.valid}`);
console.log(`AppContainer profiles under ${PACKAGES}: before=${JSON.stringify(profilesBefore)} after=${JSON.stringify(profilesAfter)}`);
console.log('');
for (const a of arms) console.log(show(a) + '\n');

if (!verdict.valid) {
  console.log('⛔ ARM A IS VOID — the rows above are not evidence about the jail.');
  process.exit(1);
}
