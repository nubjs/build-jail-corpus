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
const TIMEOUT = Number(flag('--timeout', '90000'));
const SMOKE_TIMEOUT = Number(flag('--smoke-timeout', '60000'));
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
//
// ⛔ EVERY ROOT CARRIES ITS OWN DEPTH AND ENTRY CAP, and the caps are small on purpose. A hosted
// runner's `%TEMP%` holds the whole toolcache extraction; an unbounded walk of it, repeated once
// per arm, is minutes of I/O buying nothing -- a marker written into temp is at depth 1 or 2.
const SCAN = [
  [() => HOST_TEMP, 3, 20000],
  [() => PACKAGES, 6, 20000],
  [() => 'C:\\Windows\\Temp', 2, 5000],
  [() => 'C:\\Temp', 2, 5000],
  [() => BASE, 6, 20000],
];
const scanOutside = (marker) => {
  const out = {};
  for (const [rootOf, maxDepth, cap] of SCAN) {
    const root = rootOf();
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
    out[root] = hits;
  }
  return out;
};

// ⛔ A FRAME THAT DOES NOT PARSE IS NOT A RECORD. Returning `{parseError}` made it truthy, and the
// gate then counted a garbage arm as one that had produced evidence -- caught in a dry run, where
// the crash landed in the formatter instead of in the verdict.
const FRAME = new RegExp(`@@PRO${'BE'}@@([\\s\\S]*?)@@E${'ND'}@@`);
let lastParseError = null;
const extract = (stdout) => {
  const m = FRAME.exec(stdout ?? '');
  if (!m) return null;
  try {
    return JSON.parse(m[1]);
  } catch (e) {
    lastParseError = String(e.message);
    return null;
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
// ⛔ THE SPELLING IS SETTLED ONCE, BY A THREE-SECOND SMOKE TEST, AND NOT RE-TRIED PER ARM. Trying
// N spellings inside every arm is what killed the first run of this probe: each jailed spawn that
// produces nothing burns the full timeout, and `nub run --sandbox <shape> <cmd> [args]` has three
// plausible spellings x five arms, so a jail that never starts costs 45 minutes of wall clock and
// leaves a jailed grandchild behind per attempt (spawnSync's deadline kills the DIRECT child only).
// MEASURED, run 31119799480: the runner lost communication with the server at exactly that mark.
// Settling the spelling on a payload with no fixture in it costs three spawns total, and a total
// failure is then reported in three minutes instead of being indistinguishable from a slow run.
// Assembled at runtime for the same reason the fixture's frame is: this string travels ON the
// command line, so a literal marker would let an echo of the argv pass for a successful run.
const SMOKE_TOKEN = `@@SMO${'KE'}@@`;
const SMOKE = 'process.stdout.write("@@SMO"+"KE@@")';
const spell = (cwd, tail) => [
  ['run', '--sandbox', 'build-jail', '--', NODE, ...tail],
  ['run', '--sandbox', 'build-jail', NODE, ...tail],
];
const smokeForms = (cwd) => [
  { name: 'sep+eval', argv: spell(cwd, ['-e', SMOKE])[0] },
  { name: 'bare+eval', argv: spell(cwd, ['-e', SMOKE])[1] },
  { name: 'sep+file', argv: spell(cwd, [path.join(cwd, 'smoke.cjs')])[0] },
];

let CHOSEN = null;
const chooseSpelling = (cwd) => {
  fs.writeFileSync(path.join(cwd, 'smoke.cjs'), `${SMOKE}\n`);
  const tried = [];
  for (const f of smokeForms(cwd)) {
    const t0 = Date.now();
    const r = spawnSync(NUB, f.argv, { cwd, encoding: 'utf8', maxBuffer: 1 << 24, windowsHide: true, timeout: SMOKE_TIMEOUT });
    const ok = (r.stdout ?? '').includes(SMOKE_TOKEN);
    tried.push({ form: f.name, ok, rc: r.status, ms: Date.now() - t0, stderr: (r.stderr ?? '').slice(-600), stdout: (r.stdout ?? '').slice(-300) });
    console.log(`SMOKE[${f.name}] ok=${ok} rc=${r.status} ${Date.now() - t0}ms`);
    if (!ok) console.log(`     stderr: ${JSON.stringify((r.stderr ?? '').slice(-600))}`);
    if (ok) {
      CHOSEN = f.name;
      break;
    }
  }
  fs.writeFileSync(path.join(OUT, 'smoke.json'), JSON.stringify(tried, null, 2));
  return tried;
};

const runJailed = (cwd, label, marker, envPatch = {}) => {
  const env = { ...process.env, ...envPatch };
  for (const k of Object.keys(envPatch)) if (envPatch[k] === undefined) delete env[k];
  const p = probeArgs(label, marker);
  let argv;
  if (CHOSEN === 'sep+file') {
    const f = path.join(cwd, `${label}.mjs`);
    fs.writeFileSync(f, SRC);
    argv = ['run', '--sandbox', 'build-jail', '--', NODE, f, ...p];
  } else {
    const tail = ['--input-type=module', '-e', SRC, '--', ...p];
    argv = CHOSEN === 'bare+eval' ? spell(cwd, tail)[1] : spell(cwd, tail)[0];
  }
  const r = spawnSync(NUB, argv, { cwd, env, encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, timeout: TIMEOUT });
  return { argv: argv.map((a) => (a === SRC ? '<fixture source>' : a)), r };
};

const arms = [];
const record = (label, cwd, spawned, marker, note) => {
  lastParseError = null;
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
    parseError: lastParseError,
    profilesDuringScan: listProfiles(),
    outsideScan: scanOutside(marker),
    probe: rec,
  };
  fs.writeFileSync(path.join(OUT, `${label}.stdout.txt`), spawned.r.stdout ?? '');
  fs.writeFileSync(path.join(OUT, `${label}.stderr.txt`), spawned.r.stderr ?? '');
  arms.push(row);
  // ⛔ PRINTED AND FLUSHED TO DISK AS EACH ARM LANDS, not batched into a summary at the end. The
  // first run of this probe lost every row it had already computed when the runner died partway
  // through, and a partial log would have said in one line what a second full run had to re-earn.
  console.log(show(row));
  console.log('');
  fs.writeFileSync(path.join(OUT, 'arm-a-partial.json'), JSON.stringify(arms, null, 2));
  return row;
};

const mkcwd = (name) => {
  const d = path.join(BASE, name);
  fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: `wintmp-${name}`, version: '1.0.0', private: true }, null, 2));
  return d;
};

const profilesBefore = listProfiles();
console.log('='.repeat(100));
console.log('ARM A — `nub run --sandbox build-jail`');
console.log('='.repeat(100));
console.log(`AppContainer profiles under ${PACKAGES} BEFORE: ${JSON.stringify(profilesBefore)}`);
console.log('');

// ── U1: the unjailed reference, and the positive half of the negative control. ────────────────
{
  const marker = `nubtmpU1-${Date.now().toString(36)}`;
  const cwd = mkcwd('u1');
  const argv = [FIXTURE, ...probeArgs('U1', marker)];
  const r = spawnSync(NODE, argv, { cwd, encoding: 'utf8', maxBuffer: 1 << 28, timeout: TIMEOUT });
  record('U1', cwd, { argv: [NODE, ...argv], r }, marker, 'unjailed reference');
}

// ── The spelling gate, on a payload with no fixture in it. Three spawns, then either a chosen
//    spelling or an immediate stop. ───────────────────────────────────────────────────────────
const smoke = chooseSpelling(mkcwd('smoke'));
console.log(`SMOKE chosen spelling: ${CHOSEN ?? '<none>'}`);
console.log('');
if (!CHOSEN) {
  console.log('⛔ NO SPELLING OF `nub run --sandbox build-jail` PRODUCED OUTPUT.');
  console.log('   Arm A is not run: five arms x one dead spelling is 8 minutes that says nothing');
  console.log('   the three spawns above have not already said. The stderrs are in smoke.json.');
  for (const t of smoke) console.log(`   ${t.form}: rc=${t.rc} ${t.ms}ms stderr=${JSON.stringify(t.stderr)}`);
  process.exit(1);
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

function show(a) {
  const p = a.probe;
  if (!p) {
    return [
      `${a.label.padEnd(3)} rc=${a.rc} NO RECORD (${a.spawnError ?? a.parseError ?? 'no probe frame in stdout'})`,
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
}

console.log('-'.repeat(100));
console.log(`GATE: unjailed negative control succeeded: ${u1Neg}`);
console.log(`GATE: jailed arms that BREACHED the control: ${leaks.length ? leaks.join(',') : 'none'}`);
console.log(`GATE: jailed arms with no record: ${noRecord.length ? noRecord.join(',') : 'none'}`);
console.log(`GATE: arm A valid: ${verdict.valid}`);
console.log(`AppContainer profiles under ${PACKAGES}: before=${JSON.stringify(profilesBefore)} after=${JSON.stringify(profilesAfter)}`);

if (!verdict.valid) {
  console.log('⛔ ARM A IS VOID — the rows above are not evidence about the jail.');
  process.exit(1);
}
