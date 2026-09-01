// ⛔⛔ THE INSTRUMENT UNDER TEST CAN ONLY EVER SAY "NO", SO A SAFE-SIDE CONTROL PROVES NOTHING.
// `observed-effect.mjs` returns a verdict that can WITHHOLD a record and never publish one, so a test
// suite that only checks "the dangerous record is withheld" passes on an instrument hardwired to
// veto everything. Every case below therefore comes in a pair: the input that must veto, and a
// neighbouring input that must NOT — and the exemption cases carry their own RED CONTROL showing
// exactly which input flips the veto off, because that is the direction in which a broken probe
// publishes an under-grant.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { observedEffect, vetoesNarrowing, declaresInstallWork, INSTALL_SCRIPTS } from './observed-effect.mjs';

// The measured shapes, from the 2026-09-01 win32-x64 re-measure of 30 whole-home packages. Named
// after the packages so a future reader can go back to the record rather than to a hypothetical.
const PULUMI = { lifecyclePids: 1, writes: 0, peers: 0, declares: true };        // `== WRITES ==`, empty
const AZURE_DEVOPS = { lifecyclePids: 1, writes: 4, peers: 0, declares: true };  // npmCache 1 jailHome 1 jailTmp 2
const AMPLIFY = { lifecyclePids: 1, writes: 204, peers: 0, declares: true };     // jailHome 201 deps 1 kernelfs 2

test('a script that DECLARED install work and produced none is NONE — the run measured the venue', () => {
  const r = observedEffect(PULUMI);
  assert.equal(r.verdict, 'NONE', `@pulumi/* shape must veto; got ${r.verdict}: ${r.reason}`);
  assert.equal(vetoesNarrowing({ observedEffect: r }), true, 'NONE must veto a narrowing');
});

test('⛔ RED CONTROL: one write anywhere — a free bucket included — turns the veto OFF', () => {
  // The dangerous direction. If this stayed NONE the detector would refuse every correct narrowing;
  // if the PULUMI case above were WORK the detector would publish every under-grant. Both halves
  // have to be reachable from inputs that differ by one field.
  const r = observedEffect(AZURE_DEVOPS);
  assert.equal(r.verdict, 'WORK', `a package whose product lands in the private home did work; got ${r.verdict}`);
  assert.equal(vetoesNarrowing({ observedEffect: r }), false, 'WORK must not veto');
  const one = observedEffect({ ...PULUMI, writes: 1 });
  assert.equal(one.verdict, 'WORK', 'a single write is enough — base-covered buckets are counted');
  assert.equal(observedEffect(AMPLIFY).verdict, 'WORK');
});

test('⛔ RED CONTROL: a peer with no writes is WORK — the network half is not decorative', () => {
  // `@pulumi/*` on a runner that HAS the CLI reaches the plugin CDN and writes into `~/.pulumi`.
  // A detector that keyed on writes alone would still veto a run that plainly did its work over the
  // network, which is the same refuse-everything failure from the other side.
  assert.equal(observedEffect({ ...PULUMI, peers: 1 }).verdict, 'WORK');
});

test('⛔ RED CONTROL: `declares: false` silently removes the veto, which is why the probe must read the tree', () => {
  // This is the false-CLEAN direction for this instrument. `@pulumi/gcp@6.9.0` DOES declare
  // `install`; a probe that answered `false` — `npm view` on a version whose registry manifest was
  // stripped, say — would exempt the exact record the term exists to catch, with no error anywhere.
  const broken = observedEffect({ ...PULUMI, declares: false });
  assert.equal(broken.verdict, 'NO-INSTALL-WORK');
  assert.equal(vetoesNarrowing({ observedEffect: broken }), false,
    'a wrong `declares` publishes the under-grant silently — the probe is load-bearing');
  // And the exemption is CORRECT for a package that really runs nothing: `npm rebuild` executes no
  // script for it, so zero effect is the answer rather than a gap.
  assert.match(broken.reason, /declares no install-time script/);
});

test('an unreadable manifest is UNKNOWN, never NONE and never an exemption', () => {
  const r = observedEffect({ ...PULUMI, declares: null });
  assert.equal(r.verdict, 'UNKNOWN');
  assert.equal(vetoesNarrowing({ observedEffect: r }), false);
  // ⛔ WHY UNKNOWN RATHER THAN A VETO. This term's whole job is to REFUSE, so failing closed here
  // would turn every unreadable-manifest record into a blanket refusal — the trade `measure.sh`'s
  // attribution branch already reverted (97 correct MINIMUMs refused to fix ~37 real gaps). It costs
  // nothing today: a `{}` record with no red arm is withheld by the evidence rule regardless.
  assert.match(r.reason, /could not be read/);
});

test('zero attributed pids belongs to the attribution branch, not to this one', () => {
  const r = observedEffect({ ...PULUMI, lifecyclePids: 0 });
  assert.equal(r.verdict, 'UNATTRIBUTED');
  assert.equal(vetoesNarrowing({ observedEffect: r }), false,
    'the drivers already emit UNKNOWN-ATTRIBUTION-FAILED for this; two verdicts for one state drift');
});

test('a record measured before the marker existed is UNKNOWN and changes nothing', () => {
  for (const absent of [{}, { lifecyclePids: null, writes: null, peers: null, declares: null }]) {
    const r = observedEffect(absent);
    assert.equal(r.verdict, 'UNKNOWN', JSON.stringify(absent));
    assert.equal(vetoesNarrowing({ observedEffect: r }), false);
  }
  assert.equal(vetoesNarrowing({}), false, 'a record with no field at all vetoes nothing');
  assert.equal(vetoesNarrowing(null), false);
});

// ── the DECLARES probe, against real trees ───────────────────────────────────────────────────
const tree = ({ scripts = null, gyp = false, manifest = true } = {}) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-vacuous-oe-'));
  if (manifest) fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', ...(scripts ? { scripts } : {}) }));
  if (gyp) fs.writeFileSync(path.join(d, 'binding.gyp'), '{}');
  return d;
};

test('the probe reads the INSTALLED tree and answers on the three scripts npm runs at install', () => {
  for (const k of INSTALL_SCRIPTS) {
    assert.equal(declaresInstallWork(tree({ scripts: { [k]: 'node x.js' } })).declares, true, k);
  }
  // ⛔ `prepare` IS DELIBERATELY EXCLUDED: the OBSERVE arm is `npm rebuild`, which never runs it, so
  // counting it would call a run "should have done work" over a script the arm cannot execute.
  assert.equal(declaresInstallWork(tree({ scripts: { prepare: 'husky', build: 'tsc', test: 'jest' } })).declares, false);
  assert.equal(declaresInstallWork(tree({ scripts: null })).declares, false);
});

test('⛔ binding.gyp alone declares work — the native builds are the grants that matter most', () => {
  // npm runs `node-gyp rebuild` for a package that ships one even with NO install script. Missing
  // this would exempt exactly the packages whose grants are widest.
  assert.equal(declaresInstallWork(tree({ scripts: null, gyp: true })).declares, true);
  assert.equal(declaresInstallWork(tree({ scripts: null, gyp: false })).declares, false);
});

test('an empty or whitespace script body is not a declaration', () => {
  assert.equal(declaresInstallWork(tree({ scripts: { postinstall: '' } })).declares, false);
  assert.equal(declaresInstallWork(tree({ scripts: { postinstall: '   ' } })).declares, false);
});

test('an unreadable tree is null, never false — absence is not "runs nothing"', () => {
  assert.equal(declaresInstallWork(tree({ manifest: false })), null);
  assert.equal(declaresInstallWork(path.join(os.tmpdir(), 'agent-vacuous-does-not-exist')), null);
  assert.equal(declaresInstallWork(''), null);
  assert.equal(declaresInstallWork(undefined), null);
});

test('MEASURED: the real @pulumi and backport install scripts declare work', () => {
  // The two payload shapes behind ten of the twelve withheld records, so the probe is pinned against
  // the manifests that actually produced them rather than against invented ones.
  assert.equal(declaresInstallWork(tree({
    scripts: { build: 'tsc', install: 'node scripts/install-pulumi-plugin.js resource gcp v6.9.0' },
  })).declares, true);
  assert.equal(declaresInstallWork(tree({
    scripts: { postinstall: "test -f ./dist/src/scripts/run-postinstall.js && node ./dist/src/scripts/run-postinstall.js || echo 'Dist folder missing'" },
  })).declares, true);
});

// ── THE ROUND TRIP INTO `results.json` ────────────────────────────────────────────────────────
//
// ⛔ THIS IS THE TEST `confinedWide` DID NOT HAVE, AND ITS ABSENCE COST A WHOLE PROBE. That field was
// parsed into the parser's state and then dropped by `record.mjs`'s explicit emitted whitelist, so
// the arm ran, printed, parsed — and left no trace in any record. `publish-guard.mjs` reads records
// and never logs, so a field that stops at the parser vetoes nothing.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { marker } from './observed-effect.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const runRecorder = (logLines) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-vacuous-rt-'));
  const log = path.join(dir, 'driver.out');
  fs.writeFileSync(log, logLines.join('\n'));
  const outRoot = path.join(dir, 'out');
  execFileSync(process.execPath, [path.join(HERE, 'record.mjs'),
    '--log', log, '--pkg', 'p', '--version', '1.0.0', '--out', outRoot, '--rc', '0'], { encoding: 'utf8' });
  const found = fs.globSync(path.join(outRoot, '**', 'results.json'));
  assert.equal(found.length, 1, `exactly one record should be written, got ${found.length}`);
  const rec = JSON.parse(fs.readFileSync(found[0], 'utf8'));
  fs.rmSync(dir, { recursive: true, force: true });
  return rec;
};

test('⭑ both halves round-trip all the way INTO the record, not merely into the parser', () => {
  const lines = [
    `  ARM-FALSIFIABILITY ${JSON.stringify({ reasons: ['gate-vacuous'], declaresInstallWork: true })}`,
    `  ${marker({ lifecyclePids: 1, writes: 0, peers: 0 })}`,
    '  => VERIFIED {}',
  ];
  const parsed = parseDriverLog(lines.join('\n'));
  assert.deepEqual(parsed.observedCounts, { lifecyclePids: 1, writes: 0, peers: 0 }, 'the parser read the counts');
  assert.equal(parsed.declaresInstallWork, true, 'the parser read the declares half off ARM-FALSIFIABILITY');

  const rec = runRecorder(lines);
  assert.equal(rec.observedEffect?.verdict, 'NONE',
    'the marker printed, parsed — and must also be IN the file the guard reads');
  assert.equal(vetoesNarrowing(rec), true);
});

test('⭑ RED-GREEN on the round trip: one non-zero write count changes the recorded verdict', () => {
  const rec = runRecorder([
    `  ARM-FALSIFIABILITY ${JSON.stringify({ reasons: ['gate-vacuous'], declaresInstallWork: true })}`,
    `  ${marker({ lifecyclePids: 1, writes: 2, peers: 0 })}`,
    '  => VERIFIED {}',
  ]);
  assert.equal(rec.observedEffect?.verdict, 'WORK');
  assert.equal(vetoesNarrowing(rec), false);
});

test('FAIL CLOSED: an unparsable marker leaves the counts null, notes it, and vetoes nothing', () => {
  const r = parseDriverLog('  OBSERVED-EFFECT {not json}');
  assert.equal(r.observedCounts, null);
  assert.ok(r.notes.includes('observed-effect-marker-unparsable'));
  // Absent is not unparsable — every committed record predates the marker and must not be noted.
  const none = parseDriverLog('  => VERIFIED {"network":true}');
  assert.equal(none.observedCounts, null);
  assert.ok(!none.notes.includes('observed-effect-marker-unparsable'));
});

test('a record from a log with NO marker records UNKNOWN, never NONE — the whole committed corpus', () => {
  const rec = runRecorder(['  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}', '  => VERIFIED {}']);
  assert.equal(rec.observedEffect?.verdict, 'UNKNOWN');
  assert.equal(vetoesNarrowing(rec), false);
});

test('⛔ all three classifiers emit the marker through the shared module, never a hand-written copy', () => {
  // Three `printf`s of one marker is how a note came to be live on one platform of three. The
  // drivers are `observe.mjs` (linux), `observe-macos.mjs` (darwin) and `classify.mjs` (win32).
  for (const f of ['observe.mjs', 'observe-macos.mjs', 'classify.mjs']) {
    const src = fs.readFileSync(path.join(HERE, f), 'utf8');
    assert.match(src, /import \{ marker as observedEffectMarker \} from '\.\/observed-effect\.mjs'/,
      `${f} must import the shared marker`);
    assert.match(src, /console\.log\(observedEffectMarker\(\{/, `${f} must emit it`);
    assert.doesNotMatch(src, /'OBSERVED-EFFECT/, `${f} must not hand-roll the marker string`);
  }
});

// ── END TO END: THE MARKER IS PRODUCED BY A REAL CLASSIFIER RUN ───────────────────────────────
//
// ⛔ THE SOURCE-LEVEL CHECK ABOVE IS NOT THIS. Grepping for the import proves the line exists, not
// that it RUNS or that the counts it carries are the classifier's own. A marker emitted with the
// wrong variable — an all-writes total instead of the attributed one, say — passes every grep and
// vetoes the wrong records.
import { spawnSync } from 'node:child_process';

const CLASSIFY = path.join(HERE, 'classify.mjs');
const ROOT_PID = 100, SHELL_PID = 200;
const winRoots = (project = 'C:\\obs', home = 'C:\\Users\\nub') => ({
  project, home, jailHome: null, globalStore: `${home}\\AppData\\Local\\nub\\pm\\store`,
  projectStore: `${project}\\node_modules\\.store`, interpreter: 'C:\\Program Files\\nodejs\\node.exe',
  toolsDir: `${home}\\AppData\\Local\\nub\\pm\\tools`, temp: `${home}\\AppData\\Local\\Temp`,
  npmPrefix: null, npmCache: null, ownPkg: `${project}\\node_modules\\thing`, cwd: null,
});
const runClassify = (events) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-vacuous-cls-'));
  fs.writeFileSync(path.join(dir, 'events.ndjson'), events.map((e) => JSON.stringify(e)).join('\n') + '\n');
  fs.writeFileSync(path.join(dir, 'capture.json'), JSON.stringify({ v: 1, roots: winRoots() }));
  const r = spawnSync(process.execPath, [CLASSIFY, path.join(dir, 'events.ndjson'),
    '--capture', path.join(dir, 'capture.json'), '--platform', 'win32', '--root-pid', String(ROOT_PID)],
  { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(r.status, 0, `classify exited ${r.status}\n${r.stderr}`);
  const line = r.stdout.split('\n').find((l) => l.includes('OBSERVED-EFFECT'));
  assert.ok(line, `no OBSERVED-EFFECT line in classify output:\n${r.stdout}`);
  return JSON.parse(/OBSERVED-EFFECT\s+(\{.*\})\s*$/.exec(line.trim())[1]);
};

test('⭑ a real classifier run emits the marker, and the counts are the ATTRIBUTED ones', () => {
  const shell = [
    { op: 'exec', path: 'C:\\Windows\\System32\\cmd.exe', pid: ROOT_PID, ppid: 1 },
    { op: 'exec', path: 'C:\\Windows\\System32\\cmd.exe', pid: SHELL_PID, ppid: ROOT_PID },
  ];
  // A script that did nothing: a lifecycle shell was attributed and it wrote nowhere.
  const idle = runClassify(shell);
  assert.ok(idle.lifecyclePids > 0, `a lifecycle shell must be attributed; got ${JSON.stringify(idle)}`);
  assert.equal(idle.writes, 0);
  assert.equal(idle.peers, 0);
  assert.equal(observedEffect({ ...idle, declares: true }).verdict, 'NONE');

  // ⛔ RED CONTROL, AND IT IS THE ATTRIBUTION HALF: a write by the ROOT pid is not the script's, so
  // it must NOT raise the count. A marker built from the whole traced tree would score this as WORK
  // and exempt exactly the records the veto exists for.
  const rootOnly = runClassify([...shell,
    { op: 'write', path: 'C:\\Users\\nub\\.pulumi\\plugins\\x', pid: ROOT_PID, result: 'ok' }]);
  assert.equal(rootOnly.writes, 0, 'a write outside the lifecycle subtree must not count as the script working');
  assert.equal(observedEffect({ ...rootOnly, declares: true }).verdict, 'NONE');

  // And the script's own write does raise it.
  const worked = runClassify([...shell,
    { op: 'write', path: 'C:\\Users\\nub\\.pulumi\\plugins\\x', pid: SHELL_PID, result: 'ok' }]);
  assert.equal(worked.writes, 1);
  assert.equal(observedEffect({ ...worked, declares: true }).verdict, 'WORK');
});
