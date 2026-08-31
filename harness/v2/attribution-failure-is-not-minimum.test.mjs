// ⛔⛔ AN UNATTRIBUTED RUN MUST NOT BE RECORDED AS `MINIMUM`. THIS IS AN UNDER-PREDICTION GUARD.
//
// When the subtree filter matches nothing, the synthesized grant is `{}` — byte-identical to the
// grant for a package that genuinely needs nothing. The ladder then runs against that empty grant,
// the package passes because it exercises nothing at verify time, and the record lands as MINIMUM:
// "this package needs no permissions", asserted from a measurement that never happened.
//
// `corpus-v2-runner.yml` names this exact direction as the one that matters: a synthesized-nothing
// grant "reads as 'this package needs nothing' — an UNDER-prediction, the one direction that breaks
// real installs."
//
// MEASURED 2026-08-31 over the committed corpus, cross-tabulating each decoder's own
// `NO LIFECYCLE SHELL FOUND` warning against the verdict recorded beside it:
//
//   darwin   65 attribution failures -> 65 UNKNOWN                          (65/65 refused)
//   linux   134 attribution failures -> **100 MINIMUM** + 31 BWJT + 2 + 1
//   win32    28 attribution failures -> **26 MINIMUM** + 2 ARTIFACT-GATE-SUSPECT
//
// 126 records assert "needs nothing" on a run where nothing was attributed. The non-MINIMUM ones are
// unaffected — those verdicts do not rest on the grant being a real measurement, because the package
// failed for a reason the ladder observed directly.
//
// Darwin was already correct: `observe-macos.mjs:669` emits a token and `measure-macos.sh:906`
// branches on it. Both other decoders printed `Treat it as UNKNOWN` — prose addressed to a human
// reader, which nothing consumed and which therefore moved no verdict. This guard pins the
// back-port on all three platforms.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = import.meta.dirname;
const PROJ = '/home/u/root/observe';

/// The lifecycle shell exec. `observe.test.mjs` prepends this to EVERY case precisely because a
/// trace without it attributes nothing — which is exactly the condition under test here, so this
/// file is the one place it is deliberately withheld.
const SHELL = '100 execve("/usr/bin/sh", ["sh", "-c", "postinstall"], 0x1 /* 1 vars */) = 0\n';

const decode = (body) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'attr-test-'));
  const f = path.join(dir, 'trace.txt');
  fs.writeFileSync(f, body);
  const cap = path.join(dir, 'capture.json');
  fs.writeFileSync(cap, JSON.stringify({
    v: 1, kind: 'capture', pkg: 'p', version: '1.0.0',
    roots: {
      project: PROJ, home: '/home/u', jailHome: '/home/u/root/jailhome', temp: null,
      npmPrefix: null, ownPkg: `${PROJ}/node_modules/p`, globalStore: null,
      projectStore: `${PROJ}/node_modules/.store`, interpreter: null, toolsDir: null,
    },
  }));
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, '--capture', cap],
    { encoding: 'utf8' });
  return { out, grantLine: out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim() };
};

test('the linux decoder refuses to emit a grant it never measured', () => {
  // No lifecycle shell exec, so the subtree filter matches nothing.
  const unattributed = decode('200 write(1, "hi", 2) = 2\n');
  assert.equal(unattributed.grantLine, 'UNKNOWN-ATTRIBUTION-FAILED',
    'an unattributed run still emits a grant, so it will be recorded as a measurement');

  // ⛔ THE NEGATIVE CONTROL, AND IT IS THE HALF THAT MATTERS. A package that genuinely needs nothing
  // must still get `{}` — otherwise the "fix" is just emitting the token unconditionally, which
  // would turn every clean MINIMUM in the corpus into a non-answer. Same fixture, one line added.
  const attributed = decode(SHELL);
  assert.equal(attributed.grantLine, '{}',
    'a genuinely empty grant is now reported as an attribution failure — the token is unconditional');
});

/// Build an observe tree holding one installed package with the given `scripts`, plus an optional
/// `binding.gyp`. This is the artifact the drivers actually interrogate.
const observeTree = (scripts, gyp = false) => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-tree-'));
  const own = path.join(obs, 'node_modules', 'p');
  fs.mkdirSync(own, { recursive: true });
  fs.writeFileSync(path.join(own, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', scripts }));
  if (gyp) fs.writeFileSync(path.join(own, 'binding.gyp'), '{}');
  return obs;
};

/// Run a driver's own attribution branch, extracted from the file rather than paraphrased, with
/// `GRANT`, `OBS` and `PKG` bound. A paraphrase would drift from the thing it claims to cover,
/// invisibly — the reason `claim-cas.test.mjs` lifts its shell out of the workflow too.
const runBranch = (driver, grant, obs = observeTree({})) => {
  const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
  const start = src.indexOf('if [ "$GRANT" = "UNKNOWN-ATTRIBUTION-FAILED" ]; then');
  assert.notEqual(start, -1, `${driver}: the attribution-failure branch is gone`);
  const end = src.indexOf('\nfi\n', start) + 4;
  const body = src.slice(start, end);
  return execFileSync('bash', ['-c',
    `GRANT=${JSON.stringify(grant)}\nOBS=${JSON.stringify(obs)}\nPKG=p\n${body}\n`
    + 'echo "REACHED-THE-LADDER grant=$GRANT"'], { encoding: 'utf8' });
};

for (const driver of ['measure.sh', 'measure-macos.sh']) {
  test(`${driver} refuses only when the package actually declares an install-time script`, () => {
    // (b) A declared postinstall plus zero attribution is a real gap: refuse, and do not verify.
    const declared = runBranch(driver, 'UNKNOWN-ATTRIBUTION-FAILED', observeTree({ postinstall: 'node x.js' }));
    assert.match(declared, /=> UNKNOWN \(attribution failed/, `${driver} did not refuse a missed script`);
    assert.doesNotMatch(declared, /REACHED-THE-LADDER/,
      `${driver} carried on to the ladder after a real attribution failure, so the empty grant will `
      + 'still be verified and can still land MINIMUM');

    // ⛔ THE CONTROL THAT THIS TEST EXISTS FOR, AND THE ONE THE FIRST VERSION OF THIS FIX FAILED.
    // A package declaring only `build`/`test`/`lint` runs NOTHING under `npm rebuild`, so `{}` is a
    // real measurement. Refusing it converts a correct MINIMUM into a non-answer — measured on the
    // corpus, 97 of 134 linux attribution failures are that shape.
    const runsNothing = runBranch(driver, 'UNKNOWN-ATTRIBUTION-FAILED',
      observeTree({ build: 'tsc', test: 'jest', lint: 'eslint .' }));
    assert.match(runsNothing, /REACHED-THE-LADDER grant=\{\}/,
      `${driver} refused a package that runs no install script — that erases a true measurement`);
    assert.doesNotMatch(runsNothing, /=> UNKNOWN/, `${driver} reported UNKNOWN for a package that runs nothing`);

    // ⛔ `binding.gyp` WITH NO EXPLICIT SCRIPT IS STILL AN INSTALL-TIME SCRIPT — npm runs `node-gyp
    // rebuild`. Missing this would land a false MINIMUM on exactly the native packages whose grants
    // matter most, so it is the highest-consequence case in this file.
    const gyp = runBranch(driver, 'UNKNOWN-ATTRIBUTION-FAILED', observeTree({ build: 'tsc' }, true));
    assert.match(gyp, /=> UNKNOWN \(attribution failed/,
      `${driver} treated a binding.gyp package as running nothing — node-gyp rebuild is an install script`);

    // Fail CLOSED: a manifest that cannot be read cannot prove the package runs nothing.
    const unreadable = runBranch(driver, 'UNKNOWN-ATTRIBUTION-FAILED',
      fs.mkdtempSync(path.join(os.tmpdir(), 'obs-empty-')));
    assert.match(unreadable, /=> UNKNOWN \(attribution failed/,
      `${driver} treated an unreadable manifest as proof the package runs nothing`);

    // And a real grant must fall THROUGH the whole branch untouched.
    const ok = runBranch(driver, '{"network":true}');
    assert.match(ok, /REACHED-THE-LADDER/, `${driver} now blocks a real grant`);
    assert.doesNotMatch(ok, /=> UNKNOWN/, `${driver} reports UNKNOWN for a measured grant`);
  });
}

test('the windows driver branches on the count classify.mjs actually publishes', () => {
  // ⛔ STRUCTURAL, AND SAYING SO. Running `measure-windows.mjs` end-to-end needs an ETW capture and a
  // Windows host, so this pins the two halves of the contract that can be checked here: that
  // `classify.mjs` puts the count in the JSON payload the driver parses, and that the driver reads
  // THAT rather than re-deriving the fact from prose. Both halves can fail, which is what makes this
  // worth writing; neither is as strong as the executed cases above.
  const classify = fs.readFileSync(path.join(HERE, 'classify.mjs'), 'utf8');
  const reportStart = classify.indexOf('const report = {');
  assert.notEqual(reportStart, -1, 'classify.mjs no longer builds a `report` object');
  const reportBody = classify.slice(reportStart, classify.indexOf('\n};', reportStart));
  assert.match(reportBody, /lifecyclePids:/,
    'classify.mjs stopped publishing lifecyclePids, so the windows driver cannot see attribution failure');
  assert.match(classify, /if \(jsonOut\) fs\.writeFileSync\(jsonOut, JSON\.stringify\(report/,
    'the report is no longer the --json payload, so lifecyclePids may not reach the driver');

  const win = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(win, /if \(observed\.lifecyclePids === 0\)/,
    'measure-windows.mjs no longer refuses an unattributed run');
  // ⛔ SLICED TO THE END OF THE BRANCH, NOT TO A FIXED WIDTH. A 1,600-character window broke the
  // moment a comment was added inside the branch: the assertions below fell off the end and the test
  // went red for a reason that had nothing to do with behaviour. Bound it by the code instead.
  const branchStart = win.indexOf('if (observed.lifecyclePids === 0) {');
  const branch = win.slice(branchStart, win.indexOf('\n}\n', branchStart));

  // It must DISCRIMINATE, exactly as the POSIX drivers do: refuse only when the package declares an
  // install-time script, and count `binding.gyp` as one. A branch that refuses unconditionally is the
  // over-caution that erased 97 correct MINIMUM records on linux.
  assert.match(branch, /'preinstall', 'install', 'postinstall'/,
    'the windows branch no longer asks whether the package declares an install-time script');
  assert.match(branch, /binding\.gyp/,
    'the windows branch ignores binding.gyp, so a node-gyp package would be called "runs nothing"');
  assert.match(branch, /declares === 'no'/,
    'the windows branch no longer distinguishes "runs nothing" from "we failed to watch it"');
  assert.match(branch, /=> UNKNOWN \(attribution failed/);
  assert.match(branch, /process\.exit\(0\)/,
    'the windows branch reports UNKNOWN but does not stop, so the ladder still runs');
});
