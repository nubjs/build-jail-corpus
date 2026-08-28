// ⛔⛔ EVERY ARM THAT CAN RUN node-gyp MUST HOLD THE SAME INTERPRETER. When two arms disagree about
// which Python they are running, a failure in one is read as a defect in whatever the other blames —
// and on this axis the error points AT NUB.
//
// MEASURED on `node-sass@9.0.0` (darwin, era Node 18.20.8, epoch 5, `driver.out` retained beside the
// record). Every nub arm died with `ModuleNotFoundError: No module named 'distutils'`; Python 3.12
// removed `distutils` and node-gyp 8.4.1 requires it. `era-python.mjs --era 18` returns Python
// **3.9**, which has it — and the OBSERVE arm and the npm reference arm both held that 3.9, so npm
// installed the package cleanly. The control therefore reported "npm installs this package but nub
// cannot, even with the jail OFF" and the record was filed **BROKEN-UNJAILED-NUB**: a claimed NUB
// INSTALL DEFECT manufactured entirely by the harness handing two arms different interpreters.
//
// This is the epoch-4 npm-reference bug on the Python axis, and it is worse in one specific way.
// There, a spurious npm failure EXONERATED nub — it filed a candidate defect as a dead package.
// Here, a spurious nub failure CONVICTS it, in a verdict whose whole purpose is to name nub at fault.
//
// ⛔ `sudo` IS WHY EXPORTING THE VARIABLE IS NOT ENOUGH ON macOS. It resets the environment, so only
// what the `env` vector re-sets survives into the child. That is why `asIdentity` takes `python` and
// puts `PYTHON=` beside `PATH=` rather than relying on the driver's exported value.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');
// Comments explain the rule and quote the variable; only CODE carries it.
const code = (f) => read(f).split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l)).join('\n');

test('the jail-off control forwards the era Python on every driver', () => {
  const linux = code('measure.sh');
  const macos = code('measure-macos.sh');
  assert.match(linux, /--spawn-python "\$ERA_PYTHON"/,
    'the linux jail-off control does not forward the era Python — it will convict nub for our Python');
  assert.match(macos, /--spawn-python "\$ERA_PYTHON"/,
    'the darwin jail-off control does not forward the era Python');
});

test('asIdentity puts PYTHON on the sudo env vector, not merely in the environment', () => {
  const u = code('unjailed-nub.mjs');
  assert.match(u, /PYTHON=\$\{python\}/,
    'asIdentity does not re-set PYTHON across sudo, so macOS drops it however the driver exports it');
  assert.match(u, /PYTHON: python/,
    'the plain (linux/windows) spawn does not carry PYTHON into the child environment');
});

test('the verify arms hold the era Python too, or the control is fixed and the ladder is not', () => {
  // Fixing only the control trades one wrong verdict for another: the ladder would still fail at
  // every grant on a Python error, so the record becomes a JAIL finding instead of a nub one.
  const linux = code('measure.sh');
  const macos = code('measure-macos.sh');
  const win = code('measure-windows.mjs');
  // ⛔ SCOPED TO THE FUNCTION, NOT THE FILE. A file-wide match finds the `export PYTHON` that
  // `npm_ok` has carried since epoch 4, so deleting the verify arm's copy left this GREEN — measured
  // by removing it and watching nothing go red. An assertion that cannot fail is not an assertion.
  const lStart = linux.indexOf('\nverify () {');
  assert.notEqual(lStart, -1, 'the linux verify function is gone');
  const linuxVerify = linux.slice(lStart, linux.indexOf('\n}', lStart));
  assert.match(linuxVerify, /export PYTHON="\$ERA_PYTHON"/,
    'the linux verify arm does not export the era Python');
  // ⛔ SLICE TO THE FUNCTION'S OWN CLOSING BRACE, NOT TO A NAMED NEIGHBOUR. `unjailed_nub_ok` is
  // defined ABOVE `verify` in this file, so bounding the slice by it produced an EMPTY string and
  // the assertion read "found 0 arms" — a passing-looking shape that would have hidden the very
  // regression this guards. Caught by the count assertion, which is why it is there.
  const vStart = macos.indexOf('\nverify () {');
  assert.notEqual(vStart, -1, 'the darwin verify function is gone');
  const vEnd = macos.indexOf('\n}', vStart);
  const verify = macos.slice(vStart, vEnd);
  const sudoLines = verify.split('\n').filter((l) => l.includes('sudo -u "$RUNUSER"'));
  assert.ok(sudoLines.length >= 3, `expected at least 3 darwin verify sudo lines, found ${sudoLines.length}`);
  for (const l of sudoLines) {
    assert.ok(l.includes('PYTHON=$ERA_PYTHON'),
      `a darwin verify arm runs without the era Python:\n    ${l.trim().slice(0, 120)}`);
  }
  assert.match(win, /PYTHON: ERA_PYTHON/,
    'the windows verify arm does not carry the era Python');
});

test('the OBSERVE and npm reference arms still hold it — the parity is two-sided', () => {
  // The bug was an asymmetry, so a "fix" that dropped it from the arms that already had it would
  // restore parity and lose the interpreter everywhere. Assert both sides.
  for (const f of ['measure.sh', 'measure-macos.sh']) {
    assert.match(code(f), /PYTHON="\$ERA_PYTHON"|PYTHON=\$ERA_PYTHON/,
      `${f} lost the era Python from the arms that already had it`);
  }
  assert.match(code('measure-windows.mjs'), /PYTHON: ERA_PYTHON/,
    'the windows obsEnv lost the era Python');
});
