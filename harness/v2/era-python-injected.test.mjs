// ⛔ A DRIVER THAT CANNOT SEE THE PROVISIONED INTERPRETER FILES A TOOLCHAIN GAP AS A PACKAGE DEFECT.
//
// `era-python-parity.test.mjs` guards that every arm FORWARDS `ERA_PYTHON`. On win32 every arm did --
// they all forwarded the same `null` -- so the parity suite passed vacuously while the value was
// never found in the first place. Forwarding and DISCOVERY are separate failures and only one of
// them had a test.
//
// MEASURED on win32 probe 33229392476, `@aws-amplify+cli@2.0.0`, driver.out line 5:
//
//   ERA-PYTHON NOT-SATISFIED (era Node 10 needs python3-legacy; none of 2 candidate(s) matched)
//
// while the workflow had already installed a 3.9 and exported it as `ERA_PYTHON_LEGACY`. The cause
// was two halves, and either alone is enough to lose the interpreter: `measure-windows.mjs` composed
// its candidate list from `discoverPythons(probe)` ALONE, and its probe resolved every name through
// `where`, which searches the PATH -- exactly where both injected interpreters deliberately are not.
//
// Blast radius, measured over the 2811 driver logs carrying an `ERA-NODE PINNED` line: 1321 (47%)
// select an era <= 14, the band that needs a non-default interpreter. The win32 lane is 2265 rows.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { candidatePythons, resolveInterpreter, pythonForEra } from './era-python.mjs';

// A runner as it actually is: modern pythons ON the PATH, era interpreters installed OFF it.
const ON_PATH = {
  python3: { path: 'C:\\hostedtoolcache\\Python\\3.12.7\\x64\\python3.exe', version: 'Python 3.12.7' },
  python: { path: 'C:\\hostedtoolcache\\Python\\3.12.7\\x64\\python.exe', version: 'Python 3.12.7' },
};
const OFF_PATH = {
  'C:\\hostedtoolcache\\Python\\3.9.18\\x64\\python.exe': 'Python 3.9.18',
  'C:\\Python27\\python.exe': 'Python 2.7.18',
};
const LEGACY = 'C:\\hostedtoolcache\\Python\\3.9.18\\x64\\python.exe';
const PY2 = 'C:\\Python27\\python.exe';
// A probe that CAN resolve either form; `resolveInterpreter` is what earns that ability on Windows
// and is tested separately below.
const probe = (nameOrPath) => ON_PATH[nameOrPath]
  ?? (OFF_PATH[nameOrPath] ? { path: nameOrPath, version: OFF_PATH[nameOrPath] } : null);

test('the control: with nothing injected, a legacy era on this box is genuinely unsatisfiable', () => {
  // Known answer FIRST -- if this box could satisfy era 10 on its own, every assertion below would
  // pass without the fix and this file would be decoration. It is the win32 failure, reproduced.
  const chosen = pythonForEra(10, candidatePythons(probe, {}));
  assert.equal(chosen.path, null);
  assert.match(chosen.marker, /NOT-SATISFIED \(era Node 10 needs python3-legacy; none of 2 candidate\(s\) matched\)/);
});

test('an injected legacy interpreter satisfies the era the PATH could not', () => {
  const chosen = pythonForEra(10, candidatePythons(probe, { ERA_PYTHON_LEGACY: LEGACY }));
  assert.equal(chosen.path, LEGACY, 'era 10 did not receive the provisioned 3.9');
  assert.equal(chosen.family, 'python3-legacy');
});

test('the python2 channel is wired too, not just the one that was easiest to notice', () => {
  // Both variables or neither: a fix that wired only `ERA_PYTHON_LEGACY` leaves every era <= 7
  // native build failing on a Python 3 that node-gyp 3.x rejects outright.
  const chosen = pythonForEra(4, candidatePythons(probe, { ERA_PYTHON2: PY2, ERA_PYTHON_LEGACY: LEGACY }));
  assert.equal(chosen.path, PY2, 'era 4 did not receive the provisioned 2.7');
  assert.equal(chosen.family, 'python2');
});

test('a modern era is never handed a python2, however the box is provisioned', () => {
  // The other direction, and the expensive one: an unconditional python2 breaks every modern arm.
  const chosen = pythonForEra(24, candidatePythons(probe, { ERA_PYTHON2: PY2, ERA_PYTHON_LEGACY: LEGACY }));
  assert.equal(chosen.family, 'python3');
  assert.match(chosen.marker, /Python 3\./, `era 24 was given ${chosen.path}`);
});

test('an injected path that is also on the PATH is offered once, not twice', () => {
  const dup = ON_PATH.python3.path;
  const all = candidatePythons((n) => (n === dup ? ON_PATH.python3 : probe(n)), { ERA_PYTHON_LEGACY: dup });
  assert.equal(all.filter((c) => c.path === dup).length, 1, 'the de-duplication by path is gone');
});

test('resolveInterpreter takes an absolute path WITHOUT consulting the PATH lookup', () => {
  // The production condition exactly: `where` cannot find an off-PATH install, so a lookup-only
  // probe drops the candidate even once it is handed the right list.
  const lookup = () => null;
  assert.equal(resolveInterpreter(PY2, lookup, (p) => p === PY2), PY2);
  assert.equal(resolveInterpreter(PY2, lookup, () => false), null, 'a path that does not exist must not resolve');
  // ...and a bare NAME still goes through the lookup, or discovery stops working entirely.
  assert.equal(resolveInterpreter('python3', (n) => `/usr/bin/${n}`, () => false), '/usr/bin/python3');
});

test('the windows driver composes its candidates through the shared path', () => {
  // A source assertion, because the driver builds ERA_PYTHON in a module-scope IIFE that cannot be
  // imported on a non-win32 box. Paired with a control so it cannot pass vacuously.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'measure-windows.mjs'), 'utf8');
  assert.match(src, /pythonForEra\([^)]*candidatePythons\(probe\)\)/,
    'measure-windows.mjs does not compose its candidates through candidatePythons');
  assert.ok(!/discoverPythons/.test(src),
    'measure-windows.mjs still reaches for discoverPythons, which cannot see an injected interpreter');
  assert.match(src, /resolveInterpreter\(nameOrPath,/,
    'the windows probe cannot resolve an absolute path, so an injected candidate is dropped');
});
