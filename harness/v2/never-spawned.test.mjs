// An arm whose lifecycle script never LAUNCHED measured nothing and must be VOID, not a shortfall.
//
// ⛔ THE FAILURE THIS PREVENTS, measured 2026-08-07: `postman-code-generators@0.2.4` on win32
// produced the SAME shortfall digest at `fb0` (script ran, died immediately) and `fb1` (script
// never spawned — the `read:"disk"` rung fails the launch with ERROR_INVALID_PARAMETER). Both leave
// the tree at its pristine tarball state, so the two are byte-identical downstream, and the
// grant-independence test read their agreement as signal.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { neverSpawned, armNeverSpawned, NEVER_SPAWNED } from './never-spawned.mjs';

const HERE = import.meta.dirname;

// Verbatim from the win32 run that motivated this.
const LAUNCH_FAILED = [
  '  × lifecycle script postinstall failed for probepkg@1.0.0: failed to spawn',
  '  │ script postinstall: The parameter is incorrect. (os error -2147024809)',
].join('\n');

// Verbatim from the same package at a rung where the script DID run.
const RAN_AND_FAILED = [
  'TypeError: Cannot read properties of null (reading \'code\')',
  '  × lifecycle script postinstall failed for postman-code-generators@0.2.4:',
  '  │ script `postinstall` exited with code 1',
].join('\n');

test('⭑ a launch failure is detected', () => {
  assert.equal(neverSpawned(LAUNCH_FAILED), true);
});

test('⭑⭑ a script that RAN and exited non-zero is NOT a launch failure', () => {
  // THE load-bearing negative. Getting this wrong would VOID real measurements wholesale and
  // silently shrink the corpus — the arms that fail are exactly the ones the ladder exists to read.
  assert.equal(neverSpawned(RAN_AND_FAILED), false);
});

test('a package printing its OWN "failed to spawn" is not mistaken for nub failing to launch', () => {
  // Why the predicate anchors on nub's `lifecycle script … failed for …:` prefix rather than
  // matching the bare phrase: a package reporting that IT could not spawn something is a real
  // measurement, and voiding it would discard a genuine result.
  assert.equal(neverSpawned('node-gyp ERR! failed to spawn the compiler'), false);
  assert.equal(neverSpawned('Error: failed to spawn child process'), false);
});

test('empty / missing input is never a launch failure', () => {
  for (const v of ['', null, undefined]) assert.equal(neverSpawned(v), false);
});

test('armNeverSpawned reads the arm directory’s .log files, and ignores everything else', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-'));
  fs.writeFileSync(path.join(d, 'i.log'), 'installing…');
  assert.equal(armNeverSpawned(d), false, 'a clean arm is not void');
  fs.writeFileSync(path.join(d, 'a.log'), LAUNCH_FAILED);
  assert.equal(armNeverSpawned(d), true, 'a launch failure in any .log voids the arm');

  const d2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ns2-'));
  fs.writeFileSync(path.join(d2, 'notes.txt'), LAUNCH_FAILED);
  assert.equal(armNeverSpawned(d2), false, 'only *.log is consulted');
  assert.equal(armNeverSpawned(path.join(d2, 'nope')), false, 'a missing dir is not void');
});

test('⭑⭑ ALL THREE DRIVERS consult the shared predicate — none re-implements it', () => {
  // ⛔ A14. Three separate fixes in this effort reached one driver and were mistaken for landed.
  // A driver that grows its own spawn-failure check, or omits one while still recording a
  // shortfall, fails here rather than in the corpus hours later.
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.match(src, /never-spawned\.mjs/, `${d} must consult the shared never-spawned predicate`);
  }
});

test('⭑ CONTROL: the regex matches the real string and is not vacuous', () => {
  assert.ok(NEVER_SPAWNED instanceof RegExp);
  assert.match(LAUNCH_FAILED, NEVER_SPAWNED, 'the pattern must match the real captured output');
  assert.doesNotMatch(RAN_AND_FAILED, NEVER_SPAWNED);
});
