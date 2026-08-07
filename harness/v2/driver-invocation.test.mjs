// The invocation contract, pinned. Three callers used to carry their own copy of this and two of
// them were wrong; the point of the module is that there is now one copy, and the point of this file
// is that the one copy cannot quietly lose a term.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { driverInvocation, driverArgv } from './driver-invocation.mjs';

test('darwin runs under `sudo -E`, and BOTH terms are asserted by name', () => {
  // ⛔ THE TWO TERMS THAT WERE ACTUALLY LOST. `sudo` because dtrace needs uid 0 — without it the
  // driver dies in ~3s with `DTrace requires additional privileges` and emits no verdict line, which
  // every caller's parser then reports as its own domain failure rather than as "it never ran".
  // `-E` because the driver needs the ambient PATH to find npm and reads SUDO_USER to drop measured
  // processes back to the invoking user; a bare `sudo` strips both.
  const d = driverInvocation('darwin');
  assert.equal(d.cmd, 'sudo', 'dtrace needs uid 0; a plain `bash` invocation cannot measure at all');
  assert.ok(d.pre.includes('-E'), '`-E` is load-bearing: bare sudo strips PATH and the driver cannot find npm');
  assert.ok(d.pre.includes('bash'), 'the darwin driver is a shell script');
  assert.equal(path.basename(d.file), 'measure-macos.sh');
});

test('linux runs the shell driver directly — no privilege escalation', () => {
  // The control that keeps the darwin assertion meaningful: if `sudo` leaked onto every platform the
  // test above would still pass while the harness prompted for a password on Linux.
  const d = driverInvocation('linux');
  assert.equal(d.cmd, 'bash');
  assert.deepEqual(d.pre, [], 'linux needs no escalation — strace runs unprivileged here');
  assert.equal(path.basename(d.file), 'measure.sh');
});

test('win32 runs the node driver — not a shell, which does not exist there', () => {
  const d = driverInvocation('win32');
  assert.equal(d.cmd, process.execPath, 'there is no `bash` on Windows at all');
  assert.deepEqual(d.pre, []);
  assert.equal(path.basename(d.file), 'measure-windows.mjs');
});

test('the three platforms name three DIFFERENT drivers — the dispatch is not collapsing', () => {
  // Without this, a refactor that returned one driver for every platform would satisfy every
  // assertion above that does not check the filename, and each platform would measure with another's
  // driver. `run-batch-v2.mjs`'s own header states the three are not interchangeable.
  const files = ['linux', 'darwin', 'win32'].map((p) => path.basename(driverInvocation(p).file));
  assert.equal(new Set(files).size, 3, `each platform needs its own driver, got ${files.join(', ')}`);
});

test('driverArgv is the prefix a caller spawns with, in order', () => {
  const argv = driverArgv('darwin');
  assert.deepEqual(argv.slice(0, 2), ['-E', 'bash'], 'the flag precedes the interpreter');
  assert.equal(path.basename(argv[2]), 'measure-macos.sh', 'and the script comes last');
});

test('the driver path is ABSOLUTE — a caller in another cwd still finds it', () => {
  // ⛔ MEASURED THE HARD WAY: a stub test resolved the driver relative to the CALLER's directory, so
  // both arms spawned nothing, exited 127, and both read as the expected refusal. Only the positive
  // control exposed it.
  for (const p of ['linux', 'darwin', 'win32']) {
    assert.ok(path.isAbsolute(driverInvocation(p).file), `${p} driver path must be absolute`);
  }
});
