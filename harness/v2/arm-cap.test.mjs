// A wall-clock cap that kills the process GROUP. The control test is the one that matters: without
// it, "the grandchild died" proves nothing, because it might have exited on its own.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { runCapped, TIMEOUT_EXIT } from './arm-cap.mjs';

const shellTest = (name, fn) => test(name, { skip: process.platform === 'win32' }, fn);

/** A script that spawns a long-lived GRANDCHILD then sleeps — the shape that leaked 211 processes.
 *
 *  ⛔ THE MARKER MUST BE IN THE GRANDCHILD'S ARGV, NOT THE SCRIPT'S TEXT. The first version of this
 *  fixture put it only in an `echo`, so `pgrep -f` matched NOTHING and the group-kill test passed
 *  because it counted zero survivors either way — a test that could not fail. The control below is
 *  what exposed it. The grandchild is therefore a script whose FILENAME carries the marker, which is
 *  what lands on its command line. */
function spawner(marker) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'armcap-'));
  const grandchild = path.join(dir, `${marker}-grandchild.sh`);
  fs.writeFileSync(grandchild, '#!/bin/bash\nsleep 300\n');
  fs.chmodSync(grandchild, 0o755);
  const p = path.join(dir, 'spawner.sh');
  fs.writeFileSync(p, `#!/bin/bash\n${grandchild} &\nsleep 300\n`);
  fs.chmodSync(p, 0o755);
  return p;
}
const alive = (marker) => {
  try { return execFileSync('pgrep', ['-f', marker], { encoding: 'utf8' }).trim().split('\n').filter(Boolean).length; }
  catch { return 0; }
};

shellTest('a fast command returns its own exit code, untouched by the cap', async () => {
  const r = await runCapped('/bin/sh', ['-c', 'exit 7'], { ms: 5000 });
  assert.equal(r.code, 7);
  assert.equal(r.timedOut, false);
});

shellTest('a capped run reports 124, the convention record.mjs already reads', async () => {
  const r = await runCapped('/bin/sh', ['-c', 'sleep 30'], { ms: 300 });
  assert.equal(r.code, TIMEOUT_EXIT);
  assert.equal(r.timedOut, true);
});

shellTest('the cap reaps a GRANDCHILD — the 211-process runaway case', async () => {
  const marker = `armcapA${process.pid}`;
  const script = spawner(marker);
  const r = await runCapped('/bin/bash', [script], { ms: 400, stdio: 'ignore' });
  assert.equal(r.timedOut, true);
  await new Promise((res) => setTimeout(res, 400));
  assert.equal(alive(marker), 0, 'a descendant survived the cap — the group kill did not reach it');
});

shellTest('CONTROL: a single-pid kill LEAVES the grandchild alive', async () => {
  // ⛔ WITHOUT THIS THE TEST ABOVE PROVES NOTHING. `harness/portable-timeout.sh` does exactly this —
  // `kill "KILL", $pid` — so it would not have caught the runaway either. Demonstrating the naive
  // form failing is what makes the group kill a fix rather than a coincidence.
  const marker = `armcapB${process.pid}`;
  const script = spawner(marker);
  const child = spawn('/bin/bash', [script], { stdio: 'ignore' });   // NOT detached, NOT group-killed
  await new Promise((res) => setTimeout(res, 400));
  child.kill('SIGKILL');
  await new Promise((res) => setTimeout(res, 400));
  const survivors = alive(marker);
  try {
    assert.ok(survivors > 0, 'the naive kill was expected to orphan the grandchild');
  } finally {
    try { execFileSync('pkill', ['-f', marker]); } catch { /* nothing left */ }
  }
});

shellTest('a command that cannot be executed reports 127 rather than hanging', async () => {
  const r = await runCapped('/definitely/not/a/binary', [], { ms: 2000 });
  assert.equal(r.code, 127);
  assert.equal(r.timedOut, false);
});

test('⛔ the driver emits a line record.mjs actually parses as HARNESS-TIMEOUT', async () => {
  // The cap is worthless if its verdict does not survive parsing. `record.mjs` keys the verdict off
  // `/=>\s*TIMED-OUT/`, so a line that SAYS "HARNESS-TIMEOUT" in words matches nothing, falls through
  // unparsed, and lands on HARNESS-ERROR — a different bucket for a reason no reader could recover.
  const { parseDriverLog } = await import('./record.mjs');
  const fsMod = await import('node:fs');
  const driver = fsMod.readFileSync(path.join(import.meta.dirname, 'measure.sh'), 'utf8');
  const emitted = driver.match(/echo "  (=> TIMED-OUT \(observe arm capped[^"]*)"/);
  assert.ok(emitted, 'measure.sh no longer emits a capped-arm verdict line');
  const line = emitted[1].replace(/\$\{ARM_CAP_SECS:-900\}/, '900');
  assert.equal(parseDriverLog(line).verdict, 'HARNESS-TIMEOUT');
  assert.equal(parseDriverLog(line.replace('TIMED-OUT', 'HARNESS-TIMEOUT')).verdict, null,
    'the control: the plausible-looking spelling is the one that does NOT parse');
});

test('⛔ BOTH POSIX drivers cap the observe arm — the guard that makes landed mean landed', () => {
  // dep-scaffold.mjs records TWO v2 fixes that landed in measure.sh alone and were mistaken for done.
  // measure-windows.mjs has its own --arm-timeout and is exempt.
  for (const d of ['measure.sh', 'measure-macos.sh']) {
    const src = fs.readFileSync(path.join(import.meta.dirname, d), 'utf8');
    assert.ok(src.includes('arm-cap.mjs'), `${d} does not cap its observe arm`);
    assert.match(src, /=> TIMED-OUT \(observe arm capped/, `${d} does not emit a parseable capped verdict`);
  }
});

test('a capped arm is NOT reported as a package verdict, on BOTH POSIX drivers', () => {
  // ⛔ `BROKEN-WITHOUT-JAIL-TOO` is a claim ABOUT THE PACKAGE. A capped arm establishes no such thing.
  // The 124 branch must therefore come BEFORE the generic non-zero branch, or every runaway package
  // silently becomes a false package verdict — which looks like data and is worse than the runaway.
  // measure.sh keys the cap off OBS_RC; measure-macos.sh keys it off DT_RC, because there the
  // wrapper never writes $OBS/rc on a cap and OBS_RC falls back to 99 — which the generic branch
  // would file as BROKEN-WITHOUT-JAIL-TOO, a claim about the PACKAGE that a timeout cannot support.
  for (const [driver, capMarker] of [['measure.sh', 'OBS_RC" -eq 124'], ['measure-macos.sh', 'DT_RC" -eq 124']]) {
    const src = fs.readFileSync(path.join(import.meta.dirname, driver), 'utf8');
    const capAt = src.indexOf(capMarker);
    const genericAt = src.indexOf('OBS_RC" -ne 0');
    assert.ok(capAt !== -1, `${driver} has no cap branch (${capMarker})`);
    assert.ok(genericAt !== -1, `${driver} has no generic failure branch`);
    assert.ok(capAt < genericAt, `${driver}: the 124 branch must precede the generic failure branch`);
  }
});

test('⛔ the drivers run arm-cap with the HARNESS node, never a bare `node`', () => {
  // MEASURED: with an era pin of 4.9.1 first on the arm PATH, a bare `node` IS Node 4 and cannot
  // parse a modern .mjs — `SyntaxError: Unexpected reserved word`, reported as an arm failure that
  // was entirely the harness's own. This is the class the ERA-NODE block already warns about ("7 of
  // 8 records came back HARNESS-ERROR, all 7 pinned"), reintroduced by the cap and caught by a probe.
  for (const d of ['measure.sh', 'measure-macos.sh']) {
    const src = fs.readFileSync(path.join(import.meta.dirname, d), 'utf8');
    assert.match(src, /HARNESS_NODE="\$\(command -v node\)"/, `${d} does not resolve its own node`);
    assert.match(src, /"\$HARNESS_NODE" "\$HERE\/arm-cap.mjs"/, `${d} invokes arm-cap with a bare node`);
    // and it must be captured BEFORE anything can rewrite PATH
    const capturedAt = src.indexOf('HARNESS_NODE="$(command -v node)"');
    const firstArmPath = src.indexOf('ARM_PATH=');
    assert.ok(capturedAt !== -1 && firstArmPath !== -1 && capturedAt < firstArmPath,
      `${d}: HARNESS_NODE must be resolved before the arm PATH exists`);
  }
});
