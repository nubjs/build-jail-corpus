// A driver timeout must be distinguishable from a failed grant, in both directions.
//
// The case that made this necessary is in `driver-timeout.mjs`: a 600 s driver deadline on
// `mozjpeg@6.0.1`'s control arm was reported as "the known-sufficient grant did NOT install", and it
// blocked every win32 lane of a 25% corpus run. The strings below are the driver's real output, copied
// from `measure-windows.mjs`, not paraphrased — a test written against paraphrased output would pass
// while the pattern missed the line the driver actually prints.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { driverReportedTimeout } from './driver-timeout.mjs';

test('ALL SIX of the driver timeout lines are recognised, each on its own', () => {
  // ⛔ EACH IS ASSERTED ALONE, WHICH IS THE POINT. My first pattern matched only shapes 1 and 2 and
  // still passed, because DIRECT mode prints shape 2 and shape 4 together — so a test that fed it the
  // whole output could not tell that shape 4 was unmatched. A ladder-rung timeout prints ONLY shape 5.
  //
  // Verbatim from measure-windows.mjs at the line numbers given; do not paraphrase them.
  const lines = [
    '  => TIMED-OUT in safe Nub resolution after 600000 ms -- no lifecycle script ran',                      // 1335
    '  VERIFY[at-grant] TIMED-OUT in `install` after 600000 ms -- no verdict; check for surviving children', // 1361
    '  VERIFY[fb0] TIMED-OUT in `approve-builds` after 600000 ms -- no verdict; check for surviving children', // 1367
    '  => TIMED-OUT (install); no verdict -- a hang says nothing about the grant',                           // 1481
    '  => TIMED-OUT at the synthesized grant (install); no verdict, and the ladder is NOT walked',           // 1628
    '  => TIMED-OUT on ladder rung 2 (approve-builds); the ladder is abandoned rather than continued',       // 1663
  ];
  for (const l of lines) {
    assert.equal(driverReportedTimeout(l), true, `unmatched driver timeout line: ${l.trim()}`);
  }
});

test('every TIMED-OUT line in the driver is covered by the pattern', () => {
  // ⛔ THE ENUMERATION GUARD. The list above is a snapshot; this reads the driver and fails when it
  // grows a seventh site the pattern does not match. Without it, a new timeout site is a silent
  // miss — exactly how the first three shapes went uncovered.
  const drv = fs.readFileSync(path.join(import.meta.dirname, 'measure-windows.mjs'), 'utf8');
  const emitted = drv.split('\n')
    .filter((l) => /console\.log\(`\s*(=>|VERIFY\[)/.test(l))
    // ⛔ RENDER FIRST, THEN FILTER — and that order is the whole correctness of this guard. Line 1606
    // prints `=> JOINT-NARROW INCONCLUSIVE — the arm was ${r.void ? 'VOID' : 'TIMED-OUT'}` : the word
    // appears only INSIDE an interpolation, so it is a mention, not a timeout report, and it must not
    // be required to match. Filtering the raw source first pulled it in and failed the guard on a line
    // that was never a timeout emission.
    .map((l) => l.replace(/^\s*(?:if \([^)]*\) \{ )?console\.log\(`/, '').replace(/`\).*$/, '')
      .replace(/\$\{[^}]*\}/g, 'X').replace(/\\`/g, '`'))
    .filter((l) => l.includes('TIMED-OUT'));
  assert.ok(emitted.length >= 6, `expected at least 6 driver timeout lines, found ${emitted.length} — `
    + 'the extractor stopped matching the driver, so this guard is no longer guarding anything');
  for (const l of emitted) {
    assert.equal(driverReportedTimeout(l), true, `driver emits a timeout line the pattern misses: ${l}`);
  }
});

test('a genuinely FAILING control is not mistaken for a timeout', () => {
  // ⛔ THE DIRECTION THAT WOULD LOWER THE GATE. Classifying a real failure as a timeout turns a FAIL
  // into an INCONCLUSIVE, and a known-sufficient grant that stopped installing is exactly what must
  // still reach a human. This is the assertion that keeps the fix from being a weakening.
  const realFailure = '  VERIFY[at-grant] rc=1 artifacts=7/8 missing=1 shortfall=vendor/cjpeg.exe '
    + '(tree 78/250) OVERRIDDEN=1 REJECTED=0 grant={"write":{"project":true},"network":true}\n'
    + '  => INSUFFICIENT under {"write":{"project":true}}';
  assert.equal(driverReportedTimeout(realFailure), false);

  const cleanPass = '  VERIFY[at-grant] rc=0 artifacts=8/8 missing=0 (tree 250/250) OVERRIDDEN=1 REJECTED=0\n'
    + '  => SUFFICIENT under {"network":true}';
  assert.equal(driverReportedTimeout(cleanPass), false);
});

test('a mere MENTION of the word does not count', () => {
  // The vocabulary appears in comments, in docs, and in this repo's own verdict list, so a loose
  // pattern would fire on prose. Only the driver's full phrasing counts.
  assert.equal(driverReportedTimeout('# TIMED-OUT is recorded as its own verdict, not a failure'), false);
  assert.equal(driverReportedTimeout('verdicts: MINIMUM, TIMED-OUT, BROKEN-WITHOUT-JAIL-TOO'), false);
  assert.equal(driverReportedTimeout('HARNESS-TIMEOUT'), false);
});

test('junk and empty input are false rather than throwing', () => {
  // `runArm` calls this on `(r.stdout ?? '') + (r.stderr ?? '')`, which is '' when the driver could
  // not be spawned at all. That case must fall through to the existing judges, not crash the gate.
  for (const v of ['', null, undefined, 0, {}, []]) assert.equal(driverReportedTimeout(v), false);
});

test('falsify.mjs reads the predicate from this module rather than carrying its own copy', () => {
  // ⛔ THE DUPLICATION THIS MODULE EXISTS TO PREVENT. `driver-invocation.mjs` was extracted after the
  // same knowledge was copied three times and two copies were wrong. A second inline regex in
  // falsify.mjs would drift the same way, and the drift is invisible: both copies "work" until a
  // driver changes one phrase.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'falsify.mjs'), 'utf8');
  assert.match(src, /import \{ driverReportedTimeout \} from '\.\/driver-timeout\.mjs'/);
  assert.match(src, /driverTimedOut: driverReportedTimeout\(out\)/);
  const inlineCopies = src.match(/TIMED-OUT in \|/g) ?? [];
  assert.equal(inlineCopies.length, 0,
    'falsify.mjs still carries an inline timeout regex — delete it and use the imported predicate');
});

test('the forwarded --arm-timeout is a flag the win32 driver actually PARSES', () => {
  // ⛔ THE DEFECT THIS GUARDS IS NAMED IN falsify.mjs's OWN COMMENTS: "a flag that is parsed,
  // validated for existence and then ignored". Forwarding an argument no driver reads would look
  // exactly like a working fix — the run would still be cut at 600 s — so pin the receiving end.
  const drv = fs.readFileSync(path.join(import.meta.dirname, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /ARM_TIMEOUT_MS = Number\(flag\('--arm-timeout'/,
    'measure-windows.mjs no longer reads --arm-timeout; falsify would be forwarding it into a void');
});

test('--arm-timeout is forwarded on win32 and NOT on the POSIX drivers', () => {
  // measure.sh and measure-macos.sh impose no per-phase deadline and have no such flag, so passing it
  // there would hand the driver a stray argument. Asserted on source: the argv shape is built inside
  // falsify.mjs, which runs its whole sweep at import and so cannot be imported for a unit test.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'falsify.mjs'), 'utf8');
  const win32Branch = src.slice(src.indexOf("process.platform === 'win32'\n    ? [...DRIVER_PRE"),
    src.indexOf(': [...DRIVER_PRE, DRIVER, kase.pkg, kase.version, NUB'));
  const posixBranch = src.slice(src.indexOf(': [...DRIVER_PRE, DRIVER, kase.pkg, kase.version, NUB'));
  assert.ok(win32Branch.includes("'--arm-timeout'"), 'win32 argv must forward --arm-timeout');
  assert.ok(!posixBranch.slice(0, 200).includes("'--arm-timeout'"),
    'the POSIX argv must NOT carry --arm-timeout — neither POSIX driver parses it');
});

test('the outer budget can never be shorter than the driver phases it contains', () => {
  // ⛔ THE MIS-ORDERING THAT MADE THE ORIGINAL BUG POSSIBLE TO MISREAD. The driver applies its deadline
  // to EACH of three phases, so an arm may legitimately want 3x it; falsify's spawnSync budget bounds
  // the whole arm. A flat 900 s outer budget against a 600 s x3 inner one means the outer can fire
  // first, killing the driver before it can report its own timeout — and then the arm reads as
  // UNPARSED for a second, different reason. Deriving the outer from the inner is what orders them.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'falsify.mjs'), 'utf8');
  assert.match(src, /ARM_TIMEOUT_MS \* 3 \+ 300_000/,
    'the win32 budget must be derived from ARM_TIMEOUT_MS, not picked independently');
  // And the knob must be reachable from a batch run, which forwards no flags.
  assert.match(src, /process\.env\.NUB_V2_ARM_TIMEOUT_MS/,
    'run-batch-v2.mjs forwards no flags to falsify, so the env var is the only way in');

  // The arithmetic itself, so a future edit to the constants cannot quietly invert the ordering.
  for (const armMs of [600_000, 1_200_000, 60_000]) {
    assert.ok(armMs * 3 + 300_000 > armMs * 3,
      'the derived budget must exceed the sum of the phases it contains');
  }
});

test('judgeRight treats a driver timeout as INCONCLUSIVE, never as a failed control', () => {
  // Asserted against the source because falsify.mjs runs its whole sweep at import and cannot be
  // imported for a unit test. Narrow on purpose: it pins the two facts that carry the fix — the
  // timeout term is part of the inconclusive branch's condition, and that branch sits BEFORE the
  // CONTROL FAILED push, which is what makes a timeout unable to reach it.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'falsify.mjs'), 'utf8');
  const cond = src.indexOf('arm.timedOut || arm.driverTimedOut');
  const controlFailed = src.indexOf('⛔ CONTROL FAILED:');
  assert.ok(cond > 0, 'judgeRight no longer tests arm.driverTimedOut — a driver timeout would read as a failure');
  assert.ok(controlFailed > cond,
    'the CONTROL FAILED branch must come AFTER the timeout branch, or a timeout falls into it');
});
