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

test('the two spellings the driver actually emits are both recognised', () => {
  // Labelled phases: `install` and `approve-builds --all`.
  assert.equal(driverReportedTimeout(
    '  VERIFY[at-grant] TIMED-OUT in `install` after 600000 ms -- no verdict; check for surviving children'), true);
  assert.equal(driverReportedTimeout(
    '  VERIFY[fb0] TIMED-OUT in `approve-builds` after 600000 ms -- no verdict; check for surviving children'), true);
  // The unlabelled safe-resolve phase, which runs FIRST and is the likeliest to time out on a cold
  // venue. A pattern requiring `VERIFY[...]` would miss this one silently.
  assert.equal(driverReportedTimeout(
    '  => TIMED-OUT in safe Nub resolution after 600000 ms -- no lifecycle script ran'), true);
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
