// Golden cases for `shortfall-invariance.mjs` — the predicate that decides whether a failing ladder
// failed for a reason the GRANT could ever fix.
//
// ⛔ THIS PREDICATE CAN PUBLISH A GRANT, so its false POSITIVES are the dangerous direction and every
// clause is pinned in both polarities. The three ledgers below are transcribed from real
// `records-v2/runs/linux-x64` driver logs, named where they come from, because each one is a shape
// that has already been mis-verdicted once:
//
//   windows-foreground-love@0.6.1  all 4 arms rc=0, identical 3-file shortfall  -> must FIRE
//   mozjpeg@6.0.1                  rc=0 on both arms, shortfall MOVED 0 -> 1    -> must NOT fire
//   netlify-cli@26.2.0             all 4 arms rc=0, `<package absent>` every    -> must NOT fire
//
// The middle one is the load-bearing negative: it is a healthy `MINIMAL` record whose only distinction
// from the first is that its shortfall responded to the grant. A rule keyed on exit codes would eat it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify } from './shortfall-invariance.mjs';

/** `rc:digest:ok|abs:count` per arm, oldest first — the ledger `measure.sh` accumulates. */
const ledger = (...arms) => arms.join('\n');

test('the measured windows-foreground-love shape FIRES — a correct grant that the ladder discarded', () => {
  // 4 arms, rc=0 everywhere, the same 3-file shortfall from the synthesized grant all the way up to
  // `write:"disk"`. This record landed as NO-STATE-PASSED with `grant: null`.
  const r = classify(ledger('0:a1b2c3d4e5f6:ok:3', '0:a1b2c3d4e5f6:ok:3', '0:a1b2c3d4e5f6:ok:3', '0:a1b2c3d4e5f6:ok:3'));
  assert.equal(r.ok, true, `an invariant shortfall must be recognised: ${r.why}`);
  assert.equal(r.count, '3', 'the invariant count is what makes the verdict triageable');
});

test('⛔ the measured mozjpeg shape does NOT fire — rc=0 on every arm but the shortfall MOVED', () => {
  // `mozjpeg@6.0.1` verdicts MINIMAL. Both its arms exited 0; the narrowed arm went short by one file
  // where the passing arm went short by none. If this fires, the gate has stopped discriminating at
  // rc=0 and a genuinely necessary capability becomes droppable.
  const r = classify(ledger('0:none:ok:0', '0:deadbeef1234:ok:1'), 2);
  assert.equal(r.ok, false, 'a shortfall that responded to the grant is a capability gap');
  assert.match(r.why, /CHANGED across arms/);
});

test('⛔⛔ the measured netlify-cli shape does NOT fire — `<package absent>` is not a measurement', () => {
  // All four arms rc=0 with an identical shortfall, which satisfies every OTHER clause. What holds it
  // out is that the package was never in the arm tree: `artifacts=ABSENT/1110`, 3 files against
  // OBSERVE's 35,566. Firing here would publish `{"write":{"userHome":true}}` off a run in which
  // nothing installed — an under-grant of unknown size.
  const abs = '0:f00dcafe0001:abs:1';
  const r = classify(ledger(abs, abs, abs, abs));
  assert.equal(r.ok, false, 'an absent package must never yield a grant');
  assert.match(r.why, /ABSENT/);
});

test('a non-zero arm does not fire — the ladder failed for a reason widening could still fix', () => {
  const r = classify(ledger('0:aaaa1111bbbb:ok:2', '1:aaaa1111bbbb:ok:2', '0:aaaa1111bbbb:ok:2', '0:aaaa1111bbbb:ok:2'));
  assert.equal(r.ok, false);
  assert.match(r.why, /non-zero/);
});

test('a truncated ladder does not fire — invariance over too few points is not invariance', () => {
  // Never reaching `write:"disk"` means the top of the grant lattice was never tested, and that rung is
  // the entire reason grant-independence means anything.
  const r = classify(ledger('0:aaaa1111bbbb:ok:2', '0:aaaa1111bbbb:ok:2'));
  assert.equal(r.ok, false);
  assert.match(r.why, /not fully walked/);
});

test('an unreadable digest REFUSES rather than supporting the claim — the safe direction', () => {
  const r = classify(ledger('0:?:ok:2', '0:?:ok:2', '0:?:ok:2', '0:?:ok:2'));
  assert.equal(r.ok, false, 'an arm whose gate line carried no digest cannot corroborate anything');
});

test('a clean ladder does not report as suspect — `none` is a pass, not an invariant shortfall', () => {
  const r = classify(ledger('0:none:ok:0', '0:none:ok:0', '0:none:ok:0', '0:none:ok:0'));
  assert.equal(r.ok, false);
  assert.match(r.why, /passed the gate/);
});
