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
import { classify, shortfallDigest } from './shortfall-invariance.mjs';

/** `rc:digest:ok|abs:count` per arm, oldest first — the ledger every driver accumulates. */
const ledger = (...arms) => arms.join('\n');

// ── `shortfallDigest` — the value the arms are compared BY ────────────────────────────────────────
//
// ⛔ IT LIVES IN THIS MODULE BECAUSE THREE CALLERS WANT IT AND A MIRRORED COPY WOULD DRIFT.
// `artifact-gate.mjs` prints it for the two POSIX drivers; `measure-windows.mjs` computes it for its
// own inline gate, which cannot call the POSIX gate. `classify` is the only consumer of the result,
// so the definition sits beside it rather than inside one of the three producers.

test('the digest is order-independent, so two arms with the same shortfall agree on its identity', () => {
  // ⛔ THE MANIFEST WALK'S ORDER IS FILESYSTEM-DEPENDENT. Without the sort, two arms that fell short by
  // exactly the same files would disagree on the digest — and disagreeing digests are read here as
  // "the shortfall responded to the grant", i.e. the refusing direction. Safe, but it would silently
  // delete the verdict rather than mis-issue it, which is the failure that never gets noticed.
  const files = ['build/Makefile', 'build/config.gypi', 'lib/x.node (10B < 20B)'];
  assert.equal(shortfallDigest(files), shortfallDigest([...files].reverse()));
  assert.match(shortfallDigest(files), /^[0-9a-f]{12}$/);
});

test('a DIFFERENT shortfall gets a different digest, and an empty one is `none`', () => {
  // The positive control for the case above: a digest that only ever collided would report every
  // failing ladder as grant-independent. And `none` is not cosmetic — `classify` refuses that value by
  // name, so an arm that PASSED the gate can never be counted toward grant-independence.
  assert.notEqual(shortfallDigest(['a']), shortfallDigest(['b']));
  assert.equal(shortfallDigest([]), 'none');
  assert.equal(classify(ledger(...Array(4).fill('0:none:ok:0'))).why,
    'no shortfall — the arms passed the gate');
});

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

// ⛔⛔ THE ABSENT TRAP. These lock the near-miss of 2026-08-07: I was about to key a new verdict on
// `allArmsRc0` alone, which would have read `netlify-cli@23.9.5`/`@26.2.0`/`@27.0.1` — rc=0 on all
// four arms with `artifacts=ABSENT` and 3 files in the tree against OBSERVE's 25,538 — as clean
// installs, and let a grant publish off a run in which nothing installed. That is an under-grant,
// the one direction this system may not take.
test('installActuallyRan is FALSE when every arm exited 0 but the package was ABSENT', () => {
  const r = classify('0:aa:abs:1\n0:aa:abs:1\n0:aa:abs:1\n0:aa:abs:1', 4);
  assert.equal(r.ok, false);
  assert.equal(r.code, 'PACKAGE_ABSENT');
  assert.equal(r.allArmsRc0, true, 'the exit codes really are all zero — that is the trap');
  assert.equal(r.installActuallyRan, false, 'rc=0 with nothing installed must NEVER read as a real install');
});

test('installActuallyRan is TRUE only when the arms exited 0 AND the package was present', () => {
  const r = classify('0:aa:ok:1\n0:aa:ok:1\n0:aa:ok:1\n0:aa:ok:1', 4);
  assert.equal(r.installActuallyRan, true);
  assert.equal(r.code, 'GRANT_INDEPENDENT');
});

test('every refusal carries a machine-readable code, so a driver need not parse prose', () => {
  const cases = [
    ['0:aa:ok:1\n0:aa:ok:1', 'LADDER_TRUNCATED'],
    // ⛔ THIS SLOT USED TO BE `1,0,0,0 -> ARM_EXITED_NONZERO`, which was the node-pty defect in
    // miniature: a failed NARROWEST rung followed by matching successes IS grant-independence, and
    // refusing it filed installable packages as `NO-STATE-PASSED`. That shape now fires, asserted in
    // its own test below. What still refuses is a ladder where NOTHING installed, and one whose
    // successes are not a suffix.
    ['1:aa:ok:1\n1:aa:ok:1\n1:aa:ok:1\n1:aa:ok:1', 'ARM_EXITED_NONZERO'],
    ['0:aa:ok:1\n1:aa:ok:1\n0:aa:ok:1\n0:aa:ok:1', 'ARM_EXITED_NONZERO'],
    ['1:aa:ok:1\n1:aa:ok:1\n1:aa:ok:1\n0:aa:ok:1', 'SINGLE_OK_ARM'],
    ['0:aa:abs:1\n0:aa:ok:1\n0:aa:ok:1\n0:aa:ok:1', 'PACKAGE_ABSENT'],
    ['0:aa:ok:1\n0:bb:ok:1\n0:aa:ok:1\n0:aa:ok:1', 'SHORTFALL_VARIED'],
    ['0:?:ok:1\n0:?:ok:1\n0:?:ok:1\n0:?:ok:1', 'NO_DIGEST'],
    ['0:none:ok:0\n0:none:ok:0\n0:none:ok:0\n0:none:ok:0', 'NO_SHORTFALL'],
  ];
  for (const [ledger, code] of cases) assert.equal(classify(ledger, 4).code, code, `ledger ${ledger}`);
});

test('the measured node-pty shape FIRES — a failed NARROWEST rung must not veto the successes', () => {
  // ⛔ THE DEFECT THIS EXISTS TO PIN, measured on `node-pty@1.1.0` (3.2M downloads/wk) 2026-08-17:
  //   rc=1 missing=7 shortfall=ea0776ba56ce  {"network":true}
  //   rc=0 missing=4 shortfall=4c85700f01f2  {write:{deps,project,userHome},network}
  //   rc=0 missing=4 shortfall=4c85700f01f2  {...,read:"disk",network}
  //   rc=0 missing=4 shortfall=4c85700f01f2  {write:"disk",network}
  // The package INSTALLS — rc=0 on three grants with an identical residual. The old blanket
  // `arms.some(rc !== 0)` refusal answered NOT-GRANT-INDEPENDENT because the FIRST rung failed, and the
  // driver then filed `NO-STATE-PASSED`, which reads as "the jail blocks this" about a package the jail
  // installs fine. ~20 records share this shape.
  const r = classify(ledger(
    '1:ea0776ba56ce:ok:7', '0:4c85700f01f2:ok:4', '0:4c85700f01f2:ok:4', '0:4c85700f01f2:ok:4'));
  assert.equal(r.ok, true, `a failed narrow rung must not veto an invariant suffix: ${r.why}`);
  // ⭑ THE COUNT COMES FROM THE SUCCESSFUL RUNGS, not from the failed one. Reading `arms[0]` would
  // publish 7 — a shortfall that widening demonstrably changed — where the grant-independent residual
  // is 4, and the count is the whole triage value of the verdict.
  assert.equal(r.count, '4', 'the invariant count is the successful rungs\' 4, never the failed rung\'s 7');
  assert.equal(r.sig, '4c85700f01f2', 'and the digest is likewise the one the successes share');
  // The flags still report the ladder honestly: not every arm exited 0, so a consumer that needs that
  // stricter fact can still ask for it.
  assert.equal(r.allArmsRc0, false, 'allArmsRc0 must stay FALSE — one rung really did fail');
});

test('a wider arm failing after a narrower one succeeded still refuses — that ladder is incoherent', () => {
  // No capability story explains a grant that works and then stops working when WIDENED, so this must
  // never be blessed however matched the digests are. It is the reason the rule is a SUFFIX rule rather
  // than "ignore any failed arm".
  const r = classify(ledger('0:aa11bb22cc33:ok:2', '1:aa11bb22cc33:ok:2', '0:aa11bb22cc33:ok:2', '0:aa11bb22cc33:ok:2'));
  assert.equal(r.ok, false);
  assert.match(r.why, /non-zero/);
});
