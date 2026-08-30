// ⛔⛔ A SETTLEMENT MUST SURVIVE AN INSTRUMENT CHANGE THAT INVALIDATES NOTHING, AND MUST NOT SURVIVE
// ONE THAT INVALIDATES THE ROW.
//
// A row is SETTLED when re-measuring provably cannot change the outcome — the publish guard withheld
// its record and will withhold it again. `claim-slice.mjs` used to hold that settlement only while
// `settledAtHash` equalled the CURRENT digest, compared raw. Any harness commit moves that digest, so
// every settled row reopened on every epoch bump, including bumps whose transition invalidates
// nothing at all.
//
// MEASURED 2026-08-30 by replaying the reopen pass over a copy of the live queue at epoch 42: 59
// linux rows reopened `done` -> `pending`, all 59 lost `settledAtHash`, and 5 lost `attempts`. 55 of
// them carry `priorHarnessEpoch: null` — records from the UNVERSIONED v2 instrument, which no chain
// can rescue — so they re-settle only by being re-measured and re-withheld three times each
// (`RETRY_LIMIT` is 3 TOTAL attempts, and the reopen deletes the counter). That is three ~90-minute
// linux slices per bump, publishing nothing, and it is what held the macOS handoff for twelve hours
// across epochs 37-41.
//
// ⛔ THE POLICY HERE IS SYNTHETIC, ON PURPOSE. Pinning against the LIVE `invalidation.json` would make
// this test drift with every real epoch and quietly stop testing the property — and the property is
// about the SHAPE of a chain, not about today's digests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { settlementSurvives } from './record-validity.mjs';

const A = 'a'.repeat(64); // epoch 10
const B = 'b'.repeat(64); // epoch 11
const C = 'c'.repeat(64); // epoch 12
const current = { harnessEpoch: 12, harnessSha256: C };

/// Two hops, both measurement-neutral: `{verdicts: []}` has `.includes(v)` false for every verdict,
/// so it selects nothing. This is the shape every zero-cost bump in this corpus uses.
const neutral = {
  schemaVersion: 1,
  currentEpoch: 12,
  transitions: [
    { fromEpoch: 10, fromHarnessSha256: 'x'.repeat(64), toEpoch: 11, toHarnessSha256: A, invalidate: { verdicts: [] } },
    { fromEpoch: 11, fromHarnessSha256: A, toEpoch: 12, toHarnessSha256: B, invalidate: { verdicts: [] } },
    { fromEpoch: 12, fromHarnessSha256: B, toEpoch: 12, toHarnessSha256: C, invalidate: { verdicts: [] } },
  ],
};

const row = (verdict = 'MINIMUM', platform = 'linux-x64') =>
  ({ pkg: 'p', verdict, provenance: { platform } });

test('a settlement survives a chain of transitions that invalidate nothing', () => {
  const r = settlementSurvives(A, row(), current, neutral);
  assert.equal(r.survives, true, `settlement was dropped: ${r.reason}`);
  assert.equal(r.via, 'targeted-transition');
});

test('a settlement at the CURRENT digest needs no chain at all', () => {
  assert.equal(settlementSurvives(C, row(), current, neutral).survives, true);
});

// ⛔ THE NEGATIVE CONTROL, AND IT IS THE HALF THAT MATTERS. Preserving a settlement is only correct
// while nothing invalidates the row; a test that only proved settlements survive would happily pass
// against an implementation that never drops one, which is the dangerous direction — a row whose
// measurement the instrument genuinely changed would be frozen out of the corpus forever.
test('a settlement does NOT survive a transition whose scope matches the row', () => {
  const invalidating = {
    ...neutral,
    transitions: neutral.transitions.map((t) =>
      (t.toHarnessSha256 === B ? { ...t, invalidate: { verdicts: ['MINIMUM'] }, reason: 'MINIMUM re-derived' } : t)),
  };
  const hit = settlementSurvives(A, row('MINIMUM'), current, invalidating);
  assert.equal(hit.survives, false);
  assert.equal(hit.reason, 'MINIMUM re-derived');

  // …and a row the scope does NOT name still passes the same hop, so the selector is being read
  // rather than the transition merely being counted.
  assert.equal(settlementSurvives(A, row('UNKNOWN'), current, invalidating).survives, true);
});

test('it fails CLOSED on anything it cannot place on the chain', () => {
  // An unsettled row.
  assert.equal(settlementSurvives(null, row(), current, neutral).survives, false);
  // A digest that is not any transition's target — the chain cannot say where this settlement sits,
  // so it must not be honoured.
  assert.equal(settlementSurvives('z'.repeat(64), row(), current, neutral).survives, false);
  // A policy that does not name the current epoch: the same fail-closed rule `instrumentCompatibility`
  // applies, because a stale policy cannot vouch for anything.
  assert.equal(settlementSurvives(A, row(), current, { ...neutral, currentEpoch: 11 }).survives, false);
  // A forked chain — two transitions leaving the same digest — is ambiguous, not permissive.
  const forked = { ...neutral, transitions: [...neutral.transitions,
    { fromEpoch: 11, fromHarnessSha256: A, toEpoch: 12, toHarnessSha256: 'd'.repeat(64), invalidate: { verdicts: [] } }] };
  assert.equal(settlementSurvives(A, row(), current, forked).survives, false);
});

test('a cycle terminates rather than hanging the claim step', () => {
  const cyclic = { schemaVersion: 1, currentEpoch: 12, transitions: [
    { fromEpoch: 11, fromHarnessSha256: A, toEpoch: 12, toHarnessSha256: B, invalidate: { verdicts: [] } },
    { fromEpoch: 12, fromHarnessSha256: B, toEpoch: 12, toHarnessSha256: A, invalidate: { verdicts: [] } },
  ] };
  const r = settlementSurvives(B, row(), current, cyclic);
  assert.equal(r.survives, false);
  assert.equal(r.reason, 'invalidation transition cycle');
});
