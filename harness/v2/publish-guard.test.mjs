// Cases for the publish guard. `node --test harness/v2/publish-guard.test.mjs`.
//
// ⛔ THE DISCRIMINATION CASES ARE THE POINT, NOT THE REFUSAL. A guard that withholds everything
// satisfies every "this is withheld" assertion and would freeze the corpus at its current grants
// while looking correct. So every WITHHOLD case here is paired with a PUBLISH case that differs in
// exactly one term, and the four real records this guard was written against are all present with
// their measured field values.
//
// The four are from the 2026-08-07 linux-x64 re-measure, and they span all three branches:
//
//   @pulumi/gcp@0.16.9           narrows, vacuous, no red arm   -> WITHHOLD
//   playwright-chromium@0.17.0   narrows, vacuous, RED ARMS     -> PUBLISH
//   lmdb-store@2.0.0-alpha2      narrows, falsifiable           -> PUBLISH
//   javascript-obfuscator@1.9.0  WIDENS, vacuous                -> PUBLISH
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, capsOf, narrows, hasRedArm } from './publish-guard.mjs';

const rec = (grant, notes, minimality) => ({ grant, notes, minimality });

test('capsOf flattens a grant, and a false-valued key grants nothing', () => {
  assert.deepEqual([...capsOf({ write: { deps: true }, network: true })].sort(),
    ['network', 'write.deps']);
  // A `network: false` key must not read as covering network, or a grant that explicitly denies
  // would compare equal to one that allows.
  assert.deepEqual([...capsOf({ network: false })], []);
  assert.deepEqual([...capsOf({})], []);
  assert.deepEqual([...capsOf(null)], []);
});

test('narrows reports the dropped capabilities, and is one-directional', () => {
  assert.deepEqual(narrows({ network: true }, {}), ['network']);
  // Widening drops nothing.
  assert.deepEqual(narrows({}, { network: true }), []);
  // A record that both adds and drops still narrows on the dropped term.
  assert.deepEqual(narrows({ write: { deps: true } }, { network: true }), ['write.deps']);
});

test('hasRedArm distinguishes MINIMAL-with-arms from MINIMAL-by-construction', () => {
  // Non-empty grant + MINIMAL = one arm per capability, every one failed.
  assert.equal(hasRedArm(rec({ network: true }, [], 'MINIMAL')), true);
  // ⛔ Empty grant + MINIMAL = the driver ran NO arms ("nothing to narrow; MINIMAL by
  // construction"). Same word, zero evidence. This is the @pulumi/gcp trap.
  assert.equal(hasRedArm(rec({}, [], 'MINIMAL')), false);
  assert.equal(hasRedArm(rec({ network: true }, [], 'OVER-PREDICTED')), false);
});

// ── the four measured records ─────────────────────────────────────────────────────────────────

test('WITHHOLD: @pulumi/gcp@0.16.9 — narrows to {} on vacuous arms with no red arm', () => {
  const prior = rec({ write: { userHome: true }, network: true }, [], 'OVER-PREDICTED');
  const incoming = rec({}, ['arms-unfalsifiable'], 'MINIMAL');
  const d = decide(prior, incoming);
  assert.equal(d.publish, false);
  assert.match(d.reason, /WITHHELD/);
  assert.match(d.reason, /network/);
});

test('PUBLISH: playwright-chromium@0.17.0 — narrows on vacuous GATE but both drop arms went red', () => {
  const prior = rec({ write: { deps: true, project: true, userHome: true }, network: true }, [], null);
  const incoming = rec({ write: { userHome: true }, network: true }, ['arms-unfalsifiable'], 'MINIMAL');
  const d = decide(prior, incoming);
  assert.equal(d.publish, true, 'a narrowing proven by two red arms must not be withheld');
  assert.match(d.reason, /live detector fired/);
});

test('PUBLISH: lmdb-store@2.0.0-alpha2 — narrows to {} but its arms were falsifiable', () => {
  const prior = rec({ network: true }, [], 'OVER-PREDICTED');
  const incoming = rec({}, [], 'OVER-PREDICTED');
  const d = decide(prior, incoming);
  assert.equal(d.publish, true);
  assert.match(d.reason, /falsifiable arms/);
});

test('PUBLISH: javascript-obfuscator@1.9.0 — fully vacuous, but it WIDENS', () => {
  // gate-vacuous AND rc-vacuous, i.e. no detector alive at all — and it still publishes, because
  // widening cannot break an install. This is the control that proves the guard is not just
  // refusing everything it is handed a flag for.
  const prior = rec({}, [], 'MINIMAL');
  const incoming = rec({ network: true }, ['arms-unfalsifiable'], 'OVER-PREDICTED');
  const d = decide(prior, incoming);
  assert.equal(d.publish, true);
  assert.match(d.reason, /does not narrow/);
});

// ── red-green: break the thing each term guards ───────────────────────────────────────────────

test('RED-GREEN on the red-arm term: playwright flips to WITHHOLD if no arm went red', () => {
  const prior = rec({ write: { deps: true, project: true, userHome: true }, network: true }, [], null);
  const green = rec({ write: { userHome: true }, network: true }, ['arms-unfalsifiable'], 'MINIMAL');
  assert.equal(decide(prior, green).publish, true);
  // Exactly one field changed: the descent no longer proved the remaining capabilities necessary.
  const red = { ...green, minimality: 'OVER-PREDICTED' };
  assert.equal(decide(prior, red).publish, false,
    'with no red arm the same narrowing must be withheld');
});

test('RED-GREEN on the vacuity term: pulumi publishes once its arms are falsifiable', () => {
  const prior = rec({ write: { userHome: true }, network: true }, [], 'OVER-PREDICTED');
  const withheld = rec({}, ['arms-unfalsifiable'], 'MINIMAL');
  assert.equal(decide(prior, withheld).publish, false);
  // Same narrowing, same empty grant, same absent red arm — only the flag is gone.
  const ok = { ...withheld, notes: [] };
  assert.equal(decide(prior, ok).publish, true,
    'a falsifiable measurement may narrow to {} — that is the descent working');
});

test('a package with NO prior record always publishes', () => {
  assert.equal(decide(null, rec({}, ['arms-unfalsifiable'], 'MINIMAL')).publish, true);
});
