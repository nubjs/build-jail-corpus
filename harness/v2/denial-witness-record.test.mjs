// The CONSUMER half of the denial witness: what `record.mjs` does with a DENIAL-WITNESS marker.
// `node --test harness/v2/denial-witness-record.test.mjs`.
//
// ⛔ THE PRODUCER AND THE CONSUMER ARE TESTED SEPARATELY AND BOTH ARE NEEDED, which is the same
// lesson the descent-variant vocabulary taught: `measure.sh` emitted `network` where the recorder
// matched `no-network`, both sides had passing tests, and the recomputation silently deleted NOTHING
// while the record still claimed `grantSource: "descended"`. So the marker's exact spelling is
// asserted on this side too, against a line built the way the scorer builds it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDriverLog } from './record.mjs';
import { marker } from './denial-witness.mjs';

const drv = (lines) => parseDriverLog(lines.join('\n'));

// A gate-vacuous run whose descent dropped `no-write-userHome` and where NO arm ever went red — the
// exact shape of the 213 records this instrument was built for. MEASURED 2026-08-31 across the 6887
// committed driver logs: 213 records match it, 38 package names, 124 linux / 82 win32 / 7 darwin.
const blocked = (extra = []) => [
  '  ARM-FALSIFIABILITY {"manifestFiles":697,"filesTheScriptProduced":0,"reasons":["gate-vacuous"]}',
  '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
  '  VERIFY[synth] rc=0 grant={"write":{"userHome":true}}',
  '  => VERIFIED {"write":{"userHome":true}}',
  ...extra,
  "     ⛔ OVER-PREDICTED — the strictly narrower {} also verifies; 'no-write-userHome' was not needed",
];

const witnessLine = (verdict, cap = 'no-write-userHome') => '  ' + marker({
  cap, scope: 'userHome', verdict, refusalsInScope: verdict === 'WITNESSED' ? 3 : 0,
  lifecyclePids: 4, events: 5120, sample: [],
});

test('with no marker at all the rule is exactly what it was — every pre-witness record is untouched', () => {
  const r = drv(blocked());
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.grant, { write: { userHome: true } });
  assert.deepEqual(r.denialWitness, {}, 'an absent marker must leave the map empty, not undefined');
});

test('a CLEAN witness on the only dropped capability licenses the narrowing with no red arm', () => {
  // RED ON REVERT: delete `&& !witnessLicenses` from the unfalsifiable branch. The record then keeps
  // {"write":{"userHome":true}} — the state all 213 are in today.
  const r = drv(blocked([witnessLine('CLEAN')]));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.deepEqual(r.grant, {});
  assert.match(r.grantSourceReason, /DENIAL-WITNESS CLEAN/);
});

test('a WITNESSED refusal keeps the wide grant — the arm passed by swallowing the denial', () => {
  // This is the case the whole file exists for: @pulumi/gcp@0.16.9 downloads
  // ~/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp into the REAL home by absolute path,
  // its drop-no-write-userHome arm reported rc=0 artifacts=697/697, and the plugin was simply absent.
  const r = drv(blocked([witnessLine('WITNESSED')]));
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.grant, { write: { userHome: true } });
  assert.ok(r.notes.includes('denial-witnessed'));
  assert.match(r.grantSourceReason, /ATTEMPTED a write inside no-write-userHome/);
});

test('a WITNESSED refusal OUTRANKS a red sibling arm — that is the residual risk it closes', () => {
  // The epoch-58 rule licenses the whole narrowing off a red arm on ANY capability. `record.mjs`
  // states the gap in its own comment: a script that writes essential output into the home and
  // swallows the EACCES in JS would still narrow wrongly. Here the red arm is present AND the home
  // write was witnessed; the wide grant must survive.
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}',
    '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true},"network":true}',
    '  => VERIFIED {"write":{"userHome":true},"network":true}',
    "     'no-network' is NECESSARY — dropping it fails to verify",
    witnessLine('WITNESSED'),
    "     ⛔ OVER-PREDICTED — the strictly narrower {\"network\":true} also verifies; 'no-write-userHome' was not needed",
  ]);
  assert.equal(r.descentRedArm, true, 'the red arm must still be parsed — this is not a parse failure');
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true });
});

test('a WITNESSED refusal blocks even when the artifact gate was LIVE', () => {
  // Not restricted to the unfalsifiable case, deliberately. The gate only inspects files under the
  // package's own directory, so a package that builds something there AND loses a home write passes a
  // perfectly live gate in an arm that lost its real product.
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true}}',
    '  => VERIFIED {"write":{"userHome":true}}',
    witnessLine('WITNESSED'),
    "     ⛔ OVER-PREDICTED — the strictly narrower {} also verifies; 'no-write-userHome' was not needed",
  ]);
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true } });
});

test('VOID licenses nothing and blocks nothing — the old rule runs unchanged', () => {
  for (const v of ['VOID', 'UNSUPPORTED', 'SOMETHING-ELSE']) {
    const r = drv(blocked([witnessLine(v)]));
    assert.equal(r.grantSource, 'synthesized', `${v} must not license a narrowing`);
    assert.deepEqual(r.grant, { write: { userHome: true } });
    assert.ok(!r.notes.includes('denial-witnessed'), `${v} must not read as a witnessed refusal`);
  }
});

test('a CLEAN witness on ONE of two dropped capabilities does not license the pair', () => {
  // ⛔ THE LOAD-BEARING RESTRAINT. 153 of the 213 dropped `no-network` alongside
  // `no-write-userHome`, and `denial-witness.mjs` reports UNSUPPORTED for the network axis: both
  // adapters classify `connect` ONLY, so a jail that refuses at `socket()` — which is what Landlock
  // plus the seccomp family filter does, measured — emits no event at all, and an absence of connect
  // refusals is therefore not evidence. Licensing the pair off the home arm alone would drop
  // `network` on the strength of a detector that was never pointed at it.
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}',
    '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true},"network":true}',
    '  => VERIFIED {"write":{"userHome":true},"network":true}',
    witnessLine('CLEAN'),
    witnessLine('UNSUPPORTED', 'no-network'),
    '  => OVER-PREDICTED by: no-network no-write-userHome  (synthesized {"write":{"userHome":true},"network":true}; each named capability drops on its own)',
  ]);
  assert.deepEqual(r.overPredictedBy, ['no-network', 'no-write-userHome']);
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true });
  assert.match(r.grantSourceReason, /no-network=UNSUPPORTED/,
    'the record must name which capability had no witness, or the next reader re-derives it');
});

test('one CLEAN capability plus a JOINT-VERIFIED arm still does not narrow the unwitnessed one', () => {
  // ⛔ THE SAME RESTRAINT WITH THE SECOND LINE OF DEFENCE REMOVED. In the test above the joint-arm
  // rule ALSO keeps the grant wide, so relaxing `every` to `some` only changed the reason string. Here
  // the joint arm verified, so `some` would publish `{}` — dropping `network` on the strength of a
  // detector that was never pointed at the network axis. This is the case that pins the quantifier.
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}',
    '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true},"network":true}',
    '  => VERIFIED {"write":{"userHome":true},"network":true}',
    witnessLine('CLEAN'),
    witnessLine('UNSUPPORTED', 'no-network'),
    '  => OVER-PREDICTED by: no-network no-write-userHome  (synthesized {"write":{"userHome":true},"network":true}; each named capability drops on its own)',
    '  => JOINT-NARROW VERIFIED {} — all 2 capabilities drop TOGETHER, measured',
  ]);
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true });
});

test('a marker with an unreadable payload is NOTED and licenses nothing', () => {
  const r = drv(blocked(['  DENIAL-WITNESS {"cap": nope}']));
  assert.equal(r.grantSource, 'synthesized');
  assert.ok(r.notes.includes('denial-witness-unparsable'), 'the reader has to be told the marker was there');
  assert.deepEqual(r.denialWitness, {});
});

test('a TRUNCATED marker line licenses nothing, silently — the regex is anchored at both ends', () => {
  // A line the anchored `(\{.*\})\s*$` cannot match is indistinguishable from no marker at all, and
  // that is the fail-closed direction: no licence. It is silent, which is the price of anchoring —
  // and anchoring is what stops a marker embedded in an echoed script line from being read as the
  // driver's own. Asserted so the silence is a decision rather than a surprise.
  const r = drv(blocked(['  DENIAL-WITNESS {"cap":"no-write-userHome",']));
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.denialWitness, {});
});

test('the witness travels on the record — publish-guard.mjs reads records, not logs', () => {
  const r = drv(blocked([witnessLine('WITNESSED')]));
  assert.deepEqual(r.denialWitness, { 'no-write-userHome': 'WITNESSED' });
});
