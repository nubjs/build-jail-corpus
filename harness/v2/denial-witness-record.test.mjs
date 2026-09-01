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

// ── the pair the whole 153 turn on ────────────────────────────────────────────────────────────

// The blocked shape those records are actually in: `no-network` dropped alongside
// `no-write-userHome`, so `record.mjs`'s `every` quantifier needs a verdict on BOTH.
const pair = (...witnesses) => [
  '  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}',
  '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
  '  VERIFY[synth] rc=0 grant={"write":{"userHome":true},"network":true}',
  '  => VERIFIED {"write":{"userHome":true},"network":true}',
  ...witnesses,
  '  => OVER-PREDICTED by: no-network no-write-userHome  (synthesized {"write":{"userHome":true},"network":true}; each named capability drops on its own)',
];
const netLine = (verdict) => '  ' + marker({
  cap: 'no-network', scope: 'network', verdict,
  refusalsInScope: verdict === 'WITNESSED' ? 4 : 0, lifecyclePids: 4, events: 5120, sample: [] });

test('CLEAN on BOTH dropped capabilities plus the joint arm narrows the pair — this unblocks the 153', () => {
  // ⛔ THE POINT OF THE WHOLE NETWORK AXIS, AS A RECORD. Before it, `no-network` could only come back
  // UNSUPPORTED, `every` never held, and a perfect answer on the home arm moved nothing.
  //
  // RED ON REVERT: delete `&& !witnessLicenses` from the unfalsifiable branch in `record.mjs`;
  // the record keeps `{"write":{"userHome":true},"network":true}` and the reason names both CLEAN
  // capabilities while refusing them. The PRODUCER-side revert — making `axisFor` return null for
  // `no-network` — does NOT redden this file, because the marker here is built by hand rather than
  // scored; that half is pinned in `denial-witness.test.mjs` and `denial-witness-decode.test.mjs`.
  const r = drv([...pair(witnessLine('CLEAN'), netLine('CLEAN')),
    '  => JOINT-NARROW VERIFIED {} — all 2 capabilities drop TOGETHER, measured']);
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.deepEqual(r.grant, {});
});

test('two CLEAN witnesses do NOT substitute for the joint arm — the two restraints are independent', () => {
  // ⛔ THE WITNESS ANSWERS "DID THE SCRIPT ASK?", NOT "DO THESE DROP TOGETHER?". The descent is
  // leave-one-out, so N green arms prove each capability drops ON ITS OWN and nothing proves the
  // joint grant verifies. Reading a full sweep of CLEAN as a licence for the pair would publish an
  // inference dressed as a measurement, in the under-grant direction. The joint arm is the separate
  // measurement, and `measure.sh` runs it whenever N >= 2 — so a re-measured record supplies both.
  const r = drv(pair(witnessLine('CLEAN'), netLine('CLEAN')));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true });
  assert.match(r.grantSourceReason, /JOINT drop was never run/);
});

test('WITNESSED on the network arm alone keeps the whole grant — the expected majority outcome', () => {
  // A package that dropped `network` and still passed most likely DID reach for it and swallowed the
  // refusal, so this branch is the one most of the 153 are expected to land in. That is a success:
  // it converts "kept wide because nothing could answer" into "kept wide because a refusal was
  // measured". Note the HOME capability is kept too — the record publishes one grant, and a single
  // witnessed capability keeps all of it.
  const r = drv(pair(witnessLine('CLEAN'), netLine('WITNESSED')));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true });
  assert.ok(r.notes.includes('denial-witnessed'));
  assert.match(r.grantSourceReason, /ATTEMPTED a write inside no-network/);
});

test('a CLEAN witness on ONE of two dropped capabilities does not license the pair', () => {
  // ⛔ THE LOAD-BEARING RESTRAINT, AND IT SURVIVES THE NETWORK AXIS EXISTING. A marker can still come
  // back UNSUPPORTED for `no-network` — every darwin stream does, because
  // `adapters/macos-observe.d` has no `socket` clause, and so does any stream whose decoder predates
  // socket-family retention. Licensing the pair off the home arm alone would drop `network` on the
  // strength of a detector that was never pointed at it.
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
