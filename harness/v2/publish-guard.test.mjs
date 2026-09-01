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

// ── the second red-arm term: the driver's own per-arm announcement ─────────────────────────────
//
// ⛔ WITHOUT THIS TERM THE GUARD WITHHOLDS EXACTLY WHAT `record.mjs` NOW NARROWS, and the two files
// would disagree again in the opposite direction. `minimality: "MINIMAL"` requires EVERY arm red, so
// an OVER-PREDICTED record — some arms red, some green — can never satisfy the first term however
// plainly its descent went red. That is the shape of all 80 records the new rule narrows.

test('hasRedArm also accepts the driver-announced red descent arm', () => {
  // OVER-PREDICTED, so the MINIMAL term is false by construction; the announcement carries it.
  assert.equal(hasRedArm({ grant: { network: true }, minimality: 'OVER-PREDICTED' }), false);
  assert.equal(hasRedArm({ grant: { network: true }, minimality: 'OVER-PREDICTED', descentRedArm: true }), true);
  // ⛔ AND ON DARWIN, where the MINIMAL term is carved out entirely. The announcement has no such
  // carve-out and must not inherit one: it never existed in the two-way form that motivated it.
  assert.equal(hasRedArm({
    grant: { network: true }, minimality: 'MINIMAL', provenance: { platform: 'darwin-arm64' },
  }), false, 'the MINIMAL inference stays carved out on darwin');
  assert.equal(hasRedArm({
    grant: { network: true }, minimality: 'MINIMAL', provenance: { platform: 'darwin-arm64' },
    descentRedArm: true,
  }), true, 'but a directly announced red arm is sound there');
  // Absent and false are both "not established".
  assert.equal(hasRedArm({ grant: { network: true }, minimality: 'OVER-PREDICTED', descentRedArm: false }), false);
});

test('PUBLISH: an OVER-PREDICTED gate-vacuous narrowing publishes on its announced red arm', () => {
  // `@copilotkit/aimock@1.14.8`'s measured shape: ladder rung {write:{deps,project,userHome},network},
  // `no-network` red, the three writes each green, JOINT-NARROW VERIFIED {network:true}.
  const prior = rec({ write: { deps: true, project: true, userHome: true }, network: true }, [], null);
  const incoming = {
    ...rec({ network: true }, ['arms-unfalsifiable'], 'OVER-PREDICTED'),
    descentRedArm: true, falsifiabilityReasons: ['gate-vacuous'],
  };
  const d = decide(prior, incoming);
  assert.equal(d.publish, true, 'the guard must not withhold what record.mjs narrowed on the same evidence');
  assert.match(d.reason, /live detector fired/);
});

test('RED-GREEN on the announced red arm: the same narrowing is WITHHELD without it', () => {
  const prior = rec({ write: { deps: true, project: true, userHome: true }, network: true }, [], null);
  const withRed = {
    ...rec({ network: true }, ['arms-unfalsifiable'], 'OVER-PREDICTED'),
    descentRedArm: true, falsifiabilityReasons: ['gate-vacuous'],
  };
  assert.equal(decide(prior, withRed).publish, true);
  // Exactly one field changed.
  const noRed = { ...withRed, descentRedArm: false };
  const d = decide(prior, noRed);
  assert.equal(d.publish, false, 'with no red arm the identical narrowing must be withheld');
  assert.match(d.reason, /no descent arm went red/);
});

// ── the shapes review found, each of which published silently ────────────────────────────────

test('⛔ P2: `write:"disk"` is a capability — narrowing it away is not a no-op', () => {
  // The ladder's top rung is `{"write":"disk","network":true}` and `record.mjs` records a ladder
  // MINIMUM verbatim. Flattening only object-shaped `write` made the LARGEST possible narrowing
  // report "does not narrow" and publish.
  assert.deepEqual([...capsOf({ write: 'disk', network: true })].sort(), ['network', 'write:disk']);
  assert.deepEqual(narrows({ write: 'disk', network: true }, { network: true }), ['write:disk']);
  // A per-scope write does NOT satisfy whole-disk write.
  assert.deepEqual(narrows({ write: 'disk' }, { write: { deps: true } }), ['write:disk']);
  // …and the read axis is real too, for the `{"write":{…},"read":"disk",…}` rung.
  assert.deepEqual(narrows({ read: 'disk', network: true }, { network: true }), ['read:disk']);
});

test('⛔ P2: a vacuous record narrowing whole-disk write is WITHHELD, not waved through', () => {
  const prior = rec({ write: 'disk', network: true }, [], 'MINIMAL');
  const incoming = rec({ network: true }, ['arms-unfalsifiable'], 'OVER-PREDICTED');
  assert.equal(decide(prior, incoming).publish, false);
});

test('⛔ P3: on darwin, MINIMAL does not imply a red arm', () => {
  // measure-macos.sh's descent is a two-way branch, so a VOID arm collapses into "necessary" and
  // the driver prints MINIMAL having proven nothing. Linux/Windows keep three outcomes.
  const grant = { write: { userHome: true }, network: true };
  const darwin = { grant, notes: ['arms-unfalsifiable'], minimality: 'MINIMAL',
    provenance: { platform: 'darwin-arm64' } };
  const linux = { ...darwin, provenance: { platform: 'linux-x64' } };
  assert.equal(hasRedArm(darwin), false, 'darwin MINIMAL is not evidence a detector fired');
  assert.equal(hasRedArm(linux), true, 'linux MINIMAL with a non-empty grant IS');
  const prior = rec({ write: { deps: true, userHome: true }, network: true }, [], null);
  assert.equal(decide(prior, darwin).publish, false, 'the darwin narrowing must withhold');
  assert.equal(decide(prior, linux).publish, true, 'the linux one must still publish');
});

test('⛔ P4: a degraded VERDICT may not silently delete a measured grant', () => {
  // collate.mjs drops every non-MINIMUM verdict from the catalog, so this removes the package
  // outright. It used to fall through as "narrows on falsifiable arms" — true, and beside the point.
  const prior = { verdict: 'MINIMUM', grant: { network: true }, notes: [], minimality: 'MINIMAL' };
  for (const v of ['BROKEN-WITHOUT-JAIL-TOO', 'NO-STATE-PASSED', 'HARNESS-ERROR']) {
    const incoming = { verdict: v, grant: null, notes: [], minimality: null };
    const d = decide(prior, incoming);
    assert.equal(d.publish, false, `${v} must not replace a measured MINIMUM`);
    assert.match(d.reason, /collate\.mjs drops/);
  }
  // CONTROL: the reverse transition is an IMPROVEMENT and must publish — both happened this batch
  // (phantomjs@2.1.7 and windows-foreground-love@0.6.1).
  const wasBroken = { verdict: 'BROKEN-WITHOUT-JAIL-TOO', grant: null, notes: [], minimality: null };
  const nowMeasured = { verdict: 'MINIMUM', grant: { network: true }, notes: [], minimality: 'MINIMAL' };
  assert.equal(decide(wasBroken, nowMeasured).publish, true,
    'a package that became measurable must be allowed to gain a grant');
});

// ── THE NO-EFFECT VETO ────────────────────────────────────────────────────────────────────────
//
// ⛔⛔ WHAT THIS BLOCK IS DEFENDING AGAINST, AND IT IS A FIX SOMEONE IS ABOUT TO WRITE.
// The obvious way to unblock the twelve withheld `{}` records is a denial witness scored on the
// VERIFY arm: "the confined run attempted no refused access inside the dropped scope, so the
// narrowing is licensed". MEASURED on the 2026-09-01 win32-x64 re-measure, that licence is wrong for
// ten of the twelve — their scripts attempted nothing to be refused, because a precondition they
// silently depend on was absent on the runner. `@pulumi/*`'s `install-pulumi-plugin.js` is
// `spawnSync("pulumi", …)` followed by an unconditional `process.exit(0)`; with no Pulumi CLI on
// PATH it writes nothing, opens no socket and exits 0, so a witness returns CLEAN and every other
// detector reads green. The veto is what makes that licence unable to publish them.
//
// Each case is paired with one differing in a single term, so an instrument that vetoed
// unconditionally would fail here rather than look correct.
const eff = (verdict) => ({ verdict, reason: `test fixture: ${verdict}`, writes: 0, peers: 0, declares: true });

test('⛔ WITHHOLD: a narrowing off a run in which the script did NOTHING is vetoed', () => {
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true }, network: true } };
  const incoming = {
    verdict: 'MINIMUM', grant: {}, minimality: 'MINIMAL',
    notes: ['arms-unfalsifiable'], falsifiabilityReasons: ['gate-vacuous'],
    observedEffect: eff('NONE'),
  };
  const d = decide(prior, incoming);
  assert.equal(d.publish, false);
  // ⛔ THE REASON HAS TO NAME THE RIGHT FINDING. "No descent arm went red" points the next reader at
  // building a red arm, which for these records is impossible and would waste the effort that the
  // measurement of them was meant to save.
  assert.match(d.reason, /Nothing here measured the PACKAGE/);
  assert.match(d.reason, /network, write\.userHome/);
});

test('⛔ RED-GREEN: the same record with WORK observed falls back to the ordinary evidence rule', () => {
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true }, network: true } };
  const base = {
    verdict: 'MINIMUM', grant: {}, minimality: 'MINIMAL',
    notes: ['arms-unfalsifiable'], falsifiabilityReasons: ['gate-vacuous'],
  };
  // WORK does not PUBLISH it — the evidence rule still withholds — but it must withhold for the
  // OTHER reason, which is what proves the veto is not simply swallowing every case.
  const d = decide(prior, { ...base, observedEffect: eff('WORK') });
  assert.equal(d.publish, false);
  assert.doesNotMatch(d.reason, /Nothing here measured the PACKAGE/);
  assert.match(d.reason, /no descent arm went red/);
});

test('⛔⛔ THE VETO OUTRANKS THE STRONGEST EXISTING LICENCE, which is the whole point of its position', () => {
  // `descentRedArm` is the term that publishes an otherwise-vacuous narrowing today, and any
  // verify-arm witness would be added beside it. A no-effect run must not be publishable by either.
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true } } };
  const licensed = {
    verdict: 'MINIMUM', grant: { network: true }, minimality: 'OVER-PREDICTED',
    notes: ['arms-unfalsifiable'], falsifiabilityReasons: ['gate-vacuous'], descentRedArm: true,
  };
  // Without the veto this publishes — that is the existing, correct behaviour, and it is the control.
  assert.equal(decide(prior, licensed).publish, true);
  // With NONE observed it must not, however strong the other evidence looks.
  const vetoed = decide(prior, { ...licensed, observedEffect: eff('NONE') });
  assert.equal(vetoed.publish, false);
  assert.match(vetoed.reason, /Nothing here measured the PACKAGE/);
});

test('the veto never touches a record that does not NARROW — widening on a no-effect run still publishes', () => {
  // A wider grant cannot break an install, so the asymmetry the guard is built around is preserved:
  // the veto is a refusal added to the narrowing branch, never a new refusal of everything.
  const prior = { verdict: 'MINIMUM', grant: {} };
  const incoming = { verdict: 'MINIMUM', grant: { network: true }, observedEffect: eff('NONE') };
  assert.equal(decide(prior, incoming).publish, true);
  // And an identical grant likewise.
  assert.equal(decide({ verdict: 'MINIMUM', grant: { network: true } },
    { verdict: 'MINIMUM', grant: { network: true }, observedEffect: eff('NONE') }).publish, true);
});

test('every non-NONE verdict, and an absent field, leave the guard exactly as it was', () => {
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true } } };
  const base = {
    verdict: 'MINIMUM', grant: { network: true }, minimality: 'OVER-PREDICTED',
    notes: ['arms-unfalsifiable'], falsifiabilityReasons: ['gate-vacuous'], descentRedArm: true,
  };
  const licensed = decide(prior, base);
  assert.equal(licensed.publish, true, 'control: this narrowing publishes on its red arm');
  for (const v of ['WORK', 'NO-INSTALL-WORK', 'UNKNOWN', 'UNATTRIBUTED', 'SOMETHING-NEW']) {
    const d = decide(prior, { ...base, observedEffect: eff(v) });
    assert.equal(d.publish, true, `${v} must not veto`);
    assert.equal(d.reason, licensed.reason, `${v} must not change the reason either`);
  }
  // A record measured before the marker existed — the whole committed corpus — is untouched.
  assert.equal(decide(prior, { ...base, observedEffect: null }).reason, licensed.reason);
  assert.equal(decide(prior, base).reason, licensed.reason);
});

// ── THE FIRST MEASUREMENT, WHERE `narrows` IS EMPTY FOR THE OPPOSITE REASON ────────────────────
//
// ⛔ A PACKAGE WITH NO PRIOR RECORD DROPS NO TOKEN AND STILL LOSES CAPABILITY. nub reads an ABSENT
// catalog entry as the baseline INCLUDING its write-path promotion, and an EMPTY entry as a grant
// whose `write_paths` is empty — which returns before the promotion loop runs. So `{}` published
// where the corpus held nothing is tighter than publishing nothing at all, and every one of these
// cases used to reach `dropped.length === 0` and publish.
//
// `records-v2/runs/darwin-arm64/@pulumi+gcp/6.9.0` is committed in exactly this state: `MINIMUM`,
// grant `{}`, on the one platform of three whose runner ships no Pulumi CLI, while the linux and
// win32 records for the same version both measured `{"write":{"userHome":true},"network":true}`.
const first = (grant, observedEffect) => decide(null, { verdict: 'MINIMUM', grant, observedEffect });

test('⛔ WITHHOLD: a FIRST measurement of `{}` off a no-effect run is vetoed, though it drops nothing', () => {
  const d = first({}, eff('NONE'));
  assert.equal(d.publish, false, 'a first empty entry disables promotion and must not publish unmeasured');
  assert.match(d.reason, /EMPTY entry where the corpus has none/);
  assert.match(d.reason, /Nothing here measured the PACKAGE/);
});

test('⛔ RED CONTROL: the SAME first `{}` with real effect observed publishes', () => {
  // The dangerous direction for this term. A package that genuinely needs nothing — it ran, it did
  // its work, and the work needed no capability — must still be publishable as `{}`, or the corpus
  // loses every correct empty measurement it has. Only the observed-effect verdict differs here.
  for (const v of ['WORK', 'NO-INSTALL-WORK', 'UNKNOWN', 'UNATTRIBUTED']) {
    const d = first({}, eff(v));
    assert.equal(d.publish, true, `${v} must not veto a first empty entry; got: ${d.reason}`);
  }
  assert.equal(first({}, null).publish, true, 'a record predating the marker publishes as it always did');
});

test('⛔ RED CONTROL: a first NON-empty entry off a no-effect run still publishes', () => {
  // The term is scoped to the empty grant because that is the shape that disables promotion. A
  // no-effect run that nonetheless synthesised a capability is the old flag-never-fail case and is
  // deliberately untouched — refusing it would be the blanket refusal this guard already reverted.
  assert.equal(first({ network: true }, eff('NONE')).publish, true);
  assert.equal(first({ write: { userHome: true } }, eff('NONE')).publish, true);
});

test('a re-measure CONFIRMING an existing empty entry is left alone — the catalog does not move', () => {
  // Withholding here would buy nothing (the prior entry is the same `{}`) and would re-queue every
  // confirming run in the drain. The term asks whether the catalog would CHANGE, not whether the
  // record is well-founded.
  const d = decide({ verdict: 'MINIMUM', grant: {} }, { verdict: 'MINIMUM', grant: {}, observedEffect: eff('NONE') });
  assert.equal(d.publish, true);
  assert.equal(d.reason, 'does not narrow the existing grant');
});

test('a prior that is not a MEASUREMENT leaves the catalog empty, so `{}` still introduces an entry', () => {
  // `collate.mjs` drops every non-MINIMUM verdict, so a prior VOID is, to the catalog, no entry at
  // all — and publishing `{}` over it disables promotion exactly as a first measurement would.
  const d = decide({ verdict: 'VOID', grant: null },
    { verdict: 'MINIMUM', grant: {}, observedEffect: eff('NONE') });
  assert.equal(d.publish, false);
  assert.match(d.reason, /EMPTY entry where the corpus has none/);
});
