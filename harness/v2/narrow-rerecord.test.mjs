// Repairing a committed OVER-GRANT offline, and the properties that make writing a NARROWING to an
// archive safe: it may only ever narrow, it narrows only where today's unmodified rule already does,
// the record it writes must carry its own licence, the home may not be taken away on incomplete
// evidence, and it must touch four fields and be idempotent.
//
// ⛔ EVERY FIXTURE HERE IS A REAL CORPUS SHAPE. The narrowing log is the tool-cache shape — a
// positive `userHome` census whose every listed path sits inside a leaf nub's base profile already
// grants — which is what all 32 narrowable records look like
// (`electron-chromedriver@3.0.0` on linux is the measured original: 5 real-home writes, all five
// under `.cache/nub/pm/tools/electron-cache`). The widening log is the browser-downloader shape.
//
// ⛔ EACH GUARD HAS ITS OWN NAMED TEST AND ITS OWN RED CONTROL. A guard no fixture can break is
// either redundant or untested, and both are worth knowing.
//
//   node --test harness/v2/narrow-rerecord.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  NARROWED, REFUSED, REPAIRED_FIELDS, UNCHANGED, fieldDiff, narrowRerecord, narrowRerecordDir,
} from './narrow-rerecord.mjs';
import { REPAIRED_FIELDS as WIDEN_REPAIRED_FIELDS } from './rerecord.mjs';
import { STALE, replay } from './stale-adjudication.mjs';
import { parseDriverLog } from './record.mjs';
import { decide } from './publish-guard.mjs';

const HOME = '/home/runner';
const CAPTURE = { roots: { home: HOME, jailHome: `${HOME}/v2-x/jailhome` } };
const TOOLS = `${HOME}/.cache/nub/pm/tools`;

// The driver log the 32 narrowable records have: a descent that names `no-write-userHome`, arms that
// CAN fail (no `arms-unfalsifiable`), and a `userHome` census whose every listed path is inside
// `electron-cache` — a leaf `preset.rs` `push_rw_path`s unconditionally, so none of those writes ever
// needed `write.userHome`.
const lines = ({
  writes = ['    userHome      2'],
  feasibility = [
    '    count: 2',
    '        .cache/nub/pm/tools/electron-cache/chromedriver.zip',
    '        .cache/nub/pm/tools/electron-cache/SHASUMS256.txt',
  ],
  synthesized = '{"write":{"userHome":true},"network":true}',
  over = 'no-write-userHome',
  narrowGrant = '{"network":true}',
  falsifiability = '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":3,"reasons":[],"declaresInstallWork":true}',
  // A sibling arm that went RED, with its OWN `VERIFY[…]` line. `stale-adjudication.mjs`'s G2
  // re-attaches every `is NECESSARY` announcement to the nearest preceding VERIFY line and checks
  // that the LABEL names the capability, so an announcement floated in on its own scores
  // UNCORROBORATED and refuses the whole record.
  redArm = null,
  // ⛔ THE CENSUS IS PRESENT AND ZERO BY DEFAULT. G5 refuses an ABSENT network census exactly as G3
  // refuses an absent home census, so a fixture that omits the block tests the absence path rather
  // than whatever it meant to test.
  peers = 0,
  extra = [],
} = {}) => [
  falsifiability,
  '  == ROOTS (from capture.json — R2: no ambient reads) ==',
  `    home          ${HOME}`,
  `    jailHome      ${HOME}/v2-x/jailhome`,
  `    toolsDir      ${TOOLS}   [declared, not keyed on]`,
  '  == WRITES the script actually performed ==',
  ...writes,
  '  == NETWORK ==',
  `    AF_INET sockets: ${peers}   distinct peers: ${peers}`,
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  `    ${synthesized}`,
  '  == writePaths FEASIBILITY (distinct writes outside project/deps) ==',
  ...feasibility,
  `  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant=${synthesized}`,
  `  => MINIMUM ${synthesized}   (observed, then verified)`,
  ...(redArm ? [
    `  VERIFY[nar-${redArm}] rc=1 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant=${synthesized}`,
    `     '${redArm}' is NECESSARY — dropping it fails to verify`,
  ] : []),
  `  VERIFY[nar-${over}] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant=${narrowGrant}`,
  ...extra,
  `  => OVER-PREDICTED by: ${over}  (synthesized ${synthesized}; each named capability drops on its own)`,
];
const NARROW_LOG = lines().join('\n');

/** A committed record in the state the 32 are in: the WIDE grant, `grantSource: "synthesized"` with
 *  the pre-carve-out reason, and none of the epoch-58+ evidence fields, which did not exist when it
 *  was written. Fields the repair must preserve untouched are included deliberately. */
const committedRec = (over = {}) => ({
  pkg: 'demo-over', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM',
  grant: { write: { userHome: true }, network: true },
  synthesized: { write: { userHome: true }, network: true },
  verifiedBy: 'synth', minimality: 'OVER-PREDICTED', overPredictedBy: ['no-write-userHome'],
  writePaths: [],
  grantSource: 'synthesized',
  grantSourceReason: 'the descent narrowed, but OBSERVE attributed 2 write(s) to the REAL home and no '
    + 'denial witness came back CLEAN',
  descendedGrant: { network: true },
  notes: ['home-write-attributed'],
  eventLog: { events: 41022, dropped: 0 },
  driverRc: 0, durationMs: 91234,
  provenance: { platform: 'linux-x64', venue: 'ci', node: 'v22.15.0' },
  ...over,
});

// ── the narrowing arm fires ───────────────────────────────────────────────────────────────────────

test('⭑ a committed OVER-GRANT loses the user home from its own archived log', () => {
  // ⛔ THE MEASURED CASE. 32 committed records hold `write:{userHome}` whose entire real-home census
  // lands inside nub's own tool-cache leaves — authority over the whole user home, synthesized to
  // reach a directory the jail had already handed the script for free.
  const r = narrowRerecord({ committed: committedRec(), log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.deepEqual(r.narrowed, ['write.userHome']);
  assert.deepEqual(r.rewritten.grant, { network: true });
  // The grant never travels without the recorder's own account of why it is what it is.
  assert.equal(r.rewritten.grantSource, 'descended');
  assert.match(r.rewritten.grantSourceReason, /one capability \(no-write-userHome\) was dropped/);
  // The stale refusal marker goes with the stale grant: the census no longer refuses this drop.
  assert.ok(!r.rewritten.notes.includes('home-write-attributed'));
});

test('⭑ the repair touches the four fields it is about and NOTHING else', () => {
  // ⛔ `record.mjs`'s `rec` IS AN EXPLICIT WHITELIST, and a field missing from it is computed and then
  // thrown away — `confinedWide` shipped in that state. A rewrite that rebuilt the record instead of
  // patching it would reproduce that loss against the archive, where nothing re-reads it.
  const committed = committedRec();
  const r = narrowRerecord({ committed, log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.deepEqual(r.touched.slice().sort(), REPAIRED_FIELDS.slice().sort());
  assert.deepEqual(fieldDiff(committed, r.rewritten).slice().sort(), REPAIRED_FIELDS.slice().sort());
  // Key SET and key ORDER both, because the committed files round-trip byte-for-byte through the
  // recorder's serialization and a reordered key would hide the repair inside a whole-file diff.
  assert.deepEqual(Object.keys(r.rewritten), Object.keys(committed));
  for (const k of Object.keys(committed)) {
    if (REPAIRED_FIELDS.includes(k)) continue;
    assert.deepEqual(r.rewritten[k], committed[k], `${k} was not preserved`);
  }
  // And the fields today's recorder emits that this archive predates are NOT backfilled. For a
  // NARROWING that is load-bearing rather than tidy: `descentRedArm` is what `hasRedArm` reads, so
  // writing it would manufacture the very licence G4 exists to re-check.
  for (const k of ['falsifiabilityReasons', 'descentRedArm', 'denialWitness', 'observedEffect']) {
    assert.ok(!(k in r.rewritten), `${k} was backfilled into an archived record`);
  }
});

test('the two repairs write the SAME four fields, and a divergence is a failure rather than an inheritance', () => {
  // ⛔ DECLARED TWICE ON PURPOSE. Importing the widener's list would mean a field added to the
  // WIDENING repair silently became writable by the NARROWING one — the direction that loses
  // confinement. Pinned equal here so the divergence is caught instead of inherited.
  assert.deepEqual(REPAIRED_FIELDS, WIDEN_REPAIRED_FIELDS);
});

// ── G1: today's unmodified rule must already reach the narrowing ───────────────────────────────────

test('⭑ G1: a record today\'s rule keeps WIDE is refused — the falsifiability gate is not relaxed', () => {
  // ⛔ THE PLAYWRIGHT SHAPE, AND THE REASON THIS MODULE IS ALLOWED TO EXIST AT ALL. A positive
  // real-home census with a TRUNCATED path listing cannot be subtracted, so `record.mjs` keeps
  // `write.userHome`, `replay()` returns CURRENT, and there is no narrowing to apply.
  // `playwright-chromium@1.9.2` (linux) is the committed original: 1185 writes, `… and 1145 more`.
  const truncated = lines({
    writes: ['    userHome      1185'],
    feasibility: [
      '    count: 1185',
      '        .cache/nub/pm/tools/ms-playwright/chromium-869685/chrome-linux/chrome',
      '        … and 1184 more',
    ],
  }).join('\n');
  // The control: today's rule really does decline to narrow this one.
  assert.equal(replay({ committed: committedRec(), log: truncated, capture: CAPTURE }).verdict, 'CURRENT');
  const r = narrowRerecord({ committed: committedRec(), log: truncated, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /does not relax, waive or special-case/);
  assert.equal(r.rewritten, undefined, 'a refused record must not carry a rewrite');
});

test('G1: a log today\'s parser reads differently is refused before any repair', () => {
  // ⛔ `stale-adjudication.mjs`'s OWN G1. If the parser does not reproduce the committed `verdict` /
  // `minimality` / `overPredictedBy` / `synthesized` / `writePaths`, the grant delta is not
  // attributable to the RULE, and a repair justified by "the rule changed" has no standing.
  const r = narrowRerecord({
    committed: committedRec({ minimality: 'UNPROVEN' }), log: NARROW_LOG, capture: CAPTURE,
  });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /parse-drift on minimality/);
});

test('G1: a capture that cannot tell the real home from the jail home is refused', () => {
  // ⛔ `stale-adjudication.mjs`'s G3 roots term, reached through G1. A census rooted where the two
  // are indistinguishable bills jail-home writes to the real home and reads ZERO — a false CLEAR, in
  // the under-grant direction. A lane already billed 32 that way.
  const r = narrowRerecord({
    committed: committedRec(), log: NARROW_LOG, capture: { roots: { home: HOME, jailHome: HOME } },
  });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /do not confirm a real home distinct from the jail home/);
});

// ── G2: the direction, asked of the two grants ─────────────────────────────────────────────────────

test('⭑ G2: a PURE widening is refused, and G1 is what catches it', () => {
  // ⛔ OWNERSHIP, BECAUSE IT DECIDES WHAT A FUTURE EDIT MAY SAFELY MOVE. A replay that only ADDS
  // capabilities reaches `replay()`'s CURRENT branch — there is no dropped term — so G1 refuses it
  // before G2 is asked anything. G2's `widened` half is therefore NOT dead code and NOT this test's
  // subject: it is live only on a replay that drops AND adds, which the next test exercises. Both
  // are asserted because a refusal arriving from the wrong guard is how a gap opens later.
  const committed = committedRec({
    grant: { network: true }, grantSource: 'descended', notes: [],
  });
  const r = narrowRerecord({ committed, log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /stale-adjudication returned CURRENT/);
  assert.equal(r.rewritten, undefined, 'a refused record must not carry a rewrite');
});

test('⭑ G2: a replay that both drops and ADDS a capability is refused — that is not a narrowing', () => {
  // A record whose replay drops the home while restoring something the committed grant lost reaches
  // STALE on the dropped term alone, so `replay()` is no defence here: only the explicit
  // "nothing may be added" half stops it. Without that half this module would apply a widening under
  // a narrowing tool's name.
  const committed = committedRec({
    grant: { write: { userHome: true } },
    synthesized: { write: { userHome: true }, network: true },
  });
  // The control: the replay really does reach STALE, so the refusal below is this module's own.
  assert.equal(replay({ committed, log: NARROW_LOG, capture: CAPTURE }).verdict, STALE);
  const r = narrowRerecord({ committed, log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /would ADD network/);
  assert.match(r.reason, /may only ever NARROW/);
});

// ── G3: the home-write census, re-asked against the COMMITTED grant ────────────────────────────────

// A committed grant WIDER than the log's own synthesized one. `stale-adjudication.mjs`'s G1 pins
// `synthesized`, never `grant`, so this passes every upstream gate — and `record.mjs` never scored
// the home here, because ITS `dropsHome` compares synthesized against descended and neither carries
// the home. The rewrite takes the home off the committed grant anyway, so G3 is the only thing
// standing between the archive and a silent loss of it.
const WIDER_COMMITTED = () => committedRec({
  grant: { write: { userHome: true, project: true }, network: true },
  synthesized: { write: { project: true }, network: true },
  overPredictedBy: ['no-network'],
  descendedGrant: { write: { project: true } },
});
const widerLog = (opts = {}) => lines({
  synthesized: '{"write":{"project":true},"network":true}',
  over: 'no-network',
  narrowGrant: '{"write":{"project":true}}',
  ...opts,
}).join('\n');

test('⭑ G3: the home is not taken off a committed grant the LIVE rule never scored', () => {
  // ⛔ THE GAP THIS GUARD EXISTS FOR, AND IT IS LIVE RATHER THAN BELT-AND-BRACES. `record.mjs` asks
  // its census only when the DESCENT takes the home away. Here the descent never had it — the
  // COMMITTED grant did — so the live rule asked nothing at all and its silence is not evidence.
  const refusing = widerLog({
    writes: ['    userHome      9'],
    feasibility: ['    count: 9', '        .npm/_cacache/index-v5/aa/bb/cc'],
  });
  // The control: the log parses, the replay reaches STALE, and the drop really does take the home.
  const rep = replay({ committed: WIDER_COMMITTED(), log: refusing, capture: CAPTURE });
  assert.equal(rep.verdict, STALE, rep.reason);
  assert.ok(rep.dropped.includes('write.userHome'), 'the fixture must actually drop the home');

  const r = narrowRerecord({ committed: WIDER_COMMITTED(), log: refusing, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /home-write census came back REFUSE/);
});

test('G3: an ABSENT census refuses the home drop, and stale-adjudication owns that half', () => {
  // ⛔ THE OWNERSHIP IS THE FINDING. `homeDropVerdict` has three answers and this module's G3 requires
  // CLEAR, so it would refuse UNKNOWN too — but it never gets the chance: `stale-adjudication.mjs`'s
  // own G3 already refuses an absent census on any record whose replay drops the home, and G1 carries
  // that refusal here. So G3's UNKNOWN branch is unreachable through `replay()` while its REFUSE
  // branch (tested above) is live. Kept as `!== CLEAR` rather than narrowed to `=== REFUSE`, because
  // a fourth verdict added upstream must fail closed rather than fall through.
  const noCensus = widerLog({ writes: [], feasibility: ['    count: 0'] })
    .split('\n').filter((l) => !/== WRITES/.test(l)).join('\n');
  const r = narrowRerecord({ committed: WIDER_COMMITTED(), log: noCensus, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /no `== WRITES` census/);
  assert.match(r.reason, /does not relax, waive or special-case/);
});

test('⭑ G3: a CLEAR census resting on a TRUNCATED path listing is refused', () => {
  // ⛔ `CLEAR` IS NOT ENOUGH ON ITS OWN. A `CLEAN` denial witness clears a positive count without any
  // listing at all, so `homeWriteCensus` subtracted nothing and reconciled nothing (`basis:
  // count-only`) and what the printer omitted past its 40-entry cap is unknown. A live re-measure may
  // narrow on a witness because it can go back and look; an offline repair reading a frozen archive
  // cannot.
  const witnessed = widerLog({
    writes: ['    userHome      9'],
    feasibility: ['    count: 9', '        .npm/_cacache/index-v5/aa/bb', '        … and 8 more'],
    extra: ['  DENIAL-WITNESS {"cap":"no-write-userHome","verdict":"CLEAN"}'],
  });
  // The control: the census really does CLEAR — so what refuses this is the completeness term, not
  // the verdict term tested above.
  const parsed = parseDriverLog(witnessed);
  assert.equal(parsed.denialWitness['no-write-userHome'], 'CLEAN', 'the fixture must supply a CLEAN witness');

  const r = narrowRerecord({ committed: WIDER_COMMITTED(), log: witnessed, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /backed by no complete path listing/);
});

test('G3: a drop that does not take the home is not gated on the home census', () => {
  // Scoping control. The same refusing census, on a rewrite that leaves `write.userHome` in place,
  // must not block a narrowing it says nothing about.
  const committed = committedRec({
    grant: { write: { userHome: true }, network: true },
    synthesized: { write: { userHome: true }, network: true },
    overPredictedBy: ['no-network'],
    descendedGrant: { write: { userHome: true } },
  });
  const log = lines({
    writes: ['    userHome      9'],
    feasibility: ['    count: 9', '        .npm/_cacache/index-v5/aa/bb', '        … and 8 more'],
    over: 'no-network',
    narrowGrant: '{"write":{"userHome":true}}',
  }).join('\n');
  const r = narrowRerecord({ committed, log, capture: CAPTURE });
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.deepEqual(r.narrowed, ['network']);
  assert.deepEqual(r.rewritten.grant, { write: { userHome: true } });
});

// ── G4: the scorer, re-asked of the record actually written ────────────────────────────────────────

test('⭑ G4: a narrowing whose WRITTEN record does not carry its own licence is refused', () => {
  // ⛔⛔ THE GUARD THAT DOES THE MOST WORK, AND THE ONE `rerecord.mjs` NEVER NEEDS. `replay()` scores
  // the recorder's object, which has `descentRedArm` parsed fresh out of the log; this repair writes
  // the ARCHIVE plus four fields, and the archive predates that key. `hasRedArm` reads it OFF THE
  // RECORD, so the licence evaporates on the way to disk — and `collate.mjs`'s Gate 2 would floor the
  // platform straight back to the shipped grant at bake time. MEASURED: 132 of the 164 STALE records.
  const unfalsifiable = lines({
    // ⛔ THE NOTE COMES FROM THE PROSE LINE, NOT FROM THE MARKER. `record.mjs` greps for
    // `/ARMS-UNFALSIFIABLE/` to set the note and reads the marker only for `falsifiabilityReasons`,
    // so a fixture carrying the marker alone is falsifiable and never reaches this branch.
    falsifiability: '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":0,"reasons":["gate-vacuous"],"declaresInstallWork":true}\n'
      + '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    redArm: 'no-network',
  }).join('\n');
  const committed = committedRec({ notes: ['arms-unfalsifiable', 'home-write-attributed'] });

  // Two controls, and both matter. The replay publishes — so the refusal is G4's alone — and it
  // publishes only because the recorder's object carries the evidence the archive lacks.
  const rep = replay({ committed, log: unfalsifiable, capture: CAPTURE });
  assert.equal(rep.verdict, STALE, rep.reason);
  assert.equal(rep.incoming.descentRedArm, true, 'the fixture must license the replay on a red arm');
  assert.ok(!('descentRedArm' in committed), 'the archive must lack the field');

  const r = narrowRerecord({ committed, log: unfalsifiable, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /publish-guard withholds the narrowing once it is scored against the record/);
  assert.match(r.reason, /Re-measure it/);
});

test('G4: the same log DOES narrow once the archive carries the evidence a re-measure would write', () => {
  // The positive control for the test above: nothing about the log or the rule changed, only whether
  // the record can speak for itself. This is what a re-measure produces, and it is why the refusal
  // above points at one rather than at a backfill.
  const unfalsifiable = lines({
    // ⛔ THE NOTE COMES FROM THE PROSE LINE, NOT FROM THE MARKER. `record.mjs` greps for
    // `/ARMS-UNFALSIFIABLE/` to set the note and reads the marker only for `falsifiabilityReasons`,
    // so a fixture carrying the marker alone is falsifiable and never reaches this branch.
    falsifiability: '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":0,"reasons":["gate-vacuous"],"declaresInstallWork":true}\n'
      + '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    redArm: 'no-network',
  }).join('\n');
  const committed = committedRec({
    notes: ['arms-unfalsifiable', 'home-write-attributed'],
    falsifiabilityReasons: ['gate-vacuous'],
    descentRedArm: true,
  });
  const r = narrowRerecord({ committed, log: unfalsifiable, capture: CAPTURE });
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.deepEqual(r.rewritten.grant, { network: true });
});

// ── G5: the network census, the axis the artifact gate is equally blind to ─────────────────────────

test('⭑ G5: `network` is not dropped when the log\'s own census attributed real peers', () => {
  // ⛔⛔ THE DEFECT THIS GUARD WAS BUILT FROM, AND IT WAS FOUND BY RUNNING THE COLLATOR RATHER THAN BY
  // READING RECORDS. `artifact-gate.mjs` checks the package's artefacts are present, and a fetch a
  // WARM CACHE already satisfied leaves that check green — so `network` drops off an arm that proved
  // nothing. MEASURED: `electron-chromedriver@33.4.9` (darwin) recorded two real HTTPS connections in
  // OBSERVE and still returned `VERIFY[nar-no-network] rc=0 artifacts=11/11`. Collating the narrowed
  // corpus turned its macOS overlay into `{"write":null,"network":null}` — and `null` in an overlay
  // REMOVES — so macOS lost egress entirely. `harness/overrides` already undoes exactly that shape for
  // the sibling package `electron`, because the cold-cache install exits 1 with ENOTFOUND github.com.
  const committed = committedRec({
    grant: { write: { userHome: true }, network: true },
    synthesized: { write: { userHome: true }, network: true },
    overPredictedBy: ['no-network'],
    descendedGrant: { write: { userHome: true } },
  });
  const log = lines({
    peers: 2, over: 'no-network', narrowGrant: '{"write":{"userHome":true}}',
  }).join('\n');
  // The control: today's rule really does reach this narrowing, so what refuses it is G5 alone.
  const rep = replay({ committed, log, capture: CAPTURE });
  assert.equal(rep.verdict, STALE, rep.reason);
  assert.deepEqual(rep.dropped, ['network']);

  const r = narrowRerecord({ committed, log, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /network census came back REFUSE/);
  assert.match(r.reason, /Re-measure it on a COLD cache/);
});

test('G5: an ABSENT network census refuses the drop — an archived log cannot be re-run', () => {
  const committed = committedRec({
    grant: { write: { userHome: true }, network: true },
    overPredictedBy: ['no-network'],
    descendedGrant: { write: { userHome: true } },
  });
  const log = lines({ over: 'no-network', narrowGrant: '{"write":{"userHome":true}}' })
    .filter((l) => !/== NETWORK|distinct peers/.test(l)).join('\n');
  const r = narrowRerecord({ committed, log, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /network census came back UNKNOWN/);
});

test('G5: a drop that does not take `network` is not gated on the network census', () => {
  // Scoping control, and it is what keeps the 6 real narrowings alive: they drop `write.userHome`
  // only, on logs whose network census is positive and stays that way.
  const r = narrowRerecord({ committed: committedRec(), log: lines({ peers: 2 }).join('\n'), capture: CAPTURE });
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.deepEqual(r.narrowed, ['write.userHome']);
  assert.deepEqual(r.rewritten.grant, { network: true });
});

// ── the contested-field guard ──────────────────────────────────────────────────────────────────────

test('⭑ a non-repaired field the archive already answers differently is refused, not patched', () => {
  // The waiver is for a field the archive does not carry at all. A field that IS present and
  // DISAGREES means the log is being read differently on something this repair does not claim to fix.
  // `descendedGrant` is the one that carries weight: it is not among `stale-adjudication.mjs`'s drift
  // fields, so this is the only place a disagreement about what the descent computed is caught.
  const committed = committedRec({ descendedGrant: { write: { deps: true } } });
  assert.deepEqual(parseDriverLog(NARROW_LOG).descendedGrant, { network: true }, 'the fixture must disagree');
  const r = narrowRerecord({ committed, log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /also changes descendedGrant/);
});

// ── on disk ────────────────────────────────────────────────────────────────────────────────────────

const layDown = (rec, log) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'narrow-rerecord-'));
  fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, 'driver.out'), log);
  fs.writeFileSync(path.join(dir, 'capture.json'), JSON.stringify(CAPTURE));
  return dir;
};

test('⭑ an applied repair round-trips: re-reading it is a no-op and the replay now agrees', () => {
  const dir = layDown(committedRec(), NARROW_LOG);
  const before = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  const first = narrowRerecordDir(dir, { apply: true });
  assert.equal(first.verdict, NARROWED, first.reason);
  assert.equal(first.applied, true);

  const after = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  assert.notEqual(after, before, 'apply wrote nothing');
  // Byte-identical to the recorder's own serialization, so the on-disk diff is the repair alone.
  assert.equal(after, `${JSON.stringify(JSON.parse(after), null, 2)}\n`);

  // Idempotent: running the repair again finds nothing to narrow and does not touch the file.
  const second = narrowRerecordDir(dir, { apply: true });
  assert.equal(second.verdict, REFUSED, second.reason);
  assert.match(second.reason, /stale-adjudication returned CURRENT/);
  assert.equal(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'), after);

  // ⛔ AND THE INSTRUMENT THAT FOUND THE DEFECT NOW REPORTS IT CLEAN — with no under-grant introduced
  // on the way, which is the failure direction a narrowing can cause.
  const r = replay({ committed: JSON.parse(after), log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, 'CURRENT');
  assert.deepEqual(r.widens, [], 'the narrowed record now reads as an under-grant');

  // The record still speaks for its own narrowing after the rewrite, which is what `collate.mjs`
  // Gate 2 reads, and the fields it keys on survive.
  const rec = JSON.parse(after);
  assert.equal(decide(committedRec(), rec).publish, true);
  assert.equal(rec.verdict, 'MINIMUM');
  assert.equal(rec.provenance.platform, 'linux-x64');
  assert.deepEqual(rec.grant, { network: true });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a dry run writes nothing', () => {
  const dir = layDown(committedRec(), NARROW_LOG);
  const before = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  const r = narrowRerecordDir(dir);
  assert.equal(r.verdict, NARROWED, r.reason);
  assert.equal(r.applied, false);
  assert.equal(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'), before);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('⭑ a results.json the recorder\'s serialization does not reproduce is refused, not reformatted', () => {
  // Reformatting an archive would bury the four-field repair inside a whole-file diff, and a reviewer
  // reading that diff has no way to see what actually changed.
  const dir = layDown(committedRec(), NARROW_LOG);
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(committedRec()));
  const r = narrowRerecordDir(dir, { apply: true });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /does not round-trip/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a record with no driver.out beside it is refused rather than read from anywhere else', () => {
  const dir = layDown(committedRec(), NARROW_LOG);
  fs.rmSync(path.join(dir, 'driver.out'));
  const r = narrowRerecordDir(dir, { apply: true });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /no driver\.out/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── the diff helper ────────────────────────────────────────────────────────────────────────────────

test('the field diff sees a key ADDED or REMOVED, not only a value changed', () => {
  // ⛔ A `for (const k of Object.keys(a))` LOOP MISSES A KEY THE OTHER SIDE ADDED, and it is the
  // direction that loses a field — the one failure the rewrite gates are built to make impossible.
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 1 }), []);
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 2 }), ['a']);
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 1, b: 2 }), ['b']);
  assert.deepEqual(fieldDiff({ a: 1, b: 2 }, { a: 1 }), ['b']);
  // ⛔ AND A KEY PRESENT WITH `undefined` IS NOT THE SAME AS AN ABSENT ONE. `JSON.stringify` erases
  // the difference; the archive's whole "this record predates the field" waiver turns on it.
  assert.deepEqual(fieldDiff({ a: undefined }, {}), ['a']);
});

// ── UNCHANGED is unreachable through the corpus, and saying so is the point ────────────────────────

test('UNCHANGED is exported for symmetry with rerecord.mjs and is never returned', () => {
  // ⛔ HONEST DEAD CODE, DOCUMENTED RATHER THAN DELETED. `rerecord.mjs` reaches UNCHANGED because a
  // widening replay that agrees lands on `replay()`'s CURRENT branch with an empty `widened`. Here
  // an agreeing replay is CURRENT too — and CURRENT is G1's REFUSAL, because "today's rule reaches
  // no narrowing" is exactly what this module must decline to act on. The constant is kept so the two
  // CLIs print the same vocabulary; a future caller that distinguishes them has a name to use.
  assert.equal(UNCHANGED, 'UNCHANGED');
  const agreed = committedRec({
    grant: { network: true }, grantSource: 'descended', notes: [],
    grantSourceReason: parseDriverLog(NARROW_LOG).grantSourceReason,
  });
  assert.equal(narrowRerecord({ committed: agreed, log: NARROW_LOG, capture: CAPTURE }).verdict, REFUSED);
});
