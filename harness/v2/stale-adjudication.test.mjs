// Re-adjudicating a committed record against today's rule, and the three gates that make acting on
// an ARCHIVED log safe.
//
// ⛔ EVERY FIXTURE HERE IS EITHER A REAL CORPUS SHAPE OR A LOG THE DRIVERS DEMONSTRABLY PRODUCED.
// The `== WRITES ==` spellings are copied from the three drivers, the VOID and TRUNCATED arms are the
// shapes `verify()` returns 2 / a budget kill produce, and the ARTIFACT-GATE red arm is the `rc=0,
// missing>=1` row that 288 announcements in the committed corpus actually sit on.
//
//   node --test harness/v2/stale-adjudication.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CURRENT, DRIFT_FIELDS, REFUSED, STALE, homeWrites, parseDrift, redArmAudit, redArmRows, replay,
} from './stale-adjudication.mjs';
import { parseDriverLog } from './record.mjs';

const CAPTURE = { roots: { home: '/home/runner', jailHome: '/home/runner/v2-x/jailhome' } };

// A log whose descent drops `no-write-userHome` on a package the artifact gate cannot judge, with a
// red sibling arm on `network`. This is the shape of every record this module converts.
const lines = ({ writes = ['    jailTmp       3'], redRc = '1', redOvr = '2', redRej = '0', redLabel = 'nar-no-network' } = {}) => [
  '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":0,"reasons":["gate-vacuous"],"declaresInstallWork":true}',
  '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
  '  == WRITES ==',
  ...writes,
  '  == READS ==',
  '    deps          1',
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  '    {"write":{"project":true,"userHome":true},"network":true}',
  '  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true},"network":true}',
  '  => MINIMUM {"write":{"project":true,"userHome":true},"network":true}   (observed, then verified)',
  `  VERIFY[${redLabel}] rc=${redRc} artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=${redOvr} REJECTED=${redRej} grant={"write":{"project":true,"userHome":true}}`,
  "     'no-network' is NECESSARY — dropping it fails to verify",
  '  VERIFY[nar-no-write-userHome] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true},"network":true}',
  '  => OVER-PREDICTED by: no-write-userHome  (synthesized {"write":{"project":true,"userHome":true},"network":true}; each named capability drops on its own)',
];
const LOG = (o) => lines(o).join('\n');

// The record as the PRE-epoch-58 recorder wrote it: the wider grant, the one-term sentence, and no
// `falsifiabilityReasons` / `descentRedArm` fields at all — which is what all 288 committed records
// in this state look like.
const committedFor = (log) => {
  const p = parseDriverLog(log);
  return {
    pkg: 'demo-stale', version: '1.0.0', verdict: 'MINIMUM',
    grant: { write: { project: true, userHome: true }, network: true },
    synthesized: p.synthesized, minimality: p.minimality, overPredictedBy: p.overPredictedBy,
    writePaths: [], notes: ['arms-unfalsifiable'], grantSource: 'synthesized',
    grantSourceReason: "the descent narrowed, but this package's arms could not have failed "
      + '(arms-unfalsifiable), so a passing narrow arm is not evidence — keeping the wider grant',
    provenance: { platform: 'linux-x64' },
  };
};

// ── the write census ──────────────────────────────────────────────────────────────────────────────

test('the REAL-home write census is read from all three drivers\' spellings of the block', () => {
  // win32 prints the bare header; linux and darwin the long one. Anchoring on the long form alone
  // returned "no census" for every win32 record — 107 of the 288 — which reads as UNKNOWN and would
  // have fenced them off the answer rather than answering it.
  assert.equal(homeWrites('  == WRITES ==\n    userHome    161\n    kernelfs      2\n  == READS ==\n    userHome    146'), 161);
  assert.equal(homeWrites('  == WRITES the script actually performed ==\n    userHome      2\n  == NETWORK =='), 2);
  // darwin appends a not-billed note to some rows; the count must not be end-anchored.
  assert.equal(homeWrites('  == WRITES the script actually performed ==\n    jailHome      1  (base profile already grants this — NOT billed)\n    userHome      7\n  == READS =='), 7);
});

test('⭑ a WRITES block with no `userHome` row is ZERO, and an absent block is UNKNOWN', () => {
  // ⛔ THE DISTINCTION IS THE WHOLE GATE. The drivers omit a bucket with no members, so a block
  // without the row is a script that never touched the real home — the SAFE case, and the one a
  // "no row means unknown" reading fences off. An absent block is a log that never ran the census,
  // where nothing may be concluded either way.
  assert.equal(homeWrites('  == WRITES the script actually performed ==\n    systemfs      1\n    jailTmp    1070\n  == READS =='), 0);
  assert.equal(homeWrites('  => MINIMUM {}\n'), null);
});

test('the census stops at the next section, so READS cannot be billed as WRITES', () => {
  // Every driver prints a `userHome` row under READS too, and it is routinely two orders of
  // magnitude larger — 661 reads beside 0 writes on one committed darwin record.
  assert.equal(homeWrites('  == WRITES ==\n    jailTmp 3\n  == READS ==\n    userHome    661\n'), 0);
});

// ── the red-arm audit ─────────────────────────────────────────────────────────────────────────────

const announce = (cap) => `     '${cap}' is NECESSARY — dropping it fails to verify`;
const verify = (label, rc, ovr = 2, rej = 0, extra = '') => `  VERIFY[${label}] rc=${rc} artifacts=8/8 missing=0${extra} (tree 10/10) OVERRIDDEN=${ovr} REJECTED=${rej} grant={}`;

test('CONTROL: a genuine exit-code red arm is scored EXIT-CODE and carries the licence', () => {
  // Without this the classifications below could all be produced by a regex that matches nothing.
  const a = redArmAudit([verify('nar-no-network', 1), announce('no-network')].join('\n'));
  assert.deepEqual(a.rows.map((r) => r.kind), ['EXIT-CODE']);
  assert.equal(a.sound, true);
});

test('⭑ an announcement over a VOID arm is refused, in both spellings the driver prints', () => {
  // ⛔ THE MEASURED CASE. `measure.sh`'s descent was once a two-way `if verify …; else NECESSARY`,
  // and `wordpos@2.1.0`'s drop arm came back REJECTED=2 / VOID with `'write.deps' is NECESSARY`
  // printed anyway. A log written under that form manufactures a positive control out of an arm
  // that measured nothing, and `descentRedArm` — a regex over the prose — cannot see it.
  const byNumbers = redArmAudit([verify('nar-no-network', 1, 0, 2), announce('no-network')].join('\n'));
  assert.deepEqual(byNumbers.rows.map((r) => r.kind), ['VOID']);
  assert.equal(byNumbers.sound, false);
  const byLine = redArmAudit([
    verify('nar-no-network', 1), '     ⛔ override did not engage — arm is VOID', announce('no-network'),
  ].join('\n'));
  assert.deepEqual(byLine.rows.map((r) => r.kind), ['VOID']);
});

test('⭑ a red arm the ARTIFACT GATE produced cannot carry an EXIT-CODE licence', () => {
  // `verify` returns 1 when `rc=0` and the gate failed, and the driver announces necessity
  // identically. MEASURED across all 6887 committed logs: of 2601 announcements, 2313 sit on `rc=1`
  // and 288 sit on `rc=0`. `record.mjs` licenses on `rcLive && descentRedArm` — a sentence about the
  // EXIT CODE — so a gate-driven row is about a different detector and must not carry it.
  const a = redArmAudit([verify('nar-no-network', 0, 2, 0, ' missing=1'), announce('no-network')].join('\n'));
  assert.deepEqual(a.rows.map((r) => r.kind), ['ARTIFACT-GATE']);
  assert.equal(a.sound, false, 'a gate-driven announcement licensed an exit-code narrowing');
  // And it is not "unsound" — it is simply about something else, so it neither carries nor poisons.
  assert.deepEqual(a.unsound, []);
});

test('a kill at the arm budget is not a denial', () => {
  for (const rc of [124, 137]) {
    const a = redArmAudit([verify('nar-no-network', rc), announce('no-network')].join('\n'));
    assert.deepEqual(a.rows.map((r) => r.kind), ['TRUNCATED'], `rc=${rc} was read as a real failure`);
  }
});

test('an announcement whose arm does not name its capability is UNCORROBORATED', () => {
  // Proximity alone is a guess. MEASURED over all 2601 announcements in the corpus the nearest
  // VERIFY line is 1-26 lines above and its label matches every time, so this costs nothing today
  // and makes a future interleaving visible instead of silently mis-attributed.
  const a = redArmAudit([verify('nar-no-write-deps', 1), announce('no-network')].join('\n'));
  assert.deepEqual(a.rows.map((r) => r.kind), ['UNCORROBORATED']);
  const orphan = redArmAudit([announce('no-network')].join('\n'));
  assert.deepEqual(orphan.rows.map((r) => r.kind), ['UNCORROBORATED']);
});

// ── G1: the parse-drift control ───────────────────────────────────────────────────────────────────

test('the drift control names the fields the rule does NOT compute, and grant is not among them', () => {
  // ⛔ `grant` IN THIS LIST WOULD MAKE THE MODULE REFUSE EXACTLY WHAT IT EXISTS TO FIND.
  assert.ok(!DRIFT_FIELDS.includes('grant'));
  for (const f of ['verdict', 'minimality', 'overPredictedBy', 'synthesized', 'writePaths']) {
    assert.ok(DRIFT_FIELDS.includes(f), `${f} is not being checked`);
  }
});

test('⭑ drift on `minimality` REFUSES, because the grant delta is then not the rule\'s', () => {
  const log = LOG();
  const parsed = parseDriverLog(log);
  assert.deepEqual(parseDrift(committedFor(log), parsed), [], 'the control fires on a record it should pass');
  // The real shape: `records-v2/runs/win32-x64/cypress/15.19.0` is committed `UNPROVEN` and today's
  // parser reads `OVER-PREDICTED` off the same log. 25 committed records are in that state.
  const stale = { ...committedFor(log), minimality: 'UNPROVEN' };
  assert.deepEqual(parseDrift(stale, parsed), ['minimality']);
  assert.equal(replay({ committed: stale, log, capture: CAPTURE }).verdict, REFUSED);
});

// ── the replay, end to end ────────────────────────────────────────────────────────────────────────

test('⭑ a record frozen at the pre-epoch-58 rule is STALE, and the drop is scored by publish-guard', () => {
  const log = LOG();
  const r = replay({ committed: committedFor(log), log, capture: CAPTURE });
  assert.equal(r.verdict, STALE, r.reason);
  assert.deepEqual(r.dropped, ['write.userHome']);
  assert.deepEqual(r.grant, { write: { project: true }, network: true });
  // ⛔ THE PROJECT'S SCORER DECIDED IT, not this module. `decide` is imported, and its own words are
  // what reach the reason — a hand-rolled version of that rule was wrong here once.
  assert.equal(r.decision.publish, true);
  assert.match(r.decision.reason, /arms that went red/);
});

test('a record the current rule agrees with is CURRENT, not STALE', () => {
  const log = LOG();
  const already = { ...committedFor(log), grant: { write: { project: true }, network: true } };
  const r = replay({ committed: already, log, capture: CAPTURE });
  assert.equal(r.verdict, CURRENT, r.reason);
  assert.deepEqual(r.widens, [], 'an agreeing record must not read as an under-grant');
});

test('⭑ a committed grant the current rule would WIDEN is named, not reported as agreement', () => {
  // ⛔ MEASURED at `cf36b27f8` after the home-write term landed: 115 committed records already
  // dropped `write.userHome` on a package whose own census attributed real-home writes, so the rule
  // reaches a strictly WIDER grant for each. This module proposes narrowings only, so `dropped` is
  // empty for all of them — and the flat "the current rule reaches the committed grant" sentence was
  // then false in the under-grant direction, which is the direction this project forbids.
  const log = LOG({ writes: ['    userHome    629'] });
  const under = { ...committedFor(log), grant: { write: { project: true }, network: true } };
  const r = replay({ committed: under, log, capture: CAPTURE });
  assert.equal(r.verdict, CURRENT, r.reason);
  assert.deepEqual(r.widens, ['write.userHome']);
  assert.match(r.reason, /UNDER-GRANT/);
});

test('⭑ a positive real-home census stops the drop UPSTREAM, in the rule this module replays', () => {
  // ⛔ THE MEASURED CASE, AND IT IS THE REASON THE GATE EXISTS. The records the shipped rule would
  // narrow include playwright/puppeteer browser downloaders whose entire product is a home write —
  // `playwright-chromium@1.9.2` performed 1185 real-home writes,
  // `@playwright/browser-chromium@1.61.1` 629. A red sibling arm proves the chain fires SOMEWHERE;
  // it cannot prove it fires on the home write, which `artifact-gate.mjs` never looks at.
  //
  // ⛔ AND THIS IS THE SINGLE-IMPLEMENTATION PROOF. The refusal is `record.mjs`'s, applied inside
  // `parseDriverLog`, so `replay()` never sees a narrowing to police — the committed WIDE grant is
  // simply what today's rule reaches. A second copy of the term here is what would drift.
  const log = LOG({ writes: ['    userHome    629', '    jailTmp       8'] });
  const parsed = parseDriverLog(log);
  assert.equal(parsed.grantSource, 'synthesized', parsed.grantSourceReason);
  assert.ok(parsed.notes.includes('home-write-attributed'), parsed.grantSourceReason);
  const r = replay({ committed: committedFor(log), log, capture: CAPTURE });
  assert.equal(r.verdict, CURRENT, r.reason);
  // A CLEAN denial witness on the dropped capability is direct evidence and lifts it — read off the
  // LOG, which is where a real record's witness comes from.
  const clean = [...lines({ writes: ['    userHome    629'] })];
  clean.splice(-1, 0, '  DENIAL-WITNESS {"cap":"no-write-userHome","verdict":"CLEAN"}');
  const cleanLog = clean.join('\n');
  assert.equal(replay({ committed: committedFor(cleanLog), log: cleanLog, capture: CAPTURE }).verdict, STALE);
});

test('⭑ G3 refuses rather than guesses when the roots cannot be confirmed', () => {
  // ⛔ `roots.jailHome` IS NULL IN EVERY DARWIN EVENT-LOG HEADER, and a lane rooted there billed 32
  // jail-home writes as real-home writes. The failure this catches is a false CLEAR, not a false
  // refusal: with the two roots indistinguishable a REAL-home write can be billed to the `jailHome`
  // bucket, and the census then reads zero on a package that wrote the home. So the fixture is a
  // record whose census is clear — which is the only kind that now reaches this gate at all.
  const log = LOG();
  const c = committedFor(log);
  assert.equal(replay({ committed: c, log, capture: null }).verdict, REFUSED);
  assert.equal(replay({ committed: c, log, capture: { roots: { home: '/h', jailHome: '/h' } } }).verdict, REFUSED);
  // A capture with NO jail home at all is fine — that is every win32 record, where OBSERVE runs
  // against the real home directly and `userHome` is unambiguously it.
  assert.equal(replay({ committed: c, log, capture: { roots: { home: '/h', jailHome: null } } }).verdict, STALE);
});

test('⭑ a log with no write census REFUSES a userHome drop rather than assuming zero', () => {
  // ⛔ THE HALF OF THE HOME-WRITE QUESTION THAT STAYS HERE. `record.mjs` lets an absent census pass,
  // on the policy its `observedCounts` states, backed by an authoring-time guard that all three
  // classifiers still print the block. No authoring-time guard reaches a log written months ago.
  const log = LOG().split('\n').filter((l) => !/== WRITES|jailTmp|== READS|    deps/.test(l)).join('\n');
  assert.equal(parseDriverLog(log).grantSource, 'descended', 'the fixture must reach this module as a narrowing');
  const r = replay({ committed: committedFor(log), log, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /no `== WRITES` census/);
});

test('⭑ a manufactured red arm cannot convert a record, however clean everything else is', () => {
  // Same log, same drop, same empty write census — only the corroborating arm is VOID.
  const good = LOG();
  assert.equal(replay({ committed: committedFor(good), log: good, capture: CAPTURE }).verdict, STALE);
  const void_ = LOG({ redOvr: '0', redRej: '2' });
  const r = replay({ committed: committedFor(void_), log: void_, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /unsound red arm/);
});
