// The REAL-home write census, and the withhold-only term it drives in `applyGrantSourceRule`.
//
// ⛔ WHAT THIS GUARDS IS AN UNDER-GRANT — the one direction this project forbids. `artifact-gate.mjs`
// only ever walks the package's OWN directory, so a home write is by construction outside everything
// it can see; a browser downloader therefore passes its `no-write-userHome` drop arm with the browser
// missing. `redArmLicenses` cannot close it: a red SIBLING arm proves the jail → denial → rc chain
// fires SOMEWHERE, never that it fires on the home write.
//
//   node --test harness/v2/write-census.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  CENSUS_CLEAR, CENSUS_REFUSE, CENSUS_UNKNOWN, homeDropVerdict, homeWrites,
} from './write-census.mjs';
import { homeWrites as reExported } from './stale-adjudication.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;

// ── the fixture ───────────────────────────────────────────────────────────────────────────────────
//
// A one-capability descent that drops `no-write-userHome` off a `{write:{project,userHome},network}`
// synthesis — the shape of every record this term exists for. Two licences are offered separately so
// each can be shown to be insufficient on its own: `redArm` is the `arms-unfalsifiable` + red-sibling
// shape the committed corpus is full of, and the default is an ordinarily falsifiable record that
// needs no licence at all.
const LOG = ({ writes = ['    jailTmp       3'], redArm = false, witness = null, census = true } = {}) => [
  `  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":3,"reasons":${redArm ? '["gate-vacuous"]' : '[]'},"declaresInstallWork":true}`,
  ...(redArm ? ['  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:'] : []),
  ...(census ? ['  == WRITES ==', ...writes] : []),
  '  == READS ==',
  '    deps          1',
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  '    {"write":{"project":true,"userHome":true},"network":true}',
  '  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true},"network":true}',
  '  => MINIMUM {"write":{"project":true,"userHome":true},"network":true}   (observed, then verified)',
  ...(redArm ? [
    '  VERIFY[nar-no-network] rc=1 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true}}',
    "     'no-network' is NECESSARY — dropping it fails to verify",
  ] : []),
  ...(witness ? [`  DENIAL-WITNESS {"cap":"no-write-userHome","verdict":"${witness}"}`] : []),
  '  VERIFY[nar-no-write-userHome] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true},"network":true}',
  '  => OVER-PREDICTED by: no-write-userHome  (synthesized {"write":{"project":true,"userHome":true},"network":true}; each named capability drops on its own)',
].join('\n');

const home = (g) => !!g?.write && (typeof g.write === 'string' || !!g.write.userHome);

// ── the census reader ─────────────────────────────────────────────────────────────────────────────

test('CONTROL: the reader answers the two cases whose real values are known independently', () => {
  // Both counts are read off the committed corpus: `@playwright/browser-chromium@1.61.1` (win32,
  // bare header) 629 and `playwright-chromium@1.9.2` (linux, long header) 1185. A reader that got
  // either of these wrong would make every conclusion below unfounded.
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n    jailTmp       8\n  == READS =='), 629);
  assert.equal(homeWrites([
    '  == WRITES the script actually performed ==',
    // ⛔ A SUFFIXED SIBLING ROW, WHICH IS WHAT THE DARWIN CLASSIFIER REALLY EMITS. `BASE_COVERED` is
    // `ownPkg jailHome jailTmp toolsRw` — `userHome` is not in it and never carries the note, so this
    // pins that a suffixed NEIGHBOUR does not derail the block rather than a suffix on the row read.
    '    jailHome      1  (base profile already grants this — NOT billed)',
    '    userHome   1185',
    '  == READS ==',
  ]), 1185);
});

test('⭑ a WRITES block with no `userHome` row is ZERO; an absent block is UNKNOWN', () => {
  // ⛔ THE DISTINCTION IS THE WHOLE GATE. The drivers omit a bucket with no members, so a block
  // without the row is a script that never touched the real home — the SAFE case, and the one a
  // "no row means unknown" reading would fence off.
  assert.equal(homeWrites('  == WRITES ==\n    systemfs      1\n    jailTmp    1070\n  == READS =='), 0);
  assert.equal(homeWrites('  => MINIMUM {}\n'), null);
});

test('a raw log and an already-split line array read identically, including a win32 CRLF log', () => {
  // `record.mjs` holds `lines` (echoed output already dropped); `stale-adjudication.mjs` holds the
  // archived string. Both must reach the same number or the two callers are reading different logs.
  const raw = '  == WRITES ==\r\n    userHome    629\r\n  == READS ==\r\n    userHome  40000\r\n';
  assert.equal(homeWrites(raw), 629);
  assert.equal(homeWrites(raw.split('\n')), 629, 'record.mjs splits on \\n alone, so rows keep a trailing \\r');
});

test('the census stops at the next section, so READS cannot be billed as WRITES', () => {
  // Every driver prints a `userHome` row under READS too, routinely two orders of magnitude larger.
  assert.equal(homeWrites('  == WRITES ==\n    jailTmp 3\n  == READS ==\n    userHome    661\n'), 0);
});

// ── the classifier ────────────────────────────────────────────────────────────────────────────────

test('⭑ only positive evidence clears a home drop, and there are exactly two kinds of it', () => {
  const withHome = '  == WRITES ==\n    userHome    629\n  == READS ==';
  assert.equal(homeDropVerdict({ log: withHome, witness: null }).verdict, CENSUS_REFUSE);
  assert.equal(homeDropVerdict({ log: withHome, witness: 'CLEAN' }).verdict, CENSUS_CLEAR);
  // Everything that is not the word CLEAN is "not established" and clears nothing.
  for (const w of ['WITNESSED', 'VOID', 'UNSUPPORTED', undefined]) {
    assert.equal(homeDropVerdict({ log: withHome, witness: w }).verdict, CENSUS_REFUSE, `witness ${w} cleared a home drop`);
  }
  assert.equal(homeDropVerdict({ log: '  == WRITES ==\n    jailTmp 3\n  == READS ==', witness: null }).verdict, CENSUS_CLEAR);
  assert.equal(homeDropVerdict({ log: '  => MINIMUM {}', witness: null }).verdict, CENSUS_UNKNOWN);
});

// ── the term inside `applyGrantSourceRule` ────────────────────────────────────────────────────────

test('⭑ a positive real-home census WITHHOLDS the narrowing a red sibling arm would have licensed', () => {
  // ⛔ THE MEASURED CASE. `playwright-chromium@1.9.2` (linux) attributed 1185 real-home writes and
  // still dropped `write.userHome`; `@playwright/browser-chromium@1.61.1` (win32) 629. Both carry a
  // red sibling arm on `network`, which is what `redArmLicenses` reads as a positive control — and
  // it is a control for the EXIT CODE, not for the home write the artifact gate never looks at.
  const r = parseDriverLog(LOG({ writes: ['    userHome   1185'], redArm: true }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.equal(home(r.grant), true, 'the grant lost the home the script demonstrably wrote to');
  assert.match(r.grantSourceReason, /attributed 1185 write\(s\) to the REAL home/);
  assert.ok(r.notes.includes('home-write-attributed'), 'the withholding must be queryable in the record, not just in prose');
  // The narrowing it refused is still recorded, so the delta is auditable rather than invisible.
  assert.equal(home(r.descendedGrant), false);
});

test('⭑ the same shape without `arms-unfalsifiable` is withheld too — the term is not a falsifiability rider', () => {
  // An ordinarily falsifiable record needs no licence at all and reaches `n === 1` directly, so a
  // term written into the falsifiability branch would miss it entirely.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'] }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.ok(r.notes.includes('home-write-attributed'));
});

test('⛔ RED CONTROL: a census attributing NO real-home write still narrows', () => {
  // Without this the assertions above could be produced by a term that refuses every home drop, which
  // would make the whole descent inert on this capability.
  for (const redArm of [true, false]) {
    const r = parseDriverLog(LOG({ redArm }));
    assert.equal(r.grantSource, 'descended', `redArm=${redArm}: ${r.grantSourceReason}`);
    assert.equal(home(r.grant), false);
    assert.ok(!r.notes.includes('home-write-attributed'));
  }
});

test('⛔ RED CONTROL: a CLEAN denial witness narrows over a positive census', () => {
  // The witness scores the DROP ARM's own jailed trace, so it outranks the observe arm's count.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'], witness: 'CLEAN' }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.equal(home(r.grant), false);
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('⭑ WITHHOLD-ONLY: a record the chain already kept wide keeps its own, better reason', () => {
  // ⛔ THE TERM IS AN OVERRIDE ON `source === 'descended'`, NOT A BRANCH IN THE CHAIN, and this is
  // what that buys. A two-capability leave-one-out record already reaches the wider grant for a more
  // complete reason — nothing proves the two drop TOGETHER — and as a branch this term fired first
  // and replaced that sentence on records whose grant does not change at all.
  const log = LOG({ writes: ['    userHome    629'] })
    .replace('=> OVER-PREDICTED by: no-write-userHome ', '=> OVER-PREDICTED by: no-network no-write-userHome ');
  const r = parseDriverLog(log);
  assert.deepEqual(r.overPredictedBy, ['no-network', 'no-write-userHome']);
  assert.equal(r.grantSource, 'synthesized');
  assert.match(r.grantSourceReason, /leave-one-out/);
  assert.ok(!r.notes.includes('home-write-attributed'), 'the census overrode a withholding it did not cause');
});

test('⭑ WITNESSED keeps outranking this term, and owns the reason when both apply', () => {
  // ⛔ A WITNESSED refusal is direct evidence the script ASKED and the jail REFUSED — strictly
  // stronger than a count of what it wrote unjailed. Reordering these two branches would replace the
  // better finding with the weaker one in the record.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'], witness: 'WITNESSED' }));
  assert.equal(r.grantSource, 'synthesized');
  assert.ok(r.notes.includes('denial-witnessed'), r.grantSourceReason);
  assert.ok(!r.notes.includes('home-write-attributed'));
  assert.match(r.grantSourceReason, /ATTEMPTED a write inside no-write-userHome/);
});

test('⭑ an absent census does NOT fire the term, which is the documented policy and not an oversight', () => {
  // ⛔ THE CENSUS IS AN OBSERVE PRODUCT, and this file's settled policy for an absent OBSERVE product
  // is `observedCounts`': absence vetoes nothing, so every existing record keeps the behaviour it was
  // measured under. The absence case is covered elsewhere instead — by the driver-parity assertion
  // below at authoring time, and by `stale-adjudication.mjs`'s G3 for an archived log.
  const r = parseDriverLog(LOG({ census: false }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('⭑ the term is keyed on the GRANT, not on the arm name', () => {
  // A descent can name `no-write-userHome` over a grant that never carried the home — deleting it is
  // then a no-op and there is nothing to withhold. Keying on `overPredictedBy` would withhold a
  // narrowing that does not touch the home at all.
  const log = LOG({ writes: ['    userHome    629'] })
    .replace(/\{"write":\{"project":true,"userHome":true\},"network":true\}/g, '{"write":{"project":true},"network":true}');
  const r = parseDriverLog(log);
  assert.equal(home(r.synthesized), false, 'the fixture must present a grant without the home');
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('an ECHOED census line cannot open a block, so echoed output cannot forge an acquittal', () => {
  // ⛔ THE DEFENCE IS THE HEADER REGEX, NOT THE ECHO FILTER, and saying so is the point of this test:
  // `^\s*==` cannot get past the `|`, so the census is safe on the raw log too. An UNPREFIXED second
  // block DOES win, which is the honest limit — the census is printed by the OBSERVE classifier and
  // a later descent arm's package output is the only thing that could sit after it.
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n    | == WRITES ==\n    |     jailTmp 1\n  == READS =='), 629);
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n  == WRITES ==\n    jailTmp 1\n  == READS =='), 0);
});

// ── ONE implementation, two readers ───────────────────────────────────────────────────────────────

test('⭑ `stale-adjudication.mjs` re-exports this census rather than carrying a second copy', () => {
  // ⛔ THE DEFECT CLASS THIS PROJECT HAS PAID FOR FIVE TIMES: a soundness guard wired into one reader
  // and not the other. Identity, not equivalence — two functions that agree today are exactly the
  // pair that drifts.
  assert.equal(reExported, homeWrites);
});

test('⭑ neither reader defines a census of its own', () => {
  // Scans CODE, not prose: both files legitimately discuss `== WRITES` in their comments, and a raw
  // line scan would flag the documentation of the rule as a violation of it.
  const code = (f) => fs.readFileSync(path.join(HERE, f), 'utf8').split('\n')
    .filter((l) => !/^(\/\/|\*|\/\*)/.test(l.trimStart())).join('\n');
  const CENSUS_REGEX = /==\\s\*?WRITES|\[A-Za-z\]\[A-Za-z0-9\]\*/;
  assert.match(code('write-census.mjs'), CENSUS_REGEX, 'CONTROL: the scan cannot see the census it is looking for');
  for (const f of ['record.mjs', 'stale-adjudication.mjs']) {
    assert.doesNotMatch(code(f), CENSUS_REGEX, `${f} carries its own copy of the census parser`);
  }
});

test('⭑ all three classifiers emit a census header this module matches', () => {
  // ⛔ THIS IS WHAT BACKS THE DECISION TO LET AN ABSENT CENSUS PASS. The term is scoped to a POSITIVE
  // count, so a driver that stopped printing the block would silently disarm it in `record.mjs`.
  // Asserted at authoring time instead, the same shape `three-driver-parity.test.mjs` uses: a fourth
  // driver, or a reworded header, fails here rather than in a record nobody re-reads.
  for (const f of ['observe.mjs', 'observe-macos.mjs', 'classify.mjs']) {
    const emitted = fs.readFileSync(path.join(HERE, f), 'utf8')
      .split('\n').filter((l) => /console\.log\('== WRITES/.test(l));
    assert.equal(emitted.length, 1, `${f} does not print exactly one == WRITES header`);
    const header = /console\.log\('([^']+)'\)/.exec(emitted[0])[1];
    assert.equal(homeWrites(`${header}\n    userHome    7\n  == READS ==`), 7,
                 `${f} prints a header this module's reader does not recognise: ${header}`);
  }
});
