// THE VALUE-LEVEL CONTRACT: the drivers and `record.mjs` must agree on what the descent's variant
// names MEAN, not merely that a marker by some name exists.
//
// ⛔ WHY THIS IS A SEPARATE GUARD FROM `marker-contract.test.mjs`. That file pins the PRESENCE of a
// marker on both sides — every marker emitted is parsed, every marker parsed is emitted. It cannot see
// three drivers agreeing that `=> OVER-PREDICTED by:` exists while disagreeing about the vocabulary of
// the names that line CARRIES. That is exactly what happened, and it survived every existing check:
//
//   `measure.sh` emitted the bare `network` / `write.deps`. `record.mjs`'s `applyGrantSourceRule`
//   recomputes the descended grant by matching the literal `no-network` / `no-write-<scope>`. Neither
//   Linux name matched, so the recomputation deleted nothing, `descendedGrant` came back identical to
//   the synthesized grant, and a record published `grantSource: "descended"` beside an un-narrowed
//   value. MEASURED against the committed corpus: all five linux-x64 records carrying an
//   over-prediction re-parse with `descendedGrant === grant`.
//
// The marker existed. Both sides emitted and parsed it. The PAYLOAD disagreed, silently, in a field
// the catalog reasons about. This file is the generalisation: wherever `record.mjs` does a LITERAL
// match on a value a driver produced, the token is pinned on both sides here.
//
// ⛔ `descent-contract.test.mjs` is the SENTENCE contract and it covers `measure-windows.mjs` only.
// This is the VOCABULARY contract and it covers all three. They are complementary: a driver can speak
// the right sentences with the wrong nouns, which is the defect above.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

const DRIVERS = {
  linux: 'measure.sh',
  macos: 'measure-macos.sh',
  windows: 'measure-windows.mjs',
};

/**
 * A driver's EXECUTABLE lines, with comments stripped.
 *
 * ⛔ MATCHING RAW SOURCE IS WHAT MAKES A FILE LIKE THIS VACUOUS, and it is not a hypothetical: the
 * first version of `descent-contract.test.mjs` searched whole source for `no-network`, which appears
 * in a COMMENT explaining the contract, so renaming the real variants left every assertion green. The
 * comment above this very line names both tokens, so without stripping, this file would certify its
 * own prose. Shell `#` and JS `//` both, since the drivers are two languages.
 *
 * ⛔ A BARE `startsWith('*')` FOR THE JSDOC CONTINUATION EATS A SHELL `case` ARM, AND IT DID. `*)` is
 * the default arm of every `case` in `measure.sh` — including the one the joint arm branches on — so
 * the first version of this stripper silently deleted the `JOINT-NARROW FAILED` and `is NECESSARY`
 * emissions and then reported them missing. Caught by this file's own drift guard on its first run,
 * which is the only reason it is not still here. `descent-contract.test.mjs` carries the same bare
 * form; it is harmless there only because the driver it reads has no such line.
 */
const code = (src) => src.split('\n').filter((l) => {
  const t = l.trim();
  const jsdocCont = t === '*' || t.startsWith('* ') || t.startsWith('*/');
  if (jsdocCont) return false;
  return t && !t.startsWith('#') && !t.startsWith('//') && !t.startsWith('/*');
}).join('\n');

const CODE = Object.fromEntries(Object.entries(DRIVERS).map(([k, f]) => [k, code(read(f))]));
const RECORD = read('record.mjs');

// ── INSTRUMENT CHECKS — everything below is worthless without these ────────────────────────────────

test('INSTRUMENT: the comment stripper leaves real code and removes real comments', () => {
  for (const [platform, c] of Object.entries(CODE)) {
    assert.ok(c.length > 2000, `the stripper reduced ${DRIVERS[platform]} to ${c.length} chars — it is broken`);
    assert.ok(c.length < read(DRIVERS[platform]).length, `the stripper removed nothing from ${DRIVERS[platform]}`);
  }
  // The positive and negative controls for the stripper itself, in both comment syntaxes.
  assert.equal(code('# no-network in a shell comment\n// no-network in a JS comment\n'), '',
    'the stripper keeps comments, so a token named only in prose would count as emitted');
  assert.ok(code('  out.push("no-network");').includes('no-network'),
    'the stripper drops real code, so it would report a correct driver as broken');
  // ⛔ THE REGRESSION CONTROL FOR THE BUG THIS STRIPPER SHIPPED WITH. A shell `case` default arm
  // begins with `*`, which a JSDoc-continuation rule eats — deleting the driver's own FAILED and
  // NECESSARY emissions and reporting them as missing.
  assert.ok(code('        *) echo "  => JOINT-NARROW FAILED $JOINT";;').includes('JOINT-NARROW FAILED'),
    'the stripper eats a shell `case` default arm, so every emission in one reads as absent');
  assert.equal(code(' * a JSDoc continuation line\n */\n'), '',
    'the stripper keeps JSDoc continuations, so a token named in one would count as emitted');
});

// ── THE VOCABULARY `record.mjs` CAN PARSE, READ OFF `record.mjs` ITSELF ────────────────────────────

// ⛔ DERIVED FROM THE RECORDER, NOT HARDCODED HERE. A hardcoded list is a third place the vocabulary
// lives, and a third place is how the second one drifted. If `applyGrantSourceRule` learns a new name,
// this test starts demanding it of the drivers automatically.
const RULE = /const applyGrantSourceRule[\s\S]*?\n};/.exec(RECORD)?.[0] ?? '';

test('INSTRUMENT: the rule body was located and contains its literal matches', () => {
  assert.ok(RULE.length > 400, `applyGrantSourceRule was not found in record.mjs (got ${RULE.length} chars)`);
  assert.match(RULE, /'no-network'/, 'the rule no longer matches `no-network` — this test is looking at the wrong code');
  assert.match(RULE, /no-write-/, 'the rule no longer matches `no-write-` — this test is looking at the wrong code');
});

test('⭑ every driver emits the variant vocabulary record.mjs matches', () => {
  // ⛔ THE ASSERTION THE WHOLE FILE EXISTS FOR. Checked in executable code, per driver, by name.
  const missing = [];
  for (const [platform, c] of Object.entries(CODE)) {
    for (const token of ['no-network', 'no-write-']) {
      if (!c.includes(token)) missing.push(`${DRIVERS[platform]} never produces \`${token}\``);
    }
  }
  assert.deepEqual(missing, [], 'a driver names its descent variants something record.mjs cannot parse, '
    + 'so its `descendedGrant` silently equals the synthesized grant:\n  ' + missing.join('\n  '));
});

test('⭑ no driver still uses the LEGACY bare spelling in its descent', () => {
  // ⛔ THE NEGATIVE HALF, AND IT IS NOT REDUNDANT WITH THE TEST ABOVE. A driver can emit BOTH — the
  // canonical name in one place and the bare one in the summary line that `record.mjs` actually reads
  // — and the presence check alone would pass. This is what Linux's defect looked like in the source.
  // Scoped to the capability-list construction so ordinary uses of the word `network` do not match.
  const legacy = [];
  for (const [platform, c] of Object.entries(CODE)) {
    for (const re of [/push\(\s*["'`]network["'`]/, /push\(\s*["'`]write\./, /push\(\s*["'`]read["'`]/]) {
      if (re.test(c)) legacy.push(`${DRIVERS[platform]} builds a variant name with ${re}`);
    }
  }
  assert.deepEqual(legacy, [], 'a driver still constructs the pre-fix bare variant names:\n  ' + legacy.join('\n  '));
});

test('INSTRUMENT: the legacy detector can actually fire', () => {
  // Without this, the test above passes on a driver set where the regexes match nothing by accident.
  const fake = code('  out.push("network");\n  out.push("write." + k);\n');
  assert.match(fake, /push\(\s*["'`]network["'`]/, 'the legacy regex cannot match the spelling it exists to ban');
  assert.match(fake, /push\(\s*["'`]write\./, 'the legacy write regex cannot match the spelling it exists to ban');
});

// ── END-TO-END: THE LINUX DRIVER'S OWN WORDING, THROUGH THE REAL RECORDER ──────────────────────────

// `measure.sh`'s summary line, verbatim, with the post-fix names. `record.mjs` parses names out of
// `=> OVER-PREDICTED by:` — which is the LINUX spelling of the summary; macOS and Windows emit the
// per-arm sentence instead. Both paths are exercised in this file so neither can rot unnoticed.
const linuxLog = (names, grant, tail = []) => [
  '  ARM-FALSIFIABILITY {"pkg":"demo","falsifiable":true}',
  `  => MINIMUM ${JSON.stringify(grant)}   (observed, then verified)`,
  `  => OVER-PREDICTED by: ${names.join(' ')}  (synthesized ${JSON.stringify(grant)}; each named capability drops on its own)`,
  ...tail,
].join('\n');

test('⭑ RED-GREEN: a Linux N=1 record publishes a genuinely NARROWED grant', () => {
  // ⛔ THE ACCEPTANCE CRITERION, ASSERTED ON THE VALUE RATHER THAN ON THE FIELD'S PRESENCE. Before the
  // fix this returned `grantSource: "descended"` with `grant` UNCHANGED at the synthesized value —
  // so a test that only checked `grantSource === 'descended'` passed on the broken code. The
  // un-narrowed value is what has to fail.
  const r = parseDriverLog(linuxLog(['no-network'], { write: { deps: true }, network: true }));
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: { deps: true } },
    'the published grant still carries `network`, which an arm proved droppable — the descent was a no-op');
  assert.deepEqual(r.descendedGrant, { write: { deps: true } });
});

test('a write scope drops by name and an emptied `write` object collapses', () => {
  const r = parseDriverLog(linuxLog(['no-write-deps'], { write: { deps: true }, network: true }));
  assert.deepEqual(r.grant, { network: true }, 'an emptied `write` must be removed, not left as `{}`');
});

test('⭑ RED-GREEN: N>=2 keeps the WIDE grant until the Linux joint arm verifies it', () => {
  const grant = { write: { deps: true }, network: true };
  const names = ['no-network', 'no-write-deps'];

  const without = parseDriverLog(linuxLog(names, grant));
  assert.equal(without.grantSource, 'synthesized', 'N>=2 narrowed with no joint arm — that is an inference');
  assert.deepEqual(without.grant, grant);

  const withJoint = parseDriverLog(linuxLog(names, grant,
    ['  => JOINT-NARROW VERIFIED {} — all 2 capabilities drop TOGETHER, measured']));
  assert.equal(withJoint.grantSource, 'descended');
  assert.deepEqual(withJoint.grant, {}, 'a verified joint arm is a measurement and must be published');
});

test('a FAILED or INCONCLUSIVE Linux joint arm does NOT narrow', () => {
  const grant = { write: { deps: true }, network: true };
  for (const tail of [
    '  => JOINT-NARROW FAILED {} — each capability drops alone but not together;',
    '  => JOINT-NARROW INCONCLUSIVE — the arm was VOID, so the joint drop is unmeasured;',
  ]) {
    const r = parseDriverLog(linuxLog(['no-network', 'no-write-deps'], grant, [tail]));
    assert.equal(r.grantSource, 'synthesized', `\`${tail.trim().slice(0, 34)}\` must not narrow`);
    assert.deepEqual(r.grant, grant);
  }
});

test('⭑ an UNPARSEABLE variant name keeps the wide grant and says so', () => {
  // ⛔ THE GUARD THAT MAKES THE WHOLE CLASS LOUD. This is the pre-fix Linux wording driven through the
  // post-fix recorder: it must NOT come back `descended`, because nothing was recomputed. Before the
  // guard it did exactly that, which is how the defect stayed invisible for the life of the descent.
  const r = parseDriverLog(linuxLog(['network'], { write: { deps: true }, network: true }));
  assert.equal(r.grantSource, 'synthesized',
    'a name the recorder cannot parse produced a "descended" grant — the no-op is being published as a measurement');
  assert.deepEqual(r.grant, { write: { deps: true }, network: true }, 'the wide grant must be kept');
  assert.ok(r.notes.includes('descent-name-unparsed'), 'the failure must be queryable in the record, not just in prose');
  assert.match(r.grantSourceReason, /cannot parse/);
});

// ── THE LINUX DRIVER EMITS WHAT THESE CASES PIN ───────────────────────────────────────────────────

test('⭑ DRIFT GUARD: measure.sh emits the sentences and names these cases assume', () => {
  // Without this the hardcoded logs above could drift from the driver and every case would keep
  // passing while the real descent went unparsed — the same failure, one level up.
  const c = CODE.linux;
  for (const re of [
    /out\.push\("no-network"\)/,
    /out\.push\("no-write-" \+ k\)/,
    /=> OVER-PREDICTED by:\$NARROWER/,
    /=> JOINT-NARROW VERIFIED \$JOINT/,
    /=> JOINT-NARROW FAILED \$JOINT/,
    /=> JOINT-NARROW INCONCLUSIVE/,
    /arm-falsifiability\.mjs" --snapshot/,
    /arm-falsifiability\.mjs" --obs/,
  ]) {
    assert.match(c, re, `measure.sh no longer emits what these tests pin: ${re}`);
  }
});

test('⭑ the joint arm is gated at N>=2 and reads all THREE verify outcomes', () => {
  // ⛔ THE GATE IS THE POINT: at N=1 the single leave-one-out arm IS the joint case, so an
  // unconditional joint arm would spend a full jail run re-measuring what was already measured.
  assert.match(CODE.linux, /DROPPED_N.*-ge 2|"\$\{DROPPED_N:-0\}" -ge 2/,
    'the joint arm is no longer gated at N>=2');
  // ⛔ AND THE OUTCOME THAT MUST NOT COLLAPSE. `verify` returns 0/1/2 and a VOID arm (2) measured
  // NOTHING. `if verify …; then VERIFIED; else FAILED; fi` files an arm that never ran as evidence
  // that the capabilities do not drop together — see the loop above it, where the same collapse
  // manufactured a `NECESSARY` verdict on `wordpos@2.1.0`.
  const joint = /verify "\$JOINT" "joint-narrow"[\s\S]*?esac/.exec(CODE.linux)?.[0] ?? '';
  assert.ok(joint, 'the joint arm no longer calls `verify` and branches on its status');
  assert.match(joint, /^\s*2\)/m, 'the joint arm does not handle rc 2 (VOID) separately — it reads an unmeasured arm as a failure');
});

// ── the macOS descent's THIRD outcome ──────────────────────────────────────────────────────────────
//
// ⛔ `measure-macos.sh` USED `if verify …`, SO VOID COLLAPSED INTO "NECESSARY". `verify` returns 2 when
// the override did not engage — nothing was measured — and 2 is falsy in shell, so the old two-way
// branch read it as "the narrowing failed ⇒ that capability is necessary" and the descent went on to
// print `=> MINIMAL` having proven nothing. `measure.sh` has always branched three ways.
//
// The GRANT stayed safe (a kept capability is an over-grant), but `minimality: MINIMAL` is the field
// that claims the minimum was PROVEN, and it was being emitted unearned. `record.mjs` already parsed
// both sentences — a consumer with no producer — so the fix was a port, and this is its round trip.
const macosDescentLog = (verdict, lines = []) => [
  '  ARM-FALSIFIABILITY {"pkg":"demo","falsifiable":true}',
  '  => MINIMUM {"network":true}   (observed, then verified)',
  ...lines,
  verdict,
].join('\n');

test('⭑ a VOID macOS narrowing yields UNPROVEN, not MINIMAL', () => {
  const r = parseDriverLog(macosDescentLog(
    '  => DESCENT INCOMPLETE — no capability dropped, but network was never measured; MINIMALITY IS UNPROVEN',
    ["     ⛔ INCONCLUSIVE for 'network' — the arm was VOID, so nothing was measured; NOT evidence of necessity"],
  ));
  assert.equal(r.minimality, 'UNPROVEN',
    'an unmeasured capability is not a necessary one — "no capability dropped" is not evidence of minimality here');
  assert.ok(r.notes.includes('descent-inconclusive'),
    'the per-capability line must also mark the record, so the reason survives without the verdict line');
});

test('⭑ the CONTROL: a macOS descent with no VOID arm still reports MINIMAL', () => {
  // Without this, a change that made everything UNPROVEN would satisfy the test above while
  // destroying the verdict it exists to protect — the same shape as a harness that refuses everything.
  const r = parseDriverLog(macosDescentLog(
    '  => MINIMAL — every capability in {"network":true} is independently necessary',
    ["     narrowing 'network' fails ⇒ that capability IS necessary"],
  ));
  assert.equal(r.minimality, 'MINIMAL');
  assert.ok(!r.notes.includes('descent-inconclusive'), 'nothing was inconclusive, so nothing should say so');
});

test('⭑ DRIFT GUARD: measure-macos.sh emits the three-way vocabulary this pins', () => {
  // The producer half. `record.mjs` parsed these sentences for months while the macOS driver emitted
  // neither, so asserting the consumer alone proves nothing about what darwin records actually say.
  const src = fs.readFileSync(path.join(HERE, DRIVERS.macos), 'utf8');
  for (const re of [/INCONCLUSIVE for /, /=> DESCENT INCOMPLETE/, /the arm was VOID/]) {
    assert.match(src, re, `measure-macos.sh no longer emits what these tests pin: ${re}`);
  }
  assert.doesNotMatch(src, /if verify "\$gg" "nar-\$nm"; then/,
    'the two-way branch is what collapsed VOID into "necessary" — it must not come back');
});
