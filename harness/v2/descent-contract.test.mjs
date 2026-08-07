// The Windows descent's OUTPUT CONTRACT: every line it prints must mean what `record.mjs` reads.
//
// ⛔ THE DESCENT COMMUNICATES WITH THE RECORDER ENTIRELY THROUGH PROSE, so a wording that drifts by
// one word is a field that silently goes null. That is not hypothetical — it is the same defect
// class caught three times in one day (`events LOST` matching only the Windows wording; `=> MINIMAL`
// parsed but never emitted by the macOS driver, so its strongest descent result filed as `null`; the
// R7 marker spelled two ways). This file is to the descent what `marker-contract.test.mjs` is to the
// venue markers.
//
// ⛔ AND ONE OF THESE IS A CONTRACT RATHER THAN A LABEL, WHICH IS EASY TO MISS. `record.mjs`'s
// `applyGrantSourceRule` recomputes the descended grant by matching the literal variant names
// `no-network` and `no-write-<scope>` out of `overPredictedBy`. A driver that named its variants
// anything else — `network`, `write.deps` — produces a "descended" grant IDENTICAL to the
// synthesized one, so the record claims it narrowed while publishing the wide value. The assertions
// below pin the names, not just the sentences.
//
// ⛔ WHAT THIS CANNOT PROVE. It drives `record.mjs` with the driver's own wording; it does not run
// the descent. No Windows VERIFY arm has ever passed (every arm fails at every grant on an EPERM
// reading the package's own store entry), so the descent has never executed on a real package. This
// pins the interface it will speak the moment it can run — which is exactly the part that would
// otherwise be discovered wrong afterwards, from a corpus of null fields.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseDriverLog } from './record.mjs';

const DRIVER = fs.readFileSync(path.join(import.meta.dirname, 'measure-windows.mjs'), 'utf8');

// ⛔ THE DRIVER'S CODE, WITH COMMENTS STRIPPED. Matching raw source is what makes this file vacuous:
// the first version of this check searched the whole file for `no-network`, which appears in a
// COMMENT explaining the contract — so renaming the actual variants to the Linux spelling left every
// assertion green. Caught by running that exact control. Only executable lines count.
//
// ⛔ A BARE `startsWith('*')` FOR THE JSDOC CONTINUATION ALSO EATS A SHELL `case` DEFAULT ARM, AND IT
// HAS ALREADY DONE SO ONCE — in `descent-vocabulary.test.mjs`, where it deleted `measure.sh`'s own
// `JOINT-NARROW FAILED` emission and then reported it missing. This file reads a `.mjs` driver with no
// such line, so the bare form was harmless HERE, which is exactly why it would have sat until someone
// added a `case` arm to `measure-windows.mjs` and a contract test started silently reading a mutilated
// file. Fixed on discovery rather than documented and left live.
const CODE = DRIVER.split('\n').filter((l) => {
  const t = l.trim();
  const jsdocCont = t === '*' || t.startsWith('* ') || t.startsWith('*/');
  return !t.startsWith('//') && !jsdocCont && !t.startsWith('/*');
}).join('\n');

// The regression control for the line above, so the trap cannot be re-armed silently.
test('INSTRUMENT: the comment stripper does not eat a shell `case` default arm', () => {
  const strip = (s) => s.split('\n').filter((l) => {
    const t = l.trim();
    const jsdocCont = t === '*' || t.startsWith('* ') || t.startsWith('*/');
    return !t.startsWith('//') && !jsdocCont && !t.startsWith('/*');
  }).join('\n');
  assert.match(strip('        *) echo "  => JOINT-NARROW FAILED";;'), /JOINT-NARROW FAILED/,
    'the stripper eats a `case` default arm, so every emission inside one reads as absent');
  assert.doesNotMatch(strip(' * a JSDoc continuation naming no-network\n'), /no-network/,
    'the stripper keeps JSDoc continuations, so a token named only in prose would count as emitted');
});

// ⛔ VALIDATED FIRST. If this scan silently matched nothing, every assertion below would pass while
// checking an empty string — the vacuous-green failure this whole file exists to prevent.
test('INSTRUMENT: the driver really contains a descent that prints these lines', () => {
  for (const needle of ['OVER-PREDICTED', '=> MINIMAL', 'DESCENT INCOMPLETE', 'JOINT-NARROW',
                        'INCONCLUSIVE for']) {
    assert.ok(CODE.includes(needle), `measure-windows.mjs no longer emits \`${needle}\``);
  }
  assert.ok(CODE.length > 2000 && CODE.length < DRIVER.length,
    'the comment stripper produced an implausible result, so these checks may be looking at nothing');
});

test('⭑ the VARIANT NAMES are the ones record.mjs can parse, checked in the CODE', () => {
  // ⛔ THIS IS THE CONTRACT, NOT A LABEL. `applyGrantSourceRule` matches the literal `no-network` and
  // `no-write-<scope>` out of `overPredictedBy` to recompute the descended grant. Any other spelling
  // — `network`, `write.deps` — parses to nothing, so `descendedGrant` comes back equal to the
  // synthesized grant and the record claims it narrowed while publishing the wide value. Asserted
  // against the `variants.push` sites specifically, because the names also appear in prose.
  assert.match(CODE, /variants\.push\(\['no-network'/,
    'the network variant is no longer named `no-network`, which record.mjs cannot parse');
  assert.match(CODE, /variants\.push\(\[`no-write-\$\{k\}`/,
    'the write variants are no longer named `no-write-<scope>`, which record.mjs cannot parse');
});

const MINIMUM = '  => MINIMUM {"write":{"deps":true},"network":true}   (observed, then verified)';
// The falsifiability line must be present for a descended grant to be trusted at all — absence of it
// is read as "the check never ran", not as "the arms were falsifiable".
const FALSIFIABLE = '  ARM-FALSIFIABILITY {"pkg":"demo","falsifiable":true}';

test('one dropped capability descends, and the recomputed grant is actually narrower', () => {
  const r = parseDriverLog([
    FALSIFIABLE, MINIMUM,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"write":{"deps":true}} also verifies; 'no-network' was not needed`,
  ].join('\n'));
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(r.overPredictedBy, ['no-network']);
  // ⛔ THE ASSERTION THE NAME SPELLING EXISTS FOR. A name `record.mjs` cannot parse leaves
  // `descendedGrant` equal to the synthesized grant, and the record then says `descended` while
  // publishing the wide value — silently, in the over-grant direction.
  assert.deepEqual(r.descendedGrant, { write: { deps: true } });
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: { deps: true } });
});

test('a write scope drops by name, and the write object collapses when it empties', () => {
  const r = parseDriverLog([
    FALSIFIABLE, MINIMUM,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"network":true} also verifies; 'no-write-deps' was not needed`,
  ].join('\n'));
  assert.deepEqual(r.overPredictedBy, ['no-write-deps']);
  assert.deepEqual(r.descendedGrant, { network: true }, 'an emptied `write` object must be removed, not left as {}');
});

test('⭑ TWO dropped capabilities keep the WIDE grant unless the joint arm ran', () => {
  // ⛔ THE UNDER-GRANT GUARD. Leave-one-out proves each capability drops ON ITS OWN and nothing
  // proves they drop TOGETHER; the joint grant is strictly narrower than any arm that ran. Publishing
  // it off the individual results would be an inference dressed as a measurement.
  const both = [
    FALSIFIABLE, MINIMUM,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"write":{"deps":true}} also verifies; 'no-network' was not needed`,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"network":true} also verifies; 'no-write-deps' was not needed`,
  ];
  const without = parseDriverLog(both.join('\n'));
  assert.equal(without.grantSource, 'synthesized', 'N>=2 narrowed without a joint arm — that is an inference');
  assert.deepEqual(without.grant, { write: { deps: true }, network: true }, 'the wide grant must be kept');

  const withJoint = parseDriverLog([...both, '  => JOINT-NARROW VERIFIED {} — all 2 capabilities drop TOGETHER, measured'].join('\n'));
  assert.equal(withJoint.grantSource, 'descended');
  assert.deepEqual(withJoint.grant, {}, 'a verified joint arm is a measurement and must be published');
});

test('a FAILED or INCONCLUSIVE joint arm does NOT narrow', () => {
  const base = [
    FALSIFIABLE, MINIMUM,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"write":{"deps":true}} also verifies; 'no-network' was not needed`,
    `     ⛔ OVER-PREDICTED — the strictly narrower {"network":true} also verifies; 'no-write-deps' was not needed`,
  ];
  for (const tail of [
    '  => JOINT-NARROW FAILED {} — each capability drops alone but not together;',
    '  => JOINT-NARROW INCONCLUSIVE — the arm was VOID, so the joint drop is unmeasured;',
  ]) {
    const r = parseDriverLog([...base, tail].join('\n'));
    assert.equal(r.grantSource, 'synthesized', `\`${tail.trim().slice(0, 30)}\` must not narrow`);
    assert.deepEqual(r.grant, { write: { deps: true }, network: true });
  }
});

test('every capability necessary records MINIMAL rather than a null minimality', () => {
  const r = parseDriverLog([
    FALSIFIABLE, MINIMUM,
    "     'no-network' is NECESSARY — dropping it fails to verify",
    '  => MINIMAL — every capability in {"write":{"deps":true},"network":true} is independently necessary',
  ].join('\n'));
  assert.equal(r.minimality, 'MINIMAL', 'the strongest descent result must not file as null');
  assert.deepEqual(r.overPredictedBy, []);
  assert.equal(r.grantSource, 'synthesized');
});

test('an empty grant is MINIMAL by construction, in the phrase record.mjs reads', () => {
  const r = parseDriverLog([
    FALSIFIABLE, '  => MINIMUM {}   (observed, then verified)',
    '  DESCEND   grant is already empty — nothing to narrow; MINIMAL by construction.',
  ].join('\n'));
  assert.equal(r.minimality, 'MINIMAL');
});

test('a VOID arm is INCONCLUSIVE, never evidence that the capability was necessary', () => {
  // ⛔ THE OUTCOME THAT MUST NOT COLLAPSE INTO "NECESSARY". A VOID arm measured nothing, so reading
  // it as necessity manufactures evidence in the direction that HIDES over-prediction.
  const r = parseDriverLog([
    FALSIFIABLE, MINIMUM,
    "     ⛔ INCONCLUSIVE for 'no-network' — the arm was VOID, so nothing was measured; NOT evidence of necessity",
    '  => DESCENT INCOMPLETE — no capability dropped, but no-network was never measured; MINIMALITY IS UNPROVEN',
  ].join('\n'));
  assert.equal(r.minimality, 'UNPROVEN', 'an unmeasured capability must not read as MINIMAL');
  assert.ok(r.notes.includes('descent-inconclusive'));
  assert.deepEqual(r.overPredictedBy, []);
});

test('⭑ DRIFT GUARD: the driver emits the exact sentences these cases pin', () => {
  // Without this, the hardcoded strings above could drift away from `measure-windows.mjs` and every
  // case would keep passing while the real descent went unparsed — the same failure, one level up.
  const emits = [
    /OVER-PREDICTED — the strictly narrower \$\{JSON\.stringify\(sub\)\} also verifies; '\$\{name\}' was not needed/,
    // ⛔ `g0`, NOT `GRANT`. `0f1aeecf2` made the Windows descent a FUNCTION taking the grant to
    // descend from, precisely so the ladder path could call it — and this guard, whose whole job is
    // to notice that kind of drift, went red and stayed red instead of being updated with it.
    /=> MINIMAL — every capability in \$\{JSON\.stringify\(g0\)\} is independently necessary/,
    /=> DESCENT INCOMPLETE — no capability dropped, but \$\{inconclusive\.join\(' '\)\} was never measured/,
    /=> JOINT-NARROW VERIFIED \$\{JSON\.stringify\(joint\)\}/,
    /INCONCLUSIVE for '\$\{name\}' — the arm was VOID/,
    /grant is already empty — nothing to narrow; MINIMAL by construction\./,
  ];
  for (const re of emits) {
    assert.match(DRIVER, re, `measure-windows.mjs no longer emits the wording these tests pin: ${re}`);
  }
});
