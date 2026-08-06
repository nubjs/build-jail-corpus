// Parser tests for `record.mjs`, against REAL driver output.
//
// ⛔ THE FIXTURES ARE CAPTURED FROM A LIVE RUN, NOT HAND-WRITTEN FROM THE DRIVER SOURCE. A fixture
// reconstructed from the `echo` statements in `measure-macos.sh` tests the parser against my reading
// of the driver rather than against the driver, and would agree with a parser that is wrong in
// exactly the way my reading was. These three blocks are `macos-v2-measure` run 31088841052's VERIFY
// step verbatim, and they happen to cover the three outcomes that matter: a grant that verified and
// then narrowed (over-prediction), and two that did not verify at all.
//
//   node --test harness/v2/record.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDriverLog, firstObject } from './record.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const load = (f) => fs.readFileSync(path.join(FIX, f), 'utf8');

test('a verified grant that narrows records the VERIFIED grant, not the narrower one', () => {
  const r = parseDriverLog(load('macos-_apollo_protobufjs-1.2.7.txt'));
  assert.equal(r.verdict, 'MINIMUM');
  assert.deepEqual(r.grant, { write: { deps: true } });
  assert.equal(r.verifiedBy, 'synth');
  // ⛔ THE RECORDED GRANT IS THE ONE WHOSE ARM PASSED, AND `{}` IS NOT IT even though a `{}` arm also
  // passed here. Leave-one-out proves each capability droppable INDIVIDUALLY, never jointly, so
  // adopting the narrowest observed variant as the grant would under-grant the moment a package has
  // two capabilities — the one direction that breaks a real install. The over-prediction is recorded
  // beside the grant instead, which is the honest shape.
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(r.overPredictedBy, ['no-write-deps']);
});

test('a grant that did not verify is UNDER-PREDICTED with no grant, not a harness error', () => {
  for (const f of ['macos-_nuxt_components-2.1.0.txt', 'macos-codeceptjs-1.1.3.txt']) {
    const r = parseDriverLog(load(f));
    assert.equal(r.verdict, 'UNDER-PREDICTED', f);
    assert.equal(r.grant, null, f);
    // The hypothesis is still worth keeping: it is what the next fix has to explain.
    assert.ok(r.synthesized, f);
    assert.ok(r.notes.includes('under-predicted'), f);
  }
});

test('the synthesized grant survives even when the driver only observed', () => {
  const r = parseDriverLog(load('macos-codeceptjs-1.1.3.txt'));
  assert.deepEqual(r.synthesized, { write: { deps: true }, network: true });
});

// ⛔ THE NEGATIVE CONTROL. Silence must not read as an empty grant: a driver killed by a deadline or
// dying before its first `=>` has measured NOTHING, and emitting `{}` for it would record "this
// package needs no capabilities" — an under-grant manufactured out of an instrument failure.
test('a log with no terminal line yields no verdict, so the caller must call it HARNESS-*', () => {
  const r = parseDriverLog('### foo@1.0.0\n  OBSERVE   rc=0 files=3\n');
  assert.equal(r.verdict, null);
  assert.equal(r.grant, null);
});

test('a trailing paren does not get swallowed into the grant', () => {
  assert.deepEqual(
    firstObject('  => VERIFIED {"write":{"deps":true}}   (observed, then verified)'),
    { write: { deps: true } },
  );
});

// The Windows and Linux drivers are not exercised by a captured fixture — no v2 run on either has
// produced one this lane could read back. These assert only the vocabulary difference the parser
// exists to resolve, and are marked as such rather than presented as end-to-end coverage.
test('MINIMUM via the ladder is distinguished from MINIMUM via synthesis', () => {
  const synth = parseDriverLog('  => MINIMUM {"write":{"deps":true}}   (observed, then verified)');
  assert.equal(synth.verifiedBy, 'synth');
  const ladder = parseDriverLog('  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)');
  assert.equal(ladder.verifiedBy, 'ladder');
  assert.equal(ladder.verdict, 'MINIMUM');
});

test('a VOID arm is never reported as a grant of any width', () => {
  const r = parseDriverLog('  => ⛔ VOID — the override did not engage on the verdict arm; NOTHING was measured.');
  assert.equal(r.verdict, 'VOID');
  assert.equal(r.grant, null);
});

// ── `events-lost` must fire on EVERY driver's wording, not just the one it was written against ────
//
// ⛔ A NOTE THAT FIRES ON ONE VENUE OF THREE IS WORSE THAN ABSENT, because its silence reads as a
// clean trace. `record.mjs` keyed on `events LOST`, which is the WINDOWS spelling and genuinely live
// there — so the note was never dead, and that is precisely why nobody caught it. macOS and Linux
// announce event loss in their own words and were never noted at all: both darwin records dropped an
// event and shipped `notes: []`. A dropped event is a path never seen, which UNDER-predicts the
// grant, so this is the record's only warning that its own evidence is incomplete.

const HARNESS = path.dirname(fileURLToPath(import.meta.url));

// The rendered form of each driver's loss line, with its interpolations filled in. Hand-rendered
// rather than captured, because no fixture we hold has ever lost an event — so the drift guard below
// is what keeps these honest, by asserting each wording is still the one its driver emits.
const LOSS_LINES = {
  'windows / measure-windows.mjs':
    '  !! 7 events LOST -- exact-set claims are not supported by this trace',
  'macos / observe-macos.mjs (tracer drop)':
    '  ⛔ THE TRACER DROPPED 7 EVENT(S). A dropped event is a path never',
  'macos / observe-macos.mjs (loss ledger)':
    '  ⛔ LOSS LEDGER DISAGREES: END says 7, 5 per-event records survived',
  'linux / observe.mjs':
    '  ⛔ 7 trace lines the decoder could not parse',
};

test('DRIFT GUARD: each wording under test is still the one its driver actually emits', () => {
  // Without this, the hardcoded strings above could drift away from the drivers and every case below
  // would keep passing while the real note went dead again — the same failure, one level up.
  const src = (f) => fs.readFileSync(path.join(HARNESS, f), 'utf8');
  assert.match(src('measure-windows.mjs'), /events LOST -- exact-set claims/,
    'the Windows driver no longer emits the wording these tests pin');
  assert.match(src('observe-macos.mjs'), /THE TRACER DROPPED \$\{/,
    'the macOS adapter no longer emits THE TRACER DROPPED');
  assert.match(src('observe-macos.mjs'), /LOSS LEDGER DISAGREES: END says/,
    'the macOS adapter no longer emits LOSS LEDGER DISAGREES');
  assert.match(src('observe.mjs'), /trace lines the decoder could not parse/,
    'the Linux decoder no longer emits its unparsed-lines line');
});

for (const [driver, line] of Object.entries(LOSS_LINES)) {
  test(`\`events-lost\` fires on the ${driver} wording`, () => {
    // Injected into a REAL driver log so the note is exercised on a record that otherwise parses
    // completely, rather than on a synthetic stub that could pass for unrelated reasons.
    const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
    base.splice(1, 0, line);
    const r = parseDriverLog(base.join('\n'));
    assert.ok(r.notes.includes('events-lost'),
      `a dropped event went unnoted for ${driver} — the record claims complete evidence it does not have:\n${JSON.stringify(r.notes)}`);
  });
}

test('CONTROL: a driver log that lost NOTHING carries no `events-lost` note', () => {
  // The control without which every case above is consistent with a detector that fires on any line
  // at all. All three real fixtures are clean traces, verified: none contains a loss line.
  for (const f of ['macos-_apollo_protobufjs-1.2.7.txt', 'macos-_nuxt_components-2.1.0.txt', 'macos-codeceptjs-1.1.3.txt']) {
    const r = parseDriverLog(load(f));
    assert.ok(!r.notes.includes('events-lost'),
      `${f} lost no events but was noted as if it had — the detector is too wide:\n${JSON.stringify(r.notes)}`);
  }
});

test('a driver that trips TWO loss lines still yields exactly one note', () => {
  // macOS emits both of its wordings on the same run. `out.notes` is de-duplicated, and this pins it.
  const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
  base.splice(1, 0, LOSS_LINES['macos / observe-macos.mjs (tracer drop)'],
                    LOSS_LINES['macos / observe-macos.mjs (loss ledger)']);
  const r = parseDriverLog(base.join('\n'));
  assert.equal(r.notes.filter((n) => n === 'events-lost').length, 1,
    `one loss must produce one note:\n${JSON.stringify(r.notes)}`);
});
