// The replay signal must reach the record, and the three drivers must not disagree about it.
//
// ⛔ THE DEFECT. `record.mjs` matched only `REPLAY SUSPECTED`. `measure.sh` had already retired its
// heuristic in favour of `side-effects-cache: restored` — the one predicate measured to work — and
// announces it as `REPLAY CONFIRMED`, a spelling that line never matched. So the STRONGEST replay
// signal produced no note at all, while the two weak ones did.
//
// ⛔ AND THE WINDOWS PREDICATE WAS ONE `measure.sh` HAD MEASURED TO BE WRONG IN BOTH DIRECTIONS.
// `running build scripts for` is printed only for a DEFAULT-TRUSTED package; a deferred one prints
// `ignored build scripts for` and runs under `approve-builds`, which prints neither. Measured on the
// Linux lane: `es5-ext@0.10.64` (cold, approved, genuinely rebuilt) gave 0 occurrences and
// FALSE-FIRED; `msgpackr-extract@3.0.4` (genuinely restored from cache) gave 1 and STAYED QUIET.
// Both noisy and blind. It fired on all four arms of `postman-code-generators@0.2.4`, which is how
// this was found.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;

test('⭑ REPLAY CONFIRMED reaches the record — it previously produced no note at all', () => {
  const r = parseDriverLog('  ⛔ REPLAY CONFIRMED -- nub restored this package\'s build output\n');
  assert.ok(r.notes.includes('replay-confirmed'),
    `the strongest replay signal was dropped; notes=${JSON.stringify(r.notes)}`);
});

test('REPLAY SUSPECTED still reaches the record, under its own weaker name', () => {
  const r = parseDriverLog('     !! REPLAY SUSPECTED -- no install line; the script may not have run\n');
  assert.ok(r.notes.includes('replay-suspected'));
  assert.ok(!r.notes.includes('replay-confirmed'),
    'a heuristic guess must never be recorded as a confirmation');
});

test('a clean log carries neither note — otherwise every record reads as a replay', () => {
  const r = parseDriverLog('  VERIFY[synth] rc=0 artifacts=10/10 missing=0\n');
  assert.ok(!r.notes.some((n) => n.startsWith('replay-')), JSON.stringify(r.notes));
});

test('⭑ no driver uses the BARE line as a replay predicate — the prefixed form is a different question', () => {
  // The guard that keeps the three lanes from drifting apart again. `override-probe-parity.test.mjs`
  // does the same job for the override probe.
  //
  // ⛔ THE BARE SUBSTRING IS BANNED; `defaultTrust: running build scripts for` IS NOT, and the
  // distinction is the whole point. This guard first banned the substring outright and immediately
  // flagged `measure.sh`, which uses the PREFIXED form to decide whether `nub install` already ran
  // the build scripts — so it should skip `approve-builds` and not run them twice. That is a
  // correct use: the prefixed line is exactly what nub prints on the default-trusted path, and
  // asking "did install already run them?" is precisely what it answers.
  //
  // What is wrong is inferring REPLAY from its ABSENCE. A deferred package prints `ignored build
  // scripts for` instead and runs under `approve-builds`, which prints neither — so absence means
  // "not default-trusted", not "never ran".
  for (const f of ['measure.sh', 'measure-windows.mjs', 'measure-macos.sh']) {
    const src = fs.readFileSync(path.join(HERE, f), 'utf8');
    const live = src
      .split('\n')
      .filter((l) => !/^\s*(#|\/\/)/.test(l))
      .filter((l) => /running build scripts for/.test(l))
      .filter((l) => !/defaultTrust: running build scripts for/.test(l));
    assert.deepEqual(live, [],
      `${f} tests for the BARE 'running build scripts for' outside a comment — as a replay `
      + 'predicate it false-fires on an approved rebuild and stays quiet on a real replay.');
  }
});

test('CONTROL: the banned bare form IS detected, so the guard above can go red', () => {
  // Without this, narrowing the filter could have quietly made it match nothing at all.
  const bare = "  if (!/running build scripts for/.test(logs)) {";
  const prefixed = "    if grep -q 'defaultTrust: running build scripts for' \"$v/i.log\"; then";
  const flag = (l) => [l]
    .filter((x) => !/^\s*(#|\/\/)/.test(x))
    .filter((x) => /running build scripts for/.test(x))
    .filter((x) => !/defaultTrust: running build scripts for/.test(x));
  assert.equal(flag(bare).length, 1, 'the predicate no longer detects the bare form it exists to ban');
  assert.equal(flag(prefixed).length, 0, 'the predicate flags the legitimate prefixed use');
});

test('⭑ the Windows arms run under RUST_LOG=debug, or its predicate cannot observe anything', () => {
  // `side-effects-cache: restored` is a `tracing::debug!`. Without debug logging the check is
  // unfalsifiable — permanently green, which is the vacuous shape this repo keeps rediscovering.
  const src = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(src, /RUST_LOG: 'debug'/,
    'the Windows arm env has no RUST_LOG=debug, so the replay line can never appear');
  assert.match(src, /side-effects-cache: restored/,
    'the Windows driver does not test for the restored line at all');
});
