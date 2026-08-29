// A line the jail-off control ECHOED is package output, never a verdict.
//
// The control prints what nub said with a `    | ` prefix, so a real nub defect and a harness
// asymmetry stop leaving byte-identical records. But every verdict pattern in record.mjs is
// UNANCHORED -- `/=>\s*VERIFIED\s/` and 16 siblings -- while the drivers' own comments state the
// parser "keys every verdict on a LEADING `=>`". Code and comment disagreed, so a `=>` anywhere in
// a line an arbitrary package printed could be read as a verdict, and the LAST match wins.
//
// MEASURED across all 6880 driver logs before the fix landed: 2958 echoed lines across 135 files,
// of which ZERO matched any verdict pattern. The hole was real and had never fired -- which is
// exactly the kind that fires later, on a package nobody has measured yet.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseDriverLog } from './record.mjs';

/// A log shaped like the real thing: the control fails, echoes nub's output, then the driver states
/// the actual verdict on its own line.
const log = (echoed) => [
  '  jail-off control: nub failed with the jail OFF; asking npm before naming a culprit',
  ...echoed.map((l) => `    | ${l}`),
  '  => BROKEN-WITHOUT-JAIL-TOO',
].join('\n');

test('the fixture reaches a verdict at all, so the assertions below are not vacuous', () => {
  // Known-answer control. If parseDriverLog stops recognising this shape, every assertion here
  // passes against `undefined` and the guard silently becomes decoration.
  assert.equal(parseDriverLog(log([])).verdict, 'BROKEN-WITHOUT-JAIL-TOO');
});

// ⛔ ONLY A STICKY VERDICT ACTUALLY INJECTS, and the RED drive is what established that. An echoed
// '=> REFUSED-MALICIOUS' is HARMLESS: the driver prints its real verdict after the echo, and a later
// match overwrites an earlier one. But MINIMUM/VERIFIED are deliberately NEVER DOWNGRADED once seen
// ("a MINIMUM is therefore never downgraded once seen", record.mjs) -- so an echoed MINIMUM survives
// the real verdict that follows it. Two earlier drafts of a test here passed with the fix removed,
// because they used non-sticky tokens; they are gone rather than left as decoration.
test('it holds for the terminal verdicts too, where the cost is highest', () => {
  for (const token of ['=> MINIMUM {} (observed, then verified)', '=> MINIMUM {} (ladder fallback)', '=> VERIFIED {}']) {
    const parsed = parseDriverLog(log([`some-tool: ${token}`]));
    assert.equal(parsed.verdict, 'BROKEN-WITHOUT-JAIL-TOO',
      `echoed "${token}" changed the verdict`);
  }
});

test('a genuine verdict line is still read when it merely looks indented', () => {
  // The filter keys on a leading `|`, NOT on indentation — the drivers indent every verdict line
  // by two spaces, so keying on whitespace would discard every verdict in the corpus.
  assert.equal(parseDriverLog('      => NO-STATE-PASSED').verdict, 'NO-STATE-PASSED');
});
