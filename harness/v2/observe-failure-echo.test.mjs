// ⛔⛔ A `BROKEN-WITHOUT-JAIL-TOO` RECORD THAT DOES NOT SAY WHY IS NOT A MEASUREMENT, IT IS A TALLY.
//
// The verdict is a claim ABOUT THE PACKAGE — that nothing installs it unjailed. Four different
// findings produce it and they are not interchangeable: a download URL that 404s today, a native
// compile that fails, a toolchain the runner does not ship, and a dependency the era Node cannot
// parse. npm says which one it was, on stderr, into `"$OBS/npm.log"`; the Linux driver captured that
// file and then discarded it with the scratch dir.
//
// MEASURED 2026-08-31: 258 linux records exit at that branch carrying the `OBSERVE rc=` line, the
// verdict, and nothing else — `elm@0.15.1` and `@sitespeed.io/edgedriver@132.0.2957-115` among them.
// macOS has echoed a `tail -20` of the same file since the branch was written, so the class read as
// darwin-diagnosable and linux-opaque for no reason but the missing line. This file is what stops
// that asymmetry coming back.
//
// ⛔ EXECUTED, NOT GREPPED. A source match cannot tell an echo that fires from one sitting past an
// `exit 0`, and the branch order here is load-bearing (a capped arm must not be filed as a package
// verdict) — so the region is extracted from the driver and run under real bash, exactly as
// `linux-ladder.test.mjs` runs the ladder. The falsification control is in the file too: `NO_ECHO`
// deletes the echo from that same region and asserts the cause vanishes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const DRIVER = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');

/// The OBSERVE arm's post-run verdict block: the file/trace tally, the ARM-CAP branch and the
/// unjailed-failure branch. Anchored on the statements that open and close it rather than on line
/// numbers, so an edit anywhere above cannot silently shift the slice.
const REGION = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => l.startsWith('OBS_FILES=$(find "$OBS"'));
  const end = lines.findIndex((l) => l.startsWith('# The dependency closure npm actually installed'));
  return start < 0 || end < 0 ? '' : lines.slice(start, end).join('\n');
})();

/// The same region with the echo STATEMENTS removed — the control that proves the assertions below
/// are about the echo and not about something else in the block. Matched on the statement shape and
/// not on the substring `npm.log`, which also appears in the branch's own comment.
const NO_ECHO = REGION.split('\n').filter((l) => !/^\s*sed .*npm\.log/.test(l)).join('\n');

/// A real npm 10 failure block: `code 1` names the category, the `gyp ERR!` line names the cause.
const GYP_LOG = [
  'npm error code 1',
  'npm error path /tmp/obs-x/observe/node_modules/heapdump',
  'npm error command failed',
  'npm error command sh -c node-gyp rebuild',
  'npm error gyp ERR! find Python Python is not set from command line or npm configuration',
  'npm error gyp ERR! stack Error: Could not find any Python installation to use',
  'npm error Node.js v22.23.1',
].join('\n');

/**
 * Run the extracted region with a fabricated observe dir, and return its stdout.
 *
 * `set -uo pipefail` matches the driver's own options (`measure.sh:44`), so an unbound name here
 * fails the same way it would in production rather than quietly expanding to nothing.
 */
const run = (npmLog, { obsRc = 1, source = REGION } = {}) => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'observe-echo-'));
  fs.writeFileSync(path.join(obs, 'npm.log'), `${npmLog}\n`);
  // The tally line reads this unconditionally; an absent file would make every case measure a
  // driver that had already died on the line above the one under test.
  fs.writeFileSync(path.join(obs, 'trace.txt'), 'x\n'.repeat(3));
  const script = path.join(obs, 'region.sh');
  fs.writeFileSync(script, [
    'set -uo pipefail',
    `OBS=${JSON.stringify(obs)}`,
    `OBS_RC=${obsRc}`,
    source,
    '',
  ].join('\n'));
  return execFileSync('bash', [script], { encoding: 'utf8' });
};

test('INSTRUMENT: the region was located, and the control removes exactly the echo', () => {
  // Every case below is vacuous if the slice is empty or if it never reaches the branch under test.
  assert.ok(REGION.includes('=> BROKEN-WITHOUT-JAIL-TOO'), 'the unjailed-failure branch is not in the extracted region');
  assert.ok(REGION.includes('=> TIMED-OUT'), 'the ARM-CAP branch is not in the extracted region');
  // Two echoes, one per branch. If a third `npm.log` reader ever lands here the control below would
  // start deleting something it does not own, so the count is pinned rather than assumed.
  assert.equal(REGION.split('\n').length - NO_ECHO.split('\n').length, 2,
    'the control no longer removes exactly the two npm.log echoes');
});

test('a control failure carries npm\'s own diagnosis into driver.out', () => {
  const out = run(GYP_LOG);
  assert.match(out, /=> BROKEN-WITHOUT-JAIL-TOO \(unjailed control failed rc=1/,
    'the verdict line lost its rc, which is the first split a reader makes');
  assert.match(out, /gyp ERR! find Python/, 'the cause did not reach driver.out');
  assert.match(out, /Node\.js v22\.23\.1/, 'the tail is shorter than the block npm printed');

  // ⛔ THE RED CONTROL, IN THE FILE. Without it every assertion above would keep passing if the echo
  // were deleted tomorrow and something else in the block happened to print the same text.
  const control = run(GYP_LOG, { source: NO_ECHO });
  assert.match(control, /=> BROKEN-WITHOUT-JAIL-TOO/, 'the control removed more than the echo');
  assert.doesNotMatch(control, /gyp ERR!/,
    'the cause survived deleting the echo, so these assertions are not testing the echo');
});

test('the echo is a bounded excerpt, not the whole log', () => {
  // A record is evidence, not an archive: node-gyp logs run to tens of thousands of lines and the
  // useful end is the last one. 20 is the volume macOS settled on and the fetch branch above reuses.
  const out = run(Array.from({ length: 60 }, (_, i) => `line-${i + 1}`).join('\n'));
  const echoed = out.split('\n').filter((l) => l.startsWith('    | '));
  assert.equal(echoed.length, 20, 'the echo is no longer capped at 20 lines');
  assert.ok(echoed.at(-1).endsWith('line-60'), 'the echo kept the head of the log instead of the tail');
  assert.doesNotMatch(out, /line-40\b/, 'the cap is not being applied to the tail');
});

test('an echoed line is package output, never a verdict', () => {
  // `parseDriverLog` drops `/^\s*\|\s/` lines because the verdict patterns are unanchored and the
  // LAST match wins — so an echoed MINIMUM, which is deliberately never downgraded once seen, would
  // outrank the verdict printed above it. That is why this echo uses the `    | ` prefix.
  const injected = 'npm error a package printed => MINIMUM {} (observed, then verified)';

  // ⛔ THE CONTROL IS macOS'S OWN PREFIX, WHICH IS THE ALTERNATIVE THIS DIFF REJECTED.
  // `measure-macos.sh` echoes the same file with `sed 's/^/     /'` — an indent, no pipe — and
  // nothing filters that. Without this arm the assertion below would pass against a driver that
  // echoes nothing at all, which is exactly the shape it exists to rule out.
  const bare = run(injected, { source: REGION.replaceAll("s/^/    | /", "s/^/     /") });
  assert.equal(parseDriverLog(bare).verdict, 'MINIMUM',
    'the bare-indent control did not inject, so this fixture cannot detect the hazard');

  assert.equal(parseDriverLog(run(injected)).verdict, 'BROKEN-WITHOUT-JAIL-TOO',
    'a package\'s own output was read as the record\'s verdict');
});

test('a capped arm echoes too, and is still not a package verdict', () => {
  // The cap says the measurement ran out of time, which supports no claim about the package — but a
  // reader still needs to see what the arm was doing when it was killed.
  const out = run(GYP_LOG, { obsRc: 124 });
  assert.equal(parseDriverLog(out).verdict, 'HARNESS-TIMEOUT',
    'the cap started reading as a verdict about the package');
  assert.match(out, /gyp ERR! find Python/, 'the capped arm still discards npm\'s output');
});
