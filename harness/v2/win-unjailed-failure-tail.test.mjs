// ⛔⛔ `rc=1` IS NOT A REASON, AND FOR 562 win32 RECORDS IT WAS THE ONLY THING WE KEPT.
//
// The unjailed rebuild is the CONTROL arm: when it fails, the driver files
// `BROKEN-WITHOUT-JAIL-TOO` — a claim that nub cannot build this package even with the jail off.
// That exit printed the verdict, named the binary, and exited. It never printed WHY.
//
// MEASURED corpus-wide: 562 win32 records with that verdict carry a `driver.out` under 1200 bytes
// containing no error output whatsoever. A complete one, in full:
//
//     ### bootstrap-slider@4.2.0   (D:\jail\m-bootstrapslider-msk15pqz)
//       CAPTURE user=... elevated=True rootPid=4924 exit=1 events=21017 lost=0
//       => BROKEN-WITHOUT-JAIL-TOO (unjailed rebuild rc=1)
//       VENUE-NUB-BINARY {...}
//
// "node-gyp cannot find MSVC", "the tarball 404s" and "the postinstall crashed" are exactly the
// distinctions this corpus exists to draw, and all 562 are unclassifiable. The darwin lane has never
// had the hole: `measure-macos.sh:687` tails `npm.log` on the same failure.
//
// The output was never lost — `adapters/windows.ps1` spawns the traced child with
// `-RedirectStandardOutput (Join-Path $OutDir 'run.out')` / `-RedirectStandardError ... 'run.err'`
// and the driver passes `-OutDir CAP`. It was on disk the whole time and nothing read it.
//
// ⛔ THESE TESTS EXECUTE THE DRIVER'S OWN FUNCTIONS AND ITS OWN CALL LINE, lifted out of
// `measure-windows.mjs` at run time — the `failure-reason-fallback.test.mjs` /
// `rebuild-spec-is-versioned.test.mjs` idiom. `measure-windows.mjs` needs ETW and a real Windows
// kernel so it cannot be driven to this branch here, but the tail itself is ordinary I/O and there
// is no reason to assert on its TEXT when it can be RUN. Every extractor asserts it found its
// anchor, so drift fails loudly instead of silently testing the empty string.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');

/// A top-level `function` declaration, anchored on its header and closed on the first column-0 `}`.
function extractFn(name) {
  const lines = SRC.split('\n');
  const start = lines.findIndex((l) => l.startsWith(`function ${name}(`));
  assert.notEqual(start, -1, `ANCHOR DRIFT: measure-windows.mjs has no \`function ${name}\``);
  const end = lines.findIndex((l, i) => i > start && l === '}');
  assert.notEqual(end, -1, `ANCHOR DRIFT: \`${name}\` is never closed at column 0`);
  return lines.slice(start, end + 1).join('\n');
}

/// The rebuild exit's actual tail line. Lifted rather than transcribed so that WHICH files it reads
/// and in WHICH order are decided by the driver, not restated here where they could drift apart.
function extractTailCall() {
  const line = SRC.split('\n').find((l) => /emitFailureTail\(readTracedLog\(/.test(l));
  assert.ok(line, 'the unjailed-rebuild exit no longer tails the traced child log — the 562-record hole is back');
  return line.trim();
}

/// Runs the driver's real composition against a `cap` directory and returns the lines it logged.
function runTail(cap, { call = extractTailCall() } = {}) {
  const out = [];
  const body = `${extractFn('readTracedLog')}\n${extractFn('emitFailureTail')}\n${call}`;
  new Function('fs', 'path', 'CAP', 'console', body)(fs, path, cap, { log: (m) => out.push(m) });
  return out;
}

/// A capture directory holding whatever the traced child wrote. `null` omits the file entirely,
/// which is the shape a capture that died before spawning leaves behind.
function capture({ stdout = null, stderr = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-tail-'));
  if (stdout !== null) fs.writeFileSync(path.join(dir, 'run.out'), stdout);
  if (stderr !== null) fs.writeFileSync(path.join(dir, 'run.err'), stderr);
  return dir;
}

// The real shape of the failure that dominates this bucket: npm's progress chatter on stdout, and
// node-gyp's diagnosis — the part a reader needs — on stderr, below more than a full window of it.
const NOISE = Array.from({ length: 30 }, (_, i) => `npm http fetch GET 200 https://registry.npmjs.org/dep-${i} 41ms`);
const RUN_OUT = [...NOISE, '', '> bufferutil@4.0.7 install D:\\jail\\obs\\node_modules\\bufferutil', '> node-gyp rebuild'].join('\n');
const CAUSE = 'gyp ERR! stack Error: Could not find any Visual Studio installation to use';
const RUN_ERR = [
  'gyp ERR! find VS msvs_version not set from command line or npm config',
  'gyp ERR! find VS could not find a version of Visual Studio 2017 or newer to use',
  CAUSE,
  'npm ERR! code 1',
].join('\n');

test('⭑ the unjailed-rebuild exit reports WHY, which is the whole of the 562-record defect', () => {
  const emitted = runTail(capture({ stdout: RUN_OUT, stderr: RUN_ERR })).join('\n');

  // ⛔ THE INSTRUMENT CHECK FIRST. If stdout alone already carried the cause then this fixture would
  // pass for a half-fix that only ever reads `run.out`, and the assertion below would prove nothing.
  assert.ok(!RUN_OUT.includes('Visual Studio'),
    'the fixture puts the cause on stdout too, so it cannot detect a driver that ignores run.err');

  assert.match(emitted, /Could not find any Visual Studio installation/,
    'the traced child said why it failed and the driver still dropped it — this is the bug');
  assert.match(emitted, /^ {4}\| /m,
    'the tail is not using the driver\'s `    | ` prefix, which the publisher and every sibling log share');
});

test('⭑ stderr is appended LAST, so a window of npm chatter cannot bury the cause', () => {
  // 30 lines of stdout noise against a 20-line window: only the stderr-last ordering reaches the
  // diagnosis. This is the one composition detail a plausible rewrite gets backwards.
  const emitted = runTail(capture({ stdout: RUN_OUT, stderr: RUN_ERR })).join('\n');
  assert.match(emitted, /npm ERR! code 1/, 'the tail did not reach the end of stderr');

  // ⛔ THE CONTROL, AND IT DISCRIMINATES RATHER THAN RESTATES: run the SAME functions with the
  // operands swapped. If err-then-out also surfaced the cause, the ordering would not be load-bearing
  // and this test would be decoration.
  const swapped = runTail(capture({ stdout: RUN_OUT, stderr: RUN_ERR }), {
    call: "emitFailureTail(readTracedLog(path.join(CAP, 'run.err')) + readTracedLog(path.join(CAP, 'run.out')));",
  }).join('\n');
  assert.doesNotMatch(swapped, /Visual Studio/,
    'reversing the concatenation still surfaced the cause, so this fixture does not test the ordering');
});

test('the excerpt is bounded on BOTH axes — 20 lines, and no single line of unbounded width', () => {
  // A driver.out is evidence, not an archive, and on Windows the long-line case is ordinary rather
  // than pathological: a node-gyp failure prints the whole MSBuild invocation as ONE line.
  const long = 'cl.exe /c /nologo '.repeat(1000);
  const emitted = runTail(capture({ stdout: Array.from({ length: 200 }, (_, i) => `line-${i}`).join('\n'), stderr: long }));
  assert.ok(emitted.length <= 20, `the tail emitted ${emitted.length} lines; the window is 20`);
  assert.ok(emitted.every((l) => l.length < 600),
    `a ${Math.max(...emitted.map((l) => l.length))}-char line reached driver.out — the width cap is gone`);
  assert.ok(emitted.some((l) => l.endsWith('…')), 'the over-wide line was dropped rather than truncated');
});

test('a capture that died before spawning stays a clean verdict, not a HARNESS-ERROR', () => {
  // `run.out`/`run.err` are absent whenever the traced process never started. Throwing here would
  // convert a classifiable BROKEN-WITHOUT-JAIL-TOO into an unclassifiable crash — trading one hole
  // for a worse one, on the very path this change exists to fix.
  assert.deepEqual(runTail(capture({})), [],
    'a capture with no run.* logs must emit nothing and must not throw');
  assert.deepEqual(runTail(capture({ stdout: '   \n\n  \n', stderr: '' })), [],
    'a whitespace-only log produced blank ` | ` lines instead of staying silent');
});

// ⛔ SCOPED TO THE REBUILD BLOCK, NEVER TO THE FILE — the lesson `fetch-diagnosis.test.mjs` records
// in its own header. Merely DEFINING `emitFailureTail` somewhere in the driver satisfies a file-wide
// search while the exit that needs it calls nothing, which is exactly the pre-fix state: the helper
// would exist, the 562 records would still say `rc=1`, and a file-wide assertion would be green.
test('the tail is wired into the rebuild exit itself, not merely defined somewhere in the driver', () => {
  const start = SRC.indexOf('if (meta.exitCode !== 0) {');
  assert.notEqual(start, -1, 'the unjailed-rebuild guard is gone — re-read the driver');
  const block = SRC.slice(start, SRC.indexOf('\n}', start));
  assert.match(block, /BROKEN-WITHOUT-JAIL-TOO \(unjailed rebuild/,
    'this is meant to be the unjailed-rebuild failure exit');
  assert.match(block, /emitFailureTail\(readTracedLog\(/,
    'the rebuild exit still publishes rc= and nothing else — the 562-record blind spot');
  assert.match(block, /run\.err/,
    'the exit reads only stdout; npm writes its diagnosis to stderr, so the cause is still dropped');
});
