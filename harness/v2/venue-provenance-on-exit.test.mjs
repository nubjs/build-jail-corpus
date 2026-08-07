// Every early exit must still name the binary that produced the record.
//
// ⛔ WHY THIS IS A SOURCE GUARD AND NOT AN EXECUTION TEST. `measure-windows.mjs` needs ETW and a
// real Windows kernel; it cannot be driven to its `BROKEN-WITHOUT-JAIL-TOO` branch on any other
// platform, and this repo's other Windows guards are source-shaped for the same reason. The
// behavioural confirmation is a live re-measure on the VM, recorded in the task list — this file
// exists so a THIRD early exit added later cannot silently reintroduce the gap.
//
// ⛔ WHAT WENT WRONG. The `VENUE-NUB-BINARY` marker was emitted from an inline block near the end of
// the driver, which is AFTER both `BROKEN-WITHOUT-JAIL-TOO` exits. MEASURED on win32 shakeout round
// 1: `react-signature-pad-wrapper@1.3.1` and `@intlify/vue-router-bridge@0.1.0` carry `nubGitSha:
// null` and no `nubBinary` key at all, while the control `ref-napi@3.0.3` (MINIMUM, full path)
// carries a full sha256. Two of ten records could not say what produced them.
//
// ⛔ AND IT IS THIS VERDICT WHERE ATTRIBUTION MATTERS MOST. `BROKEN-WITHOUT-JAIL-TOO` claims "nub
// cannot build this at all" — true only of a PARTICULAR binary. `ctrlc-windows@0.1.9` sat in that
// bucket until the tarball symlink fix and installs cleanly after it. The records most likely to
// flip on a fix were exactly the ones least able to name the binary they were taken on.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const HERE = import.meta.dirname;
const SRC = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');

/**
 * For each `BROKEN-WITHOUT-JAIL-TOO` announcement, return whether the driver names the binary
 * before the `process.exit` that follows it. Deliberately generic: it finds the exits by the
 * verdict string rather than by line number, so a new one is covered the day it is written.
 */
function exitsThatNameTheBinary(src) {
  const lines = src.split('\n');
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/=> BROKEN-WITHOUT-JAIL-TOO/.test(lines[i])) continue;
    // The exit is on this line or within the next few; scan until we hit it.
    let names = /emitBinaryProvenance\(\)/.test(lines[i]);
    let found = /process\.exit\(/.test(lines[i]);
    for (let j = i + 1; j < Math.min(i + 6, lines.length) && !found; j++) {
      if (/emitBinaryProvenance\(\)/.test(lines[j])) names = true;
      if (/process\.exit\(/.test(lines[j])) found = true;
    }
    out.push({ line: i + 1, names, found });
  }
  return out;
}

test('the guard finds the exits at all — otherwise every assertion below is vacuous', () => {
  const found = exitsThatNameTheBinary(SRC);
  assert.ok(found.length >= 2,
    `expected at least the two known BROKEN-WITHOUT-JAIL-TOO exits, found ${found.length}`);
  assert.ok(found.every((e) => e.found), 'a verdict announcement with no process.exit near it — re-read the scanner');
});

test('⭑ every BROKEN-WITHOUT-JAIL-TOO exit names the binary before exiting', () => {
  const bad = exitsThatNameTheBinary(SRC).filter((e) => !e.names);
  assert.deepEqual(bad, [],
    `these early exits publish a record that cannot say which binary produced it (lines ${bad.map((e) => e.line).join(', ')}). `
    + 'Call emitBinaryProvenance() before process.exit().');
});

test('the emitter is idempotent, so the normal path does not print the marker twice', () => {
  // A duplicate marker would make `record.mjs` parse two conflicting provenance lines. The flag
  // lives ON THE FUNCTION rather than in a sibling `let` — see the note at the definition.
  assert.match(SRC, /function emitBinaryProvenance\(\)\s*\{\s*\n\s*if \(emitBinaryProvenance\.done\) return;/,
    'the once-guard is missing or was rewritten as a module-scope binding');
  assert.doesNotMatch(SRC, /^let venueBinaryEmitted/m,
    'a module-scope `let` guard is in the temporal dead zone at the early call sites and would throw there');
});

test('CONTROL: the pre-fix shape FAILS the predicate, so the guard can go red', () => {
  // Without this, the assertions above would keep passing if the calls were deleted tomorrow.
  const preFix = [
    'if (fetch.status !== 0) {',
    '  console.log(`  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed`);',
    '  process.exit(0);',
    '}',
  ].join('\n');
  const found = exitsThatNameTheBinary(preFix);
  assert.equal(found.length, 1, 'the control snippet should contain exactly one exit');
  assert.equal(found[0].names, false,
    'the predicate reports the pre-fix shape as compliant — it cannot detect what it exists to detect');
});
