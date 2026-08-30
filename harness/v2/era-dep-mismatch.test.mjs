// ⛔⛔ AN ARM THAT RAN A DEPENDENCY ITS ERA NODE CANNOT PARSE IS NOT EVIDENCE THE PACKAGE IS DEAD.
//
// The harness dates the npm arms with `--before`; NO `nub install` is dated, and nub has no
// equivalent to pass (`minimumReleaseAge` is a floor on age, not a ceiling on publish date). So every
// nub arm resolves TODAY's dependency versions into a tree running an era Node.
//
// MEASURED on `electron-prebuilt@0.28.3` (run 33319235832): the era-dated npm OBSERVE arm resolved
// 108 packages and installed cleanly on Node 4.9.1; every nub arm resolved 146 and every one failed,
// because `psl@1.15.0` throws `SyntaxError: Unexpected token ...` under Node 4. The record says
// BROKEN-WITHOUT-JAIL-TOO -- "nothing installs this" -- about a package that installs fine.
//
// The detector changes no verdict. It makes the class COUNTABLE on the record, for the 3900 macOS and
// windows rows still ahead, where the same old-package population will hit the same wall.
//
// ⛔ THE FIXTURES ARE THE REAL MEASURED SHAPES, and the counts below are pinned to a hand measurement
// over all 733 committed driver logs: 18 carry the warning, 39 carry a dependency-store SyntaxError
// (33 BROKEN-WITHOUT-JAIL-TOO + 6 MINIMUM), 78 carry the toolchain one. An earlier version of this
// detector conflated the two SyntaxError classes and fired on 75 MINIMUM against a hand count of 6 --
// a filter producing a surprising split is more likely broken than insightful, and it was.
import assert from 'node:assert/strict';
import test from 'node:test';
import { detectEraDepMismatch, parseDriverLog } from './record.mjs';

// Verbatim from the electron-prebuilt@0.28.3 driver log, echo prefixes included: the evidence lives
// in the `    | ` lines that `parseDriverLog` strips, which is why the detector reads the RAW log.
const DEPENDENCY = [
  '  ERA-NODE PINNED 4.9.1 (provisioned) (arms will run: v4.9.1)',
  '    | warn:   punycode@2.3.1: wanted node >=6, got 4.9.1',
  '    | warn:   request@2.88.2: wanted node >= 6, got 4.9.1',
  '    | /home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec0a830a560da/node_modules/psl/dist/psl.cjs:1',
  '    | (function (exports, require, module) { "use strict"; ... }',
  '    | SyntaxError: Unexpected token ...',
  '  => BROKEN-WITHOUT-JAIL-TOO',
].join('\n');

// From `cldr-data@26.0.9` (darwin): the runner's OWN npm, out of the hosted toolcache, under era
// Node 4. A different defect, and folding it in made the dependency count useless.
const TOOLCHAIN = [
  '        /Users/runner/hostedtoolcache/node/22.23.2/arm64/lib/node_modules/npm/lib/cli.js:2',
  "          const { enableCompileCache } = require('node:module')",
  '        SyntaxError: Unexpected token {',
].join('\n');

test('a modern dependency under an era Node is detected, and named', () => {
  const d = detectEraDepMismatch(DEPENDENCY);
  assert.ok(d, 'the measured shape was not detected at all');
  assert.deepEqual(d.warned.map((w) => w.spec), ['punycode@2.3.1', 'request@2.88.2'],
    'both engine warnings must be captured — the spacing differs between them (`>=6` and `>= 6`)');
  assert.equal(d.warned[0].wantsMajor, 6);
  assert.equal(d.warned[0].got, '4.9.1');
  assert.match(d.storeSyntaxError, /psl\.cjs$/, 'the failing dependency file must be named');
  assert.equal(d.toolchainSyntaxError, null, 'a dependency failure was misfiled as a toolchain one');
});

test('a full-semver engine bound is caught, not just a bare major', () => {
  // `wanted node >=16.20.0` was silently dropped by a `(\d+),` pattern. Found only because a loose
  // hand count over the corpus said 18 and the structured one said 17.
  const d = detectEraDepMismatch('    | warn:   typescript@7.0.2: wanted node >=16.20.0, got 14.21.3');
  assert.ok(d, 'a semver engine bound went undetected');
  assert.equal(d.warned[0].wantsMajor, 16);
  assert.equal(d.warned[0].got, '14.21.3');
});

test('the runner\'s own npm failing under an era Node is a DIFFERENT class', () => {
  const d = detectEraDepMismatch(TOOLCHAIN);
  assert.ok(d, 'the toolchain shape was not detected');
  assert.match(d.toolchainSyntaxError, /node_modules\/npm\/lib\/cli\.js$/);
  assert.equal(d.storeSyntaxError, null,
    'the runner\'s npm was counted as a package dependency — that conflation fired on 75 MINIMUM '
    + 'records against a hand count of 6');
});

test('a clean log detects nothing, and a SyntaxError alone is not enough', () => {
  assert.equal(detectEraDepMismatch('  OBSERVE   rc=0 files=1182\n  => MINIMUM'), null,
    'a clean log must not report a mismatch, or every record carries a false marker');
  // The negative control that keeps it honest: the SyntaxError must be tied to a LOADED FILE. A
  // package that merely prints those words is not evidence of anything.
  assert.equal(detectEraDepMismatch('  | echo: SyntaxError: Unexpected token from a test fixture'), null,
    'a bare SyntaxError string with no module path was read as an era mismatch');
});

test('the field reaches the parsed record, computed from the RAW log', () => {
  // `parseDriverLog` strips `    | ` lines before parsing verdicts. If the detector ran on the
  // filtered lines it would see nothing at all, so this pins WHICH input it reads.
  const parsed = parseDriverLog(DEPENDENCY);
  assert.ok(parsed.eraDepMismatch, 'the detector ran on the filtered lines, where the evidence is gone');
  assert.equal(parsed.verdict, 'BROKEN-WITHOUT-JAIL-TOO', 'the verdict must be unaffected by the detector');
});
