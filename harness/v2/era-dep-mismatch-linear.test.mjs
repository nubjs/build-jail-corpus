// ⛔⛔ THE DETECTOR RUNS ON EVERY RECORD, SO A BACKTRACKING REGEX IN IT IS A MEASUREMENT HAZARD,
// NOT A PERFORMANCE NIT.
//
// Epoch 40 shipped `/(\S*\/\S+\.(?:c|m)?js):\d+/g` to find the file paths Node prints above a parse
// error. Two unbounded `\S` quantifiers ahead of a literal suffix means that on a whitespace-free run
// containing NO match, the engine tries every split of that run.
//
// MEASURED on the committed log for `@vscode+windows-process-tree@0.8.0` (darwin-arm64, 25 KB):
// that pattern took **5,556 ms and returned ZERO matches**, while the engine-warning regex sitting
// beside it in the same function took 0.3 ms. The trigger is a 5,532-character token with no
// whitespace anywhere in it — a node-gyp `.deps` line listing every include path — so the cost is
// superlinear in that token, and EVERY native-build package emits one. Over 817 real logs the
// detector averaged 52 ms of pure backtracking apiece.
//
// Why that is a correctness problem and not a speed one: `run-batch-v2.mjs` gives `record.mjs` a
// 120-second budget, and the growth is CUBIC — measured on this fixture's own shape, 1,500 chars
// costs 228 ms, 2,000 costs 537 ms, 3,000 costs 1,805 ms and 4,000 costs 4,273 ms, i.e. doubling the
// token multiplies the cost by eight. That is a path from "this package uses node-gyp" to a
// HARNESS-TIMEOUT on a measurement that was otherwise fine — the instrument corrupting the result.
//
// The guard is a BUDGET plus a NEGATIVE CONTROL, and the control is the load-bearing half: it runs
// the epoch-40 pattern on the same fixture and requires it to blow the budget. Without that, a test
// asserting "the new one is fast" passes just as happily against a fixture too small to exercise
// anything — which is precisely how a performance test comes to assert nothing at all.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectEraDepMismatch } from './record.mjs';

/// The epoch-40 pattern, verbatim. Kept here as the control arm rather than described in prose,
/// because the whole point is to EXECUTE the defect rather than assert a string is absent.
const EPOCH_40_PATTERN = /(\S*\/\S+\.(?:c|m)?js):\d+/g;

/// A node-gyp `.deps` line: one enormous token with no whitespace and no `.js:<line>` in it. This is
/// the real shape, reduced — the measured one was 5,532 characters.
const gypDepsToken = (chars) => {
  let s = '';
  while (s.length < chars) s += '"./Release/.deps/Release/obj.target/../../node-addon-api",';
  return s.slice(0, chars);
};

const ms = (fn) => {
  const t = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t) / 1e6;
};

test('a long whitespace-free token with no match costs the detector nothing', () => {
  // A SyntaxError is present so the path scan actually runs — without it the caller short-circuits
  // and the test would pass by never reaching the code it exists to guard.
  const log = [
    '  ERA-NODE PINNED 4.9.1 (provisioned)',
    `    | gyp info deps ${gypDepsToken(2500)}`,
    '    | SyntaxError: Unexpected token ...',
  ].join('\n');

  const control = ms(() => { EPOCH_40_PATTERN.lastIndex = 0; [...log.matchAll(EPOCH_40_PATTERN)]; });
  const actual = ms(() => detectEraDepMismatch(log));

  // ⛔ THE CONTROL FIRST. If the epoch-40 pattern is fast on this fixture then the fixture is too
  // small and every other assertion here is vacuous — so fail, and say to grow the token.
  assert.ok(control > 300,
    `the control pattern took only ${control.toFixed(0)}ms on a 2,500-char token, so this fixture `
    + 'no longer exercises the blowup — grow gypDepsToken until it does, or this test asserts nothing');
  assert.ok(actual < 100,
    `the detector took ${actual.toFixed(0)}ms on a token the old pattern needed ${control.toFixed(0)}ms `
    + 'for; the path scan backtracks again');
});

test('the path scan still finds what it is for, and still rejects a bare filename', () => {
  // Both real shapes, from the measured logs: a store path (the dependency class) and a hostedtoolcache
  // path (the toolchain class), each printed by Node with trailing source and the error.
  const dep = [
    '    | /home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec0a830a560da/node_modules/psl/dist/psl.cjs:1',
    '    | SyntaxError: Unexpected token ...',
  ].join('\n');
  assert.equal(detectEraDepMismatch(dep).storeSyntaxError,
    '/home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec0a830a560da/node_modules/psl/dist/psl.cjs');

  const tool = [
    '        /Users/runner/hostedtoolcache/node/22.23.2/arm64/lib/node_modules/npm/lib/cli.js:2',
    '        SyntaxError: Unexpected token {',
  ].join('\n');
  assert.equal(detectEraDepMismatch(tool).toolchainSyntaxError,
    '/Users/runner/hostedtoolcache/node/22.23.2/arm64/lib/node_modules/npm/lib/cli.js');

  // A filename with no directory is not a load path — it is prose, or a package's own output — and
  // classifying it would put a record in a class on the strength of a word.
  const bare = 'index.js:1\nSyntaxError: Unexpected token ...';
  assert.equal(detectEraDepMismatch(bare), null,
    'a bare filename with no `/` was treated as a load path');
});

test('a path is found even when the line carries other text before it', () => {
  // The drivers prefix package output with `    | `, and Node itself indents stack frames — so the
  // path is never at column 0. Walking back to WHITESPACE rather than to the start of the line is
  // what makes that work, and it is the part a naive anchored pattern gets wrong.
  //
  // ⛔ THE LEADING `(` IS KEPT, AND THAT IS DELIBERATE — it is what the epoch-40 pattern did too
  // (`\S*` happily consumed it), and the two classifiers test for `/store/` and `hostedtoolcache`
  // as SUBSTRINGS, so a delimiter on the front changes no verdict. Pinning it here rather than
  // trimming it keeps this change a pure performance fix with byte-identical output, which is the
  // only reason it can land on a live corpus without re-measuring anything.
  const log = [
    '    | at require (/home/runner/.cache/nub/pm/store/x@1.0.0-abc/node_modules/x/index.mjs:7)',
    '    | SyntaxError: Unexpected token ...',
  ].join('\n');
  assert.equal(detectEraDepMismatch(log).storeSyntaxError,
    '(/home/runner/.cache/nub/pm/store/x@1.0.0-abc/node_modules/x/index.mjs');
});
