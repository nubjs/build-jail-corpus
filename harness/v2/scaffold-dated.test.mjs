// ⛔⛔ EVERY INSTALL AN ARM MAKES CARRIES THE ERA DATE, NOT JUST THE FETCH. This rule has now been
// broken three separate times in this harness, each time in a SECOND install that someone added
// after the fetch already had `--before`:
//
//   * the observe lane's scaffold — fixed, and `observe-only.mjs:330` records the cost verbatim:
//     "without `--before` this pulled TODAY's `typings`, `flow-typed` and `webdriver-manager` into a
//     tree pinned to 2016, and the era Node then could not parse them";
//   * all three drivers' npm REFERENCE arm — fixed in epoch 4;
//   * all three drivers' SCAFFOLD install — fixed here, in epoch 5.
//
// The failure is silent and it is attributed to the PACKAGE: modern JavaScript reaches an era Node,
// which throws `Unexpected token`, the arm exits non-zero and the driver records
// `BROKEN-WITHOUT-JAIL-TOO` — a claim that nothing installs the package. MEASURED on the retained
// darwin driver logs when this was found: 178 of 282 such records carry `Unexpected token`.
//
// So this test reads the driver SOURCES rather than any one behaviour. A source test is the right
// shape precisely because the bug is an omission — there is no failing run to catch, only a missing
// argument, and the next person to add an install will not read this file unless it goes red.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');

// The install COMMAND each driver issues for the scaffold, as a single line.
const scaffoldLine = (src, marker) => {
  const at = src.indexOf(marker);
  assert.notEqual(at, -1, `the scaffold install site moved — this test is now checking nothing (${marker})`);
  return src.slice(at, at + 400);
};

test('the LINUX scaffold install is dated', () => {
  const line = scaffoldLine(read('measure.sh'), 'npm install --no-audit --no-fund --ignore-scripts ${ERA_BEFORE:+"$ERA_BEFORE"} $ARM_SCAFFOLD');
  assert.match(line, /\$\{ERA_BEFORE:\+"\$ERA_BEFORE"\}/);
});

test('the MACOS scaffold install is dated', () => {
  const line = scaffoldLine(read('measure-macos.sh'), '--ignore-scripts ${ERA_BEFORE:+"$ERA_BEFORE"} $ARM_SCAFFOLD');
  assert.match(line, /\$\{ERA_BEFORE:\+"\$ERA_BEFORE"\}/);
});

test('the WINDOWS scaffold install reuses the fetch\'s own date', () => {
  const src = read('measure-windows.mjs');
  const at = src.indexOf('...scaffold]');
  assert.notEqual(at, -1, 'the scaffold install site moved');
  const region = src.slice(Math.max(0, at - 400), at + 40);
  assert.match(region, /eraResolution\.before/,
    'the windows scaffold install does not carry the date the fetch used');
});

test('CONTROL: an UNDATED install line would fail these checks', () => {
  // ⛔ THE ASSERTION ABOVE IS `match`, WHICH PASSES ON ANY LINE CONTAINING THE PATTERN — so without
  // this, a rewrite that dropped the flag but left the marker string in a comment would read green.
  const undated = 'npm install --no-audit --no-fund --ignore-scripts $ARM_SCAFFOLD > "$OBS/scaffold.log"';
  assert.doesNotMatch(undated, /\$\{ERA_BEFORE:\+"\$ERA_BEFORE"\}/);
  assert.doesNotMatch('run(NODE, [NPM, "install", ...scaffold]', /eraResolution\.before/);
});

test('every driver dates its package FETCH too — the rule these three are instances of', () => {
  assert.match(read('measure.sh'), /--ignore-scripts \$\{ERA_BEFORE:\+"\$ERA_BEFORE"\} "\$PKG@\$VER"/);
  assert.match(read('measure-macos.sh'), /--ignore-scripts \$\{ERA_BEFORE:\+"\$ERA_BEFORE"\} "\$PKG@\$VER"/);
  assert.match(read('measure-windows.mjs'), /eraResolution\.args/);
});
