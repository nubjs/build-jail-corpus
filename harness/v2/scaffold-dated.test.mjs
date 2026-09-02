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
import { npmInstall } from './scaffold-install.mjs';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');

// The install COMMAND each driver issues for the scaffold, as a single line.
const scaffoldLine = (src, marker) => {
  const at = src.indexOf(marker);
  assert.notEqual(at, -1, `the scaffold install site moved — this test is now checking nothing (${marker})`);
  return src.slice(at, at + 400);
};

// ⛔ THE SCAFFOLD INSTALL MOVED ON 2026-09-01 AND THIS TEST MOVED WITH IT, KEEPING ITS PURPOSE. The
// three drivers no longer each issue their own `npm install`; they hand the plan to
// `scaffold-install.mjs`, which applies it in recoverable batches. So the date now has to survive TWO
// hops rather than one — driver into the module's argv, then module into every npm invocation it makes
// — and both halves are asserted below. Dropping either restores exactly the omission this file exists
// for, and the second is the newly-reachable one: a bisect issues SEVERAL installs, so "the install is
// dated" stopped being a statement about a single command line.
test('the LINUX driver hands the era date to the scaffold installer', () => {
  const line = scaffoldLine(read('measure.sh'), 'scaffold-install.mjs" --observe "$OBS" --pkg "$PKG"');
  assert.match(line, /\$\{ERA_BEFORE:\+--before "\$ERA_BEFORE"\}/,
    'the linux scaffold install does not carry the date the fetch used');
});

test('the MACOS driver hands the era date to the scaffold installer', () => {
  const line = scaffoldLine(read('measure-macos.sh'), 'scaffold-install.mjs" --observe "$OBS" --pkg "$PKG"');
  assert.match(line, /\$\{ERA_BEFORE:\+--before "\$ERA_BEFORE"\}/,
    'the macos scaffold install does not carry the date the fetch used');
});

test('the WINDOWS driver reuses the fetch\'s own date', () => {
  const src = read('measure-windows.mjs');
  const at = src.indexOf("scaffold-install.mjs'), '--observe'");
  assert.notEqual(at, -1, 'the scaffold install site moved — this test is now checking nothing');
  const region = src.slice(at, at + 300);
  assert.match(region, /eraResolution\.before/,
    'the windows scaffold install does not carry the date the fetch used');
});

test('⛔ AND THE INSTALLER ITSELF DATES EVERY BATCH IT ISSUES', () => {
  // The second hop. A driver that passes `--before` to a module which drops it is the same silent
  // omission with one more layer of indirection — and it is invisible to a source scan of the drivers,
  // which is all this file could do before the module existed.
  const argvOf = (opts) => JSON.parse(npmInstall({
    specs: ['x@1'], cwd: here, env: process.env,
    npmArgv: [process.execPath, '-p', 'JSON.stringify(process.argv.slice(2))'], ...opts,
  }).out.trim());
  assert.ok(argvOf({ before: '2016-05-05T00:00:00.000Z' }).includes('--before=2016-05-05T00:00:00.000Z'),
    'a dated batch must carry --before');
  // ⛔ THE ONE DELIBERATE EXCEPTION, ASSERTED HERE SO IT CANNOT QUIETLY SPREAD. `UNDATED_TOOLS` is
  // undated because the dated artifact is a stub rather than a period-correct tool: `pulumi` at a 2018
  // date resolves 0.0.1, which ships no bin at all and leaves the arm at rc=127 exactly as if nothing
  // had been scaffolded. Measured — see `script-scaffold.mjs`.
  assert.ok(!argvOf({ before: '2016-05-05T00:00:00.000Z', dated: false }).some((a) => a.startsWith('--before')),
    'the undated tools tier must not be dated');
});

test('CONTROL: an UNDATED driver line would fail these checks', () => {
  // ⛔ THE ASSERTIONS ABOVE ARE `match`, WHICH PASSES ON ANY LINE CONTAINING THE PATTERN — so without
  // this, a rewrite that dropped the flag but left the marker string in a comment would read green.
  const undated = '"$HERE/scaffold-install.mjs" --observe "$OBS" --pkg "$PKG" > "$OBS/scaffold.log"';
  assert.doesNotMatch(undated, /\$\{ERA_BEFORE:\+--before "\$ERA_BEFORE"\}/);
  assert.doesNotMatch("run(NODE, [path.join(HERE, 'scaffold-install.mjs'), '--observe', OBS]", /eraResolution\.before/);
});

test('every driver dates its package FETCH too — the rule these three are instances of', () => {
  assert.match(read('measure.sh'), /--ignore-scripts \$\{ERA_BEFORE:\+"\$ERA_BEFORE"\} "\$PKG@\$VER"/);
  assert.match(read('measure-macos.sh'), /--ignore-scripts \$\{ERA_BEFORE:\+"\$ERA_BEFORE"\} "\$PKG@\$VER"/);
  assert.match(read('measure-windows.mjs'), /eraResolution\.args/);
});
