// The win32 jail-off control must hold the same toolchain as the arm it is compared against.
//
// That arm decides BROKEN-UNJAILED-NUB ("npm installs this, nub cannot") against
// BROKEN-WITHOUT-JAIL-TOO ("nothing installs this"), purely by comparison with the npm reference.
// So if the control runs nub's lifecycle scripts on a DIFFERENT Node or Python from the one npm
// gets, a toolchain difference alone is recorded as a nub install defect -- the exact failure
// epoch 4 (npm reference), epoch 13 (era Python) and epoch 15 (era PATH) each fixed on one arm.
//
// win32 was left out of all three because `measure-windows.mjs` has its OWN `unjailedNubOk` rather
// than calling `unjailed-nub.mjs`'s. Epoch 15's reason states it outright: "WIN32 IS NOT FIXED ...
// runs its control in-process from imported classify/offSwitchEngaged and never calls this module".
// Every other arm in that driver -- the OBSERVE/npm reference and every verify rung -- already
// passes `PATH: ARM_PATH` with the era `PYTHON`.
//
// This matters more on win32 than anywhere else: 45 of the 62 `write:"disk"` grants in the catalog
// rest on a win32 record ALONE, so the widest capability the jail grants was justified by the
// platform least able to tell "the jail blocked it" from "nub cannot install it here".
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const DRIVER = path.join(import.meta.dirname, 'measure-windows.mjs');

/// The body of the driver's `unjailedNubOk`, from its declaration to the first line that closes it
/// at column zero. Scoped deliberately: the driver spawns nub in many places and only the control
/// arm is under test here.
function controlBody() {
  const src = fs.readFileSync(DRIVER, 'utf8').split('\n');
  const start = src.findIndex((l) => l.startsWith('const unjailedNubOk = '));
  assert.notEqual(start, -1, 'measure-windows.mjs no longer declares its own unjailedNubOk');
  const end = src.findIndex((l, i) => i > start && l === '};');
  assert.notEqual(end, -1, 'could not find the end of unjailedNubOk');
  return src.slice(start, end + 1).join('\n');
}

test('the control still spawns nub, so the assertions below are not vacuous', () => {
  // A known-answer control. If the driver stops spawning nub here, every env assertion passes
  // trivially -- which is precisely how a guard silently becomes decoration.
  const body = controlBody();
  // TWO call sites, THREE runtime spawns: the resolve is its own call, while install and
  // approve-builds share one call inside a two-entry loop. Asserting three here fails on correct
  // code -- which is what this control caught when it was first written.
  const spawns = body.match(/run\(NUB,/g) ?? [];
  assert.ok(spawns.length >= 2,
    `expected the control's resolve call and its install/approve loop, found ${spawns.length}`);
});

test('every nub spawn in the control carries an explicit env', () => {
  for (const line of controlBody().split('\n')) {
    if (!line.includes('run(NUB,')) continue;
    assert.match(line, /\benv:/,
      `a nub spawn with no env inherits the RUNNER's Node and Python, so a toolchain difference `
        + `alone becomes a recorded nub defect. Offending line: ${line.trim()}`);
  }
});

test('that env is the era toolchain, not an arbitrary one', () => {
  const body = controlBody();
  assert.match(body, /PATH:\s*ARM_PATH/,
    'the control must run on ARM_PATH, the same era PATH the npm reference and verify rungs use');
  assert.match(body, /ERA_PYTHON\s*\?\s*\{\s*PYTHON:\s*ERA_PYTHON\s*\}/,
    'the era PYTHON rides the same env vector as PATH -- omitting it is the epoch-13 defect');
});
