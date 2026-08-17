// Every measurement driver's terminal path must consult the SHARED jail-off control.
//
// ⛔⛔ THIS IS THE STRUCTURAL FIX FOR A CLASS OF BUG, NOT A STYLE CHECK. The class: a driver reaches a
// verdict that names the jail without having asked whether the jail was the difference, or asks with a
// control that silently was not measuring what it claimed. Both have happened here, and neither
// produced an error — the first filed jail findings for packages nothing installs, and the second
// produced unanimous agreement, which reads as a confident exoneration.
//
// A per-driver copy is what let them drift: the control existed on Linux for weeks before macOS got it,
// macOS's copy then ran as root while every arm it was compared against ran as the user, and NONE of
// the three ever asserted that its own off-switch engaged. Sharing one module is the fix; this file is
// what keeps it shared, because the cheapest way to "fix" a future divergence is to paste the function
// back into one driver and adjust it there.
//
// ⛔ SOURCE-MATCHING IS THE RIGHT INSTRUMENT *HERE*, WHICH IS UNUSUAL IN THIS SUITE AND WORTH SAYING.
// The ladder suites deliberately EXECUTE their drivers because a grep cannot tell a ladder that fires
// from three literals sitting beside an unreachable loop. But those suites each stub the control out —
// they must, since the real one runs two installs — so no executing test can observe that a driver
// still calls the real thing. The absence this file guards is precisely the one the executing tests are
// blind to.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { OFF_SWITCH_CLAIM, VERDICT } from './unjailed-nub.mjs';

const HERE = import.meta.dirname;
const MODULE = 'unjailed-nub.mjs';

/** Every driver that measures a package, with how it reaches the shared module.
 *
 * `anchor` marks where the TERMINAL stage begins — the exact line that consumes the control's answer.
 *
 * ⛔ AN EXPLICIT ANCHOR, NOT A CLEVER REGEX, AND THE FIRST ATTEMPT PROVES WHY. Searching for "the first
 * mention of the module" put the boundary at the JS driver's IMPORT on line 37, which made the entire
 * file count as the terminal stage and flagged a legitimate fetch-stage verdict 1700 lines away. Each
 * driver also emits control-shaped verdicts from OTHER stages on their own authority, so a guard that
 * cannot tell the stages apart argues for deleting real code. If an anchor ever stops matching, the
 * INSTRUMENT test below fails loudly rather than silently widening the scope.
 */
const DRIVERS = [
  { file: 'measure.sh', how: 'cli', anchor: 'unjailed_nub_ok "$PKG" "$VER"' },
  { file: 'measure-macos.sh', how: 'cli', anchor: 'unjailed_nub_ok "$PKG" "$VER"' },
  { file: 'measure-windows.mjs', how: 'import', anchor: 'const NUB_ARM = unjailedNubOk();' },
];

const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

test('INSTRUMENT: every driver named here exists, and the module they share does too', () => {
  // A typo'd filename would make every assertion below vacuous — `read` would throw, but a future
  // refactor that turned these into a filtered glob would silently check nothing.
  for (const { file } of DRIVERS) {
    assert.ok(fs.existsSync(path.join(HERE, file)), `${file} is missing — this list is stale`);
  }
  assert.ok(fs.existsSync(path.join(HERE, MODULE)), `${MODULE} is missing`);
  assert.equal(DRIVERS.length, 3, 'three platforms are measured; a fourth driver must be added here');
  // ⛔ EVERY ANCHOR MUST STILL MATCH. An anchor that silently stopped matching would widen the terminal
  // stage to the whole file (flagging other stages' legitimate verdicts) or narrow it to nothing
  // (checking no code at all). The second failure is the dangerous one, so it is asserted here.
  for (const { file, anchor } of DRIVERS) {
    assert.ok(read(file).includes(anchor), `${file} no longer contains its terminal-stage anchor: ${anchor}`);
  }
});

test('⭑⭑ every driver reaches the SHARED control, never its own copy', () => {
  for (const { file, how } of DRIVERS) {
    const src = read(file);
    assert.match(src, new RegExp(MODULE.replace('.', '\\.')),
      `${file} does not reference ${MODULE} — a private copy of the control is how the three drifted apart`);
    if (how === 'import') {
      assert.match(src, new RegExp(`import\\s*{[^}]*}\\s*from\\s*'\\./${MODULE.replace('.', '\\.')}'`),
        `${file} is a JS driver and must IMPORT the module rather than shelling out to it`);
    }
  }
});

test('⭑⭑ no driver reimplements the off-switch assertion locally', () => {
  // ⛔ THE CLAIM STRING LIVES IN EXACTLY ONE PLACE. A driver that spells it out itself has a second
  // copy to keep in step with nub's actual output, and the failure mode of a stale copy is silent:
  // the assertion stops matching, every cell reports a broken off-switch, and the whole platform
  // floods with HARNESS-ERROR. The module exports it; a driver that needs it imports it.
  for (const { file } of DRIVERS) {
    assert.ok(
      !read(file).includes(OFF_SWITCH_CLAIM),
      `${file} hardcodes the off-switch claim — import it from ${MODULE} instead`,
    );
  }
});

test('⭑ no driver hardcodes a verdict the module owns, in the TERMINAL stage', () => {
  // The spellings the terminal control produces are the module's vocabulary. A driver echoing one
  // itself can drift from what `record.mjs` matches, and the symptom is a cell with NO verdict rather
  // than a wrong one — which reads as "the stage did not run" and gets re-queued forever.
  //
  // ⛔ SCOPED TO AFTER THE CONTROL CALL, BECAUSE THE SAME TOKEN IS EMITTED LEGITIMATELY ELSEWHERE. Each
  // driver also has a TOP-OF-FILE control, keyed on OBSERVE, which answers a different question with a
  // different program (`npm rebuild` on an already-materialised tree, versus a fresh `nub install`) and
  // reaches `BROKEN-WITHOUT-JAIL-TOO` on its own authority. A blanket ban on the string flagged two of
  // those and would have been "fixed" by deleting a real verdict — so the guard has to know which stage
  // it is looking at. Verified: the unscoped form fails on `measure.sh` for exactly that reason.
  //
  // HARNESS-ERROR and HARNESS-TIMEOUT are deliberately NOT checked at all: drivers emit those from many
  // unrelated places (a failed OSV screen, a dead tracer) and they are not this module's to own.
  const owned = [VERDICT.brokenUnjailedNub, VERDICT.brokenWithoutJailToo];
  for (const { file, anchor } of DRIVERS) {
    const src = read(file);
    const from = src.indexOf(anchor);
    assert.ok(from > 0, `${file} never calls the control, so there is no terminal stage to scope to`);
    const terminalStage = src.slice(from);
    for (const v of owned) {
      // A comment may name a verdict — documentation, not an emission. Only lines that PRINT one count,
      // since that is what `record.mjs` would read.
      const emits = terminalStage.split('\n').filter((l) => {
        const code = l.replace(/^\s*(#|\/\/).*$/, '');
        return new RegExp(`(echo|console\\.log)[^\\n]*=>[^\\n]*${v}`).test(code);
      });
      assert.deepEqual(emits, [], `${file} prints \`=> ${v}\` in its terminal stage; the module owns it`);
    }
  }
});

test('⭑ the shared control is consulted BEFORE the terminal verdict, in every driver', () => {
  // ⛔ ORDER IS THE WHOLE POINT OF THE ARM. A terminal verdict printed before the control has answered
  // names the jail on the strength of the ladder alone — the exact over-claim this stage exists to
  // prevent — and `record.mjs` takes the LAST `=>` in a log, so a verdict emitted afterwards would
  // also silently overwrite whatever the control concluded.
  for (const { file } of DRIVERS) {
    const src = read(file);
    const firstCall = src.search(new RegExp(`unjailed[_-]?[nN]ub[_-]?[oO]k|${MODULE.replace('.', '\\.')}`));
    assert.ok(firstCall > 0, `${file} never calls the control`);
    const terminal = src.indexOf(`=> ${VERDICT.noStatePassed}`);
    if (terminal >= 0) {
      assert.ok(terminal > firstCall,
        `${file} emits its terminal verdict before consulting the control`);
    }
  }
});
