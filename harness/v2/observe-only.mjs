// Re-decide the UNJAILED verdicts without the jail, because they never needed it.
//
// ⛔ THE OBSERVATION THAT UNBLOCKS THE RE-MEASURE. `BROKEN-WITHOUT-JAIL-TOO` is emitted at
// `measure.sh:477` (the fetch gate) and `:673` (the observe control), BOTH in the observe phase and
// both BEFORE any jailed verify arm runs. So the verdict on 1,481 of the 1,529 BROKEN-* records is
// decided entirely by npm: fetch with `--ignore-scripts`, then `npm rebuild`. nub is never invoked.
//
// ⛔ WHICH MEANS `falsify` DOES NOT GATE THEM, AND SHOULD NOT. The falsification control proves the
// harness can detect an UNDER-GRANTED jail arm. That is a property of the verify ladder, and a record
// whose verdict is decided before the ladder starts never exercises it. Blocking this population on
// that control is a real cost being paid for no coverage: the corpus runner has been refusing to
// start since 2026-08-17 over a `hugo-extended@0.141.0` case that concerns the jail, while 1,481
// npm-decided records sit unmeasured behind it.
//
// ⛔ AND THE LIMIT IS EXPLICIT, BECAUSE THIS FILE COULD OTHERWISE BE MISREAD AS A WAY AROUND THE
// GATE. It re-decides ONLY the observe verdict. It CANNOT produce a grant, a minimality, or any
// `MINIMUM`/`NO-STATE-PASSED`/`UNDER-PREDICTED` verdict — every one of those needs the jail and the
// falsification control that guards it. A run of this tool is a DISPOSITION LEDGER, not a corpus
// record, and it writes to its own file rather than `records-v2/`.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fetchArgs } from './era-resolution.mjs';
import { armPath, ambientTools } from './arm-path.mjs';
import { scriptScaffold } from './script-scaffold.mjs';
import { pythonForEra } from './era-python.mjs';

/** The verdict the observe phase would reach, from the two gates' own outcomes. */
export function observeVerdict({ fetchRc, rebuildRc, capped }) {
  if (capped) return 'HARNESS-TIMEOUT';
  if (fetchRc !== 0) return 'BROKEN-WITHOUT-JAIL-TOO';
  if (rebuildRc !== 0) return 'BROKEN-WITHOUT-JAIL-TOO';
  // ⛔ NOT `MINIMUM`. A clean observe says only that the package installs unjailed; what the jail
  // would have concluded is a different question this tool cannot answer.
  return 'INSTALLS-UNJAILED';
}

/** Disposition for a row whose recorded verdict is being revisited. */
export function disposition(previous, now) {
  if (previous === now) return 'CONFIRMED';
  if (now === 'INSTALLS-UNJAILED') return 'STALE-RECORD';
  if (now === 'HARNESS-TIMEOUT') return 'UNMEASURED-TIMEOUT';
  return 'CHANGED';
}

export { fetchArgs, armPath, ambientTools, scriptScaffold, pythonForEra, spawnSync, fs, path };
