// The ONE place that knows how to INVOKE a platform's measurement driver.
//
// ⛔ THIS EXISTS BECAUSE THE KNOWLEDGE WAS COPIED THREE TIMES AND TWO COPIES WERE WRONG.
//
// `run-batch-v2.mjs` has always invoked the darwin driver as `sudo -E bash`. `falsify.mjs` invoked
// the same driver as plain `bash`, so on darwin it could never run at all — and reported that as
// "the harness cannot detect a bad grant", an instrument failure wearing the costume of the finding
// the instrument exists to make. `e2e.mjs` then landed a THIRD copy with the same omission; its
// `── DIRECT:` banner check caught it and reported `unavailable`, which is safe, but darwin's
// collated-catalog round trip would have silently never run — the exact thing wiring darwin was for.
//
// Both wrong copies were written while the correct one sat in a sibling file. The e2e copy was even
// added under a comment observing that three copies already existed and choosing to add a fourth.
// So the fix is not a fourth correction; it is deleting the duplication.
//
// ⛔ WHAT THIS DOES NOT OWN, deliberately: whether a driver SUPPORTS a given mode. Invocation and
// capability are different questions, and `e2e.mjs` answers the second by requiring the driver to
// PRINT its `── DIRECT:` banner rather than by consulting any list — because a list of capabilities
// is the same kind of second copy, and a driver that accepts a flag and ignores it satisfies a list
// while satisfying nothing else. Ask the run, not the table.

import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** How to run the measurement driver on `platform`: `{ file, cmd, pre }`.
 *
 *  `cmd` plus `pre` plus `file` is the argv prefix; callers append the driver's own arguments.
 *
 *  ⛔ `sudo -E` ON DARWIN, AND THE `-E` IS LOAD-BEARING. dtrace needs uid 0, and the driver reads
 *  `SUDO_USER` to drop every measured process back to the invoking user — but it also needs the
 *  ambient PATH to find npm, which a bare `sudo` strips. Dropping either half is silent: without
 *  `sudo` the driver dies with `DTrace requires additional privileges` in ~3s and emits no verdict
 *  line, which every caller's parser reports as its own domain failure rather than as "it never ran".
 */
export function driverInvocation(platform = process.platform) {
  if (platform === 'win32') {
    return { file: path.join(HERE, 'measure-windows.mjs'), cmd: process.execPath, pre: [] };
  }
  if (platform === 'darwin') {
    return { file: path.join(HERE, 'measure-macos.sh'), cmd: 'sudo', pre: ['-E', 'bash'] };
  }
  return { file: path.join(HERE, 'measure.sh'), cmd: 'bash', pre: [] };
}

/** The full argv prefix — `[...pre, file]` — for spawning with `cmd`. */
export function driverArgv(platform = process.platform) {
  const { file, pre } = driverInvocation(platform);
  return [...pre, file];
}
