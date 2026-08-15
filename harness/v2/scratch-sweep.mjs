// May the driver's scratch root be deleted yet?
//
// ⛔ THIS EXISTS BECAUSE A LONG SLICE FILLS THE DISK AND DIES MID-RUN. MEASURED: `measure.sh` creates
// `ROOT="$(mktemp -d "$HOME/v2-XXXXXX")"` per invocation and never removes it — no `trap`, no cleanup —
// and `run-batch-v2.mjs` did not remove it either. A descent runs ~9 arms per package, each root
// holding a full npm cache and node_modules, so **75 packages left 658 roots and 193 GB**, and both
// lanes of a 25% linux run died `ENOSPC: no space left on device`.
//
// It is a separate module because the decision is an `rm -rf` on a path parsed out of a subprocess's
// stdout, and every condition below is load-bearing. Inline in the batch loop it would be untestable:
// that file runs its whole sweep at import.

import path from 'node:path';

/** Decide whether `log`'s driver scratch root may be swept, and say why not when it may not.
 *
 *  Returns `{ root, sweep, reason }`. `root` is null when the log carries no header.
 *
 *  ⛔ WHY NOT IN THE DRIVER, WHICH IS THE OBVIOUS PLACE. A `trap ... rm -rf "$ROOT"` in `measure.sh`
 *  would silently break `falsify.mjs`: it parses the root out of the same header and reads
 *  `verify-at-grant/{i,a}.log` from it AFTER the driver has exited. With no logs, `refusalSeen` and
 *  `scriptRan` are both false, and it reports refusal failures about arms that were fine. Only the
 *  batch runner knows the root's real end of life — `record.mjs` has returned and the record is read.
 *
 *  ⛔ AND NEVER BEFORE THE ARTIFACT OF RECORD IS OUT. `record.mjs` copies `trace.txt.gz` and
 *  `capture.json` into the record directory and notes `*-copy-failed` when it cannot. The raw trace is
 *  the ARCHIVE — with it a decoder bug is a re-parse, without it a permanent invisible hole, and this
 *  corpus has already measured two such decoder losses. So a root whose copy failed is KEPT, trading
 *  disk for evidence: a full disk stops the run LOUDLY, a lost archive does not stop it at all.
 */
/*  ⛔ `p` IS INJECTABLE BECAUSE A WINDOWS PATH IS UNPARSEABLE BY POSIX `path`, AND THAT SILENTLY
 *  DISABLES THE SWEEP RATHER THAN BREAKING IT. `path.isAbsolute('C:\\jail\\m-x')` is FALSE on POSIX and
 *  `basename` returns the whole string, so a win32 root evaluated with POSIX semantics is refused as
 *  "not shaped like a driver root" — the disk then fills exactly as before, with no error anywhere. In
 *  production this is always the driver's own platform and the default is right; the seam exists so the
 *  win32 shape can be asserted from a POSIX test host, the same way `provision-node-matrix.mjs` takes a
 *  `platform` for the flat-vs-`bin` archive difference. */
export function sweepDecision({ log = '', notes = [], runs = '', keepRoots = false, p = path } = {}) {
  // All three drivers print `### <pkg>@<ver>   (<root>)`; `measure-macos.sh` appends ` nub=<path>`,
  // which is why the root group is not anchored to end-of-line. Anchoring it made `root` null on
  // darwin in falsify.mjs and fabricated alarms there — the same parse, the same trap.
  const root = /^###\s+\S+\s+\((\S+)\)/m.exec(log)?.[1] ?? null;
  if (keepRoots) return { root, sweep: false, reason: 'keep-roots requested' };
  if (!root) return { root: null, sweep: false, reason: 'no driver header, so no known root' };
  if (notes.some((n) => String(n).endsWith('-copy-failed'))) {
    return { root, sweep: false, reason: 'an artifact copy failed, so this root is the only evidence' };
  }
  // A blast-radius guard, not a formality. Every driver names its root `v2-<rand>` (POSIX) or
  // `m-<pkg>-<rand>` (win32); anything else is not a root and is not ours to delete. A relative path
  // would resolve against whatever cwd the caller happens to hold, so absolute is required too.
  if (!p.isAbsolute(root) || !/^(v2-|m-)/.test(p.basename(root))) {
    return { root, sweep: false, reason: 'not shaped like a driver scratch root' };
  }
  // ⛔ AND NEVER A DIRECTORY CONTAINING THE RECORDS. Cheap, and the one mistake that would delete the
  // run's own output rather than its garbage.
  if (runs && p.resolve(runs).startsWith(p.resolve(root) + p.sep)) {
    return { root, sweep: false, reason: 'the records tree lives inside it' };
  }
  return { root, sweep: true, reason: 'record written and artifacts copied' };
}
