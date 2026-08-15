// Did the measurement driver report hitting ITS OWN deadline?
//
// ⛔ THIS EXISTS BECAUSE A DRIVER TIMEOUT WAS BEING READ AS A FAILED GRANT, AND THAT MISDIAGNOSIS
// BLOCKED AN ENTIRE PLATFORM'S SWEEP. There are TWO deadlines over every arm and they are enforced by
// different processes:
//
//   falsify.mjs   `--budget`       900 s   spawnSync's own timeout -> r.error.code === 'ETIMEDOUT'
//   the driver     `--arm-timeout`  600 s   applied per phase INSIDE measure-windows.mjs
//
// Only the first is visible to a caller as a timeout. When the driver's own deadline fires it prints a
// TIMED-OUT line and exits NORMALLY, so spawnSync sees a clean child and the caller's `timedOut` stays
// false. The arm then has no `rc=` to parse, reads as UNPARSED, and a caller that equates
// "no verdict" with "the grant did not install" reports a failure the run never established.
//
// MEASURED 2026-08-15: `mozjpeg@6.0.1`'s known-SUFFICIENT control arm hit the 600 s install deadline
// on win32. Arms ran 752 s and 790 s (a ~150 s safe-resolve plus the 600 s cut), the driver printed
//   VERIFY[at-grant] TIMED-OUT in `install` after 600000 ms -- no verdict
// and `falsify.mjs` announced "CONTROL FAILED: the known-sufficient grant did NOT install", refusing
// to start every win32 lane of the 25% run. Nothing was wrong with the grant, the jail, or the record.
//
// The driver states the rule itself, at `measure-windows.mjs:186`: "TIMED-OUT is recorded as its own
// verdict -- it is NOT a failure, and must never be read as one: a failure says the grant was
// insufficient, a timeout says nothing about the grant."

/** True when `out` carries a driver-reported timeout, i.e. the driver hit its own `--arm-timeout`.
 *
 *  ⛔ THERE ARE SIX EMISSION SITES IN FIVE SHAPES, AND MY FIRST PATTERN COVERED TWO OF THEM. I wrote it
 *  against the two lines I had in hand and it passed its tests, because the DIRECT-mode output happens
 *  to print a matching line and a non-matching one together. The full set in `measure-windows.mjs`:
 *
 *    1335  => TIMED-OUT in safe Nub resolution after <n> ms -- no lifecycle script ran
 *    1361  VERIFY[<label>] TIMED-OUT in `install` after <n> ms -- no verdict; check for surviving children
 *    1367  VERIFY[<label>] TIMED-OUT in `approve-builds` after <n> ms -- no verdict; ...
 *    1481  => TIMED-OUT (<stage>); no verdict -- a hang says nothing about the grant
 *    1628  => TIMED-OUT at the synthesized grant (<stage>); no verdict, and the ladder is NOT walked
 *    1663  => TIMED-OUT on ladder rung <i> (<stage>); the ladder is abandoned rather than continued
 *
 *  Three of those do NOT contain ` TIMED-OUT in `. A ladder-rung timeout (1663) prints ONLY shape 5, so
 *  the narrow pattern would have missed it silently — the same class of miss this module exists to fix.
 *  Hence the prefix is matched, not the phrasing after it: every site is either `=> TIMED-OUT` at the
 *  start of a line or `VERIFY[<label>] TIMED-OUT`.
 *
 *  ⛔ AND IT MUST STILL NOT MATCH A MERE MENTION. `TIMED-OUT` appears in this codebase's comments and
 *  in the verdict vocabulary, so the required prefix is what keeps prose out. Matching a bare
 *  `TIMED-OUT` anywhere would let a genuinely FAILING control be reclassified as a timeout, which is
 *  the one direction that would LOWER the gate rather than merely mis-describe it.
 *
 *  ⛔ WHY NOT THE EXIT CODE, WHICH LOOKS MORE ROBUST: every timeout site exits 3, but 3 is NOT
 *  timeout-exclusive — `measure-windows.mjs:1479` also exits 3 for VOID ("the override did not
 *  engage"). VOID is a different diagnosis with a different remedy, and `judgeRight` already handles it
 *  in an earlier branch, so keying on rc alone would conflate the two.
 */
export function driverReportedTimeout(out) {
  if (typeof out !== 'string' || !out) return false;
  return /^\s*=> TIMED-OUT\b|VERIFY\[[^\]]*\] TIMED-OUT\b/m.test(out);
}
