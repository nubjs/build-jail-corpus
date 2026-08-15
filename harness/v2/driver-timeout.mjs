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
 *  ⛔ BOTH SPELLINGS ARE MATCHED, because the driver emits a different one before an arm has a label.
 *  `measure-windows.mjs` prints `VERIFY[<label>] TIMED-OUT in \`install\`|\`approve-builds\`` for the
 *  two labelled phases, and a bare `=> TIMED-OUT in safe Nub resolution` for the safe-resolve phase
 *  that runs first. Matching only the labelled form would miss a timeout in the phase MOST likely to
 *  hit one on a cold venue, and would do it silently.
 *
 *  ⛔ AND IT MUST NOT MATCH A MERE MENTION. The word appears in this codebase's own comments and in
 *  the `TIMED-OUT` verdict vocabulary, so the pattern requires the driver's full phrasing — the
 *  literal ` TIMED-OUT in ` with a preceding `VERIFY[...]` or `=>`. A looser pattern would classify a
 *  genuinely failing control as a timeout, which is the one direction that would LOWER the gate.
 */
export function driverReportedTimeout(out) {
  if (typeof out !== 'string' || !out) return false;
  return /VERIFY\[[^\]]*\] TIMED-OUT in |=> TIMED-OUT in /.test(out);
}
