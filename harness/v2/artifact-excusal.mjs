// Which artifact files may differ in SIZE between the observe run and a verify arm without that
// counting as a shortfall.
//
// ⛔⛔ WHY THIS IS ITS OWN MODULE. The excusal list lived inside `artifact-gate.mjs`, which the two
// POSIX drivers invoke as a CLI. `measure-windows.mjs` cannot invoke it that way, so it carries its
// own `missingArtifacts` — and that copy had NO excusal at all. Every Windows record has therefore
// been counting the whole node-gyp output family (`config.gypi`, `.target.mk`, `.d`, `.o`) as
// shortfall, while both POSIX drivers excused them.
//
// ⛔ AND THE COMMENT THAT HID IT WAS FALSE. `measure-windows.mjs` stated that importing
// `artifact-gate.mjs` "does NOT run its CLI -- its main-module guard resolves the invoked script's
// path to a URL and compares it against its own". `artifact-gate.mjs` has NO such guard: it reads
// `process.argv` at top level and exits when the flags are absent. Importing it really would have
// run and exited, which is presumably why the logic was hand-copied — and the false reassurance is
// what made the copy look safe. Third fix this effort to reach one driver and stop there (the `T3`
// tripwire was blind on macOS; the dependency scaffold was Linux-only).
//
// This module has NO top-level side effects and NO CLI, so both a CLI script and a long-running
// driver can import it without the guard question arising at all.

/**
 * Files a toolchain REGENERATES per run, whose byte length legitimately varies with paths, host, or
 * resolver state.
 *
 * ⛔ SIZE ONLY — see `excusesSizeDifference` for the envelope that keeps this from hiding a real
 * failure. Absence and zero bytes are never excused.
 */
export const TOOLCHAIN_GENERATED = [
  /(^|\/)build\/config\.gypi$/,
  /(^|\/)build\/Makefile$/,
  /(^|\/)build\/.*\.target\.mk$/,
  /(^|\/)build\/.*\.d$/,
  /(^|\/)build\/gyp-mac-tool$/,
  /(^|\/)build\/.*\.o$/,
  /(^|\/)npm-shrinkwrap\.json$/,
  /(^|\/)package-lock\.json$/,
];

/** Is this path one the toolchain regenerates? Path-shape only; says nothing about size. */
export const isToolchainGenerated = (f) => TOOLCHAIN_GENERATED.some((r) => r.test(f));

/**
 * THE WHOLE EXCUSAL DECISION, so no caller can implement half of it.
 *
 * ⛔ THE ENVELOPE IS THE SAFETY PROPERTY, NOT THE LIST. Only the "shorter than the reference but
 * NON-EMPTY" comparison is dropped. A file that is ABSENT never reaches here, and a ZERO-BYTE file
 * against a non-empty reference is NOT excused — that is the truncated/download-blocked shape the
 * gate exists to catch, and no generator, path or layout difference can produce it.
 *
 * @param f path relative to the package root
 * @param armSize bytes this arm produced (caller has already established the file EXISTS)
 * @returns true => the size difference is expected and must not be recorded as shortfall
 */
export const excusesSizeDifference = (f, armSize) => isToolchainGenerated(f) && armSize > 0;
