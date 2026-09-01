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
// ⛔⛔ THE BUILD DIRECTORY IS NOT ALWAYS NAMED `build/`, AND EVERY PATTERN BELOW USED TO ASSUME IT WAS.
//
// `node-pre-gyp` gives each NAPI target its own build root, `build-tmp-napi-v<N>/`, and gyp writes the
// WHOLE family into it — `config.gypi`, `Makefile`, the `.target.mk` sub-targets, the `.d` dep files,
// the `.o` objects. Anchoring on the literal name `build/` therefore did not miss one file; it missed
// an entire build tree, and it fabricated the worst verdict this harness can issue for installs that
// exited rc=0 with 100% of their artifacts present.
//
// ⛔ THIS FRAGMENT IS WHY THE FIX IS A DIRECTORY, NOT A FILE LIST. The first cut of this change
// excused `build-tmp-napi-v<N>/config.gypi` ALONE, because `config.gypi` was the only file the archived
// corpus had ever shown under that directory. A re-measure of `@discordjs/opus@0.10.0` at the pinned
// Nub with that narrower rule in place then produced `rc=0 artifacts=750/750` and `missing=161`, every
// entry a `build-tmp-napi-v3/Release/.deps/**/*.o.d` that was merely SHORTER (2919B < 3052B,
// 3037B < 3170B, …) — the same `.d` class the `build/` line has excused since `lmdb-store@2.0.0-alpha2`,
// at the same unanchored directory. Fixing one file at a time just moves the shortfall to the next
// member of the same family, so the directory is what generalises.
const NODE_GYP_BUILD_DIR = String.raw`(?:build|build-tmp-napi-v\d+)`;
const inBuildDir = (tail) => new RegExp(String.raw`(^|\/)${NODE_GYP_BUILD_DIR}\/${tail}$`);

export const TOOLCHAIN_GENERATED = [
  // MEASURED under a `build-tmp-napi-v<N>` root, and the signature is the opposite of a denied write:
  //     @tensorflow/tfjs-node@4.22.0  darwin-arm64  rc=0  artifacts=611/611
  //       build-tmp-napi-v8/config.gypi  16817B -> 16829B -> 16831B -> 16831B  (ref 17149B)
  //     @discordjs/opus@0.10.0        linux-x64     rc=0  artifacts=750/750
  //       build-tmp-napi-v3/config.gypi  19538B -> 19552B -> 19552B -> 19552B  (ref 19897B)
  // Every artifact present, rc=0 at every rung, and the differing file GROWS MONOTONICALLY as the grant
  // widens — because `config.gypi` records the grant. A denied write shrinks a file; it does not make it
  // larger each time you hand the build more authority. Both packages landed `NO-STATE-PASSED`, which
  // asserts that no expressible grant installs them at all. The growth is also why: a shortfall that
  // CHANGES across arms cannot be called invariant under widening, so the one escape hatch that would
  // have caught a gate artifact was closed by the artifact itself.
  inBuildDir(String.raw`config\.gypi`),
  inBuildDir(String.raw`Makefile`),
  // The ninja generator's `Makefile`. CMake emits one or the other depending on the generator it picks,
  // and both serialise the same thing: absolute toolchain paths and per-target rules derived from where
  // the inputs happened to live. MEASURED on `wrtc@0.1.6`, darwin-arm64: rc=0, artifacts=2819/2819,
  // `build/build.ninja` 33379B -> 33979B -> 34079B -> 34079B against 43109B — grant-monotone.
  inBuildDir(String.raw`build\.ninja`),
  inBuildDir(String.raw`.*\.target\.mk`),
  inBuildDir(String.raw`.*\.d`),
  inBuildDir(String.raw`gyp-mac-tool`),
  inBuildDir(String.raw`.*\.o`),
  // ⛔ CMAKE'S CONFIGURE LOG IS THE `config.gypi` OF THE CMAKE WORLD AND WAS ABSENT FROM THIS LIST
  // ENTIRELY. `CMakeConfigureLog.yaml` is a transcript of the configure run — every compiler probe,
  // every detected path, the environment it ran in. None of it describes what the package produced.
  //
  // MEASURED on `wrtc`, darwin-arm64, rc=0 and artifacts=2819/2819 (0.2.1) and 84/84 (0.0.67), with
  // `build/CMakeFiles/CMakeConfigureLog.yaml` the SOLE shortfall and grant-monotone throughout:
  //     0.2.1   144639B -> 145749B -> 145934B -> 145934B  (ref 149573B)
  //     0.0.67  126547B -> 127447B -> 127597B -> 127597B  (ref 132692B)
  //
  // ANCHORED ON `CMakeFiles/`, DELIBERATELY NOT ON `build/`, because anchoring on the build directory's
  // NAME is the exact defect the `build-tmp-napi-v<N>` entry above exists to repair: cmake-js and
  // node-pre-gyp both place the CMake build root somewhere other than `build/`. `CMakeFiles/` is
  // CMake's own generated scratch directory and nothing else ever writes that file.
  /(^|\/)CMakeFiles\/CMakeConfigureLog\.yaml$/,
  /(^|\/)npm-shrinkwrap\.json$/,
  /(^|\/)package-lock\.json$/,
];

// ⛔ WHAT WAS CONSIDERED AND LEFT OUT, so a later reader does not re-derive it as an oversight.
//
//   * `build/CMakeCache.txt` — CMake's cache of detected paths, and by mechanism it belongs. It is
//     excluded because it MOVES NOTHING: its only 3 sightings are the linux `wrtc` records, whose
//     shortfall lists run to `(+4241)`, `(+1725)` and `(+4315)` genuinely ABSENT files — builds that
//     produced nothing. Excusing it would widen the gate on resemblance and change no verdict, which
//     is the direction that under-grants.
//   * `node-addon-api/*.Makefile` and `node-addon-api/*.target.mk` — reported alongside the two
//     classes above, and they are NOT the same class. All 243 corpus entries, across 161 gate-failure
//     lines, are ABSENT entries and not one is a size difference: gyp computes a sub-target's path
//     from where the included `.gyp` REALLY lives, so npm's hoisted tree and nub's isolated store put
//     the file at different depths and one of them lands outside the measured package's own
//     directory. That is a real instrument defect with a different mechanism, and its fix was a PATH
//     question for the manifest walk rather than an excusal — excusing an absence would dismantle the
//     envelope in `excusesSizeDifference`. FIXED in `gyp-subtarget-spill.mjs`, which computes the
//     phantom's location in each layout and lets the walk find the file where it actually is; this
//     list is deliberately still silent about the class.
//   * `vue-demi`'s `lib/index.{cjs,mjs,d.ts}` — `vue-demi-switch` rewrites them per installed Vue
//     major, so two arms resolving different Vue majors legitimately produce different bytes. A
//     package-owned source file, not a toolchain record; out of scope for this list by construction.

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
