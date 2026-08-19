// The PATH a measured arm runs under — built explicitly, never inherited.
//
// ⛔ THE DEFECT. All three drivers PREPEND the era Node bin to the ambient runner `$PATH`
// (`measure.sh:138`, `measure-macos.sh:190`, `era-node.mjs:94`) rather than replacing it. So whether
// a package hits `sh: <bin>: command not found` depends on what the runner IMAGE happened to ship,
// and those images drift between versions. That is not a small axis: `command not found` is the
// LARGEST failure class in the corpus — 105 of the 1,529 `BROKEN-*` records — so its size is
// currently a property of the runner rather than of the packages.
//
// MEASURED, on the machine this was written on: `tsc` resolves from `~/Library/pnpm/tsc` and
// `rimraf` from `~/.config/yarn/global/node_modules/.bin`. A control run there scored a package as
// PASSING the exact step the corpus records as failing — the precondition was silently already met.
//
// ⛔ THIS IS THE HARNESS'S OWN R6 RULE, TURNED ON THE HARNESS. `measure.sh` already argues it for the
// era Node: "normalisation that is RECORDED is a covered axis, normalisation that is INVISIBLE is a
// silent bet it did not matter." The arm PATH was the invisible one.
//
// ⛔⛔ FILTERING DIRECTORIES IS NOT SUFFICIENT, AND THAT WAS MEASURED HERE RATHER THAN ASSUMED.
// After dropping every package-manager directory below, `tsc` and `rimraf` STILL resolved — from
// `/usr/local/bin`, where `npm install -g` symlinks them and where a native build genuinely needs to
// look. There is no directory rule that separates the two, because the contamination is per-BINARY.
// So this module does BOTH, and the second half is the one that makes a record honest:
//
//   1. DROP the package-manager directories. Cheap, safe, and it removes the common case.
//   2. PROBE what survived, and RECORD it. `ambientTools()` reports which npm-installable CLI names
//      are still resolvable when the arm starts, so a record states the contamination it ran under
//      instead of hiding it. Feed that set to `scriptScaffold({ has })` and the scaffold will not
//      re-install a tool the box already leaks.
//
// Enforcing beyond this needs a controlled filesystem (a container), not a longer regex. Until that
// exists, VISIBLE contamination is the correct outcome and silent contamination is the defect.
//
// ⛔ SUBTRACTIVE, NOT A WHITELIST, AND THAT CHOICE IS LOAD-BEARING. A whitelist of system directories
// would be cleaner to describe and would BREAK currently-passing records: 4,917 of 6,880 records are
// `MINIMUM`, and a native build legitimately reaches for Homebrew, Xcode, hostedtoolcache and rustup
// paths this file must not have to enumerate correctly. So it removes only the directories that ship
// npm-INSTALLED CLIs — the actual contamination source — and keeps everything else. A missed drop
// leaves one record as contaminated as it is today; an over-broad whitelist would fail thousands.

import path from 'node:path';

/** PATH entries that hold npm/yarn/pnpm/bun-installed command-line tools.
 *
 *  Each pattern is anchored on a directory segment, so `/opt/homebrew/bin` (a SYSTEM tool source, and
 *  where a modern GNU Make comes from) is kept while `~/.npm-global/bin` is dropped. */
export const CONTAMINATING = [
  /(^|\/)\.npm-global(\/|$)/,
  /(^|\/)\.npm-packages(\/|$)/,
  /(^|\/)\.yarn(\/|$)/,
  /(^|\/)yarn(\/|$).*(\/|^)global(\/|$)/,
  /(^|\/)\.config\/yarn\/global(\/|$)/,
  /(^|\/)\.pnpm(\/|$)/,
  /(^|\/)Library\/pnpm(\/|$)/,
  /(^|\/)\.local\/share\/pnpm(\/|$)/,
  /(^|\/)\.bun(\/|$)/,
  /(^|\/)\.volta(\/|$)/,
  /(^|\/)\.nvm(\/|$)/,          // a second Node with its own global bin
  /(^|\/)\.fnm(\/|$)/,
  /(^|\/)\.nodenv(\/|$)/,
  /(^|\/)\.nub(\/|$)/,          // nub's own shim dir — never the thing under measurement
  /(^|\/)node_modules\/\.bin(\/|$)/,  // a stray tree's bin, never the fixture's own
  /(^|\/)lib\/node_modules(\/|$)/,    // npm's global prefix
];

/** True when `entry` is a directory that ships npm-installed CLIs. */
export function isContaminating(entry) {
  const p = entry.replace(/\\/g, '/');
  return CONTAMINATING.some((re) => re.test(p));
}

/** Build the PATH an arm runs under.
 *
 *  `fixtureBin` (the fixture's own `node_modules/.bin`) comes FIRST because that is what npm itself
 *  puts ahead of everything for a lifecycle script, and it is the only bin directory the measurement
 *  is entitled to see. `eraBin` follows so the package builds against the Node its author targeted.
 *
 *  Returns `{ armPath, dropped, kept }` — `dropped` exists so the RECORD can say what was removed.
 *  A sanitisation nobody can read back is exactly the invisible normalisation this file exists to
 *  end, so a caller that does not record `dropped` has only half-applied the fix. */
export function armPath({ ambient = process.env.PATH ?? '', eraBin = null, fixtureBin = null, sep = path.delimiter } = {}) {
  const entries = ambient.split(sep).filter(Boolean);
  const dropped = entries.filter(isContaminating);
  const kept = entries.filter((e) => !isContaminating(e));
  const head = [fixtureBin, eraBin].filter(Boolean);
  return { armPath: [...head, ...kept].join(sep), dropped, kept };
}

/** One line for `driver.out`, in the same declare-it-or-it-did-not-happen shape as `ERA-NODE`. */
export function armPathMarker({ dropped }) {
  return dropped.length
    ? `ARM-PATH SANITISED (dropped ${dropped.length}: ${dropped.join(', ')})`
    : 'ARM-PATH SANITISED (nothing to drop)';
}

/** The npm-installable command names a lifecycle script in this corpus is known to invoke.
 *
 *  Drawn from the measured distribution over the 105 `command not found` records, so it probes what
 *  actually matters rather than a general catalogue of build tools. */
export const LEAKABLE = [
  'tsc', 'husky', 'patch-package', 'rimraf', 'typings', 'run-p', 'run-s', 'bower', 'rollup',
  'flow-typed', 'simple-git-hooks', 'grunt', 'gulp', 'ngcc', 'nuxt', 'webpack', 'babel', 'lefthook',
  'lerna', 'cross-env', 'ts-node', 'browserify', 'tslint', 'remix', 'opencollective',
  'webdriver-manager', 'node-pre-gyp', 'pnpm', 'yarn', 'bun', 'pulumi',
];

/** Which of `LEAKABLE` resolve under `armPath` right now.
 *
 *  ⛔ THIS IS THE HALF THAT MAKES THE RECORD TRUE. A run where `tsc` was ambient cannot be compared
 *  with one where it was not, and nothing in the corpus currently says which happened. `resolve` is
 *  injected so this is testable without a filesystem. */
export function ambientTools(armPathValue, { resolve, sep = path.delimiter } = {}) {
  const dirs = armPathValue.split(sep).filter(Boolean);
  const found = {};
  for (const name of LEAKABLE) {
    const hit = resolve(name, dirs);
    if (hit) found[name] = hit;
  }
  return found;
}

/** One line for `driver.out`. Named tools, not a count, because the NAMES decide which records the
 *  contamination could have changed. */
export function ambientToolsMarker(found) {
  const names = Object.keys(found);
  return names.length
    ? `ARM-AMBIENT-TOOLS ${names.length} leaked: ${names.map((n) => `${n}=${found[n]}`).join(' ')}`
    : 'ARM-AMBIENT-TOOLS none';
}
