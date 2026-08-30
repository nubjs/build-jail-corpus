// ⛔ NUB'S RESOLVE-TIME SUPPLY-CHAIN GATES MUST BE OFF IN THE MEASUREMENT ARM, AND ONLY THERE.
//
// `trustPolicy` and `minimumReleaseAge` refuse during RESOLUTION, before any lifecycle script exists
// to confine. They can therefore never produce a jail finding, and when they fire the jail question
// cannot be asked at all: the record comes back `HARNESS-ERROR: Nub could not materialize the tree
// with --ignore-scripts`, an instrument failure rather than a measurement.
//
// MEASURED 2026-08-30 -- a DEADLOCK, not a tunable. `fast-glob@^3.3.2` -> `fastq`: 1.20.3 has a
// trusted publisher but is 1 day old (age gate, exit 21); 1.20.2 is old enough but was published
// manually with `attestations: null` (trust gate, exit 23); the resolver picks 1.20.2 and ABORTS
// rather than continuing to 1.20.1, which satisfies the range, is 249 days old and is fully signed.
// No version clears both gates for ~14 days, so every tree containing fast-glob is unmeasurable.
// That was 20 of the 21 reasons the epoch-28 diagnostic printed on run 33285785801.
//
// This is NOT screening off: the harness runs its own fail-closed OSV screen (`security-screen.sh`)
// over the resolved tree, which is why supply-chain screening is the INSTRUMENT's job here.
//
// The last test is the one that is easy to regress into. An env var is the obvious way to set these
// and it is WRONG: it reaches npm too, and npm answers `npm warn Unknown env config "trust-policy"`
// on stderr for each -- measured, both keys -- including in the reference rebuild whose outcome
// decides BROKEN-WITHOUT-JAIL-TOO. A project `.npmrc` in the arm directory cannot reach npm, because
// OBSERVE lives in a SIBLING directory (`$ROOT/observe`, `$ROOT/Observe`, `ROOT/observe`).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');

/// Each driver, with the line that MINTS the nub arm directory. The opt-out must ride with that
/// line: an arm created without it is an arm the gates can still refuse.
const DRIVERS = [
  { file: 'measure.sh', mint: /local v="\$ROOT\/verify-\$label"/ },
  { file: 'measure-macos.sh', mint: /local v="\$ROOT\/verify-\$label"/ },
  { file: 'measure-windows.mjs', mint: /const v = path\.join\(ROOT, `verify-\$\{label\}`\)/ },
];

for (const { file, mint } of DRIVERS) {
  test(`${file} disables both resolve-time gates where it mints the arm`, () => {
    const lines = read(file).split('\n');
    const at = lines.findIndex((l) => mint.test(l));
    assert.ok(at !== -1, `no arm-directory mint site in ${file} — the anchor moved, so this whole `
      + 'file is asserting nothing until it is re-pointed');
    // Within the mint block, not merely somewhere in the file: placement is the guarantee.
    const block = lines.slice(at, at + 40).join('\n');
    assert.match(block, /trust-policy=off/,
      `${file} mints an arm without disabling trustPolicy, so a package mid-provenance-drift makes `
      + 'the whole tree unmeasurable');
    assert.match(block, /minimum-release-age=0/,
      `${file} mints an arm without disabling the release-age gate, so a recently-published `
      + 'dependency makes the tree unmeasurable');
    assert.match(block, /\.npmrc/, `${file} does not write the settings to a project .npmrc`);
  });
}

test('the settings never reach npm through the environment', () => {
  // npm READS npm_config_* and warns on both keys. Two extra stderr lines in every npm arm —
  // including the reference rebuild that decides BROKEN-WITHOUT-JAIL-TOO — is not a trade worth
  // making when a file in the arm directory is airtight.
  for (const { file } of DRIVERS) {
    // ⛔ CODE ONLY. The first version of this assertion read the raw file and failed on the COMMENT
    // in `measure.sh` that explains why the env form is wrong — a guard that fires on its own
    // rationale, which is a broken reader rather than a finding.
    const src = read(file).split('\n')
      .filter((l) => !/^\s*(#|\/\/)/.test(l)).join('\n');
    assert.doesNotMatch(src, /npm_config_trust_policy/,
      `${file} sets the trust policy through the environment, which npm also reads`);
    assert.doesNotMatch(src, /npm_config_minimum_release_age/,
      `${file} sets the release-age gate through the environment, which npm also reads`);
  }
});

test('the opt-out does not land in the OBSERVE directory', () => {
  // OBSERVE is the npm arm and is the CONTROL the jail verdicts are measured against. Giving it a
  // different resolver policy than the reference tool would silently change what it is a control OF.
  for (const { file } of DRIVERS) {
    const lines = read(file).split('\n');
    const at = lines.findIndex((l) => /(OBS=|const OBS = )/.test(l));
    assert.ok(at !== -1, `no OBSERVE root in ${file}`);
    const block = lines.slice(at, at + 25).join('\n');
    assert.doesNotMatch(block, /trust-policy=off|minimum-release-age=0/,
      `${file} writes the nub gate opt-out into the npm OBSERVE arm`);
  }
});
