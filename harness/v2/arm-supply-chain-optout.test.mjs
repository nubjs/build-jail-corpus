// ⛔ NUB'S RESOLVE-TIME SUPPLY-CHAIN GATES MUST BE OFF IN EVERY MEASUREMENT ARM, AND ONLY THERE.
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
//
// ⛔⛔ THE ASSERTION IS PER-WRITE, AND THAT IS THE WHOLE LESSON OF EPOCH 29. That epoch added a
// SECOND `.npmrc` write at the top of each arm function and was a TOTAL NO-OP: the pre-existing
// `side-effects-cache=false` write further down truncated it before any install ran. The first
// version of this file asserted only that the keys appeared "within 40 lines of the mint site",
// which the no-op satisfied perfectly -- a guard that passed while the thing it guarded did nothing,
// proven wrong only by CI still refusing `fastq@1.20.2` at the new epoch. Asserting that EVERY write
// to an arm `.npmrc` carries EVERY key is the invariant that cannot be satisfied by a clobber.
//
// This is NOT screening off: the harness runs its own fail-closed OSV screen (`security-screen.sh`)
// over the resolved tree, so supply-chain screening is the INSTRUMENT's job here.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');
const KEYS = ['side-effects-cache=false', 'trust-policy=off', 'minimum-release-age=0'];

/// Every statement that writes an arm's `.npmrc`, with the literal content it writes. The JS driver
/// writes through a shared constant, so its definition is what carries the content.
function npmrcWrites(file) {
  const src = read(file);
  const out = [];
  for (const line of src.split('\n')) {
    if (/^\s*(#|\/\/)/.test(line)) continue;
    if (!/\.npmrc/.test(line)) continue;
    if (/printf|writeFileSync/.test(line)) out.push(line);
  }
  if (file.endsWith('.mjs')) {
    // Resolve the constant each write names, so an indirection cannot hide a missing key.
    const decl = src.match(/const ARM_NPMRC = '([^']*)'/);
    return out.map((l) => (l.includes('ARM_NPMRC') && decl ? decl[1] : l));
  }
  return out;
}

for (const file of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
  test(`${file}: every arm .npmrc write carries every setting`, () => {
    const writes = npmrcWrites(file);
    // Control: without this the loop below passes vacuously the moment the writes are renamed away.
    assert.ok(writes.length > 0, `no arm .npmrc write found in ${file} — the extractor is broken, or `
      + 'the arm no longer configures nub at all');
    for (const w of writes) {
      for (const key of KEYS) {
        assert.ok(w.includes(key),
          `${file} writes an arm .npmrc without \`${key}\`. A second write to the same path TRUNCATES `
          + `the first, so a partial write is not a partial fix — it is a total one:\n    ${w.trim()}`);
      }
    }
  });
}

test('the settings never reach npm through the environment', () => {
  // npm READS npm_config_* and warns on both keys. Two extra stderr lines in every npm arm —
  // including the reference rebuild that decides BROKEN-WITHOUT-JAIL-TOO — is not a trade worth
  // making when a file in the arm directory is airtight.
  for (const file of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    // ⛔ CODE ONLY. An earlier version read the raw file and failed on the COMMENT in `measure.sh`
    // that explains why the env form is wrong — a guard firing on its own rationale.
    const src = read(file).split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l)).join('\n');
    assert.doesNotMatch(src, /npm_config_trust_policy/,
      `${file} sets the trust policy through the environment, which npm also reads`);
    assert.doesNotMatch(src, /npm_config_minimum_release_age/,
      `${file} sets the release-age gate through the environment, which npm also reads`);
  }
});

test('the opt-out does not land in the npm OBSERVE arm', () => {
  // OBSERVE is the npm arm and is the CONTROL the jail verdicts are measured against. Giving it a
  // different resolver policy than the reference tool would silently change what it is a control OF.
  for (const file of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const lines = read(file).split('\n');
    const at = lines.findIndex((l) => /(OBS=|const OBS = )/.test(l));
    assert.ok(at !== -1, `no OBSERVE root in ${file}`);
    const block = lines.slice(at, at + 25).join('\n');
    assert.doesNotMatch(block, /trust-policy=off|minimum-release-age=0/,
      `${file} writes the nub gate opt-out into the npm OBSERVE arm`);
  }
});
