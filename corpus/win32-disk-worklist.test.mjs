// This worklist drives a re-measure aimed at NARROWING the widest grant the jail hands out, so its
// false POSITIVES are the dangerous direction: a package wrongly called an artifact gets re-measured
// toward a narrower grant it may genuinely need, and under-granting is what breaks installs on a user's
// machine. Every case below is pinned so a package that might really need the whole disk stays out.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isWholeDisk, wholeDiskPackages, classify, recordSlug } from './win32-disk-worklist.mjs';

const rec = (version, grant, verdict = 'MINIMUM') => ({ version, grant, verdict });
const DISK = { write: 'disk', network: true };
const NARROW = { network: true };

test('whole-disk is the string form, and the per-scope object is NOT it', () => {
  assert.equal(isWholeDisk(DISK), true);
  // ⛔ THE NEAR MISS THAT MATTERS. `deps+project+userHome` is broad but bounded, and it is a legitimate
  // measured grant — counting it as whole-disk would put dozens of correct entries on a narrowing list.
  assert.equal(isWholeDisk({ write: { deps: true, project: true, userHome: true }, network: true }), false);
  assert.equal(isWholeDisk({ network: true }), false);
  assert.equal(isWholeDisk(null), false);
});

test('⛔ version BANDS are searched, not just defaults', () => {
  // Measured on the shipped catalog: 13 whole-disk grants sit on a default and 21 inside bands. A scan
  // of defaults alone reports a third of the problem while looking thorough.
  const catalog = {
    packages: {
      onlyBanded: { default: { network: true }, versions: { '<2.0.0': { write: 'disk' } } },
      bandedGroup: { default: {}, versions: { '<3.0.0': { default: { write: 'disk' } } } },
      osOverlay: { default: {}, win: { write: 'disk' } },
      clean: { default: { write: { deps: true } } },
    },
  };
  assert.deepEqual(wholeDiskPackages(catalog), ['bandedGroup', 'onlyBanded', 'osOverlay']);
});

test('win32 asked for disk and POSIX measured less at the SAME version → a candidate with a target', () => {
  const r = classify({
    windows: [rec('1.0.0', DISK)],
    macos: [rec('1.0.0', NARROW)],
    linux: [rec('1.0.0', NARROW)],
  });
  assert.equal(r.verdict, 'win32-only-with-posix-target');
  assert.deepEqual(r.diskVersions, ['1.0.0']);
  assert.equal(r.posixNarrow.length, 2, 'both POSIX platforms give the re-measure a target');
});

test('⛔⛔ a package a POSIX platform ALSO needs disk for is NOT an artifact', () => {
  // The false positive this list must never produce. If macOS needed the whole disk too, the grant is
  // about the package rather than the harness, and re-measuring it toward something narrower is aimed
  // at a capability it demonstrably uses.
  for (const posix of ['macos', 'linux']) {
    const r = classify({ windows: [rec('1.0.0', DISK)], [posix]: [rec('1.0.0', DISK)] });
    assert.equal(r.verdict, 'posix-needs-disk-too', `${posix} needing disk must clear the package`);
    assert.deepEqual(r.posixNarrow, [], 'and it must offer no narrowing target');
  }
});

test('⛔ a POSIX record at a DIFFERENT version is not a target for this one', () => {
  // Grants are version-scoped, so macOS@2.0.0 says nothing about what win32@1.0.0 needed. Treating it
  // as a target would aim the re-measure at a number nothing measured.
  const r = classify({ windows: [rec('1.0.0', DISK)], macos: [rec('2.0.0', NARROW)] });
  assert.equal(r.verdict, 'win32-only-no-posix-overlap');
  assert.deepEqual(r.posixNarrow, []);
});

test('⛔ a record with NO grant is not evidence that the platform needed less', () => {
  // A refusal, a timeout, or a package nothing installs produces `grant: null`. Reading that as "macOS
  // did fine without disk" would manufacture an artifact finding out of an absence of measurement.
  const r = classify({ windows: [rec('1.0.0', DISK)], macos: [rec('1.0.0', null, 'BROKEN-WITHOUT-JAIL-TOO')] });
  assert.equal(r.verdict, 'win32-only-no-posix-overlap',
    'a null grant must not become a narrowing target');
});

test('no win32 record at all is its own bucket, not a candidate', () => {
  const r = classify({ macos: [rec('1.0.0', NARROW)] });
  assert.equal(r.verdict, 'no-win32-record');
});

test('a win32 record that did not ask for disk clears the package', () => {
  const r = classify({ windows: [rec('1.0.0', NARROW)], macos: [rec('1.0.0', NARROW)] });
  assert.equal(r.verdict, 'win32-did-not-ask');
});

test('a scoped name maps to its on-disk slug', () => {
  // Getting this wrong makes every scoped package look like it has no records, which lands it in
  // `no-win32-record` and silently drops it from the worklist.
  assert.equal(recordSlug('@larksuite/cli'), '@larksuite+cli');
  assert.equal(recordSlug('elm'), 'elm');
});
