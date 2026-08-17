// The coverage checker decides what gets measured, so its FALSE NEGATIVES are the dangerous direction:
// a package it wrongly reports as covered is one that silently never gets measured and whose grant the
// catalog therefore never learns. Every clause below is pinned in that polarity.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readList, recordSlug, hasRecord, gaps } from './check-coverage.mjs';

/** A fake filesystem: the set of paths that "exist". */
const fakeExists = (present) => (p) => present.has(p);

test('the list is names only — comments and blank lines are not packages', () => {
  const names = readList(`# a comment\n\n  esbuild  \n@scope/pkg\n# another\n`);
  assert.deepEqual(names, ['esbuild', '@scope/pkg'],
    'a comment read as a package name would dispatch a measurement for "#"');
});

test('a scoped name maps to its on-disk slug', () => {
  // ⛔ `@scope/name` is stored `@scope+name`. Getting this wrong makes every scoped package look
  // UNCOVERED forever — the checker would dispatch them endlessly and never see a record appear.
  assert.equal(recordSlug('@mongodb-js/zstd'), '@mongodb-js+zstd');
  assert.equal(recordSlug('esbuild'), 'esbuild', 'an unscoped name must pass through untouched');
});

test('a record is found only at the exact package/version/platform path', () => {
  const p = 'R/records-v2/runs/linux-x64/esbuild/1.0.0/results.json';
  const exists = fakeExists(new Set([p]));
  assert.equal(hasRecord('R', 'esbuild', '1.0.0', 'linux', exists), true);
  // The three axes that must all match, each checked so a sloppy join cannot pass by accident.
  assert.equal(hasRecord('R', 'esbuild', '1.0.1', 'linux', exists), false, 'a DIFFERENT version is a gap');
  assert.equal(hasRecord('R', 'esbuild', '1.0.0', 'macos', exists), false, 'a different PLATFORM is a gap');
  assert.equal(hasRecord('R', 'other', '1.0.0', 'linux', exists), false, 'a different PACKAGE is a gap');
});

test('an unknown platform throws rather than silently reporting covered', () => {
  assert.throws(() => hasRecord('R', 'x', '1.0.0', 'freebsd', () => false), /unknown platform/);
});

test('a package whose LATEST has no record is a gap — this is the freshness mechanism', async () => {
  // ⛔ THE WHOLE REASON THE LIST HOLDS NAMES. The record exists for 1.0.0, but latest has moved to
  // 2.0.0, so the package is NOT covered any more and must be re-measured. A version-pinned list would
  // have reported this as covered forever.
  const exists = fakeExists(new Set(['R/records-v2/runs/linux-x64/pkg/1.0.0/results.json']));
  const r = await gaps({ root: 'R', names: ['pkg'], platforms: ['linux'], latestOf: async () => '2.0.0', exists });
  assert.deepEqual(r.gaps, [{ name: 'pkg', version: '2.0.0', platform: 'linux' }]);
});

test('a package whose latest IS recorded is not a gap', async () => {
  const exists = fakeExists(new Set(['R/records-v2/runs/linux-x64/pkg/2.0.0/results.json']));
  const r = await gaps({ root: 'R', names: ['pkg'], platforms: ['linux'], latestOf: async () => '2.0.0', exists });
  assert.deepEqual(r.gaps, [], 'a covered package must not be dispatched again');
});

test('gaps are per PLATFORM — one platform covered does not cover the others', async () => {
  // Measured reality this guards: the corpus has had per-platform holes while pooled counts looked
  // complete, which is how 5 win32-only specs once hid behind a healthy total.
  const exists = fakeExists(new Set(['R/records-v2/runs/linux-x64/pkg/1.0.0/results.json']));
  const r = await gaps({
    root: 'R', names: ['pkg'], platforms: ['macos', 'linux', 'windows'],
    latestOf: async () => '1.0.0', exists,
  });
  assert.deepEqual(r.gaps.map((g) => g.platform), ['macos', 'windows']);
});

test('⛔ an UNRESOLVABLE name is reported, never silently treated as covered', async () => {
  // A typo'd or unpublished line must not read as "nothing to do" — that is the false negative this
  // checker exists to prevent, and it would hide forever because a missing package produces no record
  // and no gap either.
  const r = await gaps({
    root: 'R', names: ['ghost-pkg', 'ok-pkg'], platforms: ['linux'],
    latestOf: async (n) => { if (n === 'ghost-pkg') throw new Error('404 Not Found'); return '1.0.0'; },
    exists: fakeExists(new Set(['R/records-v2/runs/linux-x64/ok-pkg/1.0.0/results.json'])),
  });
  assert.equal(r.unresolved.length, 1, 'the unresolvable name must be surfaced');
  assert.equal(r.unresolved[0].name, 'ghost-pkg');
  assert.match(r.unresolved[0].why, /404/, 'and carry WHY, so a log says more than "no"');
  assert.deepEqual(r.gaps, [], 'while the resolvable, recorded package stays out of the gap set');
});

test('a resolver returning nothing is unresolved, not version-undefined', async () => {
  // `latestOf` yielding null used to be the shape that would join `.../undefined/results.json`, miss,
  // and dispatch a measurement for a version that does not exist.
  const r = await gaps({ root: 'R', names: ['p'], platforms: ['linux'], latestOf: async () => null, exists: () => false });
  assert.deepEqual(r.gaps, []);
  assert.equal(r.unresolved[0].why, 'no latest version');
});
