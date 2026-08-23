import { test } from 'node:test';
import assert from 'node:assert/strict';
import { eraNodeFromDriverOut, supportsImport, refusalTextWaived } from './stamp-waiver.mjs';

// The marker as the drivers actually print it, copied from a real run rather than paraphrased.
const REAL = '  ERA-NODE PINNED 10.24.1 (arms will run: v10.24.1)';
const MODERN = '  ERA-NODE PINNED 22.23.2 (arms will run: v22.23.2)';

test('the era comes from the driver marker, in the shape the drivers print it', () => {
  assert.deepEqual(eraNodeFromDriverOut(REAL), { major: 10, minor: 24 });
  assert.deepEqual(eraNodeFromDriverOut(MODERN), { major: 22, minor: 23 });
  // The macOS driver prints `(provisioned)` between the version and the parenthetical.
  assert.deepEqual(
    eraNodeFromDriverOut('ERA-NODE PINNED 6.17.1 (provisioned) (arms will run: v6.17.1)'),
    { major: 6, minor: 17 },
  );
});

test('an absent or unparseable marker reads as UNKNOWN, never as a low era', () => {
  assert.equal(eraNodeFromDriverOut(''), null);
  assert.equal(eraNodeFromDriverOut(undefined), null);
  // The near-miss that matters: a driver that failed before pinning says so, and this must not
  // be mistaken for an old Node — that would waive the check on precisely the broken venue.
  assert.equal(eraNodeFromDriverOut('ERA-NODE lookup FAILED for mozjpeg@6.0.1'), null);
});

test('supportsImport mirrors nub\'s own 20.6 threshold at the boundary', () => {
  assert.equal(supportsImport({ major: 20, minor: 5 }), false);
  assert.equal(supportsImport({ major: 20, minor: 6 }), true);
  assert.equal(supportsImport({ major: 21, minor: 0 }), true);
  assert.equal(supportsImport({ major: 10, minor: 24 }), false);
  assert.equal(supportsImport(null), false);
});

test('the waiver fires for the opted-in case on the era that provoked it', () => {
  const kase = { refusalNeedsImportStamp: true };
  assert.equal(refusalTextWaived(kase, eraNodeFromDriverOut(REAL)), true);
});

test('a case that did NOT opt in is never waived, whatever the era', () => {
  assert.equal(refusalTextWaived({}, { major: 10, minor: 24 }), false);
  assert.equal(refusalTextWaived({ refusalNeedsImportStamp: false }, { major: 4, minor: 9 }), false);
});

test('an UNKNOWN era does not waive — the strict direction, and the one worth pinning', () => {
  // A driver that printed no marker is a venue that may be broken in a way the waiver would hide.
  assert.equal(refusalTextWaived({ refusalNeedsImportStamp: true }, null), false);
});

test('a modern arm is still held to the refusal text', () => {
  const kase = { refusalNeedsImportStamp: true };
  assert.equal(refusalTextWaived(kase, eraNodeFromDriverOut(MODERN)), false);
  // The boundary itself: 20.6 carries the stamp, so the text must be there.
  assert.equal(refusalTextWaived(kase, { major: 20, minor: 6 }), false);
  assert.equal(refusalTextWaived(kase, { major: 20, minor: 5 }), true);
});
