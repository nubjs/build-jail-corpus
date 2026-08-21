import { test } from 'node:test';
import assert from 'node:assert/strict';
import { observeVerdict, disposition } from './observe-only.mjs';

test('a failing fetch or rebuild is the unjailed verdict, exactly as the driver decides it', () => {
  assert.equal(observeVerdict({ fetchRc: 1, rebuildRc: 0 }), 'BROKEN-WITHOUT-JAIL-TOO');
  assert.equal(observeVerdict({ fetchRc: 0, rebuildRc: 1 }), 'BROKEN-WITHOUT-JAIL-TOO');
});

test('a clean observe is NOT reported as MINIMUM', () => {
  // ⛔ MINIMUM is a claim about a GRANT, which needs the jail and the falsification control that
  // guards it. Reporting it here would launder an observe-only run into a capability verdict.
  assert.equal(observeVerdict({ fetchRc: 0, rebuildRc: 0 }), 'INSTALLS-UNJAILED');
});

test('a capped arm is a timeout, never a package verdict', () => {
  assert.equal(observeVerdict({ fetchRc: 0, rebuildRc: 124, capped: true }), 'HARNESS-TIMEOUT');
});

test('a package that now installs marks the record STALE, not merely CHANGED', () => {
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'INSTALLS-UNJAILED'), 'STALE-RECORD');
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'BROKEN-WITHOUT-JAIL-TOO'), 'CONFIRMED');
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'HARNESS-TIMEOUT'), 'UNMEASURED-TIMEOUT');
});
