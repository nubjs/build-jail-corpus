import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firstCause, observeVerdict, disposition } from './observe-only.mjs';

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

test('a capped FETCH is a timeout, never a package verdict', () => {
  // ⛔ FOUND BY READING A PASSING CONTROL. `ibm_db@0.0.9` returned fetch=124 and was dispositioned
  // CONFIRMED — which happened to be the expected answer for that row, so the 5/5 tally looked clean
  // while the row was right by accident. Every slow-fetching package would otherwise become a false
  // CONFIRMED in the sweep.
  assert.equal(observeVerdict({ fetchRc: 124, rebuildRc: null }), 'HARNESS-TIMEOUT');
  assert.equal(observeVerdict({ fetchRc: 0, rebuildRc: 124 }), 'HARNESS-TIMEOUT');
  assert.equal(observeVerdict({ fetchRc: 0, rebuildRc: 0, fetchCapped: true }), 'HARNESS-TIMEOUT');
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'HARNESS-TIMEOUT'), 'UNMEASURED-TIMEOUT');
});

test('⛔ an npm-only arm can never call a BROKEN-UNJAILED-NUB record stale', () => {
  // That verdict means "npm installs it, nub does not". This runner drives npm ONLY, so a
  // succeeding arm re-confirms the half that was never in doubt and leaves the nub half unmeasured.
  // The first CI sweep dispositioned 22 of 31 such records as STALE-RECORD — 22 open nub defects
  // reported as fixed, in the class the maintainer singled out as severe.
  assert.equal(disposition('BROKEN-UNJAILED-NUB', 'INSTALLS-UNJAILED'), 'NUB-UNMEASURED');
  // A FAILING arm removes the "npm installs it" premise, so the record genuinely changed.
  assert.equal(disposition('BROKEN-UNJAILED-NUB', 'BROKEN-WITHOUT-JAIL-TOO'), 'CHANGED');
  // The ordinary bucket is unaffected: there, npm failing IS the verdict.
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'INSTALLS-UNJAILED'), 'STALE-RECORD');
  assert.equal(disposition('BROKEN-WITHOUT-JAIL-TOO', 'BROKEN-WITHOUT-JAIL-TOO'), 'CONFIRMED');
});

test('firstCause skips the bare exit code and the OS banner npm prints first', async () => {
  // ⛔ MEASURED ON A REAL LEDGER: taking the first /npm error|ERR!/ line captured a useless one on
  // 240 of 625 rows, so the ledger looked attributed and was not — 385 of 959 was the honest count.
  const { firstCause } = await import('./observe-only.mjs');
  const log = [
    'npm error code 1',
    'npm ERR! Linux 6.11.0-1018-azure',
    'npm error command failed',
    'gyp ERR! configure error',
    'gyp ERR! stack Error: Could not find any Python installation to use',
  ].join('\n');
  // `gyp ERR! configure error` names the PHASE, not the reason — it was the answer here until the
  // phase markers were demoted below the lines that carry text.
  assert.equal(firstCause(log), 'gyp ERR! stack Error: Could not find any Python installation to use');
});

test('firstCause never returns LESS than the old behaviour', () => {
  // If every line is uninformative it still reports one, rather than null.
  assert.equal(firstCause('npm error code 1'), 'npm error code 1');
  assert.equal(firstCause('nothing interesting here'), null);
});
