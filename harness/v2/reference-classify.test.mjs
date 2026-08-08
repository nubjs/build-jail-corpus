import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyReference, firstErrorFrom } from './reference-classify.mjs';

const arm = (outcome, error = '') => ({
  quorum: { outcome, fingerprint: error ? `fp-${outcome}` : null },
  lifecycle: { provenCount: outcome === 'pass' ? 1 : 0 },
  attempts: error ? [{ stages: { install: { error: firstErrorFrom(error) } } }] : [],
});
const record = (nub, npm, extra = {}) => ({
  status: 'complete',
  arms: { nubUnjailed: nub, npmUnjailed: npm },
  lifecycle: { expectedCount: 1 },
  provenance: { runtime: { node: { version: 'v22.23.2' }, os: { platform: 'linux', arch: 'x64' } } },
  ...extra,
});

test('the classifier preserves package-manager differentials instead of blaming the jail', () => {
  assert.equal(classifyReference(record(arm('consistent-failure', 'Error: failed'), arm('pass'))).code,
    'NUB_PM_DIVERGENCE');
  assert.equal(classifyReference(record(arm('pass'), arm('consistent-failure', 'Error: failed'))).code,
    'NPM_PM_DIVERGENCE');
});

test('a timed-out arm remains incomplete instead of becoming a package-manager verdict', () => {
  const classified = classifyReference(record(arm('timeout', 'REFERENCE-DEADLINE-REACHED'), arm('pass')));
  assert.equal(classified.code, 'REFERENCE_TIMEOUT');
  assert.equal(classified.status, 'incomplete');
});

test('a recovered clean retry is transient evidence, not a package-manager divergence', () => {
  assert.equal(classifyReference(record(arm('pass-after-failure'), arm('pass'))).code,
    'TRANSIENT_EXTERNAL_DOWNLOAD');
  assert.equal(classifyReference(record(arm('pass'), arm('pass-after-failure'))).code,
    'TRANSIENT_EXTERNAL_DOWNLOAD');
});

test('an incompatible Nub binary or contaminated fixture is an instrument failure, not a package differential', () => {
  for (const message of ['Error: unknown key `buildJail` in install', 'Error: ERR_NUB_LOCKFILE_AMBIGUOUS']) {
    const classified = classifyReference(record(arm('consistent-failure', message), arm('pass')));
    assert.equal(classified.code, 'HARNESS_INTERNAL');
    assert.equal(classified.status, 'incomplete');
  }
});

test('metadata classes outrank failure signatures when both managers fail', () => {
  const both = record(arm('consistent-failure', 'gyp ERR! build error'), arm('consistent-failure', 'gyp ERR! build error'), {
    packageMetadata: { engines: { node: '<=16' } },
  });
  assert.equal(classifyReference(both).code, 'INCOMPATIBLE_NODE');
});

test('a package libc constraint excludes the wrong Linux runtime cell', () => {
  const both = record(arm('consistent-failure', 'Error: unsupported runtime'),
    arm('consistent-failure', 'Error: unsupported runtime'), {
      packageMetadata: { libc: ['glibc'] },
    });
  both.provenance.runtime.os.libc = { family: 'musl', version: '1.2.5' };
  assert.equal(classifyReference(both).code, 'OS_CPU_MISMATCH');
});

test('toolchain, transient, permanent and unknown failures stay mutually exclusive', () => {
  const cases = [
    ['gyp ERR! find Python Could not find any Python installation', 'TOOLCHAIN_PREREQUISITE'],
    ['npm ERR! code ECONNRESET', 'TRANSIENT_EXTERNAL_DOWNLOAD'],
    ['npm ERR! code ETARGET No matching version found', 'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ['Error: surprising opaque failure', 'UNCLASSIFIED'],
  ];
  for (const [message, expected] of cases) {
    const classified = classifyReference(record(arm('consistent-failure', message), arm('consistent-failure', message)));
    assert.equal(classified.code, expected, message);
  }
});

test('a green exit without lifecycle evidence remains incomplete', () => {
  const green = record(arm('pass'), arm('pass'));
  green.arms.nubUnjailed.lifecycle.provenCount = 0;
  green.arms.npmUnjailed.lifecycle.provenCount = 0;
  assert.deepEqual(classifyReference(green), {
    status: 'incomplete',
    code: 'LIFECYCLE_NOT_PROVEN',
    confidence: 'deterministic',
    summary: 'both package managers exited successfully but exact package lifecycle hooks were not proven in both arms',
    evidence: ['expectedLifecyclePackages=1', 'incompleteArms=2'],
  });
});

test('failure excerpts remove credentials and machine roots before fingerprinting', () => {
  const error = firstErrorFrom('Error: /tmp/run failed at https://u:secret@example.test/x', { project: '/tmp/run' });
  assert.doesNotMatch(error.summary, /secret|\/tmp\/run/);
  assert.match(error.summary, /<PROJECT>/);
});

test('Node module errors outrank deprecation warnings and source snippets', () => {
  const error = firstErrorFrom(`npm warn deprecated old package\n  throw err;\nError: Cannot find module '/project/node_modules/a/scripts/install.js'\n  code: 'MODULE_NOT_FOUND'`,
    { project: '/project' });
  assert.equal(error.summary, "Error: Cannot find module '<PROJECT>/node_modules/a/scripts/install.js'");
  assert.ok(error.codes.includes('MODULE_NOT_FOUND'));
});

test('both managers missing a package lifecycle file is a permanent package failure', () => {
  const message = "Error: Cannot find module '/project/node_modules/a/scripts/install.js' MODULE_NOT_FOUND";
  assert.equal(classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message))).code, 'PACKAGE_BROKEN_OR_UNAVAILABLE');
});

test('a passing resolved tree with no install hooks is a terminal population exclusion', () => {
  const green = record(arm('pass'), arm('pass'));
  green.lifecycle.expectedCount = 0;
  green.arms.nubUnjailed.lifecycle.expectedCount = 0;
  green.arms.npmUnjailed.lifecycle.expectedCount = 0;
  assert.equal(classifyReference(green).code, 'NO_LIFECYCLE_SCRIPT');
  assert.equal(classifyReference(green).status, 'classified');
});
