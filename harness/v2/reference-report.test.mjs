import assert from 'node:assert/strict';
import { test } from 'node:test';
import { referenceEvidenceSha } from './reference-probe.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildReferenceAccounting, readReferenceRecords } from './reference-report.mjs';

const profile = { id: 'developer-v1', sha256: 'p' };
const instrument = { harnessEpoch: 3, harnessSha256: 'i' };
const matrix = { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }, { version: '19.9.0' }] };
const row = (pkg, priorBucket = 'brokenWithoutJailToo') => ({
  pkg, version: '1.0.0', os: 'linux', prior: { bucket: priorBucket, verdict: 'old', recordSha256: pkg },
});
const record = (sourceRow, node, code, status = 'classified') => {
  const value = {
    schemaVersion: 1, pkg: sourceRow.pkg, version: sourceRow.version, profile,
    source: { kind: 'legacy-reference-accounting', os: sourceRow.os, nodeVersion: node,
      worklistSha256: 'w', priorRecordSha256: sourceRow.prior.recordSha256,
      nodeMatrixSha256: 'm', prior: sourceRow.prior },
    provenance: {
      runtime: { node: { version: `v${node}`, sha256: 'a'.repeat(64) }, os: { platform: 'linux' } },
      orchestrator: { node: { version: 'v22.23.2', sha256: 'b'.repeat(64) } },
      npm: { version: null, executable: { sha256: 'c'.repeat(64) } },
      nub: { gitSha: 'd'.repeat(40), sha256: 'e'.repeat(64) },
      instrument,
    },
    classification: { code, status, summary: code, evidence: [] }, arms: {},
  };
  value.provenance.evidenceSha256 = referenceEvidenceSha(value);
  return value;
};

test('accounting never mixes runtime cells with package-version or package counts', () => {
  const a = row('a'); const b = row('b', 'noVerdict');
  const report = buildReferenceAccounting({ rows: [a, b], worklistSha256: 'w', matrix,
    matrixSha256: 'm', profile, instrument, records: [
      record(a, '18.20.8', 'REFERENCE_PASSES'),
      record(a, '19.9.0', 'INCOMPATIBLE_NODE'),
      record(b, '18.20.8', 'UNCLASSIFIED', 'incomplete'),
    ] });
  assert.equal(report.expected.runtimeCells, 4);
  assert.deepEqual(report.observed, { rows: 3, packageVersions: 2, packages: 2 });
  assert.deepEqual(report.byClassification.REFERENCE_PASSES, { rows: 1, packageVersions: 1, packages: 1 });
  assert.equal(report.integrity.missing, 1);
  assert.equal(report.integrity.incomplete, 1);
  assert.equal(report.fixedFormerBrokenWithoutJail.rows, 1);
  assert.equal(report.status, 'incomplete');
  assert.equal(report.backlog.find((group) => group.code === 'UNCLASSIFIED').priority, 'P0');
  assert.deepEqual(report.backlog.find((group) => group.code === 'UNCLASSIFIED').examples[0].outcomes, {});
});

test('a no-lifecycle false positive is reported separately from a recovered install', () => {
  const a = row('a'); const b = row('b');
  const report = buildReferenceAccounting({ rows: [a, b], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] }, matrixSha256: 'm', profile, instrument,
    records: [record(a, '18.20.8', 'REFERENCE_PASSES'), record(b, '18.20.8', 'NO_LIFECYCLE_SCRIPT')] });
  assert.equal(report.fixedFormerBrokenWithoutJail.rows, 1);
  assert.equal(report.excludedFormerBrokenWithoutJailNoLifecycle.rows, 1);
  assert.equal(report.backlog.some((group) => group.code === 'NO_LIFECYCLE_SCRIPT'), false);
});

test('an expected pnpm platform policy differential is counted without creating a Nub-fix backlog', () => {
  const a = row('a');
  const report = buildReferenceAccounting({ rows: [a], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] }, matrixSha256: 'm', profile, instrument,
    records: [record(a, '18.20.8', 'REQUIRED_PLATFORM_POLICY_DIFFERENTIAL')] });
  assert.deepEqual(report.byClassification.REQUIRED_PLATFORM_POLICY_DIFFERENTIAL,
    { rows: 1, packageVersions: 1, packages: 1 });
  assert.equal(report.backlog.length, 0);
});

test('an altered evidence record is rejected instead of counted', () => {
  const a = row('a'); const value = record(a, '18.20.8', 'REFERENCE_PASSES');
  value.classification.code = 'PACKAGE_BROKEN_OR_UNAVAILABLE';
  const report = buildReferenceAccounting({ rows: [a], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] }, matrixSha256: 'm', profile, instrument, records: [value] });
  assert.equal(report.observed.rows, 0);
  assert.equal(report.integrity.invalid[0].reason, 'evidence-hash');
});

test('a record cannot claim an OS cell different from the runtime that produced it', () => {
  const a = row('a'); const value = record(a, '18.20.8', 'REFERENCE_PASSES');
  value.provenance.runtime.os.platform = 'darwin';
  value.provenance.evidenceSha256 = referenceEvidenceSha(value);
  const report = buildReferenceAccounting({ rows: [a], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] }, matrixSha256: 'm', profile, instrument, records: [value] });
  assert.equal(report.integrity.invalid[0].reason, 'runtime-os');
});

test('mixed Nub subjects and the wrong harness runtime are integrity failures', () => {
  const a = row('a'); const b = row('b');
  const first = record(a, '18.20.8', 'REFERENCE_PASSES');
  const second = record(b, '18.20.8', 'REFERENCE_PASSES');
  second.provenance.nub.gitSha = 'f'.repeat(40);
  second.provenance.evidenceSha256 = referenceEvidenceSha(second);
  let report = buildReferenceAccounting({ rows: [a, b], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] },
    matrixSha256: 'm', profile, instrument, records: [first, second] });
  assert.deepEqual(new Set(report.integrity.invalid.map((entry) => entry.reason)), new Set(['nub-subject']));

  first.provenance.orchestrator.node.version = 'v26.7.0';
  first.provenance.evidenceSha256 = referenceEvidenceSha(first);
  report = buildReferenceAccounting({ rows: [a], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] },
    matrixSha256: 'm', profile, instrument, records: [first] });
  assert.equal(report.integrity.invalid[0].reason, 'orchestrator');
});

test('an unreadable reference record is an integrity failure rather than disappearing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-report-'));
  const dir = path.join(root, 'one');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'reference.json'), '{not json}\n');
  const a = row('a');
  const report = buildReferenceAccounting({ rows: [a], worklistSha256: 'w',
    matrix: { harnessNode: '22.23.2', versions: [{ version: '18.20.8' }] }, matrixSha256: 'm', profile, instrument,
    records: readReferenceRecords(root) });
  assert.equal(report.observed.rows, 0);
  assert.equal(report.integrity.invalid[0].reason, 'read-error');
  assert.equal(report.status, 'incomplete');
});
