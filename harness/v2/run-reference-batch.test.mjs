import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { test } from 'node:test';
import { referenceEvidenceSha } from './reference-probe.mjs';
import {
  readReferenceWorklist,
  referenceRecordDir,
  referenceRecordReuse,
  selectReferenceRows,
} from './run-reference-batch.mjs';

const row = {
  schemaVersion: 1, pkg: '@scope/example', version: '1.2.3', os: 'linux',
  prior: { recordSha256: 'a'.repeat(64), bucket: 'brokenWithoutJailToo' },
};

test('worklists are read identically from plain NDJSON and deterministic gzip', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-batch-list-'));
  const body = Buffer.from(`${JSON.stringify(row)}\n`);
  const plain = path.join(root, 'rows.ndjson'); const gz = `${plain}.gz`;
  fs.writeFileSync(plain, body); fs.writeFileSync(gz, gzipSync(body, { mtime: 0 }));
  assert.deepEqual(readReferenceWorklist(plain).rows, [row]);
  assert.deepEqual(readReferenceWorklist(gz).rows, [row]);
});

test('record paths include OS and exact Node version before the package key', () => {
  assert.equal(referenceRecordDir('/records', row, '22.23.2', { id: 'developer-v1', sha256: 'a'.repeat(64) }),
    path.join('/records', 'linux', 'node-22.23.2', 'profile-developer-v1-aaaaaaaaaaaa',
      '@scope+example', '1.2.3'));
});

test('deterministic shards partition eligible rows exactly once', () => {
  const rows = Array.from({ length: 11 }, (_, index) => ({
    ...row, pkg: `package-${index}`, prior: { ...row.prior, bucket: index < 6 ? 'a' : 'b' },
  }));
  const shards = Array.from({ length: 4 }, (_, shardIndex) => selectReferenceRows(rows, {
    os: 'linux', priorBucket: 'a', shardIndex, shardCount: 4,
  }).rows);
  assert.deepEqual(shards.flat().map((entry) => entry.pkg).sort(),
    rows.slice(0, 6).map((entry) => entry.pkg).sort());
  assert.equal(new Set(shards.flat().map((entry) => entry.pkg)).size, 6);
  assert.throws(() => selectReferenceRows(rows, { os: 'linux', priorBucket: 'typo' }), /unknown prior bucket/);
  assert.throws(() => selectReferenceRows(rows, { os: 'linux', limit: 0 }), /positive integer/);
  assert.throws(() => selectReferenceRows(rows, {
    os: 'linux', includeSpecs: ['package-0@1.2.3'], shardCount: 2,
  }), /explicit specs/);
});

test('resume requires exact worklist, runtime cell, profile, instrument and subject identities', () => {
  const provenance = { instrument: { sha256: 'i' }, runtime: { node: { sha256: 'n' } },
    toolchain: { cc: 'v' }, nub: { sha256: 'u' }, npm: { version: '11' } };
  const expected = { row, worklistSha256: 'w', matrixSha256: 'm', nodeVersion: '22.23.2',
    profileSha256: 'p', provenance };
  const record = { schemaVersion: 1, pkg: row.pkg, version: row.version,
    source: { worklistSha256: 'w', priorRecordSha256: row.prior.recordSha256,
      nodeMatrixSha256: 'm', nodeVersion: '22.23.2', os: 'linux' },
    profile: { sha256: 'p' }, provenance: structuredClone(provenance), arms: {} };
  record.provenance.evidenceSha256 = referenceEvidenceSha(record);
  assert.deepEqual(referenceRecordReuse(record, expected), { reusable: true, reason: 'exact' });
  record.source.nodeVersion = '22.23.1';
  record.provenance.evidenceSha256 = referenceEvidenceSha(record);
  assert.deepEqual(referenceRecordReuse(record, expected), { reusable: false, reason: 'runtime-cell' });
});
