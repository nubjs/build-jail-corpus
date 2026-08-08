import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { worklistCounts } from './make-reference-worklist.mjs';
import { readReferenceWorklist } from './run-reference-batch.mjs';

const root = path.resolve(import.meta.dirname, '..', '..');
const input = path.join(root, 'inputs', 'reference-legacy-failures.ndjson.gz');
const manifestFile = path.join(root, 'inputs', 'reference-legacy-failures.manifest.json');

test('the checked-in legacy failure worklist is the complete pinned accounting population', () => {
  const bytes = fs.readFileSync(input);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const worklist = readReferenceWorklist(input);
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), manifest.worklistSha256);
  assert.equal(worklist.sha256, manifest.worklistSha256);
  assert.deepEqual(worklistCounts(worklist.rows), manifest.counts);
  assert.deepEqual(manifest.counts, {
    rows: 1963,
    packageVersions: 935,
    packages: 407,
    byBucket: {
      artifactGateSuspect: 71,
      brokenWithoutJailToo: 1498,
      harnessError: 110,
      noStatePassed: 112,
      noVerdict: 172,
    },
  });
  assert.deepEqual(manifest.source, {
    commit: '1ceeb3d05ce1c5adcf6ae1fb89fbfdf5e50f0b6e',
    tree: 'records-v2',
  });
  assert.ok(worklist.rows.every((row) => row.source.commit === manifest.source.commit
    && row.source.tree === manifest.source.tree
    && row.prior.recordPath.startsWith('records-v2/')
    && /^[a-f0-9]{64}$/.test(row.prior.recordSha256)));
});
