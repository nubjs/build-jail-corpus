import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { buildReferenceWorklist, priorBucketFor, worklistCounts } from './make-reference-worklist.mjs';

const writeRecord = (root, platform, pkg, version, verdict) => {
  const dir = path.join(root, platform, pkg.replace('/', '+'), version);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify({
    pkg, version, verdict, provenance: { platform, node: 'v22.1.0', at: '2026-08-08T00:00:00Z' },
  })}\n`);
};

test('legacy verdicts map to the five accounting buckets without absorbing successful rows', () => {
  assert.equal(priorBucketFor('BROKEN-WITHOUT-JAIL-TOO'), 'brokenWithoutJailToo');
  assert.equal(priorBucketFor('UNDER-PREDICTED'), 'noVerdict');
  assert.equal(priorBucketFor('UNKNOWN'), 'noVerdict');
  assert.equal(priorBucketFor('BROKEN-UNJAILED-NUB'), 'noVerdict');
  assert.equal(priorBucketFor('NO-STATE-PASSED'), 'noStatePassed');
  assert.equal(priorBucketFor('HARNESS-TIMEOUT'), 'harnessError');
  assert.equal(priorBucketFor('ARTIFACT-GATE-SUSPECT'), 'artifactGateSuspect');
  assert.equal(priorBucketFor('MINIMUM'), null);
});

test('the worklist retains exact source evidence and reports each unit separately', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-worklist-'));
  writeRecord(root, 'linux-x64', '@scope/a', '1.0.0', 'BROKEN-WITHOUT-JAIL-TOO');
  writeRecord(root, 'darwin-arm64', '@scope/a', '1.0.0', 'UNKNOWN');
  writeRecord(root, 'win32-x64', 'b', '2.0.0', 'HARNESS-ERROR');
  writeRecord(root, 'linux-x64', 'passing', '1.0.0', 'MINIMUM');
  const rows = buildReferenceWorklist(root, { sourceCommit: 'a'.repeat(40) });
  assert.equal(rows.length, 3);
  assert.equal(rows[0].prior.recordSha256.length, 64);
  assert.deepEqual(worklistCounts(rows), {
    rows: 3, packageVersions: 2, packages: 2,
    byBucket: { brokenWithoutJailToo: 1, harnessError: 1, noVerdict: 1 },
  });
});
