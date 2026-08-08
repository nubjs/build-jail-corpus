import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';
import { fileIdentity } from './runtime-provenance.mjs';

const claim = path.join(import.meta.dirname, '..', 'claim-slice.mjs');
const read = (file) => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);

test('claiming a v2 slice reopens stale done rows but preserves current and inherited refusals', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-epoch-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const instrument = computeHarnessIdentity();
  fs.writeFileSync(queue, [
    { pkg: 'stale', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM' },
    {
      pkg: 'current', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM',
      harnessVersion: 2, harnessEpoch: instrument.harnessEpoch,
      harnessSha256: instrument.harnessSha256, platform: 'linux-x64',
    },
    {
      pkg: 'malicious', version: '1.0.0', os: 'linux', status: 'refused-malicious',
      verdict: 'REFUSED-MALICIOUS', sourceVerdict: 'v1-resolved-tree-screen',
    },
  ].map(JSON.stringify).join('\n') + '\n');
  const result = spawnSync(process.execPath, [claim, '--queue', queue, '--claim', '1',
    '--os', 'linux', '--run', 'test-run'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'stale@1.0.0');
  const rows = read(queue);
  assert.equal(rows[0].status, 'claimed');
  assert.match(rows[0].invalidated.reason, /transition|v2 record/);
  assert.equal(rows[1].status, 'done');
  assert.equal(rows[2].status, 'refused-malicious');
});

test('completion stamps the queue with the durable record identity', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-stamp-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const verdicts = path.join(root, 'verdicts.ndjson');
  const instrument = computeHarnessIdentity();
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', os: 'linux', status: 'claimed', run: 'test-run',
  })}\n`);
  fs.writeFileSync(verdicts, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', verdict: 'MINIMUM', harnessVersion: 2,
    harnessEpoch: instrument.harnessEpoch, harnessSha256: instrument.harnessSha256,
    platform: 'linux-x64', nubSha256: 'nub', node: 'v22.0.0',
  })}\n`);
  const result = spawnSync(process.execPath, [claim, '--queue', queue, '--complete', verdicts,
    '--run', 'test-run'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const [row] = read(queue);
  assert.equal(row.status, 'done');
  assert.equal(row.harnessEpoch, instrument.harnessEpoch);
  assert.equal(row.harnessSha256, instrument.harnessSha256);
  assert.equal(row.nubSha256, 'nub');
  assert.equal(row.platform, 'linux-x64');
});

test('claiming with a new Nub subject reopens a same-harness row', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-subject-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const nub = path.join(root, 'nub');
  fs.writeFileSync(nub, 'new subject binary');
  const instrument = computeHarnessIdentity();
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM',
    harnessVersion: 2, harnessEpoch: instrument.harnessEpoch,
    harnessSha256: instrument.harnessSha256, platform: 'linux-x64',
    nubSha256: 'old-nub', nubGitSha: 'old-commit', node: process.version,
    nodeSha256: fileIdentity(process.execPath).sha256,
  })}\n`);
  const result = spawnSync(process.execPath, [claim, '--queue', queue, '--claim', '1',
    '--os', 'linux', '--run', 'test-run', '--subject-nub', nub,
    '--subject-nub-git-sha', 'new-commit'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'demo@1.0.0');
  assert.match(read(queue)[0].invalidated.reason, /Nub binary|Nub commit/);
});
