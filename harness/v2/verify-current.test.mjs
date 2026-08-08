import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';

const verify = path.join(import.meta.dirname, '..', 'verify-corpus.mjs');

function fixture({ stale = false, queueStatus = 'done' } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-current-'));
  const recordDir = path.join(root, 'runs', 'linux-x64', 'demo', '1.0.0');
  fs.mkdirSync(recordDir, { recursive: true });
  const instrument = computeHarnessIdentity();
  const record = {
    pkg: 'demo', version: '1.0.0', harnessVersion: 2, harnessEpoch: instrument.harnessEpoch,
    verdict: 'MINIMUM', grant: { network: true }, minimality: 'MINIMAL', grantSource: 'synthesized',
    standing: { latestVersion: '1.0.0' },
    resolvedTrees: [{
      digest: 'tree', specCount: 1, specs: ['demo@1.0.0'], lockfiles: { digest: 'lock', files: [] },
      kinds: ['direct', 'npm-observe-resolved', 'nub-verify-resolved'],
    }],
    provenance: {
      platform: 'linux-x64', harnessEpoch: instrument.harnessEpoch,
      harnessSha256: stale ? 'stale' : instrument.harnessSha256, node: process.version,
      nubBinary: { sha256: 'nub' },
      runtime: {
        node: { version: process.version, sha256: 'node' }, npm: { version: '10.0.0' },
        python: [], buildTools: {}, os: { release: 'test' }, runner: {}, environment: {},
      },
    },
  };
  fs.writeFileSync(path.join(recordDir, 'results.json'), `${JSON.stringify(record, null, 2)}\n`);
  const queue = path.join(root, 'queue.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', os: 'linux', status: queueStatus,
    ...(queueStatus === 'done' ? { verdict: 'MINIMUM' } : {}),
  })}\n`);
  return { root, queue };
}

function run(options, args = ['--current-instrument']) {
  return spawnSync(process.execPath, [verify, '--records', path.join(options.root, 'runs'),
    '--queue', options.queue, ...args], { encoding: 'utf8' });
}

test('the slice gate accepts a current instrument record', () => {
  const result = run(fixture());
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /all records match current harness epoch 3/);
});

test('the slice gate rejects a stale instrument record', () => {
  const result = run(fixture({ stale: true }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /not valid under current harness epoch/);
});

test('the complete strict gate rejects any unfinished queue row', () => {
  const result = run(fixture({ queueStatus: 'pending' }), ['--strict', '--complete']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /queue row\(s\) are not done/);
});
