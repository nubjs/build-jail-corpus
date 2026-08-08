import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';

const collate = path.join(import.meta.dirname, '..', 'collate.mjs');

function runFixture(mutator = (record) => record) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'collate-strict-'));
  const runs = path.join(root, 'runs', 'linux-x64', 'demo', '1.0.0');
  fs.mkdirSync(runs, { recursive: true });
  const instrument = computeHarnessIdentity();
  const record = mutator({
    pkg: 'demo', version: '1.0.0', harnessVersion: 2, harnessEpoch: instrument.harnessEpoch,
    verdict: 'MINIMUM', grant: { network: true }, grantSource: 'synthesized', minimality: 'MINIMAL',
    standing: { latestVersion: '1.0.0' },
    securityScreens: [],
    resolvedTrees: [{
      digest: 'tree', specCount: 1, specs: ['demo@1.0.0'], lockfiles: { digest: 'lock', files: [] },
      kinds: ['direct', 'npm-observe-resolved', 'nub-verify-resolved'],
    }],
    provenance: {
      platform: 'linux-x64', harnessEpoch: instrument.harnessEpoch,
      harnessSha256: instrument.harnessSha256, node: process.version,
      nubBinary: { sha256: 'nub' },
      runtime: {
        node: { version: process.version, sha256: 'node' },
        npm: { version: '10.0.0' }, python: [], buildTools: {},
        os: { release: 'test' }, runner: {}, environment: {},
      },
    },
  });
  fs.writeFileSync(path.join(runs, 'results.json'), `${JSON.stringify(record, null, 2)}\n`);
  const out = path.join(root, 'catalog.json');
  const result = spawnSync(process.execPath, [collate, '--runs', path.join(root, 'runs'),
    '--overrides', path.join(root, 'overrides'), '--out', out, '--strict'], { encoding: 'utf8' });
  return { result, out };
}

test('strict collation writes a provenance-bound catalog from current complete records', () => {
  const { result, out } = runFixture();
  assert.equal(result.status, 0, result.stderr);
  const catalog = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(catalog.provenance.harnessEpoch, 3);
  assert.match(catalog.provenance.harnessSha256, /^[0-9a-f]{64}$/);
  assert.match(catalog.provenance.recordsSha256, /^[0-9a-f]{64}$/);
  assert.equal(catalog.provenance.recordCount, 1);
});

test('strict collation refuses stale instrument records and writes no catalog', () => {
  const { result, out } = runFixture((record) => ({
    ...record, provenance: { ...record.provenance, harnessSha256: 'stale' },
  }));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /record provenance failure/);
  assert.equal(fs.existsSync(out), false);
});
