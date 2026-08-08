import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { computeHarnessIdentity, instrumentFiles } from './instrument.mjs';
import { recordValidity } from './record-validity.mjs';

function fixture(lineEnding = '\n') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'instrument-'));
  fs.mkdirSync(path.join(root, 'harness', 'v2'), { recursive: true });
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  const config = {
    schemaVersion: 1,
    harnessEpoch: 3,
    inputs: ['harness', '.github/workflows/corpus-v2-runner.yml', '.gitattributes'],
    excludePrefixes: ['harness/results/'],
    excludeFiles: ['harness/v2/invalidation.json'],
  };
  const write = (rel, text) => {
    const file = path.join(root, ...rel.split('/'));
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text.replace(/\n/g, lineEnding));
  };
  write('harness/v2/instrument.json', `${JSON.stringify(config, null, 2)}\n`);
  write('harness/v2/invalidation.json', '{"schemaVersion":1,"currentEpoch":3,"transitions":[]}\n');
  write('harness/v2/measure.sh', '#!/bin/sh\necho measured\n');
  write('harness/shared.mjs', 'export const answer = 1;\n');
  write('harness/results/ignored/results.json', '{"generated":true}\n');
  write('.github/workflows/corpus-v2-runner.yml', 'name: v2\n');
  write('.gitattributes', '* text=auto eol=lf\n');
  return root;
}

test('the canonical harness identity is line-ending stable and excludes generated results', () => {
  const lf = fixture('\n');
  const crlf = fixture('\r\n');
  assert.equal(computeHarnessIdentity(lf).harnessSha256, computeHarnessIdentity(crlf).harnessSha256);
  assert.ok(!instrumentFiles(lf).some((file) => file.startsWith('harness/results/')));
});

test('tracked or untracked harness inputs and workflow config all change the identity', () => {
  const root = fixture();
  const before = computeHarnessIdentity(root).harnessSha256;
  fs.writeFileSync(path.join(root, 'harness', 'v2', 'new-helper.mjs'), 'export default 1;\n');
  const helper = computeHarnessIdentity(root).harnessSha256;
  fs.appendFileSync(path.join(root, '.github', 'workflows', 'corpus-v2-runner.yml'), 'timeout-minutes: 1\n');
  const workflow = computeHarnessIdentity(root).harnessSha256;
  assert.notEqual(helper, before, 'an untracked helper must be part of the instrument');
  assert.notEqual(workflow, helper, 'runner configuration must be part of the instrument');
});

test('resume requires exact instrument and subject identities', () => {
  const current = { harnessEpoch: 3, harnessSha256: 'new' };
  const policy = { currentEpoch: 3, transitions: [] };
  const record = {
    harnessVersion: 2,
    harnessEpoch: 3,
    pkg: 'demo',
    verdict: 'MINIMUM',
    provenance: {
      harnessSha256: 'new', platform: 'linux-x64', node: 'v22.0.0', nubGitSha: 'abc',
      runtime: { node: { sha256: 'node' } }, nubBinary: { sha256: 'nub' },
    },
  };
  assert.equal(recordValidity(record, current, policy, {
    platform: 'linux-x64', nodeVersion: 'v22.0.0', nodeSha256: 'node', nubSha256: 'nub', nubGitSha: 'abc',
  }).reusable, true);
  assert.match(recordValidity(record, current, policy, { nubSha256: 'other' }).reason, /Nub binary/);
  assert.match(recordValidity({ ...record, provenance: { ...record.provenance, harnessSha256: 'old' } },
    current, policy).reason, /transition|match/);
});

test('a malware refusal ignores an unused Nub subject but remains bound to its screening runtime', () => {
  const current = { harnessEpoch: 3, harnessSha256: 'new' };
  const policy = { currentEpoch: 3, transitions: [] };
  const record = {
    harnessVersion: 2,
    harnessEpoch: 3,
    pkg: 'malicious-demo',
    verdict: 'REFUSED-MALICIOUS',
    provenance: {
      harnessSha256: 'new',
      platform: 'linux-x64',
      node: 'v22.0.0',
      runtime: { node: { sha256: 'node-a' } },
    },
  };
  assert.equal(recordValidity(record, current, policy, {
    platform: 'linux-x64',
    nodeVersion: 'v22.0.0',
    nodeSha256: 'node-a',
    nubSha256: 'new-unused-nub',
    nubGitSha: 'new-unused-commit',
  }).reusable, true);
  assert.match(recordValidity(record, current, policy, {
    platform: 'linux-x64', nodeVersion: 'v23.0.0', nodeSha256: 'node-b',
  }).reason, /Node runtime|Node executable/);
});

test('targeted transitions preserve only records outside the declared scope', () => {
  const current = { harnessEpoch: 4, harnessSha256: 'new' };
  const policy = { currentEpoch: 4, transitions: [{
    fromEpoch: 3, fromHarnessSha256: 'old', toEpoch: 4, toHarnessSha256: 'new',
    invalidate: { platforms: ['win32-x64'] }, reason: 'Windows observer changed',
  }] };
  const base = {
    harnessVersion: 2, harnessEpoch: 3, pkg: 'demo', verdict: 'MINIMUM',
    provenance: { harnessSha256: 'old', platform: 'linux-x64' },
  };
  assert.equal(recordValidity(base, current, policy).reusable, true);
  assert.equal(recordValidity({ ...base, provenance: { ...base.provenance, platform: 'win32-x64' } },
    current, policy).reusable, false);
});
