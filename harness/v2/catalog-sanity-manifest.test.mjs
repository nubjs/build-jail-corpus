import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./catalog-sanity-manifest.mjs', import.meta.url));

test('records hashes for the exact catalog, subjects, and fixture instruments', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-sanity-manifest-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const args = ['catalog', 'candidate-bin', 'candidate-addon', 'baseline-bin', 'baseline-addon', 'packages', 'network', 'relocated-store', 'instrument', 'instrument-output', 'workflow', 'manifest-helper', 'subject-helper', 'budget-helper', 'environment']
    .flatMap((name) => {
      const file = path.join(root, name);
      fs.writeFileSync(file, name);
      return [`--${name}`, file];
    });
  const out = path.join(root, 'reports', 'manifest.json');
  const sha = '0123456789abcdef0123456789abcdef01234567';
  execFileSync(process.execPath, [script, '--out', out, '--corpus-sha', sha, '--candidate-source-sha', sha, '--baseline-source-sha', sha, ...args]);
  const manifest = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(manifest.corpusSha, sha);
  assert.equal(manifest.files.catalog.bytes, 'catalog'.length);
  assert.match(manifest.files.network.sha256, /^[a-f0-9]{64}$/);
  assert.match(manifest.files.environment.sha256, /^[a-f0-9]{64}$/);
});
