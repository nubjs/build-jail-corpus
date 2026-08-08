import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  collectInstalledSpecs, digestSpecs, queryOsvMalware, screenSpecs, splitSpec,
} from './osv-screen.mjs';

const fixture = () => fs.mkdtempSync(path.join(os.tmpdir(), 'osv-screen-'));
const manifest = (dir, name, version) => {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version }));
};

test('collects a hoisted tree including scoped and nested package versions', () => {
  const root = fixture();
  manifest(path.join(root, 'node_modules', 'target'), 'target', '1.0.0');
  manifest(path.join(root, 'node_modules', '@scope', 'dep'), '@scope/dep', '2.0.0');
  manifest(path.join(root, 'node_modules', 'target', 'node_modules', 'nested'), 'nested', '3.0.0');
  assert.deepEqual(collectInstalledSpecs(root), ['@scope/dep@2.0.0', 'nested@3.0.0', 'target@1.0.0']);
});

test('follows an isolated-layout symlink once and refuses an unreadable package manifest', () => {
  const root = fixture();
  const store = path.join(root, 'store', 'target');
  manifest(store, 'target', '1.0.0');
  fs.mkdirSync(path.join(root, 'node_modules'), { recursive: true });
  fs.symlinkSync(store, path.join(root, 'node_modules', 'target'), 'dir');
  assert.deepEqual(collectInstalledSpecs(root), ['target@1.0.0']);
  fs.rmSync(path.join(store, 'package.json'));
  assert.throws(() => collectInstalledSpecs(root), /cannot read installed manifest/);
});

test('attributes a transitive MAL advisory to the exact positional query', () => {
  const specs = ['clean-target@1.0.0', '@scope/bad-transitive@2.0.0'];
  const flagged = queryOsvMalware(specs, (queries) => ({
    results: queries.map((q) => q.package.name === '@scope/bad-transitive'
      ? { vulns: [{ id: 'MAL-2025-12345' }, { id: 'GHSA-not-malware' }] } : {}),
  }));
  assert.deepEqual(flagged, [{ spec: '@scope/bad-transitive@2.0.0', ids: ['MAL-2025-12345'] }]);
});

test('refuses a short OSV batch and reuses only an exact clean tree digest', () => {
  assert.throws(() => queryOsvMalware(['a@1.0.0'], () => ({ results: [] })), /returned 0 results/);
  const cacheDir = fixture();
  let calls = 0;
  const request = (queries) => { calls++; return { results: queries.map(() => ({})) }; };
  const first = screenSpecs({ specs: ['a@1.0.0'], kind: 'resolved', cacheDir, request });
  const second = screenSpecs({ specs: ['a@1.0.0'], kind: 'verify', cacheDir, request });
  screenSpecs({ specs: ['a@1.0.1'], kind: 'verify', cacheDir, request });
  assert.equal(first.cacheHit, false);
  assert.equal(second.cacheHit, true);
  assert.equal(calls, 2);
  assert.notEqual(digestSpecs(['a@1.0.0']), digestSpecs(['a@1.0.1']));
  assert.deepEqual(splitSpec('@scope/a@1.2.3'), ['@scope/a', '1.2.3']);
});
