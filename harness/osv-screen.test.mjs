import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  collectInstalledSpecs, collectLockfileIdentity, digestSpecs, queryOsvMalware, screenSpecs, splitSpec,
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

test('screens every isolated virtual-store entry, not only dependencies nested under the target', () => {
  const root = fixture();
  const target = path.join(root, 'node_modules', '.store', 'target@1.0.0', 'node_modules', 'target');
  const transitive = path.join(root, 'node_modules', '.store', 'transitive@2.0.0',
    'node_modules', 'transitive');
  manifest(target, 'target', '1.0.0');
  manifest(transitive, 'transitive', '2.0.0');
  fs.symlinkSync(path.relative(path.join(root, 'node_modules'), target),
    path.join(root, 'node_modules', 'target'), 'dir');
  assert.deepEqual(collectInstalledSpecs(root), ['target@1.0.0', 'transitive@2.0.0']);
  // A package directory that still holds CODE but has lost its manifest must fail closed: it can be
  // executed and cannot be screened. `index.js` is what makes this the fail-closed case rather than
  // the empty-directory case below — removing the manifest alone left the directory EMPTY, which is
  // now legitimately skipped, so this fixture no longer expressed the intent its name gives it.
  fs.rmSync(path.join(transitive, 'package.json'));
  fs.writeFileSync(path.join(transitive, 'index.js'), 'module.exports = 1;\n');
  assert.throws(() => collectInstalledSpecs(root), /cannot read installed manifest/);
  assert.throws(() => collectInstalledSpecs(root), /it holds: index\.js/,
    'the refusal must name what it found, or the next occurrence is another round of theorising');
});

// ⛔ THE EMPTY DIRECTORY IS THE ONE THAT COST MEASUREMENTS. MEASURED on run 33299339164: 4 of the 12
// withheld instrument failures were this screen dying on `node_modules/fsevents/package.json: ENOENT`
// in the npm reference tree — a third of the residual, each one a package that would otherwise have
// produced a verdict. An empty directory holds no code, so nothing can execute from it and there is
// nothing for a vulnerability screen to screen; fail-closed exists to stop an unscreened PACKAGE
// slipping through, and an empty directory is not a package.
//
// The mechanism that creates it is NOT known. `fsevents` is `os: darwin`, and the obvious theory —
// era npm leaving an empty directory for a platform-skipped optional dependency — was tested on npm
// 5.5.1 and 6.4.1 and FALSIFIED: both omit the directory entirely. So the non-empty case above still
// refuses, and now reports its contents, which is what will identify this next time.
test('an empty package directory is skipped, and the rest of the tree is still screened', () => {
  const root = fixture();
  manifest(path.join(root, 'node_modules', 'target'), 'target', '1.0.0');
  fs.mkdirSync(path.join(root, 'node_modules', 'fsevents'), { recursive: true });
  assert.deepEqual(collectInstalledSpecs(root), ['target@1.0.0'],
    'an empty directory must neither throw nor contribute a spec, and must not stop the walk');
});

test('a manifest that exists but does not parse still fails closed', () => {
  const root = fixture();
  manifest(path.join(root, 'node_modules', 'target'), 'target', '1.0.0');
  const broken = path.join(root, 'node_modules', 'broken');
  fs.mkdirSync(broken, { recursive: true });
  fs.writeFileSync(path.join(broken, 'package.json'), '{ this is not json');
  // The ENOENT branch must not swallow a parse failure: that package IS present and IS unscreened.
  assert.throws(() => collectInstalledSpecs(root), /cannot read installed manifest/);
});

test('screens every package in a pnpm virtual store', () => {
  const root = fixture();
  const target = path.join(root, 'node_modules', '.pnpm', 'target@1.0.0',
    'node_modules', 'target');
  const transitive = path.join(root, 'node_modules', '.pnpm', 'transitive@2.0.0',
    'node_modules', 'transitive');
  manifest(target, 'target', '1.0.0');
  manifest(transitive, 'transitive', '2.0.0');
  fs.symlinkSync(path.relative(path.join(root, 'node_modules'), target),
    path.join(root, 'node_modules', 'target'), 'dir');
  assert.deepEqual(collectInstalledSpecs(root), ['target@1.0.0', 'transitive@2.0.0']);
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

test('records exact lockfile identity separately from the resolved tree digest', () => {
  const root = fixture();
  fs.writeFileSync(path.join(root, 'package-lock.json'), '{"lockfileVersion":3}\n');
  fs.writeFileSync(path.join(root, 'nub.lock'), 'version = 1\n');
  const first = collectLockfileIdentity(root);
  assert.equal(first.files.length, 2);
  assert.deepEqual(first.files.map((file) => file.path), ['package-lock.json', 'nub.lock']);
  fs.appendFileSync(path.join(root, 'nub.lock'), 'changed = true\n');
  assert.notEqual(collectLockfileIdentity(root).digest, first.digest);
});
