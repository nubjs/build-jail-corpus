import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { cacheKey, runtimeDependencySpecs, verifyBundle, verifyRuntimeDependencies, writeBundleManifest } from './runtime-bundle.mjs';

const identity = (overrides = {}) => ({
  candidateSha: '9d349f7c300a41fd9401d3d3c2e706b2d75c5fff', platform: 'linux', arch: 'x64',
  profile: 'fast', features: ['nub-cli/build-jail-catalog-override'],
  recipeSha256: 'e'.repeat(64), nodeVersion: 'v22.23.2', rustcSha256: 'd'.repeat(64), ...overrides,
});

function bundle(platform = 'linux') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-bundle-'));
  fs.writeFileSync(path.join(root, platform === 'win32' ? 'nub.exe' : 'nub'), 'nub binary');
  fs.mkdirSync(path.join(root, 'runtime', 'addons'), { recursive: true });
  fs.writeFileSync(path.join(root, 'runtime', 'preload.mjs'), 'preload');
  fs.writeFileSync(path.join(root, 'runtime', 'addons', 'nub-native.node'), 'native addon');
  for (const name of ['@js-temporal/polyfill', '@oxc-project/runtime', '@petamoriken/float16', 'jsbi', 'urlpattern-polyfill']) {
    const packageRoot = path.join(root, 'runtime', 'node_modules', name);
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name }));
  }
  if (platform === 'win32') fs.writeFileSync(path.join(root, 'busybox.exe'), 'busybox');
  return root;
}

test('runtime bundle verifies exactly the cached binary, addon, and identity', () => {
  const root = bundle(); const expected = identity();
  const manifest = writeBundleManifest(root, expected);
  assert.equal(verifyBundle(root, expected).files.nub.sha256, manifest.files.nub.sha256);
});

test('runtime bundle rejects missing, corrupted, and wrong-source cache hits', () => {
  const root = bundle(); const expected = identity(); writeBundleManifest(root, expected);
  assert.throws(() => verifyBundle(root, identity({ features: ['different-feature'] })), /identity does not match/);
  fs.rmSync(path.join(root, 'runtime', 'addons', 'nub-native.node'));
  assert.throws(() => verifyBundle(root, expected), /missing/);
  fs.writeFileSync(path.join(root, 'runtime', 'addons', 'nub-native.node'), 'corrupt addon');
  assert.throws(() => verifyBundle(root, expected), /hash does not match/);
  assert.throws(() => verifyBundle(root, identity({ candidateSha: 'a'.repeat(40) })), /identity does not match/);
});

test('runtime bundle refuses sidecar symlinks rather than inheriting files outside the bundle', () => {
  const root = bundle();
  fs.symlinkSync('preload.mjs', path.join(root, 'runtime', 'linked-preload.mjs'));
  assert.throws(() => writeBundleManifest(root, identity()), /contains a symlink/);
});

test('runtime staging resolves exact source-root packages before entering the empty sidecar', () => {
  const source = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-source-'));
  const staged = path.join(source, 'runtime');
  for (const [name, version] of [['@js-temporal/polyfill', '0.5.1'], ['@oxc-project/runtime', '0.140.0'],
    ['@petamoriken/float16', '3.9.3'], ['jsbi', '4.3.2'], ['urlpattern-polyfill', '10.1.0']]) {
    const packageRoot = path.join(source, 'node_modules', name);
    fs.mkdirSync(packageRoot, { recursive: true }); fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name, version }));
    const stagedRoot = path.join(staged, 'node_modules', name);
    fs.mkdirSync(stagedRoot, { recursive: true }); fs.writeFileSync(path.join(stagedRoot, 'package.json'), JSON.stringify({ name, version }));
  }
  const expected = ['@js-temporal/polyfill@0.5.1', '@oxc-project/runtime@0.140.0', '@petamoriken/float16@3.9.3', 'jsbi@4.3.2', 'urlpattern-polyfill@10.1.0'];
  assert.deepEqual(runtimeDependencySpecs(source), expected);
  const cli = spawnSync(process.execPath, [fileURLToPath(new URL('./runtime-bundle.mjs', import.meta.url)), '--runtime-dependency-specs', '--source-root', source], { encoding: 'utf8' });
  assert.equal(cli.status, 0);
  assert.deepEqual(cli.stdout.trim().split('\n'), expected);
  if (process.platform !== 'win32') {
    const workspace = fileURLToPath(new URL('../../', import.meta.url));
    const workflow = fs.readFileSync(path.join(workspace, '.github/workflows/catalog-boundary-artifact-records.yml'), 'utf8');
    const start = workflow.indexOf('            RUNTIME_DEP_SPECS_TEXT=');
    const end = workflow.indexOf('            rm -rf runtime/node_modules', start);
    assert.ok(start >= 0 && end > start, 'the actual workflow staging block must be exercised');
    const script = `set -euo pipefail\n${workflow.slice(start, end)}\nprintf '%s\\n' "\${RUNTIME_DEP_SPECS[@]}"`;
    const env = { ...process.env, GITHUB_WORKSPACE: workspace,
      PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH}` };
    const shell = spawnSync('/bin/bash', ['-c', script], { cwd: source, env, encoding: 'utf8' });
    assert.equal(shell.status, 0, shell.stderr);
    assert.deepEqual(shell.stdout.trim().split('\n'), expected);
    const absent = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime-source-absent-'));
    const failure = spawnSync('/bin/bash', ['-c', script], { cwd: absent, env, encoding: 'utf8' });
    assert.notEqual(failure.status, 0, 'failed dependency resolution must stop before npm arguments are built');
  }
  assert.doesNotThrow(() => verifyRuntimeDependencies(source, staged));
  fs.writeFileSync(path.join(staged, 'node_modules', 'jsbi', 'package.json'), JSON.stringify({ name: 'jsbi', version: '4.3.3' }));
  assert.throws(() => verifyRuntimeDependencies(source, staged), /jsbi differs/);
});

test('Windows bundles require the busybox sidecar and cache keys bind every identity field', () => {
  const root = bundle('win32'); const expected = identity({ platform: 'win32' });
  writeBundleManifest(root, expected);
  assert.doesNotThrow(() => verifyBundle(root, expected));
  fs.rmSync(path.join(root, 'busybox.exe'));
  assert.throws(() => verifyBundle(root, expected), /missing/);
  assert.notEqual(cacheKey(expected), cacheKey(identity({ platform: 'win32', candidateSha: 'b'.repeat(40) })));
  assert.notEqual(cacheKey(expected), cacheKey(identity({ platform: 'win32', recipeSha256: 'f'.repeat(64) })));
  assert.notEqual(cacheKey(expected), cacheKey(identity({ platform: 'win32', features: ['different-feature'] })));
  assert.notEqual(cacheKey(expected), cacheKey(identity({ platform: 'win32', nodeVersion: 'v23.0.0' })));
  assert.notEqual(cacheKey(expected), cacheKey(identity({ platform: 'win32', rustcSha256: 'c'.repeat(64) })));
});

test('CLI write and verify discriminate a # and space script path and fail after corruption', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'runtime bundle # path '));
  const script = path.join(dir, 'runtime-bundle.mjs');
  fs.copyFileSync(new URL('./runtime-bundle.mjs', import.meta.url), script);
  const root = path.join(dir, 'bundle root'); fs.mkdirSync(root);
  fs.writeFileSync(path.join(root, 'nub'), 'nub binary');
  fs.mkdirSync(path.join(root, 'runtime', 'addons'), { recursive: true });
  fs.writeFileSync(path.join(root, 'runtime', 'preload.mjs'), 'preload');
  fs.writeFileSync(path.join(root, 'runtime', 'addons', 'nub-native.node'), 'native addon');
  for (const name of ['@js-temporal/polyfill', '@oxc-project/runtime', '@petamoriken/float16', 'jsbi', 'urlpattern-polyfill']) {
    const packageRoot = path.join(root, 'runtime', 'node_modules', name);
    fs.mkdirSync(packageRoot, { recursive: true });
    fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({ name }));
  }
  const expected = identity();
  const args = ['--root', root, '--candidate-sha', expected.candidateSha, '--platform', expected.platform,
    '--arch', expected.arch, '--profile', expected.profile, '--features', expected.features.join(','),
    '--recipe-sha256', expected.recipeSha256, '--node-version', expected.nodeVersion, '--rustc-sha256', expected.rustcSha256];
  const invoke = (operation) => spawnSync(process.execPath, [script, operation, ...args], { encoding: 'utf8' });
  assert.equal(invoke('--write').status, 0);
  assert.equal(invoke('--verify').status, 0);
  fs.writeFileSync(path.join(root, 'runtime', 'addons', 'nub-native.node'), 'corrupted addon');
  const corrupt = invoke('--verify');
  assert.notEqual(corrupt.status, 0);
  assert.match(corrupt.stderr, /RUNTIME-BUNDLE-ERROR .*hash does not match/);
});
