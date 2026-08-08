import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  loadReferenceProfile,
  referenceEnvironment,
  referenceProfileIdentity,
  validateReferenceProfile,
  writeReferenceProject,
} from './reference-profile.mjs';

test('the checked-in profile deterministically creates the same realistic project for each manager', () => {
  const profile = loadReferenceProfile();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-profile-'));
  writeReferenceProject(root, {
    profile, pkg: '@scope/example', version: '1.2.3', arm: 'nub-unjailed-1', buildJail: false,
    manager: 'npm',
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).dependencies,
    { '@scope/example': '1.2.3' });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'nub.jsonc'), 'utf8')),
    { install: { buildJail: false } });
  assert.ok(fs.existsSync(path.join(root, 'README.md')));
  assert.ok(fs.existsSync(path.join(root, 'src', 'index.js')));
  assert.doesNotMatch(fs.readFileSync(path.join(root, '.npmrc'), 'utf8'), /side-effects-cache/);
  assert.equal(referenceProfileIdentity(profile).sha256.length, 64);
});

test('the Nub fixture disables its private side-effects cache without changing npm configuration', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-nub-fixture-'));
  writeReferenceProject(root, {
    profile: loadReferenceProfile(), pkg: 'example', version: '1.0.0', arm: 'nub-1',
    buildJail: false, manager: 'nub',
  });
  assert.match(fs.readFileSync(path.join(root, '.npmrc'), 'utf8'), /side-effects-cache=false/);
});

test('the arm environment is isolated, scrubs CI and retains no ambient cache or home', () => {
  const profile = loadReferenceProfile();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-env-'));
  const { env, roots } = referenceEnvironment(root, profile, {
    PATH: '/bin', HOME: '/ambient', XDG_CACHE_HOME: '/ambient/cache', CI: '1', GITHUB_ACTIONS: 'true',
    NODE_EXECUTABLE: '/runtime/node', NPM_TOKEN: 'secret', PRIVATE_BUILD_KEY: 'secret',
  });
  assert.equal(env.PATH, `/runtime${path.delimiter}/bin`);
  assert.equal(env.CI, undefined);
  assert.equal(env.GITHUB_ACTIONS, undefined);
  assert.equal(env.HOME, roots.home);
  assert.equal(env.XDG_CACHE_HOME, roots.cache);
  assert.equal(env.npm_config_cache, roots.npmCache);
  assert.equal(env.NODE_COMPAT, '1');
  assert.equal(env.NODE_EXECUTABLE, '/runtime/node');
  assert.equal(env.PATH.split(path.delimiter)[0], '/runtime');
  assert.equal(env.NPM_TOKEN, undefined);
  assert.equal(env.PRIVATE_BUILD_KEY, undefined);
  assert.equal(env.XDG_CONFIG_HOME, roots.config);
});

test('profiles use platform-neutral safe paths and cannot replace generated control files', () => {
  const base = loadReferenceProfile();
  for (const name of ['../outside', 'C:\\outside', 'nested\\outside', '/outside', 'package.json', 'nub.jsonc', '.npmrc']) {
    const profile = structuredClone(base);
    profile.fixture.files[name] = 'bad';
    assert.throws(() => validateReferenceProfile(profile));
  }
  assert.throws(() => validateReferenceProfile({ ...base, id: '../escape' }), /path-safe id/);
});
