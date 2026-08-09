import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  assertReferenceProfilePlatform,
  loadReferenceProfile,
  referenceEnvironment,
  referenceHostCommands,
  referenceHostPathEntries,
  referenceProfileIdentity,
  targetManifest,
  toolProbesForPlatform,
  validateReferenceProfile,
  writeReferenceProject,
} from './reference-profile.mjs';
import { provisionReferenceHost } from './reference-profile-host.mjs';

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

test('the native graphics profile binds its POSIX packages and exact library probes', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-native-graphics.json', import.meta.url));
  assert.equal(profile.id, 'native-graphics-posix-v1');
  assert.deepEqual(profile.supportedPlatforms, ['linux', 'darwin']);
  assert.deepEqual(referenceHostCommands(profile, 'linux')[1].slice(-5),
    ['libcairo2-dev', 'libpango1.0-dev', 'libjpeg-dev', 'libgif-dev', 'librsvg2-dev']);
  assert.match(toolProbesForPlatform(profile, 'linux').map((probe) => probe.join(' ')).join('\n'),
    /pkg-config --modversion pangocairo/);
  assert.match(toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n'),
    /brew list --versions .*jpeg-turbo/);
  assert.throws(() => referenceHostCommands(profile, 'win32'), /does not support win32/);
  assert.equal(referenceProfileIdentity(profile).sha256.length, 64);
});

test('the GNU Make profile activates and probes Homebrew keg-only commands', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-gnu-make-darwin.json', import.meta.url));
  assert.equal(profile.id, 'gnu-make-darwin-v1');
  assert.deepEqual(profile.supportedPlatforms, ['darwin']);
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [['brew', 'install', 'make']]);

  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-make-prefix-'));
  const gnubin = path.join(prefix, 'libexec', 'gnubin');
  fs.mkdirSync(gnubin, { recursive: true });
  const calls = [];
  assert.deepEqual(referenceHostPathEntries(profile, 'darwin', (command, args) => {
    calls.push([command, ...args]);
    return { status: 0, error: null, stdout: `${prefix}\n`, stderr: '' };
  }), [fs.realpathSync(gnubin)]);
  assert.deepEqual(calls, [['brew', '--prefix', 'make']]);
  assert.throws(() => referenceHostPathEntries(profile, 'darwin', () => ({
    status: 1, error: null, stdout: '', stderr: 'unknown formula',
  })), /cannot resolve brew prefix for make: unknown formula/);

  const absentPrefix = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-make-absent-'));
  assert.throws(() => referenceHostPathEntries(profile, 'darwin', () => ({
    status: 0, error: null, stdout: `${absentPrefix}\n`, stderr: '',
  })), /host PATH entry is absent/);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-gnu-make-env-'));
  const { env } = referenceEnvironment(root, profile, {
    PATH: '/usr/bin', NODE_EXECUTABLE: '/runtime/node',
  }, { platform: 'darwin', resolveHostPaths: () => [gnubin] });
  assert.deepEqual(env.PATH.split(path.delimiter), ['/runtime', gnubin, '/usr/bin']);
  assert.match(toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n'),
    /brew list --versions make/);
});

test('the Automake follow-up profile adds only the newly evidenced build prerequisite', () => {
  const profile = loadReferenceProfile(
    new URL('./reference-profile-gnu-make-automake-darwin.json', import.meta.url),
  );
  assert.equal(profile.id, 'gnu-make-automake-darwin-v1');
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [['brew', 'install', 'make', 'automake']]);
  const probes = toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n');
  assert.match(probes, /aclocal --version/);
  assert.match(probes, /brew list --versions make automake/);
});

test('the Libtool follow-up profile proves Homebrew GNU tool aliases', () => {
  const profile = loadReferenceProfile(
    new URL('./reference-profile-gnu-make-automake-libtool-darwin.json', import.meta.url),
  );
  assert.equal(profile.id, 'gnu-make-automake-libtool-darwin-v1');
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [
    ['brew', 'install', 'make', 'automake', 'libtool'],
  ]);
  const probes = toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n');
  assert.match(probes, /glibtool --version/);
  assert.match(probes, /glibtoolize --version/);
  assert.match(probes, /brew list --versions make automake libtool/);
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

test('a profile declares and provisions only its supported host platforms', () => {
  const profile = structuredClone(loadReferenceProfile());
  profile.id = 'native-tools-v1';
  profile.supportedPlatforms = ['linux'];
  profile.hostPackages = { linux: { manager: 'apt', packages: ['libexample-dev'] } };
  profile.toolProbes.linux = [['pkg-config', '--modversion', 'example']];
  assert.deepEqual(referenceHostCommands(profile, 'linux'), [
    ['sudo', 'apt-get', 'update'],
    ['sudo', 'apt-get', 'install', '--yes', '--no-install-recommends', 'libexample-dev'],
  ]);
  assert.deepEqual(toolProbesForPlatform(profile, 'linux').at(-1),
    ['pkg-config', '--modversion', 'example']);
  assert.throws(() => assertReferenceProfilePlatform(profile, 'darwin'), /does not support darwin/);

  const calls = [];
  provisionReferenceHost(profile, 'linux', (command, args) => {
    calls.push([command, ...args]);
    return { status: 0, error: null };
  });
  assert.deepEqual(calls, referenceHostCommands(profile, 'linux'));
  assert.throws(() => provisionReferenceHost(profile, 'linux', () => ({ status: 1, error: null })),
    /host command failed/);
});

test('host package declarations reject shell arguments, manager drift and undeclared platforms', () => {
  const base = loadReferenceProfile();
  for (const hostPackages of [
    { linux: { manager: 'brew', packages: ['libexample'] } },
    { linux: { manager: 'apt', packages: ['--option'] } },
    { solaris: { manager: 'apt', packages: ['libexample'] } },
    { darwin: { manager: 'brew', packages: ['make'], pathPrepend: [{ package: 'other', relative: 'bin' }] } },
    { darwin: { manager: 'brew', packages: ['make'], pathPrepend: [{ package: 'make', relative: '../bin' }] } },
    { darwin: { manager: 'brew', packages: ['make'], pathPrepend: [{ package: 'make', relative: 'bin', extra: true }] } },
  ]) {
    assert.throws(() => validateReferenceProfile({ ...base, hostPackages }), /invalid host packages/);
  }
  assert.throws(() => validateReferenceProfile({ ...base, supportedPlatforms: [] }), /supportedPlatforms/);
});

test('target metadata retains dependency classes needed to explain published lifecycle failures', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-target-metadata-'));
  const packageRoot = path.join(root, 'node_modules', 'example');
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
    name: 'example', version: '1.0.0',
    dependencies: { runtime: '^1.0.0' },
    devDependencies: { husky: '^5.0.0' },
    optionalDependencies: { optional: '^1.0.0' },
    peerDependencies: { peer: '^1.0.0' },
  }));
  assert.deepEqual(targetManifest(root, 'example'), {
    name: 'example', version: '1.0.0', engines: null, os: null, cpu: null, libc: null,
    scripts: {}, dependencies: ['runtime'], devDependencies: ['husky'],
    optionalDependencies: ['optional'], peerDependencies: ['peer'], deprecated: null,
  });
});
