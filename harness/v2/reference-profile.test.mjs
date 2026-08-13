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
  referenceHostPathEnvironment,
  referenceHostPathEntries,
  referenceHostToolchainCommands,
  referenceHostToolchainEnvironment,
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
    profile, pkg: '@scope/example', version: '1.2.3', arm: 'nub-unjailed-1', manager: 'npm',
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).dependencies,
    { '@scope/example': '1.2.3' });
  assert.equal(fs.existsSync(path.join(root, 'nub.jsonc')), false,
    'an unjailed reference must not require jail-only project configuration');
  assert.ok(fs.existsSync(path.join(root, 'README.md')));
  assert.ok(fs.existsSync(path.join(root, 'src', 'index.js')));
  assert.doesNotMatch(fs.readFileSync(path.join(root, '.npmrc'), 'utf8'), /side-effects-cache/);
  assert.equal(referenceProfileIdentity(profile).sha256.length, 64);
});

test('the child-stdio profile changes only platform scope and diagnostic capture', () => {
  const base = loadReferenceProfile();
  const profile = loadReferenceProfile(
    new URL('./reference-profile-child-stdio-linux.json', import.meta.url),
  );
  const expected = structuredClone(base);
  expected.id = 'child-stdio-linux-v1';
  expected.supportedPlatforms = ['linux'];
  expected.diagnostics = { captureChildStdio: true };
  delete expected.toolProbes.win32;
  assert.deepEqual(profile, expected);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-child-stdio-env-'));
  const { env } = referenceEnvironment(root, profile, { PATH: '/usr/bin' }, { platform: 'linux' });
  assert.match(env.NODE_OPTIONS, /--require=.*reference-child-stdio\.cjs$/);
});

test('the Cypress consumer profile adds only the scaffold expected from an ordinary project', () => {
  const base = loadReferenceProfile();
  const profile = loadReferenceProfile(
    new URL('./reference-profile-cypress-consumer.json', import.meta.url),
  );
  const expected = structuredClone(base);
  expected.id = 'cypress-consumer-v1';
  expected.fixture.files['cypress/plugins/.gitkeep'] = '';
  assert.deepEqual(profile, expected);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-cypress-consumer-'));
  writeReferenceProject(root, {
    profile, pkg: 'example', version: '1.0.0', arm: 'nub-1', manager: 'nub',
  });
  assert.ok(fs.existsSync(path.join(root, 'cypress', 'plugins', '.gitkeep')));
});

test('the browser-download-skip profile adds only the standard non-secret opt-out', () => {
  const base = loadReferenceProfile();
  const profile = loadReferenceProfile(
    new URL('./reference-profile-browser-download-skip.json', import.meta.url),
  );
  const expected = structuredClone(base);
  expected.id = 'browser-download-skip-v1';
  expected.supportedPlatforms = ['linux', 'darwin'];
  expected.environment.set.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '1';
  delete expected.toolProbes.win32;
  assert.deepEqual(profile, expected);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-browser-download-skip-'));
  const { env } = referenceEnvironment(root, profile, { PATH: '/usr/bin' }, { platform: 'linux' });
  assert.equal(env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD, '1');
});

test('the lifecycle debug profile changes only platform scope and diagnostic output', () => {
  const base = loadReferenceProfile();
  const profile = loadReferenceProfile(
    new URL('./reference-profile-lifecycle-debug-darwin.json', import.meta.url),
  );
  const expected = structuredClone(base);
  expected.id = 'lifecycle-debug-darwin-v1';
  expected.supportedPlatforms = ['darwin'];
  expected.environment.set.DEBUG = '1';
  delete expected.toolProbes.win32;
  assert.deepEqual(profile, expected);
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

test('the liblzma profile provisions one development library on each POSIX platform', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-liblzma-posix.json', import.meta.url));
  assert.equal(profile.id, 'liblzma-posix-v1');
  assert.deepEqual(profile.supportedPlatforms, ['linux', 'darwin']);
  assert.deepEqual(referenceHostCommands(profile, 'linux')[1].slice(-1), ['liblzma-dev']);
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [['brew', 'install', 'xz']]);
  assert.match(toolProbesForPlatform(profile, 'linux').map((probe) => probe.join(' ')).join('\n'),
    /pkg-config --modversion liblzma/);
  assert.match(toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n'),
    /brew list --versions xz/);
  assert.throws(() => referenceHostCommands(profile, 'win32'), /does not support win32/);
});

test('the liblzma follow-up derives compiler paths from the actual Homebrew prefix', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-liblzma-posix-v2.json', import.meta.url));
  const expected = loadReferenceProfile(new URL('./reference-profile-liblzma-posix.json', import.meta.url));
  expected.id = 'liblzma-posix-v2';
  expected.hostPackages.darwin.environmentPrepend = {
    CPATH: [{ package: 'xz', relative: 'include' }],
    LIBRARY_PATH: [{ package: 'xz', relative: 'lib' }],
    PKG_CONFIG_PATH: [{ package: 'xz', relative: 'lib/pkgconfig' }],
  };
  assert.deepEqual(profile, expected);

  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-xz-prefix-'));
  for (const relative of ['include', 'lib', 'lib/pkgconfig']) {
    fs.mkdirSync(path.join(prefix, relative), { recursive: true });
  }
  const execute = (command, args) => {
    assert.deepEqual([command, ...args], ['brew', '--prefix', 'xz']);
    return { status: 0, error: null, stdout: `${prefix}\n`, stderr: '' };
  };
  assert.deepEqual(referenceHostPathEnvironment(profile, 'darwin', execute), {
    CPATH: [fs.realpathSync(path.join(prefix, 'include'))],
    LIBRARY_PATH: [fs.realpathSync(path.join(prefix, 'lib'))],
    PKG_CONFIG_PATH: [fs.realpathSync(path.join(prefix, 'lib/pkgconfig'))],
  });

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-liblzma-v2-env-'));
  const { env } = referenceEnvironment(root, profile, { PATH: '/usr/bin' }, {
    platform: 'darwin', resolveHostPaths: () => [],
    resolveHostPathEnvironment: () => ({
      CPATH: ['/brew/xz/include'], LIBRARY_PATH: ['/brew/xz/lib'],
      PKG_CONFIG_PATH: ['/brew/xz/lib/pkgconfig'],
    }),
  });
  assert.equal(env.CPATH, '/brew/xz/include');
  assert.equal(env.LIBRARY_PATH, '/brew/xz/lib');
  assert.equal(env.PKG_CONFIG_PATH, '/brew/xz/lib/pkgconfig');
});

test('the X11 profile provisions and probes only the Linux development package', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-x11-linux.json', import.meta.url));
  assert.equal(profile.id, 'x11-linux-v1');
  assert.deepEqual(profile.supportedPlatforms, ['linux']);
  assert.deepEqual(referenceHostCommands(profile, 'linux')[1].slice(-1), ['libx11-dev']);
  assert.match(toolProbesForPlatform(profile, 'linux').map((probe) => probe.join(' ')).join('\n'),
    /pkg-config --modversion x11/);
  assert.throws(() => referenceHostCommands(profile, 'darwin'), /does not support darwin/);
});

test('the expanded X11 profile includes the XKB file development package', () => {
  const profile = loadReferenceProfile(new URL('./reference-profile-x11-linux-v2.json', import.meta.url));
  assert.equal(profile.id, 'x11-linux-v2');
  assert.deepEqual(profile.supportedPlatforms, ['linux']);
  assert.deepEqual(referenceHostCommands(profile, 'linux')[1].slice(-2),
    ['libx11-dev', 'libxkbfile-dev']);
  const probes = toolProbesForPlatform(profile, 'linux').map((probe) => probe.join(' ')).join('\n');
  assert.match(probes, /pkg-config --modversion x11/);
  assert.match(probes, /pkg-config --modversion xkbfile/);
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

test('the Redis downstream-build profile activates LLVM without regenerating checked-in headers', () => {
  const profile = loadReferenceProfile(
    new URL('./reference-profile-redis-build-darwin.json', import.meta.url),
  );
  assert.equal(profile.id, 'redis-build-darwin-v1');
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [
    ['brew', 'install', 'make', 'automake', 'libtool', 'llvm@21'],
  ]);
  assert.equal(profile.environment.set.REDISEARCH_GENERATE_HEADERS, '0');
  assert.deepEqual(profile.hostPackages.darwin.pathPrepend, [
    { package: 'make', relative: 'libexec/gnubin' },
    { package: 'llvm@21', relative: 'bin' },
  ]);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-redis-build-env-'));
  const { env } = referenceEnvironment(root, profile, {
    PATH: '/usr/bin', NODE_EXECUTABLE: '/runtime/node',
  }, { platform: 'darwin', resolveHostPaths: () => ['/homebrew/make', '/homebrew/llvm'] });
  assert.equal(env.REDISEARCH_GENERATE_HEADERS, '0');
  assert.deepEqual(env.PATH.split(path.delimiter),
    ['/runtime', '/homebrew/make', '/homebrew/llvm', '/usr/bin']);
  const probes = toolProbesForPlatform(profile, 'darwin').map((probe) => probe.join(' ')).join('\n');
  assert.match(probes, /brew list --versions make automake libtool llvm@21/);
  assert.match(probes, /clang --version/);
  assert.match(probes, /llvm-config --version/);
});

test('the Redis output-bound follow-up suppresses compiler warnings without hiding build exits', () => {
  const profile = loadReferenceProfile(
    new URL('./reference-profile-redis-build-darwin-v2.json', import.meta.url),
  );
  assert.equal(profile.id, 'redis-build-darwin-v2');
  assert.equal(profile.environment.set.REDISEARCH_GENERATE_HEADERS, '0');
  assert.equal(profile.environment.set.CFLAGS, '-w');
  assert.equal(profile.environment.set.CXXFLAGS, '-w');
  assert.equal(profile.environment.set.MAKEFLAGS, undefined);
  assert.deepEqual(referenceHostCommands(profile, 'darwin'), [
    ['brew', 'install', 'make', 'automake', 'libtool', 'llvm@21'],
  ]);
});

test('the Redis Linux profile pre-provisions exact source-pinned Rust toolchains outside attempt homes', () => {
  const profile = loadReferenceProfile(
    new URL('./reference-profile-redis-build-linux.json', import.meta.url),
  );
  assert.equal(profile.id, 'redis-build-linux-v1');
  assert.deepEqual(profile.supportedPlatforms, ['linux']);
  assert.equal(profile.environment.set.REDISEARCH_GENERATE_HEADERS, '0');
  assert.deepEqual(profile.hostToolchains.linux.rustup, {
    profile: 'minimal', toolchains: ['1.94.0', '1.92.0'],
  });
  assert.deepEqual(referenceHostToolchainCommands(profile, 'linux'), [
    ['rustup', 'toolchain', 'install', '1.94.0', '1.92.0',
      '--profile', 'minimal', '--no-self-update'],
    ['cargo', '+1.94.0', '--version'],
    ['rustc', '+1.94.0', '--version', '--verbose'],
    ['cargo', '+1.92.0', '--version'],
    ['rustc', '+1.92.0', '--version', '--verbose'],
  ]);
  const toolchainEnv = referenceHostToolchainEnvironment(profile, 'linux', { tempDir: '/controlled' });
  const profileRoot = path.dirname(toolchainEnv.RUSTUP_HOME);
  assert.equal(path.basename(toolchainEnv.RUSTUP_HOME), 'rustup');
  assert.equal(path.dirname(profileRoot), path.resolve('/controlled', 'nub-reference-toolchains'));
  assert.match(path.basename(profileRoot), /^redis-build-linux-v1-[a-f0-9]{16}$/);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-redis-linux-env-'));
  const { env, roots } = referenceEnvironment(root, profile, {
    PATH: '/usr/bin', HOME: '/ambient', CARGO_HOME: '/ambient/cargo', RUSTUP_HOME: '/ambient/rustup',
  }, {
    platform: 'linux',
    resolveHostToolchainEnvironment: () => ({ RUSTUP_HOME: '/controlled/rustup' }),
  });
  assert.equal(env.HOME, roots.home);
  assert.equal(env.RUSTUP_HOME, '/controlled/rustup');
  assert.equal(env.CARGO_HOME, undefined);
  assert.match(toolProbesForPlatform(profile, 'linux').map((probe) => probe.join(' ')).join('\n'),
    /cargo \+1\.94\.0 --version[\s\S]*cargo \+1\.92\.0 --version/);
  const provisioned = [];
  provisionReferenceHost(profile, 'linux', (command, args, options) => {
    provisioned.push({ command: [command, ...args], rustupHome: options.env.RUSTUP_HOME });
    return { status: 0, error: null };
  });
  assert.deepEqual(provisioned.map((entry) => entry.command),
    referenceHostToolchainCommands(profile, 'linux'));
  assert.ok(provisioned.every((entry) => /nub-reference-toolchains/.test(entry.rustupHome)));
  assert.throws(() => referenceHostToolchainCommands(profile, 'darwin'), /does not support darwin/);
});

test('the screened exotic-dependency profile changes only Nub source policy', () => {
  const base = loadReferenceProfile();
  const profile = loadReferenceProfile(
    new URL('./reference-profile-screened-exotic-subdeps.json', import.meta.url),
  );
  const expected = structuredClone(base);
  expected.id = 'screened-exotic-subdeps-v1';
  expected.fixture.managerNpmrc.nub.blockExoticSubdeps = 'false';
  assert.deepEqual(profile, expected);

  const nubRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-screened-exotic-nub-'));
  writeReferenceProject(nubRoot, {
    profile, pkg: 'example', version: '1.0.0', arm: 'nub-1', manager: 'nub',
  });
  assert.match(fs.readFileSync(path.join(nubRoot, '.npmrc'), 'utf8'), /blockExoticSubdeps=false/);

  const npmRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-screened-exotic-npm-'));
  writeReferenceProject(npmRoot, {
    profile, pkg: 'example', version: '1.0.0', arm: 'npm-1', manager: 'npm',
  });
  assert.doesNotMatch(fs.readFileSync(path.join(npmRoot, '.npmrc'), 'utf8'), /blockExoticSubdeps/);
});

test('the Nub fixture disables its private side-effects cache without changing npm configuration', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-nub-fixture-'));
  writeReferenceProject(root, {
    profile: loadReferenceProfile(), pkg: 'example', version: '1.0.0', arm: 'nub-1',
    manager: 'nub',
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
  assert.throws(() => validateReferenceProfile({ ...base, diagnostics: { captureChildStdio: 'yes' } }),
    /diagnostics/);
  assert.throws(() => validateReferenceProfile({ ...base, diagnostics: { captureGrandchildren: true } }),
    /diagnostics/);
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
    { darwin: { manager: 'brew', packages: ['xz'], environmentPrepend: { CFLAGS: [{ package: 'xz', relative: 'include' }] } } },
    { darwin: { manager: 'brew', packages: ['xz'], environmentPrepend: { CPATH: [{ package: 'other', relative: 'include' }] } } },
    { darwin: { manager: 'brew', packages: ['xz'], environmentPrepend: { CPATH: [{ package: 'xz', relative: '../include' }] } } },
    { linux: { manager: 'apt', packages: ['liblzma-dev'], environmentPrepend: { CPATH: [{ package: 'liblzma-dev', relative: 'include' }] } } },
  ]) {
    assert.throws(() => validateReferenceProfile({ ...base, hostPackages }), /invalid host packages/);
  }
  assert.throws(() => validateReferenceProfile({ ...base, supportedPlatforms: [] }), /supportedPlatforms/);
});

test('host toolchain declarations accept only exact minimal Rust releases on supported platforms', () => {
  const base = loadReferenceProfile();
  const valid = {
    ...base,
    supportedPlatforms: ['linux'],
    hostToolchains: { linux: { rustup: { profile: 'minimal', toolchains: ['1.94.0'] } } },
  };
  assert.doesNotThrow(() => validateReferenceProfile(valid));
  for (const hostToolchains of [
    [],
    { darwin: { rustup: { profile: 'minimal', toolchains: ['1.94.0'] } } },
    { linux: { rustup: { profile: 'default', toolchains: ['1.94.0'] } } },
    { linux: { rustup: { profile: 'minimal', toolchains: ['stable'] } } },
    { linux: { rustup: { profile: 'minimal', toolchains: ['1.94.0', '1.94.0'] } } },
    { linux: { rustup: { profile: 'minimal', toolchains: ['1.94.0'], components: ['clippy'] } } },
  ]) {
    assert.throws(() => validateReferenceProfile({ ...valid, hostToolchains }),
      /hostToolchains|host toolchains/);
  }
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
