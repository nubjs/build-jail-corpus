import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  collectAuxiliaryLogs,
  collectLifecyclePackages,
  lifecycleEvidence,
  quorumForAttempts,
  referenceEvidenceSha,
  resolveNpmInvocation,
  runManagerAttempt,
  runProcess,
  runReferenceProbe,
} from './reference-probe.mjs';
import { loadReferenceProfile } from './reference-profile.mjs';

const stage = (output = '', exitCode = 0) => ({
  exitCode, timedOut: false, spawnError: null, output,
  error: exitCode ? { summary: output, fingerprint: `fp-${output}` } : null,
});

test('npm is launched through the CLI bundled with the exact target Node', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-npm-runtime-'));
  const targetNode = path.join(root, 'bin', 'node');
  const npmCli = path.join(root, 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js');
  fs.mkdirSync(path.dirname(targetNode), { recursive: true });
  fs.mkdirSync(path.dirname(npmCli), { recursive: true });
  fs.writeFileSync(targetNode, 'node');
  fs.writeFileSync(npmCli, 'npm');
  assert.deepEqual(resolveNpmInvocation(targetNode), {
    command: targetNode, prefixArgs: [npmCli], cliPath: npmCli,
  });
});

test('retry quorum distinguishes stable, unstable and recovered reference outcomes', () => {
  assert.deepEqual(quorumForAttempts([{ outcome: 'pass' }]), { outcome: 'pass', fingerprint: null });
  assert.deepEqual(quorumForAttempts([
    { outcome: 'fail', fingerprint: 'a' }, { outcome: 'fail', fingerprint: 'a' },
  ]), { outcome: 'consistent-failure', fingerprint: 'a' });
  assert.deepEqual(quorumForAttempts([
    { outcome: 'fail', fingerprint: 'a' }, { outcome: 'pass', fingerprint: null },
  ]), { outcome: 'pass-after-failure', fingerprint: null });
  assert.equal(quorumForAttempts([
    { outcome: 'fail', fingerprint: 'a' }, { outcome: 'fail', fingerprint: 'b' },
  ]).outcome, 'unstable');
  assert.deepEqual(quorumForAttempts([
    { outcome: 'fail', fingerprint: 'a' },
    { outcome: 'fail', fingerprint: 'b' },
    { outcome: 'fail', fingerprint: 'a' },
  ]), { outcome: 'consistent-failure', fingerprint: 'a' });
  assert.equal(quorumForAttempts([
    { outcome: 'fail', fingerprint: 'a' }, { outcome: 'timeout', fingerprint: null },
  ]).outcome, 'unstable');
  assert.deepEqual(quorumForAttempts([
    { outcome: 'invalid-tree', fingerprint: 'missing' },
    { outcome: 'invalid-tree', fingerprint: 'missing' },
  ]), { outcome: 'invalid-tree', fingerprint: 'missing' });
});

test('the evidence hash covers the compact record that is stored', () => {
  const record = {
    provenance: {},
    security: { status: 'clean', specs: ['example@1.0.0'] },
    arms: { nubUnjailed: { attempts: [{ stages: { install: { output: 'large log', exitCode: 0 } } }] } },
  };
  const hash = referenceEvidenceSha(record);
  record.provenance.evidenceSha256 = hash;
  assert.equal(referenceEvidenceSha(record), hash);
  record.arms.nubUnjailed.attempts[0].stages.install.exitCode = 1;
  assert.notEqual(referenceEvidenceSha(record), hash);
});

test('process logs retain their beginning and end without allowing unbounded output files', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-output-cap-'));
  const result = await runProcess(process.execPath, ['-e',
    `process.stdout.write('BEGIN\\n' + 'x'.repeat(${9 * 1024 * 1024}) + '\\nEND\\n')`], {
    cwd: root, env: process.env, timeoutMs: 30_000, logBase: path.join(root, 'large'), relativeTo: root,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdoutTruncated, true);
  assert.match(result.output, /^BEGIN\n/);
  assert.match(result.output, /\nEND\n/);
  assert.ok(fs.statSync(path.join(root, 'large.stdout')).size <= 2 * 1024 * 1024);
});

test('failed lifecycle diagnostics written to private log files are retained as evidence', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-auxiliary-log-'));
  const home = path.join(root, 'work', 'home');
  const cache = path.join(root, 'work', 'cache');
  const overflow = path.join(root, 'work', 'overflow');
  const retained = path.join(root, 'records', 'attempts', 'npm-1');
  const log = path.join(home, 'Library', 'Detox', 'ios', 'build', 'detox_ios.log');
  fs.mkdirSync(path.dirname(log), { recursive: true });
  fs.writeFileSync(log, 'xcodebuild: error: unsupported architecture\n');
  fs.writeFileSync(path.join(home, 'unrelated.json'), '{"ignored":true}\n');
  fs.mkdirSync(cache, { recursive: true });
  for (let index = 0; index < 15; index += 1) {
    fs.writeFileSync(path.join(cache, `${String(index).padStart(2, '0')}.log`), `cache log ${index}\n`);
  }
  fs.mkdirSync(overflow, { recursive: true });
  fs.writeFileSync(path.join(overflow, 'omitted.log'), 'overflow log\n');

  const captured = collectAuxiliaryLogs({ home, cache, overflow }, retained, path.join(root, 'records'));
  assert.equal(captured.candidateCount, 17);
  assert.equal(captured.files.length, 16);
  assert.equal(captured.retentionTruncated, true);
  assert.deepEqual(captured.captureFailures, []);
  const detox = captured.files.find((file) => file.sourceRoot === 'home');
  assert.equal(detox.relativePath, 'Library/Detox/ios/build/detox_ios.log');
  assert.match(detox.error.summary, /xcodebuild: error/);
  assert.equal(fs.readFileSync(path.join(root, 'records', detox.retainedPath), 'utf8'),
    'xcodebuild: error: unsupported architecture\n');

  const blocked = path.join(root, 'blocked-retained-root');
  fs.writeFileSync(blocked, 'not a directory');
  const failedCapture = collectAuxiliaryLogs({ home }, blocked, path.join(root, 'records'));
  assert.equal(failedCapture.files.length, 0);
  assert.equal(failedCapture.retentionTruncated, true);
  assert.equal(failedCapture.captureFailures[0].errorCode, 'ENOTDIR');
});

test('lifecycle evidence is manager-specific and counts actual spawn markers', () => {
  assert.equal(lifecycleEvidence('npm', {
    install: stage('> example@1.0.0 postinstall\n> node build.js\n'),
  }, [{ name: 'example', version: '1.0.0', scripts: { postinstall: 'node build.js' } }]).provenCount, 1);
  assert.equal(lifecycleEvidence('nub', {
    approve: stage('DEBUG ran postinstall for example@1.0.0\n'),
  }, [{ name: 'example', version: '1.0.0', scripts: { postinstall: 'node build.js' } }]).provenCount, 1);
});

test('the lifecycle census follows hoisted packages and virtual-store entries', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-census-'));
  const write = (dir, manifest) => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
  };
  write(path.join(root, 'node_modules', 'a'), { name: 'a', version: '1.0.0', scripts: { postinstall: 'node a.js' } });
  write(path.join(root, 'node_modules', '.store', 'b@1', 'node_modules', 'b'),
    { name: 'b', version: '1.0.0', scripts: { install: 'node b.js' } });
  assert.deepEqual(collectLifecyclePackages(root).map((pkg) => pkg.name), ['a', 'b']);
});

test('the lifecycle census includes npm implicit node-gyp installs from binding.gyp', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'implicit-node-gyp-census-'));
  const packageRoot = path.join(root, 'node_modules', 'native-addon');
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
    name: 'native-addon', version: '1.0.0', scripts: { test: 'node test.js' },
  }));
  fs.writeFileSync(path.join(packageRoot, 'binding.gyp'), '{}');
  assert.deepEqual(collectLifecyclePackages(root), [{
    name: 'native-addon',
    version: '1.0.0',
    scripts: { install: 'node-gyp rebuild' },
    implicitLifecycle: ['install'],
  }]);
});

test('an explicit install lifecycle overrides npm implicit node-gyp behavior', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'explicit-node-gyp-census-'));
  const packageRoot = path.join(root, 'node_modules', 'native-addon');
  fs.mkdirSync(packageRoot, { recursive: true });
  fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
    name: 'native-addon', version: '1.0.0', scripts: { install: 'node custom.js' },
  }));
  fs.writeFileSync(path.join(packageRoot, 'binding.gyp'), '{}');
  assert.deepEqual(collectLifecyclePackages(root)[0], {
    name: 'native-addon',
    version: '1.0.0',
    scripts: { install: 'node custom.js' },
    implicitLifecycle: [],
  });
});

test('a manager attempt screens the resolved tree before deleting it and running lifecycle scripts', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-attempt-'));
  const profile = loadReferenceProfile();
  const calls = [];
  let screened = false;
  const execute = async (command, args, options) => {
    calls.push([command, ...args]);
    if (command === '/target/node' && args[0] === '--version') return stage('v18.20.8\n');
    if (args.includes('--ignore-scripts')) {
      const pkgDir = path.join(options.cwd, 'node_modules', 'example');
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({
        name: 'example', version: '1.0.0', scripts: { postinstall: 'node build.js' },
      }));
      return stage();
    }
    if (args[0] === 'install') {
      assert.equal(screened, true, 'ordinary install began before the tree screen');
      assert.equal(fs.existsSync(path.join(options.cwd, 'node_modules')), false,
        'ordinary install did not start from a clean node_modules');
      return stage('WARN ignored build scripts for 1 package(s): example');
    }
    if (args[0] === 'approve-builds') return stage('DEBUG ran postinstall for example@1.0.0');
    return stage();
  };
  const result = await runManagerAttempt({
    manager: 'nub', attempt: 1, pkg: 'example', version: '1.0.0', executable: '/fake/nub',
    profile, root, timeoutMs: 1_000, execute,
    targetNode: '/target/node', targetNodeVersion: 'v18.20.8',
    screenTree(project) {
      assert.ok(fs.existsSync(path.join(project, 'node_modules', 'example', 'package.json')));
      screened = true;
      return { status: 'clean', digest: 'd', specCount: 1, specs: ['example@1.0.0'] };
    },
  });
  assert.equal(result.outcome, 'pass');
  assert.equal(result.lifecycle.provenCount, 1);
  assert.ok(calls.some((call) => call.includes('commit')), 'fixture repository has no initial commit');
  assert.ok(calls.some((call) => call.includes('approve-builds')));
});

test('a Nub attempt approves an implicit binding.gyp lifecycle instead of reporting a false pass', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-implicit-attempt-'));
  const calls = [];
  const execute = async (command, args, options) => {
    calls.push([command, ...args]);
    if (command === '/target/node' && args[0] === '--version') return stage('v18.20.8\n');
    if (args.includes('--ignore-scripts')) {
      const packageRoot = path.join(options.cwd, 'node_modules', 'native-addon');
      fs.mkdirSync(packageRoot, { recursive: true });
      fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({
        name: 'native-addon', version: '1.0.0', scripts: {},
      }));
      fs.writeFileSync(path.join(packageRoot, 'binding.gyp'), '{}');
      return stage();
    }
    if (args[0] === 'install') return stage('WARN ignored build scripts for native-addon');
    if (args[0] === 'approve-builds') {
      fs.writeFileSync(path.join(options.env.HOME, 'native-build.log'), 'compiler: fatal error\n');
      return stage('DEBUG ran install for native-addon@1.0.0\nError: native build failed', 1);
    }
    return stage();
  };
  const result = await runManagerAttempt({
    manager: 'nub', attempt: 1, pkg: 'native-addon', version: '1.0.0', executable: '/fake/nub',
    profile: loadReferenceProfile(), root, timeoutMs: 1_000, execute,
    targetNode: '/target/node', targetNodeVersion: 'v18.20.8',
    screenTree: () => ({ status: 'clean', digest: 'd', specCount: 1, specs: ['native-addon@1.0.0'] }),
  });
  assert.equal(result.outcome, 'fail');
  assert.equal(result.lifecyclePackages[0].scripts.install, 'node-gyp rebuild');
  assert.equal(result.auxiliaryLogs.files[0].relativePath, 'native-build.log');
  assert.ok(calls.some((call) => call.includes('approve-builds')));
});

test('a successful preflight that did not install the exact target cannot become a green reference', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-missing-target-'));
  const result = await runManagerAttempt({
    manager: 'npm', attempt: 1, pkg: 'example', version: '1.0.0', executable: 'npm',
    profile: loadReferenceProfile(), root, timeoutMs: 1_000,
    targetNode: '/target/node', targetNodeVersion: 'v18.20.8',
    execute: async (command, args) => command === '/target/node' && args[0] === '--version'
      ? stage('v18.20.8\n') : stage(),
    screenTree: () => ({ status: 'clean', digest: 'd', specCount: 0, specs: [] }),
  });
  assert.equal(result.outcome, 'invalid-tree');
  assert.match(result.stages.target.error.summary, /TARGET-NOT-INSTALLED/);
});

test('an exhausted batch deadline stops before spawning the next stage', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-deadline-'));
  let spawned = false;
  const result = await runManagerAttempt({
    manager: 'npm', attempt: 1, pkg: 'example', version: '1.0.0', executable: 'npm',
    profile: loadReferenceProfile(), root, timeoutMs: 30_000, deadlineMs: Date.now() - 1,
    execute: async () => { spawned = true; return stage(); },
  });
  assert.equal(spawned, false);
  assert.equal(result.outcome, 'timeout');
  assert.equal(result.stages.runtime.timedOut, true);
});

test('an unexpected per-package exception becomes a durable harness classification', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-probe-error-'));
  const record = await runReferenceProbe({
    pkg: 'example', version: '1.0.0', nub: '/fake/nub', outRoot: root,
    profile: loadReferenceProfile(), workRoot: path.join(root, 'work'),
    staticProvenance: {
      instrument: { harnessEpoch: 3, harnessSha256: 'test' },
      runtime: { node: { version: process.version }, os: { platform: process.platform, arch: process.arch } },
      toolchain: {}, nub: null, npm: null,
    },
    directScreen: () => ({ status: 'clean', digest: 'd', specCount: 1 }),
    execute: async () => { throw new Error('synthetic execution failure'); },
  });
  assert.equal(record.classification.code, 'HARNESS_INTERNAL');
  assert.equal(record.classification.status, 'incomplete');
  assert.deepEqual(record.profile.supportedPlatforms, ['linux', 'darwin', 'win32']);
  assert.deepEqual(record.profile.hostPackages, {});
  assert.deepEqual(record.profile.hostToolchains, {});
  assert.ok(record.profile.toolProbes.common.length > 0);
  assert.match(record.provenance.probeError.summary, /synthetic execution failure/);
  assert.ok(fs.existsSync(path.join(root, 'reference.json')));
});

test('lifecycle proof treats a semver v-prefix as the same installed version', () => {
  const evidence = lifecycleEvidence('npm', {
    install: stage('> @scope/example@1.2.3 install\n> node install.js\n'),
  }, [{ name: '@scope/example', version: 'v1.2.3', scripts: { install: 'node install.js' } }]);
  assert.equal(evidence.provenCount, 1);
  assert.deepEqual(evidence.missingMarkers, []);
});
