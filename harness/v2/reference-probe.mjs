// Differential unjailed-install probe. This establishes whether a package works through Nub and
// npm before any jail capability is inferred. Every lifecycle boundary is preceded by an exact
// resolved-tree OSV screen; ordinary installs then start from an absent node_modules tree.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { collectInstalledSpecs, collectLockfileIdentity, screenSpecs } from '../osv-screen.mjs';
import { computeHarnessIdentity } from './instrument.mjs';
import { classifyReference, firstErrorFrom } from './reference-classify.mjs';
import {
  DEFAULT_REFERENCE_PROFILE,
  loadReferenceProfile,
  referenceEnvironment,
  referenceProfileIdentity,
  targetManifest,
  toolProbesForPlatform,
  writeReferenceProject,
} from './reference-profile.mjs';
import { collectRuntimeProvenance, fileIdentity, probeNodeRuntime, probeTool } from './runtime-provenance.mjs';

const MAX_CAPTURE = 2 * 1024 * 1024;
const CAPTURE_HEAD = 256 * 1024;

export function resolveNpmInvocation(targetNode, npm = 'npm') {
  if (npm !== 'npm') return { command: npm, prefixArgs: [], cliPath: null };
  const nodeDir = path.dirname(targetNode);
  const candidates = [
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.resolve(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  const cliPath = candidates.find((candidate) => fs.existsSync(candidate));
  if (!cliPath) throw new Error(`could not locate the npm CLI bundled with target Node ${targetNode}`);
  return { command: targetNode, prefixArgs: [cliPath], cliPath };
}

const probeNpm = (targetNode, npm) => {
  const invocation = resolveNpmInvocation(targetNode, npm);
  const probe = probeTool(invocation.command, [...invocation.prefixArgs, '--version']);
  if (!probe) throw new Error(`could not execute npm through target Node ${targetNode}`);
  return {
    ...probe,
    cli: fileIdentity(invocation.cliPath),
    invocation: [invocation.command, ...invocation.prefixArgs],
  };
};

const compactSecurity = (security) => {
  if (!security) return security;
  const { specs: _, ...compact } = security;
  return compact;
};

const stripCapturedOutput = (record) => {
  record.security = compactSecurity(record.security);
  for (const arm of Object.values(record.arms ?? {})) {
    for (const attempt of arm.attempts ?? []) {
      attempt.security = compactSecurity(attempt.security);
      for (const stage of Object.values(attempt.stages ?? {})) delete stage.output;
    }
  }
};

export function referenceEvidenceSha(record) {
  const compact = structuredClone(record);
  stripCapturedOutput(compact);
  if (compact.provenance) delete compact.provenance.evidenceSha256;
  return crypto.createHash('sha256').update(`${JSON.stringify(compact)}\n`).digest('hex');
}

const appendBounded = (prior, chunk) => {
  const next = prior + chunk;
  return next.length <= MAX_CAPTURE ? next
    : next.slice(0, CAPTURE_HEAD) + next.slice(-(MAX_CAPTURE - CAPTURE_HEAD));
};

export async function runProcess(command, args, {
  cwd, env, timeoutMs, logBase, relativeTo = path.dirname(logBase),
} = {}) {
  fs.mkdirSync(path.dirname(logBase), { recursive: true });
  const stdoutPath = `${logBase}.stdout`;
  const stderrPath = `${logBase}.stderr`;
  const startedAt = new Date().toISOString();
  const before = Date.now();
  let stdout = ''; let stderr = ''; let stdoutBytes = 0; let stderrBytes = 0;
  let timedOut = false; let spawnError = null;

  const result = await new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd, env, windowsHide: true, detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.stdout.on('data', (chunk) => {
      stdoutBytes += chunk.length;
      stdout = appendBounded(stdout, chunk.toString());
    });
    child.stderr.on('data', (chunk) => {
      stderrBytes += chunk.length;
      stderr = appendBounded(stderr, chunk.toString());
    });
    child.on('error', (error) => { spawnError = error; });
    const timer = setTimeout(() => {
      timedOut = true;
      if (process.platform === 'win32' && child.pid) {
        spawn('taskkill.exe', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
      } else if (child.pid) {
        try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
        setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }, 2_000).unref();
      }
    }, timeoutMs).unref();
    child.on('close', (status, signal) => {
      clearTimeout(timer);
      resolve({ status, signal });
    });
  });
  fs.writeFileSync(stdoutPath, stdout);
  fs.writeFileSync(stderrPath, stderr);
  const output = `${stdout}\n${stderr}`;
  const roots = { project: cwd, home: env?.HOME, temp: env?.TMPDIR, cache: env?.XDG_CACHE_HOME };
  return {
    command: [command, ...args],
    startedAt,
    durationMs: Date.now() - before,
    exitCode: result.status,
    signal: result.signal,
    timedOut,
    spawnError: spawnError?.message ?? null,
    stdoutPath: path.relative(relativeTo, stdoutPath).split(path.sep).join('/'),
    stderrPath: path.relative(relativeTo, stderrPath).split(path.sep).join('/'),
    stdoutBytes,
    stderrBytes,
    stdoutTruncated: stdoutBytes > Buffer.byteLength(stdout),
    stderrTruncated: stderrBytes > Buffer.byteLength(stderr),
    error: result.status === 0 && !timedOut && !spawnError ? null : firstErrorFrom(output, roots),
    output,
  };
}

const lifecycleHooks = ['preinstall', 'install', 'postinstall'];
const normalizeLifecycleVersion = (version) => /^v\d+\./.test(version) ? version.slice(1) : version;

export function collectLifecyclePackages(projectRoot) {
  const packages = new Map();
  const visitedPackages = new Set();
  const visitedModules = new Set();
  const real = (value) => { try { return fs.realpathSync(value); } catch { return null; } };

  const visitPackage = (pkgDir) => {
    const physical = real(pkgDir);
    if (!physical || visitedPackages.has(physical)) return;
    visitedPackages.add(physical);
    let manifest;
    try { manifest = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')); } catch { return; }
    const scripts = Object.fromEntries(lifecycleHooks
      .filter((hook) => typeof manifest.scripts?.[hook] === 'string')
      .map((hook) => [hook, manifest.scripts[hook]]));
    const implicitNodeGyp = !scripts.preinstall && !scripts.install
      && fs.existsSync(path.join(pkgDir, 'binding.gyp'));
    if (implicitNodeGyp) scripts.install = 'node-gyp rebuild';
    if (manifest.name && manifest.version && Object.keys(scripts).length) {
      packages.set(`${manifest.name}@${manifest.version}`, {
        name: manifest.name,
        version: manifest.version,
        scripts,
        implicitLifecycle: implicitNodeGyp ? ['install'] : [],
      });
    }
    visitModules(path.join(pkgDir, 'node_modules'));
  };
  const visitModules = (modulesDir) => {
    const physical = real(modulesDir);
    if (!physical || visitedModules.has(physical)) return;
    visitedModules.add(physical);
    let entries;
    try { entries = fs.readdirSync(modulesDir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const entryPath = path.join(modulesDir, entry.name);
      if (entry.name.startsWith('@')) {
        let scoped = [];
        try { scoped = fs.readdirSync(entryPath, { withFileTypes: true }); } catch { /* ignore */ }
        for (const child of scoped) if (!child.name.startsWith('.')) visitPackage(path.join(entryPath, child.name));
      } else visitPackage(entryPath);
    }
  };

  visitModules(path.join(projectRoot, 'node_modules'));
  for (const storeName of ['.store', '.nub']) {
    const store = path.join(projectRoot, 'node_modules', storeName);
    let entries = [];
    try { entries = fs.readdirSync(store, { withFileTypes: true }); } catch { /* absent */ }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const entryPath = path.join(store, entry.name);
      if (entry.name === 'node_modules') visitModules(entryPath);
      else visitModules(path.join(entryPath, 'node_modules'));
    }
  }
  return [...packages.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

export function lifecycleEvidence(manager, stages, expected) {
  const output = Object.values(stages).map((stage) => stage?.output ?? '').join('\n');
  const marker = (spec, hook) => {
    const at = spec.lastIndexOf('@');
    return `${spec.slice(0, at + 1)}${normalizeLifecycleVersion(spec.slice(at + 1))}:${hook}`;
  };
  const observed = manager === 'npm'
    ? [...output.matchAll(/^>\s+([^\s]+@[^\s]+)\s+(preinstall|install|postinstall)\b/gm)]
      .map((match) => marker(match[1], match[2]))
    : [...output.matchAll(/ran\s+(preinstall|install|postinstall)\s+for\s+([^\s]+@[^\s]+)/gm)]
      .map((match) => marker(match[2], match[1]));
  const expectedMarkers = expected.flatMap((entry) => Object.keys(entry.scripts)
    .map((hook) => marker(`${entry.name}@${entry.version}`, hook)));
  const observedSet = new Set(observed);
  const missingMarkers = expectedMarkers.filter((marker) => !observedSet.has(marker));
  const fullyProven = expected.filter((entry) => Object.keys(entry.scripts)
    .every((hook) => observedSet.has(marker(`${entry.name}@${entry.version}`, hook))));
  return {
    expectedCount: expected.length,
    expectedHookCount: expectedMarkers.length,
    provenCount: fullyProven.length,
    provenHookCount: expectedMarkers.length - missingMarkers.length,
    markers: [...observedSet].sort().slice(0, 200),
    missingMarkers: missingMarkers.slice(0, 200),
    method: manager === 'npm' ? 'foreground-script package headers' : 'Nub completed package-hook markers',
  };
}

export function quorumForAttempts(attempts) {
  if (!attempts.length) return { outcome: 'harness-error', fingerprint: null };
  if (attempts.some((attempt) => attempt.outcome === 'refused-malicious')) {
    return { outcome: 'refused-malicious', fingerprint: null };
  }
  const passes = attempts.filter((attempt) => attempt.outcome === 'pass');
  if (passes.length) return { outcome: attempts[0].outcome === 'pass' ? 'pass' : 'pass-after-failure', fingerprint: null };
  if (attempts.every((attempt) => attempt.outcome === 'timeout')) return { outcome: 'timeout', fingerprint: null };
  if (attempts.some((attempt) => attempt.outcome === 'harness-error')) return { outcome: 'harness-error', fingerprint: null };
  const counts = new Map();
  for (const attempt of attempts) {
    if (!attempt.fingerprint) continue;
    const key = `${attempt.outcome}\0${attempt.fingerprint}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const [dominantKey, dominantCount] = ranked[0] ?? ['', 0];
  const [dominantOutcome, dominantFingerprint] = dominantKey.split('\0');
  if (dominantCount > attempts.length / 2) {
    if (dominantOutcome === 'invalid-tree') return { outcome: 'invalid-tree', fingerprint: dominantFingerprint };
    if (dominantOutcome === 'fail') return { outcome: 'consistent-failure', fingerprint: dominantFingerprint };
  }
  const fingerprints = [...new Set(attempts.map((attempt) => attempt.fingerprint).filter(Boolean))];
  return { outcome: 'unstable', fingerprint: fingerprints.length ? fingerprints.join(',') : null };
}

const realScreenTree = (project, kind, cacheDir, out) => {
  const specs = collectInstalledSpecs(project);
  return screenSpecs({ specs, kind, cacheDir, out, lockfiles: collectLockfileIdentity(project) });
};

const stageOk = (stage) => stage && stage.exitCode === 0 && !stage.timedOut && !stage.spawnError;
const terminalStage = (stages) => stages.approve ?? stages.install ?? stages.preflight
  ?? stages.fixture ?? stages.fixtureAdd ?? stages.fixtureInit ?? stages.runtime;

export async function runManagerAttempt({
  manager, attempt, pkg, version, executable, profile, root, recordRoot = root, workRoot = root, timeoutMs,
  deadlineMs = Infinity,
  targetNode = process.env.NODE_EXECUTABLE ?? process.execPath,
  targetNodeVersion = process.version,
  execute = runProcess, screenTree = realScreenTree,
  securityCacheDir = path.join(recordRoot, 'osv-cache'),
}) {
  const invocation = Array.isArray(executable)
    ? { command: executable[0], prefixArgs: executable.slice(1) }
    : { command: executable, prefixArgs: [] };
  const attemptRoot = path.join(workRoot, 'attempts', `${manager}-${attempt}`);
  const retainedRoot = path.join(recordRoot, 'attempts', `${manager}-${attempt}`);
  const project = path.join(attemptRoot, 'project');
  fs.rmSync(retainedRoot, { recursive: true, force: true });
  writeReferenceProject(project, {
    profile, pkg, version, arm: `${manager}-${attempt}`, buildJail: false, manager,
  });
  const { env, roots } = referenceEnvironment(attemptRoot, profile);
  env.NODE_EXECUTABLE = targetNode;
  const targetNodeDir = path.dirname(targetNode);
  if (env.PATH?.split(path.delimiter)[0] !== targetNodeDir) {
    env.PATH = [targetNodeDir, env.PATH].filter(Boolean).join(path.delimiter);
  }
  if (manager === 'nub') env.RUST_LOG = 'warn,aube::commands::install::lifecycle=debug';
  const stages = {};
  const run = (name, command, args) => {
    const remaining = deadlineMs - Date.now();
    const logBase = path.join(retainedRoot, name);
    if (remaining <= 0) {
      fs.mkdirSync(path.dirname(logBase), { recursive: true });
      fs.writeFileSync(`${logBase}.stdout`, '');
      fs.writeFileSync(`${logBase}.stderr`, 'REFERENCE-DEADLINE-REACHED\n');
      return Promise.resolve({
        command: [command, ...args], startedAt: new Date().toISOString(), durationMs: 0,
        exitCode: null, signal: null, timedOut: true, spawnError: null,
        stdoutPath: path.relative(recordRoot, `${logBase}.stdout`).split(path.sep).join('/'),
        stderrPath: path.relative(recordRoot, `${logBase}.stderr`).split(path.sep).join('/'),
        stdoutBytes: 0, stderrBytes: 27, stdoutTruncated: false, stderrTruncated: false,
        error: firstErrorFrom('REFERENCE-DEADLINE-REACHED'), output: '\nREFERENCE-DEADLINE-REACHED\n',
      });
    }
    return execute(command, args, {
      cwd: project, env, timeoutMs: Math.min(timeoutMs, remaining), logBase, relativeTo: recordRoot,
    });
  };

  stages.runtime = await run('runtime', targetNode, ['--version']);
  const actualRuntime = stages.runtime.output.trim().split(/\r?\n/)[0];
  if (!stageOk(stages.runtime) || actualRuntime !== targetNodeVersion) {
    stages.runtime.error ??= firstErrorFrom(`RUNTIME-MISMATCH expected ${targetNodeVersion} got ${actualRuntime || '(none)'}`);
    return { manager, attempt, outcome: stages.runtime.timedOut ? 'timeout' : 'harness-error',
      fingerprint: stages.runtime.error.fingerprint,
      stages, roots, packageMetadata: null, lifecyclePackages: [], security: null };
  }

  if (profile.fixture.gitRepository) {
    for (const [name, args] of [
      ['fixtureInit', ['init', '--quiet']],
      ['fixtureAdd', ['add', '--all']],
      ['fixture', ['-c', 'user.name=Nub corpus', '-c', 'user.email=corpus@example.invalid',
        'commit', '--quiet', '--no-gpg-sign', '-m', 'fixture']],
    ]) {
      if (name === 'fixture') {
        env.GIT_AUTHOR_DATE = '2000-01-01T00:00:00Z';
        env.GIT_COMMITTER_DATE = '2000-01-01T00:00:00Z';
      }
      stages[name] = await run(name, 'git', args);
      delete env.GIT_AUTHOR_DATE;
      delete env.GIT_COMMITTER_DATE;
      if (!stageOk(stages[name])) {
        const terminal = terminalStage(stages);
        return { manager, attempt, outcome: terminal.timedOut ? 'timeout' : 'fail', fingerprint: terminal.error?.fingerprint ?? null,
          stages, roots, packageMetadata: null, lifecyclePackages: [], security: null };
      }
    }
  }

  const preflightArgs = manager === 'npm'
    ? ['install', '--ignore-scripts', '--no-audit', '--no-fund'] : ['install', '--ignore-scripts'];
  stages.preflight = await run('preflight', invocation.command, [...invocation.prefixArgs, ...preflightArgs]);
  if (!stageOk(stages.preflight)) {
    const terminal = terminalStage(stages);
    return { manager, attempt, outcome: terminal.timedOut ? 'timeout' : 'fail', fingerprint: terminal.error?.fingerprint ?? null,
      stages, roots, packageMetadata: null, lifecyclePackages: [], security: null };
  }

  let security;
  try {
    security = screenTree(project, `${manager}-reference-resolved`, securityCacheDir,
      path.join(retainedRoot, 'clearance.json'));
  } catch (error) {
    stages.security = { error: firstErrorFrom(`OSV-SCREEN-ERROR ${error.message}`, { project, ...roots }) };
    return { manager, attempt, outcome: 'harness-error', fingerprint: stages.security.error.fingerprint,
      stages, roots, packageMetadata: null, lifecyclePackages: [], security: null };
  }
  if (security.status !== 'clean') {
    return { manager, attempt, outcome: 'refused-malicious', fingerprint: null, stages, roots,
      packageMetadata: null, lifecyclePackages: [], security };
  }
  const packageMetadata = targetManifest(project, pkg);
  const lifecyclePackages = collectLifecyclePackages(project);
  if (packageMetadata?.name !== pkg || normalizeLifecycleVersion(packageMetadata?.version ?? '')
    !== normalizeLifecycleVersion(version)) {
    const output = `TARGET-NOT-INSTALLED expected ${pkg}@${version} got ${packageMetadata?.name ?? '(missing)'}@${packageMetadata?.version ?? '(missing)'}`;
    stages.target = { exitCode: null, signal: null, timedOut: false, spawnError: null,
      error: firstErrorFrom(output, { project, ...roots }), output };
    return { manager, attempt, outcome: 'invalid-tree', fingerprint: stages.target.error.fingerprint,
      stages, roots, packageMetadata, lifecyclePackages, security };
  }
  fs.rmSync(path.join(project, 'node_modules'), { recursive: true, force: true });

  const installArgs = manager === 'npm'
    ? ['install', '--no-audit', '--no-fund', '--foreground-scripts'] : ['install'];
  stages.install = await run('install', invocation.command, [...invocation.prefixArgs, ...installArgs]);
  if (manager === 'nub' && stageOk(stages.install) && lifecyclePackages.length > 0) {
    stages.approve = await run('approve', invocation.command, [...invocation.prefixArgs, 'approve-builds', '--all']);
  }
  const terminal = terminalStage(stages);
  const ok = stageOk(stages.install) && (!stages.approve || stageOk(stages.approve));
  return {
    manager,
    attempt,
    outcome: ok ? 'pass' : terminal.timedOut ? 'timeout' : 'fail',
    fingerprint: ok ? null : terminal.error?.fingerprint ?? null,
    stages,
    roots,
    packageMetadata,
    lifecyclePackages,
    lifecycle: lifecycleEvidence(manager, stages, lifecyclePackages),
    security,
  };
}

const shouldRetry = (attempts, maxAttempts) => {
  if (attempts.length >= maxAttempts) return false;
  if (attempts.at(-1)?.outcome === 'refused-malicious') return false;
  if (attempts[0]?.outcome === 'pass') return false;
  if (attempts.length < 2) return true;
  const quorum = quorumForAttempts(attempts);
  return quorum.outcome === 'unstable' && attempts.length < maxAttempts;
};

export const collectToolchain = (profile, nub) => ({
  nub: { ...probeTool(nub), executable: fileIdentity(nub) },
  probes: toolProbesForPlatform(profile).map(([command, ...args]) => ({
    requested: [command, ...args], result: probeTool(command, args),
  })),
});

export const collectReferenceProvenance = (
  profile, nub, npm = 'npm', nubGitSha = null,
  targetNode = process.env.NODE_EXECUTABLE ?? process.execPath,
) => {
  const orchestrator = collectRuntimeProvenance();
  return {
    instrument: computeHarnessIdentity(),
    orchestrator,
    runtime: {
      node: probeNodeRuntime(targetNode),
      os: orchestrator.os,
      runner: orchestrator.runner,
      environment: orchestrator.environment,
    },
    toolchain: collectToolchain(profile, nub),
    nub: { ...fileIdentity(nub), gitSha: nubGitSha },
    npm: probeNpm(targetNode, npm),
  };
};

export async function runReferenceProbe({
  pkg, version, nub, npm = 'npm', outRoot, profile = loadReferenceProfile(), maxAttempts = 3,
  profilePath = DEFAULT_REFERENCE_PROFILE,
  workRoot = null,
  timeoutMs = 15 * 60_000, execute = runProcess,
  deadlineMs = Infinity,
  nubGitSha = null,
  targetNode = process.env.NODE_EXECUTABLE ?? process.execPath,
  staticProvenance = null,
  source = null,
  securityCacheDir = path.join(outRoot, 'osv-cache'),
  directScreen = ({ spec, cacheDir, out }) => screenSpecs({ specs: [spec], kind: 'direct', cacheDir, out }),
  screenTree = realScreenTree,
}) {
  if (!pkg || !version || !nub || !outRoot) throw new Error('pkg, version, nub and outRoot are required');
  fs.mkdirSync(outRoot, { recursive: true });
  const ownedWorkRoot = workRoot == null;
  const scratchRoot = workRoot ?? fs.mkdtempSync(path.join(os.tmpdir(), 'nub-reference-'));
  const persist = () => {
    record.provenance.finishedAt ??= new Date().toISOString();
    stripCapturedOutput(record);
    record.provenance.evidenceSha256 = referenceEvidenceSha(record);
    fs.writeFileSync(path.join(outRoot, 'reference.json'), `${JSON.stringify(record, null, 2)}\n`);
    if (ownedWorkRoot) fs.rmSync(scratchRoot, { recursive: true, force: true });
    return record;
  };
  const captured = staticProvenance ?? collectReferenceProvenance(profile, nub, npm, nubGitSha, targetNode);
  const instrument = captured.instrument;
  const runtime = captured.runtime;
  const repositoryRoot = path.resolve(import.meta.dirname, '..', '..');
  const profileSource = path.relative(repositoryRoot, path.resolve(profilePath));
  if (profileSource === '..' || profileSource.startsWith(`..${path.sep}`) || path.isAbsolute(profileSource)) {
    throw new Error('reference profiles must be versioned inside the corpus repository');
  }
  const record = {
    schemaVersion: 1,
    pkg,
    version,
    status: 'running',
    profile: {
      ...referenceProfileIdentity(profile),
      source: profileSource.split(path.sep).join('/'),
      fixture: profile.fixture,
      environment: profile.environment,
    },
    security: null,
    arms: {},
    lifecycle: { expectedCount: 0 },
    packageMetadata: null,
    classification: null,
    source,
    provenance: {
      instrument,
      orchestrator: captured.orchestrator,
      runtime,
      toolchain: captured.toolchain,
      nub: captured.nub,
      npm: captured.npm,
      startedAt: new Date().toISOString(),
    },
  };

  try {
    record.security = directScreen({
      spec: `${pkg}@${version}`,
      cacheDir: securityCacheDir,
      out: path.join(outRoot, 'direct-clearance.json'),
    });
  } catch (error) {
    record.status = 'harness-error';
    record.security = { status: 'error', error: firstErrorFrom(`OSV-SCREEN-ERROR ${error.message}`) };
    record.classification = classifyReference(record);
    return persist();
  }
  if (record.security.status !== 'clean') {
    record.status = 'refused-malicious';
    record.classification = classifyReference(record);
    return persist();
  }

  try {
    const npmInvocation = resolveNpmInvocation(targetNode, npm);
    for (const [key, manager, executable] of [
      ['nubUnjailed', 'nub', nub],
      ['npmUnjailed', 'npm', [npmInvocation.command, ...npmInvocation.prefixArgs]],
    ]) {
      const attempts = [];
      do {
        attempts.push(await runManagerAttempt({ manager, attempt: attempts.length + 1, pkg, version,
          executable, profile, recordRoot: outRoot, workRoot: scratchRoot, timeoutMs, deadlineMs,
          targetNode, targetNodeVersion: runtime.node.version, execute, screenTree,
          securityCacheDir }));
      } while (shouldRetry(attempts, maxAttempts));
      const lastWithMetadata = [...attempts].reverse().find((attempt) => attempt.packageMetadata);
      const lastLifecycle = [...attempts].reverse().find((attempt) => attempt.lifecycle);
      record.arms[key] = {
        executable: manager === 'nub' ? fileIdentity(nub) : captured.npm,
        attempts,
        quorum: quorumForAttempts(attempts),
        packageMetadata: lastWithMetadata?.packageMetadata ?? null,
        lifecycle: lastLifecycle?.lifecycle ?? { expectedCount: 0, provenCount: 0, markers: [], method: null },
      };
      if (record.arms[key].quorum.outcome === 'refused-malicious') break;
    }
  } catch (error) {
    record.status = 'harness-error';
    record.provenance.probeError = firstErrorFrom(error.stack ?? `Error: ${error.message}`,
      { work: scratchRoot });
    record.classification = classifyReference(record);
    return persist();
  }

  const metadataArm = record.arms.nubUnjailed?.packageMetadata ? record.arms.nubUnjailed : record.arms.npmUnjailed;
  record.packageMetadata = metadataArm?.packageMetadata ?? null;
  record.lifecycle.expectedCount = Math.max(0,
    ...Object.values(record.arms).map((arm) => arm.lifecycle?.expectedCount ?? 0));
  record.status = Object.keys(record.arms).length === 2 ? 'complete'
    : Object.values(record.arms).some((arm) => arm.quorum?.outcome === 'refused-malicious')
      ? 'refused-malicious' : 'harness-error';
  record.classification = classifyReference(record);
  return persist();
}

const splitSpec = (spec) => {
  const at = spec.lastIndexOf('@');
  return at > 0 ? [spec.slice(0, at), spec.slice(at + 1)] : null;
};

async function cli(argv) {
  const opt = (name, fallback = '') => argv.includes(name) ? argv[argv.indexOf(name) + 1] : fallback;
  const spec = opt('--spec');
  const parsed = splitSpec(spec);
  if (!parsed) throw new Error('--spec must be an exact package@version');
  const nub = opt('--nub');
  const outRoot = path.resolve(opt('--out'));
  if (!nub || !opt('--out')) throw new Error('--nub and --out are required');
  const profilePath = path.resolve(opt('--profile', DEFAULT_REFERENCE_PROFILE));
  const record = await runReferenceProbe({
    pkg: parsed[0], version: parsed[1], nub: path.resolve(nub), npm: opt('--npm', 'npm'), outRoot,
    nubGitSha: opt('--nub-git-sha') || null,
    targetNode: path.resolve(opt('--node', process.env.NODE_EXECUTABLE ?? process.execPath)),
    profile: loadReferenceProfile(profilePath), profilePath,
    maxAttempts: Number(opt('--attempts', '3')),
    timeoutMs: Number(opt('--timeout', '900')) * 1000,
  });
  console.log(`REFERENCE ${spec} ${record.classification.code} (${record.classification.status})`);
  return record.classification.status === 'incomplete' ? 3 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.exitCode = await cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-PROBE-ERROR ${error.stack ?? error.message}`); process.exitCode = 2; }
}
