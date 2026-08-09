// Runtime and host-tool identity captured once per batch and copied into every record.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

export function fileIdentity(file) {
  if (!file) return null;
  try {
    const bytes = fs.readFileSync(file);
    return {
      path: file,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      bytes: bytes.length,
    };
  } catch { return null; }
}

const outputOf = (result) => `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();

export function endpointIdentity(value) {
  if (!value) return null;
  let display = '<configured-non-url>';
  try {
    const parsed = new URL(value);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    display = parsed.toString();
  } catch { /* retain only the digest for a non-URL endpoint spelling */ }
  return {
    display,
    sha256: crypto.createHash('sha256').update(value).digest('hex'),
  };
}

function commandPath(command, env = process.env) {
  if (path.isAbsolute(command) && fs.existsSync(command)) return command;
  const lookup = process.platform === 'win32'
    ? spawnSync('where.exe', [command], { encoding: 'utf8', windowsHide: true, env })
    : spawnSync('which', [command], { encoding: 'utf8', env });
  if (lookup.status !== 0) return null;
  return String(lookup.stdout ?? '').split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? null;
}

function runtimeLibc() {
  if (process.platform !== 'linux') return null;
  const header = process.report?.getReport?.().header ?? {};
  if (header.glibcVersionRuntime) return { family: 'glibc', version: header.glibcVersionRuntime };
  try {
    if (fs.readdirSync('/lib').some((entry) => /^ld-musl-.*\.so\.1$/.test(entry))) {
      return { family: 'musl', version: null };
    }
  } catch { /* a minimal image may not expose /lib */ }
  return { family: null, version: null };
}

export function probeTool(command, args = ['--version'], env = process.env) {
  const resolvedPath = commandPath(command, env);
  if (!resolvedPath) return null;
  const windowsScript = process.platform === 'win32' && /\.(?:cmd|bat)$/i.test(resolvedPath);
  const options = { encoding: 'utf8', windowsHide: true, timeout: 30_000, env };
  const result = windowsScript
    ? spawnSync([resolvedPath, ...args]
      .map((value) => `"${String(value).replaceAll('"', '""')}"`).join(' '), {
      ...options, shell: env.ComSpec ?? process.env.ComSpec ?? 'cmd.exe',
    })
    : spawnSync(resolvedPath, args, options);
  if (result.error || result.status !== 0) return null;
  return {
    command: [command, ...args],
    path: resolvedPath,
    executable: fileIdentity(resolvedPath),
    version: outputOf(result).split(/\r?\n/).find(Boolean) ?? null,
  };
}

export function probeNodeRuntime(executable) {
  const result = spawnSync(executable, ['--version'], {
    encoding: 'utf8', windowsHide: true, timeout: 30_000,
  });
  const version = outputOf(result).split(/\r?\n/).find(Boolean) ?? null;
  if (result.error || result.status !== 0 || !/^v\d+\.\d+\.\d+$/.test(version ?? '')) {
    throw new Error(`could not execute target Node runtime ${executable}: ${result.error?.message ?? version ?? `exit ${result.status}`}`);
  }
  return { version, ...fileIdentity(executable) };
}

export function collectRuntimeProvenance(env = process.env) {
  const python = [
    probeTool('python3', ['--version'], env),
    probeTool('python', ['--version'], env),
    ...(process.platform === 'win32' ? [probeTool('py', ['-3', '--version'], env)] : []),
  ].filter(Boolean).filter((tool, index, all) =>
    all.findIndex((other) => other.path === tool.path && other.version === tool.version) === index);
  const buildTools = process.platform === 'win32'
    ? { cl: probeTool('cl', ['/?'], env), msbuild: probeTool('msbuild', ['-version'], env) }
    : { cc: probeTool('cc', ['--version'], env), cxx: probeTool('c++', ['--version'], env),
      make: probeTool('make', ['--version'], env) };
  const exposedEnv = ['CI', 'GITHUB_ACTIONS', 'NODE_ENV', 'NODE_EXECUTABLE',
    'RUNNER_OS', 'RUNNER_ARCH',
    'RUNNER_ENVIRONMENT', 'ImageOS', 'ImageVersion', 'LANG', 'LC_ALL'];
  return {
    node: { version: process.version, ...fileIdentity(process.execPath) },
    npm: probeTool('npm', ['--version'], env),
    python,
    buildTools,
    os: {
      platform: process.platform,
      arch: process.arch,
      libc: runtimeLibc(),
      type: os.type(),
      release: os.release(),
      version: os.version(),
      machine: typeof os.machine === 'function' ? os.machine() : null,
    },
    runner: {
      provider: env.GITHUB_ACTIONS ? 'github-actions' : null,
      os: env.RUNNER_OS ?? null,
      arch: env.RUNNER_ARCH ?? null,
      environment: env.RUNNER_ENVIRONMENT ?? null,
      imageOS: env.ImageOS ?? null,
      imageVersion: env.ImageVersion ?? null,
    },
    environment: {
      values: Object.fromEntries(exposedEnv.map((key) => [key, env[key] ?? null])),
      endpoints: { nodeMirror: endpointIdentity(env.NODEJS_ORG_MIRROR) },
      pathSha256: crypto.createHash('sha256').update(env.PATH ?? '').digest('hex'),
      shell: env.SHELL ?? env.ComSpec ?? null,
    },
  };
}
