// Runtime and host-tool identity captured once per batch and copied into every record.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
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

function commandPath(command) {
  const lookup = process.platform === 'win32'
    ? spawnSync('where.exe', [command], { encoding: 'utf8', windowsHide: true })
    : spawnSync('which', [command], { encoding: 'utf8' });
  if (lookup.status !== 0) return null;
  return String(lookup.stdout ?? '').split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? null;
}

export function probeTool(command, args = ['--version']) {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true, timeout: 30_000 });
  if (result.error || result.status !== 0) return null;
  const resolvedPath = commandPath(command);
  return {
    command: [command, ...args],
    path: resolvedPath,
    executable: fileIdentity(resolvedPath),
    version: outputOf(result).split(/\r?\n/).find(Boolean) ?? null,
  };
}

export function collectRuntimeProvenance(env = process.env) {
  const python = [
    probeTool('python3'),
    probeTool('python'),
    ...(process.platform === 'win32' ? [probeTool('py', ['-3', '--version'])] : []),
  ].filter(Boolean).filter((tool, index, all) =>
    all.findIndex((other) => other.path === tool.path && other.version === tool.version) === index);
  const buildTools = process.platform === 'win32'
    ? { cl: probeTool('cl', []), msbuild: probeTool('msbuild', ['-version']) }
    : { cc: probeTool('cc'), cxx: probeTool('c++'), make: probeTool('make') };
  const exposedEnv = ['CI', 'GITHUB_ACTIONS', 'NODE_ENV', 'RUNNER_OS', 'RUNNER_ARCH',
    'RUNNER_ENVIRONMENT', 'ImageOS', 'ImageVersion', 'LANG', 'LC_ALL'];
  return {
    node: { version: process.version, ...fileIdentity(process.execPath) },
    npm: probeTool('npm'),
    python,
    buildTools,
    os: {
      platform: process.platform,
      arch: process.arch,
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
      pathSha256: crypto.createHash('sha256').update(env.PATH ?? '').digest('hex'),
      shell: env.SHELL ?? env.ComSpec ?? null,
    },
  };
}
