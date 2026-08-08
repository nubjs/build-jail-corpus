import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_REFERENCE_PROFILE = path.join(import.meta.dirname, 'reference-profile.json');

const canonicalJson = (value) => {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
};

const safeRelative = (name) => {
  if (typeof name !== 'string' || !name || name.startsWith('/') || name.includes('\\')
    || /^[A-Za-z]:/.test(name)) return false;
  return name.split('/').every((part) => part && part !== '.' && part !== '..');
};

export function validateReferenceProfile(profile) {
  if (!profile || profile.schemaVersion !== 1 || !/^[a-z0-9][a-z0-9._-]*$/.test(profile.id ?? '')) {
    throw new Error('reference profile must have schemaVersion 1 and a path-safe id');
  }
  const files = profile.fixture?.files;
  if (!files || typeof files !== 'object' || Array.isArray(files)) {
    throw new Error('reference profile fixture.files must be an object');
  }
  for (const [name, contents] of Object.entries(files)) {
    if (!safeRelative(name) || typeof contents !== 'string') {
      throw new Error(`reference profile has an invalid fixture file ${JSON.stringify(name)}`);
    }
    if (['package.json', 'nub.jsonc', '.npmrc'].includes(name)) {
      throw new Error(`reference profile cannot replace generated fixture file ${name}`);
    }
  }
  const npmrc = profile.fixture?.npmrc ?? {};
  if (!npmrc || typeof npmrc !== 'object' || Array.isArray(npmrc)
    || Object.entries(npmrc).some(([key, value]) => !key || typeof value !== 'string')) {
    throw new Error('reference profile fixture.npmrc must contain string values');
  }
  const managerNpmrc = profile.fixture?.managerNpmrc ?? {};
  if (!managerNpmrc || typeof managerNpmrc !== 'object' || Array.isArray(managerNpmrc)
    || Object.entries(managerNpmrc).some(([manager, values]) => !['npm', 'nub'].includes(manager)
      || !values || typeof values !== 'object' || Array.isArray(values)
      || Object.entries(values).some(([key, value]) => !key || typeof value !== 'string'))) {
    throw new Error('reference profile fixture.managerNpmrc must contain npm/nub string maps');
  }
  const set = profile.environment?.set ?? {};
  const unset = profile.environment?.unset ?? [];
  const inherit = profile.environment?.inherit ?? [];
  if (!set || typeof set !== 'object' || Array.isArray(set)
    || Object.entries(set).some(([key, value]) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
      || typeof value !== 'string')) {
    throw new Error('reference profile environment.set must contain valid string assignments');
  }
  if (!Array.isArray(unset) || unset.some((key) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))) {
    throw new Error('reference profile environment.unset must be an array of environment names');
  }
  if (!Array.isArray(inherit) || inherit.some((key) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key))
    || new Set(inherit).size !== inherit.length) {
    throw new Error('reference profile environment.inherit must contain unique environment names');
  }
  for (const group of Object.values(profile.toolProbes ?? {})) {
    if (!Array.isArray(group) || group.some((probe) => !Array.isArray(probe)
      || !probe.length || probe.some((part) => typeof part !== 'string'))) {
      throw new Error('reference profile tool probes must be non-empty string arrays');
    }
  }
  return profile;
}

export function loadReferenceProfile(file = DEFAULT_REFERENCE_PROFILE) {
  return validateReferenceProfile(JSON.parse(fs.readFileSync(file, 'utf8')));
}

export function referenceProfileIdentity(profile) {
  const bytes = Buffer.from(`${JSON.stringify(canonicalJson(validateReferenceProfile(profile)))}\n`);
  return {
    id: profile.id,
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    schemaVersion: profile.schemaVersion,
  };
}

export function writeReferenceProject(root, { profile, pkg, version, arm, buildJail, manager }) {
  validateReferenceProfile(profile);
  fs.mkdirSync(root, { recursive: true });
  const packageJson = {
    name: `nub-corpus-${arm.replace(/[^a-z0-9-]/g, '-')}`,
    version: '1.0.0',
    private: true,
    type: 'module',
    dependencies: { [pkg]: version },
  };
  fs.writeFileSync(path.join(root, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`);
  fs.writeFileSync(path.join(root, 'nub.jsonc'), `${JSON.stringify({ install: { buildJail } }, null, 2)}\n`);
  if (!['npm', 'nub'].includes(manager)) throw new Error('reference project manager must be npm or nub');
  const npmrcValues = {
    ...(profile.fixture.npmrc ?? {}),
    ...(profile.fixture.managerNpmrc?.[manager] ?? {}),
  };
  const npmrc = Object.entries(npmrcValues)
    .sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => `${key}=${value}`).join('\n');
  fs.writeFileSync(path.join(root, '.npmrc'), `${npmrc}\n`);
  for (const [name, contents] of Object.entries(profile.fixture.files).sort(([a], [b]) => a.localeCompare(b))) {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
  return packageJson;
}

export function referenceEnvironment(root, profile, base = process.env) {
  validateReferenceProfile(profile);
  const env = Object.fromEntries((profile.environment?.inherit ?? [])
    .filter((key) => base[key] != null).map((key) => [key, base[key]]));
  for (const key of profile.environment?.unset ?? []) delete env[key];
  Object.assign(env, profile.environment?.set ?? {});
  if (env.NODE_EXECUTABLE) {
    env.PATH = [path.dirname(env.NODE_EXECUTABLE), env.PATH].filter(Boolean).join(path.delimiter);
  }

  const home = path.join(root, 'home');
  const temp = path.join(root, 'tmp');
  const cache = path.join(root, 'cache');
  const config = path.join(root, 'config');
  const npmCache = path.join(root, 'npm-cache');
  for (const dir of [home, temp, cache, config, npmCache]) fs.mkdirSync(dir, { recursive: true });
  env.HOME = home;
  env.USERPROFILE = home;
  env.TMPDIR = temp;
  env.TMP = temp;
  env.TEMP = temp;
  env.XDG_CACHE_HOME = cache;
  env.XDG_CONFIG_HOME = config;
  env.LOCALAPPDATA = cache;
  env.npm_config_cache = npmCache;
  env.npm_config_audit = 'false';
  env.npm_config_fund = 'false';
  env.npm_config_update_notifier = 'false';
  return { env, roots: { home, temp, cache, config, npmCache } };
}

export function targetManifest(project, pkg) {
  const file = path.join(project, 'node_modules', ...pkg.split('/'), 'package.json');
  try {
    const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    return {
      name: manifest.name ?? null,
      version: manifest.version ?? null,
      engines: manifest.engines ?? null,
      os: manifest.os ?? null,
      cpu: manifest.cpu ?? null,
      libc: manifest.libc ?? null,
      scripts: Object.fromEntries(Object.entries(manifest.scripts ?? {})
        .filter(([name, value]) => ['preinstall', 'install', 'postinstall', 'prepare'].includes(name)
          && typeof value === 'string')),
      deprecated: manifest.deprecated ?? null,
    };
  } catch {
    return null;
  }
}

export function toolProbesForPlatform(profile, platform = process.platform) {
  validateReferenceProfile(profile);
  return [
    ...(profile.toolProbes?.common ?? []),
    ...(profile.toolProbes?.[platform === 'win32' ? 'win32' : 'posix'] ?? []),
  ];
}
