// Validate an exact, cacheable Nub runtime bundle before a corpus cell can use it.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const BUNDLE_SCHEMA_VERSION = 1;
export const RUNTIME_PACKAGES = [
  '@js-temporal/polyfill', '@oxc-project/runtime', '@petamoriken/float16', 'jsbi', 'urlpattern-polyfill',
];

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const hashFile = (file) => sha256(fs.readFileSync(file));

function runtimePackageVersion(root, name) {
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(path.join(root, 'node_modules', name, 'package.json'), 'utf8')); } catch (error) {
    throw new Error(`runtime package ${name} is unreadable under ${root}: ${error.message}`);
  }
  if (typeof parsed.version !== 'string' || !parsed.version) throw new Error(`runtime package ${name} has no version under ${root}`);
  return parsed.version;
}

// The sidecar is a release-equivalent, independently-resolving tree: derive exact specs while
// still at the source root, then verify the installed sidecar did not drift.
export function runtimeDependencySpecs(sourceRoot) {
  return RUNTIME_PACKAGES.map((name) => `${name}@${runtimePackageVersion(sourceRoot, name)}`);
}

export function verifyRuntimeDependencies(sourceRoot, runtimeRoot) {
  for (const name of RUNTIME_PACKAGES) {
    const source = runtimePackageVersion(sourceRoot, name);
    const staged = runtimePackageVersion(runtimeRoot, name);
    if (source !== staged) throw new Error(`runtime package ${name} differs: source ${source}, staged ${staged}`);
  }
}

export function bundleIdentity({ candidateSha, platform, arch, profile, features, recipeSha256, nodeVersion, rustcSha256 }) {
  if (!/^[0-9a-f]{40}$/i.test(candidateSha ?? '')) throw new Error('candidateSha must be a 40-hex commit');
  if (!platform || !arch || !profile || !recipeSha256 || !nodeVersion || !rustcSha256) throw new Error('bundle identity is incomplete');
  if (!/^[0-9a-f]{64}$/i.test(recipeSha256)) throw new Error('recipeSha256 must be a sha256');
  if (!/^[0-9a-f]{64}$/i.test(rustcSha256)) throw new Error('rustcSha256 must be a sha256');
  if (!Array.isArray(features) || !features.length || features.some((feature) => typeof feature !== 'string' || !feature)) {
    throw new Error('features must be a nonempty string array');
  }
  return {
    candidateSha: candidateSha.toLowerCase(), platform, arch, profile, features: [...features].sort(),
    recipeSha256, nodeVersion, rustcSha256,
  };
}

export function cacheKey(identity) {
  const normalized = bundleIdentity(identity);
  return `catalog-runtime-v${BUNDLE_SCHEMA_VERSION}-${sha256(JSON.stringify(normalized))}`;
}

function relativeFiles(identity) {
  const executable = identity.platform === 'win32' ? 'nub.exe' : 'nub';
  return identity.platform === 'win32' ? [executable, 'busybox.exe'] : [executable];
}

function bundledFiles(root, identity) {
  const files = [];
  const visit = (relative) => {
    const absolute = path.join(root, relative);
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) throw new Error(`runtime bundle contains a symlink: ${relative}`);
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(absolute).sort()) visit(path.join(relative, name));
      return;
    }
    if (!stat.isFile()) throw new Error(`runtime bundle contains an unsupported entry: ${relative}`);
    files.push(relative.split(path.sep).join('/'));
  };
  for (const file of relativeFiles(identity)) visit(file);
  visit('runtime');
  return files.sort();
}

function requiredFiles(identity) {
  return [
    ...relativeFiles(identity), 'runtime/preload.mjs', 'runtime/addons/nub-native.node',
    ...RUNTIME_PACKAGES.map((name) => `runtime/node_modules/${name}/package.json`),
  ];
}

export function writeBundleManifest(root, identity) {
  const normalized = bundleIdentity(identity);
  const files = Object.fromEntries(bundledFiles(root, normalized).map((name) => {
    const file = path.join(root, name);
    const bytes = fs.readFileSync(file);
    return [name, { bytes: bytes.length, sha256: sha256(bytes) }];
  }));
  const manifest = { schemaVersion: BUNDLE_SCHEMA_VERSION, identity: normalized, files };
  fs.writeFileSync(path.join(root, 'runtime-bundle.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

export function verifyBundle(root, identity) {
  const manifestPath = path.join(root, 'runtime-bundle.json');
  let manifest;
  try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (error) {
    throw new Error(`runtime bundle manifest is unreadable: ${error.message}`);
  }
  const expected = bundleIdentity(identity);
  if (manifest?.schemaVersion !== BUNDLE_SCHEMA_VERSION) throw new Error('runtime bundle schema version is invalid');
  if (JSON.stringify(manifest.identity) !== JSON.stringify(expected)) throw new Error('runtime bundle identity does not match the exact candidate');
  const names = Object.keys(manifest.files ?? {}).sort();
  if (!names.length || requiredFiles(expected).some((name) => !manifest.files?.[name])) {
    throw new Error('runtime bundle file set is incomplete');
  }
  for (const name of names) {
    const file = path.join(root, name);
    let stat;
    try { stat = fs.statSync(file); } catch { throw new Error(`runtime bundle file is missing: ${name}`); }
    const recorded = manifest.files[name];
    if (stat.size !== recorded.bytes || hashFile(file) !== recorded.sha256) {
      throw new Error(`runtime bundle file hash does not match: ${name}`);
    }
  }
  const actual = bundledFiles(root, expected);
  if (JSON.stringify(names) !== JSON.stringify(actual)) throw new Error('runtime bundle file set does not match manifest');
  return manifest;
}

function cli(argv) {
  const option = (name) => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
  if (argv.includes('--runtime-dependency-specs')) {
    const root = option('--source-root');
    if (!root) throw new Error('--runtime-dependency-specs requires --source-root');
    console.log(runtimeDependencySpecs(root).join('\n'));
    return;
  }
  if (argv.includes('--verify-runtime-dependencies')) {
    const sourceRoot = option('--source-root'), runtimeRoot = option('--runtime-root');
    if (!sourceRoot || !runtimeRoot) throw new Error('--verify-runtime-dependencies requires --source-root and --runtime-root');
    verifyRuntimeDependencies(sourceRoot, runtimeRoot);
    return;
  }
  const identity = bundleIdentity({
    candidateSha: option('--candidate-sha'), platform: option('--platform'), arch: option('--arch'),
    profile: option('--profile'), features: (option('--features') ?? '').split(',').filter(Boolean),
    recipeSha256: option('--recipe-sha256'), nodeVersion: option('--node-version'), rustcSha256: option('--rustc-sha256'),
  });
  if (argv.includes('--cache-key')) { console.log(cacheKey(identity)); return; }
  const root = option('--root');
  if (!root) throw new Error('--root is required');
  const operation = argv.includes('--write') ? writeBundleManifest : argv.includes('--verify') ? verifyBundle : null;
  if (!operation) throw new Error('choose --write or --verify');
  console.log(JSON.stringify(operation(root, identity)));
}

// Do not use `realpathSync.native` here: Windows returns a `\\?\\`-prefixed path whose file URL
// differs from Node's import URL, silently skipping the CLI. The portable form also resolves macOS
// `/tmp` to Node's `/private/tmp` import path; `pathToFileURL` retains literal `#` and spaces.
const invokedPath = process.argv[1] && (() => {
  try { return fs.realpathSync(process.argv[1]); } catch { return path.resolve(process.argv[1]); }
})();
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`RUNTIME-BUNDLE-ERROR ${error.message}`); process.exitCode = 2; }
}
