// Canonical identity of the complete corpus measurement instrument.
//
// The digest deliberately covers the whole harness tree rather than a hand-maintained import list.
// A test-only edit may therefore cause a safe re-measure, but a newly introduced helper can never
// change answers while remaining absent from the identity. Generated v1 results are the sole tree
// exclusion. The compatibility policy is hashed separately because embedding a target digest in the
// policy would otherwise make it self-referential.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const HERE = import.meta.dirname;
export const REPO_ROOT = path.resolve(HERE, '..', '..');
export const CONFIG_PATH = path.join(HERE, 'instrument.json');
export const INVALIDATION_PATH = path.join(HERE, 'invalidation.json');

const posix = (p) => p.split(path.sep).join('/');

function canonicalBytes(bytes) {
  // Source/config files are text, but treating an accidental binary as opaque avoids corrupting it.
  if (bytes.includes(0)) return bytes;
  return Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n'));
}

function readJson(file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object') throw new Error(`${file} is not a JSON object`);
  return value;
}

export function loadInstrumentConfig(root = REPO_ROOT) {
  const config = readJson(path.join(root, 'harness', 'v2', 'instrument.json'));
  if (config.schemaVersion !== 1 || !Number.isInteger(config.harnessEpoch)
    || config.harnessEpoch < 1 || !Array.isArray(config.inputs) || !config.inputs.length) {
    throw new Error('harness/v2/instrument.json has an unsupported or incomplete contract');
  }
  return config;
}

export function instrumentFiles(root = REPO_ROOT, config = loadInstrumentConfig(root)) {
  const excludedFiles = new Set((config.excludeFiles ?? []).map(posix));
  const excludedPrefixes = (config.excludePrefixes ?? []).map(posix);
  const files = [];
  const excluded = (rel) => excludedFiles.has(rel)
    || excludedPrefixes.some((prefix) => rel.startsWith(prefix));

  const visit = (absolute) => {
    const rel = posix(path.relative(root, absolute));
    if (excluded(rel) || excludedPrefixes.some((prefix) => `${rel}/`.startsWith(prefix))) return;
    const stat = fs.lstatSync(absolute);
    if (stat.isSymbolicLink()) {
      files.push(rel);
      return;
    }
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(absolute).sort()) visit(path.join(absolute, entry));
      return;
    }
    if (stat.isFile()) files.push(rel);
  };

  for (const input of config.inputs) {
    const absolute = path.resolve(root, input);
    if (!absolute.startsWith(`${root}${path.sep}`) && absolute !== root) {
      throw new Error(`instrument input escapes repository root: ${input}`);
    }
    if (!fs.existsSync(absolute)) throw new Error(`instrument input is absent: ${input}`);
    visit(absolute);
  }
  return [...new Set(files)].sort();
}

export function hashCanonicalFile(file) {
  const stat = fs.lstatSync(file);
  const bytes = stat.isSymbolicLink()
    ? Buffer.from(`symlink:${posix(fs.readlinkSync(file))}`)
    : canonicalBytes(fs.readFileSync(file));
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

export function computeHarnessIdentity(root = REPO_ROOT) {
  const config = loadInstrumentConfig(root);
  const files = instrumentFiles(root, config);
  const hash = crypto.createHash('sha256');
  for (const rel of files) {
    const absolute = path.join(root, ...rel.split('/'));
    const stat = fs.lstatSync(absolute);
    const bytes = stat.isSymbolicLink()
      ? Buffer.from(`symlink:${posix(fs.readlinkSync(absolute))}`)
      : canonicalBytes(fs.readFileSync(absolute));
    // Length-prefix path and bytes so concatenation can never make two file sets collide.
    hash.update(`${Buffer.byteLength(rel)}:${rel}:${bytes.length}:`);
    hash.update(bytes);
  }
  const policyPath = path.join(root, 'harness', 'v2', 'invalidation.json');
  return {
    schemaVersion: config.schemaVersion,
    harnessEpoch: config.harnessEpoch,
    harnessSha256: hash.digest('hex'),
    inputCount: files.length,
    invalidationPolicySha256: hashCanonicalFile(policyPath),
  };
}

export function loadInvalidationPolicy(root = REPO_ROOT) {
  const policy = readJson(path.join(root, 'harness', 'v2', 'invalidation.json'));
  if (policy.schemaVersion !== 1 || !Number.isInteger(policy.currentEpoch)
    || !Array.isArray(policy.transitions)) {
    throw new Error('harness/v2/invalidation.json has an unsupported or incomplete contract');
  }
  return policy;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const identity = computeHarnessIdentity();
    if (process.argv.includes('--paths')) {
      for (const file of instrumentFiles()) console.log(file);
    } else if (process.argv.includes('--json')) {
      console.log(JSON.stringify(identity, null, 2));
    } else {
      console.log(identity.harnessSha256);
    }
  } catch (error) {
    console.error(`INSTRUMENT-ERROR ${error.message}`);
    process.exitCode = 2;
  }
}
