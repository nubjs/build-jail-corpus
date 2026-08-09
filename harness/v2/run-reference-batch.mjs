// Sequential reference-accounting batch. One invocation owns the full wait; callers should run it
// under the project watcher/managed terminal rather than poll individual packages.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { pathToFileURL } from 'node:url';
import { loadNodeMatrix } from './node-matrix.mjs';
import {
  collectReferenceProvenance,
  referenceEvidenceSha,
  runReferenceProbe,
} from './reference-probe.mjs';
import { loadReferenceProfile, referenceProfileIdentity } from './reference-profile.mjs';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const hostOs = (platform = process.platform) => platform === 'darwin' ? 'macos'
  : platform === 'win32' ? 'windows' : platform === 'linux' ? 'linux' : null;

export function readReferenceWorklist(file) {
  const bytes = fs.readFileSync(file);
  const body = file.endsWith('.gz') ? gunzipSync(bytes) : bytes;
  const rows = body.toString('utf8').split(/\r?\n/).filter(Boolean).map((line, index) => {
    let row;
    try { row = JSON.parse(line); } catch (error) { throw new Error(`worklist line ${index + 1}: ${error.message}`); }
    if (row.schemaVersion !== 1 || !row.pkg || !row.version
      || !['linux', 'macos', 'windows'].includes(row.os) || !row.prior?.recordSha256) {
      throw new Error(`worklist line ${index + 1} has an invalid reference row`);
    }
    return row;
  });
  const keys = rows.map((row) => `${row.pkg}\0${row.version}\0${row.os}`);
  if (new Set(keys).size !== keys.length) throw new Error('worklist contains duplicate package/version/OS rows');
  return { rows, sha256: sha256(bytes), bytes: bytes.length };
}

const pathPart = (value, label) => {
  if (typeof value !== 'string' || !value || value.includes('/') || value.includes('\\')
    || value === '.' || value === '..') throw new Error(`invalid ${label} path component ${JSON.stringify(value)}`);
  return value;
};

export function referenceRecordDir(root, { pkg, version, os }, nodeVersion, profile) {
  if (!profile?.id || !profile?.sha256) throw new Error('profile identity is required for a reference record path');
  const packagePart = pathPart(pkg.replace('/', '+'), 'package');
  return path.join(root, pathPart(os, 'OS'), `node-${pathPart(nodeVersion, 'Node version')}`,
    `profile-${pathPart(profile.id, 'profile')}-${profile.sha256.slice(0, 12)}`, packagePart, pathPart(version, 'package version'));
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

export function referenceRecordReuse(record, {
  row, worklistSha256, matrixSha256, nodeVersion, profileSha256, provenance,
}) {
  if (!record || record.schemaVersion !== 1) return { reusable: false, reason: 'schema' };
  if (referenceEvidenceSha(record) !== record.provenance?.evidenceSha256) {
    return { reusable: false, reason: 'evidence-hash' };
  }
  if (record.pkg !== row.pkg || record.version !== row.version) return { reusable: false, reason: 'target' };
  if (record.source?.worklistSha256 !== worklistSha256
    || record.source?.priorRecordSha256 !== row.prior.recordSha256) {
    return { reusable: false, reason: 'worklist' };
  }
  if (record.source?.nodeMatrixSha256 !== matrixSha256 || record.source?.nodeVersion !== nodeVersion
    || record.source?.os !== row.os) return { reusable: false, reason: 'runtime-cell' };
  if (record.profile?.sha256 !== profileSha256) return { reusable: false, reason: 'profile' };
  for (const field of ['instrument', 'orchestrator', 'runtime', 'toolchain', 'nub', 'npm']) {
    if (!same(record.provenance?.[field], provenance[field])) return { reusable: false, reason: field };
  }
  return { reusable: true, reason: 'exact' };
}

const readRecord = (file) => {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
};

const writeJsonAtomic = (file, value) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(temporary, file);
};

const positiveInteger = (value, name) => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
};

export function selectReferenceRows(allRows, {
  os, priorBucket = null, includeSpecs = null, limit = Infinity, shardIndex = 0, shardCount = 1,
}) {
  if (limit !== Infinity) limit = positiveInteger(limit, 'limit');
  shardCount = positiveInteger(shardCount, 'shardCount');
  if (!Number.isSafeInteger(shardIndex) || shardIndex < 0 || shardIndex >= shardCount) {
    throw new Error(`shardIndex must be between 0 and ${shardCount - 1}`);
  }
  const buckets = new Set(allRows.map((row) => row.prior.bucket));
  if (priorBucket && !buckets.has(priorBucket)) throw new Error(`unknown prior bucket ${priorBucket}`);
  const selectedSpecs = includeSpecs ? new Set(includeSpecs) : null;
  if (selectedSpecs?.size === 0) throw new Error('includeSpecs cannot be empty');
  const eligibleRows = allRows.filter((row) => row.os === os
    && (!priorBucket || row.prior.bucket === priorBucket)
    && (!selectedSpecs || selectedSpecs.has(`${row.pkg}@${row.version}`)));
  if (selectedSpecs) {
    const found = new Set(eligibleRows.map((row) => `${row.pkg}@${row.version}`));
    const missingSpecs = [...selectedSpecs].filter((spec) => !found.has(spec));
    if (missingSpecs.length) throw new Error(`selected specs have no ${os} worklist row: ${missingSpecs.join(', ')}`);
  }
  return {
    eligibleRows,
    rows: eligibleRows.filter((_, index) => index % shardCount === shardIndex).slice(0, limit),
  };
}

const parseArgs = (argv) => {
  const valued = new Set(['--worklist', '--out', '--nub', '--npm', '--nub-git-sha', '--node', '--profile', '--node-matrix',
    '--attempts', '--timeout', '--deadline-seconds', '--limit', '--prior-bucket', '--specs', '--canary',
    '--shard-index', '--shard-count']);
  const flags = new Set(['--retry-incomplete', '--skip-canary']);
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (flags.has(arg)) { options[arg.slice(2)] = true; continue; }
    if (!valued.has(arg) || argv[i + 1] == null) throw new Error(`unknown or incomplete option ${arg}`);
    options[arg.slice(2)] = argv[++i];
  }
  return options;
};

export async function runReferenceBatch({
  worklistFile, outRoot, nub, npm = 'npm', nubGitSha = null,
  targetNode = process.env.NODE_EXECUTABLE ?? process.execPath,
  profileFile = path.join(import.meta.dirname, 'reference-profile.json'),
  matrixFile = path.join(import.meta.dirname, 'node-matrix.json'),
  maxAttempts = 3, timeoutMs = 15 * 60_000, deadlineMs = Infinity, limit = Infinity,
  priorBucket = null, includeSpecs = null, retryIncomplete = false, skipCanary = false,
  shardIndex = 0, shardCount = 1,
  canarySpec = 'es5-ext@0.10.64',
  runProbe = runReferenceProbe,
}) {
  const worklist = readReferenceWorklist(worklistFile);
  const profile = loadReferenceProfile(profileFile);
  const profileIdentity = referenceProfileIdentity(profile);
  const nodeMatrix = loadNodeMatrix(matrixFile);
  const os = hostOs();
  if (!os) throw new Error(`unsupported host platform ${process.platform}`);
  maxAttempts = positiveInteger(maxAttempts, 'maxAttempts');
  if (maxAttempts < 2) throw new Error('maxAttempts must be at least 2 to establish stable failures');
  timeoutMs = positiveInteger(timeoutMs, 'timeoutMs');
  if (deadlineMs !== Infinity && (!Number.isFinite(deadlineMs) || deadlineMs <= Date.now())) {
    throw new Error('deadlineMs must be a future timestamp or Infinity');
  }
  const { rows, eligibleRows } = selectReferenceRows(worklist.rows, {
    os, priorBucket, includeSpecs, limit, shardIndex, shardCount,
  });
  const provenance = collectReferenceProvenance(profile, nub, npm, nubGitSha, targetNode);
  const nodeVersion = provenance.runtime.node.version.replace(/^v/, '');
  const nodeCell = nodeMatrix.matrix.versions.find((entry) => entry.version === nodeVersion);
  if (!nodeCell) throw new Error(`target Node ${nodeVersion} is not an exact cell in ${matrixFile}`);
  const securityCacheDir = path.join(outRoot, 'osv-cache');
  const manifestFile = path.join(outRoot, `batch-${os}-node-${nodeVersion}.json`);
  const manifest = {
    schemaVersion: 1,
    status: 'running',
    startedAt: new Date().toISOString(),
    worklist: { file: path.resolve(worklistFile), sha256: worklist.sha256, bytes: worklist.bytes },
    nodeMatrix: { file: path.resolve(matrixFile), sha256: nodeMatrix.sha256, selectedAt: nodeMatrix.matrix.selectedAt },
    cell: { os, node: nodeCell },
    profile: profileIdentity,
    provenance,
    selectedRows: rows.length,
    eligibleRows: eligibleRows.length,
    shard: { index: shardIndex, count: shardCount },
    completed: 0,
    skipped: 0,
    classifications: {},
    incomplete: 0,
    deadlineReached: false,
  };
  const save = () => writeJsonAtomic(manifestFile, manifest);
  fs.mkdirSync(outRoot, { recursive: true });
  save();

  if (!skipCanary) {
    const at = canarySpec.lastIndexOf('@');
    if (at <= 0) throw new Error('canary must be an exact package@version');
    const canary = { pkg: canarySpec.slice(0, at), version: canarySpec.slice(at + 1) };
    const canaryOut = path.join(outRoot, 'controls', `node-${nodeVersion}`,
      `profile-${profileIdentity.id}-${profileIdentity.sha256.slice(0, 12)}`, canary.pkg.replace('/', '+'), canary.version);
    const record = await runProbe({ ...canary, nub, npm, outRoot: canaryOut, profile, profilePath: profileFile,
      maxAttempts, timeoutMs, deadlineMs, targetNode, staticProvenance: provenance, securityCacheDir,
      source: { kind: 'reference-positive-control', nodeMatrixSha256: nodeMatrix.sha256, nodeVersion, os } });
    const arms = [record.arms?.nubUnjailed, record.arms?.npmUnjailed];
    const proven = arms.every((arm) => arm?.quorum?.outcome === 'pass'
      && (arm.lifecycle?.expectedCount ?? 0) > 0
      && arm.lifecycle.provenCount === arm.lifecycle.expectedCount);
    manifest.canary = { spec: canarySpec, classification: record.classification, proven };
    save();
    if (record.classification?.code !== 'REFERENCE_PASSES' || !proven) {
      manifest.status = 'canary-failed'; manifest.finishedAt = new Date().toISOString(); save();
      return manifest;
    }
  }

  for (const row of rows) {
    if (Date.now() >= deadlineMs) { manifest.deadlineReached = true; break; }
    const dir = referenceRecordDir(outRoot, row, nodeVersion, profileIdentity);
    const existing = readRecord(path.join(dir, 'reference.json'));
    const reuse = existing && referenceRecordReuse(existing, {
      row, worklistSha256: worklist.sha256, matrixSha256: nodeMatrix.sha256,
      nodeVersion, profileSha256: profileIdentity.sha256, provenance,
    });
    if (reuse?.reusable && (!retryIncomplete || existing.classification?.status !== 'incomplete')) {
      manifest.skipped += 1;
      const code = existing.classification?.code ?? 'MISSING_CLASSIFICATION';
      manifest.classifications[code] = (manifest.classifications[code] ?? 0) + 1;
      if (existing.classification?.status === 'incomplete') manifest.incomplete += 1;
      save();
      continue;
    }
    const source = {
      kind: 'legacy-reference-accounting', worklistSha256: worklist.sha256,
      priorRecordSha256: row.prior.recordSha256, prior: row.prior,
      nodeMatrixSha256: nodeMatrix.sha256, nodeVersion, os,
    };
    const record = await runProbe({ pkg: row.pkg, version: row.version, nub, npm, outRoot: dir,
      profile, profilePath: profileFile, maxAttempts, timeoutMs, targetNode, staticProvenance: provenance,
      securityCacheDir, deadlineMs, source });
    manifest.completed += 1;
    const code = record.classification?.code ?? 'MISSING_CLASSIFICATION';
    manifest.classifications[code] = (manifest.classifications[code] ?? 0) + 1;
    if (record.classification?.status === 'incomplete') manifest.incomplete += 1;
    save();
  }
  manifest.status = manifest.deadlineReached ? 'deadline' : manifest.incomplete ? 'incomplete' : 'complete';
  manifest.finishedAt = new Date().toISOString();
  save();
  return manifest;
}

async function cli(argv) {
  const options = parseArgs(argv);
  for (const required of ['worklist', 'out', 'nub']) if (!options[required]) throw new Error(`--${required} is required`);
  const base = import.meta.dirname;
  const deadlineSeconds = Number(options['deadline-seconds'] ?? '0');
  const manifest = await runReferenceBatch({
    worklistFile: path.resolve(options.worklist), outRoot: path.resolve(options.out), nub: path.resolve(options.nub),
    npm: options.npm ?? 'npm', nubGitSha: options['nub-git-sha'] ?? null,
    targetNode: path.resolve(options.node ?? process.env.NODE_EXECUTABLE ?? process.execPath),
    profileFile: path.resolve(options.profile ?? path.join(base, 'reference-profile.json')),
    matrixFile: path.resolve(options['node-matrix'] ?? path.join(base, 'node-matrix.json')),
    maxAttempts: Number(options.attempts ?? '3'), timeoutMs: Number(options.timeout ?? '900') * 1000,
    deadlineMs: deadlineSeconds > 0 ? Date.now() + deadlineSeconds * 1000 : Infinity,
    limit: options.limit == null ? Infinity : Number(options.limit), priorBucket: options['prior-bucket'] ?? null,
    includeSpecs: options.specs ? options.specs.split(',').map((spec) => spec.trim()).filter(Boolean) : null,
    shardIndex: Number(options['shard-index'] ?? '0'), shardCount: Number(options['shard-count'] ?? '1'),
    retryIncomplete: options['retry-incomplete'] ?? false, skipCanary: options['skip-canary'] ?? false,
    canarySpec: options.canary ?? 'es5-ext@0.10.64',
  });
  console.log(`REFERENCE-BATCH status=${manifest.status} selected=${manifest.selectedRows} completed=${manifest.completed} skipped=${manifest.skipped} incomplete=${manifest.incomplete}`);
  console.log(`REFERENCE-BATCH classifications=${JSON.stringify(manifest.classifications)}`);
  return manifest.status === 'complete' ? 0 : manifest.status === 'deadline' ? 75 : 3;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.exitCode = await cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-BATCH-ERROR ${error.stack ?? error.message}`); process.exitCode = 2; }
}
