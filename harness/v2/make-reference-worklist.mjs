// Convert a pinned v2 record tree into the exact reference-accounting population. The worklist
// retains old verdicts as diagnostic context; none of them is accepted as a new reference answer.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

export const priorBucketFor = (verdict) => {
  if (verdict === 'BROKEN-WITHOUT-JAIL-TOO') return 'brokenWithoutJailToo';
  if (['UNDER-PREDICTED', 'UNKNOWN', 'BROKEN-UNJAILED-NUB'].includes(verdict)) return 'noVerdict';
  if (verdict === 'NO-STATE-PASSED') return 'noStatePassed';
  if (String(verdict ?? '').startsWith('HARNESS-')) return 'harnessError';
  if (verdict === 'ARTIFACT-GATE-SUSPECT') return 'artifactGateSuspect';
  return null;
};

const osForPlatform = (platform) => {
  if (platform?.startsWith('linux')) return 'linux';
  if (platform?.startsWith('darwin')) return 'macos';
  if (platform?.startsWith('win')) return 'windows';
  return null;
};

const walkResults = (root) => {
  const found = [];
  const visit = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.name === 'results.json') found.push(file);
    }
  };
  visit(root);
  return found;
};

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const posixRelative = (root, file) => path.relative(root, file).split(path.sep).join('/');

export function buildReferenceWorklist(recordsRoot, { sourceCommit, sourceTree = 'records-v2' } = {}) {
  if (!sourceCommit) throw new Error('sourceCommit is required');
  const rows = [];
  const seen = new Set();
  for (const file of walkResults(recordsRoot)) {
    const bytes = fs.readFileSync(file);
    const record = JSON.parse(bytes);
    const bucket = priorBucketFor(record.verdict);
    if (!bucket) continue;
    const platform = record.provenance?.platform;
    const os = osForPlatform(platform);
    if (!record.pkg || !record.version || !os) {
      throw new Error(`${posixRelative(recordsRoot, file)} lacks package, version, or recognized platform`);
    }
    const key = `${record.pkg}\0${record.version}\0${os}`;
    if (seen.has(key)) throw new Error(`duplicate legacy reference row ${record.pkg}@${record.version} ${os}`);
    seen.add(key);
    rows.push({
      schemaVersion: 1,
      pkg: record.pkg,
      version: record.version,
      os,
      prior: {
        bucket,
        verdict: record.verdict,
        platform,
        node: record.provenance?.node ?? null,
        measuredAt: record.provenance?.at ?? null,
        corpusGitSha: record.provenance?.corpusGitSha ?? null,
        recordPath: `${sourceTree}/${posixRelative(recordsRoot, file)}`,
        recordSha256: sha256(bytes),
      },
      source: { commit: sourceCommit, tree: sourceTree },
    });
  }
  return rows.sort((a, b) => `${a.pkg}\0${a.version}\0${a.os}`.localeCompare(`${b.pkg}\0${b.version}\0${b.os}`));
}

export function worklistCounts(rows) {
  const byBucket = {};
  for (const row of rows) byBucket[row.prior.bucket] = (byBucket[row.prior.bucket] ?? 0) + 1;
  return {
    rows: rows.length,
    packageVersions: new Set(rows.map((row) => `${row.pkg}\0${row.version}`)).size,
    packages: new Set(rows.map((row) => row.pkg)).size,
    byBucket: Object.fromEntries(Object.entries(byBucket).sort()),
  };
}

const parseArgs = (argv) => {
  const known = new Set(['--records', '--out', '--manifest', '--source-commit', '--source-tree',
    '--expect-total', '--expect-broken']);
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!known.has(argv[i]) || argv[i + 1] == null) throw new Error(`unknown or incomplete option ${argv[i]}`);
    options[argv[i].slice(2)] = argv[i + 1];
  }
  return options;
};

function cli(argv) {
  const options = parseArgs(argv);
  for (const required of ['records', 'out', 'source-commit']) {
    if (!options[required]) throw new Error(`--${required} is required`);
  }
  const root = path.resolve(options.records);
  const rows = buildReferenceWorklist(root, {
    sourceCommit: options['source-commit'], sourceTree: options['source-tree'] ?? 'records-v2',
  });
  const counts = worklistCounts(rows);
  if (options['expect-total'] && counts.rows !== Number(options['expect-total'])) {
    throw new Error(`expected ${options['expect-total']} reference rows, found ${counts.rows}`);
  }
  if (options['expect-broken']
    && counts.byBucket.brokenWithoutJailToo !== Number(options['expect-broken'])) {
    throw new Error(`expected ${options['expect-broken']} broken-without-jail rows, found ${counts.byBucket.brokenWithoutJailToo ?? 0}`);
  }
  const out = path.resolve(options.out);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const body = Buffer.from(rows.length ? `${rows.map((row) => JSON.stringify(row)).join('\n')}\n` : '');
  const output = out.endsWith('.gz') ? gzipSync(body, { level: 9, mtime: 0 }) : body;
  fs.writeFileSync(out, output);
  const manifest = {
    schemaVersion: 1,
    source: { commit: options['source-commit'], tree: options['source-tree'] ?? 'records-v2' },
    worklistSha256: sha256(output),
    counts,
  };
  const manifestPath = path.resolve(options.manifest ?? `${out}.manifest.json`);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`REFERENCE-WORKLIST rows=${counts.rows} packageVersions=${counts.packageVersions} packages=${counts.packages}`);
  console.log(`REFERENCE-WORKLIST buckets=${JSON.stringify(counts.byBucket)}`);
  console.log(`REFERENCE-WORKLIST sha256=${manifest.worklistSha256}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-WORKLIST-ERROR ${error.message}`); process.exitCode = 2; }
}
