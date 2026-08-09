// Account for reference outcomes without mixing cells, package-versions, and package names.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { computeHarnessIdentity } from './instrument.mjs';
import { loadNodeMatrix } from './node-matrix.mjs';
import { referenceEvidenceSha } from './reference-probe.mjs';
import { loadReferenceProfile, referenceProfileIdentity } from './reference-profile.mjs';
import { readReferenceWorklist } from './run-reference-batch.mjs';

const walkNamed = (root, name) => {
  const found = [];
  const visit = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const file = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(file); else if (entry.name === name) found.push(file);
    }
  };
  visit(root);
  return found;
};

const cellKey = (pkg, version, os, node) => `${pkg}\0${version}\0${os}\0${node}`;
const legacyKey = (value) => `${value.pkg}\0${value.version}\0${value.os}`;
const osForPlatform = (platform) => platform === 'darwin' ? 'macos'
  : platform === 'win32' ? 'windows' : platform === 'linux' ? 'linux' : null;
const units = (records) => ({
  rows: records.length,
  packageVersions: new Set(records.map((record) => `${record.pkg}\0${record.version}`)).size,
  packages: new Set(records.map((record) => record.pkg)).size,
});

const countBy = (records, keyFor) => Object.fromEntries([...records.reduce((map, record) => {
  const key = keyFor(record); if (!key) return map;
  if (!map.has(key)) map.set(key, []); map.get(key).push(record); return map;
}, new Map()).entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, values]) => [key, units(values)]));

const fingerprintsFor = (record) => [...new Set(Object.values(record.arms ?? {})
  .flatMap((arm) => [arm.quorum?.fingerprint, ...(arm.attempts ?? []).map((attempt) => attempt.fingerprint)])
  .filter(Boolean))].sort();

const firstErrorsFor = (record) => [...new Set(Object.values(record.arms ?? {})
  .flatMap((arm) => arm.attempts ?? [])
  .flatMap((attempt) => Object.values(attempt.stages ?? {}))
  .map((stage) => stage?.error?.summary).filter(Boolean))].sort();

export const remediationFor = (code) => ({
  HARNESS_INTERNAL: { priority: 'P0', disposition: 'instrument-fix', experiment: 'fix the recorded harness stage and invalidate affected evidence' },
  LIFECYCLE_NOT_PROVEN: { priority: 'P0', disposition: 'instrument-fix', experiment: 'repair exact package-hook proof before accepting either reference arm' },
  UNCLASSIFIED: { priority: 'P0', disposition: 'classify-evidence', experiment: 'inspect the retained first-error/signature cluster and add a general classifier or profile experiment' },
  UNSTABLE_REFERENCE: { priority: 'P0', disposition: 'retry', experiment: 'repeat fresh isolated arms until quorum or retain an unstable terminal class' },
  REFERENCE_TIMEOUT: { priority: 'P0', disposition: 'retry-or-bound', experiment: 'separate the batch deadline from a repeatable package hang, then set an evidence-backed bound' },
  NUB_PM_DIVERGENCE: { priority: 'P1', disposition: 'nub-fix', experiment: 'reproduce the npm-pass/Nub-fail differential as a Nub package-manager defect' },
  NUB_PM_RESOLVER_DEFECT: { priority: 'P1', disposition: 'nub-fix', experiment: 'reproduce and fix the peer-context non-convergence before comparing lifecycle behavior' },
  REFERENCE_PASSES: { priority: 'none', disposition: 'recovered-reference', experiment: null },
  REQUIRED_PLATFORM_POLICY_DIFFERENTIAL: { priority: 'none', disposition: 'expected-pnpm-policy-differential', experiment: null },
  TOOLCHAIN_PREREQUISITE: { priority: 'P1', disposition: 'profile-experiment', experiment: 'add the named build tool to a versioned toolchain profile and compare before/after cells' },
  SYSTEM_LIBRARY_PREREQUISITE: { priority: 'P1', disposition: 'profile-experiment', experiment: 'add the evidenced native development library to a versioned toolchain profile and compare before/after cells' },
  UNDECLARED_EXTERNAL_TOOL_REQUIRED: { priority: 'P1', disposition: 'profile-experiment', experiment: 'add the evidenced common build command to a versioned project tool profile and compare before/after cells' },
  PROJECT_FIXTURE_PREREQUISITE: { priority: 'P1', disposition: 'profile-experiment', experiment: 'add the evidenced repository/project file to a versioned fixture profile and compare before/after cells' },
  ENVIRONMENT_PREREQUISITE: { priority: 'P1', disposition: 'profile-experiment', experiment: 'add only the evidenced non-secret environment value to a versioned profile and compare before/after cells' },
  PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  PUBLISHED_SOURCE_PREREQUISITE: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  PUBLISHED_SCRIPT_PLATFORM_ASSUMPTION: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  PUBLISHED_SCRIPT_RECURSION: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  PUBLISHED_SCRIPT_NOT_EXECUTABLE: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  PUBLISHED_INSTALLER_OUTPUT_LIMIT: { priority: 'P1', disposition: 'profile-experiment', experiment: 'suppress only evidenced non-semantic build diagnostics in a versioned profile; if the limit repeats, retain it as a terminal package failure' },
  EXTERNAL_ARTIFACT_UNAVAILABLE: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  OBSOLETE_PYTHON_ASSUMPTION: { priority: 'none', disposition: 'runtime-compatibility', experiment: null },
  TRANSIENT_EXTERNAL_DOWNLOAD: { priority: 'P1', disposition: 'retry', experiment: 'rerun isolated attempts and retain endpoint/checksum evidence until quorum' },
  NPM_PM_DIVERGENCE: { priority: 'P2', disposition: 'oracle-investigation', experiment: 'inspect why ordinary npm fails when Nub passes before changing the shared fixture' },
  OBSOLETE_NATIVE_ASSUMPTION: { priority: 'P2', disposition: 'runtime-compatibility', experiment: 'compare supported Node majors; do not hide an ABI failure with a broader jail grant' },
  OBSOLETE_NODE_ASSUMPTION: { priority: 'P2', disposition: 'runtime-compatibility', experiment: 'compare supported Node majors; do not hide a removed Node behavior with a broader jail grant' },
  OBSOLETE_TYPESCRIPT_ASSUMPTION: { priority: 'none', disposition: 'runtime-compatibility', experiment: null },
  OBSOLETE_XCODE_ASSUMPTION: { priority: 'none', disposition: 'runtime-compatibility', experiment: null },
  INCOMPATIBLE_NODE: { priority: 'none', disposition: 'expected-runtime-exclusion', experiment: null },
  OS_CPU_MISMATCH: { priority: 'none', disposition: 'expected-platform-exclusion', experiment: null },
  PACKAGE_BROKEN_OR_UNAVAILABLE: { priority: 'none', disposition: 'terminal-package-failure', experiment: null },
  REFUSED_MALICIOUS: { priority: 'none', disposition: 'security-refusal', experiment: null },
  NO_LIFECYCLE_SCRIPT: { priority: 'none', disposition: 'population-exclusion', experiment: null },
}[code] ?? { priority: 'P1', disposition: 'review', experiment: 'review retained evidence before proposing a profile change' });

export function buildReferenceAccounting({
  rows, worklistSha256, matrix, matrixSha256, profile, instrument, records, expectedNubGitSha = null,
}) {
  const expected = new Map();
  for (const row of rows) for (const node of matrix.versions) {
    expected.set(cellKey(row.pkg, row.version, row.os, node.version), {
      ...row, nodeVersion: node.version, npmVersion: node.npm ?? null,
    });
  }
  const valid = [];
  const invalid = [];
  const duplicate = [];
  const otherProfiles = {};
  const seen = new Map();
  const recordedNubGitShas = new Set(records
    .filter((record) => record.source?.kind === 'legacy-reference-accounting')
    .map((record) => record.provenance?.nub?.gitSha).filter((value) => /^[a-f0-9]{40}$/.test(value ?? '')));
  const nubGitSha = expectedNubGitSha ?? (recordedNubGitShas.size === 1 ? [...recordedNubGitShas][0] : null);
  if (expectedNubGitSha && !/^[a-f0-9]{40}$/.test(expectedNubGitSha)) {
    throw new Error('expected Nub git SHA must be 40 lowercase hexadecimal characters');
  }
  for (const record of records) {
    if (record._readError) {
      invalid.push({ key: null, reason: 'read-error', file: record._file, error: record._readError });
      continue;
    }
    if (record.source?.kind !== 'legacy-reference-accounting') continue;
    const key = cellKey(record.pkg, record.version, record.source?.os, record.source?.nodeVersion);
    const wanted = expected.get(key);
    let reason = null;
    if (!wanted) reason = 'unexpected-cell';
    else if (record.source.worklistSha256 !== worklistSha256
      || record.source.priorRecordSha256 !== wanted.prior.recordSha256) reason = 'worklist';
    else if (record.source.nodeMatrixSha256 !== matrixSha256) reason = 'node-matrix';
    else if (record.profile?.sha256 !== profile.sha256) {
      const keyProfile = `${record.profile?.id ?? 'unknown'}@${record.profile?.sha256 ?? 'unknown'}`;
      otherProfiles[keyProfile] = (otherProfiles[keyProfile] ?? 0) + 1;
      continue;
    } else if (record.provenance?.runtime?.node?.version !== `v${record.source.nodeVersion}`
      || !/^[a-f0-9]{64}$/.test(record.provenance?.runtime?.node?.sha256 ?? '')) reason = 'runtime-node';
    else if (osForPlatform(record.provenance?.runtime?.os?.platform) !== record.source.os) reason = 'runtime-os';
    else if (record.provenance?.orchestrator?.node?.version !== `v${matrix.harnessNode}`
      || !/^[a-f0-9]{64}$/.test(record.provenance?.orchestrator?.node?.sha256 ?? '')) reason = 'orchestrator';
    else if (wanted.npmVersion && record.provenance?.npm?.version !== wanted.npmVersion) reason = 'runtime-npm';
    else if (!/^[a-f0-9]{64}$/.test(record.provenance?.npm?.executable?.sha256 ?? '')) reason = 'runtime-npm';
    else if (!nubGitSha || record.provenance?.nub?.gitSha !== nubGitSha
      || !/^[a-f0-9]{64}$/.test(record.provenance?.nub?.sha256 ?? '')
      || (record.provenance?.runtime?.os?.platform === 'win32'
        && !/^[a-f0-9]{64}$/.test(record.provenance?.nub?.sidecars?.busybox?.sha256 ?? ''))) {
      reason = 'nub-subject';
    }
    else if (JSON.stringify(record.provenance?.instrument) !== JSON.stringify(instrument)) reason = 'instrument';
    else if (referenceEvidenceSha(record) !== record.provenance?.evidenceSha256) reason = 'evidence-hash';
    else if (!record.classification?.code || !record.classification?.status) reason = 'classification';
    if (reason) { invalid.push({ key, reason, pkg: record.pkg, version: record.version }); continue; }
    if (seen.has(key)) { duplicate.push({ key, pkg: record.pkg, version: record.version }); continue; }
    seen.set(key, record); valid.push(record);
  }
  const missing = [...expected.entries()].filter(([key]) => !seen.has(key)).map(([, row]) => row);
  const incomplete = valid.filter((record) => record.classification.status === 'incomplete'
    || record.classification.code === 'UNCLASSIFIED');
  const byClassification = countBy(valid, (record) => record.classification.code);
  const byOs = countBy(valid, (record) => record.source.os);
  const byNode = countBy(valid, (record) => record.source.nodeVersion);
  const byProfile = countBy(valid, (record) => record.profile.id);
  const transitions = {};
  for (const bucket of [...new Set(valid.map((record) => record.source.prior?.bucket).filter(Boolean))].sort()) {
    transitions[bucket] = countBy(valid.filter((record) => record.source.prior?.bucket === bucket),
      (record) => record.classification.code);
  }

  const oldBrokenRows = rows.filter((row) => row.prior.bucket === 'brokenWithoutJailToo');
  const passLegacyKeys = new Set(valid.filter((record) => record.classification.code === 'REFERENCE_PASSES')
    .map((record) => legacyKey({ ...record, os: record.source.os })));
  const noLifecycleKeys = new Set(valid.filter((record) => record.classification.code === 'NO_LIFECYCLE_SCRIPT')
    .map((record) => legacyKey({ ...record, os: record.source.os })));
  const cleared = oldBrokenRows.filter((row) => passLegacyKeys.has(legacyKey(row)));
  const excludedNoLifecycle = oldBrokenRows.filter((row) => noLifecycleKeys.has(legacyKey(row)));
  const fixed = { lowerBound: true, ...units(cleared), expectedLegacyRows: oldBrokenRows.length };
  const noLifecycle = { lowerBound: true, ...units(excludedNoLifecycle), expectedLegacyRows: oldBrokenRows.length };

  const backlogGroups = new Map();
  for (const record of valid.filter((entry) => entry.classification.code !== 'REFERENCE_PASSES')) {
    const code = record.classification.code;
    if (remediationFor(code).priority === 'none') continue;
    const fingerprints = fingerprintsFor(record);
    const signature = `${code}\0${fingerprints.join(',') || record.classification.summary}`;
    if (!backlogGroups.has(signature)) backlogGroups.set(signature, {
      code, fingerprints, firstErrors: new Set(), records: [],
    });
    for (const summary of firstErrorsFor(record)) backlogGroups.get(signature).firstErrors.add(summary);
    backlogGroups.get(signature).records.push(record);
  }
  const backlog = [...backlogGroups.values()].map((group) => ({
    code: group.code,
    ...remediationFor(group.code),
    fingerprints: group.fingerprints,
    firstErrors: [...group.firstErrors].slice(0, 20),
    counts: units(group.records),
    evidence: [...new Set(group.records.flatMap((record) => record.classification.evidence ?? []))].slice(0, 20),
    examples: group.records.slice(0, 12).map((record) => ({
      pkg: record.pkg, version: record.version, os: record.source.os, node: record.source.nodeVersion,
      priorVerdict: record.source.prior?.verdict ?? null,
      outcomes: Object.fromEntries(Object.entries(record.arms ?? {})
        .map(([name, arm]) => [name, arm.quorum?.outcome ?? null])),
    })),
  })).sort((a, b) => `${a.priority}\0${a.code}\0${a.fingerprints.join(',')}`
    .localeCompare(`${b.priority}\0${b.code}\0${b.fingerprints.join(',')}`));

  const complete = missing.length === 0 && invalid.length === 0 && duplicate.length === 0;
  const classified = incomplete.length === 0;
  return {
    schemaVersion: 1,
    status: complete && classified ? 'complete' : 'incomplete',
    inputs: { worklistSha256, nodeMatrixSha256: matrixSha256, profile, instrument, nubGitSha },
    expected: { ...units([...expected.values()]), runtimeCells: expected.size },
    observed: units(valid),
    integrity: { missing: missing.length, invalid, duplicate, incomplete: incomplete.length, otherProfiles },
    fixedFormerBrokenWithoutJail: fixed,
    excludedFormerBrokenWithoutJailNoLifecycle: noLifecycle,
    byClassification,
    intersections: { os: byOs, node: byNode, profile: byProfile, priorBucketToClassification: transitions },
    backlog,
  };
}

export function readReferenceRecords(root) {
  return walkNamed(root, 'reference.json').map((file) => {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (error) { return { _readError: error.message, _file: file }; }
  });
}

const parseArgs = (argv) => {
  const valued = new Set(['--records', '--worklist', '--node-matrix', '--profile', '--out', '--backlog', '--nub-git-sha']);
  const flags = new Set(['--strict', '--complete']);
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (flags.has(argv[i])) { options[argv[i].slice(2)] = true; continue; }
    if (!valued.has(argv[i]) || argv[i + 1] == null) throw new Error(`unknown or incomplete option ${argv[i]}`);
    options[argv[i].slice(2)] = argv[++i];
  }
  return options;
};

function cli(argv) {
  const options = parseArgs(argv);
  for (const required of ['records', 'worklist', 'out']) if (!options[required]) throw new Error(`--${required} is required`);
  const base = import.meta.dirname;
  const worklist = readReferenceWorklist(path.resolve(options.worklist));
  const nodeMatrix = loadNodeMatrix(path.resolve(options['node-matrix'] ?? path.join(base, 'node-matrix.json')));
  const profile = referenceProfileIdentity(loadReferenceProfile(path.resolve(options.profile ?? path.join(base, 'reference-profile.json'))));
  const report = buildReferenceAccounting({ rows: worklist.rows, worklistSha256: worklist.sha256,
    matrix: nodeMatrix.matrix, matrixSha256: nodeMatrix.sha256, profile, instrument: computeHarnessIdentity(),
    records: readReferenceRecords(path.resolve(options.records)), expectedNubGitSha: options['nub-git-sha'] ?? null });
  const out = path.resolve(options.out); fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  const backlogFile = path.resolve(options.backlog ?? out.replace(/\.json$/, '.backlog.json'));
  fs.writeFileSync(backlogFile, `${JSON.stringify({ schemaVersion: 1, groups: report.backlog }, null, 2)}\n`);
  console.log(`REFERENCE-REPORT status=${report.status} expected=${report.expected.runtimeCells} observed=${report.observed.rows} missing=${report.integrity.missing} incomplete=${report.integrity.incomplete}`);
  console.log(`REFERENCE-REPORT fixed-old-broken-lower-bound=${report.fixedFormerBrokenWithoutJail.rows}/${report.fixedFormerBrokenWithoutJail.expectedLegacyRows}`);
  console.log(`REFERENCE-REPORT classes=${JSON.stringify(report.byClassification)}`);
  if ((options.complete && report.integrity.missing) || (options.strict && report.status !== 'complete')) process.exitCode = 3;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-REPORT-ERROR ${error.stack ?? error.message}`); process.exitCode = 2; }
}
