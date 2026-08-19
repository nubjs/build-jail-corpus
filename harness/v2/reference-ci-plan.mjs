import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { loadNodeMatrix } from './node-matrix.mjs';
import { loadReferenceProfile } from './reference-profile.mjs';

const runners = {
  linux: 'ubuntu-24.04',
  macos: 'macos-15',
  windows: 'windows-2025',
};

const platformForOs = { linux: 'linux', macos: 'darwin', windows: 'win32' };

export function planReferenceCells(matrix, {
  os = 'linux', node = matrix.versions.at(-1)?.version, shards = 1, profile = null,
} = {}) {
  const operatingSystems = os === 'all' ? Object.keys(runners) : [os];
  if (operatingSystems.some((name) => !runners[name])) throw new Error(`unknown reference OS ${os}`);
  if (profile) {
    const unsupported = operatingSystems.filter((name) => !profile.supportedPlatforms.includes(platformForOs[name]));
    if (unsupported.length) {
      throw new Error(`reference profile ${profile.id} does not support ${unsupported.join(', ')}`);
    }
  }
  // ⛔ `all` MEANS EVERY NUB-SUPPORTED MAJOR, NOT EVERY MAJOR THE MATRIX CARRIES, and the two stopped
  // being the same thing when the matrix dropped its floor to 4. The matrix now serves two different
  // consumers: ERA SELECTION for the corpus, which needs 4 upward so an old package can be measured
  // on the runtime its author targeted, and THIS plan, which measures REFERENCE behaviour across the
  // Nodes Nub supports. Crossing all 23 majors with 3 operating systems and 8 shards is 552 jobs
  // against GitHub's limit of 256 — the suite caught it, and the honest fix is to say which range
  // this consumer wants rather than to raise the cap.
  //
  // This is exactly what `nubMinimum` is retained in the matrix FOR: a recorded fact about which
  // Nodes Nub augments, no longer the matrix's floor.
  const nubFloor = Number(String(matrix.nubMinimum).split('.')[0]);
  const supported = matrix.versions.filter((entry) => entry.major >= nubFloor);
  const selected = node === 'all' ? supported
    : matrix.versions.filter((entry) => entry.version === node);
  if (!selected.length) throw new Error(`unknown reference Node version ${node}`);
  shards = Number(shards);
  if (![1, 2, 4, 8, 16].includes(shards)) throw new Error(`reference shards must be one of 1, 2, 4, 8, or 16`);
  const include = operatingSystems.flatMap((name) => selected.flatMap((entry) =>
    Array.from({ length: shards }, (_, shard) => ({
      os: name,
      runner: runners[name],
      node: entry.version,
      npm: entry.npm,
      shard,
      shards,
    }))));
  if (include.length > 256) {
    throw new Error(`reference plan has ${include.length} jobs, exceeding the GitHub matrix limit of 256`);
  }
  return { include };
}

const parseArgs = (argv) => {
  const valued = new Set(['--os', '--node', '--shards', '--node-matrix', '--profile', '--github-output']);
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (!valued.has(argv[i]) || argv[i + 1] == null) throw new Error(`unknown or incomplete option ${argv[i]}`);
    options[argv[i].slice(2)] = argv[++i];
  }
  return options;
};

function cli(argv) {
  const options = parseArgs(argv);
  const { matrix } = loadNodeMatrix(options['node-matrix']);
  const profile = options.profile ? loadReferenceProfile(options.profile) : null;
  const plan = planReferenceCells(matrix, {
    os: options.os ?? 'linux', node: options.node, shards: options.shards ?? 1, profile,
  });
  const value = JSON.stringify(plan);
  if (options['github-output']) {
    const build = JSON.stringify({ include: [...new Map(plan.include
      .map((cell) => [cell.os, { os: cell.os, runner: cell.runner }])).values()] });
    fs.appendFileSync(options['github-output'], `matrix=${value}\nbuild_matrix=${build}\n`);
  }
  console.log(value);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { cli(process.argv.slice(2)); }
  catch (error) { console.error(`REFERENCE-CI-PLAN-ERROR ${error.message}`); process.exitCode = 2; }
}
