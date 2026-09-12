import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const values = {};
for (let index = 0; index < argv.length; index += 2) {
  const key = argv[index];
  if (!key?.startsWith('--') || argv[index + 1] == null) throw new Error('usage: catalog-sanity-manifest.mjs --out <path> --key <path-or-value> ...');
  values[key.slice(2)] = argv[index + 1];
}
if (!values.out) throw new Error('missing --out');

const digest = (file) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const requiredFiles = ['catalog', 'candidate-bin', 'candidate-addon', 'baseline-bin', 'baseline-addon', 'packages', 'network', 'relocated-store', 'instrument', 'instrument-output', 'workflow', 'manifest-helper', 'subject-helper', 'budget-helper', 'environment'];
for (const key of requiredFiles) {
  if (!values[key]) throw new Error(`missing --${key}`);
  if (!fs.statSync(values[key]).isFile()) throw new Error(`--${key} is not a file: ${values[key]}`);
}

const files = Object.fromEntries(requiredFiles.map((key) => [key, {
  path: values[key], sha256: digest(values[key]), bytes: fs.statSync(values[key]).size,
}]));
for (const key of ['candidate-busybox', 'baseline-busybox']) {
  if (values[key]) files[key] = { path: values[key], sha256: digest(values[key]), bytes: fs.statSync(values[key]).size };
}

const manifest = {
  corpusSha: values['corpus-sha'],
  candidateSourceSha: values['candidate-source-sha'],
  baselineSourceSha: values['baseline-source-sha'],
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  files,
};
for (const key of ['corpusSha', 'candidateSourceSha', 'baselineSourceSha']) {
  if (!/^[a-f0-9]{40}$/.test(manifest[key] ?? '')) throw new Error(`${key} must be a full SHA`);
}
fs.mkdirSync(path.dirname(values.out), { recursive: true });
fs.writeFileSync(values.out, `${JSON.stringify(manifest, null, 2)}\n`);
