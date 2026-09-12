// Materialize one bounded artifact-only campaign chunk and fail closed before any package install.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { screenSpecs } from '../osv-screen.mjs';

export const MAX_SPECS = 5;
export const PLATFORMS = new Set(['linux', 'macos', 'windows']);
const RUNNERS = { linux: 'ubuntu-24.04', macos: 'macos-14', windows: 'windows-2022' };

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

export function readManifest(file) {
  const bytes = fs.readFileSync(file);
  let manifest;
  try { manifest = JSON.parse(bytes); } catch (error) { throw new Error(`manifest is not JSON: ${error.message}`); }
  if (manifest?.schemaVersion !== 2 || !Array.isArray(manifest?.chunks)) {
    throw new Error('manifest lacks schemaVersion 2 chunks');
  }
  return { manifest, sha256: sha256(bytes) };
}

export function selectChunk(manifest, chunk, platform) {
  const index = Number(chunk);
  if (!Number.isInteger(index) || index < 1) throw new Error(`chunk must be a positive integer, got ${chunk}`);
  if (!PLATFORMS.has(platform)) throw new Error(`platform must be one of ${[...PLATFORMS].join(', ')}, got ${platform}`);
  const selected = manifest.chunks.find((entry) => entry?.index === index);
  if (!selected || !Array.isArray(selected.specs)) throw new Error(`manifest has no chunk ${index}`);
  if (!selected.specs.length || selected.specs.length > MAX_SPECS) throw new Error(`chunk ${index} has invalid size ${selected.specs.length}`);
  if (new Set(selected.specs).size !== selected.specs.length) throw new Error(`chunk ${index} has duplicate specs`);
  for (const spec of selected.specs) {
    const at = typeof spec === 'string' ? spec.lastIndexOf('@') : -1;
    if (at <= 0 || at === spec.length - 1) throw new Error(`chunk ${index} has invalid exact spec ${JSON.stringify(spec)}`);
  }
  return { index, platform, specs: selected.specs };
}

export function selectRun(manifest, plan) {
  if (!Array.isArray(plan?.chunks) || !plan.chunks.length
    || !Array.isArray(plan?.platforms) || !plan.platforms.length) {
    throw new Error('run plan requires nonempty chunks and platforms');
  }
  if (new Set(plan.chunks).size !== plan.chunks.length
    || new Set(plan.platforms).size !== plan.platforms.length) {
    throw new Error('run plan contains duplicate selections');
  }
  const jobs = plan.platforms.flatMap((platform) => plan.chunks.map((chunk) => {
    const selected = selectChunk(manifest, chunk, platform);
    return { chunk: selected.index, platform, runner: RUNNERS[platform] };
  }));
  if (jobs.length > 90) throw new Error('run plan exceeds 90 jobs');
  return { include: jobs };
}

export function materializeChunk({ manifestFile, chunk, platform, out }) {
  const { manifest, sha256: manifestSha256 } = readManifest(manifestFile);
  const selected = selectChunk(manifest, chunk, platform);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, `${selected.specs.join('\n')}\n`);
  return { ...selected, manifestSha256, worklistSha256: sha256(fs.readFileSync(out)) };
}

export function screenWorklist({ file, out, cacheDir, request = null }) {
  const specs = fs.readFileSync(file, 'utf8').split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (!specs.length || specs.length > MAX_SPECS || new Set(specs).size !== specs.length) {
    throw new Error(`worklist must contain 1..${MAX_SPECS} unique specs`);
  }
  return screenSpecs({ specs, kind: 'catalog-campaign-worklist', out, cacheDir, request });
}

function cli(argv) {
  const option = (name) => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
  const manifest = option('--manifest'); const chunk = option('--chunk'); const platform = option('--platform');
  const out = option('--out'); const screen = argv.includes('--screen'); const cacheDir = option('--cache-dir');
  if (argv.includes('--matrix')) {
    if (!manifest) throw new Error('--matrix requires --manifest');
    const planFile = option('--plan');
    const plan = chunk && platform ? { chunks: [Number(chunk)], platforms: [platform] }
      : JSON.parse(fs.readFileSync(planFile, 'utf8'));
    console.log(JSON.stringify(selectRun(readManifest(manifest).manifest, plan)));
    return;
  }
  if (!manifest || !chunk || !platform || !out) throw new Error('usage: --manifest <file> --chunk <n> --platform <os> --out <worklist> [--screen --cache-dir <dir>]');
  const result = materializeChunk({ manifestFile: path.resolve(manifest), chunk, platform, out: path.resolve(out) });
  if (screen) {
    if (!cacheDir) throw new Error('--screen requires --cache-dir');
    const clearance = screenWorklist({ file: out, out: `${out}.osv.json`, cacheDir: path.resolve(cacheDir) });
    if (clearance.status !== 'clean') process.exitCode = 42;
  }
  console.log(JSON.stringify(result));
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`CATALOG-CAMPAIGN-INPUT-ERROR ${error.message}`); process.exitCode = 2; }
}
