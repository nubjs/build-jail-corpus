// Fail-closed OSV screening for an exact npm package-version set.
//
// The corpus uses this at two different boundaries:
//   1. a direct name@version screen before fetching the requested tarball; and
//   2. a resolved-tree screen after an --ignore-scripts install and before any lifecycle script.
//
// A direct screen cannot replace the tree screen: a clean target can resolve a compromised
// transitive dependency. A tree clearance is reusable only when the sorted exact spec set hashes to
// the same digest. Callers should keep the cache inside one measurement run; OSV changes over time.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const CHUNK_SIZE = 500;
const EXIT_MALICIOUS = 42;

export function splitSpec(spec) {
  if (typeof spec !== 'string') return null;
  const at = spec.lastIndexOf('@');
  if (at <= 0 || at === spec.length - 1) return null;
  return [spec.slice(0, at), spec.slice(at + 1)];
}

export function normalizeSpecs(specs) {
  const out = [...new Set(specs)];
  for (const spec of out) {
    const parsed = splitSpec(spec);
    if (!parsed || parsed.some((part) => part.length === 0)) {
      throw new Error(`unusable exact npm spec ${JSON.stringify(spec)}`);
    }
  }
  return out.sort();
}

export function digestSpecs(specs) {
  const normalized = normalizeSpecs(specs);
  if (normalized.length === 0) throw new Error('resolved tree contained zero package versions');
  return crypto.createHash('sha256').update(`${normalized.join('\n')}\n`).digest('hex');
}

/**
 * Enumerate the dependency graph reachable from a project's node_modules. Package directories may
 * be real directories, POSIX symlinks, or Windows junctions. We follow their real paths, but visit
 * each physical package and node_modules directory once so virtual-store back-links cannot loop.
 */
export function collectInstalledSpecs(projectRoot) {
  const specs = new Set();
  const visitedPackages = new Set();
  const visitedModules = new Set();

  const real = (p) => {
    try { return fs.realpathSync(p); } catch { return null; }
  };

  const visitPackage = (pkgDir) => {
    const physical = real(pkgDir);
    if (!physical || visitedPackages.has(physical)) return;
    visitedPackages.add(physical);

    let manifest;
    try { manifest = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')); } catch (e) {
      throw new Error(`cannot read installed manifest ${path.join(pkgDir, 'package.json')}: ${e.message}`);
    }
    if (typeof manifest.name !== 'string' || !manifest.name
      || typeof manifest.version !== 'string' || !manifest.version) {
      throw new Error(`installed manifest ${path.join(pkgDir, 'package.json')} lacks exact name/version`);
    }
    specs.add(`${manifest.name}@${manifest.version}`);
    visitModules(path.join(pkgDir, 'node_modules'));
  };

  const visitModules = (modulesDir) => {
    const physical = real(modulesDir);
    if (!physical || visitedModules.has(physical)) return;
    visitedModules.add(physical);

    let entries;
    try { entries = fs.readdirSync(modulesDir, { withFileTypes: true }); } catch (e) {
      throw new Error(`cannot enumerate installed tree ${modulesDir}: ${e.message}`);
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const entryPath = path.join(modulesDir, entry.name);
      if (entry.name.startsWith('@')) {
        let scoped;
        try { scoped = fs.readdirSync(entryPath, { withFileTypes: true }); } catch (e) {
          throw new Error(`cannot enumerate installed scope ${entryPath}: ${e.message}`);
        }
        for (const child of scoped) {
          if (child.name.startsWith('.')) continue;
          visitPackage(path.join(entryPath, child.name));
        }
      } else {
        visitPackage(entryPath);
      }
    }
  };

  const modules = path.join(projectRoot, 'node_modules');
  if (!real(modules)) throw new Error(`installed tree is absent: ${modules}`);
  visitModules(modules);
  return normalizeSpecs([...specs]);
}

export function queriesFor(specs) {
  return normalizeSpecs(specs).map((spec) => {
    const [name, version] = splitSpec(spec);
    return { package: { name, ecosystem: 'npm' }, version };
  });
}

/** Query OSV and return [{spec, ids}]. `request` is injectable for deterministic tests. */
export function queryOsvMalware(specs, request = null) {
  const normalized = normalizeSpecs(specs);
  const queries = queriesFor(normalized);
  const flagged = [];

  const curlRequest = (slice) => {
    const r = spawnSync('curl', ['-sS', '--fail-with-body', '--max-time', '120', '-X', 'POST',
      'https://api.osv.dev/v1/querybatch', '-H', 'Content-Type: application/json',
      '--data-binary', '@-'], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, input: JSON.stringify({ queries: slice }),
    });
    if (r.status !== 0) {
      throw new Error(`OSV query failed (curl ${r.status}): ${(r.stderr || r.stdout || '').slice(0, 300)}`);
    }
    try { return JSON.parse(r.stdout); } catch (e) {
      throw new Error(`OSV response was not JSON: ${e.message}`);
    }
  };

  for (let offset = 0; offset < queries.length; offset += CHUNK_SIZE) {
    const slice = queries.slice(offset, offset + CHUNK_SIZE);
    const parsed = (request ?? curlRequest)(slice, offset);
    const results = parsed?.results;
    if (!Array.isArray(results) || results.length !== slice.length) {
      throw new Error(`OSV returned ${Array.isArray(results) ? results.length : 'no'} results for `
        + `${slice.length} queries at offset ${offset}; refusing a partial or malformed screen`);
    }
    results.forEach((result, i) => {
      const ids = [...new Set((result?.vulns ?? []).map((v) => v?.id)
        .filter((id) => typeof id === 'string' && id.startsWith('MAL-'))) ].sort();
      if (ids.length) flagged.push({ spec: normalized[offset + i], ids });
    });
  }
  return flagged;
}

export function screenSpecs({ specs, kind, cacheDir, out, request = null }) {
  const normalized = normalizeSpecs(specs);
  const digest = digestSpecs(normalized);
  const cachePath = cacheDir ? path.join(cacheDir, `${digest}.json`) : null;
  let result = null;
  if (cachePath) {
    try {
      const candidate = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
      if (candidate.digest === digest && candidate.status === 'clean'
        && JSON.stringify(candidate.specs) === JSON.stringify(normalized)) {
        result = { ...candidate, kind, cacheHit: true };
      }
    } catch { /* a missing or malformed cache is not a clearance */ }
  }
  if (!result) {
    const maliciousAdvisories = queryOsvMalware(normalized, request);
    result = {
      schemaVersion: 1,
      kind,
      status: maliciousAdvisories.length ? 'refused-malicious' : 'clean',
      digest,
      specCount: normalized.length,
      specs: normalized,
      maliciousAdvisories,
      screenedAt: new Date().toISOString(),
      cacheHit: false,
    };
    if (cachePath && result.status === 'clean') {
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(cachePath, `${JSON.stringify(result, null, 2)}\n`);
    }
  }
  if (out) {
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
  }
  return result;
}

function cli(argv) {
  const specs = [];
  let tree = null; let kind = null; let cacheDir = null; let out = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--spec') specs.push(argv[++i]);
    else if (arg === '--tree') tree = argv[++i];
    else if (arg === '--kind') kind = argv[++i];
    else if (arg === '--cache-dir') cacheDir = argv[++i];
    else if (arg === '--out') out = argv[++i];
    else throw new Error(`unknown argument ${arg}`);
  }
  if ((tree ? 1 : 0) + (specs.length ? 1 : 0) !== 1) {
    throw new Error('name exactly one input: --tree <project> or one or more --spec <name@version>');
  }
  if (!kind) throw new Error('--kind is required');
  const selected = tree ? collectInstalledSpecs(tree) : specs;
  const result = screenSpecs({ specs: selected, kind, cacheDir, out });
  // One machine-readable line for record.mjs. Keep the full exact spec set in the clearance file,
  // but not in driver stdout: a large dependency graph would otherwise bloat every corpus record.
  const marker = { ...result };
  delete marker.specs;
  console.log(`OSV-SCREEN ${JSON.stringify(marker)}`);
  if (result.status === 'clean') {
    console.log(`  SECURITY ${kind} clean: ${result.specCount} exact package-version(s), tree ${result.digest.slice(0, 12)}`
      + `${result.cacheHit ? ' (cached exact-tree clearance)' : ''}`);
    return 0;
  }
  console.log(`  => REFUSED-MALICIOUS (${kind} OSV screen): `
    + result.maliciousAdvisories.map((x) => `${x.spec} [${x.ids.join(',')}]`).join('; '));
  return EXIT_MALICIOUS;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try { process.exitCode = cli(process.argv.slice(2)); } catch (e) {
    console.error(`OSV-SCREEN-ERROR ${e.message}`);
    process.exitCode = 2;
  }
}

export { EXIT_MALICIOUS };
