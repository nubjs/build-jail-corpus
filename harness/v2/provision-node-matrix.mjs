// Pre-provision every Node in the matrix, ONCE per box, into a STABLE cache the drivers can read.
//
// ⛔ WHY THIS IS A SEPARATE STEP AND NOT SOMETHING A DRIVER DOES PER PACKAGE. Both shell drivers set
// `NUB_CACHE_DIR="$ROOT/nubcache"` — a PER-RUN directory, deliberately, so a measurement cannot be
// contaminated by a previous one's cache. A `nub node install` inside that scope therefore downloads
// ~20 MB EVERY package and throws it away, which at corpus scale is thousands of redundant downloads
// of the same nine tarballs. Measured: one install of 18.20.8 is 20 MB / 3.2 s.
//
// So provisioning is hoisted out of the measurement entirely: run this once, then every driver finds
// the versions already on disk and only has to put the right one first on PATH.
//
// ⛔ THE DRIVERS SELF-ENABLE ON THE DIRECTORY'S EXISTENCE, so this script is the ONLY switch. A box
// that has not run it measures exactly as before — no flag to forget, no half-pinned run. That also
// makes the failure mode legible: a missing pin is a missing provision, not a silent fallback.
//
//   node provision-node-matrix.mjs            # provision all matrix versions
//   node provision-node-matrix.mjs --check    # report what is present, install nothing
//
// The stable root is `NUB_ERA_NODE_ROOT` when set, else nub's own default cache (`~/.cache/nub`), so
// a version already provisioned by ordinary nub use is reused rather than re-fetched.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadNodeMatrix } from './node-matrix.mjs';

/** The stable cache root era-Node versions live under — NEVER a per-run directory. */
export function eraNodeRoot(env = process.env) {
  return env.NUB_ERA_NODE_ROOT || path.join(os.homedir(), '.cache', 'nub');
}

/** Where a provisioned version's `node` executable sits, given the stable root.
 *
 *  ⛔ VERIFIED AGAINST A REAL INSTALL, not inferred from a doc: `nub node install 18.20.8` lands in
 *  `<root>/node/18.20.8/bin/node` — NO `v` prefix on the directory. `nub node ls` did NOT list that
 *  version afterwards even though the directory existed, so the DIRECTORY is the source of truth here
 *  and `ls` is not consulted. */
export function nodeBinDir(root, version) {
  return path.join(root, 'node', version, 'bin');
}

export function isProvisioned(root, version, exists = fs.existsSync) {
  const bin = nodeBinDir(root, version);
  return exists(path.join(bin, 'node')) || exists(path.join(bin, 'node.exe'));
}

/** Provision every matrix version that is missing. Returns one row per version. */
export function provisionMatrix({ nub = 'nub', root = eraNodeRoot(), check = false, run = spawnSync } = {}) {
  const { matrix } = loadNodeMatrix();
  const rows = [];
  for (const entry of matrix.versions) {
    const already = isProvisioned(root, entry.version);
    if (already || check) {
      rows.push({ version: entry.version, major: entry.major, present: already, installed: false });
      continue;
    }
    // A per-version failure is NOT fatal for the others: a box that cannot fetch Node 19 should still
    // be able to measure everything that wants 18 or 22.
    const r = run(nub, ['node', 'install', entry.version],
      { encoding: 'utf8', env: { ...process.env, NUB_CACHE_DIR: root }, timeout: 600_000 });
    const ok = r.status === 0 && isProvisioned(root, entry.version);
    rows.push({ version: entry.version, major: entry.major, present: ok, installed: ok,
      error: ok ? undefined : (r.stderr || r.stdout || `exit ${r.status}`).trim().split('\n').slice(-1)[0] });
  }
  return { root, rows };
}

if (import.meta.filename === process.argv[1]) {
  const check = process.argv.includes('--check');
  const nub = process.env.NUB_BIN || 'nub';
  const { root, rows } = provisionMatrix({ nub, check });
  process.stdout.write(`era-node root: ${root}\n`);
  for (const r of rows) {
    const state = r.present ? (r.installed ? 'installed' : 'present') : `MISSING${r.error ? ` (${r.error})` : ''}`;
    process.stdout.write(`  ${String(r.major).padStart(2)}  ${r.version.padEnd(10)} ${state}\n`);
  }
  const missing = rows.filter((r) => !r.present);
  process.stdout.write(`${rows.length - missing.length}/${rows.length} provisioned\n`);
  // Non-zero when anything is missing, so a batch runner can refuse to start a run that would
  // silently measure everything on the ambient Node.
  process.exit(missing.length ? 1 : 0);
}
