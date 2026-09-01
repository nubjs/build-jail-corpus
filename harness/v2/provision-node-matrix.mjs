// Pre-provision every Node in the matrix, ONCE per box, into a STABLE cache the drivers can read.
//
// ⛔ WHY THIS IS A SEPARATE STEP AND NOT SOMETHING A DRIVER DOES PER PACKAGE. Both shell drivers set
// `NUB_CACHE_DIR="$ROOT/nubcache"` — a PER-RUN directory, deliberately, so a measurement cannot be
// contaminated by a previous one's cache. Any fetch inside that scope therefore downloads ~20 MB EVERY
// package and throws it away, which at corpus scale is thousands of redundant downloads of the same
// tarballs. Measured: one install of 18.20.8 is 20 MB / 3.2 s.
//
// So provisioning is hoisted out of the measurement entirely: run this once, then every driver finds
// the versions already on disk and only has to put the right one first on PATH.
//
// ⛔ THE DRIVERS SELF-ENABLE ON THE DIRECTORY'S EXISTENCE, so this script is the fast path rather than
// a switch: a box that has not run it still pins, per package, through `era-provision.mjs`. What this
// step buys is that the fetch happens once instead of being re-checked on every package, and that
// `run-batch-v2.mjs` can tell BEFORE a run whether every era in the matrix is reachable.
//
//   node provision-node-matrix.mjs            # provision all matrix versions
//   node provision-node-matrix.mjs --check    # report what is present, install nothing
//
// The stable root is `NUB_ERA_NODE_ROOT` when set, else nub's own default cache (`~/.cache/nub`), so
// a version already provisioned by ordinary nub use is reused rather than re-fetched.
//
// ⛔ DETECTION SPANS BOTH LAYOUTS A PROVISIONED NODE CAN HAVE — nub's `<root>/node/<version>/…` and
// `era-provision.mjs`'s `<root>/era-node/<version>/<stem>/…`. Knowing only the first made this module
// answer MISSING for every version on a box the drivers had already provisioned. See `nodeBinDir`.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { eraLayout, provisionEraNode } from './era-provision.mjs';
import { loadNodeMatrix } from './node-matrix.mjs';

/** The stable cache root era-Node versions live under — NEVER a per-run directory. */
export function eraNodeRoot(env = process.env) {
  return env.NUB_ERA_NODE_ROOT || path.join(os.homedir(), '.cache', 'nub');
}

/** Where a provisioned version's `node` executable sits, given the stable root.
 *
 *  ⛔ THE WINDOWS ARCHIVE IS FLAT AND THAT IS NOT A DETAIL — IT IS A DIFFERENT PATH. On POSIX the
 *  distribution has `bin/node`; the Windows zip puts `node.exe` at the version ROOT, with
 *  `node_modules`, `npm.cmd` and `corepack.cmd` beside it and NO `bin/` at all. Verified by listing a
 *  real `nub node install 18.20.8` on `nub-win3`, and it is the same flat/`bin` split the sandbox's
 *  own `grant_build_jail_extra_reads` comment documents for the interpreter closure.
 *
 *  Getting this wrong is SILENT AND TOTAL on Windows: `bin/node.exe` never exists, so every version
 *  reads as MISSING even straight after a successful install, the pin never engages, and the hard gate
 *  blocks forever. That is exactly what happened — the provisioner reported `0/9 provisioned` while
 *  nub printed "Installed in 6.6s" nine times.
 *
 *  ⛔ ALSO VERIFIED: no `v` prefix on the version directory, and `nub node ls` did NOT list a version
 *  it had just installed — so the DIRECTORY is the source of truth here and `ls` is never consulted.
 *
 *  ⛔⛔ TWO LAYOUTS EXIST ON A REAL BOX AND THIS FILE USED TO KNOW ONLY ONE. `era-provision.mjs` — the
 *  per-package fallback every driver reaches when this hoisted step has not run — unpacks a nodejs.org
 *  archive into `<root>/era-node/<version>/<stem>/`, not into nub's `<root>/node/<version>/`. MEASURED
 *  on the corpus: of 484 post-era `BROKEN-WITHOUT-JAIL-TOO` records, 476 read
 *  `ERA-NODE PINNED <v> (provisioned)` — the `(provisioned)` suffix means the fast path that calls this
 *  function MISSED and the fallback ran, on every single record, and the recorded `pinnedBin` is
 *  `…/.cache/nub/era-node/4.9.1/node-v4.9.1-linux-x64/bin`.
 *
 *  The consequence is not cosmetic. `run-batch-v2.mjs` gates a run on this answer, so a box whose Nodes
 *  were provisioned the way boxes actually get provisioned reports `0/23` and, under
 *  `NUB_V2_REQUIRE_ERA_NODE=1`, REFUSES TO START. This is the same "one owner for a path, or it drifts"
 *  failure `era-provision.mjs` records in its own CLI comment, drifted back the other way. */
export function nodeBinCandidates(root, version, platform = process.platform, arch = process.arch) {
  const nubRoot = path.join(root, 'node', version);
  const eraRoot = path.join(root, 'era-node', version);
  const { stem, binSubdir } = eraLayout(version, { platform, arch });
  // nub's layout FIRST, so it stays the answer when nothing is on disk and the fallback below is a
  // pure path computation — which is what keeps this usable to build a path before provisioning.
  return [
    platform === 'win32' ? nubRoot : path.join(nubRoot, 'bin'),
    // Nothing is stripped during extraction, so the payload sits under the archive's own stem —
    // except in a cache written before that change, which era-provision.mjs still accepts.
    path.resolve(eraRoot, stem, binSubdir),
    path.resolve(eraRoot, binSubdir),
  ];
}

/** ⛔ RESOLVES, and it must: the caller pairs this with `isProvisioned` to build a PATH entry, so a
 *  `present` decided under one layout and a directory built under another is the false-PRESENT this
 *  module's test header calls the worst outcome — a PATH pointing at nothing, an arm silently on the
 *  ambient Node, and a record claiming the pin. Falls back to nub's layout when nothing exists. */
export function nodeBinDir(root, version, platform = process.platform, exists = fs.existsSync,
                           arch = process.arch) {
  const candidates = nodeBinCandidates(root, version, platform, arch);
  return candidates.find((d) => exists(path.join(d, 'node')) || exists(path.join(d, 'node.exe')))
    ?? candidates[0];
}

export function isProvisioned(root, version, exists = fs.existsSync, platform = process.platform,
                              arch = process.arch) {
  const bin = nodeBinDir(root, version, platform, exists, arch);
  return exists(path.join(bin, 'node')) || exists(path.join(bin, 'node.exe'));
}

/** Provision every matrix version that is missing. Returns one row per version.
 *
 *  ⛔ THE DOWNLOAD IS `era-provision.mjs`'s, NOT `nub node install`'s, AND THAT IS A CORRECTION.
 *  This used to spawn `nub node install <version>` with `NUB_CACHE_DIR: root` to redirect it at the
 *  stable root. That redirect is INERT: nub's Node store is `cache_dir()/node/…` and `cache_dir()`
 *  reads only `XDG_CACHE_HOME` (`nub-core/src/node/discovery.rs`), while `NUB_CACHE_DIR` is the PM
 *  tarball-cache knob and never reaches it. With the default root the two coincided and it looked
 *  correct; with `NUB_ERA_NODE_ROOT` set it installed into `~/.cache/nub`, then asked the CUSTOM root
 *  whether the version was there, got MISSING, and re-installed all of them on every invocation.
 *
 *  `provisionEraNode` honours a root, needs no `nub` on PATH (this gate runs before a run does), and
 *  EXECUTES the binary to match `--version` — so a truncated download or a wrong-arch build is a loud
 *  mismatch rather than a pin that quietly is not the era. It is also what the drivers already fall
 *  back to, so one provisioner now writes what one detector reads. */
export function provisionMatrix({ root = eraNodeRoot(), check = false, provision = provisionEraNode } = {}) {
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
    const r = provision(entry.version, { root: path.join(root, 'era-node') });
    const ok = Boolean(r?.binDir);
    rows.push({ version: entry.version, major: entry.major, present: ok, installed: ok,
      binDir: r?.binDir ?? null,
      error: ok ? undefined : (r?.status ?? 'provisioner returned nothing') });
  }
  return { root, rows };
}

if (import.meta.filename === process.argv[1]) {
  const check = process.argv.includes('--check');
  const { root, rows } = provisionMatrix({ check });
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
