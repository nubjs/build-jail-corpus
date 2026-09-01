// The FOURTH replay path, made shared so it stops being a one-driver fix.
//
// ⛔⛔ THIS IS NOT A NEW GUARD. `measure.sh` has carried it since the `playwright-chromium@0.17.0`
// measurement, under the heading "THE FOURTH REPLAY PATH, AND THE STORE EVICTION ABOVE CANNOT REACH
// IT". `measure-macos.sh` and `measure-windows.mjs` never got it — grep either for `jail-home`,
// `ms-playwright` or `SE-PURGE` and both come back empty. That is the same shape as the two
// one-driver fixes this harness already records (`dep-scaffold.mjs`'s header: "the dependency-scaffold
// fix landed in `measure.sh` on 2026-08-07 and was LINUX-ONLY for as long as it took to notice… That
// is the SECOND time a v2 fix reached one driver and was mistaken for landed"). So the body moves
// here, all three drivers call it, and `arm-artifact-cache.test.mjs` asserts all three do.
//
// ⛔ THE GAP IS VISIBLE IN THE COMMITTED CORPUS AND IT IS ONE-SIDED. Of 6,887 records, 110 wrote into
// `pm/tools/{electron-cache,ms-playwright}` and 44 of those are `MINIMUM` with an EMPTY grant — 44 of
// 44 on **darwin-arm64**, none on linux, across exactly two families (`electron` ×6,
// `electron-chromedriver` ×38). The platform split IS the missing port.
//
// MEASURED 2026-09-01, `electron@33.4.11`, darwin-arm64, nub at the pinned `30757a70` built with
// `--features nub-cli/build-jail-catalog-override` (the corpus runner's own feature set). Grant `{}`
// in every row; the only variable is what ran before it in the same state root, with `HOME`,
// `XDG_CACHE_HOME`, `XDG_DATA_HOME` and `TMPDIR` all pinned under one directory so "cold" is
// provable rather than assumed:
//
//   COLD — nothing ran first                    rc=1  `getaddrinfo ENOTFOUND github.com`, no `dist/`
//   WARM — a `{write:{userHome},network}` arm    rc=0  `dist/` present  ← what the record captured
//   WARM + THIS EVICTION                         rc=1  red again, and `node-gyp`/`npm-prefix` spared
//
// The committed record for that cell reads `VERIFY[nar-no-network] rc=0 artifacts=109/109 missing=0`
// and narrows to `{}`; `harness/overrides/electron.json` records that same grant breaking a real
// install twice with the same `ENOTFOUND github.com`. The third row is this module.
//
// ⛔ THE PRIVATE HOME IS KEPT IN THE PURGE BUT IT IS NOT WHAT CARRIES THE ARTEFACT, and measuring it
// is what settled that. `preset.rs` documents `$cache/nub/jail-home/<slug>` as "PERSISTENT across
// runs", which reads like a second shared root — but `package_home_slug` hashes the CANONICALIZED
// package dir, which resolves to the arm's own project-local virtual store
// (`<arm>/node_modules/.store/<pkg>@<ver>/node_modules/<pkg>`), so two arms of one run produced two
// slugs four seconds apart (`electron-f8e8ba60aef880e5`, `electron-1a10d23ee60a1933`). It is carried
// because `measure.sh` carries it and a port that quietly drops a term is how three copies diverge
// again — not because a false pass has been measured through it.
//
// ⛔ THE LEAVES, NEVER `tools` ITSELF. `tools` also holds the node-gyp nub bootstraps for itself and
// links into the global store; wiping it strands the only node-gyp a confined native build can
// reach, which is the exact failure the store eviction's "spared as nub tooling" logic exists to
// prevent — it presents as INSUFFICIENT and INFLATES the grant.

import fs from 'node:fs';
import path from 'node:path';

/**
 * The leaves under `$cache/nub/pm/tools` that hold a PACKAGE'S downloaded artefact.
 *
 * The bar for an entry: nub redirects a confined script at it by environment variable
 * (`build_jail.rs::redirect_playwright_browsers`, `redirect_electron_cache`), and what lands there
 * is the product of a fetch a descent arm is trying to prove unnecessary. A leaf holding nub's own
 * tooling fails that bar and belongs in `TOOLING_LEAVES`.
 */
export const ARTIFACT_CACHE_LEAVES = ['ms-playwright', 'electron-cache'];

/** nub's own bootstrapped tooling under the same parent. Never removed; see the note above. */
export const TOOLING_LEAVES = ['node-gyp', 'npm-prefix'];

/**
 * The side-effects cache's spelling of a package name.
 *
 * ⛔ `__`, NOT `+`, AND NOT THE RAW NAME — measured rather than assumed, and `measure.sh` records
 * what the wrong guess cost: the store spells a scoped package `@scarf+scarf@1.4.0-<hash>` while the
 * side-effects cache spells the same package `@scarf__scarf@1.4.0`, so a `+` spelling purges NOTHING
 * for every scoped package while reading as a working guard.
 */
export const sideEffectsSlug = (pkg) => pkg.replace(/\//g, '__');

const rmLeaf = (p) => {
  try {
    if (!fs.existsSync(p)) return false;
    fs.rmSync(p, { recursive: true, force: true });
    return true;
  } catch { return false; }
};

/**
 * Clear everything a LATER arm could replay through that the store eviction cannot reach.
 *
 * `jailCache` is the `<cache>/nub` root — `${XDG_CACHE_HOME:-$HOME/.cache}/nub` on POSIX,
 * `%LOCALAPPDATA%\nub` on Windows. Returns counts rather than printing, so the drivers own their own
 * log line and a test can assert behaviour without capturing stdout.
 *
 * ⛔ READ `sideEffects: 0` AS THE HEALTHY STATE. Every arm writes `side-effects-cache=false`, so an
 * entry should never exist; a NON-ZERO count is the interesting one and says something wrote to that
 * cache despite the setting. `measure.sh` records an earlier draft of its own comment having this
 * exactly backwards.
 */
export function purgeArmReplayRoots(jailCache, pkg) {
  const toolsDir = path.join(jailCache, 'pm', 'tools');
  const removed = [];
  const spared = [];
  let toolsPresent = true;
  let entries;
  try { entries = fs.readdirSync(toolsDir); } catch { entries = []; toolsPresent = false; }
  for (const name of entries) {
    if (!ARTIFACT_CACHE_LEAVES.includes(name)) { spared.push(name); continue; }
    if (rmLeaf(path.join(toolsDir, name))) removed.push(name);
  }

  // The private home is keyed on a hash of the package dir, which differs per arm root, so match the
  // readable basename rather than trying to recompute nub's hash.
  //
  // ⛔ THE HASH IS PART OF THE PATTERN, AND `measure.sh`'s GLOB LEFT IT OUT. That form is
  // `jail-home/"$(basename "$PKG")"-*`, and `electron-chromedriver-<hash>` starts with `electron-`
  // — so measuring `electron` swept a SIBLING PACKAGE'S private home, and the electron family is
  // exactly where both names occur (6 and 38 records). `package_home_slug` is
  // `format!("{name}-{:016x}", …)`, i.e. always sixteen lowercase hex digits (observed:
  // `electron-b667e16f85d15e8c`), so anchoring on that is what makes the match the package's own.
  // Over-eviction never fabricates a false PASS — it only makes a neighbour colder — but it is
  // wasted re-downloads for another lane on a shared box, and the tightening is one regex.
  let homes = 0;
  const homeRoot = path.join(jailCache, 'jail-home');
  const leaf = pkg.includes('/') ? pkg.slice(pkg.lastIndexOf('/') + 1) : pkg;
  const slug = new RegExp(`^${leaf.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-[0-9a-f]{16}$`);
  try {
    for (const name of fs.readdirSync(homeRoot)) {
      if (slug.test(name) && rmLeaf(path.join(homeRoot, name))) homes++;
    }
  } catch { /* no private-home root yet — first arm on this box */ }

  let sideEffects = 0;
  const seRoot = path.join(jailCache, 'pm', 'side-effects-v1');
  const seLeaf = sideEffectsSlug(pkg);
  try {
    for (const name of fs.readdirSync(seRoot)) {
      if (name.startsWith(`${seLeaf}@`) && rmLeaf(path.join(seRoot, name))) sideEffects++;
    }
  } catch { /* no side-effects root — the healthy state */ }

  return { removed, spared, homes, sideEffects, toolsPresent };
}

/** The one line the three drivers print, in the shape `EVICT[...]` already uses. */
export function marker(label, r) {
  if (!r.toolsPresent && !r.homes && !r.sideEffects) {
    return `  EVICT-REPLAY[${label}] no tools dir yet (first arm on this box)`;
  }
  return `  EVICT-REPLAY[${label}] ${r.removed.length} artefact cache(s) removed`
    + `${r.removed.length ? ` (${r.removed.join(', ')})` : ''}`
    + `, ${r.spared.length} spared as nub tooling`
    + `, ${r.homes} private home(s), ${r.sideEffects} side-effects entr${r.sideEffects === 1 ? 'y' : 'ies'}`;
}

// CLI for the two shell drivers: --cache <nub cache root> --pkg <name> [--label <label>]
// ⛔ `realpathSync` ON BOTH SIDES, NOT `import.meta.filename === process.argv[1]`. On macOS `/tmp` is
// a symlink to `/private/tmp`, so the plain compare silently skips this branch when the script is
// reached through one — the same dead-CLI shape `publish-guard.mjs` was caught with. Same form as
// `dep-scaffold.mjs`.
if (process.argv[1]
  && fs.realpathSync(process.argv[1]) === fs.realpathSync(import.meta.filename)) {
  const argv = process.argv.slice(2);
  const one = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : '');
  const cache = one('--cache'); const pkg = one('--pkg');
  if (!cache || !pkg) {
    console.error('usage: arm-artifact-cache.mjs --cache <nub-cache-root> --pkg <name> [--label <l>]');
    process.exit(2);
  }
  console.log(marker(one('--label') || 'arm', purgeArmReplayRoots(cache, pkg)));
}
