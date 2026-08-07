// Derive a catalog `writePaths` list from the writes a lifecycle script left in its PRIVATE home.
//
// ⛔⛔ WHAT `writePaths` IS, AND THE THING IT IS NOT. It is NOT a narrower spelling of
// `write:{userHome}`. It grants nothing at all. nub's implementation
// (`crates/nub-cli/src/pm_engine/build_jail.rs::persist_declared_home_writes`, read 2026-08-06 on
// `sandbox/integration`) runs AFTER the lifecycle scripts finish and does exactly one thing:
//
//     rename(private_jail_home/<rel>  ->  real_home/<rel>)     for each declared <rel>
//
// So an entry only ever moves something that ALREADY LANDED in the throwaway home — which the base
// profile grants read-write anyway (`compiler/preset.rs`: "This package's own HOME … read-write").
// It is a PERSISTENCE declaration, not a capability.
//
// ⛔ THE CONSEQUENCE, AND IT IS THE WHOLE REASON THIS FILE READS ONE BUCKET AND REFUSES THE OTHER.
// The v2 classifiers split home writes in two, and the split is measured rather than guessed because
// the drivers redirect `HOME` for the traced run exactly as the jail does:
//
//   jailHome bucket  — the write FOLLOWED `$HOME`. In the real jail it lands in the private home,
//                      SUCCEEDS, and is then thrown away with that directory. Nothing is refused, so
//                      no scope is earned; what is lost is the artefact. ⇒ THIS is what `writePaths`
//                      exists for, and it is the only input this file accepts.
//
//   userHome bucket  — the write named the REAL home by ABSOLUTE path and did not follow `$HOME`
//                      (measured: `@pulumi/gcp@0.16.9` wrote `/home/runner/.pulumi/...` with `HOME`
//                      pointed at the jail home, and playwright writes into
//                      `$HOME/.cache/nub/pm/tools/ms-playwright` because nub itself sets
//                      `PLAYWRIGHT_BROWSERS_PATH` to that absolute path). In the real jail that write
//                      is REFUSED unless `write:{userHome}` is granted. Promotion cannot help: there
//                      is nothing in the private home to move. ⇒ Feeding this bucket in would swap a
//                      grant the package needs for a no-op, which is an UNDER-GRANT — the one
//                      direction this project may not take. `refuseUserHome` states that in code so
//                      the rule cannot be lost to a refactor, and a test pins it.
//
// ⛔ AND PROMOTION IS AUTHORITY, SO OVER-DECLARING IS NOT THE SAFE DIRECTION. Everywhere else here,
// "when in doubt, loosen" holds because a wider grant only ever costs reach INSIDE a run that is
// already happening. An entry here makes nub copy files into the user's real home, so a junk entry
// is a package writing where it was never observed to need to. That asymmetry is why this file
// REFUSES rather than widens whenever the answer is not a small named set.
import fs from 'node:fs';
import path from 'node:path';

// ⛔ ONE VOCABULARY, READ FROM THE FILE THAT OWNS IT. `sharedHomeRoots` is what stops the collapse
// below walking up to `Library/Caches` — the cache root of every application on the machine — and v1
// already maintains that list in `harness/baseline.json`. A second copy here would drift, and its
// drift would be silent and in the widening direction.
//
// ⛔ NOT A VENUE ROOT, so this does NOT violate the classifiers' rule that every ROOT comes from
// `capture.json`. That rule is about machine-specific PATHS, which are what make a classification
// venue-dependent. These are static NAMES with no machine in them.
const BASELINE = JSON.parse(
  fs.readFileSync(path.join(import.meta.dirname, '..', 'baseline.json'), 'utf8'),
);

/** How many entries still count as "one or a few nameable directories".
 *
 *  Past this the honest answer is that the writes SCATTER and no small set names them, so the
 *  derivation declares nothing and the package keeps whatever it had. Deliberately tight, on the
 *  asymmetry in this file's header: declaring nothing costs exactly the status quo (the artefact is
 *  discarded, as it is for every package today), while declaring a long tail hands a package a copy
 *  into the real home for every directory it happened to touch. The observed shape it is sized
 *  against is one vendor directory per package — puppeteer's 355 paths collapse to the single
 *  `.cache/puppeteer` — so a package needing five unrelated ones is not a case this has evidence for.
 */
export const MAX_ENTRIES = 4;

/** Why a derivation declined to emit anything. Strings, not a boolean, because "we derived nothing"
 *  and "we refused" are different facts and a reader of `driver.out` has to be able to tell them
 *  apart without re-deriving. */
export const REFUSAL = {
  NONE_OBSERVED: 'the script wrote nothing into its private home — there is nothing to promote',
  ALL_AT_ROOT: 'every write was a FILE at the top of the private home, or landed in a directory the '
    + 'TOOLCHAIN owns (see `writePathsDeny`) — an entry names a directory belonging to the PACKAGE, '
    + 'so there is nothing to name',
  SCATTERED: 'the writes SCATTER — no small set of directories names them, so the honest answer is '
    + 'to declare nothing rather than promote a long tail into the user\'s real home',
};

/** ⛔ THE RULE THAT MAY NOT BE DELETED: a REAL-home write is never promotable.
 *
 *  Callers pass the classifier's `userHome` bucket here to get a stated answer instead of silently
 *  treating it as a candidate. It always refuses, and it exists so that the refusal is a named,
 *  tested function rather than a comment somebody removes. See this file's header for the mechanism.
 */
export function refuseUserHome(count) {
  return {
    paths: [],
    pinned: [],
    refused: `${count} write(s) landed in the REAL home by absolute path, so promotion cannot reach `
      + 'them — nub moves OUT of the private home, and nothing of theirs is in it. Only '
      + '`write:{userHome}` covers these; emitting `writePaths` instead would be an UNDER-GRANT.',
  };
}

/** Normalize one observed absolute path into a POSIX path relative to `root`, or `null` when it is
 *  not under `root` at all.
 *
 *  ⛔ SEPARATOR-TERMINATED, NEVER A BARE `startsWith`. `<root>-backup/x` starts with `<root>` and is
 *  a different directory; the same class of bug `record.mjs`'s `insideHome` carries a scar for.
 *  Backslashes are folded because the Windows driver reports native paths and a `\`-separated
 *  relative path is not what the catalog schema accepts.
 */
export function relativizeUnder(abs, root) {
  if (!abs || !root) return null;
  const norm = (s) => s.replace(/\\/g, '/').replace(/\/+$/, '');
  const a = norm(abs);
  const r = norm(root);
  if (a === r) return null; // the home itself is not a subpath of itself
  if (!a.startsWith(`${r}/`)) return null;
  return a.slice(r.length + 1);
}

/** The MINIMAL set of home-relative directory entries covering every observed private-home write.
 *
 *  THE COLLAPSE RULE IS v1's, VERBATIM IN BEHAVIOUR (`harness/search.mjs::homeWritePaths`), because
 *  it is the one that was measured. An entry is the LONGEST `sharedHomeRoots` prefix that matches,
 *  plus ONE segment — the first directory the package itself owns. `.cache` + `puppeteer`;
 *  `Library/Caches` + `Cypress`. Two vendors under one shared root therefore yield TWO entries and
 *  never their parent, which is the case an unbounded shared-ancestor collapse gets most wrong: it
 *  produced `Library/Caches` for cypress, and it got WIDER the more a package wrote.
 *
 *  A path with nothing BELOW the matched root is a file, not a directory grant, and is dropped.
 *
 *  @param {Iterable<string>} rels  home-relative POSIX paths, already under the PRIVATE home
 *  @param {{version?: string|null, max?: number, sharedRoots?: string[]}} opts
 *  @returns {{paths: string[], pinned: string[], refused: string|null}}
 */
export function deriveWritePaths(
  rels,
  {
    version = null,
    max = MAX_ENTRIES,
    sharedRoots = BASELINE.sharedHomeRoots ?? [],
    deny = BASELINE.writePathsDeny ?? [],
  } = {},
) {
  const roots = sharedRoots
    .map((r) => r.toLowerCase())
    .sort((a, b) => b.length - a.length);
  const denied = deny.map((d) => d.toLowerCase().replace(/\/+$/, ''));

  const all = [...rels];
  if (all.length === 0) return { paths: [], pinned: [], refused: REFUSAL.NONE_OBSERVED };

  const dirs = new Set();
  for (const rel of all) {
    // ⛔ SCHEMA CONFORMANCE IS ENFORCED HERE, NOT ASSUMED. `catalog_v2.rs::parse_write_paths` refuses
    // an absolute entry, a `~` entry, anything containing `..`, an empty entry and a duplicate — and
    // a REJECTED override does not fail loudly, it makes nub fall back to the COMPILED-IN catalog
    // while every other precondition still reads green. So a path that cannot become a legal entry
    // is dropped here rather than shipped and silently discarded downstream.
    const clean = rel.replace(/^\.\//, '').replace(/\/+$/, '');
    if (!clean || clean === '.' || clean.startsWith('/') || clean.startsWith('~')) continue;
    if (clean.split('/').includes('..')) continue;

    const low = clean.toLowerCase();
    // ⛔ THE TOOLCHAIN'S OWN STATE IS NEVER PROMOTED — dropped HERE, before the collapse, so a denied
    // path cannot contribute a segment to some other entry either. Measured: without this the two
    // symlink cases in `observe.test.mjs` derived `.npm/_npx` from a symlink npm's own npx bootstrap
    // creates, which would copy an npx cache entry into the user's real `~/.npm`. Promotion is a
    // write into `$HOME`, so a wrong entry here is not the safe direction it would be on a grant.
    if (denied.some((d) => low === d || low.startsWith(`${d}/`))) continue;
    const root = roots.find((r) => low === r || low.startsWith(`${r}/`));
    const depth = root ? root.split('/').length + 1 : 1;
    const segs = clean.split('/');
    if (segs.length <= depth) continue; // a file at that level, not a directory to move
    dirs.add(segs.slice(0, depth).join('/'));
  }

  if (dirs.size === 0) return { paths: [], pinned: [], refused: REFUSAL.ALL_AT_ROOT };

  // A shallower entry subsumes a deeper one when both survived (a package owning both `x` and
  // `x/y`); keep only the shallowest, or the deeper entry's move finds a destination the shallower
  // one already populated.
  //
  // ⛔ THIS CANNOT FIRE AGAINST THE SHIPPED `sharedHomeRoots`, AND THAT IS A PROPERTY OF THE LIST
  // RATHER THAN OF THIS CODE — which is exactly why it is kept and why it takes an injected root
  // list. Every multi-segment entry in `baseline.json` has its own parent in the list as well
  // (`Library` beside `Library/Caches`, `.local` beside `.local/share`), so the longest-match rule
  // never produces a bare `Library` next to a `Library/Caches/V`: a path under `Library` matches
  // `Library` and yields two segments. Add ONE non-prefix-closed root and the pair becomes
  // reachable, which is what the test injects. Deleting the filter on "it never fires today" would
  // make that future root silently emit a redundant nested pair.
  const sorted = [...dirs].sort();
  const paths = sorted.filter((d) => !sorted.some((o) => o !== d && d.startsWith(`${o}/`)));

  if (paths.length > max) {
    return {
      paths: [],
      pinned: [],
      refused: `${REFUSAL.SCATTERED} (${paths.length} entries derived, cap ${max}): `
        + `${paths.slice(0, 8).join(', ')}${paths.length > 8 ? ', …' : ''}`,
    };
  }

  // ⛔ AN ENTRY EMBEDDING THE MEASURED VERSION MOVES ON THE NEXT RELEASE. `.cache/foo-1.2.3` stops
  // matching silently the moment the package publishes again, and walking UP is not the fix — the
  // next level is a shared root and widening to it is exactly what the collapse floor prevents. So
  // it is REPORTED, and `collate.mjs` pins the grant's `versions` matcher on the strength of it
  // (it already reads `writePathsVersionPinned` and appends the re-measure note).
  //
  // Exact substring of the MEASURED version, never a "looks like a version" regex: a regex fires on
  // legitimate names and misses unusual schemes, and both failures are silent.
  const pinned = version ? paths.filter((e) => e.includes(version)) : [];
  return { paths, pinned, refused: null };
}
