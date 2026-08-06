// Turn a set of observed write paths into an ENUMERATED DIRECTORY GRANT, or say why it cannot be
// done. The narrower rung between "nothing" and the whole `userHome` scope.
//
// ⛔ THIS IS NOT `writePaths`. The catalog's existing `writePaths` field is a PROMOTION list — the
// subpaths of a package's throwaway private `$HOME` that nub MOVES into the real home after the
// lifecycle scripts exit (`catalog_v2.rs` `Caps::write_paths`, consumed only by
// `pm_engine/build_jail.rs::persist_declared_home_writes`, which runs in nub's OWN unconfined
// process after `child.wait()`). Promotion can never need a grant and never narrows one. What this
// file synthesizes is a GRANT: a set of directories the confined child may write to, in place of
// `write: {userHome: true}` handing it the whole home.
//
// THE SHAPE IT EMITS, chosen so it extends the existing schema rather than adding a field:
//
//   "write": { "userHome": true }                       ← today: the whole scope
//   "write": { "userHome": [".cache/nub/pm/tools/ms-playwright"] }   ← the new rung
//
// A scope's value becomes `true` OR an array of scope-relative directories. `parse_reach` already
// refuses any value that is not `true`, so the array form is a strict extension with exactly one
// spelling per answer and no ambiguity to resolve.
//
// ⛔⛔ THE ENFORCEMENT PRECONDITION, MEASURED FROM SOURCE, AND THE TIER IS UNSOUND WITHOUT IT.
// A grant naming a path that does not exist adds NO RULE on either Linux backend:
//   · Landlock — `backend/linux_landlock.rs::add_rule` opens the path `O_PATH` and returns
//     `Ok(false)` when the open fails. No rule.
//   · Bubblewrap — `backend/linux_grants.rs:175` SKIPS a `FsOrigin::Speculative` rule whose path
//     is absent, and every curated/v2 rule is Speculative (`compiler/curated.rs:1229`).
// A package cache directory that does not exist yet is the COMMON case for this tier, so nub must
// `create_dir_all` each enumerated directory before installing the rule or the grant silently
// compiles to nothing — an under-grant, the one direction this system may not take. The precedent
// is already in the tree: `backend/windows.rs` creates the `AC` / `AC\Temp` leaves for exactly this
// reason (`compiler/preset.rs:590-596`).
//
// THAT PRECONDITION IS ALSO WHAT MAKES THE ROLL-UP SOUND, so the two are one decision rather than
// an implementation detail plus a heuristic. Because nub creates each granted directory AND its
// ancestors, a script's `mkdir` of any ancestor returns EEXIST inside the jail and is not a need.
// That is the only reason `ANCESTOR_COVERED` below may drop an observed write instead of billing
// it, and it is why the rule is evidence-based rather than a blanket "ignore parents": a write of a
// real FILE directly into an ancestor still bills that ancestor.

// ⛔ OVER-DETECTING VOLATILITY IS SAFE; UNDER-DETECTING IS NOT, so every rule here leans toward
// "volatile". Stopping the roll-up EARLIER yields a SHALLOWER directory — a wider grant, which
// still installs. Failing to notice a volatile segment yields a grant pinned to one run's random
// name, which under-grants every subsequent run. The asymmetry is the whole design of this
// predicate; do not "tighten" a rule here without re-reading it.
//
// Each pattern is pinned by a known-answer test in `pathgrant.test.mjs`, with the two measured
// cases as controls: `chromium-764964` (volatile BELOW a stable ancestor ⇒ enumerable) and
// hugo-extended's `ca2223935f4dec08eea62524ef6923e6` (volatile AT THE TOP ⇒ not enumerable).
const VOLATILE = [
  // A version, with or without a `v`: `resource-gcp-v0.16.9`, `electron-v0.28.3`, `22.23.1`.
  /\d+\.\d+/,
  // A hex or base36 run long enough to be a hash, a mktemp suffix, or an inode: hugo's 32-hex
  // download dir, `node-gyp-tmp-5xuClF`, `.links/288743bfc460ff…`.
  /[0-9a-fA-F]{8,}/,
  // A digit run long enough to be a build number, a pid, or a timestamp: `chromium-764964`,
  // `electron-tmp-download-2881-1786023227333`, `pulumi-20260806T124738`.
  /\d{3,}/,
];

// A mktemp/mkstemp tail — an alphanumeric run of six or more that mixes both cases, which is what
// `XXXXXX` resolves to: `playwright-download-8zlprA`, `node-gyp-tmp-5xuClF`, gcc's `ccXRCCB2`.
//
// ⛔ THIS ALSO MATCHES AN ORDINARY camelCase DIRECTORY NAME, and that is accepted rather than
// worked around. A false "volatile" only makes the roll-up stop one segment earlier — it grants
// the PARENT, which is wider and still installs. The obvious tightening, "must also contain a
// digit", would let `playwright-download-yjKhqN` through, and that is the failing direction.
const MIXED_CASE_RUN = /[A-Za-z0-9]{6,}/g;
const mixedCaseTail = (seg) =>
  [...seg.matchAll(MIXED_CASE_RUN)].some((m) => /[a-z]/.test(m[0]) && /[A-Z]/.test(m[0]));

/** Is this ONE path segment unsafe to name in a catalog entry? */
export function volatileSegment(seg) {
  return VOLATILE.some((re) => re.test(seg)) || mixedCaseTail(seg);
}

const isAncestorOrEqual = (a, b) => a === b || (a === '' ? true : b.startsWith(`${a}/`));

/**
 * The directory a single observed write path justifies granting.
 *
 * Walk the segments left to right and stop at the FIRST volatile one, granting its PARENT — that
 * is what keeps `ms-playwright/chromium-764964/chrome-linux/locales/sk.pak` at `ms-playwright`
 * rather than pinning a build number, and it is the same move that makes the grant survive the
 * version-stamping hazard `writePaths` hit in v1.
 *
 * With no volatile segment, grant the path's PARENT rather than the path itself. A grant must be a
 * DIRECTORY: a file that does not exist yet cannot be opened to attach a rule, and creating it
 * needs write on the containing directory either way.
 */
export function rollUp(rel) {
  const segs = rel.split('/').filter(Boolean);
  const stop = segs.findIndex(volatileSegment);
  return (stop === -1 ? segs.slice(0, -1) : segs.slice(0, stop)).join('/');
}

/**
 * Synthesize an enumerated directory grant for one scope, or refuse with a stated reason.
 *
 * `paths` are scope-relative (`.pulumi/plugins`, not `/home/u/.pulumi/plugins`).
 *
 * Returns `{ok: true, dirs}` or `{ok: false, reason}`. A refusal is a first-class answer: the
 * caller falls back to the whole-scope grant, which is what ships today, so a refusal costs
 * nothing and a wrong "ok" breaks an install.
 */
export function enumerateGrant(paths, { max = 12 } = {}) {
  const rel = [...new Set(paths)].filter((p) => p !== '' && p !== '.');
  if (rel.length === 0) return { ok: false, reason: 'no paths' };

  // Which observed writes produced each candidate directory. Kept rather than reduced to a set
  // because the ancestor rule below is EVIDENCE-BASED — it may only drop a candidate whose every
  // justifying write is itself part of the directory chain nub creates.
  const by = new Map();
  for (const p of rel) {
    const d = rollUp(p);
    if (!by.has(d)) by.set(d, []);
    by.get(d).push(p);
  }

  const candidates = [...by.keys()];
  // ⛔ DROP AN ANCESTOR ONLY WHEN NUB'S OWN `create_dir_all` ACCOUNTS FOR EVERY WRITE THAT EARNED
  // IT. `mkdir(~/.cache)`, `mkdir(~/.cache/nub)`, … are real successful writes in the OBSERVE
  // trace — the CI runner's home was fresh — and billing them naively rolls the grant all the way
  // up to `$HOME`, which is the whole scope and defeats the tier. They are not needs in the jail
  // because nub creates the granted directory and its parents before the child starts. A write of
  // a FILE into an ancestor is a different thing and still bills it: `@pulumi/kubernetes` writes
  // `.pulumi/.cachedVersionInfo` directly, so `.pulumi` survives for that package and not for
  // `@pulumi/gcp`, which writes no such file. That divergence is the rule working, not noise.
  const kept = candidates.filter((d) => {
    const deeper = candidates.filter((o) => o !== d && isAncestorOrEqual(d, o));
    if (deeper.length === 0) return true;
    return !by.get(d).every((p) => deeper.some((o) => isAncestorOrEqual(p, o)));
  });

  // Collapse anything left that nests: the shallower entry already covers the deeper one.
  const dirs = kept
    .filter((d) => !kept.some((o) => o !== d && isAncestorOrEqual(o, d)))
    .sort();

  if (dirs.includes('')) {
    return {
      ok: false,
      reason: 'a write reaches the scope root itself — no directory below it covers the set',
    };
  }
  if (dirs.length > max) {
    return { ok: false, reason: `${dirs.length} directories exceeds the cap of ${max}` };
  }
  return { ok: true, dirs };
}

/**
 * Do two OBSERVE runs agree on the enumeration? The only honest stability evidence.
 *
 * ⛔ AGREEMENT ON THE DIRECTORY SET IS THE TEST, NOT AGREEMENT ON THE PATHS. The paths are expected
 * to differ — that is what the roll-up exists to absorb. hugo-extended's download directory is a
 * fresh 32-hex name every run, so its PATHS never match; what disqualifies it is that the roll-up
 * lands on the scope root, which `enumerateGrant` already refuses. A package whose paths differ but
 * whose DIRECTORIES match is exactly the case this tier is for.
 */
export function agree(a, b) {
  if (!a.ok || !b.ok) return { stable: false, reason: (a.ok ? b : a).reason };
  const [x, y] = [a.dirs.join('\n'), b.dirs.join('\n')];
  return x === y
    ? { stable: true, dirs: a.dirs }
    : { stable: false, reason: `run 1 ${JSON.stringify(a.dirs)} != run 2 ${JSON.stringify(b.dirs)}` };
}
