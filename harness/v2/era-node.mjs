// Which Node to measure a package-version on: the one its author actually built against.
//
// ⛔ `engines` ALONE IS THE WRONG SIGNAL, AND IT FAILS IN BOTH DIRECTIONS. This is v1's measured
// finding (`search.mjs`), carried over because it cost real verdicts to learn:
//
//   too OLD:  @tailwindcss/oxide@4.1.14, published 2025-10, declares `>= 10`. A 2025 Rust-toolchain
//             package cannot run on Node 10 and nobody ever tested it there — the floor is stale
//             boilerplate. electron@31.7.7 (2025-01, `>= 12.20.55`) is the same shape.
//   too NEW:  better-sqlite3@8.7.0 (2023-09) and @rspack/core@0.0.26 (2023-03) declare NO engines,
//             so they fell to the newest default and their C++ met a V8 that had REMOVED the API
//             they call (`no matching member function for call to 'SetAccessor'`). uuid@0.0.2 is
//             from 2011 and got Node 22.
//
// So START from the Node that was CURRENT WHEN THE VERSION WAS PUBLISHED, then RAISE it to whatever
// `engines` genuinely requires. A publish date cannot be stale boilerplate the way a declared floor
// can, and it exists for every version. `engines` keeps exactly the authority it deserves — a LOWER
// bound — and loses the authority it does not, which is to nominate an ancient runtime for a modern
// release.
//
// ⛔ THIS EVALUATES `engines` WITH `satisfiesNodeRange`, NOT v1's SMALLEST-MAJOR HEURISTIC. v1 took
// the minimum major any comparator mentioned, which reads `14 || 16 || 18` as a floor of 14 — and
// then picks 14 even though the range EXCLUDES 15, 17 and everything above 18. Asking the range
// whether a candidate satisfies it is both simpler and correct for disjunctions.
//
// ⛔ THE FLOOR IS 18 HERE AND IT IS STRUCTURAL, NOT A CHOICE. v1 deliberately floored at Node 10
// ("raising it to 18 breaks a lot more shit" — measuring old packages on a Node they never
// targeted). v2's Node matrix only CARRIES 18-26, because 18.19.0 is nub's own support minimum, so
// a 2011 package is measured on 18 regardless. That is a real difference in what the two corpora
// mean, and `clampedToFloor` marks every record it applies to so the gap is visible in the data
// rather than inferred later.
import { satisfiesNodeRange } from './node-range.mjs';

/** Active-LTS boundaries, from nodejs/Release: the major that was CURRENT at a given date.
 *
 *  ⛔ NOT DERIVABLE FROM THE MATRIX, which is why this table exists despite the duplication. The
 *  matrix's `released` is the date of the specific PATCH it pins (18.20.8 → 2025-03-27), not when
 *  Node 18 became current (2022-10-25). Mapping an era off `released` would put a 2023 package on
 *  Node 18 only if the pinned patch predated it, which is nearly the opposite of the intent. */
// ⛔ THE FIRST ENTRY USED TO BE `['2011-01-01', 10]`, WHICH WAS ITS OWN SILENT FLOOR. It mapped every
// package published before late 2018 — SEVEN YEARS of npm — onto Node 10, so a 2013 package and a
// 2017 package got the same runtime and neither got its own. That was harmless only while the matrix
// floored at 18 and clamped them all anyway; now that the matrix carries 4 upward, this table is what
// decides whether an old package is measured on its era or on a convenient guess.
//
// Major `0` is deliberate for the 0.x era. The matrix carries no 0.x line, so the pick is CLAMPED to
// the floor and MARKED — which is the honest record ("its era was 0.x, the matrix has none, it ran on
// 4") rather than a quiet retarget that reads as a real pin.
export const LTS_AT = [
  ['2011-01-01', 0], ['2013-03-11', 0], ['2015-02-06', 0],
  ['2015-09-08', 4], ['2016-10-18', 6], ['2017-10-31', 8],
  ['2018-10-30', 10], ['2019-10-22', 12], ['2020-10-27', 14],
  ['2021-10-26', 16], ['2022-10-25', 18], ['2023-10-24', 20], ['2024-10-29', 22],
  ['2025-10-28', 24],
];

/** The Node major current at `published` (an ISO date string), or null when the date is unusable. */
export function eraMajorAt(published) {
  const t = published ? Date.parse(published) : NaN;
  if (!Number.isFinite(t)) return null;
  let major = LTS_AT[0][1];
  for (const [when, m] of LTS_AT) if (t >= Date.parse(when)) major = m;
  return major;
}

/** Pick the Node a package-version should be measured on.
 *
 *  Returns the chosen matrix entry plus every input and adjustment that produced it, so a record can
 *  carry WHY it ran where it ran. A record that cannot explain its own pin is the failure mode this
 *  shape exists to prevent: v1 shipped a Linux run whose every record said `pinnedTo: null` because
 *  the selection silently fell through, and nothing in the record could distinguish that from a
 *  deliberate no-pin.
 */
export function chooseEraNode({ engines = null, publishedAt = null, matrix }) {
  const versions = [...(matrix?.versions ?? [])].sort((a, b) => a.major - b.major);
  if (!versions.length) throw new Error('chooseEraNode needs a validated Node matrix');
  const floor = versions[0].major;
  const ceiling = versions[versions.length - 1].major;
  const harnessMajor = Number(String(matrix.harnessNode).split('.')[0]);

  const eraMajor = eraMajorAt(publishedAt);
  // No usable date ⇒ the harness's own Node, which is the least surprising default and is already
  // pinned in the matrix. NOT the newest available: that is the "too NEW" failure above.
  const startRaw = eraMajor ?? harnessMajor;
  const start = Math.min(Math.max(startRaw, floor), ceiling);

  const satisfies = (entry) => !engines || satisfiesNodeRange(entry.version, engines);
  // RAISE ONLY. The first candidate at or above the era that `engines` accepts.
  let chosen = versions.find((v) => v.major >= start && satisfies(v)) ?? null;
  let raisedByEngines = Boolean(chosen && chosen.major > start);
  let enginesUnsatisfiable = false;
  if (!chosen) {
    // `engines` accepts nothing at or above the era. Either it demands something older than the
    // matrix carries, or it is unparseable/contradictory. Fall back to the era pick and SAY SO —
    // refusing to measure would drop the package from the corpus for a bad metadata string.
    chosen = versions.find((v) => v.major >= start) ?? versions[versions.length - 1];
    enginesUnsatisfiable = Boolean(engines);
    raisedByEngines = false;
  }
  return {
    major: chosen.major,
    version: chosen.version,
    npm: chosen.npm ?? null,
    // ⛔ WHETHER A DRIVER SHOULD ACTUALLY PIN, WHICH IS NOT THE SAME AS WHETHER A PICK EXISTS.
    //
    // MEASURED, and it cost a falsification-control failure to find: `@apollo/rover@0.4.8` declares
    // `engines: ">=14 <=17"` and the matrix floors at 18, so NOTHING it accepts is available. Pinning
    // it to 18 anyway runs it on a Node its own metadata forbids — both falsify arms went UNPARSED in
    // 6s, and the same case PASSES with the pin disabled. Forcing a Node the package explicitly
    // rejects is strictly WORSE than the ambient default: the era pin exists to run a version on a
    // runtime it was built for, and when no such runtime is on offer the honest answer is not to pin.
    //
    // `version` still names the era pick so the record can say what it WANTED, and
    // `enginesUnsatisfiable` still says why it could not be honoured — the data stays complete either
    // way. Only the PATH manipulation is withheld.
    pinnable: !enginesUnsatisfiable,
    engines: engines ?? null,
    publishedAt: publishedAt ?? null,
    eraMajor,
    startMajor: start,
    raisedByEngines,
    enginesUnsatisfiable,
    // Marks the two places the answer is bounded by what the matrix CARRIES rather than by evidence.
    clampedToFloor: startRaw < floor,
    clampedToCeiling: startRaw > ceiling,
    matrixFloor: floor,
    matrixCeiling: ceiling,
  };
}

/** `engines.node` and the publish date for one package-version, via `npm view`.
 *
 *  ⛔ `npm view` COLLAPSES its output when only ONE requested field exists. Ask for two and a normal
 *  package returns `{"engines.node": …, "time": {…}}` — but a package with NO `engines` returns the
 *  TIME MAP ITSELF at top level, with no `time` key to reach for. Handling only the wrapped shape
 *  yielded `published: null` for exactly the packages that need the date MOST (the ones with no
 *  engines to fall back on), so the date-aware pin was inert precisely where it mattered. MEASURED
 *  in v1 on better-sqlite3@8.7.0 and @rspack/core@0.0.26. Both shapes are detected via the version
 *  under test appearing as a top-level key.
 */
export function enginesAndDate(pkg, version, { spawnSync, npmArgv = ['npm'], timeout = 30_000 } = {}) {
  try {
    const [cmd, ...pre] = npmArgv;
    const r = spawnSync(cmd, [...pre, 'view', `${pkg}@${version}`, 'engines.node', 'time', '--json'],
      { encoding: 'utf8', timeout });
    if (r.status !== 0) return { engines: null, published: null };
    const j = JSON.parse(r.stdout || '{}');
    const engines = typeof j['engines.node'] === 'string' ? j['engines.node'] : null;
    const time = j.time && typeof j.time === 'object' ? j.time
      : (typeof j[version] === 'string' ? j : null);
    return { engines, published: time?.[version] ?? null };
  } catch {
    return { engines: null, published: null };
  }
}

// ── CLI ───────────────────────────────────────────────────────────────────────
//
// ⛔ EXISTS SO THE SHELL DRIVERS SHARE ONE IMPLEMENTATION. `measure-macos.sh` and the Linux driver
// are shell; `measure-windows.mjs` and `run-batch-v2.mjs` are JS. Reimplementing the era rule in awk
// would give the corpus two selectors that drift, and a drifted selector is invisible in the data —
// the records would simply disagree about which Node an era means, with nothing to flag it. One
// process per package is a rounding error against an install.
//
//   node era-node.mjs <pkg> <version>            # queries npm for engines + publish date
//   node era-node.mjs <pkg> <version> --engines '>=18' --published 2023-09-15   # no network
//
// Prints the full selection object as one line of JSON on stdout, so a shell caller can take the
// whole thing (`jq -r .version`) rather than parsing prose. Exits non-zero ONLY on usage error: a
// package whose metadata cannot be fetched still gets a pin (the harness-Node fallback), because
// dropping it would remove it from the corpus over a registry hiccup.
if (import.meta.filename === process.argv[1]) {
  const [pkg, version, ...rest] = process.argv.slice(2);
  if (!pkg || !version) {
    process.stderr.write('usage: era-node.mjs <pkg> <version> [--engines <range>] [--published <date>]\n');
    process.exit(2);
  }
  const flag = (name) => {
    const i = rest.indexOf(`--${name}`);
    return i === -1 ? undefined : rest[i + 1];
  };
  const { loadNodeMatrix } = await import('./node-matrix.mjs');
  const { matrix } = loadNodeMatrix();
  let engines = flag('engines');
  let publishedAt = flag('published');
  // Only reach the network when the caller did not already supply both — a batch runner that has the
  // packument in hand should pass them and stay offline.
  if (engines === undefined || publishedAt === undefined) {
    const { spawnSync } = await import('node:child_process');
    const looked = enginesAndDate(pkg, version, { spawnSync });
    if (engines === undefined) engines = looked.engines;
    if (publishedAt === undefined) publishedAt = looked.published;
  }
  const pick = chooseEraNode({ engines: engines ?? null, publishedAt: publishedAt ?? null, matrix });
  // ⛔ `packageVersion`, NOT `version`. `pick.version` is the NODE version, so spreading it over a
  // key called `version` silently rewrote the PACKAGE's version to the Node's — the first run of
  // this CLI printed `{"pkg":"demo","version":"18.20.8"}` for `demo@1.0.0`. A record carrying that
  // would name a package-version that does not exist, and nothing downstream would flag it.
  process.stdout.write(`${JSON.stringify({ pkg, packageVersion: version, ...pick })}\n`);
}
