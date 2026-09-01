// The driver's own attributed write census, and the ONE implementation of the question it answers:
// did the lifecycle subtree write the user's REAL home, and did anything positively establish that
// it did not?
//
// ⛔⛔ WHY THIS IS A LEAF MODULE RATHER THAN A FUNCTION IN EITHER OF ITS TWO READERS. Both
// `record.mjs` (which applies the rule when a record is written) and `stale-adjudication.mjs` (which
// re-adjudicates an ARCHIVED record) need this census, and `stale-adjudication.mjs` already imports
// `parseDriverLog` from `record.mjs`. Importing the census the other way is a CYCLE, and a cycle
// here does not throw: `homeWrites` is a `const`, so it sits in the temporal dead zone while the
// cycle resolves and the importer silently receives `undefined`. A guard that is `undefined` is a
// guard that never fires, with no error anywhere. So the census lives below both of them and imports
// nothing from the harness EXCEPT a strictly-lower leaf: `tool-cache-leaves.mjs` imports nothing at
// all, so it cannot re-open the cycle, and sharing the leaf list is the only way this file and the
// two classifiers cannot come to disagree about which writes are free.
//
// ⛔ THE HOLE THIS CLOSES, AND IT IS AN UNDER-GRANT — the one direction this project forbids.
// `artifact-gate.mjs` only ever walks the package's OWN directory, so a write into the user's home
// is by construction outside everything it can see. For a package whose real product IS a home write
// — a browser downloader, a plugin fetcher — the `no-write-userHome` drop arm therefore passes with
// the product missing, and the grant narrows off an arm that proved nothing. MEASURED on the
// committed corpus at `cf36b27f8`: of the 425 records whose descent named `no-write-userHome`, 348
// have a POSITIVE real-home write count in their own census and NOT ONE has a CLEAN denial witness;
// `ibm_db@2.8.2` (win32) attributed 3337 real-home writes, `playwright-chromium@1.9.2` (linux) 1185,
// `@playwright/browser-chromium@1.61.1` (win32) 629.
//
// ⛔ ON win32 NOTHING ELSE CATCHES IT. No jailed trace is taken on that platform, so
// `denial-witness.mjs` cannot run at all and cannot be made to without an event-schema change
// (measured: zero win32 rows carry a read or write outcome; Create carries no DesiredAccess and
// AppContainer denies AT Create). The census is the only home-write detector that platform has.

// ⛔ THREE SPELLINGS, ONE BLOCK, AND THE HEADER IS THE ONLY THING IN COMMON. `observe.mjs` and
// `observe-macos.mjs` print `== WRITES the script actually performed ==`, `classify.mjs` the bare
// `== WRITES ==`. Anchoring on the long form silently returned "no block" for every win32 record,
// which reads as "unknown". MEASURED over the 425 arm-carrying logs: 243 long form, 182 bare, 0
// unmatched.
const WRITES_HEADER = /^\s*==\s*WRITES\b/;
const SECTION = /^\s*==\s/;
// A bucket row is `<scope> <count>` with the paths indented deeper beneath it. Not end-anchored, for
// two reasons and only the second is exercised by the `userHome` row this file reads: the POSIX
// classifiers append `(base profile already grants this — NOT billed)` to any bucket in
// `BASE_COVERED` (`ownPkg jailHome jailTmp toolsRw` — `userHome` is deliberately not among them, and
// MEASURED over the corpus not one of the 2637 `userHome` rows carries a suffix), and a win32 log's
// trailing `\r` would defeat a bare `$`.
const BUCKET = /^\s{2,6}([A-Za-z][A-Za-z0-9]*)\s+(\d+)\b/;

// ── the FREE-DIRECTORY subtraction ────────────────────────────────────────────────────────────────
//
// ⛔⛔ WHAT THIS EXISTS FOR: a `userHome` row is NOT the same question as "did the script need the
// user's home". nub `push_rw_path`s three leaves inside its own tool cache — `preset.rs`, one loop,
// no `cfg` — and on both POSIX drivers that cache sits under `$HOME`. Any classifier that does not
// carve those leaves out therefore bills a write nub HANDS THE SCRIPT FOR FREE as a real-home write,
// and this gate then refuses a narrowing on the strength of it.
//
// MEASURED over the whole committed archive, split on `0492dce58` — the commit that grew the
// classifiers' carve-out from one leaf to three:
//
//     era      records with userHome>0 whose EVERY listed path is a tool-cache leaf
//     before   72   (28 darwin, 44 linux)        toolsRw bucket present in:  0 records
//     after     0                                toolsRw bucket present in: 20 records
//
// A clean separation in both directions, which is what makes this an ERA effect rather than a
// standing classifier bug: the live classifiers are correct, and it is the ARCHIVE that cannot be
// re-measured. Of the 115 records the epoch-70 term caused to be repaired, 32 are in that first row.
//
// ⛔ THIS IS A SUBTRACTION OFF POSITIVE PATH EVIDENCE, NEVER A PATTERN OVER A COUNT. The gate keeps
// its wide answer unless the log ITSELF lists every path behind its own `userHome` row and every one
// of them falls inside a leaf the jail grants. Absent, truncated or unreconciled evidence leaves the
// count exactly as it was — the direction that costs a false refusal rather than an under-grant.
import { TOOL_CACHE_LEAVES } from './tool-cache-leaves.mjs';

// The classifiers echo every declared root before the census. That echo is what makes the tool-cache
// parent a DECLARED root here too rather than a `~/.cache/nub` pattern this file invented — the same
// R2 rule the classifiers hold themselves to, reached through the log instead of through
// `capture.json`, which an archived-record reader does not always have.
const ROOTS_HEADER = /^\s*==\s*ROOTS\b/;
const ROOT_ROW = /^\s{2,6}([A-Za-z][A-Za-z0-9]*)\s+(\S.*?)\s*$/;
// `observe.mjs` marks an unkeyed root `   [declared, not keyed on]` and `classify.mjs` marks a keyed
// one `   [keyed on]`. Stripped before the value is read, and anchored on two-or-more spaces plus a
// bracketed tail so a path that merely contains a bracket survives.
const ROOT_TAG = /\s{2,}\[[^\]]*\]$/;
// All three spellings of "this venue has no such root": `(null)`, `(null — this platform has no such
// root)`, `(null — declared inapplicable)`.
const ROOT_NULL = /^\(null\b/;

// The RAW listing of every write outside project/deps, printed by both POSIX classifiers. It is the
// `userHome` bucket UNIONED with `outside`, each entry relativized under `home` when it is under
// `home` and printed whole when it is not — which is exactly what lets the two be told apart again
// below, and told apart with a reconciliation rather than by assumption.
const FEAS_HEADER = /^\s*==\s*writePaths FEASIBILITY\b/;
const FEAS_COUNT = /^(\s*)count:\s*(\d+)\s*$/;
const FEAS_MORE = /^\s*…\s+and\s+(\d+)\s+more\s*$/;
// POSIX root, a drive-letter path, and a UNC path. Only the first can occur today — `classify.mjs`
// prints no feasibility block at all — but a listing that gained win32 entries must FAIL the
// reconciliation rather than read a `C:\…` path as a home-relative one.
const ABSOLUTE = /^(\/|[A-Za-z]:[\\/]|\\\\)/;

// ⛔ EITHER A RAW LOG OR AN ALREADY-SPLIT ARRAY, because the two callers hold different things.
// `record.mjs` reads every other term off its `lines` — the log with the `    | ` ECHOED output
// already dropped — and the census is read off the same text so no term in that function is looking
// at a different log from its neighbours. `stale-adjudication.mjs` reads an archived file and has
// only the string. Neither depends on the echo filter for soundness: `^\s*==` cannot get past the
// `|`, so an echoed header opens no block either way.
const linesOf = (log) => (Array.isArray(log) ? log : String(log).split(/\r?\n/));

// The REAL-home write count the driver attributed to the lifecycle subtree, or null when the log
// carries no census at all. ⛔ AN ABSENT `userHome` ROW INSIDE A PRESENT BLOCK IS ZERO, NOT UNKNOWN —
// the drivers omit a bucket with no members, so reading absence as unknown fences off exactly the
// records whose home write never happened, which are the safe ones.
//
// ⛔ THE `userHome` BUCKET IS THE REAL HOME AND `jailHome` IS ITS OWN BUCKET, because the drivers
// root both from `capture.json`. Never re-derive this from an EVENT-LOG header: `roots.jailHome` is
// null in every darwin one, and a classifier rooted there bills jail-home writes as real-home
// writes. A reader that cannot confirm the two roots are distinct must REFUSE rather than count —
// `stale-adjudication.mjs` carries that term for archived records.
export const homeWrites = (log) => {
  let inBlock = false;
  let count = null;
  for (const l of linesOf(log)) {
    if (WRITES_HEADER.test(l)) { inBlock = true; count = 0; continue; }
    if (!inBlock) continue;
    if (SECTION.test(l)) { inBlock = false; continue; }
    const m = BUCKET.exec(l);
    if (m && m[1] === 'userHome') count = Number(m[2]);
  }
  return count;
};

// Every bucket row in the `== WRITES` block, or null when there is no block. Same scan as
// `homeWrites` — which stays the public one-number reader its two callers already use — because the
// subtraction below needs `outside` as well, and reconciling a listing against ONE of the two rows
// it was built from would prove nothing.
const writeBuckets = (lines) => {
  let inBlock = false, seen = false;
  const out = {};
  for (const l of lines) {
    if (WRITES_HEADER.test(l)) { inBlock = true; seen = true; continue; }
    if (!inBlock) continue;
    if (SECTION.test(l)) { inBlock = false; continue; }
    const m = BUCKET.exec(l);
    if (m) out[m[1]] = Number(m[2]);
  }
  return seen ? out : null;
};

const rootsEcho = (lines) => {
  let inBlock = false;
  const out = {};
  for (const raw of lines) {
    const l = raw.replace(/\r$/, '');
    if (ROOTS_HEADER.test(l)) { inBlock = true; continue; }
    if (!inBlock) continue;
    if (SECTION.test(l)) { inBlock = false; continue; }
    const m = ROOT_ROW.exec(l);
    if (!m) continue;
    const v = m[2].replace(ROOT_TAG, '').trim();
    out[m[1]] = ROOT_NULL.test(v) ? null : v;
  }
  return out;
};

// ⛔ THE BLOCK IS CLOSED BY INDENTATION, NOT BY THE NEXT `==` HEADER, and that is not a stylistic
// choice. What follows the listing in a real driver log is `EVICT[…]` / `VERIFY[…]` at the OUTER
// indent, never a section header, so a `^\s*==` terminator runs straight past the end of the block
// and swallows the whole descent transcript as paths. Anchoring on "deeper than the `count:` line"
// stops exactly where the printer stops.
const feasibility = (lines) => {
  let state = 0, count = null, more = 0, countIndent = 0;
  const paths = [];
  for (const raw of lines) {
    const l = raw.replace(/\r$/, '');
    if (state === 0) { if (FEAS_HEADER.test(l)) state = 1; continue; }
    if (state === 1) {
      const c = FEAS_COUNT.exec(l);
      if (!c) return null;                       // a header with no count is a malformed block
      count = Number(c[2]); countIndent = c[1].length; state = 2;
      continue;
    }
    const m = FEAS_MORE.exec(l);
    if (m) { more = Number(m[1]); continue; }
    const indent = /^(\s*)/.exec(l)[1].length;
    if (!l.trim() || indent <= countIndent) break;
    paths.push(l.trim());
  }
  return count === null ? null : { count, paths, more };
};

/**
 * How many of a log's attributed REAL-home writes actually cost a capability.
 *
 * Returns `null` when the log carries no census at all, else `{ total, free, billable, basis }`.
 * `basis` is `'paths'` when the log listed every path behind its own `userHome` row and the listing
 * reconciled, and `'count-only'` otherwise — in which case `billable === total` and nothing has been
 * subtracted.
 *
 * ⛔⛔ FIVE CONDITIONS, ALL REQUIRED, AND EVERY ONE OF THEM IS A WAY THE SUBTRACTION COULD BE WRONG.
 * Failing any of them is not an error: it returns the ORIGINAL count, which is the answer this gate
 * gave before this function existed. The asymmetry is the whole design — subtracting a write the
 * package really needed is an UNDER-GRANT, the one direction this project forbids, while failing to
 * subtract a free one costs a record its narrowing and nothing else.
 *
 *   1. The ROOTS echo declares a non-null `home` AND a non-null `toolsDir`, and `toolsDir` lies
 *      strictly under `home`. If it does not, a tool-cache write never reached the `userHome` bucket
 *      in the first place and there is nothing here to subtract.
 *   2. A `writePaths FEASIBILITY` block exists with a `count:` line. `classify.mjs` prints none, so
 *      every win32 record takes this exit and keeps its full count — see the note on the verdict.
 *   3. Nothing was elided: no `… and N more`, and the listed line count equals `count`. The printer
 *      caps the listing at 40 entries, and a subtraction over a truncated list would clear a record
 *      on 40 free paths while 300 real-home writes sat past the cap.
 *   4. The absolute/relative split reconciles: the printer relativizes an entry exactly when it is
 *      under `home`, so the non-absolute entries must number `userHome` and the absolute ones
 *      `outside`. This is what tells the two buckets apart AGAIN rather than assuming `outside` is
 *      empty, and it is what makes a stray win32-shaped path fail the check instead of being read as
 *      a home-relative one.
 *
 * ⛔ THERE IS NO SEPARATE `count === userHome + outside` CHECK, AND ITS ABSENCE IS DELIBERATE — a
 * mutation test is what removed it. Condition 4 already asserts `relative === userHome` and
 * `absolute === outside`, whose sum IS `paths.length`, and condition 3 asserts `paths.length ===
 * count`; together they give `count === userHome + outside` with nothing left over. A fifth check
 * saying so directly could not be made to fail on its own — every fixture that broke it broke 3 or 4
 * first — so it was code no red control could reach. Condition 4's message carries all four numbers
 * instead. Do not restore it.
 *
 * ⛔ CONDITION 3 IS ALSO SUBSUMED BY 4 ON ANY HONEST LOG, and is kept anyway because it is the only
 * one that NAMES truncation. In a real log `count` is the printer's `userHome + outside`, so a
 * truncated listing fails 4 as well — but the reason a reader gets then is "the entries do not
 * reconcile", which sends them looking for a decoder bug instead of at the 40-entry cap. Its red
 * control is therefore on the REASON, not on the verdict.
 */
export const homeWriteCensus = (log) => {
  const lines = linesOf(log);
  const buckets = writeBuckets(lines);
  if (buckets === null) return null;
  const total = buckets.userHome ?? 0;
  const wide = (why) => ({ total, free: 0, billable: total, basis: 'count-only', why });
  if (total === 0) return { total: 0, free: 0, billable: 0, basis: 'count-only', why: null };

  const roots = rootsEcho(lines);
  const { home, toolsDir } = roots;
  if (!home || !toolsDir) return wide('the log echoes no `home`/`toolsDir` root pair');
  if (!(toolsDir.startsWith(`${home}/`) || toolsDir.startsWith(`${home}\\`))) {
    return wide('the declared tool cache does not sit under the declared home, so no free write could have billed `userHome`');
  }
  const feas = feasibility(lines);
  if (!feas) return wide('the log lists no `writePaths FEASIBILITY` paths behind its `userHome` count');
  if (feas.more || feas.paths.length !== feas.count) {
    return wide(`the path listing is TRUNCATED (${feas.paths.length} shown of ${feas.count}), so what it omits is unknown`);
  }
  const outside = buckets.outside ?? 0;
  const relative = feas.paths.filter((p) => !ABSOLUTE.test(p));
  const absolute = feas.paths.length - relative.length;
  if (relative.length !== total || absolute !== outside) {
    return wide(`the path listing (${relative.length} home-relative, ${absolute} absolute) does not `
      + `reconcile with userHome ${total} + outside ${outside}`);
  }

  const relTools = toolsDir.slice(home.length + 1);
  const leaves = TOOL_CACHE_LEAVES.map((l) => `${relTools}/${l}`);
  const isFree = (p) => leaves.some((leaf) => p === leaf || p.startsWith(`${leaf}/`));
  const free = relative.filter(isFree).length;
  return { total, free, billable: total - free, basis: 'paths', why: null };
};

// The three answers, and the middle one is why this is not a boolean.
export const CENSUS_REFUSE = 'REFUSE';
export const CENSUS_CLEAR = 'CLEAR';
export const CENSUS_UNKNOWN = 'UNKNOWN';

/**
 * May a descent DROP `write.userHome` on the strength of this log?
 *
 * ⛔⛔ THE ONLY THING THAT LICENSES THE DROP IS POSITIVE EVIDENCE, AND THERE ARE EXACTLY TWO KINDS.
 * A census that ran and attributed ZERO writes to the real home is one. A DENIAL-WITNESS verdict of
 * `CLEAN` — a live, jailed, subtree-attributed trace in which the script never asked for anything
 * inside the scope — is the other, and it outranks a positive count because it is a statement about
 * the DROP ARM rather than about the observe arm. `WITNESSED`, `VOID`, `UNSUPPORTED` and absent are
 * all "not established" and license nothing; `record.mjs` handles `WITNESSED` in an earlier branch
 * that must keep outranking this one.
 *
 * ⛔ `UNKNOWN` IS NOT `REFUSE`, AND THE TWO CALLERS TAKE DIFFERENT POLICIES ON IT ON PURPOSE. This
 * function classifies; it does not decide. See each call site for which way it goes and why.
 *
 * ⛔ THE COUNT IT DECIDES ON IS THE BILLABLE ONE, NOT THE RAW ROW. `homeWriteCensus` subtracts the
 * writes the log itself places inside nub's tool-cache read-write leaves, which the jail grants
 * unconditionally — see the long note there for the five conditions that have to hold before a
 * single write is subtracted, and for the measurement. `homeWrites` on the returned object stays the
 * RAW row, because that is what it has always meant and a reader reconciling a record against its
 * own `driver.out` must be able to find the same number in both.
 */
export const homeDropVerdict = ({ log, witness }) => {
  const census = homeWriteCensus(log);
  if (census === null) {
    return {
      verdict: CENSUS_UNKNOWN,
      homeWrites: null,
      billableHomeWrites: null,
      freeHomeWrites: null,
      censusBasis: null,
      reason: 'the log carries no `== WRITES` census, so whether the script wrote the REAL home was '
        + 'never established',
    };
  }
  const { total: n, free, billable } = census;
  const stated = { homeWrites: n, billableHomeWrites: billable, freeHomeWrites: free, censusBasis: census.basis };
  if (n === 0) {
    return { verdict: CENSUS_CLEAR, ...stated, reason: 'the census ran and attributed no write to the REAL home' };
  }
  if (billable === 0) {
    // ⛔ A DISTINCT SENTENCE FROM `n === 0`, DELIBERATELY. "Nothing was written" and "everything
    // written was free" are different findings, and a record that reads the first when the second is
    // true hides the only fact that would let a reviewer re-check the subtraction.
    return {
      verdict: CENSUS_CLEAR,
      ...stated,
      reason: `OBSERVE attributed ${n} write(s) to the REAL home, but the log's own writePaths listing `
        + `places all ${free} of them inside nub's tool-cache read-write leaves `
        + `(${TOOL_CACHE_LEAVES.join(', ')}), which the base profile grants unconditionally — so none `
        + 'of them needed `write.userHome`',
    };
  }
  if (witness === 'CLEAN') {
    return {
      verdict: CENSUS_CLEAR,
      ...stated,
      reason: `OBSERVE attributed ${n} write(s) to the REAL home, but the drop arm's own jailed trace `
        + 'shows the lifecycle subtree never attempted a write inside the dropped scope '
        + '(DENIAL-WITNESS CLEAN)',
    };
  }
  // Naming the free ones inside the refusal is what stops the next reader re-deriving the subtraction
  // by hand to find out whether it ran at all.
  const carved = free ? ` — ${free} of them inside nub's tool-cache leaves and ${billable} not —` : '';
  return {
    verdict: CENSUS_REFUSE,
    ...stated,
    reason: `OBSERVE attributed ${n} write(s) to the REAL home${carved} and no denial witness came back CLEAN, `
      + 'so the passing drop arm is as consistent with a swallowed refusal as with the capability '
      + 'being unnecessary — the artifact gate cannot see a home write',
  };
};
