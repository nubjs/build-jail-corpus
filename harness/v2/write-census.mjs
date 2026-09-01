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
// nothing from the harness.
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
 */
export const homeDropVerdict = ({ log, witness }) => {
  const n = homeWrites(log);
  if (n === null) {
    return {
      verdict: CENSUS_UNKNOWN,
      homeWrites: null,
      reason: 'the log carries no `== WRITES` census, so whether the script wrote the REAL home was '
        + 'never established',
    };
  }
  if (n === 0) {
    return { verdict: CENSUS_CLEAR, homeWrites: 0, reason: 'the census ran and attributed no write to the REAL home' };
  }
  if (witness === 'CLEAN') {
    return {
      verdict: CENSUS_CLEAR,
      homeWrites: n,
      reason: `OBSERVE attributed ${n} write(s) to the REAL home, but the drop arm's own jailed trace `
        + 'shows the lifecycle subtree never attempted a write inside the dropped scope '
        + '(DENIAL-WITNESS CLEAN)',
    };
  }
  return {
    verdict: CENSUS_REFUSE,
    homeWrites: n,
    reason: `OBSERVE attributed ${n} write(s) to the REAL home and no denial witness came back CLEAN, `
      + 'so the passing drop arm is as consistent with a swallowed refusal as with the capability '
      + 'being unnecessary — the artifact gate cannot see a home write',
  };
};
