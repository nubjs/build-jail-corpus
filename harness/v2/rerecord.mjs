// Repair a committed record whose grant is an UNDER-GRANT, by replaying its OWN archived driver log
// through today's recorder and writing the wider grant back in place.
//
// ⛔⛔ WHAT THIS EXISTS TO FIX, AND WHY IT IS NOT A RE-MEASURE. `artifact-gate.mjs` only ever walks
// the package's own directory, so a write into the user's REAL home is by construction outside
// everything it can see. For a package whose product IS a home write — a browser downloader, a
// plugin fetcher — the `no-write-userHome` drop arm therefore PASSES with the product missing, and
// the descent narrows the grant off an arm that proved nothing. Epoch 70 fixed the RULE: `record.mjs`
// now refuses to drop `write.userHome` when the driver's own attributed census recorded real-home
// writes and no denial witness came back CLEAN (`write-census.mjs`). But a rule only runs at
// MEASUREMENT time, and MEASURED on the committed corpus at `2e2a672db` 115 records were already
// frozen at the bad answer — the worst `ibm_db@2.8.2` (win32), 3337 attributed real-home writes
// against a committed grant of `{"network":true}`, no write scope at all.
//
// ⛔ RE-MEASURING THEM IS THE WRONG INSTRUMENT, NOT MERELY THE EXPENSIVE ONE. These package names are
// heavily version-swept and `record-validity.mjs` has no version selector, so re-running the 115
// costs 880 records on a single runner that already has a queue. And nothing about the MEASUREMENT is
// stale: no driver, arm, toolchain or jail moved between then and now. Only the recorder's READING of
// the log changed, and every affected record's `driver.out` is committed beside it. Replaying the
// archive is therefore the instrument that matches the defect — the same shape as
// `stale-adjudication.mjs`, which replays the same logs to find grants that are too WIDE.
//
// ⛔⛔ AND THIS MODULE MAY ONLY EVER WIDEN. A re-record that NARROWS a committed grant is precisely
// the harm being repaired, arriving through the repair. The gate is not a consequence of which
// branch of `replay()` a record lands in — it is asked directly of the two grants, with
// `publish-guard.mjs`'s own `narrows`, so it still fires if the verdict routing above it ever
// changes. There is no flag that turns it off.
//
// ── WHY A SIBLING OF `stale-adjudication.mjs` RATHER THAN A MODE INSIDE IT ────────────────────────
//
// That module is a pure ADJUDICATOR: every export is a classifier, and its CLI only ever reads. It is
// also the instrument used to VERIFY this repair (`--scan`, and its `underGranted` tally). An
// instrument that can mutate the thing it measures is one bad flag away from reporting a corpus it
// just edited, so the writer lives in its own file and the adjudicator keeps the property that no
// invocation of it can write. The two also answer different questions with different gates: G1/G2/G3
// there all exist to WITHHOLD a NARROWING; the gates here ask whether a WIDENING is confined to the
// fields the repair is allowed to touch. Nothing is re-implemented — `replay()` is imported, and
// through it `parseDriverLog` and `decide`.
//
// ── WHAT IS WRITTEN, AND WHAT IS DELIBERATELY LEFT ALONE ──────────────────────────────────────────
//
// The repair writes FOUR fields: `grant`, and the three that explain it — `grantSource`,
// `grantSourceReason`, `notes`. Nothing else. In particular it does NOT backfill the fields today's
// recorder emits that these archived records predate (`falsifiabilityReasons`, `descentRedArm`,
// `denialWitness`, `observedEffect`, and on one record `writePaths`). Those are provenance about the
// ORIGINAL measurement's evidence; writing them now would make an archived record claim a recorder
// generation it was not produced by, and it is a second, unaudited rewrite riding on the authorized
// one. MEASURED across all 115: every one carries all four repaired keys already, so the rewrite adds
// no key, removes none, and reorders none — and all 115 round-trip byte-for-byte through
// `JSON.stringify(rec, null, 2) + '\n'`, so the diff is exactly the repair.
//
// ⛔ `record.mjs`'s EMITTED-FIELD WHITELIST IS WHY THE DIFF IS CHECKED AT ALL. `rec` there is an
// explicit list, and a field that is parsed but missing from it is computed on every run and then
// thrown away — `confinedWide` shipped in exactly that state, so the one arm adjudicating the write
// axis of a `write:"disk"` record left no trace in the corpus. A rewrite that reconstructed the
// record from the recorder's object instead of PATCHING the committed one would reproduce that loss
// against the archive, silently, and no other gate in this repo would see it. So the record written
// is the committed object with four assignments, and the full-record diff is re-derived from the
// bytes afterwards rather than assumed from the construction.
//
//   usage: rerecord.mjs --record <records-v2/runs/<plat>/<pkg>/<ver>> [--apply]
//          rerecord.mjs --scan   <records-v2> [--apply]
//
// Dry run by default: it prints what it WOULD write and exits 0. `--apply` is what writes.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { CURRENT, replay } from './stale-adjudication.mjs';
import { narrows } from './publish-guard.mjs';

export const WIDENED = 'WIDENED';
export const UNCHANGED = 'UNCHANGED';
export const REFUSED = 'REFUSED';

// ⛔ THE WHOLE LIST, AND IT IS THE CONTRACT THE DIFF GATE ENFORCES. `grant` is the repair;
// `grantSource` and `grantSourceReason` are the recorder's own account of WHY the grant is what it
// is, and a grant rewritten without them is the silent-narrowing shape the grant-source fields exist
// to prevent, in reverse. `notes` carries `home-write-attributed`, which is the queryable marker that
// this record's home write was attributed rather than assumed.
export const REPAIRED_FIELDS = ['grant', 'grantSource', 'grantSourceReason', 'notes'];

const norm = (v) => JSON.stringify(v ?? null);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o ?? {}, k);

/**
 * Which top-level fields differ between two records, by the recorder's own serialization.
 *
 * ⛔ COMPUTED OVER THE UNION OF BOTH KEY SETS, so a key ADDED or REMOVED shows up as a difference
 * rather than being skipped by iterating only one side. That is the half a `for (const k of
 * Object.keys(a))` loop silently gets wrong, and it is the direction that loses a field.
 */
export const fieldDiff = (a, b) => [...new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})])]
  .filter((k) => norm(a?.[k]) !== norm(b?.[k]) || has(a, k) !== has(b, k));

/**
 * Decide what to do with one committed record, given its own archived log.
 *
 * Returns `{ verdict, reason }` plus, on WIDENED, the `rewritten` record and the `widened` capability
 * list. Writes nothing — `rerecordRecordDir` owns the filesystem.
 */
export const rerecord = ({ committed, log, capture }) => {
  const r = replay({ committed, log, capture });

  // ⛔ NO RECORD, NO REPAIR — AND `parse-drift` IS THE ONE THAT MATTERS. `replay()` builds its
  // record immediately after G1, so an absent `incoming` means it refused before that: G1 says
  // today's parser does not read this log the way the recorder that wrote the record did, and the
  // difference between the two grants is then not attributable to the RULE at all. Repairing on
  // that basis would republish the corpus on the strength of a parser change. G2's unsound-red-arm
  // refusal lands here too, with its own sentence quoted.
  const next = r.incoming;
  if (!next) {
    return {
      verdict: REFUSED,
      reason: `stale-adjudication returned ${r.verdict} before a record could be built — ${r.reason}`,
      replay: r,
    };
  }

  const widened = narrows(next.grant, committed?.grant);
  const narrowed = narrows(committed?.grant, next.grant);

  // ⛔⛔ THE LAW, ASKED OF THE TWO GRANTS AND OF NOTHING ELSE. It is deliberately NOT phrased as
  // "`replay()` said CURRENT", because that would make the one invariant this module must never break
  // a consequence of another module's verdict routing. Asked directly it is also LIVE rather than
  // decorative: MEASURED on the committed corpus at `2e2a672db` it fires on the 132 records
  // `stale-adjudication --scan` reports STALE, every one of which is a log whose replay drops a
  // capability. Those are real narrowings and they may well be correct — but a narrowing is scored by
  // `publish-guard.decide()` against a re-run descent, never applied offline by a repair tool.
  if (narrowed.length) {
    return {
      verdict: REFUSED,
      reason: `⛔ REFUSED — replaying this log would DROP ${narrowed.join(', ')} from `
        + `${JSON.stringify(committed?.grant ?? null)} to ${JSON.stringify(next?.grant ?? null)}. This `
        + 'module may only ever WIDEN: narrowing a committed grant offline, with no arm re-run, is the '
        + 'under-grant this repair exists to undo. Re-measure it, or adjudicate it with '
        + 'stale-adjudication.mjs, which scores a narrowing with publish-guard.',
      replay: r,
    };
  }

  // ⛔ THE TWO MODULES MUST AGREE ON WHETHER THIS IS A NARROWING. Past the gate above there is no
  // dropped capability, so `replay()` has to have reached CURRENT; anything else means it refused or
  // went STALE for a reason its own grant comparison does not show, and the two readings of this log
  // have diverged. Refusing is the only safe answer to an instrument disagreement — never pick one.
  if (r.verdict !== CURRENT) {
    return {
      verdict: REFUSED,
      reason: `⛔ REFUSED — the replay drops nothing, yet stale-adjudication returned ${r.verdict}: `
        + `${r.reason}. The two readings of this log disagree, so neither may be acted on.`,
      replay: r,
    };
  }

  if (!widened.length) {
    return { verdict: UNCHANGED, reason: 'the current rule reaches the committed grant — nothing to repair', replay: r };
  }

  // ⛔ EVERY FIELD OUTSIDE THE REPAIRED SET MUST EITHER AGREE OR BE ABSENT FROM THE ARCHIVE. "Absent"
  // is the honest case and the only one waived: `falsifiabilityReasons`, `descentRedArm`,
  // `denialWitness` and `observedEffect` did not exist when these records were written, so today's
  // recorder computes a value where the archive has no key at all, and the repair leaves the archive
  // as it found it. A field that IS present and DISAGREES is a different animal — the log is being
  // read differently on something this repair does not claim to fix — and it refuses.
  // MEASURED across all 115: zero records are in that state.
  const contested = fieldDiff(committed, next)
    .filter((k) => !REPAIRED_FIELDS.includes(k) && has(committed, k));
  if (contested.length) {
    return {
      verdict: REFUSED,
      reason: `⛔ REFUSED — replaying this log also changes ${contested.join(', ')}, which the archive `
        + 'already carries a value for. This repair rewrites the GRANT and the three fields that '
        + 'explain it; a disagreement anywhere else is not attributable to the grant rule and must be '
        + 're-measured, not patched.',
      replay: r,
      contested,
    };
  }

  // ⛔ THE COMMITTED OBJECT, PATCHED — never the recorder's object, written out. `record.mjs`'s `rec`
  // is an explicit whitelist and a field missing from it is silently dropped; rebuilding the record
  // from `next` would reproduce that loss against an archive nothing else re-reads. Patching four
  // keys that all already exist also preserves key ORDER, which is what keeps the committed file's
  // byte-for-byte round-trip intact and the diff readable.
  const rewritten = { ...committed };
  for (const f of REPAIRED_FIELDS) rewritten[f] = f === 'notes' ? [...new Set(next[f])] : next[f];

  // ⛔ RE-DERIVED FROM THE RESULT, NOT ASSUMED FROM THE CONSTRUCTION ABOVE. The loop is four lines and
  // obviously correct today; the failure this catches is the edit that makes it not — spreading
  // `next` instead of `committed`, or growing `REPAIRED_FIELDS` by a field the repair was never
  // authorized to write. Both are green under every other gate in this repo.
  const touched = fieldDiff(committed, rewritten);
  const stray = touched.filter((k) => !REPAIRED_FIELDS.includes(k));
  if (stray.length) {
    return {
      verdict: REFUSED,
      reason: `⛔ REFUSED — the rewrite would change ${stray.join(', ')}, outside the repaired set `
        + `(${REPAIRED_FIELDS.join(', ')}). A field silently lost or gained in a rewrite is a `
        + 'regression nothing else in this repo would catch.',
      replay: r,
    };
  }
  const keysBefore = Object.keys(committed);
  const keysAfter = Object.keys(rewritten);
  if (keysBefore.length !== keysAfter.length || keysBefore.some((k, i) => k !== keysAfter[i])) {
    return {
      verdict: REFUSED,
      reason: '⛔ REFUSED — the rewrite changes the record\'s key set or their order, so the committed '
        + 'file would be reformatted beyond the repair.',
      replay: r,
    };
  }

  return {
    verdict: WIDENED,
    reason: `the committed grant is an UNDER-GRANT; replaying this record's own log restores `
      + `${widened.join(', ')} — ${next.grantSourceReason}`,
    widened,
    touched,
    committedGrant: committed?.grant ?? null,
    grant: next.grant,
    rewritten,
    replay: r,
  };
};

/**
 * The same, for a record directory laid out the way the corpus is. Writes only under `apply`.
 *
 * ⛔ THE SERIALIZATION IS `record.mjs`'s, EXACTLY — `JSON.stringify(rec, null, 2)` plus a trailing
 * newline. MEASURED: all 115 target files round-trip through it byte-for-byte, so the on-disk diff of
 * an applied repair is the four fields and nothing else. A record that does NOT round-trip is
 * refused rather than reformatted, because reformatting an archive hides the repair inside noise.
 */
export const rerecordRecordDir = (dir, { apply = false } = {}) => {
  const resultsPath = path.join(dir, 'results.json');
  const logPath = path.join(dir, 'driver.out');
  if (!fs.existsSync(logPath)) return { verdict: REFUSED, reason: 'no driver.out beside the record' };
  const raw = fs.readFileSync(resultsPath, 'utf8');
  const committed = JSON.parse(raw);
  let capture = null;
  try { capture = JSON.parse(fs.readFileSync(path.join(dir, 'capture.json'), 'utf8')); } catch { capture = null; }

  const out = { ...rerecord({ committed, log: fs.readFileSync(logPath, 'utf8'), capture }), committed, dir };
  if (out.verdict !== WIDENED) return out;

  if (raw !== `${JSON.stringify(committed, null, 2)}\n`) {
    return {
      ...out,
      verdict: REFUSED,
      reason: '⛔ REFUSED — this results.json does not round-trip through the recorder\'s own '
        + 'serialization, so rewriting it would reformat the file around the repair and hide it.',
    };
  }
  const text = `${JSON.stringify(out.rewritten, null, 2)}\n`;
  if (apply) fs.writeFileSync(resultsPath, text);
  return { ...out, applied: apply, text };
};

// ⛔ `pathToFileURL`, AND `process.argv[1] &&` BEFORE IT. The string form never matches on Windows,
// where the whole CLI is then skipped while the process exits 0 — a total loss every caller reads as
// success — and `pathToFileURL(undefined)` throws on a bare import. `cli-guard.test.mjs` pins both.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : '');
  // ⛔ DRY RUN IS THE DEFAULT AND WRITING IS THE OPT-IN. This is the only tool in the harness that
  // edits a committed record in place, and the corpus has no undo short of git.
  const apply = argv.includes('--apply');
  const show = (r) => {
    const id = `${r.committed?.pkg}@${r.committed?.version}`;
    if (r.verdict === WIDENED) {
      console.log(`${WIDENED.padEnd(9)} ${id}  ${JSON.stringify(r.committedGrant)} -> ${JSON.stringify(r.grant)}  (+${r.widened.join(', ')})`);
    } else if (r.verdict === REFUSED) {
      console.log(`${REFUSED.padEnd(9)} ${id}  ${r.reason}`);
    }
  };

  const one = opt('--record');
  if (one) {
    const r = rerecordRecordDir(one, { apply });
    show(r);
    if (r.verdict === UNCHANGED) console.log(`${UNCHANGED.padEnd(9)} ${r.committed?.pkg}@${r.committed?.version}  ${r.reason}`);
    process.exit(r.verdict === REFUSED ? 10 : 0);
  }

  const root = opt('--scan');
  if (!root) {
    console.error('usage: rerecord.mjs --record <dir> [--apply] | --scan <records-v2> [--apply]');
    process.exit(2);
  }
  const tally = { [WIDENED]: 0, [UNCHANGED]: 0, [REFUSED]: 0 };
  const byPlatform = {};
  const runs = path.join(root, 'runs');
  // ⛔ WALK, NEVER CONSTRUCT. A scoped name is `+`-encoded on disk (`@pulumi+gcp`), and a lane that
  // read `@x` as a scope DIRECTORY fabricated 224 of 300 specs before anyone noticed.
  for (const plat of fs.readdirSync(runs)) {
    const pd = path.join(runs, plat);
    if (!fs.statSync(pd).isDirectory()) continue;
    for (const slugDir of fs.readdirSync(pd)) {
      const sd = path.join(pd, slugDir);
      if (!fs.statSync(sd).isDirectory()) continue;
      for (const ver of fs.readdirSync(sd)) {
        const dir = path.join(sd, ver);
        if (!fs.existsSync(path.join(dir, 'results.json'))) continue;
        const r = rerecordRecordDir(dir, { apply });
        tally[r.verdict] += 1;
        if (r.verdict === WIDENED) {
          byPlatform[plat] = (byPlatform[plat] ?? 0) + 1;
          console.log(`${plat.padEnd(13)} ${r.committed?.pkg}@${r.committed?.version}  ${JSON.stringify(r.committedGrant)} -> ${JSON.stringify(r.grant)}`);
        }
      }
    }
  }
  console.log(JSON.stringify({ ...tally, byPlatform, applied: apply }));
  if (!apply) console.log('DRY RUN — nothing was written. Re-run with --apply.');
}
