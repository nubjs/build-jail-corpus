// Repair a committed record whose grant is an OVER-GRANT, by replaying its OWN archived driver log
// through today's recorder and writing the narrower grant back in place.
//
// ⛔⛔ WHAT THIS EXISTS TO FIX. 438 package@version specs in the committed corpus hold
// `write:{userHome}` — authority over the ENTIRE user home — or the wider `write:"disk"`, and that
// grant is most of what the build jail is for. A large part of it is not a measurement at all: it is
// an OLD READING of a measurement. `write-census.mjs`'s tool-cache subtraction is the current
// example — nub `push_rw_path`s three leaves inside its own tool cache and both POSIX drivers put
// that cache under `$HOME`, so every write a script makes into `electron-cache` landed in the
// `userHome` census bucket and synthesized `write.userHome` to reach a directory the jail had
// already handed it for free. The leaf list grew from one name to three at `0492dce58`, and the
// records written before that are frozen at the wide answer with their `driver.out` committed beside
// them, listing every path.
//
// ⛔ RE-MEASURING THEM IS THE WRONG INSTRUMENT, NOT MERELY THE EXPENSIVE ONE — the same argument
// `rerecord.mjs` makes for the opposite direction. Nothing about the MEASUREMENT is stale: no driver,
// arm, toolchain or jail moved. Only the recorder's READING of the log changed, and the log is right
// there. Replaying the archive is the instrument that matches the defect.
//
// ── WHY THIS IS A SIBLING OF `rerecord.mjs` AND NOT A FLAG ON IT ──────────────────────────────────
//
// `rerecord.mjs` may only ever WIDEN, and that is a deliberate safety property rather than an
// oversight: an offline re-record that can narrow could under-grant off a log that is INCOMPLETE in a
// way a fresh measurement would not be. Inverting it — or adding a `--narrow` flag — would put both
// directions behind one law and leave neither module able to state its own. So the law lives once per
// file, in the imperative, and each file can only ever move a grant one way:
//
//     rerecord.mjs         may only ever WIDEN   — repairs an UNDER-grant (a broken install)
//     narrow-rerecord.mjs  may only ever NARROW  — repairs an OVER-grant  (lost confinement)
//
// Both are real defects; they simply fail in opposite directions. What makes the narrowing sound is
// not that it is safer — it is not — but that every guard here FAILS CLOSED: on any doubt at all the
// record keeps the wider grant it already has, which is exactly the state the corpus is in today.
//
// ⛔⛔ AND NOTHING HERE RELAXES THE FALSIFIABILITY GATE. This module narrows ONLY where today's
// unmodified rule, run over this record's own committed log, ALREADY reaches the narrower grant —
// that is what `stale-adjudication.mjs`'s `STALE` verdict means, and it is the first guard. The rule
// is `parseDriverLog`, imported. The narrowing is scored by `publish-guard.decide()`, imported. There
// is no exemption, no waiver and no flag: a record today's rule keeps wide, this module keeps wide.
//
// ── WHAT IS WRITTEN, AND THE ONE GUARD THAT IS NOT IN THE WIDENING SIBLING ────────────────────────
//
// The same FOUR fields `rerecord.mjs` writes — `grant` and the three that explain it — and for the
// same reason: the epoch-58+ evidence fields (`falsifiabilityReasons`, `descentRedArm`,
// `denialWitness`, `observedEffect`) are provenance about the ORIGINAL measurement, and backfilling
// them would make an archived record claim a recorder generation it was not produced by.
//
// ⛔⛔ FOR A NARROWING THAT RESTRAINT IS NOT COSMETIC, AND `G3` BELOW IS WHERE IT BITES. `replay()`
// scores the recorder's object, which HAS those fields freshly parsed. The record this module
// actually writes is the ARCHIVE plus four assignments, and it does not. Those two score differently:
// `hasRedArm` reads `descentRedArm` off the record, so a narrowing licensed by a red arm in the
// replay is licensed by NOTHING once written down. MEASURED over the committed corpus: of the 164
// records `stale-adjudication --scan` calls STALE, ZERO carry a `descentRedArm` key at all and 132
// carry `arms-unfalsifiable`, so `decide()` re-asked of the written record WITHHOLDS 132 of them.
//
// That is not a technicality to route around. `collate.mjs`'s Gate 2 asks `narrowingEvidence` of the
// RAW committed record when it decides whether a platform may sit below the shipped grant, so a
// record narrowed without its own licence is floored straight back to the shipped grant at bake time
// — the corpus would say "narrowed" while the catalog stayed wide. Refusing those 132 is therefore
// both the safe answer and the honest one; they need a re-measure, which writes the evidence fields.
//
//   usage: narrow-rerecord.mjs --record <records-v2/runs/<plat>/<pkg>/<ver>> [--apply]
//          narrow-rerecord.mjs --scan   <records-v2> [--apply]
//
// Dry run by default: it prints what it WOULD write and exits 0. `--apply` is what writes.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { STALE, replay } from './stale-adjudication.mjs';
import { decide, narrows } from './publish-guard.mjs';
import { CENSUS_CLEAR, homeDropVerdict } from './write-census.mjs';
import { NET_CLEAR, networkDropVerdict } from './network-census.mjs';

export const NARROWED = 'NARROWED';
export const UNCHANGED = 'UNCHANGED';
export const REFUSED = 'REFUSED';

// ⛔ THE SAME FOUR FIELDS `rerecord.mjs` REPAIRS, DECLARED SEPARATELY RATHER THAN IMPORTED FROM IT.
// Importing would guarantee they never differ — and would also mean a field added to the WIDENING
// repair silently became writable by the NARROWING one, which is the direction that loses
// confinement. Declared here, a divergence is a test failure instead
// (`narrow-rerecord.test.mjs` pins the two lists equal).
export const REPAIRED_FIELDS = ['grant', 'grantSource', 'grantSourceReason', 'notes'];

// The capability tokens that carry authority over the user's real home. `write:"disk"` is the string
// form of the `write` axis and subsumes the home, so a drop of either is a drop of the home.
const HOME_CAPS = ['write.userHome', 'write:disk'];

const norm = (v) => JSON.stringify(v ?? null);
const has = (o, k) => Object.prototype.hasOwnProperty.call(o ?? {}, k);

/**
 * Which top-level fields differ between two records, by the recorder's own serialization.
 *
 * ⛔ COMPUTED OVER THE UNION OF BOTH KEY SETS, so a key ADDED or REMOVED shows up as a difference
 * rather than being skipped by iterating only one side — the half a `for (const k of Object.keys(a))`
 * loop silently gets wrong, and the direction that loses a field.
 */
export const fieldDiff = (a, b) => [...new Set([...Object.keys(a ?? {}), ...Object.keys(b ?? {})])]
  .filter((k) => norm(a?.[k]) !== norm(b?.[k]) || has(a, k) !== has(b, k));

const refuse = (reason, extra = {}) => ({ verdict: REFUSED, reason, ...extra });

/**
 * Decide what to do with one committed record, given its own archived log.
 *
 * Returns `{ verdict, reason }` plus, on NARROWED, the `rewritten` record and the `narrowed`
 * capability list. Writes nothing — `narrowRerecordDir` owns the filesystem.
 */
export const narrowRerecord = ({ committed, log, capture }) => {
  const r = replay({ committed, log, capture });

  // ── G1 ── TODAY'S UNMODIFIED RULE MUST ALREADY REACH THE NARROWER GRANT.
  //
  // ⛔ `STALE` IS THE WHOLE LICENCE, AND EVERY OTHER VERDICT IS A REFUSAL RATHER THAN A CASE TO
  // HANDLE. Reaching it means `stale-adjudication.mjs` has already run, in order: its own G1
  // parse-drift control (today's parser reproduces the committed `verdict`, `minimality`,
  // `overPredictedBy`, `synthesized` and `writePaths` exactly, so the grant delta is attributable to
  // the RULE and not to a parser change); its G2 red-arm audit (every `is NECESSARY` announcement
  // re-scored from its own `VERIFY[…]` line, so a VOID or artifact-gate-driven arm cannot pose as an
  // exit-code control); its G3 archive terms (the capture confirms a real home DISTINCT from the jail
  // home, and the census is not absent); and `decide()` against the recorder's object.
  //
  // ⛔ AND `CURRENT` IS REFUSED FOR A REASON WORTH NAMING, because it is the guard that catches the
  // case this module was warned about. `playwright-chromium@1.9.2` (linux) attributed 1185 real-home
  // writes whose listed paths all sit inside a free tool-cache leaf — but the printer caps the
  // listing at 40 entries and printed `… and 1145 more`, so `homeWriteCensus` cannot subtract and
  // `record.mjs` keeps `write.userHome`. Today's rule therefore reaches no narrowing, `replay()`
  // returns CURRENT, and this guard is what refuses it. VERIFIED against the committed record.
  if (r.verdict !== STALE) {
    return refuse(
      `⛔ REFUSED — today's rule does not reach a narrower grant for this record: stale-adjudication `
      + `returned ${r.verdict} — ${r.reason}. This module narrows ONLY where the unmodified rule, `
      + 'replayed over this record\'s own log, already produces the narrowing. It does not relax, '
      + 'waive or special-case any term of that rule.',
      { replay: r },
    );
  }
  const next = r.incoming;

  // ── G2 ── THE DIRECTION, ASKED OF THE TWO GRANTS AND OF NOTHING ELSE.
  //
  // ⛔⛔ DELIBERATELY NOT PHRASED AS "`replay()` SAID STALE", which G1 already established. The one
  // invariant this module must never break cannot be a consequence of another module's verdict
  // routing, so it is asked directly with `publish-guard.mjs`'s own `narrows` — the mirror image of
  // the law in `rerecord.mjs`, which asks the same question in the opposite direction for the same
  // reason. A tool that can move a grant EITHER way is the bug, whichever way it moved this time, so
  // both halves are asserted: something must be dropped, and nothing may be added.
  //
  // ⛔ THE TWO HALVES ARE NOT EQUALLY LIVE, AND THE ASYMMETRY IS MEASURED RATHER THAN ASSUMED. The
  // "adds nothing" half is live: a replay that BOTH drops and adds reaches STALE on its dropped term,
  // so nothing above this catches it. The "drops something" half is a STRUCTURAL BACKSTOP that no
  // input can reach past G1 — `replay()` returns STALE only when `narrows(committed.grant,
  // parsed.grant)` is non-empty, which is the identical set difference computed here. Mutation-tested
  // both ways: disabling the second half turns a test red, disabling the first turns none red. It is
  // kept rather than deleted for two reasons — the direction this module may move a grant is stated
  // in full here rather than inferred from another module's verdict routing, and `rerecord.mjs`
  // carries the mirror of exactly this backstop, equally unreachable and equally kept (verified by
  // the same mutation against its own suite). Deleting one side would leave the pair asymmetric on
  // the single property they exist to state in opposite directions.
  const narrowed = narrows(committed?.grant, next.grant);
  const widened = narrows(next.grant, committed?.grant);
  if (!narrowed.length) {
    return refuse(
      `⛔ REFUSED — the replay drops nothing, yet stale-adjudication returned ${r.verdict}: `
      + `${r.reason}. The two readings of this log disagree, so neither may be acted on.`,
      { replay: r },
    );
  }
  if (widened.length) {
    return refuse(
      `⛔ REFUSED — replaying this log would ADD ${widened.join(', ')} to `
      + `${JSON.stringify(committed?.grant ?? null)}. This module may only ever NARROW; a repair that `
      + 'both drops and adds is not a narrowing and must be re-recorded by rerecord.mjs or '
      + 're-measured, never applied here.',
      { replay: r },
    );
  }

  // ── G3 ── THE HOME-WRITE CENSUS, RE-ASKED AGAINST THE COMMITTED GRANT.
  //
  // ⛔⛔ THIS IS NOT A SECOND COPY OF `record.mjs`'s TERM — IT ASKS A DIFFERENT QUESTION, AND THE GAP
  // IS REAL RATHER THAN BELT-AND-BRACES. `record.mjs` computes `dropsHome` from the log's own
  // SYNTHESIZED grant against the DESCENDED one, so it consults the census only when the descent
  // itself takes the home away. This module takes the home away from the COMMITTED grant, and those
  // two are not the same object: `stale-adjudication.mjs`'s G1 pins `synthesized`, not `grant`, so a
  // record whose committed grant is WIDER than today's synthesized one — a ladder rung, or a grant
  // widened by a later repair — has its home removed by an edit `record.mjs` never scored. On that
  // record the live rule asked nothing and this guard is the only thing between the archive and a
  // silent loss of the home. Scoped to a drop that actually takes a home capability, because that is
  // the only drop it speaks to.
  //
  // ⛔ `CLEAR` IS REQUIRED, NOT MERELY "NOT REFUSED". `homeDropVerdict` has three answers and only
  // `CLEAR` is positive evidence — either the census ran and attributed nothing to the real home, or
  // everything it attributed was inside a tool-cache leaf the jail grants unconditionally, or the
  // drop arm's own jailed trace came back `CLEAN`. `UNKNOWN` means the log carries no census at all,
  // and an archived log cannot be re-run to find out.
  if (narrowed.some((c) => HOME_CAPS.includes(c))) {
    const census = homeDropVerdict({ log, witness: next?.denialWitness?.['no-write-userHome'] });
    if (census.verdict !== CENSUS_CLEAR) {
      return refuse(
        `⛔ REFUSED — this rewrite drops ${narrowed.filter((c) => HOME_CAPS.includes(c)).join(', ')} `
        + `from the committed grant, and the home-write census came back ${census.verdict}: `
        + `${census.reason}. Only positive evidence licenses taking the home away.`,
        { replay: r, census },
      );
    }

    // ⛔⛔ AND THE PATH EVIDENCE MUST BE COMPLETE, WHICH `CLEAR` ALONE DOES NOT GUARANTEE. A positive
    // `userHome` count can still clear on a `CLEAN` denial witness while the log's own path listing
    // was TRUNCATED — the printer caps at 40 entries — so nothing on disk says what the other
    // entries were. `homeWriteCensus` reports that as `basis: 'count-only'`, meaning it subtracted
    // nothing and reconciled nothing. A live re-measure may narrow on a witness because it can go
    // back and look; an offline repair reading a frozen archive cannot, so it stops here. Scoped to
    // a POSITIVE count: a census that attributed zero real-home writes has no listing to truncate
    // and is `count-only` by construction.
    if (census.homeWrites > 0 && census.censusBasis !== 'paths') {
      return refuse(
        `⛔ REFUSED — the census cleared this drop, but its ${census.homeWrites} attributed real-home `
        + 'write(s) are backed by no complete path listing (basis `count-only`), so what the log '
        + 'omits is unknown and nothing was reconciled. An archived log cannot be re-run to find '
        + 'out; a truncated listing is refused rather than trusted.',
        { replay: r, census },
      );
    }
  }

  // ── G5 ── THE NETWORK CENSUS, THE SAME QUESTION ON THE AXIS NOBODY HAD ASKED IT OF.
  //
  // ⛔⛔ FOUND BY RUNNING THE COLLATOR, NOT BY READING THE RECORDS. Every record-level and
  // field-level check on this repair was green while it silently re-created a defect a hand-written
  // override already patches. `artifact-gate.mjs` decides a drop arm by checking the package's
  // artefacts are present, and a fetch a WARM CACHE made unnecessary leaves that check perfectly
  // satisfied — so `network` drops off an arm that proved nothing, exactly as `write.userHome` did
  // before the home-write census. MEASURED: `electron-chromedriver@33.4.9` (darwin) recorded two real
  // HTTPS connections in OBSERVE and still returned `VERIFY[nar-no-network] rc=0 artifacts=11/11`.
  // Collating the narrowed corpus turned its macOS overlay into `{"write":null,"network":null}` —
  // and in an overlay `null` REMOVES, so macOS got no egress at all. `harness/overrides` carries a
  // hand-written entry undoing precisely that shape for the sibling package `electron`, because
  // `nub install electron@33.4.11` on a cold cache exits 1 with `getaddrinfo ENOTFOUND github.com`.
  //
  // ⛔ THE OVERRIDE IS THE EVIDENCE, NOT THE MECHANISM — this guard reads the record's own committed
  // census and never the overrides file, so it is an axis-level rule rather than a package
  // exemption, and it withholds on every package whose log shows the same thing.
  if (narrowed.includes('network')) {
    const net = networkDropVerdict({ log, witness: next?.denialWitness?.['no-network'] });
    if (net.verdict !== NET_CLEAR) {
      return refuse(
        `⛔ REFUSED — this rewrite drops network from the committed grant, and the network census came `
        + `back ${net.verdict}: ${net.reason}. Re-measure it on a COLD cache; do not narrow it here.`,
        { replay: r, net },
      );
    }
  }

  // ⛔ EVERY FIELD OUTSIDE THE REPAIRED SET MUST EITHER AGREE OR BE ABSENT FROM THE ARCHIVE. "Absent"
  // is the honest case and the only one waived: the epoch-58+ evidence fields did not exist when
  // these records were written, so today's recorder computes a value where the archive has no key at
  // all, and the repair leaves the archive as it found it. A field that IS present and DISAGREES is a
  // different animal — the log is being read differently on something this repair does not claim to
  // fix — and it refuses. `descendedGrant` is the one that carries real weight here: it is not among
  // `stale-adjudication.mjs`'s drift fields, so this is the only place a disagreement about what the
  // descent actually computed can be caught.
  const contested = fieldDiff(committed, next)
    .filter((k) => !REPAIRED_FIELDS.includes(k) && has(committed, k));
  if (contested.length) {
    return refuse(
      `⛔ REFUSED — replaying this log also changes ${contested.join(', ')}, which the archive already `
      + 'carries a value for. This repair rewrites the GRANT and the three fields that explain it; a '
      + 'disagreement anywhere else is not attributable to the grant rule and must be re-measured, '
      + 'not patched.',
      { replay: r, contested },
    );
  }

  // ⛔ THE COMMITTED OBJECT, PATCHED — never the recorder's object, written out. `record.mjs`'s `rec`
  // is an explicit whitelist and a field missing from it is silently dropped; rebuilding the record
  // from `next` would reproduce that loss against an archive nothing else re-reads. Patching four
  // keys that all already exist also preserves key ORDER, which is what keeps the committed file's
  // byte-for-byte round-trip intact and the diff readable.
  const rewritten = { ...committed };
  for (const f of REPAIRED_FIELDS) rewritten[f] = f === 'notes' ? [...new Set(next[f])] : next[f];

  // ── G4 ── THE PROJECT'S SCORER, RE-ASKED OF THE RECORD ACTUALLY BEING WRITTEN.
  //
  // ⛔⛔ `replay()` ALREADY RAN `decide()`, AND THIS IS NOT THE SAME CALL. It scored `r.incoming` —
  // the recorder's object, carrying `descentRedArm` / `falsifiabilityReasons` / `denialWitness`
  // freshly parsed out of the log. What goes on disk is the ARCHIVE plus four assignments, and the
  // archive predates all three. `hasRedArm` reads `descentRedArm` OFF THE RECORD, so a narrowing the
  // replay licenses on a red arm is licensed by nothing once written down, and `collate.mjs`'s Gate 2
  // — which asks `narrowingEvidence` of the raw committed record — would floor the platform straight
  // back to the shipped grant at bake time. MEASURED: this refuses 132 of the 164 STALE records,
  // every one of them carrying `arms-unfalsifiable` with no `descentRedArm` key. Backfilling the
  // evidence fields to get past it is the wrong repair: the record would then assert a recorder
  // generation it was not produced by, on a licence this module manufactured for it.
  const decision = decide(committed, rewritten);
  if (!decision.publish) {
    return refuse(
      `⛔ REFUSED — publish-guard withholds the narrowing once it is scored against the record that `
      + `would actually be written: ${decision.reason} The replay licenses it only because the `
      + 'recorder\'s object carries evidence fields this archive predates, and this repair does not '
      + 'backfill them. Re-measure it — a fresh run writes the evidence with the grant.',
      { replay: r, decision, rewritten },
    );
  }

  // ⛔ RE-DERIVED FROM THE RESULT, NOT ASSUMED FROM THE CONSTRUCTION ABOVE. The loop is two lines and
  // obviously correct today; the failure this catches is the edit that makes it not — spreading
  // `next` instead of `committed`, or growing `REPAIRED_FIELDS` by a field the repair was never
  // authorized to write. Both are green under every other gate in this repo.
  const touched = fieldDiff(committed, rewritten);
  const stray = touched.filter((k) => !REPAIRED_FIELDS.includes(k));
  if (stray.length) {
    return refuse(
      `⛔ REFUSED — the rewrite would change ${stray.join(', ')}, outside the repaired set `
      + `(${REPAIRED_FIELDS.join(', ')}). A field silently lost or gained in a rewrite is a `
      + 'regression nothing else in this repo would catch.',
      { replay: r },
    );
  }
  const keysBefore = Object.keys(committed);
  const keysAfter = Object.keys(rewritten);
  if (keysBefore.length !== keysAfter.length || keysBefore.some((k, i) => k !== keysAfter[i])) {
    return refuse(
      '⛔ REFUSED — the rewrite changes the record\'s key set or their order, so the committed file '
      + 'would be reformatted beyond the repair.',
      { replay: r },
    );
  }

  return {
    verdict: NARROWED,
    reason: `the committed grant is an OVER-GRANT that predates the current rule; replaying this `
      + `record's own log drops ${narrowed.join(', ')} — ${decision.reason}`,
    narrowed,
    touched,
    committedGrant: committed?.grant ?? null,
    grant: rewritten.grant,
    rewritten,
    decision,
    replay: r,
  };
};

/**
 * The same, for a record directory laid out the way the corpus is. Writes only under `apply`.
 *
 * ⛔ THE SERIALIZATION IS `record.mjs`'s, EXACTLY — `JSON.stringify(rec, null, 2)` plus a trailing
 * newline — so the on-disk diff of an applied repair is the four fields and nothing else. A record
 * that does NOT round-trip is refused rather than reformatted, because reformatting an archive hides
 * the repair inside noise.
 */
export const narrowRerecordDir = (dir, { apply = false } = {}) => {
  const resultsPath = path.join(dir, 'results.json');
  const logPath = path.join(dir, 'driver.out');
  if (!fs.existsSync(logPath)) return { verdict: REFUSED, reason: 'no driver.out beside the record', dir };
  const raw = fs.readFileSync(resultsPath, 'utf8');
  const committed = JSON.parse(raw);
  let capture = null;
  try { capture = JSON.parse(fs.readFileSync(path.join(dir, 'capture.json'), 'utf8')); } catch { capture = null; }

  const out = { ...narrowRerecord({ committed, log: fs.readFileSync(logPath, 'utf8'), capture }), committed, dir };
  if (out.verdict !== NARROWED) return out;

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
  // ⛔ DRY RUN IS THE DEFAULT AND WRITING IS THE OPT-IN. This edits a committed record in place, and
  // the corpus has no undo short of git.
  const apply = argv.includes('--apply');
  const show = (r) => {
    const id = `${r.committed?.pkg}@${r.committed?.version}`;
    if (r.verdict === NARROWED) {
      console.log(`${NARROWED.padEnd(9)} ${id}  ${JSON.stringify(r.committedGrant)} -> ${JSON.stringify(r.grant)}  (-${r.narrowed.join(', ')})`);
    } else if (r.verdict === REFUSED) {
      console.log(`${REFUSED.padEnd(9)} ${id}  ${r.reason}`);
    }
  };

  const one = opt('--record');
  if (one) {
    const r = narrowRerecordDir(one, { apply });
    show(r);
    if (r.verdict === UNCHANGED) console.log(`${UNCHANGED.padEnd(9)} ${r.committed?.pkg}@${r.committed?.version}  ${r.reason}`);
    process.exit(r.verdict === REFUSED ? 10 : 0);
  }

  const root = opt('--scan');
  if (!root) {
    console.error('usage: narrow-rerecord.mjs --record <dir> [--apply] | --scan <records-v2> [--apply]');
    process.exit(2);
  }
  // ⛔ `REFUSED` IS THE ORDINARY OUTCOME HERE, NOT AN ERROR. Most of the corpus is a record today's
  // rule agrees with, which lands as G1's refusal; the tally is what says so, and `--verbose` is what
  // prints the reasons when a specific refusal is being audited.
  const verbose = argv.includes('--verbose');
  const tally = { [NARROWED]: 0, [UNCHANGED]: 0, [REFUSED]: 0 };
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
        const r = narrowRerecordDir(dir, { apply });
        tally[r.verdict] += 1;
        if (r.verdict === NARROWED) {
          byPlatform[plat] = (byPlatform[plat] ?? 0) + 1;
          console.log(`${plat.padEnd(13)} ${r.committed?.pkg}@${r.committed?.version}  ${JSON.stringify(r.committedGrant)} -> ${JSON.stringify(r.grant)}`);
        } else if (verbose && r.verdict === REFUSED) {
          console.log(`REFUSED   ${plat.padEnd(13)} ${r.committed?.pkg}@${r.committed?.version}  ${r.reason}`);
        }
      }
    }
  }
  console.log(JSON.stringify({ ...tally, byPlatform, applied: apply }));
  if (!apply) console.log('DRY RUN — nothing was written. Re-run with --apply.');
}
