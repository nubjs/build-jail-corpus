// Is a COMMITTED record's grant stale against the rule the recorder runs TODAY — and is the evidence
// already in that record's own driver log strong enough to act on it without re-measuring?
//
// ⛔⛔ WHAT THIS EXISTS TO CATCH, AND IT IS A WHOLE POPULATION RATHER THAN A PACKAGE. The three-term
// falsifiability rule landed in `record.mjs` at epoch 58 (`0204bfec3`, 2026-08-31) and brought two
// fields with it: `falsifiabilityReasons`, which says WHICH detector died, and `descentRedArm`, the
// driver's own announcement that an arm went red. `applyGrantSourceRule` had answered the question
// with ONE term before that — "carries `arms-unfalsifiable` ⇒ keep the wider grant" — and every
// record written under it is frozen at that answer. The epoch-58 transition invalidated 45 packages,
// so the rest were never re-adjudicated.
//
// MEASURED on the committed corpus (6887 records, `probe/corpus-v2-lane` at 654eee444): 288 records
// hold `write:{userHome}` with `no-write-userHome` in `overPredictedBy` and the pre-epoch-58
// sentence "this package's arms could not have failed (arms-unfalsifiable)". ALL 288 carry
// `falsifiabilityReasons: null` and no `descentRedArm` — not because the check never ran, but
// because the RECORD had nowhere to put its answer. Their `driver.out` files are committed beside
// them and all 288 carry the `ARM-FALSIFIABILITY` marker: 281 say `gate-vacuous` ALONE, i.e. the
// exit code was live all along, and 71 contain a red descent arm. The evidence was measured, printed
// and archived; only the adjudication is old.
//
// ⛔ SO THIS IS A REPAIR OF THE READER, NEVER A RELAXATION OF THE GATE — the same shape as
// `gyp-subtarget-spill.mjs`, which made a live gate stop reporting phantom absences by fixing where
// it looked. Nothing here waives `arms-unfalsifiable`. The rule is re-run verbatim by importing
// `parseDriverLog`, the publish decision is made by importing `decide`, and this module's own
// contribution is THREE GATES THAT CAN ONLY WITHHOLD:
//
//   G1  PARSE-DRIFT CONTROL. Today's parser must reproduce the committed record's `verdict`,
//       `minimality`, `overPredictedBy`, `synthesized` and `writePaths` EXACTLY. If it does not,
//       this log is not being read the way it was read when the record was written, and the delta
//       between old and new grant is no longer attributable to the RULE. Without this gate a parser
//       change of any kind would silently republish the whole corpus.
//
//   G2  RED-ARM AUDIT. `descentRedArm` is a regex over the driver's PROSE, and prose is not the arm.
//       Each announcement is re-attached to its own `VERIFY[<label>]` line and re-scored from the
//       numbers there. Two hazards it closes, both with corpus evidence:
//         · A VOID arm announced as necessity. `measure.sh`'s descent loop was once
//           `if verify …; else NECESSARY`, and `wordpos@2.1.0`'s `drop-writedeps` arm came back
//           `REJECTED=2` / VOID with `'write.deps' is NECESSARY` printed anyway. A log written under
//           that form manufactures a positive control out of an arm that measured nothing.
//         · A GATE-driven red arm read as an EXIT-CODE control. `verify` returns 1 when `rc=0` and
//           the ARTIFACT GATE failed, and the driver announces necessity identically. MEASURED
//           across all 6887 logs: of 2601 announcements, 2313 sit on `rc=1` and 288 sit on `rc=0` —
//           a live artifact gate, not a live exit code. `record.mjs` licenses on
//           `rcLive && descentRedArm`, a sentence about the EXIT CODE, so a gate-driven row cannot
//           carry it. None of the 288 currently rest on one; the next record can.
//
//   G3  HOME-WRITE REALITY. A red arm proves the jail → denial → rc chain fires SOMEWHERE in this
//       run. It cannot prove it fires on the HOME write, because `artifact-gate.mjs` only ever walks
//       the package's own directory and a home write is by construction outside it. So a narrowing
//       that drops `write.userHome` is refused whenever OBSERVE attributed writes to the REAL-home
//       bucket and no denial witness came back CLEAN for that capability.
//
//       ⛔ THIS IS NOT HYPOTHETICAL AND IT IS THE REASON THE GATE IS HERE. 13 of the 70 records the
//       shipped rule would narrow are playwright/puppeteer browser downloaders whose ENTIRE product
//       is a home write: `playwright-chromium@1.9.2` (linux) performed 1185 real-home writes,
//       `@playwright/browser-chromium@1.61.1` (win32) 629. Both have red sibling arms on `network`
//       and `write.project`, both would drop `write.userHome`, and the drop arm passes because the
//       browser download is not something the artifact gate can see. On win32 nothing else catches
//       it — no jailed trace is taken there, so `denial-witness.mjs` cannot run at all.
//
// ⛔ THE ROOTS COME FROM `capture.json`, NEVER FROM A LOG HEADER. `roots.jailHome` is null in every
// darwin EVENT-LOG header, and a classifier rooted there bills jail-home writes as real-home writes.
// The driver's own `== WRITES ==` block is already rooted from `capture.json` and bills `jailHome` as
// its own bucket, so `userHome` there is the real home — but this module re-reads the capture and
// REFUSES rather than counts when the roots cannot be confirmed distinct.
//
//   usage: stale-adjudication.mjs --record <records-v2/runs/<plat>/<pkg>/<ver>>
//          stale-adjudication.mjs --scan   <records-v2>  [--only-stale]
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseDriverLog, isTruncatedRc } from './record.mjs';
import { decide, narrows } from './publish-guard.mjs';
import { observedEffect } from './observed-effect.mjs';

export const STALE = 'STALE';
export const CURRENT = 'CURRENT';
export const REFUSED = 'REFUSED';

// ── the driver's own attributed write census ──────────────────────────────────────────────────────
//
// ⛔ THREE SPELLINGS, ONE BLOCK, AND THE HEADER IS THE ONLY THING IN COMMON. linux prints
// `== WRITES the script actually performed ==`, darwin the same, win32 the bare `== WRITES ==`.
// Anchoring on `== WRITES` covers all three; anchoring on the long form silently returned "no block"
// for every win32 record, which reads as "unknown" and would have fenced 107 records off the answer.
const WRITES_HEADER = /^\s*==\s*WRITES\b/;
const SECTION = /^\s*==\s/;
// A bucket row is `<scope> <count>` with the paths indented deeper beneath it. darwin appends
// `(base profile already grants this — NOT billed)` to some rows, so the count is not end-anchored.
const BUCKET = /^\s{2,6}([A-Za-z][A-Za-z0-9]*)\s+(\d+)\b/;

// The REAL-home write count the driver attributed to the lifecycle subtree, or null when the log
// carries no census at all. ⛔ AN ABSENT `userHome` ROW INSIDE A PRESENT BLOCK IS ZERO, NOT UNKNOWN —
// the drivers omit a bucket with no members, so reading absence as unknown fences off exactly the
// records whose home write never happened, which are the safe ones.
export const homeWrites = (log) => {
  const lines = String(log).split(/\r?\n/);
  let inBlock = false;
  let count = null;
  for (const l of lines) {
    if (WRITES_HEADER.test(l)) { inBlock = true; count = 0; continue; }
    if (!inBlock) continue;
    if (SECTION.test(l)) { inBlock = false; continue; }
    const m = BUCKET.exec(l);
    if (m && m[1] === 'userHome') count = Number(m[2]);
  }
  return count;
};

// ── the red-arm audit ─────────────────────────────────────────────────────────────────────────────
//
// Both announcement spellings, and both are the `*)` default of the drivers' three-way `case`.
const ANNOUNCE = /^\s*'([^']+)' is NECESSARY — dropping it fails to verify\s*$|^\s*narrowing '([^']+)' fails ⇒ that capability IS necessary\s*$/;
const VERIFY = /^\s*VERIFY\[([^\]]+)\]\s+rc=(-?\d+)\b.*?OVERRIDDEN=(\d+)\s+REJECTED=(\d+)/;
const VOID_LINE = /arm is VOID/;

const slug = (s) => String(s).replace(/[^a-z0-9]/gi, '').toLowerCase();

// One row per announcement, each scored from the numbers on its OWN arm's VERIFY line.
//
// ⛔ THE ARM IS FOUND BY WALKING BACK TO THE NEAREST `VERIFY[…]` AND THEN CHECKING THE LABEL NAMES
// THE CAPABILITY. Proximity alone is a guess: MEASURED over all 2601 announcements in the corpus the
// nearest VERIFY line is between 1 and 26 lines above and its label matches the capability every
// time, so the label check costs nothing today and is what makes a future interleaving detectable
// instead of silently mis-attributed.
export const redArmRows = (log) => {
  const lines = String(log).split(/\r?\n/);
  const rows = [];
  for (let i = 0; i < lines.length; i += 1) {
    const a = ANNOUNCE.exec(lines[i]);
    if (!a) continue;
    const cap = a[1] ?? a[2];
    let v = null; let sawVoid = false;
    for (let j = i - 1; j >= 0; j -= 1) {
      if (VOID_LINE.test(lines[j])) sawVoid = true;
      const m = VERIFY.exec(lines[j]);
      if (m) { v = m; break; }
    }
    if (!v) { rows.push({ cap, kind: 'UNCORROBORATED', why: 'no VERIFY line precedes the announcement' }); continue; }
    const [, label, rcs, ovrs, rejs] = v;
    const rc = Number(rcs); const overridden = Number(ovrs); const rejected = Number(rejs);
    const base = { cap, label, rc, overridden, rejected };
    if (!slug(label).includes(slug(cap))) {
      rows.push({ ...base, kind: 'UNCORROBORATED', why: `arm \`${label}\` does not name \`${cap}\`` });
    } else if (sawVoid || overridden < 1 || rejected !== 0) {
      // The two VOID spellings `verify` prints before `return 2`, plus the numbers that produce the
      // second one. Either means the arm measured nothing and the announcement is manufactured.
      rows.push({ ...base, kind: 'VOID', why: `OVERRIDDEN=${overridden} REJECTED=${rejected}${sawVoid ? ' and the arm printed a VOID line' : ''}` });
    } else if (isTruncatedRc(rc)) {
      rows.push({ ...base, kind: 'TRUNCATED', why: `rc=${rc} is a kill at the budget, not a denial` });
    } else if (rc === 0) {
      rows.push({ ...base, kind: 'ARTIFACT-GATE', why: 'rc=0 — the ARTIFACT GATE failed, so this arm says nothing about the exit code' });
    } else {
      rows.push({ ...base, kind: 'EXIT-CODE', why: `rc=${rc} with the override engaged` });
    }
  }
  return rows;
};

// A licence that reads "the exit code was a live detector and an arm went red" is sound only when at
// least one announcement is EXIT-CODE and none is manufactured. A GATE row is not manufactured — it
// is simply about a different detector — so it neither carries nor poisons the licence.
export const redArmAudit = (log) => {
  const rows = redArmRows(log);
  const unsound = rows.filter((r) => r.kind === 'VOID' || r.kind === 'TRUNCATED' || r.kind === 'UNCORROBORATED');
  return {
    rows,
    exitCode: rows.filter((r) => r.kind === 'EXIT-CODE').length,
    gate: rows.filter((r) => r.kind === 'ARTIFACT-GATE').length,
    unsound,
    sound: unsound.length === 0 && rows.some((r) => r.kind === 'EXIT-CODE'),
  };
};

// ── G1: the parse-drift control ───────────────────────────────────────────────────────────────────
//
// Everything the grant-source rule does NOT compute. `grant`, `grantSource`, `grantSourceReason`,
// `descendedGrant`, `falsifiabilityReasons` and `descentRedArm` are deliberately absent: those are
// the delta this module exists to find.
export const DRIFT_FIELDS = ['verdict', 'minimality', 'overPredictedBy', 'synthesized', 'writePaths'];

const norm = (v) => JSON.stringify(v ?? null);

export const parseDrift = (committed, parsed) => DRIFT_FIELDS.filter((f) => {
  const was = f === 'writePaths' ? (committed?.writePaths ?? []) : committed?.[f];
  const now = f === 'writePaths' ? (parsed?.grant?.writePaths ?? []) : parsed?.[f];
  return norm(was) !== norm(now);
});

// ── the replay ────────────────────────────────────────────────────────────────────────────────────
export const replay = ({ committed, log, capture }) => {
  const parsed = parseDriverLog(log);

  const drift = parseDrift(committed, parsed);
  if (drift.length) {
    return {
      verdict: REFUSED,
      reason: `parse-drift on ${drift.join(', ')} — today's parser does not read this log the way the `
        + 'recorder that wrote the record did, so the difference in grant is not attributable to the rule',
    };
  }

  const dropped = narrows(committed?.grant, parsed.grant);
  if (!dropped.length) {
    return { verdict: CURRENT, reason: 'the current rule reaches the committed grant', grant: parsed.grant };
  }

  // G2. Audited whenever the red arm is present at all: the audit can only WITHHOLD, so auditing a
  // record whose licence came from somewhere else costs a refusal we did not have to make and never
  // publishes one we should not.
  if (parsed.descentRedArm === true) {
    const audit = redArmAudit(log);
    if (!audit.sound) {
      const why = audit.unsound.length
        ? audit.unsound.map((r) => `${r.cap}: ${r.kind} (${r.why})`).join('; ')
        : `every red announcement is ARTIFACT-GATE driven (${audit.gate}), so nothing here exercised the exit code`;
      return { verdict: REFUSED, reason: `unsound red arm — ${why}`, audit };
    }
  }

  // G3.
  if (dropped.includes('write.userHome')) {
    const roots = capture?.roots;
    if (!roots || typeof roots.home !== 'string' || !roots.home
      || (roots.jailHome != null && roots.jailHome === roots.home)) {
      return {
        verdict: REFUSED,
        reason: 'the capture\'s roots do not confirm a real home distinct from the jail home, so the '
          + 'write census cannot be attributed — never guess this one, a lane already billed 32 '
          + 'jail-home writes as real-home writes',
      };
    }
    const hw = homeWrites(log);
    if (hw === null) {
      return { verdict: REFUSED, reason: 'the log carries no `== WRITES ==` census, so whether the script wrote the real home is unknown' };
    }
    if (hw > 0 && committed?.denialWitness?.['no-write-userHome'] !== 'CLEAN'
      && parsed?.denialWitness?.['no-write-userHome'] !== 'CLEAN') {
      return {
        verdict: REFUSED,
        reason: `OBSERVE attributed ${hw} write(s) to the REAL home and no denial witness came back `
          + 'CLEAN, so the passing drop arm is as consistent with a swallowed refusal as with the '
          + 'capability being unnecessary — the artifact gate cannot see a home write',
        homeWrites: hw,
      };
    }
  }

  // ⛔ THE RECORD HANDED TO `decide` IS THE COMMITTED ONE WITH EXACTLY THE FIELDS THE RECORDER WOULD
  // HAVE REWRITTEN, and `observedEffect` is recomputed here for the same reason `record.mjs`'s CLI
  // computes it: the veto is a REFUSAL, and carrying the committed record's absent one forward would
  // make this path laxer than the pipeline it is standing in for.
  const incoming = {
    ...committed,
    grant: parsed.grant,
    grantSource: parsed.grantSource,
    grantSourceReason: parsed.grantSourceReason,
    descendedGrant: parsed.descendedGrant ?? null,
    notes: parsed.notes,
    falsifiabilityReasons: parsed.falsifiabilityReasons ?? null,
    descentRedArm: parsed.descentRedArm === true,
    denialWitness: parsed.denialWitness ?? {},
    writePaths: parsed.grant?.writePaths ?? [],
    observedEffect: observedEffect({
      lifecyclePids: parsed.observedCounts?.lifecyclePids ?? null,
      writes: parsed.observedCounts?.writes ?? null,
      peers: parsed.observedCounts?.peers ?? null,
      declares: parsed.declaresInstallWork,
    }),
  };

  // ⛔ THE PROJECT'S SCORER, IMPORTED. Re-deriving "may this narrowing publish?" here is how the two
  // would drift, and the naive re-derivation — refuse anything carrying `arms-unfalsifiable` — is the
  // exact drift to expect.
  const decision = decide(committed, incoming);
  if (!decision.publish) {
    return { verdict: REFUSED, reason: `publish-guard: ${decision.reason}`, incoming, dropped, decision };
  }
  return {
    verdict: STALE,
    reason: `the committed grant predates the current rule; replaying it over this record's own log `
      + `drops ${dropped.join(', ')} — ${decision.reason}`,
    grant: parsed.grant,
    incoming,
    dropped,
    decision,
  };
};

// Convenience for a record directory laid out the way the corpus is.
export const replayRecordDir = (dir) => {
  const read = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
  const committed = read('results.json');
  const logPath = path.join(dir, 'driver.out');
  if (!fs.existsSync(logPath)) return { verdict: REFUSED, reason: 'no driver.out beside the record', committed };
  let capture = null;
  try { capture = read('capture.json'); } catch { capture = null; }
  return { ...replay({ committed, log: fs.readFileSync(logPath, 'utf8'), capture }), committed };
};

// ⛔ `pathToFileURL`, AND `process.argv[1] &&` BEFORE IT. The string form never matches on Windows,
// where the whole CLI is then skipped while the process exits 0 — a total loss every caller reads as
// success — and `pathToFileURL(undefined)` throws on a bare import. `cli-guard.test.mjs` pins both.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : '');
  const one = opt('--record');
  if (one) {
    const r = replayRecordDir(one);
    console.log(`${r.verdict} ${r.committed?.pkg}@${r.committed?.version}: ${r.reason}`);
    if (r.grant) console.log(`  grant ${JSON.stringify(r.committed?.grant)} -> ${JSON.stringify(r.grant)}`);
    process.exit(r.verdict === REFUSED ? 10 : 0);
  }
  const root = opt('--scan');
  if (!root) {
    console.error('usage: stale-adjudication.mjs --record <dir> | --scan <records-v2> [--only-stale]');
    process.exit(2);
  }
  const tally = { STALE: 0, CURRENT: 0, REFUSED: 0 };
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
        const r = replayRecordDir(dir);
        tally[r.verdict] += 1;
        if (r.verdict === STALE || (r.verdict === REFUSED && !argv.includes('--only-stale'))) {
          console.log(`${r.verdict.padEnd(8)} ${plat.padEnd(13)} ${r.committed?.pkg}@${r.committed?.version}  ${r.reason}`);
        }
      }
    }
  }
  console.log(JSON.stringify(tally));
}
