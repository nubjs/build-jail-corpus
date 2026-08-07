// Turn a v2 driver's STDOUT into a corpus record.
//
// ⛔ THE THREE DRIVERS PRINT; NONE OF THEM WRITES A RECORD. `measure.sh`, `measure-macos.sh` and
// `measure-windows.mjs` were each built to be read by a human on a probe branch, so every v2 result
// so far has lived in a workflow log that expires. A queue-driven lane needs a durable artifact per
// (platform, pkg, version), and that artifact has to be shaped like a v1 record or nothing
// downstream can read it: `collate.mjs` keys on `rec.grant` / `rec.verdict` / `provenance.platform`
// and takes repeated `--runs <dir>`, and `claim-slice.mjs --reconcile` keys on the same three. So
// this parses the driver's own terminal vocabulary into that shape rather than inventing one.
//
// ⛔ THE THREE VOCABULARIES DIFFER AND ONE PAIR IS A FALSE FRIEND. The POSIX drivers print
// `=> VERIFIED <grant>` where the Windows driver prints `=> MINIMUM <grant>   (observed, then
// verified)` for the SAME outcome, and the Windows driver ALSO prints `=> MINIMUM <grant>
// (ladder fallback; ...)` for a materially different one — a grant OBSERVE under-predicted and the
// ladder repaired. Keying on the word `MINIMUM` alone therefore merges the arm that proves synthesis
// works with the arm that proves it failed. `verifiedBy` keeps them apart in the record; the verdict
// stays `MINIMUM` so a v2 record collates through the existing catalog builder unchanged.
//
// ⛔ A DRIVER THAT PRODUCES NO TERMINAL LINE IS AN INSTRUMENT FAILURE, NOT AN EMPTY GRANT. It gets a
// `HARNESS-*` verdict, which `claim-slice.mjs` deliberately refuses to close a queue row on — the
// row returns to `pending` so a later fix can reach it. Emitting `null` here instead would bake the
// harness's own failure into the corpus as a measurement, which is the thing this project exists to
// prevent.
//
//   usage: node record.mjs --log <driver-stdout> --pkg <p> --version <v> --out <dir> [--rc <n>]
//                          [--platform <p>] [--duration-ms <n>] [--nub-sha <sha>] ...

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// A grant is a JSON object with no string values containing braces, so brace-depth scanning is
// exact. `JSON.parse` on a regex-sliced tail is not: `(observed, then verified)` trails the object
// on every VERIFIED line and a greedy match swallows it.
export const firstObject = (line) => {
  const start = line.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  for (let i = start; i < line.length; i++) {
    if (line[i] === '{') depth++;
    else if (line[i] === '}' && --depth === 0) {
      try { return JSON.parse(line.slice(start, i + 1)); } catch { return null; }
    }
  }
  return null;
};

const VERDICTS = {
  'BROKEN-WITHOUT-JAIL-TOO': /=>\s*BROKEN-WITHOUT-JAIL-TOO/,
  'NO-STATE-PASSED': /=>\s*NO-STATE-PASSED/,
  VOID: /=>\s*(?:⛔\s*)?VOID/,
  UNKNOWN: /=>\s*UNKNOWN\b/,
  'OBSERVE-ONLY': /=>\s*OBSERVE-ONLY/,
  'HARNESS-TIMEOUT': /=>\s*TIMED-OUT/,
  'HARNESS-ERROR': /=>\s*(?:HARNESS-ERROR|CAPTURE FAILED|PARSE FAILED)|SYNTHESIZE FAILED|DTRACE NEVER STARTED/,
};

export function parseDriverLog(log) {
  const lines = log.split('\n');
  const out = {
    verdict: null,
    grant: null,
    synthesized: null,
    verifiedBy: null,
    minimality: null,
    overPredictedBy: [],
    notes: [],
    rawLogPath: null,
    capturePath: null,
    eventLogPath: null,
    eventLog: null,
    // Venue-portability R3/R6. Null rather than guessed: a driver that does not report these has
    // not measured them, and inventing a value here would make an unmeasured field indistinguishable
    // from a measured one.
    storeLayout: null,
    interpreterPath: null,
    overrides: null,
    // ⛔ WHICH DERIVED `writePaths` ENTRIES EMBED THE MEASURED VERSION. `collate.mjs` already reads
    // `writePathsVersionPinned` off a record and turns it into a re-measure note — that reader has
    // existed since v1 and has been inert for every v2 record, because no v2 driver emitted the
    // marker. An entry like `.cache/foo-1.2.3` names a directory that MOVES on the next release, so
    // without this the catalog would ship an entry that silently stops matching. Empty ARRAY, not
    // null: the classifier always answers this question now, so "no pinned entries" is a measured
    // answer rather than an absence.
    writePathsVersionPinned: [],
    // ⛔ WHERE THE JAILED ARMS RAN. Two records from different venues can agree on every other field
    // and still have been measured under filesystem roots with different ACLs — and on Windows that
    // is not hypothetical: any jail root under `C:\Users\<user>` fails before a single script runs
    // with "could not evaluate ALL APPLICATION PACKAGES rights on …: The access control list (ACL)
    // structure is invalid. (os error 1336)", because that home carries seven inheritable
    // `S-1-15-2-…` AppContainer package SIDs. MEASURED: only the root path changed between the
    // failing and passing runs. So a record that does not name its jail root cannot distinguish
    // "this package needs a wider grant" from "this run was rooted somewhere the jail cannot build a
    // token", and a reader comparing two venues would attribute the second to the first.
    jailRoot: null,
    observeUser: null,
    ciChild: null,
    cwdUnplaceableWrites: null,
    cwdResolved: null,
    nubBinary: null,
  };

  let synthesizedNext = false;
  for (const l of lines) {
    // ⛔ THE RETAINED EVENT LOG. The driver writes the file and prints its PATH; this reader only
    // learns where it is. That keeps the contract at two stdout lines, so a platform adopts
    // retention by printing them and this file never learns a trace format.
    // ⛔ THE RAW TRACER OUTPUT IS THE ARTIFACT OF RECORD; the normalized event log below it is a
    // derived cache. A normalized stream bakes in today's DECODER the way a scope tag bakes in
    // today's classifier — and both of those decoders have already been measured losing events
    // silently. With the raw kept, a decoder bug is a re-parse; without it, a permanent hole.
    const rwf = /RAWLOG-FILE\s+(\S+)/.exec(l);
    if (rwf) { out.rawLogPath = rwf[1]; continue; }
    // A raw trace with unknown capture parameters is worth much less than it looks: "no `linkat`
    // records" means `linkat` never fired under one adapter revision and was never SUBSCRIBED under
    // another, and nothing in the byte stream tells them apart.
    const rwc = /RAWLOG-CAPTURE\s+(\S+)/.exec(l);
    if (rwc) { out.capturePath = rwc[1]; continue; }
    if (/RAW TRACE NOT RETAINED/.test(l)) out.notes.push('rawlog-missing');
    const evf = /EVENTLOG-FILE\s+(\S+)/.exec(l);
    if (evf) { out.eventLogPath = evf[1]; continue; }
    // Venue-portability R3/R6, same two-stdout-line contract as the retention markers above: the
    // driver measures, this file only learns. A platform adopts these by printing them.
    const sl = /VENUE-STORE-LAYOUT\s+(isolated|hoisted)/.exec(l);
    if (sl) { out.storeLayout = sl[1]; continue; }
    // ⛔ `(.+)$` AND NOT `(\S+)`, AND ON WINDOWS THAT IS THE DIFFERENCE BETWEEN A PATH AND A LIE.
    // The stock Windows Node is `C:\Program Files\nodejs\node.exe`, so `(\S+)` records
    // `C:\Program` — a path that does not exist, silently, in the field whose entire job is to say
    // where the interpreter lives. `interpreterInsideHome` is then computed against that truncation
    // too. Caught by a test, before any Windows record carried it: this marker is new on that lane.
    // The trailing `.trim()` is load-bearing for the same platform, because a driver writing CRLF
    // leaves a `\r` that `(.+)$` would otherwise take as part of the path.
    const ip = /VENUE-INTERPRETER\s+(.+)$/.exec(l);
    if (ip) { out.interpreterPath = ip[1].trim(); continue; }
    const jr = /VENUE-JAIL-ROOT\s+(.+)$/.exec(l);
    if (jr) { out.jailRoot = jr[1].trim(); continue; }
    // R7. The driver asserts it; this only learns what was asserted, so a reader can check the
    // claim rather than trust that the assertion was present in whatever driver revision ran.
    const ou = /VENUE-OBSERVE-USER\s+(.+)$/.exec(l);
    if (ou) { out.observeUser = ou[1].trim(); continue; }
    // ⛔ WHETHER THE CI SCRUB REACHED THE TRACED CHILD, as opposed to having been performed on the
    // driver. The distinction is platform-shaped: macOS reaches the child through `sudo … env`, whose
    // env_reset builds a fresh environment, so an `unset` in the driver proves nothing about what the
    // script saw. Recorded rather than left in the log because a record claiming a CI normalisation
    // in `overrides` should also carry the evidence that it took effect.
    const cc = /VENUE-CI-CHILD\s+(.+)$/.exec(l);
    if (cc) {
      out.ciChild = cc[1].trim();
      if (/^LEAKED/.test(out.ciChild)) out.notes.push('ci-env-leaked-to-child');
      if (/SELF-CHECK FAILED/.test(l)) out.notes.push('ci-scrub-unverified');
      continue;
    }
    // The binary's content hash and detected features. Same two-stdout-line contract as the markers
    // above: the driver measures, this file only learns.
    const nb = /VENUE-NUB-BINARY\s+(\{.*)/.exec(l);
    if (nb) {
      try { out.nubBinary = JSON.parse(nb[1]); }
      catch { out.notes.push('nub-binary-unparsable'); }
      continue;
    }
    const ov = /VENUE-OVERRIDES\s+(\{.*)/.exec(l);
    if (ov) {
      try { out.overrides = JSON.parse(ov[1]); }
      catch { out.notes.push('overrides-unparsable'); }
      continue;
    }
    const wvp = /WRITEPATHS-VERSION-PINNED\s+(\[.*\])\s*$/.exec(l);
    if (wvp) {
      try { out.writePathsVersionPinned = JSON.parse(wvp[1]); }
      catch { out.notes.push('writepaths-pinned-unparsable'); }
      continue;
    }
    const evs = /EVENTLOG-STATS\s+(\{.*)/.exec(l);
    if (evs) {
      try { out.eventLog = JSON.parse(evs[1]); }
      catch { out.notes.push('eventlog-stats-unparsable'); }
      continue;
    }
    // A record that carries a verdict and no evidence is the state this whole mechanism exists to
    // end, so it is NOTED rather than left to be inferred from an absent file.
    if (/EVENTLOG NOT WRITTEN/.test(l)) out.notes.push('eventlog-missing');
    // The synthesized grant is printed on the line AFTER the banner. macOS restates it on its
    // `### DONE` line, which is the only place it survives an OBSERVE-ONLY run.
    if (/SYNTHESIZED GRANT/.test(l)) { synthesizedNext = true; continue; }
    if (synthesizedNext) {
      synthesizedNext = false;
      const g = firstObject(l);
      if (g) out.synthesized = g;
      continue;
    }
    if (/###\s+DONE\s.*\ssynthesized=/.test(l)) {
      out.synthesized ??= firstObject(l.slice(l.indexOf('synthesized=')));
    }
    if (/REPLAY SUSPECTED/.test(l)) out.notes.push('replay-suspected');
    // ⛔ THE GRANT WAS WIDENED BECAUSE A WRITE COULD NOT BE PLACED, not because the package needed
    // the width. A reader comparing this record against another platform's has to be able to see
    // that from the record alone; the `STALE` variant additionally says the wrong resolution was
    // PROVEN, not merely suspected. macOS-only today — the cause is posix_spawn addchdir_np.
    if (/CWD-UNOBSERVED/.test(l)) out.notes.push('cwd-unobserved');
    if (/Severity: STALE/.test(l)) out.notes.push('cwd-stale');
    // ⛔ WHICH WRITES THE GUARD COULD NOT PLACE, BY NAME. The grant covers them with `deps`+`project`
    // — a calibrated guess, not a measurement. If a macOS install ever breaks because one landed
    // somewhere else, the fix is a single catalog line, but only if the record says WHICH paths were
    // in doubt; otherwise the next person must re-measure to learn it and the run is long gone.
    const up = /CWD-UNPLACEABLE-WRITES\s+(\[.*\])\s*$/.exec(l);
    if (up) { try { out.cwdUnplaceableWrites = JSON.parse(up[1]); } catch { out.notes.push('cwd-unplaceable-unparsable'); } continue; }
    const cr = /CWD-RESOLVED\s+(\d+)/.exec(l);
    if (cr) { out.cwdResolved = Number(cr[1]); continue; }
    // ⛔ THE ARMS FOR THIS PACKAGE COULD NOT HAVE FAILED, so a green one is not evidence. Either the
    // package ships its build output prebuilt — making the artifact gate's manifest the tarball's own
    // file set, present in every arm before any script runs — or its script ends in a status swallow
    // (`|| true`, `|| (exit 0)`), so `rc` is 0 whatever happened. The GRANT may still be correct; what
    // is absent is a signal that could have gone red. Recorded because an unfalsifiable arm filed as a
    // clean MINIMAL is the shape that erodes trust in a whole corpus. See `arm-falsifiability.mjs`.
    if (/ARMS-UNFALSIFIABLE/.test(l)) out.notes.push('arms-unfalsifiable');
    // ⛔ EACH DRIVER SPELLS EVENT LOSS DIFFERENTLY, AND KEYING ON ONE SPELLING SILENTLY EXEMPTS THE
    // OTHERS. `events LOST` is the WINDOWS wording (`measure-windows.mjs`) and it is live there — so
    // this note was never dead, which is exactly what made the defect hard to see: it fired on the
    // one platform it was written against. macOS and Linux say it in their own words and were
    // therefore never noted at all. MEASURED: both darwin records dropped an event, `notes: []`.
    //
    //   windows  `!! N events LOST -- exact-set claims are not supported by this trace`
    //   macos    `⛔ THE TRACER DROPPED N EVENT(S).`  and  `⛔ LOSS LEDGER DISAGREES: …`
    //   linux    `⛔ N trace lines the decoder could not parse`
    //
    // A dropped event is a path never seen, which UNDER-predicts the grant — so this note is the
    // record's only warning that its own evidence is incomplete, and a note that fires on one venue
    // of three is worse than absent, because its silence reads as a clean trace. `out.notes` is
    // de-duplicated below, so a driver tripping two of these (macOS emits both) still yields one.
    if (/events LOST|THE TRACER DROPPED|LOSS LEDGER DISAGREES|trace lines the decoder could not parse/.test(l)) {
      out.notes.push('events-lost');
    }
    if (/INCONCLUSIVE for/.test(l)) out.notes.push('descent-inconclusive');
    if (/UNDER-PREDICTED/.test(l)) out.notes.push('under-predicted');
  }

  // ⛔ THE DRIVERS NARRATE THEIR WAY TO A VERDICT, so a later `=>` line is not automatically the
  // answer: a `=> VERIFIED` is followed by descent arms that print `=>` conclusions of their own,
  // and macOS's DIAGNOSE arm prints after that. A MINIMUM is therefore never downgraded once seen.
  for (const l of lines) {
    // ⛔ `=> VERIFIED <g>` (POSIX) and `=> MINIMUM <g> (observed, then verified)` (Windows) are the
    // SAME outcome under different words; `=> MINIMUM <g> (ladder fallback)` is a DIFFERENT one —
    // OBSERVE under-predicted and the ladder repaired it. Keying on the word MINIMUM alone would
    // merge the arm that proves synthesis works with the arm that proves it failed.
    const verified = /=>\s*VERIFIED\s/.test(l) || /=>\s*MINIMUM\s.*observed, then verified/.test(l);
    const ladder = /=>\s*MINIMUM\s.*ladder fallback/.test(l);
    if (verified || ladder) {
      out.verdict = 'MINIMUM';
      out.grant = firstObject(l) ?? {};
      out.verifiedBy = ladder ? 'ladder' : 'synth';
      continue;
    }
    // Linux prints one summary line naming every droppable capability; macOS prints one line PER
    // dropped capability, quoting the variant name. Both mean the synthesis over-predicted.
    if (/=>\s*OVER-PREDICTED by:/.test(l)) {
      out.minimality = 'OVER-PREDICTED';
      out.overPredictedBy = (/by:([^(]*)/.exec(l)?.[1] ?? '').trim().split(/\s+/).filter(Boolean);
      continue;
    }
    const narrowed = /OVER-PREDICTED\s+—.*'([^']+)'\s+was not needed/.exec(l);
    if (narrowed) {
      out.minimality = 'OVER-PREDICTED';
      out.overPredictedBy.push(narrowed[1]);
      continue;
    }
    if (/=>\s*MINIMAL\b/.test(l) || /grant is already empty/.test(l)) { out.minimality = 'MINIMAL'; continue; }
    if (/=>\s*DESCENT INCOMPLETE/.test(l)) { out.minimality = 'UNPROVEN'; continue; }
    if (out.verdict === 'MINIMUM') continue;
    // ⛔ A SUSPECT GRANT IS RETAINED BUT IS NOT A MEASUREMENT, AND THE RECORD HAS TO SAY BOTH.
    // The driver reaches this when every ladder arm exited 0 and fell short by the SAME files at every
    // grant up to `write:"disk"` — a shortfall invariant under widening, so not a capability gap. The
    // grant is kept because discarding it is the defect this verdict exists to fix (3 of 45 linux
    // records, one of them with a correct narrow grant already in hand), but `verifiedBy` stays null
    // and no `minimality` is claimed: the leave-one-out descent never ran. `collate.mjs` keeps the
    // verdict out of the catalog on exactly that basis.
    if (/=>\s*ARTIFACT-GATE-SUSPECT/.test(l)) {
      out.verdict = 'ARTIFACT-GATE-SUSPECT';
      out.grant = firstObject(l);
      out.notes.push('artifact-shortfall-grant-independent');
      continue;
    }
    // ⛔ macOS's `=> UNDER-PREDICTED` IS A REAL FINDING, NOT AN INSTRUMENT FAILURE — and it has no
    // grant, because no state the harness can express installed the package. It gets its own verdict
    // so the collator excludes it from the catalog (there is no measured minimum) while the queue
    // still closes the row: re-running it would produce the same answer, and `HARNESS-*` would put it
    // in an endless retry loop.
    //
    // ⛔ THE `=>` IS THE WHOLE DISCRIMINATOR, AND IT USED TO MEAN SOMETHING WEAKER. Before macOS had
    // a ladder, this line fired the moment the SYNTHESIZED grant failed — so a package the ladder
    // would have repaired was filed as having no minimum, and `collate.mjs` gave it no catalog entry,
    // dropping it to the base profile at install time. `measure-macos.sh` now emits the bare
    // `!! OBSERVE UNDER-PREDICTED` for that intermediate state, which lands in `notes` here exactly
    // as the Linux and Windows spellings do, and reserves the `=>` form for "every rung up to
    // write:\"disk\" failed". All three drivers therefore now mean the same thing by it.
    if (/=>\s*UNDER-PREDICTED/.test(l)) { out.verdict = 'UNDER-PREDICTED'; continue; }
    for (const [v, re] of Object.entries(VERDICTS)) {
      if (re.test(l)) { out.verdict = v; break; }
    }
  }

  // `OBSERVE-ONLY` carries a grant on its own line and is NOT a measurement — the driver says so
  // itself ("this is a HYPOTHESIS"). Recording the hypothesis as `synthesized` and leaving `grant`
  // null is what stops the collator treating it as one.
  if (out.verdict === 'OBSERVE-ONLY' && !out.synthesized) {
    const l = lines.find((x) => /=>\s*OBSERVE-ONLY/.test(x));
    if (l) out.synthesized = firstObject(l);
  }
  out.notes = [...new Set(out.notes)];
  out.overPredictedBy = [...new Set(out.overPredictedBy)];
  applyGrantSourceRule(out, lines);
  return out;
}

// ⛔ WHICH VALUE THE CATALOG GETS, AND WHY IT IS NOT SIMPLY "THE NARROWEST ONE".
//
// `collate.mjs` keys on `grant`, and `grant` was the SYNTHESIZED value — so on every over-predicting
// record the descent's narrower, jail-VERIFIED minimum was computed and then thrown away. That
// contradicts the point of the catalog (grant the narrowest set that still installs), systematically
// and on every platform.
//
// The reason it was not simply changed to "always take the descended value" is a real tension: the
// descended value is narrower and therefore better, but it rests on ARMS PASSING — and an arm can
// pass for the wrong reason. The synthesized value is wider and dumber but cannot be flattered. So
// the rule uses the falsifiability instrument as its gate:
//
//   grant = the DESCENDED minimum when the arms that justified it COULD have failed,
//           the SYNTHESIZED value otherwise.
//
// ⛔⛔ AND A SECOND GUARD THE OBVIOUS IMPLEMENTATION GETS WRONG: THE DESCENT IS LEAVE-ONE-OUT, SO
// DROPPING TWO CAPABILITIES AT ONCE WAS NEVER MEASURED. `measure.sh:824` says so in its own summary —
// "each named capability drops on its own". Each of N over-predicted capabilities has an arm proving
// IT is droppable individually; nothing proves they are jointly droppable, and the joint grant is
// strictly narrower than any arm that ran. Narrowing to it would be an INFERENCE presented as a
// measurement, in the under-grant direction. With N >= 2 the record therefore keeps the synthesized
// value unless the driver ran an explicit JOINT-NARROW arm — and either way it says which.
const applyGrantSourceRule = (out, lines) => {
  if (out.verdict !== 'MINIMUM' || !out.grant) return;
  const n = out.overPredictedBy.length;
  // ⛔ ABSENCE OF THE FLAG IS NOT EVIDENCE OF FALSIFIABILITY — it is usually evidence the CHECK NEVER
  // RAN. Every record taken before `arm-falsifiability.mjs` existed has no flag and no check, and
  // treating those as falsifiable would retroactively narrow the whole existing corpus on the
  // strength of a test that was never performed. Same distinction as an absent vs a null root, and
  // the same direction of harm. The detector prints an `ARM-FALSIFIABILITY` line unconditionally, so
  // that line — not the absence of the flag — is what says the question was asked.
  const checked = lines.some((l) => /ARM-FALSIFIABILITY\s/.test(l));
  const unfalsifiable = out.notes.includes('arms-unfalsifiable');
  // The synthesized grant minus every capability an arm proved droppable. Keyed on the driver's own
  // variant names, so this cannot drift from what was actually run.
  //
  // ⛔⛔ AN UNRECOGNISED NAME IS A FAILED RECOMPUTATION, AND IT USED TO BE INVISIBLE. This loop
  // silently ignored any name it could not match, so a driver spelling its variants differently
  // produced a `descended` grant IDENTICAL to the synthesized one — and the record then published
  // `grantSource: "descended"` beside the un-narrowed value, claiming a narrowing that never
  // happened. MEASURED: `measure.sh` emitted the bare `network` / `write.deps` for the whole life of
  // the Linux descent, so `descendedGrant === grant` in every linux-x64 record that over-predicted.
  //
  // The driver-side spelling is now `no-*` on all three platforms, which is the fix. This guard is
  // why the same defect cannot recur silently in a fourth: a name nobody can parse forces the wider
  // synthesized grant and SAYS SO, instead of dressing a no-op as a measurement. Deliberately NOT a
  // second vocabulary — the legacy Linux spelling is not accepted here, because accepting it is what
  // would let the two sides drift apart again.
  const descended = JSON.parse(JSON.stringify(out.grant));
  const unparsedNames = [];
  for (const name of out.overPredictedBy) {
    if (name === 'no-network') { delete descended.network; continue; }
    // `read` is a SCOPE, not a map of scopes, so the whole key goes — there is no `no-read-<scope>`
    // to mirror `no-write-<scope>`, and inventing one would be a second vocabulary of exactly the
    // kind the guard above exists to prevent. This case is what lets ladder rung 1 narrow at all:
    // that rung carries `read:"disk"`, and without a parse for the drop the record kept the WIDE
    // grant and recorded `descent-name-unparsed`. Safe by construction — the descent only ever
    // keeps a drop whose arm VERIFIED, so a dropped `read` is one the install provably did not need.
    if (name === 'no-read') { delete descended.read; continue; }
    const w = /^no-write-(.+)$/.exec(name);
    if (w) {
      if (descended.write) {
        delete descended.write[w[1]];
        if (!Object.keys(descended.write).length) delete descended.write;
      }
      continue;
    }
    unparsedNames.push(name);
  }
  const jointVerified = lines.some((l) => /JOINT-NARROW\s+VERIFIED/.test(l));
  out.descendedGrant = descended;

  let source, reason;
  if (n === 0) {
    source = 'synthesized'; reason = 'no capability was droppable — synthesized IS the minimum';
  } else if (unparsedNames.length) {
    // ⛔ TESTED BEFORE EVERY NARROWING BRANCH, because this is an INSTRUMENT failure and the branches
    // below would otherwise publish its no-op as a result. Deliberately louder than the other
    // `synthesized` outcomes: those are honest measurements of an uncertain package, this one says
    // the harness and the recorder disagree about their own vocabulary and the record cannot be
    // computed. The wide grant is the safe direction, so a record is still produced — but it must not
    // read as `descended`.
    source = 'synthesized';
    reason = `the descent named ${unparsedNames.length} capabilit${unparsedNames.length === 1 ? 'y' : 'ies'} `
      + `this recorder cannot parse (${unparsedNames.join(', ')}) — the descended grant could not be `
      + 'recomputed, so the wider synthesized value is kept rather than a narrowing that was never applied';
    out.notes.push('descent-name-unparsed');
  } else if (unfalsifiable) {
    // Tested BEFORE `!checked`: the flag is itself positive evidence the check ran, so a log
    // carrying the flag must never be mistaken for one that predates the detector.
    source = 'synthesized';
    reason = 'the descent narrowed, but this package\'s arms could not have failed '
      + '(arms-unfalsifiable), so a passing narrow arm is not evidence — keeping the wider grant';
  } else if (!checked) {
    source = 'synthesized';
    reason = 'the descent narrowed, but this record predates the falsifiability check — no '
      + 'ARM-FALSIFIABILITY line, so whether a passing arm is evidence was never established';
  } else if (n === 1) {
    source = 'descended';
    reason = `one capability (${out.overPredictedBy[0]}) was dropped and the resulting grant was `
      + 'verified in the real jail by a single arm';
  } else if (jointVerified) {
    source = 'descended';
    reason = `${n} capabilities were dropped and the JOINT grant was explicitly verified`;
  } else {
    source = 'synthesized';
    reason = `${n} capabilities each drop on their own, but the descent is leave-one-out and the `
      + 'JOINT drop was never run — narrowing to it would be an inference, not a measurement';
  }
  out.grantSource = source;
  out.grantSourceReason = reason;
  if (source === 'descended') out.grant = descended;
};

// ── CLI ───────────────────────────────────────────────────────────────────────
//
// ⛔⛔ `pathToFileURL`, NEVER `file://${process.argv[1]}` — AND THIS FILE IS WHERE THAT MISTAKE COSTS
// A WHOLE PLATFORM'S CORPUS. On Windows `process.argv[1]` is `D:\a\repo\harness\v2\record.mjs`
// while `import.meta.url` is `file:///D:/a/repo/harness/v2/record.mjs`: backslashes, and one slash
// versus three. The string form therefore NEVER matches on Windows, so everything below is skipped,
// the process prints nothing and EXITS 0.
//
// ⛔ AND THE CALLER CANNOT TELL. `run-batch-v2.mjs` checks `if (w.status !== 0)` and moves on, so a
// Windows batch would mark every row measured while writing no `results.json` at all — a silent
// total loss with a green log. `records-v2/runs/` holding `darwin-arm64` and `linux-x64` and no
// `win32-x64` is consistent with exactly this.
//
// `adapters/windows-retain.mjs` already carries this scar and its fix; `adapters/linux.mjs` uses the
// string form and is correct there and only there, because it never runs anywhere else.
// ⛔ `process.argv[1] &&` GUARDS THE IMPORT CASE, and it is not defensive padding.
// `pathToFileURL(undefined)` THROWS, so without it merely IMPORTING this module from a context
// with no `argv[1]` — `node -e`, a REPL, an embedder — dies before any caller runs. The naive
// string form this replaced was wrong on Windows but TOTAL: it just returned false. Swapping in a
// correct comparison therefore introduced a new failure mode, which is worth stating because the
// tests did not catch it: `node --test` always supplies `argv[1]`.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const log = fs.readFileSync(opt('--log'), 'utf8');
  const pkg = opt('--pkg');
  const version = opt('--version');
  const rc = Number(opt('--rc', '0'));
  const parsed = parseDriverLog(log);

  // ⛔ WHAT MACHINE, IN WHAT STATE (VENUE-PORTABILITY R3 + R6). Before this, two records produced on
  // different venues were INDISTINGUISHABLE in the record, so a divergence between them could not be
  // attributed without going back to the run — and the runs are ephemeral.
  //
  // ⛔ `ciEnvSet` AND `storeLayout` ARE SEPARATE FIELDS AND NEITHER IMPLIES THE OTHER. `is_ci()` is
  // `env::var_os("CI").is_some()` and `install_report.rs` returns the isolated layout when it is set,
  // so CI genuinely measures a DIFFERENT store layout. That difference is real and must be PRESERVED,
  // not normalised away; recording it is what turns a confound into a covered axis. Where the two
  // states disagree the catalog takes the UNION, because over-granting is safe and under-granting
  // breaks installs.
  //
  // ⛔ `storeLayout` IS OBSERVED, NOT INFERRED FROM `CI`. Deriving it from the env var would encode
  // the very rule this field exists to let us check, and would then agree with itself forever. The
  // driver reports what the arm tree actually contained; absent that, `null` — never a guess.
  // (MEASURED, and the reason this matters: a `CI`-unset install on the VM still produced a
  // `node_modules/.store`, so the "CI implies isolated" rule is not a biconditional.)
  // ⛔ CONTAINMENT IS PER-PLATFORM, AND THE POSIX-ONLY TEST WAS SILENTLY WRONG ON WINDOWS FOR EVERY
  // RECORD. The old form was `interpreterPath.startsWith(`${home}/`)` — a FORWARD slash, and a
  // case-SENSITIVE compare. On win32 the separator is `\` and the filesystem is case-insensitive, so
  // that expression is unsatisfiable there: `interpreterInsideHome` has been `false` on every win32
  // record regardless of where Node actually lives. `false` is a claim, not an absence, so nothing
  // downstream could tell it apart from a genuine measurement — which is exactly the failure R3
  // exists to prevent, arriving through the field meant to prevent it.
  //
  // The two POSIX-visible differences are both real: Windows folds case (`C:\Users\NUB` and
  // `c:\users\nub` are one directory) and separates with `\`. Both are normalised before comparing,
  // and the boundary check stays a SEPARATOR-terminated prefix on every platform so `/home/nubbins`
  // is never read as being inside `/home/nub`.
  const insideHome = (child, home, platform) => {
    if (!child || !home) return null;
    const win = platform.startsWith('win32');
    const fold = (s) => (win ? s.replace(/\//g, '\\').toLowerCase() : s).replace(/[\\/]+$/, '');
    const sep = win ? '\\' : '/';
    const c = fold(child), h = fold(home);
    return c === h || c.startsWith(h + sep);
  };

  // ⛔ AN UNDECLARED VENUE IS `unknown`, NEVER A PLAUSIBLE GUESS. This defaulted to `local`, so a run
  // on the corpus VM with `NUB_CORPUS_VENUE` unset recorded `venue: "local"` — a wrong value that
  // reads exactly like a right one. That is the same shape as every other "absent is not empty"
  // defect this harness has hit (the manifest, the falsifiability flag, the temp roots), and it is
  // worse in one way: venue is PROVENANCE, so a wrong value poisons the ability to re-examine the
  // record later rather than merely the current answer. `unknown` is non-breaking for consumers and
  // makes the gap visible IN THE DATA.
  //
  // ⛔ AND IT IS NEVER INFERRED — not from `CI`, not from the hostname, not from the interpreter
  // path. A cloud VM and a laptop are not distinguishable from inside; an inferred venue is a guess
  // wearing a fact's clothing, and the entire value of the field is that it is ASSERTED by whoever
  // knows. `GITHUB_ACTIONS` is the one exception and is not an inference: the runner sets it itself.
  const resolveVenue = (env) => {
    if (env.GITHUB_ACTIONS) return 'ci';
    const declared = env.NUB_CORPUS_VENUE;
    if (declared) return declared;
    // Loud, once per record, naming the variable and the value being written. An operator who sees
    // this once fixes it forever; a silent default is what let a mislabelled record exist at all.
    console.error('⛔ NUB_CORPUS_VENUE is not set, so this record is being written with '
      + 'venue: "unknown". Set NUB_CORPUS_VENUE=vm|local|ci to say where these arms actually ran — '
      + 'a venue comparison cannot attribute a difference between two records that both say unknown.');
    return 'unknown';
  };

  const venueProvenance = (p, platform) => {
    const env = process.env;
    const home = env.HOME ?? env.USERPROFILE ?? '';
    const interpreterPath = p.interpreterPath ?? null;
    return {
      venue: resolveVenue(env),
      ciEnvSet: env.CI !== undefined,
      storeLayout: p.storeLayout ?? null,
      interpreterPath,
      interpreterInsideHome: insideHome(interpreterPath, home, platform),
      // R3, and the reason is in `parseDriverLog`: a Windows jail root under `C:\Users\<user>` fails
      // to build a token at all, so a record has to name where its arms ran or a venue comparison
      // will read an environment failure as a capability finding.
      jailRoot: p.jailRoot ?? null,
      // R7. Null means the driver did not assert it — which is itself the finding, not a pass.
      observeUser: p.observeUser ?? null,
      // Whether the CI scrub reached the traced CHILD. Null means the driver never checked, which is
      // distinct from "clean" and must not be read as one.
      ciChild: p.ciChild ?? null,
      // The cwd guard's own accounting: how many relative paths were PLACED against the package dir
      // and confirmed by an artifact, and which writes remain unplaceable. Null means the driver did
      // not report — distinct from zero, and must not be read as "none".
      cwdResolved: p.cwdResolved ?? null,
      cwdUnplaceableWrites: p.cwdUnplaceableWrites ?? null,
      // ⛔ WHICH BINARY, WHICH `nubGitSha` PROVABLY CANNOT ANSWER. Two binaries from the SAME commit
      // behave differently when their feature sets differ. MEASURED 2026-08-06: a `--release` build
      // of the right commit, missing only `build-jail-catalog-override`, VOIDed four measurement
      // cells while reporting a `nubGitSha` identical to the working binary's. The content hash is
      // also the only identity that survives a SHARED MUTABLE binary path — lanes on one box can
      // swap the artifact mid-batch, and the hash is what distinguishes a batch measured against one
      // binary from a batch measured against two.
      nubBinary: p.nubBinary ?? null,
      // R6. Normalisation that is RECORDED is a covered axis; normalisation that is invisible is a
      // silent bet that it did not matter. The driver names each variable it set, unset or
      // redirected, so a reader can tell whether `CI` was touched — the one override that would
      // invalidate the whole acceptance test — without trusting that it was not.
      overrides: p.overrides ?? null,
    };
  };

  // ⛔ NO TERMINAL LINE IS NOT AN EMPTY GRANT. A driver killed by a deadline, or dying before it
  // reaches a `=>`, must land in the `HARNESS-*` bucket so the queue reopens the row rather than
  // recording an absence as a result.
  if (!parsed.verdict) parsed.verdict = rc === 124 || rc === 137 ? 'HARNESS-TIMEOUT' : 'HARNESS-ERROR';

  // ⛔ AND THE `!parsed.verdict` GUARD ABOVE IS EXACTLY WHY A TIMEOUT CAN STILL LAND AS `MINIMUM`.
  // The driver prints its `=> MINIMUM` the moment the SYNTH arm verifies, then descends. A budget
  // kill during the descent therefore arrives with a verdict ALREADY parsed, the `rc === 124` branch
  // never runs, and a truncated run is recorded as a completed measurement.
  //
  // MEASURED on `duckdb@1.4.4`: `driverRc: 124`, `durationMs: 2400105` (the budget, exactly),
  // killed with its cwd in `verify-drop-no-network` — recorded `verdict: "MINIMUM"`,
  // `minimality: null`. The grant is SAFE, because a cut-off descent narrows nothing and leaves the
  // synthesized grant standing, so this is a false claim of COMPLETENESS rather than an under-grant.
  // But `minimality: null` was the only tell, and it is equally produced by a package that simply
  // has no descent to run — so nothing downstream could distinguish them.
  //
  // The note is additive on purpose. Downgrading the verdict would drop the package from the catalog
  // (`collate.mjs` keeps only `MINIMUM`) and discard a grant its synth arm really did verify — the
  // same trade `ARTIFACT-GATE-SUSPECT` already settled the other way, for the same reason.
  if (rc === 124 || rc === 137) {
    parsed.notes = [...new Set([...(parsed.notes ?? []), 'driver-timeout'])];
  }

  // ⛔ RESOLVED ONCE, ABOVE THE RECORD, BECAUSE `interpreterInsideHome` NEEDS IT. Reading it out of
  // `rec.provenance` while `rec` is still being built would evaluate to `undefined`, and the
  // containment test would then silently take its POSIX branch on Windows — the same class of
  // silent-wrong-answer the test itself was written to end.
  const platform = opt('--platform', `${process.platform}-${process.arch}`);

  const rec = {
    pkg,
    version,
    // ⛔ THE RECORD SAYS WHICH HARNESS PRODUCED IT, IN ADDITION TO LIVING UNDER ITS OWN ROOT. The
    // root is the structural guarantee that v2 can never overwrite v1; this field is what survives a
    // record being copied, collated or reported out of that tree, where the path is gone.
    harnessVersion: 2,
    verdict: parsed.verdict,
    grant: parsed.grant,
    synthesized: parsed.synthesized ?? null,
    verifiedBy: parsed.verifiedBy,
    minimality: parsed.minimality,
    overPredictedBy: parsed.overPredictedBy,
    // ⛔ MIRRORED OUT OF THE GRANT, NOT PARSED SEPARATELY, AND KEPT IN BOTH PLACES ON PURPOSE.
    // `writePaths` travels INSIDE the grant so the VERIFY arm actually builds a catalog carrying it
    // and exercises nub's mover — a field the driver never puts in a catalog is a field no arm ever
    // tests. But `collate.mjs` reads it from the RECORD's top level (`grantKey`, the `folded` union,
    // and the `byVersion` fold all key on `r.writePaths`), which is the v1 shape. Mirroring is what
    // lets an emitting v2 driver reach the existing collator with no change there; deriving it
    // separately would give two values that can disagree.
    writePaths: parsed.grant?.writePaths ?? [],
    writePathsVersionPinned: parsed.writePathsVersionPinned ?? [],
    // ⛔ WHICH VALUE `grant` ABOVE IS, AND WHY. `rec` is an explicit whitelist, so the first version
    // of the grant-source rule narrowed `grant` correctly and then dropped every field explaining it
    // — a record whose grant had been narrowed with nothing saying on what basis, which is the exact
    // silent-narrowing shape the rule exists to prevent. The parse-level tests all passed; only an
    // end-to-end run of this CLI shows it, which is why one now exists.
    grantSource: parsed.grantSource ?? null,
    grantSourceReason: parsed.grantSourceReason ?? null,
    descendedGrant: parsed.descendedGrant ?? null,
    notes: [...new Set(parsed.notes)],
    // The event log's own census, inlined so `results.json` states how much evidence sits beside
    // it — event count, dropped-event count, the errno histogram — without opening the log.
    eventLog: parsed.eventLog,
    driverRc: rc,
    durationMs: Number(opt('--duration-ms', '0')) || null,
    provenance: {
      platform,
      harness: opt('--driver', ''),
      nubGitSha: opt('--nub-sha', '') || null,
      nubVersion: opt('--nub-version', '') || null,
      corpusGitSha: opt('--corpus-sha', '') || null,
      node: process.version,
      at: new Date().toISOString(),
      ...venueProvenance(parsed, platform),
    },
  };

  const dir = path.join(opt('--out'), rec.provenance.platform, pkg.replace(/\//g, '+'), version);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  // ⛔ `driver.out`, NOT `driver.log`. The repo's `.gitignore` carries a bare `*.log`, so the v1
  // corpus tracks results.json ALONE — every per-cell log it writes is silently dropped, and a
  // `.log` here would vanish the same way while looking committed on the runner's disk. MEASURED:
  // `git ls-files records | grep -c '\.log$'` is 0 against 6,750 records.
  //
  // Keeping the log is a deliberate trade, not an oversight. A v2 verdict summarises a multi-arm run
  // — synthesis, a verify arm, one descent arm per capability — so without it a surprising grant can
  // only be re-measured, never re-read, and "WHAT did the script touch" is the exact question v1
  // could never answer. Cost, sized from the captured fixtures: ~5 KB per record, ~35 MB across a
  // full three-platform corpus.
  fs.writeFileSync(path.join(dir, 'driver.out'), log);

  // ⛔ THE EVENT LOG IS COPIED INTO THE RECORD DIR, WHICH IS THE ONLY THING THE PUBLISHER COPIES.
  // `publish-record-v2.sh` does `cp -R "$REC_DIR/."` and stages the paths in its manifest — so a
  // file left in the driver's `mktemp -d` fixture root is not "somewhere else", it is GONE the
  // moment the runner ends. This copy is the whole difference between retention and a log message.
  //
  // ⛔ `events.ndjson.gz`, NOT `events.log`. The repo's `.gitignore` carries a bare `*.log`, so a
  // file named that vanishes at `git add` while looking perfectly present on the runner's disk —
  // measured on the v1 corpus, where `git ls-files records | grep -c '\.log$'` is 0 against 6,750
  // records. `driver.out` carries the same scar for the same reason.
  //
  // Gzipped rather than plain: the checkout cost is what bounds how long retention stays
  // affordable, and `gzcat`/`zgrep` keep the corpus-wide query the maintainer asked for ("what do
  // all the outside-writes look like?") a one-liner. Reversible — the driver writes both.
  //
  // ⛔ ORDER IS DELIBERATE: THE RAW TRACE AND ITS CAPTURE HEADER GO FIRST. They are the ARCHIVE —
  // the normalized `events.ndjson.gz` is a derived cache that can be rebuilt from them. If disk,
  // a size cap, or a publish policy ever forces one of the three out, the two that must survive are
  // `trace.txt.gz` and `capture.json`; the third is a re-parse away. Copying them first is what
  // makes that ordering true in practice rather than only in a comment.
  const copies = [
    [parsed.rawLogPath, 'trace.txt.gz', 'rawlog-copy-failed'],
    [parsed.capturePath, 'capture.json', 'capture-copy-failed'],
    [parsed.eventLogPath, 'events.ndjson.gz', 'eventlog-copy-failed'],
  ];
  let copyFailed = false;
  for (const [src, name, note] of copies) {
    if (!src) continue;
    try {
      fs.copyFileSync(src, path.join(dir, name));
    } catch (e) {
      // Loud, and recorded: retention is additive, so a copy failure must not cost a measured
      // package — but a record that silently lost its evidence is the state being fixed.
      rec.notes = [...new Set([...rec.notes, note])];
      copyFailed = true;
      console.error(`record.mjs: WARN could not copy ${src}: ${e.message}`);
    }
  }
  if (copyFailed) fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  console.log(dir);
}
