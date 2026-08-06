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
  };

  let synthesizedNext = false;
  for (const l of lines) {
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
    if (/events LOST/.test(l)) out.notes.push('events-lost');
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
    // ⛔ macOS's `=> UNDER-PREDICTED` IS A REAL FINDING, NOT AN INSTRUMENT FAILURE — and it has no
    // grant, because that driver has no ladder to repair one with. It gets its own verdict so the
    // collator excludes it from the catalog (there is no measured minimum) while the queue still
    // closes the row: re-running it would produce the same answer, and `HARNESS-*` would put it in
    // an endless retry loop. The Linux/Windows spelling of the same event carries no `=>` — it
    // annotates a ladder MINIMUM — so it lands in `notes` there instead.
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
  return out;
}

// ── CLI ───────────────────────────────────────────────────────────────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const log = fs.readFileSync(opt('--log'), 'utf8');
  const pkg = opt('--pkg');
  const version = opt('--version');
  const rc = Number(opt('--rc', '0'));
  const parsed = parseDriverLog(log);

  // ⛔ NO TERMINAL LINE IS NOT AN EMPTY GRANT. A driver killed by a deadline, or dying before it
  // reaches a `=>`, must land in the `HARNESS-*` bucket so the queue reopens the row rather than
  // recording an absence as a result.
  if (!parsed.verdict) parsed.verdict = rc === 124 || rc === 137 ? 'HARNESS-TIMEOUT' : 'HARNESS-ERROR';

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
    notes: [...new Set(parsed.notes)],
    driverRc: rc,
    durationMs: Number(opt('--duration-ms', '0')) || null,
    provenance: {
      platform: opt('--platform', `${process.platform}-${process.arch}`),
      harness: opt('--driver', ''),
      nubGitSha: opt('--nub-sha', '') || null,
      nubVersion: opt('--nub-version', '') || null,
      corpusGitSha: opt('--corpus-sha', '') || null,
      node: process.version,
      at: new Date().toISOString(),
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
  console.log(dir);
}
