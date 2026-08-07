// Decide whether a measure step that exited 0 actually MEASURED anything, and fail loudly when it
// did not.
//
// ⛔ WHY THIS EXISTS, AND IT IS WORSE THAN THE BUG IT WAS FOUND BESIDE. `corpus-v2-runner.yml` ends
// its measure step with `|| echo "run-batch-v2 exited non-zero — the gate below decides ..."`, which
// is deliberate: a batch that measured SOME packages and then died must still reach the commit step,
// or the whole slice is lost with the ephemeral runner. But the same `||` swallows the case where the
// batch measured NOTHING. MEASURED, run 31145732202 (the first Windows run ever dispatched): the
// falsification control refused to start the batch, `run-batch-v2.mjs` exited non-zero after 58
// seconds for a claimed slice of 10 packages, and the step's conclusion was `success`. The only
// reason anyone noticed is that a LATER step happened to crash on an unrelated defect.
//
// So the gate is not "did the batch exit 0" — that question is already answered and deliberately
// ignored. It is "did a non-empty slice produce nothing at all", which is the one outcome that can
// never be a legitimate measurement.
//
// ⛔ A PARTIAL SLICE IS A PASS, AND THAT IS THE POINT RATHER THAN A CONCESSION. "Fail when zero
// records were produced" is satisfiable by failing always, so the partial case is what gives the
// gate teeth in both directions: a batch that recorded 3 of 10 and then hit the job deadline has
// three real measurements that must be committed, and this must not take them down.
//
// ⛔ `skipped` COUNTS TOWARDS "SOMETHING HAPPENED". A resume run over rows whose records already
// exist legitimately records nothing new — every row is answered, `recorded` is 0, and failing that
// would break every re-run of an already-measured slice.

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/** The line `run-batch-v2.mjs` prints once, last, after its loop. Its ABSENCE is itself a finding:
 *  the batch died before or during the loop, which is exactly the shape run 31145732202 had. */
const SUMMARY = /^v2 batch: (\d+) attempted, (\d+) recorded, (\d+) skipped\b/;
const DEADLINE = /^DEADLINE: stopped before (\d+) package\(s\)/;

/**
 * @param {{requested:number, log:string, batchRc:number}} input
 * @returns {{ok:boolean, reason:string, summary:object|null}}
 */
export function judgeSlice({ requested, log, batchRc }) {
  // Nothing was claimed, so there is nothing to have measured. The workflow guards this with
  // `DRAINED`, but a gate that only works when its caller is correct is not a gate.
  if (requested === 0) {
    return { ok: true, reason: 'the slice was empty — nothing was claimed, so nothing is owed', summary: null };
  }

  // The LAST match, not the first: a log can carry an earlier summary from a nested or retried
  // invocation, and the run that decides the slice is the one that finished last.
  let summary = null;
  let deadlineStopped = 0;
  for (const line of String(log).split('\n')) {
    const m = SUMMARY.exec(line.trim());
    if (m) summary = { attempted: +m[1], recorded: +m[2], skipped: +m[3] };
    const d = DEADLINE.exec(line.trim());
    if (d) deadlineStopped = +d[1];
  }

  if (!summary) {
    return {
      ok: false,
      summary: null,
      reason: `the batch printed no summary line, so it died before finishing its loop over the `
        + `${requested}-package slice (rc=${batchRc}). Nothing was measured. Read the measure step's `
        + 'log above: a refusal from the falsification control, a missing worklist, or a crash in '
        + 'argument parsing all land here.',
    };
  }

  summary.deadlineStopped = deadlineStopped;
  const settled = summary.recorded + summary.skipped;
  if (settled === 0) {
    return {
      ok: false,
      summary,
      reason: `${requested} row(s) were claimed and NOTHING was settled — ${summary.attempted} `
        + `attempted, 0 recorded, 0 skipped (rc=${batchRc})`
        + (deadlineStopped ? `, with ${deadlineStopped} package(s) cut off by the job deadline` : '')
        + '. A slice that measures nothing must not report success: the rows stay claimed and are '
        + 'reclaimed by `--reclaim-stale`, which is the correct outcome, but only if this run says so.',
    };
  }

  return {
    ok: true,
    summary,
    reason: `${summary.recorded} recorded, ${summary.skipped} already-measured, of ${requested} `
      + `claimed (rc=${batchRc})`
      + (deadlineStopped ? `; ${deadlineStopped} cut off by the job deadline` : '')
      + (summary.recorded < requested - summary.skipped
        ? ' — a PARTIAL slice, which still commits what it measured' : ''),
  };
}

/** Non-empty, non-blank lines: the same shape `run-batch-v2.mjs` derives its `specs` from, so the
 *  two cannot disagree about how many packages the slice held. */
export const countSpecs = (text) => String(text).split('\n').map((s) => s.trim()).filter(Boolean).length;

// ⛔ `pathToFileURL`, NEVER `file://${process.argv[1]}` — on Windows the string form never matches,
// so the whole CLI is skipped and the process EXITS 0, which every caller reads as success. That is
// precisely the failure this file exists to catch, so getting it wrong here would be self-defeating.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const logPath = opt('--log', '');
  const slicePath = opt('--slice', '');
  const batchRc = Number(opt('--rc', '0'));

  const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
  // ⛔ AN UNREADABLE WORKLIST IS NOT AN EMPTY ONE. Defaulting `requested` to 0 would make this gate
  // pass on the very Windows path-resolution defect that produced the run it was written for.
  if (!slicePath || !fs.existsSync(slicePath)) {
    console.error(`⛔ MEASURE GATE: cannot read the worklist at ${slicePath || '<no --slice given>'} `
      + '— so it cannot be established that anything was measured.');
    process.exit(1);
  }
  const requested = countSpecs(read(slicePath));
  const verdict = judgeSlice({ requested, log: read(logPath), batchRc });

  if (!verdict.ok) {
    console.error(`⛔ THE MEASURE STEP MEASURED NOTHING: ${verdict.reason}`);
    console.error(`   worklist: ${path.resolve(slicePath)}`);
    process.exit(1);
  }
  console.log(`measure gate: ${verdict.reason}`);
}
