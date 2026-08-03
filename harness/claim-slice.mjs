// Claim a slice of PENDING queue rows for this run, or release/complete a claimed one.
//
// ⛔ THE CLAIM IS ONLY REAL ONCE THE COMMIT LANDS. This rewrites `queue.ndjson` in place; the
// WORKFLOW commits it together with the results it produced. A run that dies mid-slice therefore
// leaves its rows `claimed` with its own run id — visible, attributable, and recoverable by
// `--reclaim-stale` — rather than silently lost or, worse, silently re-run by the next slice while
// the first is still writing.
//
// Modes:
//   --claim <n> --os <os> --run <id>   mark up to n pending rows for <os> as claimed, print them
//   --complete <file> --run <id>       mark this run's claimed rows done, from an NDJSON verdict list
//   --reclaim-stale <minutes>          return rows claimed longer ago than that to pending
//   --status                           counts by status and os
//
// ONE OS PER SLICE, deliberately: a runner is a single operating system, so a mixed slice could
// never be completed by the job that claimed it.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const QUEUE = opt('--queue', path.join(here, '..', 'queue.ndjson'));

const read = () => fs.readFileSync(QUEUE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
// Written back in the SAME ORDER read. Re-sorting would make every commit a whole-file rewrite and
// destroy the diff that shows what one slice actually changed.
const write = (rows) => fs.writeFileSync(QUEUE, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);

const key = (r) => `${r.pkg}@${r.version}\t${r.os}`;

if (argv.includes('--status')) {
  const rows = read();
  const by = {};
  for (const r of rows) {
    by[r.os] ??= {};
    by[r.os][r.status] = (by[r.os][r.status] || 0) + 1;
  }
  const total = rows.length;
  const done = rows.filter((r) => r.status === 'done').length;
  console.log(`queue: ${done}/${total} done (${Math.round((done / total) * 100)}%)`);
  for (const [os, s] of Object.entries(by)) {
    console.log(`  ${os.padEnd(8)} ${Object.entries(s).map(([k, v]) => `${k}=${v}`).join('  ')}`);
  }
  process.exit(0);
}

if (argv.includes('--reclaim-stale')) {
  const minutes = Number(opt('--reclaim-stale', '120'));
  const cutoff = Date.now() - minutes * 60_000;
  const rows = read();
  let n = 0;
  for (const r of rows) {
    // A claim with no timestamp is from a run that died before writing one — reclaim it too, rather
    // than leaving a row that can never age out.
    if (r.status === 'claimed' && (!r.at || Date.parse(r.at) < cutoff)) {
      r.status = 'pending';
      delete r.run;
      delete r.at;
      n++;
    }
  }
  write(rows);
  console.error(`reclaimed ${n} row(s) claimed longer than ${minutes}min ago`);
  process.exit(0);
}

if (argv.includes('--complete')) {
  const runId = opt('--run', '');
  const verdictFile = opt('--complete', '');
  if (!runId) { console.error('--complete needs --run <id>'); process.exit(2); }
  // Verdicts keyed by pkg@version: what the harness actually recorded. A row this run claimed but
  // did not report stays CLAIMED — it is not done, and pretending otherwise would drop it from the
  // corpus while the queue reported full coverage.
  const verdicts = new Map();
  if (verdictFile && fs.existsSync(verdictFile)) {
    for (const line of fs.readFileSync(verdictFile, 'utf8').split('\n').filter(Boolean)) {
      try {
        const v = JSON.parse(line);
        if (v.pkg && v.version) verdicts.set(`${v.pkg}@${v.version}`, v.verdict ?? null);
      } catch { /* a malformed line must not lose the whole slice */ }
    }
  }
  const rows = read();
  let done = 0; let stranded = 0;
  for (const r of rows) {
    if (r.status !== 'claimed' || r.run !== runId) continue;
    const v = verdicts.get(`${r.pkg}@${r.version}`);
    if (v === undefined) { stranded++; continue; }
    r.status = 'done';
    r.verdict = v;
    delete r.run;
    delete r.at;
    done++;
  }
  write(rows);
  console.error(`completed ${done} row(s); ${stranded} claimed-but-unreported left for reclaim`);
  process.exit(0);
}

// ── claim ─────────────────────────────────────────────────────────────────────
const n = Number(opt('--claim', '100'));
const os = opt('--os', '');
const runId = opt('--run', '');
if (!os || !runId) { console.error('--claim needs --os <os> and --run <id>'); process.exit(2); }

const rows = read();
const now = new Date().toISOString();
const claimed = [];
for (const r of rows) {
  if (claimed.length >= n) break;
  if (r.status !== 'pending' || r.os !== os) continue;
  r.status = 'claimed';
  r.run = runId;
  r.at = now;
  claimed.push(r);
}
write(rows);

// stdout is the WORKLIST the runner consumes; diagnostics go to stderr so the two never mix.
for (const r of claimed) console.log(`${r.pkg}@${r.version}`);
console.error(`claimed ${claimed.length} row(s) for ${os} (run ${runId})`);
if (claimed.length === 0) console.error(`QUEUE DRAINED for ${os} — nothing pending`);
