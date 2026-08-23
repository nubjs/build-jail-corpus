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
import { computeHarnessIdentity, loadInvalidationPolicy } from './v2/instrument.mjs';
import { recordValidity } from './v2/record-validity.mjs';
import { fileIdentity } from './v2/runtime-provenance.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const QUEUE = opt('--queue', path.join(here, '..', 'queue.ndjson'));

const read = () => fs.readFileSync(QUEUE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
// Written back in the SAME ORDER read. Re-sorting would make every commit a whole-file rewrite and
// destroy the diff that shows what one slice actually changed.
const write = (rows) => fs.writeFileSync(QUEUE, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);

const key = (r) => `${r.pkg}@${r.version}\t${r.os}`;

// ⛔ A `HARNESS-*` VERDICT IS AN INSTRUMENT FAILURE, NOT A MEASUREMENT — so it must not close a row.
// search.mjs already refuses to let one satisfy its resume check (a crashed package is exactly the
// one a later fix needs to reach), but the QUEUE overrode that by marking the row `done`, so it was
// never claimed again and the harness never got the chance. The two halves disagreed and the queue
// won: instrument failures were being baked into the corpus as results while the queue reported full
// coverage — the precise failure this project exists to prevent.
//
// The row goes back to `pending` instead, carrying an attempt count. The bound matters: a package
// that crashes the harness every single time would otherwise be re-claimed by every slice forever,
// and the queue could never drain. After RETRY_LIMIT attempts the verdict is recorded as-is, which
// says the honest thing — this package could not be measured here — rather than hiding it.
const RETRY_LIMIT = 3;
const isInstrumentFailure = (v) => String(v ?? '').startsWith('HARNESS-');
const returnForRetry = (r, v) => {
  if (!isInstrumentFailure(v)) return false;
  const attempts = (r.attempts ?? 0) + 1;
  r.attempts = attempts;
  if (attempts >= RETRY_LIMIT) return false;   // out of retries: let the caller close it honestly
  r.status = 'pending';
  r.lastInstrumentFailure = v;
  delete r.run;
  delete r.at;
  delete r.verdict;
  delete r.harnessVersion;
  delete r.harnessEpoch;
  delete r.harnessSha256;
  delete r.platform;
  delete r.nubSha256;
  delete r.nubGitSha;
  delete r.node;
  delete r.nodeSha256;
  return true;
};

// The queue speaks in OS names; `process.platform` does not. Derived once so the invalidation pass
// below can tell a row THIS runner could have measured from one it could not.
const THIS_OS = process.platform === 'darwin' ? 'macos'
  : process.platform === 'win32' ? 'windows' : 'linux';

const stampIdentity = (row, record) => {
  row.harnessVersion = record.harnessVersion ?? null;
  row.harnessEpoch = record.harnessEpoch ?? record.provenance?.harnessEpoch ?? null;
  row.harnessSha256 = record.harnessSha256 ?? record.provenance?.harnessSha256 ?? null;
  row.platform = record.platform ?? record.provenance?.platform ?? null;
  row.nubSha256 = record.nubSha256 ?? record.provenance?.nubBinary?.sha256 ?? null;
  row.nubGitSha = record.nubGitSha ?? record.provenance?.nubGitSha ?? null;
  row.node = record.node ?? record.provenance?.node ?? null;
  row.nodeSha256 = record.nodeSha256 ?? record.provenance?.runtime?.node?.sha256 ?? null;
};

if (argv.includes('--status')) {
  const rows = read();
  const by = {};
  for (const r of rows) {
    by[r.os] ??= {};
    by[r.os][r.status] = (by[r.os][r.status] || 0) + 1;
  }
  const total = rows.length;
  const terminal = rows.filter((r) => ['done', 'refused-malicious'].includes(r.status)).length;
  console.log(`queue: ${terminal}/${total} terminal (${Math.round((terminal / total) * 100)}%)`);
  for (const [os, s] of Object.entries(by)) {
    console.log(`  ${os.padEnd(8)} ${Object.entries(s).map(([k, v]) => `${k}=${v}`).join('  ')}`);
  }
  process.exit(0);
}

// ⛔ THE RECORDS ARE THE TRUTH; THE QUEUE IS AN INDEX OF THEM, AND AN INDEX CAN FALL BEHIND.
//
// `--complete` only marks rows THIS RUN claimed, which is right for a live slice and leaves a gap
// everywhere else: records recovered from a lost run's log, records committed by a run whose queue
// update never landed, records carried in from an earlier corpus. Those packages are measured and the
// queue still calls them pending.
//
// MEASURED: the queue read `0/6750 done (0%)` while 158 records sat committed beside it. That is the
// same shape as every other defect here — an artifact that is internally consistent, easy to read,
// and says the opposite of the truth. A later reader concludes nothing has been measured.
//
// Reconciling is safe in the direction that matters: it only ever marks a row DONE, and only when a
// record for that exact (pkg, version, platform) exists on disk. It never invents a verdict, never
// un-does one, and never returns a row to pending — `--reclaim-stale` owns that direction.
if (argv.includes('--reconcile')) {
  const recordsDir = opt('--records', path.join(here, '..', 'records'));
  const requireCurrentInstrument = argv.includes('--require-current-instrument');
  const instrument = requireCurrentInstrument ? computeHarnessIdentity() : null;
  const invalidation = requireCurrentInstrument ? loadInvalidationPolicy() : null;
  // platform dir (`darwin-arm64`) -> queue `os` (`macos`). The queue speaks in OS names because a
  // human writes it; records speak in `${process.platform}-${process.arch}` because the harness does.
  const osOf = (plat) => (plat.startsWith('darwin') ? 'macos'
    : plat.startsWith('linux') ? 'linux'
      : plat.startsWith('win') ? 'windows' : null);

  const have = new Map();
  (function walk(d) {
    let e; try { e = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const x of e) {
      const f = path.join(d, x.name);
      if (x.isDirectory()) { walk(f); continue; }
      if (x.name !== 'results.json') continue;
      let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
      const os = osOf(r.provenance?.platform ?? '');
      if (!os || !r.pkg || !r.version || !r.verdict) continue;
      if (requireCurrentInstrument && !recordValidity(r, instrument, invalidation).reusable) continue;
      have.set(`${r.pkg}@${r.version}\t${os}`, r);
    }
  })(recordsDir);

  const rows = read();
  let marked = 0; let already = 0; let noRecord = 0; let instrumentFailures = 0;
  for (const r of rows) {
    const record = have.get(key(r));
    const v = record?.verdict;
    if (!record) { noRecord++; continue; }
    // ⛔ NEVER CLOSE A ROW ON AN INSTRUMENT FAILURE. Leave it untouched: `--complete` owns the retry
    // accounting because it knows which run produced the failure. Doing it here as well would
    // double-count attempts, and returning a row to `pending` from here could hand it to a second
    // runner while the one that claimed it is still measuring.
    if (isInstrumentFailure(v)) { instrumentFailures++; continue; }
    if (r.status === 'done') { already++; continue; }
    r.status = 'done';
    r.verdict = v;
    stampIdentity(r, record);
    r.reconciled = true;
    delete r.run;
    delete r.claimedAt;
    marked++;
  }
  if (marked) write(rows);
  console.error(`reconciled against ${have.size} record(s): marked ${marked} row(s) done, `
    + `${already} already done, ${instrumentFailures} instrument failure(s) left open, `
    + `${noRecord} row(s) have no record yet`);
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
        if (v.pkg && v.version) verdicts.set(`${v.pkg}@${v.version}`, v);
      } catch { /* a malformed line must not lose the whole slice */ }
    }
  }
  const rows = read();
  let done = 0; let stranded = 0; let retry = 0;
  for (const r of rows) {
    if (r.status !== 'claimed' || r.run !== runId) continue;
    const record = verdicts.get(`${r.pkg}@${r.version}`);
    if (record === undefined) { stranded++; continue; }
    const v = record.verdict;
    if (returnForRetry(r, v)) { retry++; continue; }
    r.status = 'done';
    r.verdict = v;
    stampIdentity(r, record);
    delete r.run;
    delete r.at;
    done++;
  }
  write(rows);
  console.error(`completed ${done} row(s); ${retry} instrument failure(s) returned to pending; `
    + `${stranded} claimed-but-unreported left for reclaim`);
  process.exit(0);
}

// ── claim ─────────────────────────────────────────────────────────────────────
const n = Number(opt('--claim', '100'));
const os = opt('--os', '');
const runId = opt('--run', '');
if (!os || !runId) { console.error('--claim needs --os <os> and --run <id>'); process.exit(2); }

const rows = read();
// The queue is itself a resume index. Old `done` rows must not hide stale records from the batch:
// stamp every completion with its instrument, then return any incompatible row to pending before
// selecting a slice. Explicit inherited malware refusals are security decisions, not measurements,
// and remain terminal until their separate revalidation policy changes.
if (path.basename(QUEUE) === 'queue-v2.ndjson') {
  const instrument = computeHarnessIdentity();
  const invalidation = loadInvalidationPolicy();
  const subjectNub = opt('--subject-nub', '');
  const subjectNubGitSha = opt('--subject-nub-git-sha', '');
  const nodeIdentity = subjectNub ? fileIdentity(process.execPath) : null;
  const nubIdentity = subjectNub ? fileIdentity(subjectNub) : null;
  if (subjectNub && (!nodeIdentity?.sha256 || !nubIdentity?.sha256 || !subjectNubGitSha)) {
    console.error('v2 claim refused: --subject-nub requires readable Node/Nub binaries and '
      + '--subject-nub-git-sha so stale done rows cannot hide a changed subject');
    process.exit(2);
  }
  for (const row of rows) {
    if (row.status !== 'done') continue;
    const pseudoRecord = {
      ...row,
      provenance: {
        platform: row.platform ?? (row.os === 'macos' ? 'darwin-unknown'
          : row.os === 'windows' ? 'win32-unknown' : `${row.os}-unknown`),
        harnessEpoch: row.harnessEpoch,
        harnessSha256: row.harnessSha256,
        node: row.node,
        runtime: { node: { sha256: row.nodeSha256 } },
        nubGitSha: row.nubGitSha,
        nubBinary: { sha256: row.nubSha256 },
      },
    };
    // ⛔⛔ THE RUNTIME IDENTITY IS THIS RUNNER'S, SO ONLY THIS RUNNER'S OWN PLATFORM MAY BE JUDGED BY
    // IT. Applying `process.version` and this box's binary hashes to a row measured on ANOTHER
    // platform asks whether a macOS row was produced by the Linux runner currently holding the
    // queue. It never was — so the row failed, was returned to pending, and got re-measured.
    //
    // That is a mutual-destruction loop and it is why the corpus could not converge. MEASURED
    // 2026-08-23: `setup-node` pins `node-version: '22'`, a FLOATING major, and the hosted images had
    // drifted apart — every darwin epoch-3 record carried `v22.23.1`, every linux one `v22.23.2`. So
    // each linux claim invalidated all 89 darwin rows as "Node runtime changed", each darwin claim
    // invalidated all 141 linux rows, and `done` oscillated around one platform's worth (200 -> 100)
    // while 230 valid records sat on disk. One macOS slice re-measured 43 of its 50 rows, and one
    // record had been written three times by three separate runs.
    //
    // The instrument and epoch checks still apply to EVERY row: those are properties of the record
    // and travel between machines. Only the runtime comparison is scoped, because only it asks a
    // question about the machine doing the asking.
    // ⛔ THE NUB SUBJECT IS GLOBAL; THE RUNNER'S NODE IS NOT. A new nub binary or commit is the same
    // change for every platform — it is the thing under measurement — so those two still reopen
    // every row. `nodeVersion`/`nodeSha256` describe the MACHINE ASKING, and are passed only for
    // rows this runner could actually have produced. `queue-epoch.test.mjs` pins the first half:
    // scoping the nub identity too made a new-subject claim stop reopening a linux row when the
    // suite ran on a Mac, which would have let a changed subject hide behind a foreign platform.
    // ⛔⛔ ONLY `nubGitSha` IDENTIFIES THE SUBJECT ACROSS PLATFORMS. Every other identity here is a
    // property of ONE machine, and comparing it to a row from another platform can never match:
    //
    //   nubGitSha  1 distinct across all 230 epoch-3 records   <- the subject, and it travels
    //   nubSha256  2 distinct, splitting EXACTLY 89 darwin / 141 linux
    //   node       2 distinct, the same 89 / 141 split
    //
    // A darwin nub binary and a linux nub binary are different FILES built from the same commit, so
    // `nubBinary.sha256` differs by construction. Judging a darwin row against this Linux runner's
    // binary reports "Nub binary changed" forever — the subject did not change, the platform did.
    //
    // That was the second half of the convergence loop and it survived the first fix: scoping only
    // the Node identity left `nubSha256` reopening every foreign row, so a linux slice still logged
    // `completed 0 row(s)` and re-measured 50 rows that already had valid records.
    //
    // `nubGitSha` stays GLOBAL, which is what keeps the guarantee that matters: a genuinely new
    // subject reopens every platform's rows. `queue-epoch.test.mjs` pins that, and it is the test
    // that caught an earlier patch of mine which scoped the whole nub identity.
    const ownPlatform = row.os === THIS_OS;
    const validity = recordValidity(pseudoRecord, instrument, invalidation, subjectNub ? {
      ...(ownPlatform
        ? { nodeVersion: process.version, nodeSha256: nodeIdentity?.sha256, nubSha256: nubIdentity?.sha256 }
        : {}),
      nubGitSha: subjectNubGitSha || null,
    } : {});
    if (validity.reusable) continue;
    row.status = 'pending';
    row.invalidated = {
      at: new Date().toISOString(),
      reason: validity.reason,
      priorVerdict: row.verdict ?? null,
      priorHarnessEpoch: row.harnessEpoch ?? null,
      priorHarnessSha256: row.harnessSha256 ?? null,
    };
    delete row.verdict;
    delete row.harnessVersion;
    delete row.harnessEpoch;
    delete row.harnessSha256;
    delete row.platform;
    delete row.nubSha256;
    delete row.nubGitSha;
    delete row.node;
    delete row.nodeSha256;
    delete row.attempts;
  }
}
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
