// Turn coverage gaps into QUEUE ROWS, so the existing runner can claim them.
//
// ⛔⛔ ROWS, NOT DISPATCHES, AND THAT IS THE WHOLE POINT. `corpus-queue-runner` already has the only
// mechanism that makes concurrent runners safe: a row goes `pending` -> `claimed` carrying the run id
// that took it, PUSHED before any measuring starts, so two runners can never hold the same row. Handing
// specs straight to a runner as workflow inputs bypasses that, and then two concurrent runs measure the
// same package while the queue no longer reflects what is in flight.
//
// ⛔ IDEMPOTENT BY (pkg, version, os), which is what lets this run on every coverage check without
// growing the queue. A gap is only a gap because no RECORD exists; a row may already be sitting there
// `pending` or `claimed` from an earlier run, and appending a second one would have two runners measure
// it — the exact collision the claim mechanism exists to prevent.
import fs from 'node:fs';
import path from 'node:path';

/** Parse an NDJSON queue into rows, preserving anything we do not understand. */
export function readQueue(text) {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    })
    .filter(Boolean);
}

/** The identity of a queue row — the tuple a claim is unique over. */
export const rowKey = (r) => `${r.pkg} ${r.version} ${r.os}`;

/** New `pending` rows for gaps the queue does not already carry.
 *
 * Returns `{ rows, added, skipped }` so a caller can report what it did rather than diffing a file.
 */
export function newRows(existing, gaps) {
  const seen = new Set(existing.map(rowKey));
  const rows = [];
  let skipped = 0;
  for (const g of gaps) {
    const row = { pkg: g.name, version: g.version, os: g.platform, status: 'pending' };
    const key = rowKey(row);
    if (seen.has(key)) { skipped++; continue; }
    seen.add(key);
    rows.push(row);
  }
  return { rows, added: rows.length, skipped };
}

/** Append rows to the queue file. Append-only: never rewrite or reorder existing rows.
 *
 * ⛔ APPEND, NEVER REWRITE. The queue is the shared file every concurrent runner re-derives its claim
 * against; rewriting it wholesale would clobber a claim another runner pushed while this ran, and a lost
 * claim is a double-measured row. Appending is the only operation that cannot lose someone else's write.
 */
export function appendRows(queuePath, rows) {
  if (!rows.length) return 0;
  const body = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
  fs.appendFileSync(queuePath, body);
  return rows.length;
}

if (import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1] ?? '').href) {
  const argv = process.argv.slice(2);
  const coverage = argv[argv.indexOf('--coverage') + 1];
  if (!argv.includes('--coverage') || !coverage) {
    console.error('usage: node corpus/gaps-to-queue.mjs --coverage <coverage.json> [--apply]');
    process.exit(2);
  }
  const root = path.resolve(import.meta.dirname, '..');
  const queuePath = path.join(root, 'queue-v2.ndjson');
  const { gaps = [] } = JSON.parse(fs.readFileSync(coverage, 'utf8'));
  const existing = readQueue(fs.readFileSync(queuePath, 'utf8'));
  const { rows, added, skipped } = newRows(existing, gaps);
  console.log(`gaps ${gaps.length}   queue rows already present ${skipped}   new pending rows ${added}`);
  for (const r of rows.slice(0, 40)) console.log(`  + ${r.pkg}@${r.version} ${r.os}`);
  if (argv.includes('--apply')) {
    appendRows(queuePath, rows);
    console.log(`appended ${added} row(s) to queue-v2.ndjson`);
  } else {
    console.log('(dry run — pass --apply to write)');
  }
}
