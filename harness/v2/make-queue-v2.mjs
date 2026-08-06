// Derive `queue-v2.ndjson` from the v1 queue, all rows pending.
//
// ⛔ A SEPARATE QUEUE FILE, NOT A COLUMN ON THE V1 QUEUE. The v1 fleet is live and claims rows out
// of `queue.ndjson` continuously; a v2 runner claiming from that same file would mark rows `done`
// against a v2 record and take them away from the v1 fleet mid-drain — two harnesses fighting over
// one index, with the loser silently unmeasured. Disjoint files make the two lanes independent, and
// `claim-slice.mjs` already takes `--queue`, so no claim logic is duplicated to get it.
//
// The SPEC SET is taken from v1 deliberately: the standing directive is to re-measure the same
// corpus under v2, and deriving the list means the two are comparable spec-for-spec rather than
// approximately.
//
//   usage: node make-queue-v2.mjs [--from queue.ndjson] [--out queue-v2.ndjson]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const FROM = opt('--from', path.join(here, '..', '..', 'queue.ndjson'));
const OUT = opt('--out', path.join(here, '..', '..', 'queue-v2.ndjson'));

const rows = fs.readFileSync(FROM, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const seen = new Set();
const out = [];
for (const r of rows) {
  const k = `${r.pkg}@${r.version}\t${r.os}`;
  if (seen.has(k)) continue;
  seen.add(k);
  // Only the four fields a claim needs. A v1 row's `verdict`/`reconciled` describe a v1 measurement
  // and would read here as a v2 result that was never taken.
  out.push({ pkg: r.pkg, version: r.version, os: r.os, status: 'pending' });
}
fs.writeFileSync(OUT, `${out.map((r) => JSON.stringify(r)).join('\n')}\n`);
console.log(`wrote ${out.length} pending row(s) to ${OUT}`);
