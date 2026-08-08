// Derive `queue-v2.ndjson` from the v1 queue without resurrecting a terminal malicious-tree refusal.
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
//                                  [--preserve-existing]

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const FROM = opt('--from', path.join(here, '..', '..', 'queue.ndjson'));
const OUT = opt('--out', path.join(here, '..', '..', 'queue-v2.ndjson'));
const PRESERVE = argv.includes('--preserve-existing');
const KNOWN = new Set(['--from', '--out', '--preserve-existing']);
const unknown = argv.filter((arg, i) => arg.startsWith('--') && !KNOWN.has(arg)
  && !(i > 0 && ['--from', '--out'].includes(argv[i - 1])));
if (unknown.length) throw new Error(`unknown flag(s): ${unknown.join(', ')}`);

const rows = fs.readFileSync(FROM, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const seen = new Set();
const out = [];
const existing = new Map();
if (PRESERVE && fs.existsSync(OUT)) {
  for (const row of fs.readFileSync(OUT, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))) {
    existing.set(`${row.pkg}@${row.version}\t${row.os}`, row);
  }
}
for (const r of rows) {
  const k = `${r.pkg}@${r.version}\t${r.os}`;
  if (seen.has(k)) continue;
  seen.add(k);
  // A resolved-tree malware refusal is a security decision, not a v1 capability measurement. Resetting
  // it to pending discards the only screen that could see the compromised transitive dependency and
  // lets v2 fetch/execute the same tree again. Every other v1 verdict remains v1-only.
  if (r.verdict === 'REFUSED-MALICIOUS') {
    out.push({
      pkg: r.pkg,
      version: r.version,
      os: r.os,
      status: 'refused-malicious',
      verdict: 'REFUSED-MALICIOUS',
      sourceVerdict: 'v1-resolved-tree-screen',
    });
  } else {
    out.push(existing.get(k) ?? { pkg: r.pkg, version: r.version, os: r.os, status: 'pending' });
  }
}
// A demand snapshot may have extended v2 after the original v1 queue was frozen. Preserve those rows
// too: `--preserve-existing` is an in-place security repair, not permission to shrink the corpus to
// the older source manifest.
if (PRESERVE) {
  for (const [key, row] of existing) {
    if (!seen.has(key)) out.push(row);
  }
}
fs.writeFileSync(OUT, `${out.map((r) => JSON.stringify(r)).join('\n')}\n`);
const refused = out.filter((r) => r.status === 'refused-malicious').length;
console.log(`wrote ${out.length} row(s) to ${OUT}: ${refused} preserved malicious-tree refusal(s)`
  + `${PRESERVE ? ', existing v2 state retained elsewhere' : ''}`);
