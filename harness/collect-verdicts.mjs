// Emit one NDJSON line per record found under a runs directory: {pkg, version, verdict}.
//
// This is the bridge between "the harness wrote records" and "the queue can mark rows done". It
// deliberately reports ONLY what is actually on disk: a row whose record is missing stays `claimed`
// and gets reclaimed later, rather than being marked done on the strength of having been attempted.
//
// ⛔ A `HARNESS-*` VERDICT IS NOT A MEASUREMENT, but it IS a completed row for queue purposes — the
// runner attempted it and produced a record saying the instrument failed. Re-running it needs a
// harness fix first, so leaving it `pending` would make every subsequent slice pick it up again and
// fail identically. It is recorded with its verdict so a sweep can find and re-queue it explicitly.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const RUNS = opt('--runs', path.join(here, '..', 'records'));
const OUT = opt('--out', '');

const files = [];
(function walk(d) {
  let entries;
  try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const f = path.join(d, e.name);
    if (e.isDirectory()) walk(f);
    else if (e.name === 'results.json') files.push(f);
  }
})(RUNS);

const lines = [];
for (const f of files) {
  try {
    const r = JSON.parse(fs.readFileSync(f, 'utf8'));
    if (!r.pkg || !r.version) continue;
    lines.push(JSON.stringify({ pkg: r.pkg, version: r.version, verdict: r.verdict ?? null }));
  } catch {
    // A truncated record (killed mid-write) must not abort the whole collection — its row simply
    // stays claimed and is reclaimed.
  }
}

const text = `${lines.join('\n')}\n`;
if (OUT) fs.writeFileSync(OUT, text); else process.stdout.write(text);
console.error(`collected ${lines.length} verdict(s) from ${files.length} record file(s)`);
