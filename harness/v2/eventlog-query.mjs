// Re-derive a scope breakdown from RETAINED event logs — any platform, no re-measure.
//
// ⛔ THIS IS THE CLAIM RETENTION RESTS ON, EXECUTED RATHER THAN ASSERTED. The argument for keeping
// the logs is that a harness fix becomes a RE-PARSE instead of a RE-MEASURE (minutes against
// runner-hours per platform), and that a scope set which did not exist at measurement time is still
// derivable. The `--tmp` scope below is exactly that case: it is not in `observe.mjs`, not in
// `observe-macos.mjs`, and not in `classify.mjs` — it is computed here, from raw paths plus the
// header's roots, over logs recorded before anyone had defined it.
//
// ⛔ ANALYSIS ONLY. Nothing here feeds grant synthesis, the driver, or the catalog, and it must
// stay that way: the moment a retained log can move a verdict, the verdict stops being an
// independent second opinion on the trace.
//
// It reads Linux and macOS logs with the same code, which is the point — the schema is shared, so
// the query is written once.
//
//   usage: node eventlog-query.mjs <events.ndjson[.gz]>... [--script-only] [--reads] [--paths <scope>]
import fs from 'node:fs';
import zlib from 'node:zlib';

const argv = process.argv.slice(2);
const files = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1] === '--paths'));
const scriptOnly = argv.includes('--script-only');
const wantReads = argv.includes('--reads');
const dumpScope = argv.includes('--paths') ? argv[argv.indexOf('--paths') + 1] : null;
if (!files.length) {
  console.error('usage: eventlog-query.mjs <events.ndjson[.gz]>... [--script-only] [--reads] [--paths <scope>]');
  process.exit(2);
}

const load = (f) => {
  const buf = fs.readFileSync(f);
  const text = (f.endsWith('.gz') ? zlib.gunzipSync(buf) : buf).toString('utf8');
  return text.trim().split('\n').map((l) => JSON.parse(l));
};

// The classifier, written HERE rather than imported, because the whole demonstration is that a
// future model can define its own. Longest-prefix against the roots the header recorded — MAPPING.md
// rule 2 — plus a `tmp` scope that no shipped classifier has.
const scopeOf = (p, roots) => {
  if (!p) return 'none';
  if (/^(\/private)?\/tmp\//.test(p) || /^(\/private)?\/var\/folders\//.test(p)) return 'tmp';
  const under = (r) => r && (p === r || p.startsWith(`${r}/`));
  if (under(roots.ownPkg)) return 'ownPkg';
  if (under(roots.jailHome)) return 'jailHome';
  if (under(roots.project)) return p.slice(roots.project.length).includes('/node_modules/') ? 'deps' : 'project';
  if (under(roots.home)) return 'userHome';
  if (/^\/(usr|bin|sbin|lib|lib64|etc|opt|System|Library|dev|proc|sys)(\/|$)/.test(p)) return 'systemfs';
  return 'outside';
};

const total = {};
const samples = new Map();
for (const f of files) {
  const rows = load(f);
  const h = rows.find((r) => r.k === 'h');
  if (!h) { console.error(`${f}: no header — not a retained event log`); continue; }
  const life = new Map(rows.filter((r) => r.k === 'p').map((p) => [p.pid, p.life === 1]));
  const per = {};
  for (const e of rows) {
    if (e.k !== 'e') continue;
    // A call that FAILED is not a need. It is retained (it names a path the script probed for), but
    // it is not counted as one here — which is a choice this query makes, not one the log made.
    if (e.r !== 0) continue;
    if (!wantReads && !e.w) continue;
    if (scriptOnly && !life.get(e.p)) continue;
    for (const p of [e.f, e.g]) {
      if (!p) continue;
      const s = scopeOf(p, h.roots);
      per[s] = (per[s] ?? 0) + (e.n ?? 1);
      total[s] = (total[s] ?? 0) + (e.n ?? 1);
      if (s === dumpScope) {
        if (!samples.has(s)) samples.set(s, new Set());
        samples.get(s).add(p);
      }
    }
  }
  console.log(`${h.platform.padEnd(13)} ${String(h.pkg).padEnd(24)} ${JSON.stringify(per)}`);
}
console.log(`${'TOTAL'.padEnd(13)} ${''.padEnd(24)} ${JSON.stringify(total)}`);
if (dumpScope && samples.has(dumpScope)) {
  const set = [...samples.get(dumpScope)].sort();
  console.log(`\n${set.length} distinct paths in scope \`${dumpScope}\`:`);
  set.slice(0, 40).forEach((p) => console.log(`  ${p}`));
  if (set.length > 40) console.log(`  … and ${set.length - 40} more`);
}
