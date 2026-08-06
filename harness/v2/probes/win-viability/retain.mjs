// Q2 (retention size) + Q3 (ancestor collapsing, with its over-grant cost) + Q4 (the temp split),
// computed over one package's normalized event stream.
//
// ⛔ ANALYSIS ONLY. Nothing here is wired into a grant, and it deliberately cannot be: the brief is a
// viability probe, and the maintainer's position is that the grant model must not move until the
// evidence is in. What it produces is the numbers a decision needs.
//
// ⛔ AND IT REPORTS THE OVER-GRANT, NOT JUST THE COMPRESSION RATIO. Collapsing N observed leaf paths
// to M ancestor directories grants strictly MORE than was observed -- everything else under those
// ancestors, including files that did not exist when the trace ran. A collapse that reports
// "487 paths -> 12 directories" and stops there is selling the win and hiding the price.
//
//   usage: node retain.mjs <events.ndjson> --project <dir> --home <dir> --temp <dir> [--json out]
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

const args = process.argv.slice(2);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
const file = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')))[0];
const project = val('--project'), home = val('--home'), temp = val('--temp', process.env.TEMP || '');
const jsonOut = val('--json');
if (!file) { console.error('usage: retain.mjs <events.ndjson> --project d --home d --temp d'); process.exit(2); }

const norm = (p) => {
  let s = String(p).replace(/\//g, '\\');
  if (s.length > 3 && s.endsWith('\\')) s = s.slice(0, -1);
  return s.toLowerCase();
};

const events = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const writes = new Set(), reads = new Set();
for (const e of events) {
  if (!e.path || e.op === 'exec' || e.op === 'connect' || e.result === 'denied') continue;
  (e.op === 'write' ? writes : reads).add(norm(e.path));
}
const W = [...writes].sort(), R = [...reads].sort();

// ── Q2: what would retaining the raw path set actually cost ──────────────────────────────────
// The retained artifact under discussion is the RAW path set, not a scope tally: a scope tag bakes
// in today's classifier, so a record carrying only `scope=outside` forces a full RE-MEASURE to adopt
// a new scope (`tmp`, say) where a record carrying the path makes it a RE-PARSE.
const gz = (s) => zlib.gzipSync(Buffer.from(s, 'utf8')).length;
const wText = W.join('\n') + '\n', rText = R.join('\n') + '\n';
const ndjsonBytes = fs.statSync(file).size;
const sizes = {
  distinctWrites: W.length, distinctReads: R.length,
  writeListBytes: Buffer.byteLength(wText), writeListGzip: gz(wText),
  readListBytes: Buffer.byteLength(rText), readListGzip: gz(rText),
  bothListBytes: Buffer.byteLength(wText + rText), bothListGzip: gz(wText + rText),
  fullNdjsonBytes: ndjsonBytes, fullNdjsonGzip: gz(fs.readFileSync(file, 'utf8')),
};

// ── Q3: ancestor collapsing, at several aggressiveness settings ──────────────────────────────
// `minSiblings` is the aggressiveness knob: a directory replaces its children only once at least
// that many observed leaves sit under it. 1 collapses everything to its parent; a large value keeps
// all but the densest directories as individual leaves.
const parentOf = (p) => { const i = p.lastIndexOf('\\'); return i > 2 ? p.slice(0, i) : p; };

const collapse = (paths, minSiblings) => {
  const byParent = new Map();
  for (const p of paths) {
    const d = parentOf(p);
    byParent.set(d, (byParent.get(d) ?? 0) + 1);
  }
  const dirs = new Set(), kept = new Set();
  for (const p of paths) {
    const d = parentOf(p);
    if ((byParent.get(d) ?? 0) >= minSiblings) dirs.add(d); else kept.add(p);
  }
  return { dirs: [...dirs].sort(), leaves: [...kept].sort(), total: dirs.size + kept.size };
};

// The over-grant: how much content sits under a proposed ancestor that the trace never saw. Counted
// on the real filesystem, because that is what a grant would actually expose. A directory that no
// longer exists is reported as such rather than scored 0 -- a missing directory is not a cheap one.
const countUnder = (dir, observed) => {
  let seen = 0, unobserved = 0, missing = false;
  const walk = (d, depth) => {
    if (depth > 8) return;
    let ents;
    try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { missing = true; return; }
    for (const e of ents) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p, depth + 1); continue; }
      if (observed.has(norm(p))) seen++; else unobserved++;
    }
  };
  walk(dir, 0);
  return { seen, unobserved, missing };
};

const collapseLevels = [1, 2, 4, 8, 16].map((k) => {
  const c = collapse(W, k);
  return { minSiblings: k, dirs: c.dirs.length, leaves: c.leaves.length, total: c.total, dirList: c.dirs };
});

// Price the most aggressive setting, which is the one a grant would plausibly use.
const aggressive = collapse(W, 2);
const overGrant = aggressive.dirs.slice(0, 40).map((d) => ({ dir: d, ...countUnder(d, writes) }));
const overGrantTotal = overGrant.reduce((a, x) => ({
  seen: a.seen + x.seen, unobserved: a.unobserved + x.unobserved,
}), { seen: 0, unobserved: 0 });

// ── Q4: the temp split ───────────────────────────────────────────────────────────────────────
// ⛔ THE SPLIT THAT DECIDES WHETHER A `tmp` SCOPE BUYS ANYTHING ON WINDOWS. A package that resolves
// temp through the API lands wherever the environment points; a package that HARDCODES a literal
// does not move when the environment does. Only the second kind needs a grant a redirect cannot
// give it, so the two are counted separately rather than lumped as "temp writes".
const T = norm(temp || 'C:\\__no_temp__');
const winTemp = 'c:\\windows\\temp';
const localTemp = norm(path.join(home || 'C:\\__no_home__', 'AppData', 'Local', 'Temp'));
const classifyTemp = (p) => {
  if (T !== 'c:\\__no_temp__' && (p === T || p.startsWith(T + '\\'))) return 'envTemp';
  if (p === winTemp || p.startsWith(winTemp + '\\')) return 'windowsTemp';
  if (p === localTemp || p.startsWith(localTemp + '\\')) return 'userLocalTemp';
  if (/\\appdata\\local\\packages\\[^\\]+\\ac\\temp(\\|$)/.test(p)) return 'appContainerTemp';
  if (/(^|\\)temp(\\|$)|(^|\\)tmp(\\|$)/.test(p)) return 'otherTempLooking';
  return null;
};
const tempSplit = {};
const tempSamples = {};
for (const p of W) {
  const k = classifyTemp(p);
  if (!k) continue;
  tempSplit[k] = (tempSplit[k] ?? 0) + 1;
  (tempSamples[k] ??= []).length < 6 && tempSamples[k].push(p);
}

// ── report ────────────────────────────────────────────────────────────────────────────────────
console.log('== Q2  RETENTION SIZE (raw path sets, the re-parseable artifact) ==');
console.log(`  distinct writes ${sizes.distinctWrites}   distinct reads ${sizes.distinctReads}`);
console.log(`  write list  ${sizes.writeListBytes} B raw / ${sizes.writeListGzip} B gzip`);
console.log(`  read list   ${sizes.readListBytes} B raw / ${sizes.readListGzip} B gzip`);
console.log(`  both        ${sizes.bothListBytes} B raw / ${sizes.bothListGzip} B gzip`);
console.log(`  full events.ndjson ${sizes.fullNdjsonBytes} B raw / ${sizes.fullNdjsonGzip} B gzip`);

console.log('\n== Q3  COLLAPSE (write paths -> directories) ==');
for (const c of collapseLevels) {
  console.log(`  minSiblings=${String(c.minSiblings).padStart(2)}  ${String(W.length).padStart(5)} paths -> ` +
    `${String(c.total).padStart(4)} entries (${c.dirs} dirs + ${c.leaves} leaves)`);
}
console.log(`\n  OVER-GRANT COST at minSiblings=2, top ${overGrant.length} directories:`);
console.log(`    observed under them ${overGrantTotal.seen}   UNOBSERVED also granted ${overGrantTotal.unobserved}`);
for (const o of overGrant.slice(0, 12)) {
  console.log(`      ${o.seen} seen / ${o.unobserved} unobserved${o.missing ? ' (partly gone)' : ''}  ${o.dir}`);
}

console.log('\n== Q4  TEMP SPLIT (write paths) ==');
console.log(`  %TEMP% at capture time: ${temp || '<unset>'}`);
if (!Object.keys(tempSplit).length) console.log('  (no temp-looking write paths)');
for (const [k, v] of Object.entries(tempSplit)) {
  console.log(`  ${k.padEnd(18)} ${String(v).padStart(5)}`);
  (tempSamples[k] ?? []).slice(0, 4).forEach((p) => console.log(`      ${p}`));
}

if (jsonOut) {
  fs.writeFileSync(jsonOut, JSON.stringify({
    sizes, collapseLevels: collapseLevels.map(({ dirList, ...c }) => c),
    overGrant, overGrantTotal, tempSplit, tempSamples,
    topWriteDirs: collapse(W, 2).dirs.slice(0, 60),
  }, null, 2));
}
