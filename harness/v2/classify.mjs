// EVENT stream -> grant. The shared half of the mapping, per MAPPING.md.
//
// observe.mjs is the Linux adapter AND classifier fused together, because on Linux the trace
// format and the classifier arrived at the same time. Windows cannot reuse it: its adapter
// (adapters/windows.mjs) already emits the normalized EVENT contract, so what is missing is the
// half after the arrow. This file is that half, written against EVENT alone -- it never looks at
// a trace format, so the Linux adapter can be pointed at it later without changing a line here.
//
//   usage: node classify.mjs <events.ndjson> --project <dir> --home <dir> [--platform win32]
//                            [--json out.json]
//
// Determinism rules 1-5 (MAPPING.md) are the whole specification. Where this file departs from
// observe.mjs the departure is a rule, not a preference:
//
//  * rule 1  normalize BEFORE classifying. Windows and macOS case-fold, Linux does not; the
//            kernel emits both `C:\d` and `C:\d\` for one directory. Both are handled once, here.
//  * rule 2  scope is LONGEST-PREFIX against roots passed IN, never a substring like
//            "contains node_modules". Roots are ordered longest-first so the package dir nested
//            inside the project resolves the same way every time.
//  * rule 3  a path that maps to no scope is REPORTED, never rounded up to write:"disk".
import fs from 'node:fs';

const args = process.argv.slice(2);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
const file = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')))[0];
const project = val('--project');
const home = val('--home');
const platform = val('--platform', process.platform);
const jsonOut = val('--json');
if (!file || !project || !home) {
  console.error('usage: classify.mjs <events.ndjson> --project <dir> --home <dir> [--platform p] [--json f]');
  process.exit(2);
}

const WIN = platform === 'win32';
const FOLD = WIN || platform === 'darwin';

// Rule 1. One normalizer, applied to every path before anything else looks at it.
const norm = (p) => {
  if (!p) return p;
  let s = WIN ? p.replace(/\//g, '\\') : p;
  const sep = WIN ? '\\' : '/';
  // The kernel emits a directory both with and without its trailing separator. Same path.
  if (s.length > 3 && s.endsWith(sep)) s = s.slice(0, -1);
  const parts = s.split(sep);
  const out = [];
  for (const seg of parts) {
    if (seg === '.') continue;
    if (seg === '..') { if (out.length > 1) out.pop(); continue; }
    out.push(seg);
  }
  s = out.join(sep);
  return FOLD ? s.toLowerCase() : s;
};

// Non-filesystem namespaces the classifier must NOT round into a write grant (rule 3). On Linux
// this is /proc,/sys,/dev; on Windows it is the NTFS metadata files the filesystem writes in the
// requesting thread's context, plus unmapped NT device paths.
const isKernelFs = (p) => WIN
  ? /^[a-z]:\\\$(mft|logfile|extend|bitmap|secure|volume)/i.test(p) || p.startsWith('\\device\\') || p.startsWith('\\??\\')
  : /^\/(proc|sys|dev)(\/|$)/.test(p);

const isSystemFs = (p) => WIN
  ? /^[a-z]:\\(windows|program files|program files \(x86\)|programdata)(\\|$)/i.test(p)
  : /^\/(usr|bin|sbin|lib|lib64|etc|opt)(\/|$)/.test(p);

// Rule 2. Roots come IN, longest-first, first match wins. `deps` must precede `project` because
// it is nested inside it; a longest-first sort gets that right without special-casing.
const ROOTS = [
  { name: 'deps', path: norm(project + (WIN ? '\\node_modules' : '/node_modules')) },
  { name: 'project', path: norm(project) },
  { name: 'userHome', path: norm(home) },
].sort((a, b) => b.path.length - a.path.length);

const under = (p, root) => p === root || p.startsWith(root + (WIN ? '\\' : '/'));

const scopeOf = (p) => {
  for (const r of ROOTS) if (under(p, r.path)) return r.name;
  if (isKernelFs(p)) return 'kernelfs';
  if (isSystemFs(p)) return 'systemfs';
  return 'outside';
};

// ⛔ ATTRIBUTION IS NOT OPTIONAL, AND ITS ABSENCE IS A SILENT 100% OVER-PREDICTION. The trace
// carries the package manager's own work as well as the lifecycle script's, and path text cannot
// tell them apart -- npm opens registry TLS sockets and writes its cache and logs under the user
// profile on every run. Without a subtree filter EVERY package synthesizes `write:userHome` +
// `network:true` regardless of what its script does, which also makes the per-path question
// (can `writePaths` replace a disk grant?) unanswerable.
//
// The Linux extractor keys on `sh -c`. Windows has no `-c` to key on, because the EVENT contract
// carries no command line -- so the equivalent is structural: npm reaches a lifecycle script
// through `cmd.exe`, and the traced ROOT is itself a cmd.exe (the launcher). The lifecycle shells
// are therefore every cmd.exe exec that is NOT the root, and the attributed set is the union of
// the subtrees rooted at them. Verified against the dprint trace in README-windows.md, where this
// admits the install.js/powershell/download subtree and excludes npm's own registry connection.
const rootPid = Number(val('--root-pid', '0'));
const SHELL = /(^|\\)cmd\.exe$/i;

const parsed = [];
let n = 0, bad = 0;
for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  let e;
  try { e = JSON.parse(line); } catch { bad++; continue; }
  n++;
  parsed.push(e);
}

// Build the process tree first: an event's attribution depends on an exec that may appear later
// in the stream, so a single streaming pass would mis-attribute whatever preceded it.
const parentOf = new Map(), imageOf = new Map();
for (const e of parsed) {
  if (e.op !== 'exec') continue;
  if (!parentOf.has(e.pid)) parentOf.set(e.pid, e.ppid);
  imageOf.set(e.pid, norm(e.path));
}
const lifecycle = new Set();
for (const [pid, img] of imageOf) if (SHELL.test(img) && pid !== rootPid) lifecycle.add(pid);
// Descendants of a lifecycle shell are lifecycle. Iterate to a fixed point rather than assuming
// the exec stream is topologically ordered.
for (let changed = true; changed;) {
  changed = false;
  for (const [pid, ppid] of parentOf) {
    if (!lifecycle.has(pid) && lifecycle.has(ppid)) { lifecycle.add(pid); changed = true; }
  }
}

const writes = new Map(), reads = new Map(), denials = [], peers = new Set(), execs = [];
const allWrites = new Set(), allPeers = new Set();
for (const e of parsed) {
  const mine = lifecycle.has(e.pid);
  if (e.op === 'connect') { allPeers.add(`${e.host}:${e.port}`); if (mine) peers.add(`${e.host}:${e.port}`); continue; }
  if (e.op === 'exec') { execs.push({ path: e.path, pid: e.pid, ppid: e.ppid }); continue; }
  const p = norm(e.path);
  if (!p) continue;
  // Rule 4. Only a genuine refusal is a refusal; the adapter already applied its own predicate,
  // so a `denied` result here is authoritative and is NOT counted as a need. A refusal outside the
  // subtree is still recorded -- it is evidence about the environment, not about the package.
  if (e.result === 'denied') { denials.push({ op: e.op, path: p, scope: scopeOf(p), mine }); continue; }
  if (e.op === 'write') allWrites.add(p);
  if (!mine) continue;
  const t = e.op === 'write' ? writes : reads;
  t.set(p, (t.get(p) ?? 0) + 1);
}

const bucket = (m) => {
  const out = {};
  for (const p of m.keys()) (out[scopeOf(p)] ??= []).push(p);
  return out;
};
const w = bucket(writes), r = bucket(reads);

// The synthesized grant: the NARROWEST catalog entry covering everything observed.
//
// `write` implies `read` at its own scope and stating the redundant `read` is a PARSE ERROR, so a
// read scope is only emitted where the same scope has no write.
const grant = {};
const wr = {};
if (w.deps) wr.deps = true;
if (w.project) wr.project = true;
if (w.userHome) wr.userHome = true;
if (Object.keys(wr).length) grant.write = wr;
if (peers.size > 0) grant.network = true;

const report = {
  events: n, malformed: bad,
  lifecyclePids: lifecycle.size,
  attributedWrites: writes.size, allTreeWrites: allWrites.size,
  attributedPeers: peers.size, allTreePeers: allPeers.size,
  writes: Object.fromEntries(Object.entries(w).map(([k, v]) => [k, v.length])),
  reads: Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v.length])),
  outsideWrites: (w.outside ?? []).slice().sort(),
  systemWrites: (w.systemfs ?? []).slice().sort(),
  kernelfsWrites: (w.kernelfs ?? []).length,
  peers: [...peers].sort(),
  denials,
  execDepth: (() => {
    const byPid = new Map(execs.map((e) => [e.pid, e]));
    let max = 0;
    for (const e of execs) { let d = 0, c = e; while (c && d < 20) { c = byPid.get(c.ppid); d++; } max = Math.max(max, d); }
    return max;
  })(),
  grant,
};

console.log(`== ATTRIBUTION == lifecycle pids: ${lifecycle.size} (root ${rootPid || 'UNSET'})`);
console.log(`  writes  script ${writes.size}  /  whole traced tree ${allWrites.size}`);
console.log(`  peers   script ${peers.size}  /  whole traced tree ${allPeers.size}`);
if (lifecycle.size === 0) {
  // Not a package with no needs -- a filter that matched nothing. Saying so beats emitting an
  // empty grant that reads as a confident "needs nothing".
  console.log('  !! NO LIFECYCLE SHELL FOUND -- the subtree filter matched nothing, so the grant');
  console.log('     below is EMPTY BY DEFAULT rather than by measurement. Treat it as UNKNOWN.');
}
console.log('== WRITES ==');
for (const [k, v] of Object.entries(w)) {
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
  if (k === 'outside' || k === 'systemfs') v.slice(0, 12).forEach((p) => console.log(`      ${p}`));
}
console.log('== READS ==');
for (const [k, v] of Object.entries(r)) console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
console.log('== NETWORK ==');
console.log(`  distinct peers: ${peers.size}`);
[...peers].slice(0, 12).forEach((h) => console.log(`      ${h}`));
console.log('== REFUSALS (adapter-classified) ==');
console.log(`  distinct: ${denials.length}`);
denials.slice(0, 15).forEach((d) => console.log(`      ${d.op} [${d.scope}] ${d.path}`));
console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
console.log('  ' + JSON.stringify(grant));
if (w.outside) console.log(`  !! ${w.outside.length} writes OUTSIDE project/home -- no scope covers these; inspect before granting`);
if (w.systemfs) console.log(`  !! ${w.systemfs.length} writes into system dirs -- an unprivileged user would be refused these`);
if (w.kernelfs) console.log(`  NOTE ${w.kernelfs.length} kernel/metadata writes -- not a write-grant question (rule 3)`);

if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2));
