// dtrace trace.txt -> the RETAINED, platform-neutral event log (NDJSON).
//
// ⛔ WHY THIS FILE EXISTS. The v2 pipeline captures a complete syscall trace into a `mktemp -d`
// fixture root, extracts a one-line verdict from it, publishes `driver.out` + `results.json`, and
// lets the runner evaporate with the trace inside it. A package with 651 script writes publishes
// ~12 path-looking lines. So a verdict can only ever be RE-MEASURED, never RE-DERIVED — which is
// why every harness fix invalidates the corpus, and why "what do all the outside-writes look like
// across the corpus?" is a question nobody can ask.
//
// ⛔⛔ THE BAR THIS FILE IS HELD TO, AND IT IS NOT "a useful debugging artifact":
//
//     the retained log must contain everything needed to re-derive ANY FUTURE grant model,
//     without re-running the package.
//
// Two concrete consequences, and the second is the one that is easy to get wrong:
//
//   1. NOTHING DERIVED IS RETAINED IN PLACE OF ITS INPUT. A path tagged with today's SCOPE
//      (`deps`/`project`/`userHome`/`outside`) bakes in today's classifier: the `tmp` scope being
//      added right now did not exist when the corpus was measured, so a scope-tagged log would
//      need a full RE-MEASURE where a raw log needs a RE-PARSE. That distinction is the whole
//      point of retention. Scopes are therefore absent from this file by construction.
//   2. THE RAW SYSCALL NAME SURVIVES ALONGSIDE THE NEUTRAL CLASS. `op` is the cross-platform class
//      a shared classifier reads; `call` is what the kernel actually saw. A model that later wants
//      to distinguish `unlink` (destroys) from `mkdir` (creates), or `renamex_np` with RENAME_SWAP
//      from an ordinary rename, needs `call` — and `op` alone cannot reconstruct it.
//
// ⛔ NO FILTERING BY DEFAULT, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT. Every filter decides
// what a future model may see, which is the same trap as a scope tag. The one filter that looks
// unambiguously safe — drop `= -1 ENOENT`, since a file that does not exist needs no grant — is
// NOT clean on inspection: a failed lookup is the record of a FALLBACK PATH the script probed and
// did not find, and on a machine where that path exists the same script would read it. So ENOENT
// records are RETAINED, and `--drop-enoent` exists to size the alternative rather than to be the
// default. Repetition is handled by gzip, which is what actually pays for retention: measured
// compression on a real trace is in the 15-30x range because the stream is overwhelmingly repeated
// prefixes.
//
// ⛔ ONE FILTER IS APPLIED UNCONDITIONALLY AND IT REMOVES NO EVENT: records the tracer itself
// could not produce. `TRACER-ERROR` lines are kept as their own record kind, because a dropped
// event is a path never seen, and the count of them is what tells a future reader the log is a
// FLOOR rather than a measurement.
//
//   usage: node macos-eventlog.mjs <trace.txt> --out <events.ndjson>
//                                  [--project <dir>] [--home <dir>] [--pkg <name>] [--jailed]
//                                  [--drop-enoent] [--stats-only]
import fs from 'node:fs';
import zlib from 'node:zlib';

const argv = process.argv.slice(2);
const val = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const has = (f) => argv.includes(f);
const file = argv.find((a, i) => !a.startsWith('--') && (i === 0 || !argv[i - 1].startsWith('--')));
if (!file) {
  console.error('usage: macos-eventlog.mjs <trace.txt> --out <events.ndjson> [--project d] [--home d]');
  process.exit(2);
}

// ── THE WIRE FORMAT ────────────────────────────────────────────────────────────────────────────
// The adapter emits `|`-delimited records whose PATH IS ALWAYS LAST, because a path is free-form
// and routinely contains `|`. Everything between the fixed header fields and the path is a
// `key=value` token, so the adapter can gain a field without renumbering the ones after it — the
// alternative (fixed positions) is what makes a format change break every downstream reader at
// once. A path is not mistaken for a token because only these KEYS are recognized.
const META_KEYS = new Set(['ret', 'errno', 'flags', 'ev', 'dirfd', 'role', 'mode']);
const splitMeta = (fields, from) => {
  const meta = {};
  let i = from;
  for (; i < fields.length; i++) {
    const eq = fields[i].indexOf('=');
    if (eq < 0) break;
    const k = fields[i].slice(0, eq);
    if (!META_KEYS.has(k)) break;
    const raw = fields[i].slice(eq + 1);
    meta[k] = /^0x/.test(raw) ? parseInt(raw, 16) : (/^-?\d+$/.test(raw) ? Number(raw) : raw);
  }
  return { meta, path: fields.slice(i).join('|') };
};

// The neutral operation class. ⛔ THIS IS A WIDENING OF THE MAPPING.md `EVENT.op` SET, NOT A
// REPLACEMENT: that contract's `read`/`write` split is a CLASSIFICATION (it reads the open flags
// and decides), and a retained log may not ship a classification in place of its input. So the
// class here names the OPERATION, the raw `call` is kept beside it, and the read/write decision is
// left to whatever classifier reads this file — including one that does not exist yet.
const OP_OF = {
  open: 'open', open_nocancel: 'open', openat: 'open', openat_nocancel: 'open',
  mkdir: 'mkdir', mkdirat: 'mkdir',
  rmdir: 'rmdir',
  unlink: 'unlink', unlinkat: 'unlink',
  rename: 'rename', renameat: 'rename', renamex_np: 'rename', renameatx_np: 'rename',
  link: 'link', linkat: 'link',
  symlink: 'symlink', symlinkat: 'symlink',
  clonefile: 'clone', clonefileat: 'clone', fclonefileat: 'clone',
  truncate: 'truncate',
  chmod: 'chmod', fchmodat: 'chmod', lchmod: 'chmod',
  chown: 'chown', lchown: 'chown', fchownat: 'chown',
  mknod: 'mknod',
  undelete: 'undelete', exchangedata: 'exchange',
  setattrlist: 'setattr', setattrlistat: 'setattr',
  setxattr: 'setxattr', removexattr: 'removexattr',
  utimes: 'utimes', utimensat: 'utimes',
};

// Darwin. AT_FDCWD is -2, so a relative path under it resolves against the process cwd exactly as
// a non-`at` call would; any OTHER dirfd means the path is relative to an open directory this
// tracer cannot name, and saying so is the honest answer. A future model that needs those can add
// an fd->path table to the adapter; inventing a resolution here would be a confidently wrong path.
const AT_FDCWD = -2;

const lines = fs.readFileSync(file, 'utf8').split('\n');

const cwds = new Map();      // pid -> cwd, tracked exactly as the decoder tracks it
const parent = new Map();    // pid -> ppid
const lifecycle = new Set(); // pids identified as a lifecycle shell by TODAY's rule
const basename = (p) => (p ?? '').split('/').pop();
const isLifecycleShell = (a0, a1) => /^(sh|bash|dash|zsh)$/.test(basename(a0)) && a1 === '-c';
const mine = (pid) => {
  for (let p = pid, i = 0; p && i < 64; p = parent.get(p), i++) if (lifecycle.has(p)) return true;
  return false;
};

const out = [];
const stats = {
  lines: lines.length, records: 0, unparsed: 0, tracerErrors: 0, tracerErrorTotal: null,
  live: false, byOp: {}, byCall: {}, byErrno: {}, failed: 0, enoent: 0, refusals: 0,
  attributed: 0, unresolvableDirfd: 0, pairedTwoPath: 0, danglingPair: 0,
};
const bump = (o, k) => { o[k] = (o[k] ?? 0) + 1; };

// Two-path operations arrive as two records sharing an `ev`. They are MERGED into one record so
// the pairing survives — `rename(a, b)` is one event with two paths, and two independent records
// lose which `b` went with which `a` the moment two renames interleave on one thread.
const pending = new Map();   // `${pid}:${ev}` -> the p1 record awaiting its p2

let seq = 0;
const push = (rec) => { rec.seq = seq++; out.push(rec); stats.records++; };

// The adapter's END-time aggregations and section headers. They are DERIVED counts — a tally of
// opens and execs by execname — so they are recomputable from the events and are not retained.
// ⛔ THEY ARE MATCHED EXPLICITLY RATHER THAN FALLING THROUGH TO `unparsed`, because `unparsed` is
// the alarm that says the wire format moved and this reader did not. An alarm that is always
// non-zero is not an alarm.
const TRAILER = /^(DTRACE-END$|TRACER-ERROR-TOTAL\||---|\s{2,}\S+\s+\d+\s*$)/;

for (const raw of lines) {
  if (!raw) continue;
  if (raw.startsWith('DTRACE-LIVE|')) { stats.live = true; continue; }
  if (raw.startsWith('TRACER-ERROR-TOTAL|')) {
    const n = Number(raw.split('|')[1]);
    if (Number.isFinite(n)) stats.tracerErrorTotal = n;
    continue;
  }
  if (raw.startsWith('TRACER-ERROR|')) {
    const g = raw.split('|');
    stats.tracerErrors++;
    // ⛔ RETAINED AS A RECORD, NOT COLLAPSED INTO A COUNT. A tracer fault means a real event was
    // DROPPED, so a reader of this log must be able to see WHERE in the stream the hole is and
    // which clause made it — a total alone cannot tell you whether the gap is in the package's
    // subtree or in npm's.
    push({
      kind: 'tracer-error', pid: Number(g[1]), ppid: Number(g[2]), comm: g[3],
      detail: g.slice(4).join('|'),
    });
    continue;
  }
  if (TRAILER.test(raw)) continue;
  const f = raw.split('|');
  const kind = f[0];
  const pid = Number(f[1]), ppid = Number(f[2]);
  if (!Number.isFinite(pid)) { if (raw.trim()) stats.unparsed++; continue; }
  if (Number.isFinite(ppid) && ppid > 0) parent.set(pid, ppid);
  if (!cwds.has(pid) && cwds.has(ppid)) cwds.set(pid, cwds.get(ppid));

  if (kind === 'EXECARGV') {
    const argv0 = f[3] ?? '', argv1 = f[4] ?? '', argv2 = f.slice(5).join('|');
    if (isLifecycleShell(argv0, argv1)) lifecycle.add(pid);
    // ⛔ THE FULL ARGV IS WHAT MAKES ATTRIBUTION RECOMPUTABLE. Today's rule is "argv[0] is a shell
    // and argv[1] is -c". A future rule might key on the script BODY, on npm's own exec of
    // `node-gyp`, or on a marker npm sets. None of those can be recovered from a boolean, and all
    // of them can be recovered from this line.
    push({ kind: 'exec', pid, ppid, argv: [argv0, argv1, argv2], lifecycleShell: lifecycle.has(pid) });
    continue;
  }
  if (kind === 'EXEC') {
    push({ kind: 'exec-success', pid, ppid, comm: f[3], psargs: f.slice(4).join('|') });
    continue;
  }
  if (kind === 'CHDIR') {
    const { meta, path } = splitMeta(f, 4);
    if (meta.ret === 0) {
      // Resolution mirrors the decoder's, and the RAW path is retained beside the result so a
      // different resolution rule can be applied later without re-running anything.
      const base = path.startsWith('/') ? path : `${cwds.get(pid) ?? ''}/${path}`;
      const parts = [];
      for (const s of base.split('/')) { if (!s || s === '.') continue; if (s === '..') parts.pop(); else parts.push(s); }
      cwds.set(pid, `/${parts.join('/')}`);
    }
    push({ kind: 'chdir', pid, ppid, comm: f[3], path, ret: meta.ret, cwd: cwds.get(pid) ?? null });
    continue;
  }
  if (kind === 'CONN' || kind === 'CONN-OTHERFAMILY') {
    const g = Object.fromEntries(f.slice(4).filter((x) => x.includes('='))
      .map((x) => [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)]));
    push({
      kind: 'event', op: 'connect', call: 'connect', pid, ppid, comm: f[3],
      af: Number(g.af ?? 0), host: kind === 'CONN' ? f[5] : null, port: Number(g.port ?? 0),
      ret: Number(g.ret ?? 0), errno: Number(g.errno ?? 0),
      lifecycle: mine(pid),
    });
    bump(stats.byOp, 'connect');
    continue;
  }
  if (kind !== 'OPEN' && kind !== 'PATHOP') { if (raw.trim()) stats.unparsed++; continue; }

  // OPEN|pid|ppid|comm|flags=..|ret=..|errno=..|<path>
  // PATHOP|pid|ppid|comm|<call>|ret=..|errno=..|[ev=..][dirfd=..][role=..]|<path>
  const call = kind === 'OPEN' ? 'open' : f[4];
  const { meta, path } = splitMeta(f, kind === 'OPEN' ? 4 : 5);
  const attributed = mine(pid);
  const rec = {
    kind: 'event',
    op: OP_OF[call] ?? call,
    call,
    pid, ppid, comm: f[3],
    path,
    // The cwd AT THIS INSTANT. A relative path plus this is losslessly re-resolvable under any
    // future rule; a pre-resolved absolute path is not, because the rule is baked in.
    cwd: cwds.get(pid) ?? null,
    ret: meta.ret ?? null,
    errno: meta.errno ?? 0,
    lifecycle: attributed,
  };
  if (meta.flags !== undefined) rec.flags = meta.flags;
  if (meta.mode !== undefined) rec.mode = meta.mode;
  if (meta.dirfd !== undefined) {
    rec.dirfd = meta.dirfd;
    // ⛔ REPORTED, NEVER GUESSED. A relative path under a real dirfd cannot be resolved by this
    // tracer, and resolving it against the cwd anyway produces a plausible path that no process
    // ever touched — the same class of defect as billing a symlink's TARGET as a written path.
    if (meta.dirfd !== AT_FDCWD && !path.startsWith('/')) {
      rec.pathUnresolvable = true;
      stats.unresolvableDirfd++;
    }
  }

  if (attributed) stats.attributed++;
  bump(stats.byOp, rec.op);
  bump(stats.byCall, call);
  if (rec.ret !== null && rec.ret < 0) {
    stats.failed++;
    bump(stats.byErrno, String(rec.errno));
    if (rec.errno === 2) stats.enoent++;
    if (rec.errno === 1 || rec.errno === 13 || rec.errno === 30) stats.refusals++;
  }

  // Merge the two halves of a two-path operation.
  if (meta.role === 'p1' && meta.ev !== undefined) {
    pending.set(`${pid}:${meta.ev}`, rec);
    continue;
  }
  if (meta.role === 'p2' && meta.ev !== undefined) {
    const first = pending.get(`${pid}:${meta.ev}`);
    if (first) {
      pending.delete(`${pid}:${meta.ev}`);
      first.path2 = path;
      if (rec.dirfd !== undefined) first.dirfd2 = rec.dirfd;
      if (rec.pathUnresolvable) first.path2Unresolvable = true;
      stats.pairedTwoPath++;
      push(first);
      continue;
    }
    // ⛔ A p2 WITH NO p1 IS A DROPPED EVENT, NOT A MALFORMED ONE — and it is exactly the shape the
    // truncated-`self->np2` defect produced in reverse. It is retained on its own rather than
    // discarded, and counted, because the count is what says the pairing is incomplete.
    stats.danglingPair++;
    rec.unpaired = true;
    push(rec);
    continue;
  }
  push(rec);
}
// Any p1 still pending never got its p2: the destination record was lost.
for (const rec of pending.values()) { rec.missingPair = true; stats.danglingPair++; push(rec); }

// ── OPTIONAL FILTERS, each measured before it is applied ───────────────────────────────────────
const dropEnoent = has('--drop-enoent');
const jailed = has('--jailed');
if (dropEnoent && jailed) {
  // ⛔ ENOENT IS NOT A SAFE DROP FROM A JAILED TRACE. A confinement layer that HIDES a path reports
  // it missing rather than refused — Linux mount-namespace hiding and macOS Seatbelt both do this —
  // so in a jailed run an ENOENT can BE the refusal. The filter is refused rather than silently
  // narrowed, because a log that quietly dropped the refusals would look complete.
  console.error('macos-eventlog: --drop-enoent REFUSED on a jailed trace; ENOENT can be a refusal there');
  process.exit(2);
}
const kept = dropEnoent ? out.filter((e) => !(e.kind === 'event' && e.ret !== null && e.ret < 0 && e.errno === 2)) : out;

const meta = {
  kind: 'meta',
  schema: 1,
  platform: 'darwin',
  tracer: 'dtrace/macos-observe.d',
  producer: 'macos-eventlog.mjs',
  pkg: val('--pkg', null),
  project: val('--project', null),
  home: val('--home', null),
  jailed,
  // ⛔ THE ROOTS ARE RECORDED, NOT THE SCOPES. Scope assignment is longest-prefix against roots
  // passed IN (MAPPING.md rule 2), so a reader holding the roots can compute today's scopes AND
  // tomorrow's — including a `tmp` scope that did not exist when this was measured.
  filters: dropEnoent ? ['drop-enoent'] : [],
  stats,
  at: new Date().toISOString(),
};

const outPath = val('--out');
const body = [JSON.stringify(meta), ...kept.map((e) => JSON.stringify(e))].join('\n') + '\n';
if (outPath && !has('--stats-only')) {
  fs.writeFileSync(outPath, body);
  fs.writeFileSync(`${outPath}.gz`, zlib.gzipSync(Buffer.from(body), { level: 9 }));
}

const gz = zlib.gzipSync(Buffer.from(body), { level: 9 }).length;
console.log(JSON.stringify({
  ...stats,
  emitted: kept.length,
  bytes: Buffer.byteLength(body),
  gzipBytes: gz,
  enoentFraction: stats.records ? +(stats.enoent / stats.records).toFixed(4) : 0,
  out: outPath ?? null,
}, null, 2));
