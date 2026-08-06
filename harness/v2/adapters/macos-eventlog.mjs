// dtrace trace.txt -> a QUERYABLE view of it (NDJSON). Derived; regenerable; not the archive.
//
// ⛔⛔ READ THIS FIRST: THIS FILE'S OUTPUT IS A CACHE. The artifact of record is the RAW dtrace
// output, `trace.txt.gz`, published beside `capture.json` in the same record dir. A normalized
// event stream bakes in TODAY'S DECODER exactly the way a scope tag bakes in today's classifier,
// and that is not a hypothetical:
//
//   * this adapter lost 100% of rename DESTINATIONS for its entire existence, silently. Every
//     normalized log written in that era would have carried the hole forward, permanently.
//   * the Linux decoder retained 18 of 27 known writes against a C fixture where its rewrite
//     retains 26 of 26. Nine losses, invisible, unrecoverable without the raw.
//
// With the raw archived, a bug in THIS FILE is a re-parse. Without it, a re-measure — or a hole
// nobody can see. So: if this file and the raw trace ever disagree, the raw trace is right.
//
// ⛔ IT IS NOT REQUIRED TO MATCH ANOTHER PLATFORM, AND MUST NOT BE TRIMMED TO THE INTERSECTION.
// Per-OS formats with per-OS parsers is the settled shape. Demanding one shared key set across
// three tracers is itself a canonicalization: it would force this lane to drop whatever dtrace
// exposes that strace and ETW do not — which is the same lossy-classification failure as scope
// tags, one level out. A macOS-only field is a REASON to capture it.
//
// In practice it DOES line up with `adapters/linux.mjs` today, because agreeing where agreement is
// free makes a cross-platform query (`../eventlog-query.mjs`) writable once instead of three times:
// `k`/`v`/`h` header, `k:"p"` process rows, `k:"e"` events with `p` pid, `o` class, `s` syscall,
// `f`/`g` paths, `r` errno symbol, `fl` flags, `w` write intent, `n` repeat count, `u`/`u2`
// unresolved base. `fixtures/schema-contract.test.mjs` watches that alignment and is ADVISORY —
// where conformance would cost fidelity, fidelity wins and the test gets relaxed.
//
// What is still true regardless of which file is the archive:
//
//   1. NOTHING DERIVED STANDS IN FOR ITS INPUT. No scope tags — the `tmp` scope added while this
//      was being written did not exist at measurement time, and a scope-tagged log would have
//      needed a re-measure to gain it. The header's `roots` make every scope recomputable instead.
//   2. THE RAW SYSCALL SURVIVES ALONGSIDE THE NEUTRAL CLASS. `o` is the class a shared classifier
//      reads; `s` is what the kernel saw. Telling `unlink` (destroys) from `mkdir` (creates), or an
//      atomic `renameatx_np` swap from an ordinary rename, needs `s`.
//
// ⛔ THREE THINGS THIS PLATFORM CARRIES THAT LINUX DOES NOT, all additive so a reader filtering on
// `k` is unaffected:
//   `k:"x"`  — the TRACER LOSS LEDGER. dtrace aborts a whole clause on a copyin fault, so the event
//              is dropped; a truncated `self->np2` lost 100% of rename destinations for as long as
//              the adapter existed, silently, because dtrace's complaint went to a stderr file
//              nothing read. A dropped event is a path never seen and therefore a capability never
//              granted, so WHERE the stream has holes has to be in the stream. strace has no
//              analogue, which is why Linux has no such record.
//   `dfd`    — the numeric dirfd, kept beside `u`. Linux resolves dirfds through its own fd table
//              and only needs to report the base; this file builds an fd table too (from its own
//              OPEN returns) but a dirfd opened before the trace started is still unresolvable, and
//              the raw value is what a later parser needs to do better.
//   `fd`     — on an FD-ONLY MUTATOR whose fd the table could not resolve. `fchmod`/`fchown`/
//              `ftruncate`/`fsetattrlist` are writes that name NO path — 37 of the 86 path-mutating
//              calls the census workload issued, and the half that subscribing the `*at` family
//              could not close. Where the fd IS known they resolve to a real path; where it is not,
//              the record is kept with the raw fd and no path, never a guessed one.
//
// ⛔ NOTHING IS FILTERED, AND THAT IS A DECISION. Every filter decides what a future model may see —
// the same trap as a scope tag. The one filter that looks unambiguously safe, dropping `ENOENT` on
// the grounds that a file which does not exist needs no grant, is not clean: a failed lookup records
// a FALLBACK the script went looking for, and on a machine where that path exists the same script
// reads it. The Linux lane measured the sharpest version of this — 21,142 of `lmdb-store`'s ENOENT
// probes are the C++ include search path, which HITS on a box with a different gcc layout. So
// ENOENT is retained, `--drop-enoent` exists only to SIZE the alternative, and it is REFUSED
// outright on a jailed trace where an ENOENT can BE the refusal. Repetition is handled by dedup plus
// gzip, which is what actually pays for retention.
//
//   usage: node macos-eventlog.mjs <trace.txt> --out <events.ndjson>
//                                  [--project <dir>] [--home <dir>] [--jail-home <dir>]
//                                  [--pkg <name>] [--version <v>] [--jailed] [--drop-enoent]
import fs from 'node:fs';
import zlib from 'node:zlib';

const EVENT_SCHEMA = 1;

const argv = process.argv.slice(2);
const val = (f, d = null) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const has = (f) => argv.includes(f);
const file = argv.find((a, i) => !a.startsWith('--') && (i === 0 || !argv[i - 1].startsWith('--')));
if (!file) {
  console.error('usage: macos-eventlog.mjs <trace.txt> --out <events.ndjson> [--project D] [--home D]');
  process.exit(2);
}

// ── THE WIRE FORMAT THIS READS ─────────────────────────────────────────────────────────────────
// The adapter emits `|`-delimited records whose PATH IS ALWAYS LAST, because a path is free-form and
// routinely contains `|`. Everything between the fixed header fields and the path is a `key=value`
// token, so the adapter can gain a field without renumbering the ones after it. A path is never
// mistaken for a token because only these KEYS are recognised.
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

// The adapter's END-time aggregations and section headers: DERIVED tallies of opens and execs by
// execname, recomputable from the events, so not retained. ⛔ MATCHED EXPLICITLY rather than left to
// fall through to `unparsed`, because `unparsed` is the alarm that says the wire format moved and
// this reader did not. An alarm that is always non-zero is not an alarm.
const TRAILER = /^(DTRACE-END$|---|\s{2,}\S+\s+\d+\s*$)/;

// ⛔ THE RESULT IS THE ERRNO SYMBOL, NOT `ok|denied`. `denied` collapses ENOENT, EACCES, EEXIST and
// ENOTDIR into one word, and they are four different answers about what a grant would have to do.
// Darwin's numbering is its own — EAGAIN is 35 here and 11 on Linux — so the table is Darwin's, and
// an unmapped value falls back to `E<n>`, which keeps the number recoverable rather than losing it.
const ERRNO = {
  1: 'EPERM', 2: 'ENOENT', 3: 'ESRCH', 4: 'EINTR', 5: 'EIO', 6: 'ENXIO', 7: 'E2BIG', 8: 'ENOEXEC',
  9: 'EBADF', 10: 'ECHILD', 11: 'EDEADLK', 12: 'ENOMEM', 13: 'EACCES', 14: 'EFAULT', 15: 'ENOTBLK',
  16: 'EBUSY', 17: 'EEXIST', 18: 'EXDEV', 19: 'ENODEV', 20: 'ENOTDIR', 21: 'EISDIR', 22: 'EINVAL',
  23: 'ENFILE', 24: 'EMFILE', 25: 'ENOTTY', 26: 'ETXTBSY', 27: 'EFBIG', 28: 'ENOSPC', 29: 'ESPIPE',
  30: 'EROFS', 31: 'EMLINK', 32: 'EPIPE', 33: 'EDOM', 34: 'ERANGE', 35: 'EAGAIN', 36: 'EINPROGRESS',
  37: 'EALREADY', 38: 'ENOTSOCK', 39: 'EDESTADDRREQ', 40: 'EMSGSIZE', 41: 'EPROTOTYPE',
  42: 'ENOPROTOOPT', 43: 'EPROTONOSUPPORT', 45: 'ENOTSUP', 47: 'EAFNOSUPPORT', 48: 'EADDRINUSE',
  49: 'EADDRNOTAVAIL', 50: 'ENETDOWN', 51: 'ENETUNREACH', 53: 'ECONNABORTED', 54: 'ECONNRESET',
  55: 'ENOBUFS', 56: 'EISCONN', 57: 'ENOTCONN', 60: 'ETIMEDOUT', 61: 'ECONNREFUSED', 62: 'ELOOP',
  63: 'ENAMETOOLONG', 65: 'EHOSTUNREACH', 66: 'ENOTEMPTY', 68: 'EUSERS', 69: 'EDQUOT', 70: 'ESTALE',
  78: 'ENOSYS', 79: 'EFTYPE', 89: 'ECANCELED', 92: 'ENOATTR',
};
const errnoName = (n) => (n === 0 ? 0 : (ERRNO[n] ?? `E${n}`));

// Darwin open(2) flags, spelled symbolically to match the Linux lane's `fl`. ⛔ WRITE INTENT LIVES
// ONLY HERE: by the time write(2) runs the fd has hidden the path, so an open that never writes
// still establishes the need for a write grant.
const OFLAGS = [
  [0x0004, 'O_NONBLOCK'], [0x0008, 'O_APPEND'], [0x0010, 'O_SHLOCK'], [0x0020, 'O_EXLOCK'],
  [0x0040, 'O_ASYNC'], [0x0080, 'O_SYNC'], [0x0100, 'O_NOFOLLOW'], [0x0200, 'O_CREAT'],
  [0x0400, 'O_TRUNC'], [0x0800, 'O_EXCL'], [0x8000, 'O_EVTONLY'], [0x20000, 'O_NOCTTY'],
  [0x100000, 'O_DIRECTORY'], [0x200000, 'O_SYMLINK'], [0x400000, 'O_DSYNC'],
  [0x1000000, 'O_CLOEXEC'], [0x20000000, 'O_NOFOLLOW_ANY'],
];
const flagText = (fl) => {
  const mode = ['O_RDONLY', 'O_WRONLY', 'O_RDWR'][fl & 0x3] ?? 'O_ACCMODE3';
  const rest = OFLAGS.filter(([b]) => (fl & b) !== 0).map(([, n]) => n);
  return [mode, ...rest].join('|');
};
const WRITE_FLAG = /O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)/;

// The neutral operation class, spelled as the Linux adapter spells it so one classifier reads both.
const OP_OF = {
  open: 'open', open_nocancel: 'open', openat: 'open', openat_nocancel: 'open',
  mkdir: 'mkdir', mkdirat: 'mkdir',
  rmdir: 'rmdir',
  unlink: 'unlink', unlinkat: 'unlink',
  rename: 'rename', renameat: 'rename', renameatx_np: 'rename',
  link: 'link', linkat: 'link',
  symlink: 'symlink', symlinkat: 'symlink',
  clonefileat: 'clone', fclonefileat: 'clone', copyfile: 'clone',
  truncate: 'truncate',
  chmod: 'chmod', fchmodat: 'chmod',
  chown: 'chown', lchown: 'chown', fchownat: 'chown',
  mknod: 'mknod', mkfifo: 'mknod',
  undelete: 'undelete', exchangedata: 'exchange',
  setattrlist: 'setattr', setattrlistat: 'setattr',
  setxattr: 'setxattr', removexattr: 'removexattr',
  utimes: 'utimes',
  // Read-side path syscalls. No grant model reads these today — a read-derived grant would be
  // `read:"disk"` for every package, since every process reads dyld's shared cache — but `open` is
  // not the only way to READ a path, and a script that only `stat`s a file leaves no open record at
  // all. Captured so a future read-scope model is a re-parse rather than a re-measure.
  stat: 'stat', stat64: 'stat', lstat: 'stat', lstat64: 'stat',
  fstatat: 'stat', fstatat64: 'stat',
  access: 'access', faccessat: 'access',
  readlink: 'readlink', readlinkat: 'readlink',
  getattrlist: 'getattr', getattrlistat: 'getattr',
  getxattr: 'getxattr', listxattr: 'listxattr',
  // FD-only mutators — writes that name no path.
  fchmod: 'chmod', fchown: 'chown', ftruncate: 'truncate',
  fsetattrlist: 'setattr', fsetxattr: 'setxattr', fremovexattr: 'removexattr',
  futimes: 'utimes',
};
// Ops whose very occurrence is a write, independent of any flags word.
const MUTATING = new Set(['mkdir', 'rmdir', 'unlink', 'rename', 'link', 'symlink', 'clone',
  'truncate', 'chmod', 'chown', 'mknod', 'undelete', 'exchange', 'setattr', 'setxattr',
  'removexattr', 'utimes']);

const AT_FDCWD = -2;   // Darwin

// ── DECODE ─────────────────────────────────────────────────────────────────────────────────────
const lines = fs.readFileSync(file, 'utf8').split('\n');

const cwds = new Map();      // pid -> cwd, tracked exactly as the decoder tracks it
const ppidOf = new Map();
const exeOf = new Map();
const argvOf = new Map();
const lifecycle = new Set();
const seenPids = new Set();
// pid -> (fd -> resolved path), built from this stream's own successful OPEN returns. It is what
// lets an fd-only mutator name a path without the tracer having been able to.
const fds = new Map();

const basename = (p) => (p ?? '').split('/').pop();
const isLifecycleShell = (a0, a1) => /^(sh|bash|dash|zsh)$/.test(basename(a0)) && a1 === '-c';
const mine = (pid) => {
  for (let p = pid, i = 0; p && i < 64; p = ppidOf.get(p), i++) if (lifecycle.has(p)) return true;
  return false;
};
const resolve = (pid, p) => {
  if (!p) return p;
  const base = p.startsWith('/') ? p : `${cwds.get(pid) ?? ''}/${p}`;
  const out = [];
  for (const s of base.split('/')) { if (!s || s === '.') continue; if (s === '..') out.pop(); else out.push(s); }
  return `/${out.join('/')}`;
};

const stats = {
  lines: lines.length, parsed: 0, unparsed: 0, live: false,
  tracerErrors: 0, tracerErrorTotal: null,
  unresolvedDirfd: 0, unresolvedFd: 0, pairedTwoPath: 0, danglingPair: 0,
  failed: 0, enoent: 0, refusals: 0, byErrno: {},
};
const events = new Map();    // dedup key -> event, carrying `n`
const lost = new Map();      // fault signature -> count
const pending = new Map();   // `${pid}:${ev}` -> the p1 half awaiting its p2

// ⛔ DEDUP IS ON THE IDENTITY OF THE CALL, NOT ON THE PATH. Same process, same syscall, same paths,
// same result, same flags = the same fact, and `n` keeps the frequency so it stays lossless for a
// capability model. It is NOT lossless for ORDER, which no grant model reads; the chdir events are
// emitted individually so path resolution stays replayable.
const emit = (e) => {
  // ⛔ THE KEY IS JSON, NOT A DELIMITER-JOINED STRING, AND THAT IS A CORRECTNESS CHOICE. Any
  // delimiter has to be a character that cannot appear in a path, a syscall name or an errno
  // symbol — and getting that wrong merges two unrelated events into one with `n:2`, silently,
  // which is indistinguishable from the dedup working. `JSON.stringify` of the tuple sidesteps the
  // question: the encoding is injective, so distinct tuples cannot collide however odd a path is.
  const key = JSON.stringify([e.p, e.s, e.f ?? null, e.g ?? null, e.r, e.fl ?? null]);
  const prev = events.get(key);
  if (prev) { prev.n++; return prev; }
  e.n = 1;
  events.set(key, e);
  return e;
};

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
    const sig = g.slice(4).join('|');
    const k = JSON.stringify([g[1], sig]);   // injective, same reason as the event dedup key
    const prev = lost.get(k);
    if (prev) prev.n++;
    else lost.set(k, { k: 'x', p: Number(g[1]), comm: g[3], sig, n: 1 });
    continue;
  }
  if (TRAILER.test(raw)) continue;
  const f = raw.split('|');
  const kind = f[0];
  const pid = Number(f[1]), ppid = Number(f[2]);
  if (!Number.isFinite(pid)) { if (raw.trim()) stats.unparsed++; continue; }
  seenPids.add(pid);
  if (Number.isFinite(ppid) && ppid > 0) { ppidOf.set(pid, ppid); seenPids.add(ppid); }
  if (!cwds.has(pid) && cwds.has(ppid)) cwds.set(pid, cwds.get(ppid));

  if (kind === 'EXECARGV') {
    const a0 = f[3] ?? '', a1 = f[4] ?? '', a2 = f.slice(5).join('|');
    // ⛔ THE FULL ARGV IS WHAT MAKES ATTRIBUTION RECOMPUTABLE, and it lives in the PROCESS table
    // rather than on each event — the same argument as the scope tags, one level up. Today's rule
    // is "argv[0] is a shell and argv[1] is -c"; a rule that later keys on the script BODY, or on
    // npm's own exec of node-gyp, replays from this and cannot replay from a boolean.
    argvOf.set(pid, JSON.stringify([a0, a1, a2]));
    if (!exeOf.has(pid)) exeOf.set(pid, a0);
    if (isLifecycleShell(a0, a1)) lifecycle.add(pid);
    stats.parsed++;
    continue;
  }
  if (kind === 'EXEC') { exeOf.set(pid, f[3]); stats.parsed++; continue; }
  if (kind === 'CHDIR') {
    const { meta, path } = splitMeta(f, 4);
    const target = resolve(pid, path);
    if (meta.ret === 0) cwds.set(pid, target);
    stats.parsed++;
    emit({ p: pid, o: 'chdir', s: 'chdir', f: target, r: errnoName(meta.errno ?? 0) });
    continue;
  }
  if (kind === 'CONN' || kind === 'CONN-OTHERFAMILY') {
    const kv = Object.fromEntries(f.slice(4).filter((x) => x.includes('='))
      .map((x) => [x.slice(0, x.indexOf('=')), x.slice(x.indexOf('=') + 1)]));
    stats.parsed++;
    // ⛔ A NON-BLOCKING connect() RETURNS EINPROGRESS ON EVERY ARM, INCLUDING TO A CLOSED PORT, so
    // the return value here is NOT a refusal signal — that needs the later getsockopt(SO_ERROR).
    // The record's value is the peer and the fact that an AF_INET connect was attempted, which is
    // exactly what the `network` capability is about.
    emit({ p: pid, o: 'connect', s: 'connect', h: kind === 'CONN' ? f[5] : null,
      pt: Number(kv.port ?? 0), af: Number(kv.af ?? 0), r: errnoName(Number(kv.errno ?? 0)) });
    continue;
  }
  // ⛔ AN FD-ONLY MUTATOR IS A WRITE THAT NAMES NO PATH, and it is 37 of the 86 path-mutating calls
  // the census workload issued — the half subscribing the `*at` family could not close. dtrace
  // cannot resolve the fd, but this stream's own OPEN returns carry (pid, fd, path), so the join
  // happens HERE, in the parser, off the archive. Where the fd is unknown (opened before the trace
  // started, or inherited across a fork this stream did not witness) the record is kept with the
  // raw fd in `u` and NO path — never a guessed one.
  if (kind === 'FDOP') {
    const kv = Object.fromEntries(f.slice(5).filter((x) => x.includes('='))
      .map((x) => [x.slice(0, x.indexOf('=')), Number(x.slice(x.indexOf('=') + 1))]));
    const call = f[4];
    const resolved = fds.get(pid)?.get(kv.fd);
    stats.parsed++;
    if (resolved === undefined) stats.unresolvedFd++;
    const e = { p: pid, o: OP_OF[call] ?? call, s: call, f: resolved ?? null,
      r: errnoName(kv.errno ?? 0), w: 1 };
    if (resolved === undefined) { e.u = `fd:${kv.fd}`; e.fd = kv.fd; }
    emit(e);
    continue;
  }
  if (kind !== 'OPEN' && kind !== 'PATHOP' && kind !== 'STATOP') {
    if (raw.trim()) stats.unparsed++;
    continue;
  }

  const isOpen = kind === 'OPEN';
  const call = isOpen ? 'open' : f[4];
  const { meta, path } = splitMeta(f, isOpen ? 4 : 5);
  if (!path) continue;
  stats.parsed++;
  const errno = meta.errno ?? 0;
  if (meta.ret !== undefined && meta.ret < 0) {
    stats.failed++;
    stats.byErrno[errnoName(errno)] = (stats.byErrno[errnoName(errno)] ?? 0) + 1;
    if (errno === 2) stats.enoent++;
    if (errno === 1 || errno === 13 || errno === 30) stats.refusals++;
  }

  let op = OP_OF[call] ?? call;
  if (isOpen) op = WRITE_FLAG.test(flagText(meta.flags ?? 0)) ? 'open-w' : 'open-r';

  const e = { p: pid, o: op, s: call, f: null, r: errnoName(errno) };
  // ⛔ A RELATIVE PATH UNDER A REAL dirfd IS NOT RESOLVABLE HERE, AND RESOLVING IT ANYWAY INVENTS A
  // PATH NO PROCESS TOUCHED — the same defect class as billing a symlink's TARGET as a written path,
  // which kept a whole capability alive once already. The record is KEPT, the raw relative path is
  // kept, and only the RESOLUTION is withheld: `u` marks it, `dfd` carries the value an fd->path
  // table could resolve later.
  if (meta.dirfd !== undefined && meta.dirfd !== AT_FDCWD && !path.startsWith('/')) {
    e.f = path;
    e.u = String(meta.dirfd);
    e.dfd = meta.dirfd;
    stats.unresolvedDirfd++;
  } else {
    e.f = resolve(pid, path);
  }
  if (isOpen) {
    e.fl = flagText(meta.flags ?? 0);
    // A successful open returns the fd. Recorded against the RESOLVED path so a later FDOP can be
    // joined to it — the table is per-pid only, so an fd inherited across a fork this stream did
    // not witness stays unresolved rather than being attributed to the wrong file.
    if ((meta.ret ?? -1) >= 0 && e.f && !e.u) {
      if (!fds.has(pid)) fds.set(pid, new Map());
      fds.get(pid).set(meta.ret, e.f);
    }
  }
  if (MUTATING.has(op) || op === 'open-w') e.w = 1;

  // Two-path operations arrive as two records sharing an `ev`, and are MERGED so the pairing
  // survives: `rename(a, b)` is ONE event with two paths, and two independent records lose which
  // `b` went with which `a` the moment two renames interleave on one thread.
  if (meta.role === 'p1' && meta.ev !== undefined) { pending.set(`${pid}:${meta.ev}`, e); continue; }
  if (meta.role === 'p2' && meta.ev !== undefined) {
    const first = pending.get(`${pid}:${meta.ev}`);
    if (first) {
      pending.delete(`${pid}:${meta.ev}`);
      first.g = e.f;
      if (e.u !== undefined) { first.u2 = e.u; first.dfd2 = e.dfd; }
      stats.pairedTwoPath++;
      emit(first);
      continue;
    }
    // ⛔ A p2 WITH NO p1 IS A DROPPED EVENT, NOT A MALFORMED ONE — the exact shape the truncated
    // `self->np2` produced in reverse. Retained on its own and counted, because the count is what
    // says the pairing is incomplete.
    stats.danglingPair++;
    e.unpaired = 1;
    emit(e);
    continue;
  }
  emit(e);
}
// A p1 still pending never got its p2: the destination record was lost.
for (const e of pending.values()) { e.missingPair = 1; stats.danglingPair++; emit(e); }

// ── OPTIONAL FILTER, measured before it is applied ─────────────────────────────────────────────
const dropEnoent = has('--drop-enoent');
const jailed = has('--jailed');
if (dropEnoent && jailed) {
  // ⛔ ENOENT IS NOT A SAFE DROP FROM A JAILED TRACE. A confinement layer that HIDES a path reports
  // it MISSING rather than refused — Linux mount-namespace hiding and macOS Seatbelt both do — so
  // there an ENOENT can BE the refusal. Refused loudly rather than silently narrowed, because a log
  // that quietly dropped the refusals would still look complete.
  console.error('macos-eventlog: --drop-enoent REFUSED on a jailed trace; ENOENT can be a refusal there');
  process.exit(2);
}
const all = [...events.values()];
const kept = dropEnoent ? all.filter((e) => e.r !== 'ENOENT') : all;

// ── SERIALIZE ──────────────────────────────────────────────────────────────────────────────────
const project = val('--project');
const home = val('--home');
const pkg = val('--pkg');
const header = {
  k: 'h', v: EVENT_SCHEMA,
  platform: `darwin-${process.arch}`,
  pkg, version: val('--version'),
  tracer: 'dtrace -s adapters/macos-observe.d',
  // ⛔ THE ROOTS ARE THE WHOLE REASON A RE-PARSE IS POSSIBLE. Every path in the stream is
  // machine-specific (`/Users/runner/v2m-hNdvB5/...`); without these a future classifier cannot tell
  // a project write from a home write and the log is a pile of strings. The roots are recorded and
  // the SCOPES are not, which is what keeps a scope set that does not exist yet derivable.
  roots: { project, home, jailHome: val('--jail-home'),
    ownPkg: pkg && project ? `${project}/node_modules/${pkg}` : null },
  filters: dropEnoent ? ['drop-enoent'] : [],
  jailed,
  at: new Date().toISOString(),
  stats,
};

// Attribution is stored PER PROCESS, never folded into an event — if the attribution RULE changes a
// re-parse recomputes it from `ppid` + `exe` + `argv`; stamped on each event it could only ever be
// re-measured.
const procs = [...seenPids].sort((a, b) => a - b).map((p) => ({
  k: 'p', pid: p, ppid: ppidOf.get(p) ?? null, exe: exeOf.get(p) ?? null,
  argv: argvOf.get(p) ?? null, cwd: cwds.get(p) ?? null, life: mine(p) ? 1 : 0,
}));

const out = [JSON.stringify(header)];
for (const p of procs) out.push(JSON.stringify(p));
for (const x of [...lost.values()].sort((a, b) => b.n - a.n)) out.push(JSON.stringify(x));
// Sorted by path then pid: adjacent lines share long prefixes, which is most of why this compresses
// as well as it does.
for (const e of kept.slice().sort((a, b) =>
  (a.f ?? '').localeCompare(b.f ?? '') || a.p - b.p || a.o.localeCompare(b.o))) {
  out.push(JSON.stringify({ k: 'e', ...e }));
}
const body = `${out.join('\n')}\n`;

const outPath = val('--out');
if (outPath) {
  fs.writeFileSync(outPath, body);
  fs.writeFileSync(`${outPath}.gz`, zlib.gzipSync(Buffer.from(body), { level: 9 }));
}
console.log(JSON.stringify({
  ...stats,
  procs: procs.length, lifecyclePids: lifecycle.size,
  distinctEvents: all.length, emitted: kept.length,
  calls: all.reduce((a, e) => a + e.n, 0),
  bytes: Buffer.byteLength(body),
  gzipBytes: zlib.gzipSync(Buffer.from(body), { level: 9 }).length,
  out: outPath,
}, null, 2));
