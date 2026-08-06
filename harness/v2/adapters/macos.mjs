// macOS god-mode observation adapter for the build-jail catalog generator.
//
// Emits the normalized EVENT stream defined in ../MAPPING.md and nothing else. All scope and grant
// logic lives downstream in the shared classifier, so this file must never learn what `deps` or
// `userHome` mean — it reports what happened, with real pids, and stops.
//
//   usage: sudo node macos.mjs --out events.ndjson [--diag diag.json] -- <command> [args...]
//
// WHY TWO SOURCES. Neither macOS instrument satisfies the contract alone, and the split is not a
// style choice — it falls out of what each one structurally cannot see:
//
//   eslogger   root, Apple-signed (no custom entitlement needed). Emits ES events as JSON with the
//              FULL path, the real pid AND ppid, and the open FLAGS. It is the only macOS source
//              that carries a pid at all, so every attributed event comes from here.
//              CANNOT see: TCP connects (ES has no such event — `uipc_connect` is UNIX-domain
//              only), and refusals (NOTIFY events fire on operations that were allowed).
//
//   fs_usage   root. Sees the refusals eslogger cannot, as a NUMERIC errno, and sees AF_INET
//              socket/connect. But it prints `command.threadid`, NEVER a pid — so nothing it
//              reports can be attributed exactly. See README-macos.md.
//
// ⛔ WHAT THIS ADAPTER DELIBERATELY DOES NOT EMIT: a connect event carrying `host`/`port`. No macOS
// god-mode source has them. fs_usage formats connect as FMT_FD (source: system_cmds/fs_usage.c,
// `SYSCALL_WITH_NOCANCEL(connect, FMT_FD)`) — fd and errno, never the sockaddr; ES has no TCP event
// at all. Inventing a peer to fill the field is precisely the over-report the contract forbids, so
// connect events are emitted WITHOUT those fields and the gap is reported in the diagnostics.
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const argv = process.argv.slice(2);
const dashdash = argv.indexOf('--');
if (dashdash < 0) { console.error('usage: sudo node macos.mjs --out <file> [--diag <file>] -- <cmd> [args]'); process.exit(2); }
const opts = argv.slice(0, dashdash), cmd = argv.slice(dashdash + 1);
const optOf = (n) => { const i = opts.indexOf(n); return i < 0 ? null : opts[i + 1]; };
const outPath = optOf('--out') ?? 'events.ndjson';
const diagPath = optOf('--diag');
if (!cmd.length) { console.error('no command given after --'); process.exit(2); }
if (process.getuid() !== 0) { console.error('macos.mjs must run as root: eslogger and fs_usage both require uid 0'); process.exit(2); }

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-adapter-'));
const esLog = path.join(work, 'eslogger.json');
const fsLog = path.join(work, 'fs_usage.txt');
const diag = { warnings: [], errors: [], counts: {} };
const fail = (m) => { diag.errors.push(m); console.error(`macos.mjs: FATAL ${m}`); };

// ─── 1. START THE TRACERS, AND PROVE THEY ARE LIVE ────────────────────────────────────────────
//
// A tracer that had not finished subscribing when the command ran produces an EMPTY stream, and an
// empty stream passes every "did we over-report?" check trivially. That is a probe measuring
// nothing while looking green. So readiness is not a sleep — it is a positive control: touch a
// sentinel path in a loop until the tracer's own output proves it saw it.
const ES_EVENTS = ['open', 'create', 'unlink', 'rename', 'link', 'truncate', 'exec', 'fork', 'exit'];
const esOut = fs.openSync(esLog, 'w');
const es = spawn('/usr/bin/eslogger', ES_EVENTS, { stdio: ['ignore', esOut, esOut] });
const fsOut = fs.openSync(fsLog, 'w');
// `-w` forces the wide format. It is NOT cosmetic: it is also what puts microseconds in the
// timestamp and the threadid on the command name. Path width still runs out — see checkTruncation.
const fsu = spawn('/usr/bin/fs_usage', ['-w', '-f', 'filesys', '-f', 'network'], { stdio: ['ignore', fsOut, fsOut] });

const sentinelDir = fs.mkdtempSync(path.join(work, 'sentinel-'));
const waitReady = (label, logFile, needle) => {
  const deadline = Date.now() + 30_000;
  let n = 0;
  while (Date.now() < deadline) {
    const s = path.join(sentinelDir, `probe-${n++}`);
    try { fs.writeFileSync(s, 'x'); fs.readFileSync(s); fs.unlinkSync(s); } catch { /* keep poking */ }
    let body = '';
    try { body = fs.readFileSync(logFile, 'utf8'); } catch { /* not yet */ }
    if (body.includes(needle)) return true;
    spawnSync('/bin/sleep', ['0.2']);
  }
  fail(`${label} never observed its own sentinel within 30s — the tracer is NOT live and any result would be vacuous`);
  return false;
};
const esReady = waitReady('eslogger', esLog, 'probe-');
const fsReady = waitReady('fs_usage', fsLog, 'probe-');

// ─── 2. RUN THE COMMAND ───────────────────────────────────────────────────────────────────────
// Dropped to the invoking (non-root) user when available. The fixture's EACCES check is meaningless
// under root, which bypasses mode bits entirely.
const asUser = process.env.SUDO_USER;
// `sudo -u` resets PATH to secure_path, which has neither npm nor a hosted node — so the traced
// command must be handed the PATH it would have had. Without this an `npm install` under
// observation fails with "command not found" and the trace is of nothing.
// sudo also drops everything else the caller set, so anything the traced command was configured
// with — including a fixture's control variable — has to be carried across explicitly.
const DROP = new Set(['SUDO_USER', 'SUDO_UID', 'SUDO_GID', 'SUDO_COMMAND', 'USER', 'LOGNAME', 'HOME', 'MAIL', 'SHELL']);
const forwarded = Object.entries(process.env)
  .filter(([k, v]) => !DROP.has(k) && typeof v === 'string' && !v.includes('\0'))
  .map(([k, v]) => `${k}=${v}`);
const run = asUser
  ? spawnSync('/usr/bin/sudo', ['-u', asUser, '/usr/bin/env', ...forwarded, ...cmd], { stdio: 'inherit' })
  : spawnSync(cmd[0], cmd.slice(1), { stdio: 'inherit' });
const rootMarkerRc = run.status;
spawnSync('/bin/sleep', ['2']);           // let the kernel drain both trace buffers before teardown
es.kill('SIGINT'); fsu.kill('SIGINT');
spawnSync('/bin/sleep', ['1']);
es.kill('SIGKILL'); fsu.kill('SIGKILL');
fs.closeSync(esOut); fs.closeSync(fsOut);

// ─── 3. PARSE eslogger ────────────────────────────────────────────────────────────────────────
// The ES JSON shape is resolved by probing candidate key paths rather than hardcoding one, and a
// miss is a LOUD failure that prints the keys actually present. A silently-wrong extraction here
// would produce a plausible, empty event stream — the worst available outcome.
const dig = (o, dotted) => dotted.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
const first = (o, paths) => { for (const p of paths) { const v = dig(o, p); if (v !== undefined && v !== null) return v; } return undefined; };
const P_PID = ['process.audit_token.pid', 'process.audit_token.remote_pid', 'process.pid', 'process.ppid'];
const P_PPID = ['process.ppid', 'process.parent_audit_token.pid', 'process.original_ppid'];

const esRecords = [];
let esBadJson = 0;
for (const line of fs.readFileSync(esLog, 'utf8').split('\n')) {
  if (!line.trim() || !line.trimStart().startsWith('{')) continue;
  try { esRecords.push(JSON.parse(line)); } catch { esBadJson++; }
}
diag.counts.eslogger_records = esRecords.length;
diag.counts.eslogger_unparsable_lines = esBadJson;
if (esReady && esRecords.length === 0) fail('eslogger produced no parsable records despite passing its sentinel — schema or invocation is wrong');

// ─── 4. THE PID SUBTREE ───────────────────────────────────────────────────────────────────────
// Built as a transitive closure over every (pid, ppid) pair ES reports, seeded from our command's
// direct children. Depth is UNBOUNDED on purpose: the one package the corpus has fully solved comes
// down to a syscall inside a bundled yarn that is a GRANDCHILD of the postinstall, so an adapter
// that stops at the direct child reports a clean run for a package that needs a grant.
const parentOf = new Map();
const commOf = new Map();
for (const r of esRecords) {
  const pid = first(r, P_PID), ppid = first(r, P_PPID);
  if (typeof pid !== 'number') continue;
  if (typeof ppid === 'number' && !parentOf.has(pid)) parentOf.set(pid, ppid);
  const exe = first(r, ['process.executable.path', 'event.exec.target.executable.path']);
  if (typeof exe === 'string') commOf.set(pid, path.basename(exe));
}
const selfPid = process.pid;
const inSubtree = (pid) => {
  // Walk to a root; a pid belongs to us if our own process is an ancestor. Cycle-guarded because a
  // reused pid inside the window can otherwise close a loop.
  const seen = new Set();
  let cur = pid;
  for (let i = 0; i < 200 && cur != null && !seen.has(cur); i++) {
    if (cur === selfPid) return true;
    seen.add(cur);
    cur = parentOf.get(cur);
  }
  return false;
};
const subtreePids = new Set([...parentOf.keys()].filter(inSubtree));
diag.counts.subtree_pids = subtreePids.size;
diag.subtree_commands = [...new Set([...subtreePids].map((p) => commOf.get(p)).filter(Boolean))];

// ─── 5. eslogger → EVENTS ─────────────────────────────────────────────────────────────────────
// Write intent is read from the OPEN FLAGS. By the time bytes move the fd hides the path, so an
// open that never writes still establishes the need for a write grant, and an open that does write
// is invisible as a write if you only watch write(2).
//
// ⛔ ES `fflag` IS THE KERNEL'S FFLAGS, NOT THE USERSPACE O_* FLAGS. They are off by one in the
// access-mode bits, because the kernel stores `oflags + 1`:
//
//     userspace  O_RDONLY=0  O_WRONLY=1  O_RDWR=2
//     kernel     FREAD  =1   FWRITE  =2  FREAD|FWRITE=3
//
// So the userspace value for O_WRONLY (0x0001) is the kernel's value for FREAD. Testing `fflag &
// 0x0001` — the obvious port of the Linux predicate — classifies EVERY READ AS A WRITE, silently,
// and over-grants every package in the corpus. Measured on the runner: a read-only open of a
// results.json reported fflag=32769 (0x8001 = O_EVTONLY|FREAD), which that predicate calls a write.
const F = { READ: 0x0001, WRITE: 0x0002, APPEND: 0x0008, CREAT: 0x0200, TRUNC: 0x0400 };
const isWriteOpen = (fflag) => typeof fflag === 'number'
  && (fflag & (F.WRITE | F.APPEND | F.CREAT | F.TRUNC)) !== 0;
// Path-taking mutators. Each names a write need on its own, independent of any open.
const MUTATORS = { create: 1, unlink: 1, rename: 1, link: 1, truncate: 1 };

const events = [];
let unknownShape = 0, esTruncated = 0;
// ES states truncation EXPLICITLY, per path, as a sibling `path_truncated` boolean. That is
// authoritative and needs no heuristic — unlike the fs_usage side, where truncation has to be
// inferred. A truncated path is DROPPED, never emitted: it would prefix-match the wrong declared
// root downstream and produce a confidently wrong grant.
const takePath = (holder) => {
  if (!holder || typeof holder.path !== 'string') return undefined;
  if (holder.path_truncated === true) { esTruncated++; return undefined; }
  return holder.path;
};
for (const r of esRecords) {
  const pid = first(r, P_PID), ppid = first(r, P_PPID);
  if (typeof pid !== 'number' || !subtreePids.has(pid)) continue;
  const ev = r.event;
  if (!ev || typeof ev !== 'object') { unknownShape++; continue; }
  const kind = Object.keys(ev)[0];
  const body = ev[kind];
  const emit = (op, p) => { if (typeof p === 'string' && p.length) events.push({ op, path: p, result: 'ok', pid, ppid }); };

  if (kind === 'open') {
    emit(isWriteOpen(first(body, ['fflag'])) ? 'write' : 'read', takePath(dig(body, 'file')));
  } else if (kind === 'exec') {
    emit('exec', takePath(dig(body, 'target.executable')));
  } else if (MUTATORS[kind]) {
    // `create` reports either an EXISTING file or a (dir, filename) pair for one that does not
    // exist yet; `rename`/`link` carry a source and a destination and BOTH are write needs.
    const dirName = takePath(dig(body, 'destination.new_path.dir'));
    const leaf = first(body, ['destination.new_path.filename']);
    for (const cand of [
      takePath(dig(body, 'target')) ?? takePath(dig(body, 'source')) ?? takePath(dig(body, 'file')),
      takePath(dig(body, 'destination.existing_file')),
      dirName && typeof leaf === 'string' ? path.join(dirName, leaf) : undefined,
    ]) emit('write', cand);
  }
}

// ─── 6. fs_usage → REFUSALS AND SOCKETS ───────────────────────────────────────────────────────
//
// ⛔ THE macOS REFUSAL PREDICATE, AND WHY THE LINUX ONE SILENTLY REPORTS ZERO HERE.
// Linux's trap is a bare `grep EACCES` also matching the FLAG name `AT_EACCESS` in successful
// faccessat calls — an over-count. The macOS trap is the mirror image and strictly more dangerous:
// fs_usage prints errno NUMERICALLY as `[%3d]` and never emits the symbolic name at all (source:
// fs_usage.c). Porting `grep EACCES` to macOS therefore matches NOTHING and reports a clean run for
// every package — a silent false NEGATIVE, which is the one direction that under-grants.
//
// The correct predicate is a bracketed errno in the fixed-width COLUMN region, and it must be
// position-anchored, because the same `[%3d]` bracket form appears in the PATHNAME column as an
// openat's directory fd, rendered `[ 3]/relative/path`, on ordinary SUCCESSFUL calls. That is the
// true macOS analogue of AT_EACCESS. A free-text `\[\s*\d+\]` scan matches it and invents refusals.
const ERRNO = { 1: 'EPERM', 13: 'EACCES', 30: 'EROFS' };
// Two discriminators, and BOTH are needed. Measured on the runner:
//
//   errno form   `05:18:56.926933  open        [ 13] (R___________)  /path/denied.txt`
//   dirfd form   `05:18:54.164789  renameat                         [4]/F365749A20...`
//
// The dirfd form is the true macOS analogue of `AT_EACCESS`: an ordinary SUCCESSFUL call carrying a
// bracketed number that is not an errno. Filtering it by "is the number a refusal errno?" alone is
// NOT enough — a process holding 13 open fds does `openat` with dirfd 13, which renders `[13]/...`
// and reads as EACCES. So:
//   (a) the errno is printed `[%3d]`, i.e. exactly THREE characters inside the brackets, space
//       padded; the dirfd is printed `[%d]` with no padding.
//   (b) the dirfd bracket is immediately followed by `/` — it is a path prefix, not a column.
const REFUSAL = /^\d\d:\d\d:\d\d\.\d+\s+(\S+)\s+(?:F=-?\d+\s*)?\[(\s{0,2}\d{1,3})\](?!\/)/;
// Calls whose bracketed value is not an errno at all, or that name no path so cannot express a
// filesystem refusal. `exit` is the dangerous member — see the comment at the match site.
const NON_PATH_CALLS = new Set(['exit', 'close', 'close_nocancel', 'read', 'write', 'fcntl',
  'fcntl_nocancel', 'ioctl', 'select', 'kevent', 'kevent_id', 'kevent_qos', 'fsync', 'lseek',
  'dup', 'dup2', 'pipe', 'socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom']);
const AF_INET_SOCKET = /^\d\d:\d\d:\d\d\.\d+\s+socket\s+.*AF_INET/;
const CONNECT_LINE = /^\d\d:\d\d:\d\d\.\d+\s+connect/;

const fsLines = fs.readFileSync(fsLog, 'utf8').split('\n');
diag.counts.fs_usage_lines = fsLines.length;
if (fsReady && fsLines.length < 5) fail('fs_usage produced almost no output despite passing its sentinel');

// fs_usage carries no pid, only `command.threadid`. Attribution is therefore by command NAME, and
// only when that name is unambiguous within our subtree. Anything else is DROPPED and counted —
// never assigned a guessed pid, which would put a refusal or a socket on the wrong process.
const subtreeCommands = new Set(diag.subtree_commands);
const commandOfLine = (l) => { const m = l.match(/\s(\S+?)\.\d+\s*$/); return m ? m[1] : null; };
const pidForCommand = (c) => {
  const hits = [...subtreePids].filter((p) => commOf.get(p) === c);
  return hits.length === 1 ? hits[0] : null;
};

// ⛔ TRUNCATION. fs_usage stores the path at MAXPATHLEN but PRINTS only `columns - overhead` bytes,
// and when it overflows it prints the TAIL with no ellipsis and no marker (source: fs_usage.c —
// `pathname = &buf[len - clen]`). A tail-trimmed absolute path is the dangerous case: it silently
// stops matching any declared root and lands in the unmapped bucket, or worse matches the wrong
// one. `-w` raises the budget to MAX_WIDE_MODE_COLS(264) minus overhead; it does not remove the
// limit. So every path taken from fs_usage is checked, and a suspect one FAILS LOUDLY.
// Two distinct incomplete-path signals, both measured on the runner:
//
//  (a) TAIL TRIM. A 124-char path printed in full; a 164-char one printed as
//      `unner/recon-1iFd0J/len160/f...` — the leading `/Users/r` simply gone, no ellipsis. So an
//      absolute path that does not START with `/` was trimmed. (The `[3]/rel` openat form is the
//      one legitimate exception and is excluded.)
//
//  (b) `>` PADDING. The KERNEL, not fs_usage, pads a VFS_LOOKUP record with `>` when there is more
//      path beyond the component it resolved (xnu bsd/vfs/vfs_lookup.c). Observed live as
//      `/System/Volumes/Data/private/var/root/Library>>>>>>>>>>>`. That string is a valid-looking
//      absolute path, so signal (a) does NOT catch it — it would be scope-assigned to whatever root
//      `/System/...` matches and silently produce a wrong answer.
let truncated = 0;
const looksTruncated = (p) => !!p && ((!p.startsWith('/') && !/^\[\d+\]\//.test(p)) || p.includes('>'));

let sockets = 0, connects = 0, droppedUnattributable = 0;
const denials = [];
for (const raw of fsLines) {
  const line = raw.trimEnd();
  if (!line) continue;
  if (AF_INET_SOCKET.test(line)) sockets++;
  if (CONNECT_LINE.test(line)) connects++;
  const m = line.match(REFUSAL);
  if (!m) continue;
  // `[%3d]` is exactly three characters wide. A shorter one is an unpadded `[%d]` — a dirfd or a
  // count that happens to sit in this position, not an errno column.
  if (m[2].length !== 3) continue;
  // ⛔ A THIRD IMPOSTOR, found in real trace data: `exit` prints the process EXIT STATUS in the very
  // same bracketed column. `05:18:56.927043  exit  [  1]` is a `cat` exiting 1 after its open was
  // refused — three characters wide, value 1, and NOT a refusal. It even sits next to the genuine
  // EACCES it followed, so it reads as corroboration. Calls that take no path can never be one.
  if (NON_PATH_CALLS.has(m[1])) continue;
  const name = ERRNO[Number(m[2].trim())];
  if (!name) continue;                                   // a bracketed errno that is not a refusal
  const comm = commandOfLine(line);
  if (!comm || !subtreeCommands.has(comm)) continue;     // not ours
  // The pathname column is whatever sits between the call/errno prefix and the trailing timing.
  const pm = line.slice(m[0].length).match(/\s(\S+)\s+\d+\.\d+/);
  const p = pm ? pm[1] : null;
  if (p && looksTruncated(p)) { truncated++; continue; }
  const pid = pidForCommand(comm);
  if (pid == null || !p) { droppedUnattributable++; continue; }
  denials.push({ op: 'read', path: p, result: 'denied', pid, ppid: parentOf.get(pid) ?? null });
}
events.push(...denials);

// A connect we saw but cannot attribute to a pid, and whose peer no macOS source exposes, is still
// evidence that the package needs network. It is emitted with the fields that ARE known and the
// missing ones OMITTED rather than filled in.
if (connects > 0 || sockets > 0) {
  const root = [...subtreePids][0];
  events.push({ op: 'connect', result: 'ok', ...(root != null ? { pid: root, ppid: parentOf.get(root) ?? null } : {}) });
}

diag.counts.af_inet_sockets = sockets;
diag.counts.connect_calls = connects;
diag.counts.refusals = denials.length;
diag.counts.dropped_unattributable = droppedUnattributable;
diag.counts.fs_usage_truncated_paths_rejected = truncated;
diag.counts.eslogger_truncated_paths_rejected = esTruncated;
diag.counts.events = events.length;
diag.counts.unknown_es_event_shape = unknownShape;
diag.command_rc = rootMarkerRc;
if (truncated > 0) diag.warnings.push(`${truncated} fs_usage path(s) were tail-truncated and REJECTED rather than emitted`);
if (droppedUnattributable > 0) diag.warnings.push(`${droppedUnattributable} fs_usage event(s) dropped: no unambiguous pid`);
diag.warnings.push('connect events carry NO host/port: no macOS god-mode source exposes the peer sockaddr');

fs.writeFileSync(outPath, events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : ''));
if (diagPath) fs.writeFileSync(diagPath, JSON.stringify(diag, null, 2));
diag.raw = { eslogger: esLog, fs_usage: fsLog };
console.error(`macos.mjs: ${events.length} events -> ${outPath}`);
console.error(JSON.stringify(diag.counts));
for (const w of diag.warnings) console.error(`macos.mjs: WARN ${w}`);
process.exit(diag.errors.length ? 1 : 0);
