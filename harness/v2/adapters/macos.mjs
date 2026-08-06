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
const esErrLog = path.join(work, 'eslogger.stderr');
const fsLog = path.join(work, 'fs_usage.txt');
const fsErrLog = path.join(work, 'fs_usage.stderr');
const psLog = path.join(work, 'ps-samples.txt');
const diag = { warnings: [], errors: [], counts: {} };
const fail = (m) => { diag.errors.push(m); console.error(`macos.mjs: FATAL ${m}`); };

// ─── 1. START THE TRACERS, AND PROVE THEY ARE LIVE ────────────────────────────────────────────
//
// A tracer that had not finished subscribing when the command ran produces an EMPTY stream, and an
// empty stream passes every "did we over-report?" check trivially. That is a probe measuring
// nothing while looking green. So readiness is not a sleep — it is a positive control: touch a
// sentinel path in a loop until the tracer's own output proves it saw it.
// ⛔ EACH TRACER'S STDERR GOES TO ITS OWN FILE, NEVER MERGED INTO THE DATA STREAM. Merging them
// (`stdio: ['ignore', out, out]`) is not merely untidy — it DESTROYS the only evidence of a tracer
// that failed, because the parser below skips every line not starting with `{` and does not even
// count it. Measured on run 2: eslogger produced 8341 records over a ~90s window while fs_usage
// produced 339811 lines over the same window, i.e. eslogger stopped early — and whatever it said
// about why went into the JSON file and was silently discarded. Never again.
const ES_EVENTS = ['open', 'create', 'unlink', 'rename', 'link', 'truncate', 'exec', 'fork'];
const esOut = fs.openSync(esLog, 'w');
const esErr = fs.openSync(esErrLog, 'w');
// ⛔ `detached: true` IS THE LOAD-BEARING FLAG ON THIS LINE, AND IT IS NOT ABOUT PROCESS LIFETIME.
// From eslogger(1), verbatim: "To avoid feedback loops when filtering output using shell pipelines,
// eslogger automatically suppresses events for all processes that are part of its process group."
//
// node's `spawn` leaves a child in the PARENT's process group, so an eslogger started the obvious
// way suppresses the adapter, the traced command, and every descendant — precisely the processes we
// exist to observe. It reports everything ELSE, so the failure has no error, no empty log, and no
// stderr: just a full, healthy-looking stream with our subtree silently absent.
//
// MEASURED on the macos-14 runner before this flag: 6682 records whose top executables were
// mdworker_shared=3291, mds=2763, mds_stores=400, xpcproxy=96, cfprefsd=63, launchd=40 — system
// daemons only, not one `node`/`sh`/`sudo`/`fixture`. The adapter's own sentinel file opens never
// appeared either, which is what the bracket control caught as `pre=false post=false`.
//
// `detached` makes node call setsid(2), putting eslogger in its own session and process group, so
// our tree is no longer "part of its process group". We still kill it by pid, so nothing leaks.
const es = spawn('/usr/bin/eslogger', ES_EVENTS, { stdio: ['ignore', esOut, esErr], detached: true });
const fsOut = fs.openSync(fsLog, 'w');
const fsErr = fs.openSync(fsErrLog, 'w');
// `-w` forces the wide format. It is NOT cosmetic: it is also what puts microseconds in the
// timestamp and the threadid on the command name. Path width still runs out — see looksTruncated.
const fsu = spawn('/usr/bin/fs_usage', ['-w', '-f', 'filesys', '-f', 'network'], { stdio: ['ignore', fsOut, fsErr] });
// Neither tracer's exit is expected before we kill it, so record the fact if one dies on its own.
let esDied = null, fsuDied = null;
es.on('exit', (code, sig) => { if (esDied === null) esDied = { code, sig, at: Date.now() }; });
fsu.on('exit', (code, sig) => { if (fsuDied === null) fsuDied = { code, sig, at: Date.now() }; });

// ─── 1b. AN ANCESTRY SOURCE THAT DOES NOT DEPEND ON eslogger ──────────────────────────────────
// The pid subtree is the load-bearing step: get it wrong and every file event is dropped, which
// looks exactly like "the package touched nothing". Run 2 failed precisely here — `subtree_pids: 0`
// out of 8341 ES records — and an ancestry map built ONLY from ES records cannot survive a tracer
// that drops or stops. So sample `ps` independently and UNION the two edge sets. `ps` misses
// processes shorter-lived than the sample interval; ES misses whatever the tracer dropped. Their
// failure modes are unrelated, which is the entire point of having both.
const psOut = fs.openSync(psLog, 'w');
const psSampler = spawn('/bin/sh', ['-c', 'while :; do /bin/ps -axo pid=,ppid=,comm=; echo "--"; /bin/sleep 0.05; done'], { stdio: ['ignore', psOut, 'ignore'] });

// ⛔ THE READINESS CHECK IS POST-HOC, NOT A POLL, AND THAT IS DELIBERATE. Polling the tracer's log
// for a sentinel cannot work: both tracers write to a FILE, so their stdout is block-buffered, and
// on an idle machine the first block does not flush for a long time. Measured — an eslogger that
// went on to capture 8341 records was declared dead by a 30s poll, because nothing had flushed yet.
//
// Instead the sentinel BRACKETS the run: a burst before, a burst after. Both must be present in the
// final captured log, which proves the tracer was live across the whole window rather than merely
// alive at the start. A tracer that missed either bracket makes the run vacuous and is fatal.
const sentinelDir = fs.mkdtempSync(path.join(work, 'sentinel-'));
const SENTINEL = 'nubobsprobe';
const dropSentinels = (tag) => {
  for (let i = 0; i < 40; i++) {
    const s = path.join(sentinelDir, `${SENTINEL}-${tag}-${i}`);
    try { fs.writeFileSync(s, 'x'); fs.readFileSync(s); fs.unlinkSync(s); } catch { /* best effort */ }
  }
};
spawnSync('/bin/sleep', ['4']);          // subscription latency, both tracers
dropSentinels('pre');

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
// `spawn`, not `spawnSync`, purely to learn the CHILD'S PID. That pid is the subtree seed, and
// seeding from it rather than from this process alone means the closure survives a missing link in
// the ancestry chain (sudo/env may exec without producing an ES record we subscribed to).
const [c0, cargs] = asUser
  ? ['/usr/bin/sudo', ['-u', asUser, '/usr/bin/env', ...forwarded, ...cmd]]
  : [cmd[0], cmd.slice(1)];
const cmdStartedAt = new Date().toISOString();
const child = spawn(c0, cargs, { stdio: 'inherit' });
const childPid = child.pid;
const rootMarkerRc = await new Promise((res) => child.on('exit', (code) => res(code)));
const cmdEndedAt = new Date().toISOString();

dropSentinels('post');
// Whether each tracer was still ALIVE at the end is a first-class result. A tracer that exited on
// its own mid-run makes every "we saw nothing there" conclusion vacuous, and until run 2 that was
// indistinguishable from a genuinely quiet package.
diag.tracer_health = {
  eslogger_exited_early: esDied,
  fs_usage_exited_early: fsuDied,
  eslogger_events_subscribed: ES_EVENTS,
};
spawnSync('/bin/sleep', ['2']);           // let the kernel drain both trace buffers before teardown
psSampler.kill('SIGKILL');
// SIGINT then WAIT, rather than SIGINT then a fixed 1s then SIGKILL. Both tracers write to a FILE,
// so their stdio is block-buffered; killing before the process actually exits discards whatever sits
// in that final partial block — which is the END of the log, i.e. exactly the part covering the
// traced command. `wait` blocks until the pid is really gone.
es.kill('SIGINT'); fsu.kill('SIGINT');
const waitGone = (pid) => spawnSync('/bin/sh', ['-c', `for i in $(seq 1 80); do kill -0 ${pid} 2>/dev/null || exit 0; /bin/sleep 0.1; done; exit 1`]).status === 0;
diag.tracer_health.eslogger_exited_cleanly = waitGone(es.pid);
diag.tracer_health.fs_usage_exited_cleanly = waitGone(fsu.pid);
es.kill('SIGKILL'); fsu.kill('SIGKILL');
fs.closeSync(esOut); fs.closeSync(fsOut); fs.closeSync(esErr); fs.closeSync(fsErr); fs.closeSync(psOut);
// Surface whatever the tracers said about themselves. Empty is the expected case; non-empty is
// almost always the answer to "why is the event stream short?".
const tail = (f) => { try { return fs.readFileSync(f, 'utf8').trim().split('\n').slice(-12).join('\n'); } catch { return ''; } };
diag.tracer_health.eslogger_stderr = tail(esErrLog);
diag.tracer_health.fs_usage_stderr = tail(fsErrLog);
if (diag.tracer_health.eslogger_stderr) console.error(`macos.mjs: eslogger stderr:\n${diag.tracer_health.eslogger_stderr}`);
if (diag.tracer_health.fs_usage_stderr) console.error(`macos.mjs: fs_usage stderr:\n${diag.tracer_health.fs_usage_stderr}`);

// ─── 3. PARSE eslogger ────────────────────────────────────────────────────────────────────────
// The ES JSON shape is resolved by probing candidate key paths rather than hardcoding one, and a
// miss is a LOUD failure that prints the keys actually present. A silently-wrong extraction here
// would produce a plausible, empty event stream — the worst available outcome.
const dig = (o, dotted) => dotted.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
const first = (o, paths) => { for (const p of paths) { const v = dig(o, p); if (v !== undefined && v !== null) return v; } return undefined; };
const P_PID = ['process.audit_token.pid', 'process.audit_token.remote_pid', 'process.pid', 'process.ppid'];
const P_PPID = ['process.ppid', 'process.parent_audit_token.pid', 'process.original_ppid'];

const esBody = fs.readFileSync(esLog, 'utf8');
const esRecords = [];
let esBadJson = 0;
for (const line of esBody.split('\n')) {
  if (!line.trim() || !line.trimStart().startsWith('{')) continue;
  try { esRecords.push(JSON.parse(line)); } catch { esBadJson++; }
}
diag.counts.eslogger_records = esRecords.length;
diag.counts.eslogger_unparsable_lines = esBadJson;

// THE POSITIVE CONTROL, evaluated now that everything has flushed. Both brackets must be present or
// the observation window did not cover the run and no conclusion drawn from it is worth anything.
const esReady = esBody.includes(`${SENTINEL}-pre`) && esBody.includes(`${SENTINEL}-post`);
if (!esReady) fail(`eslogger did not capture both sentinel brackets (pre=${esBody.includes(SENTINEL + '-pre')} post=${esBody.includes(SENTINEL + '-post')}) — the run is VACUOUS`);
if (esRecords.length === 0) fail('eslogger produced no parsable records — schema or invocation is wrong');

// ─── 4. THE PID SUBTREE ───────────────────────────────────────────────────────────────────────
// Built as a transitive closure over every (pid, ppid) pair ES reports, seeded from our command's
// direct children. Depth is UNBOUNDED on purpose: the one package the corpus has fully solved comes
// down to a syscall inside a bundled yarn that is a GRANDCHILD of the postinstall, so an adapter
// that stops at the direct child reports a clean run for a package that needs a grant.
const parentOf = new Map();
const commOf = new Map();
const edgeSource = { es_record: 0, es_fork: 0, ps_sample: 0 };
const addEdge = (pid, ppid, src) => {
  if (typeof pid !== 'number' || typeof ppid !== 'number' || parentOf.has(pid)) return;
  parentOf.set(pid, ppid); edgeSource[src]++;
};
for (const r of esRecords) {
  const pid = first(r, P_PID), ppid = first(r, P_PPID);
  const exe = first(r, ['process.executable.path', 'event.exec.target.executable.path']);
  if (typeof exe === 'string' && typeof pid === 'number') commOf.set(pid, path.basename(exe));
  // A `fork` event states the edge DIRECTLY — parent is `process`, child is the event payload —
  // and it fires for a process that never goes on to open anything, which a per-record
  // (pid, ppid) pair cannot cover. It is also the only edge available for a pure `fork` with no
  // subsequent exec, which is what a shell does before every builtin redirect.
  const childPidEv = first(r, ['event.fork.child.audit_token.pid', 'event.fork.child.ppid']);
  if (typeof childPidEv === 'number' && typeof pid === 'number') addEdge(childPidEv, pid, 'es_fork');
  addEdge(pid, ppid, 'es_record');
}
// The `ps` sampler's edges, added last so ES always wins a disagreement (ES is exact; `ps` is a
// snapshot and can observe a pid AFTER it was reparented to launchd, which would break the chain).
try {
  for (const line of fs.readFileSync(psLog, 'utf8').split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\S.*)$/);
    if (!m) continue;
    const pid = Number(m[1]), ppid = Number(m[2]);
    addEdge(pid, ppid, 'ps_sample');
    if (!commOf.has(pid)) commOf.set(pid, path.basename(m[3].trim().split(/\s+/)[0]));
  }
} catch { diag.warnings.push('ps sampler produced no output'); }
diag.counts.ancestry_edges_by_source = edgeSource;
// TWO seeds, not one. `selfPid` alone breaks if any link between this process and the fixture
// produced no ES record we subscribed to; `childPid` re-anchors the closure below that gap.
const SEEDS = new Set([process.pid, childPid].filter((p) => typeof p === 'number'));
const inSubtree = (pid) => {
  // Cycle-guarded: a pid reused inside the observation window can otherwise close a loop.
  const seen = new Set();
  let cur = pid;
  for (let i = 0; i < 200 && cur != null && !seen.has(cur); i++) {
    if (SEEDS.has(cur)) return true;
    seen.add(cur);
    cur = parentOf.get(cur);
  }
  return false;
};
// ⛔ THE SAMPLER MUST NOT OBSERVE ITSELF. The `ps` sampler is a child of this process, so its own
// pid subtree satisfies `inSubtree` and every `/bin/ps` and `/bin/sleep` it spawns — two per 50ms —
// lands in the event stream along with each one's dyld and libsystem reads. That is the observer
// effect in its most literal form: a measurable fraction of a long install's events would be the
// instrument. It cannot fabricate a WRITE (the sampler writes nothing outside the adapter's own
// tmpdir), so no grant widens, but it inflates the read set and buries the package's real activity.
const viaSampler = (pid) => {
  const seen = new Set();
  let cur = pid;
  for (let i = 0; i < 200 && cur != null && !seen.has(cur); i++) {
    if (cur === psSampler.pid) return true;
    seen.add(cur);
    cur = parentOf.get(cur);
  }
  return false;
};
const subtreePids = new Set([...parentOf.keys()].filter((p) => inSubtree(p) && !viaSampler(p)));
diag.counts.sampler_pids_excluded = [...parentOf.keys()].filter((p) => inSubtree(p) && viaSampler(p)).length;
diag.counts.subtree_pids = subtreePids.size;
diag.subtree_commands = [...new Set([...subtreePids].map((p) => commOf.get(p)).filter(Boolean))];
// When the closure comes back empty the question is always "which link is missing?", and answering
// it from a re-run costs a full CI cycle. Record the ancestry evidence inline instead.
diag.seeds = [...SEEDS];
// Which link is missing is decidable from the map itself. A seed that appears as no pid AND as no
// ppid means no source emitted a single record naming it, so the closure had nothing to anchor to —
// distinct from a seed that IS present but whose descendants were never recorded. Both seeds coming
// back false is the signature of the eslogger process-group suppression documented above.
diag.seed_presence = [...SEEDS].map((s) => ({
  pid: s,
  appears_as_child: parentOf.has(s),
  appears_as_parent: [...parentOf.values()].includes(s),
}));
diag.counts.parent_edges = parentOf.size;
diag.ancestry_sample = [...parentOf.entries()]
  .filter(([p]) => /^(sudo|env|bash|sh|zsh|fixture|node|npm|run-fixture\.sh|level1\.sh|level2\.sh)$/.test(commOf.get(p) ?? ''))
  .slice(0, 40).map(([p, pp]) => `${commOf.get(p) ?? '?'}(${p}) <- ${pp}`);
// Did the ES stream actually COVER the traced command, or did it stop partway? A record count alone
// cannot say — 8341 records that all predate the command look identical to 8341 that bracket it.
// The window and the per-executable histogram answer it directly.
{
  // The command's own start/end are what make the record window READABLE: a log whose last record
  // predates the command is a truncated capture, one that brackets it and still reports nothing is a
  // suppression. Identical symptoms downstream, completely different defects.
  const times = esRecords.map((r) => r.time).filter((t) => typeof t === 'string').sort();
  diag.eslogger_window = {
    first: times[0] ?? null, last: times[times.length - 1] ?? null,
    command_started: cmdStartedAt, command_ended: cmdEndedAt,
  };
  const hist = new Map();
  for (const r of esRecords) {
    const exe = first(r, ['process.executable.path']);
    if (typeof exe === 'string') hist.set(path.basename(exe), (hist.get(path.basename(exe)) ?? 0) + 1);
  }
  diag.eslogger_top_executables = [...hist.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15)
    .map(([k, v]) => `${k}=${v}`);
}

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

const fsBody = fs.readFileSync(fsLog, 'utf8');
const fsLines = fsBody.split('\n');
diag.counts.fs_usage_lines = fsLines.length;
// Same bracketing control as eslogger. fs_usage is the source for refusals, so a window that did
// not cover the run would report "no refusals" — a clean-looking answer that means nothing.
const fsReady = fsBody.includes(`${SENTINEL}-pre`) && fsBody.includes(`${SENTINEL}-post`);
if (!fsReady) fail(`fs_usage did not capture both sentinel brackets (pre=${fsBody.includes(SENTINEL + '-pre')} post=${fsBody.includes(SENTINEL + '-post')}) — refusal results are VACUOUS`);

// fs_usage carries no pid, only `command.threadid`. Attribution is therefore by command NAME, and
// only when that name is unambiguous within our subtree. Anything else is DROPPED and counted —
// never assigned a guessed pid, which would put a refusal or a socket on the wrong process.
const subtreeCommands = new Set(diag.subtree_commands);
const commandOfLine = (l) => { const m = l.match(/\s(\S+?)\.\d+\s*$/); return m ? m[1] : null; };
const pidForCommand = (c) => {
  const hits = [...subtreePids].filter((p) => commOf.get(p) === c);
  return hits.length === 1 ? hits[0] : null;
};

// ⛔ TRUNCATION, AND IT GOES THE OPPOSITE WAY FROM THE OBVIOUS GUESS. fs_usage stores the path at
// MAXPATHLEN but PRINTS only `columns - overhead` bytes, and when it overflows it KEEPS THE TAIL AND
// DROPS THE HEAD, with no ellipsis and no marker (source: fs_usage.c — `pathname = &buf[len-clen]`).
// It does NOT trim the tail. That direction is the dangerous one: a head-trimmed path is no longer
// absolute, so it silently stops matching any declared root and lands in the unmapped bucket — and
// a head-trimmed path that happens to still look plausible would match the WRONG root.
//
// MEASURED on the macos-14 runner, from `recon-macos.sh`'s length-ladder marks:
//   * total line width is fixed at ~242 columns (~254 for the wider `WrData` form), so the budget
//     left for the path DEPENDS ON THE CALL — a long syscall name eats into it.
//   * longest path printed COMPLETE: 154 chars. Shortest printed form observed already truncated:
//     144 chars (real length 154, the leading 10 chars gone). The boundary therefore sits in a
//     144–162 band rather than at one number, which is exactly why the check is structural
//     ("does it still start with `/`?") and not a length threshold.
//   * `-w` raises the budget to MAX_WIDE_MODE_COLS(264) minus overhead; it does not remove the limit.
//
// Two distinct incomplete-path signals, both measured on the runner:
//
//  (a) HEAD TRIM. A 154-char path printed in full; the same path behind `/System/Volumes/Data`
//      (174 chars) printed as `mes/Data/Users/runner/...` — the leading `/System/Volu` simply gone,
//      no ellipsis. So an absolute path that does not START with `/` was trimmed. (The `[3]/rel`
//      openat form is the one legitimate exception and is excluded.)
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
if (truncated > 0) diag.warnings.push(`${truncated} fs_usage path(s) were head-truncated and REJECTED rather than emitted`);
if (droppedUnattributable > 0) diag.warnings.push(`${droppedUnattributable} fs_usage event(s) dropped: no unambiguous pid`);
diag.warnings.push('connect events carry NO host/port: no macOS god-mode source exposes the peer sockaddr');

fs.writeFileSync(outPath, events.map((e) => JSON.stringify(e)).join('\n') + (events.length ? '\n' : ''));
if (diagPath) fs.writeFileSync(diagPath, JSON.stringify(diag, null, 2));
diag.raw = { eslogger: esLog, fs_usage: fsLog };
console.error(`macos.mjs: ${events.length} events -> ${outPath}`);
console.error(JSON.stringify(diag.counts));
// These three are what a failure is diagnosed FROM, so they go to the log rather than only into the
// diag file: the window says whether the capture covered the run, seed_presence says whether the
// ancestry had anything to anchor to, and the histogram says WHOSE events the tracer was willing to
// report. Together they separate "tracer died", "tracer truncated", and "tracer suppressed us".
console.error(`macos.mjs: window=${JSON.stringify(diag.eslogger_window)}`);
console.error(`macos.mjs: seeds=${JSON.stringify(diag.seed_presence)} subtree_commands=${JSON.stringify(diag.subtree_commands)}`);
console.error(`macos.mjs: es_top=${JSON.stringify(diag.eslogger_top_executables)}`);
for (const w of diag.warnings) console.error(`macos.mjs: WARN ${w}`);
process.exit(diag.errors.length ? 1 : 0);
