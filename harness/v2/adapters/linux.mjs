// Linux god-mode observation adapter: an `strace -f` text trace in, a RETAINED event stream out.
//
// WHAT THIS IS TO `observe.mjs`. This file owns the strace SURFACE — decoding a text trace into a
// normalized event stream — and `observe.mjs` is the CLASSIFIER and grant synthesizer that imports
// `decode()` from here. It did not start that way: observe.mjs carried its own regexes on the theory
// that a grant synthesizer only needs today's four scopes and could round the rest up. Measured
// against `probes/syscall-coverage.c`, that narrower decoder retained 18 of the 26 writes which
// actually executed, INVENTED one path no process touched, and truncated another — every loss in the
// under-grant direction. So the duplication is gone. The retention STEP is still separate: the
// DERIVED decode this file performs still runs after synthesis (`measure.sh` 2b), which is what
// keeps a retention failure from moving a verdict, while the RAW archive is gzipped before it
// (`measure.sh` 1b) because a copy cannot influence a grant and the case where the archive matters
// most is a synthesis that fails and exits. Sharing a pure function is not sharing a step.
//
// The rule that follows from that history: a decoding fix belongs HERE, where both the retained log
// and the synthesized grant inherit it, and gets a case in `linux.test.mjs` plus, when it can move a
// grant, one in `observe.test.mjs`.
//
// ⛔ WHAT A RETAINED LOG MAY NOT DO IS BAKE IN TODAY'S ANSWERS. The first draft of this tagged every
// path with the scope it classified into and kept nothing else. That is derived data: we were at
// that moment adding a `tmp` scope that did not exist when the corpus was measured, and a log
// carrying only `scope:"outside"` would have forced a RE-MEASURE of every record to gain it. Keeping
// the raw path, the operation and the roots makes the same change a RE-PARSE. Scope tags therefore
// appear nowhere in this file; the header carries the ROOTS, which is what lets any future
// classifier recompute them.
//
// ⛔ EVERY DECODING GAP BELOW WAS MEASURED WITH A KNOWN-ANSWER FIXTURE, not read off the source.
// `probes/syscall-coverage.c` performs 27 writes at paths it names itself; the regex decoder
// `observe.mjs` USED TO CARRY reported 18 of the 26 that executed. Every `observe.mjs` below names
// that SUPERSEDED decoder, not today's file — which imports `decode()` from here and so inherits
// each of these fixes. They are kept in the present tense of the bug because they are the
// measurement record that justifies the corresponding code:
//
//   1. A `*at` syscall whose first argument is a REAL DIRFD prints a NUMBER, not `AT_FDCWD`, and
//      observe.mjs's `^name\((?:AT_FDCWD,\s*)?"path"` matcher fails the line WHOLE. Measured misses:
//      `openat(3,"B")`, `mkdirat(3,"F")`, `unlinkat(3,"G")`, `renameat2(3,"D-src",3,"D-dst")`.
//      This adapter carries a per-pid FD TABLE built from successful opens, so a dirfd resolves.
//   2. `rename`/`link` DESTINATIONS are dropped: the matcher takes the FIRST quoted argument, which
//      is the SOURCE. Measured: `C-rename-dst` absent. The macOS lane lost 100% of its rename
//      destinations to an unrelated 32-bit truncation bug and nobody noticed for as long as that
//      adapter existed, which is the reason `path2` is a first-class field here rather than a
//      second event.
//   3. `symlinkat(target, dirfd, linkpath)` resolves `linkpath` against the wrong base and INVENTS a
//      path no process touched — worse than dropping it.
//   4. glibc rewrites the legacy syscalls, so `chmod()` reaches the kernel as `fchmodat` and
//      `chown()` as `fchownat`. observe.mjs's filter lists `chmod` and is anchored, so it matches
//      NEITHER — and `mknod` is not in the list at all. Measured live: 725 `fchmodat` + 728
//      `fchownat` in one sharp@0.32.6 install.
//   5. A path containing a double quote is truncated at the backslash, because `"([^"]*)"` cannot
//      see a C-escaped quote. Measured: `O-with"quote-file` retained as `O-with\`.
//   6. ⛔ A `clone` SPLIT ACROSS `<unfinished ...>` matches no single-line regex, so the process-tree
//      edge is lost and with it the child's inherited CWD — after which every relative path that
//      child opens resolves against the PROJECT ROOT and lands on a fabricated path. This is the one
//      loss measured to move a real package's grant, and it is the most common by far: in one
//      `lmdb-store@2.0.0-alpha2` install, 287 of 363 clone edges (79%) are split that way. node-gyp
//      compiles from `<pkg>/build` with relative `./Release/...` paths, so 70 writes were billed to
//      `<project>/Release/...` — directories that do not exist on disk after the install — earning
//      the package a `write:{project:true}` it does not need. The rejoin below is what closes it.
//
// ⛔ WHAT NO ADAPTER CAN RECOVER, stated so the log is not trusted past its evidence. The capture is
// `-e trace=file,network,process`, which subscribes to syscalls that NAME a path. The fd-only
// mutators — `ftruncate`, `fchmod`, `fchown`, `fallocate`, `copy_file_range`, `write`, and a
// `MAP_SHARED|PROT_WRITE` `mmap` — are absent from the trace entirely. That is sound for a
// CAPABILITY model and only for one: an fd can only be written through if it was opened with write
// flags, and this adapter retains that open with its flags, so "may write path P" is fully
// recoverable. What is NOT recoverable is a per-operation history, and a `/proc/self/fd/N` reopen or
// an fd passed over `SCM_RIGHTS` hides its real target. Both are recorded here as what they are.
//
//   usage: node adapters/linux.mjs <trace> --project D --home D [--jail-home D] [--pkg N]
//                                  [--version V] [--out FILE] [--summary] [--stats-json FILE]
//
// `--out` ending in `.gz` is gzipped in place. Prefer it: the stream is ~10x its own size in text.
import fs from 'node:fs';
import zlib from 'node:zlib';

export const EVENT_SCHEMA = 1;

// ── strace surface ──────────────────────────────────────────────────────────────────────────────

// Split a syscall argument list on TOP-LEVEL commas only. strace nests `{...}`, `[...]`, `(...)`
// and quoted strings inside single arguments — `statx(AT_FDCWD, "p", 0, 0, {stx_mask=...})` — so a
// naive `split(',')` shreds them and every argument after the first structure is off by one.
function splitArgs(s) {
  const out = [];
  let depth = 0, inStr = false, esc = false, cur = '';
  for (const ch of s) {
    if (esc) { cur += ch; esc = false; continue; }
    if (inStr) {
      cur += ch;
      if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; cur += ch; continue; }
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    if (ch === '}' || ch === ']' || ch === ')') depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// Decode a C string literal as strace prints it. The `\"` case is the one that matters: a path
// containing a quote is otherwise truncated at the backslash, silently and mid-path.
function unquote(a) {
  if (typeof a !== 'string' || a[0] !== '"') return null;
  const end = a.lastIndexOf('"');
  if (end <= 0) return null;
  const body = a.slice(1, end);
  let out = '', i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c !== '\\') { out += c; i++; continue; }
    const n = body[i + 1];
    if (n === 'n') { out += '\n'; i += 2; }
    else if (n === 't') { out += '\t'; i += 2; }
    else if (n === 'r') { out += '\r'; i += 2; }
    else if (n === '\\') { out += '\\'; i += 2; }
    else if (n === '"') { out += '"'; i += 2; }
    else if (n >= '0' && n <= '7') {
      let oct = '';
      let j = i + 1;
      while (j < body.length && oct.length < 3 && body[j] >= '0' && body[j] <= '7') oct += body[j++];
      out += String.fromCharCode(parseInt(oct, 8)); i = j;
    } else { out += n; i += 2; }
  }
  // strace marks a string it truncated with a trailing `...` OUTSIDE the quotes. Filenames are
  // exempt from `-s` (MEASURED: a 313-char path survived intact at the default `-s 32`), but an
  // argv element is not, so the flag is carried rather than assumed away.
  return { value: out, truncated: a.slice(end + 1).startsWith('...') };
}

// ── The syscall table. `dirfd` names the argument index holding a dirfd for the path at `path`. ──
//
// `op` is a NORMALIZED class; the raw syscall name is retained alongside it on every event, because
// the classes are this file's opinion and the syscall name is not. Gzip collapses the duplication
// to near nothing (MEASURED: keeping both costs under 2% of the compressed stream).
const SYSCALLS = {
  open:        { op: 'open',    path: 0, flags: 1 },
  openat:      { op: 'open',    dirfd: 0, path: 1, flags: 2 },
  openat2:     { op: 'open',    dirfd: 0, path: 1, how: 2 },
  creat:       { op: 'create',  path: 0 },
  mkdir:       { op: 'mkdir',   path: 0 },
  mkdirat:     { op: 'mkdir',   dirfd: 0, path: 1 },
  rmdir:       { op: 'rmdir',   path: 0 },
  unlink:      { op: 'unlink',  path: 0 },
  unlinkat:    { op: 'unlink',  dirfd: 0, path: 1, atflags: 2 },
  rename:      { op: 'rename',  path: 0, path2: 1 },
  renameat:    { op: 'rename',  dirfd: 0, path: 1, dirfd2: 2, path2: 3 },
  renameat2:   { op: 'rename',  dirfd: 0, path: 1, dirfd2: 2, path2: 3 },
  link:        { op: 'link',    path: 0, path2: 1 },
  linkat:      { op: 'link',    dirfd: 0, path: 1, dirfd2: 2, path2: 3 },
  // ⛔ symlink's FIRST argument is opaque link CONTENT the kernel stores verbatim, NOT a path any
  // process touched. `path` is the LINKPATH — the thing created — and the content rides along as
  // `path2` so a re-parse can still see it without mistaking it for a touch.
  symlink:     { op: 'symlink', path: 1, content: 0 },
  symlinkat:   { op: 'symlink', dirfd: 1, path: 2, content: 0 },
  readlink:    { op: 'readlink', path: 0 },
  readlinkat:  { op: 'readlink', dirfd: 0, path: 1 },
  stat:        { op: 'stat',    path: 0 },
  lstat:       { op: 'stat',    path: 0 },
  statx:       { op: 'stat',    dirfd: 0, path: 1 },
  newfstatat:  { op: 'stat',    dirfd: 0, path: 1 },
  fstatat64:   { op: 'stat',    dirfd: 0, path: 1 },
  statfs:      { op: 'stat',    path: 0 },
  access:      { op: 'access',  path: 0 },
  faccessat:   { op: 'access',  dirfd: 0, path: 1 },
  faccessat2:  { op: 'access',  dirfd: 0, path: 1 },
  chmod:       { op: 'chmod',   path: 0 },
  fchmodat:    { op: 'chmod',   dirfd: 0, path: 1 },
  fchmodat2:   { op: 'chmod',   dirfd: 0, path: 1 },
  chown:       { op: 'chown',   path: 0 },
  lchown:      { op: 'chown',   path: 0 },
  fchownat:    { op: 'chown',   dirfd: 0, path: 1 },
  utime:       { op: 'utimes',  path: 0 },
  utimes:      { op: 'utimes',  path: 0 },
  futimesat:   { op: 'utimes',  dirfd: 0, path: 1 },
  utimensat:   { op: 'utimes',  dirfd: 0, path: 1 },
  truncate:    { op: 'truncate', path: 0 },
  mknod:       { op: 'mknod',   path: 0 },
  mknodat:     { op: 'mknod',   dirfd: 0, path: 1 },
  chdir:       { op: 'chdir',   path: 0 },
  execve:      { op: 'exec',    path: 0 },
  execveat:    { op: 'exec',    dirfd: 0, path: 1 },
  getxattr:    { op: 'xattr',   path: 0 },
  lgetxattr:   { op: 'xattr',   path: 0 },
  setxattr:    { op: 'xattr-set', path: 0 },
  lsetxattr:   { op: 'xattr-set', path: 0 },
  mount:       { op: 'mount',   path: 0, path2: 1 },
};

// Which normalized ops MUTATE the filesystem regardless of flags. `open` is absent on purpose: its
// intent lives in the flags and is decided per event.
const MUTATING = new Set(['create', 'mkdir', 'rmdir', 'unlink', 'rename', 'link', 'symlink',
  'chmod', 'chown', 'utimes', 'truncate', 'mknod', 'xattr-set', 'mount']);
const WRITE_FLAG = /O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)/;

export function decode(text, opts = {}) {
  const lines = text.split('\n');

  const cwds = new Map();        // pid -> cwd
  // ⛔ PIDS WHOSE CWD BELIEF TRACES BACK TO AN ANCHOR WE ACTUALLY OBSERVED. Ported from
  // `observe-macos.mjs`'s `cwdTrusted` — same rule, and the same reported marker so ONE parser in
  // `record.mjs` serves both lanes: AN ABSOLUTE TARGET ESTABLISHES TRUST, A RELATIVE ONE PRESERVES IT.
  //
  // ⛔ WHY THIS IS NEEDED ON LINUX EVEN THOUGH THE FALLBACK IS USUALLY RIGHT. `resolve()` falls back
  // to `opts.project` for a cwd-relative path, and `unresolvedDirfd` only counts a NULL base — so
  // with `project` set, the unresolved case for a relative path COULD NOT FIRE, and a fabricated base
  // was indistinguishable from an observed one. The `chdir` side effect then wrote that fabricated
  // base back as an observed cwd (the `open` case beside it checks `unresolved`; `chdir` did not), so
  // one bad anchor compounded through every later relative path in that process.
  //
  // MEASURED on `lmdb-store@2.0.0-alpha2`: 126 successful RELATIVE chdirs against 2 absolute, with one
  // pid walking `Release` → `obj.target` → `lmdb-store` → `dependencies` → `lmdb` → `libraries`. The
  // compounding case is the DOMINANT one on this lane, not an edge.
  //
  // Direction of the error is the forbidden one: a path wrongly anchored under the project bills
  // `proj` rather than its true location, so it reads CHEAPER than it is — an under-grant.
  //
  // ⛔ THE ROOT IS SEEDED AS TRUSTED, AND THAT IS AN OBSERVATION RATHER THAN AN ASSUMPTION: the
  // DRIVER cds to `$OBS` before exec'ing npm, so it knows that cwd as a fact it created. Everything
  // else earns trust by inheritance or by an absolute chdir. The flag therefore fires exactly when
  // provenance is genuinely lost — a pid whose parent edge was missed re-anchors to the project
  // having never been seen to go there. This lane has that history: 287 of 363 clone edges once split
  // across `<unfinished ...>` and fabricated 70 paths.
  const cwdTrusted = new Set();
  let rootPid = null;
  const fds = new Map();         // pid -> Map(fd -> abs path)
  const ppid = new Map();        // pid -> ppid
  const argvOf = new Map();      // pid -> exec argv (first exec wins; later execs recorded as events)
  const exeOf = new Map();
  const pending = new Map();     // pid -> the text of an `<unfinished ...>` line awaiting its resume
  const lifecycle = new Set();
  const toolPids = new Set();
  let started = false;

  const events = new Map();      // dedup key -> event object with a repeat count
  const stats = { lines: lines.length, parsed: 0, unfinished: 0, joined: 0, unparsed: 0,
    unknownSyscall: new Map(), unresolvedDirfd: 0, truncatedArg: 0,
    // Relative paths resolved against a cwd we never observed the process reach, and how many of
    // those were WRITES — the writes are what move a grant, so they are counted separately.
    cwdUnobserved: 0, cwdUnobservedWrites: 0 };

  const normalize = (p) => {
    const out = [];
    for (const seg of p.split('/')) {
      if (seg === '' || seg === '.') continue;
      if (seg === '..') out.pop();
      else out.push(seg);
    }
    return '/' + out.join('/');
  };

  // Resolve a (dirfd, path) pair the way the kernel does. ⛔ An unresolvable dirfd yields an
  // EXPLICITLY MARKED path, never a guess: observe.mjs's fallback-to-project-root is what invented
  // `<project>/H-symlinkat-dirfd` for a file created somewhere else entirely, and a plausible wrong
  // path in a retained log is worse than an obviously incomplete one.
  const resolve = (pid, dirfdArg, p) => {
    if (p == null) return null;
    if (p.startsWith('/')) return { path: normalize(p) };
    let base, viaCwd = false;
    if (dirfdArg == null || dirfdArg === 'AT_FDCWD') {
      viaCwd = true;
      base = cwds.get(pid) ?? opts.project ?? null;
    } else if (/^\d+$/.test(dirfdArg)) base = fds.get(pid)?.get(Number(dirfdArg)) ?? null;
    else base = null;
    if (base == null) { stats.unresolvedDirfd++; return { path: p, base: dirfdArg ?? 'CWD', unresolved: true }; }
    // ⛔ RESOLVED, BUT AGAINST A CWD WE NEVER SAW THIS PROCESS REACH. The path is still the best
    // guess available and is kept — a plausible path beats no path for triage — but it is MARKED, so
    // nothing downstream can mistake a fabricated anchor for an observed one. Before this the two
    // were byte-identical in the output.
    if (viaCwd && !cwdTrusted.has(pid)) return { path: normalize(base + '/' + p), cwdAssumed: true };
    return { path: normalize(base + '/' + p) };
  };

  const inherit = (parent, child) => {
    ppid.set(child, parent);
    // Trust rides with the cwd it describes, and only with it: a child that inherits a believed cwd
    // inherits exactly the confidence its parent had in that value.
    if (cwds.has(parent)) {
      cwds.set(child, cwds.get(parent));
      if (cwdTrusted.has(parent)) cwdTrusted.add(child);
    }
    const t = fds.get(parent);
    if (t) fds.set(child, new Map(t));
    if (lifecycle.has(parent)) lifecycle.add(child);
  };

  const emit = (e) => {
    const key = `${e.p}\u0000${e.s}\u0000${e.f ?? ''}\u0000${e.g ?? ''}\u0000${e.r}\u0000${e.fl ?? ''}`;
    const prior = events.get(key);
    if (prior) { prior.n++; return; }
    e.n = 1;
    events.set(key, e);
  };

  // A lifecycle script is always reached through `sh -c "<script>"`. Same predicate observe.mjs
  // uses, kept identical on purpose: attribution must be REPRODUCIBLE against the existing records.
  const SHELL_EXEC = /^execve\("[^"]*\/(?:sh|bash|dash)"[^)]*"-c"/;

  for (const raw of lines) {
    if (!raw) continue;
    const pidM = raw.match(/^(\d+)\s+/);
    const pid = pidM ? Number(pidM[1]) : 0;
    // ⛔ THE ROOT'S CWD IS KNOWN BY CONSTRUCTION, NOT ASSUMED. The first pid in the trace is the
    // process the driver itself launched, and `measure.sh` cds to `$OBS` before exec'ing npm — so
    // `opts.project` IS that process's cwd, established by the driver rather than inferred by this
    // decoder. Seeding it is what keeps the guard targeted: without it every path in a normal run
    // would flag, the marker would fire on every record, and a reader would learn to ignore it.
    if (rootPid == null && opts.project) {
      rootPid = pid;
      cwds.set(pid, normalize(opts.project));
      cwdTrusted.add(pid);
    }
    let line = raw.replace(/^\d+\s+/, '');

    if (line.startsWith('---') || line.startsWith('+++')) continue;

    // Rejoin a syscall split across an `<unfinished ...>` / `<... name resumed>` pair. Without this
    // the RESULT is orphaned from the path, so a call that FAILED reads as one that succeeded —
    // which is the over-grant direction, but it also loses every genuine refusal on a blocking call.
    if (line.endsWith('<unfinished ...>')) {
      pending.set(pid, line.slice(0, -'<unfinished ...>'.length));
      stats.unfinished++;
      continue;
    }
    const res = line.match(/^<\.\.\.\s+([a-z_0-9]+)\s+resumed>(.*)$/);
    if (res) {
      const head = pending.get(pid);
      if (head == null) continue;
      pending.delete(pid);
      // ⛔ DO NOT STRIP THE LEADING `)` OFF THE RESUMED HALF. The unfinished half ends mid-argument
      // list with NO closing paren, so that `)` is the one that closes the call. Stripping it (which
      // this did in its first draft) leaves `clone(flags=... = 151` — unparseable — and the pid the
      // clone RETURNED is the process-tree edge, so losing it silently drops a whole subtree's
      // parent linkage. Caught by the known-answer fixture, where 2 lines went unparsed.
      line = head + res[2];
      stats.joined++;
    }

    if (SHELL_EXEC.test(line) && !line.includes('= -1')) { lifecycle.add(pid); started = true; }
    if (!started) toolPids.add(pid);

    const m = line.match(/^([a-z_0-9]+)\((.*?)\)\s*=\s*(.*)$/);
    if (!m) { stats.unparsed++; continue; }
    stats.parsed++;
    const [, name, argText, resultText] = m;

    // Process topology first: an event's attribution depends on it and a clone can precede any call.
    const cl = /^(clone3?|v?fork)$/.test(name) ? Number(resultText.match(/^(\d+)/)?.[1]) : NaN;
    if (Number.isInteger(cl) && cl > 0) { inherit(pid, cl); continue; }

    const spec = SYSCALLS[name];
    if (!spec) {
      if (/^(socket|connect|bind|sendto|recvfrom)$/.test(name)) {
        if (name === 'connect') {
          const port = line.match(/sin6?_port=htons\((\d+)\)/);
          const addr = line.match(/inet6?_addr\("([^"]+)"/);
          if (addr) emit({ p: pid, o: 'connect', s: name, h: addr[1], pt: port ? Number(port[1]) : null,
            r: /^-1\s+([A-Z]+)/.exec(resultText)?.[1] ?? 0 });
        }
        continue;
      }
      stats.unknownSyscall.set(name, (stats.unknownSyscall.get(name) ?? 0) + 1);
      continue;
    }

    const args = splitArgs(argText);
    const errM = resultText.match(/^-1\s+([A-Z0-9]+)/);
    const errno = errM ? errM[1] : 0;

    const q = (i) => (i == null ? null : unquote(args[i]));
    const pq = q(spec.path);
    if (pq?.truncated) stats.truncatedArg++;
    const r1 = pq ? resolve(pid, spec.dirfd == null ? null : args[spec.dirfd], pq.value) : null;
    const p2q = q(spec.path2);
    const r2 = p2q ? resolve(pid, spec.dirfd2 == null ? null : args[spec.dirfd2], p2q.value) : null;

    // Side effects on the decoder's own state, applied only on SUCCESS — a failed chdir does not
    // move the cwd and a failed open yields no fd.
    if (errno === 0) {
      // ⛔ AN ABSOLUTE TARGET ESTABLISHES TRUST; A RELATIVE ONE PRESERVES IT. The absolute case is
      // self-anchoring — it says where the process now IS regardless of where we believed it was —
      // so it repairs a lost chain. The relative case can only be as good as the base it was applied
      // to, which is why it must not manufacture confidence. Previously this line wrote the resolved
      // path back unconditionally, so a fabricated base became an observed cwd for everything after.
      if (spec.op === 'chdir' && r1) {
        cwds.set(pid, r1.path);
        const wasTrusted = cwdTrusted.has(pid);
        if (pq.value.startsWith('/') || wasTrusted) cwdTrusted.add(pid); else cwdTrusted.delete(pid);
      }
      if (spec.op === 'open' && r1 && !r1.unresolved) {
        const fd = Number(resultText.match(/^(\d+)/)?.[1]);
        if (Number.isInteger(fd)) {
          if (!fds.has(pid)) fds.set(pid, new Map());
          fds.get(pid).set(fd, r1.path);
        }
      }
      if (spec.op === 'exec') { exeOf.set(pid, r1?.path ?? null); argvOf.set(pid, args[1] ?? null); }
    }

    const flagText = spec.flags != null ? args[spec.flags]
      : spec.how != null ? (args[spec.how]?.match(/flags=([A-Z_|0-9]+)/)?.[1] ?? null)
      : null;
    let op = spec.op;
    if (op === 'open') op = flagText && WRITE_FLAG.test(flagText) ? 'open-w' : 'open-r';
    if (op === 'unlink' && spec.atflags != null && /AT_REMOVEDIR/.test(args[spec.atflags] ?? '')) op = 'rmdir';

    const e = { p: pid, o: op, s: name, f: r1?.path ?? null, r: errno };
    if (r1?.unresolved) e.u = r1.base;
    // ⛔ THE PATH IS A BEST GUESS, NOT AN OBSERVATION. Marked on the event so a re-parse, the
    // classifier and a human triaging a retained log all see the same caveat — the point of the whole
    // guard is that this is no longer indistinguishable from a resolved path.
    if (r1?.cwdAssumed || r2?.cwdAssumed) {
      e.ca = 1;
      stats.cwdUnobserved++;
      if (MUTATING.has(op) || op === 'open-w') stats.cwdUnobservedWrites++;
    }
    if (r2) { e.g = r2.path; if (r2.unresolved) e.u2 = r2.base; }
    if (spec.content != null) { const c = q(spec.content); if (c) e.g = c.value; }
    if (flagText) e.fl = flagText;
    if (MUTATING.has(op) || op === 'open-w') e.w = 1;
    emit(e);
  }

  // Attribution, computed the same way observe.mjs computes it so a re-parse can reproduce today's
  // grants exactly — but stored PER PROCESS, never folded into the events. If the attribution RULE
  // changes, a re-parse recomputes it from `ppid` + `exe`; if it were stamped on each event it could
  // only be re-measured. Same argument as the scope tags, one level up.
  const procs = [];
  for (const p of new Set([...cwds.keys(), ...fds.keys(), ...ppid.keys(), ...exeOf.keys(),
    ...[...events.values()].map((e) => e.p)])) {
    procs.push({ k: 'p', pid: p, ppid: ppid.get(p) ?? null, exe: exeOf.get(p) ?? null,
      argv: argvOf.get(p) ?? null, cwd: cwds.get(p) ?? null,
      life: lifecycle.has(p) || (started && !toolPids.has(p)) ? 1 : 0 });
  }
  procs.sort((a, b) => a.pid - b.pid);

  return { procs, events: [...events.values()], stats, lifecyclePids: lifecycle.size };
}

export function serialize(decoded, header) {
  const out = [];
  out.push(JSON.stringify({ k: 'h', v: EVENT_SCHEMA, ...header,
    stats: { ...decoded.stats, unknownSyscall: Object.fromEntries(decoded.stats.unknownSyscall) } }));
  for (const p of decoded.procs) out.push(JSON.stringify(p));
  // Sorted by path then pid: adjacent lines share long prefixes, which is most of why this
  // compresses as well as it does.
  const evs = decoded.events.slice().sort((a, b) =>
    (a.f ?? '').localeCompare(b.f ?? '') || a.p - b.p || a.o.localeCompare(b.o));
  for (const e of evs) out.push(JSON.stringify({ k: 'e', ...e }));
  return out.join('\n') + '\n';
}

// ── CLI ─────────────────────────────────────────────────────────────────────────────────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const val = (f, d = null) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
  const file = args.find((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')));
  if (!file) { console.error('usage: linux.mjs <trace> --project D --home D [--jail-home D] [--jail-tmp D] [--out F]'); process.exit(2); }
  const project = val('--project'), home = val('--home');
  const decoded = decode(fs.readFileSync(file, 'utf8'), { project });
  const text = serialize(decoded, {
    platform: `linux-${process.arch}`,
    pkg: val('--pkg'), version: val('--version'),
    tracer: 'strace -f -e trace=file,network,process',
    // ⛔ THE ROOTS ARE THE WHOLE REASON A RE-PARSE IS POSSIBLE. Every path in the stream is
    // machine-specific (`/home/runner/v2-hNdvB5/...`); without these a future classifier cannot tell
    // a project write from a home write, and the log is a pile of strings.
    roots: { project, home, jailHome: val('--jail-home'), jailTmp: val('--jail-tmp'), ownPkg: val('--pkg') && project ? `${project}/node_modules/${val('--pkg')}` : null },
    at: new Date().toISOString(),
  });
  const out = val('--out');
  if (out) {
    fs.writeFileSync(out, out.endsWith('.gz') ? zlib.gzipSync(Buffer.from(text), { level: 9 }) : text);
  } else if (!args.includes('--summary')) process.stdout.write(text);
  if (args.includes('--summary') || out) {
    const s = decoded.stats;
    const unknown = [...s.unknownSyscall.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    console.log(`  EVENTS    ${decoded.events.length} distinct from ${s.parsed} calls`
      + ` (${s.lines} lines, ${s.joined} rejoined, ${s.unparsed} unparsed)`);
    console.log(`  PROCS     ${decoded.procs.length}   lifecycle shells ${decoded.lifecyclePids}`);
    if (s.unresolvedDirfd) console.log(`  ⛔ ${s.unresolvedDirfd} paths with an UNRESOLVED dirfd — kept, marked, never guessed`);
    if (s.truncatedArg) console.log(`  ⛔ ${s.truncatedArg} arguments strace TRUNCATED`);
    if (unknown.length) console.log(`  unsubscribed/unmapped syscalls: ${unknown.map(([k, v]) => `${k}×${v}`).join(' ')}`);
    if (out) console.log(`  wrote ${out} (${fs.statSync(out).size} bytes)`);
  }
  // ⛔ THE SAME CENSUS THE HUMAN LINES ABOVE PRINT, MACHINE-READABLE, so the driver can hand it to
  // `record.mjs` as `EVENTLOG-STATS` and a linux record can carry an `eventLog` block the way a
  // darwin one already does. Without it a record states a verdict and says nothing about how much
  // of the trace the decoder understood — and `unparsed` / `unresolvedDirfd` / `rejoined` are
  // exactly the numbers that would have made the clone-edge loss visible while it was happening.
  // Written only on request, and never in place of the human summary a `driver.out` reader sees.
  const statsOut = val('--stats-json');
  if (statsOut) {
    const s = decoded.stats;
    fs.writeFileSync(statsOut, JSON.stringify({
      lines: s.lines, parsed: s.parsed, unparsed: s.unparsed,
      unfinished: s.unfinished, rejoined: s.joined,
      unresolvedDirfd: s.unresolvedDirfd, truncatedArg: s.truncatedArg,
      procs: decoded.procs.length, lifecyclePids: decoded.lifecyclePids,
      distinctEvents: decoded.events.length,
      unknownSyscall: Object.fromEntries(s.unknownSyscall),
      out: out ?? null,
      gzipBytes: out ? fs.statSync(out).size : null,
    }));
  }
}
