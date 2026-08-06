// Known-answer tests for the Linux retention adapter.
//
// ⛔ EVERY CASE BELOW IS A DECODING FAILURE THAT WAS MEASURED, NOT IMAGINED. `probes/
// syscall-coverage.c` performs 27 writes at paths it names itself and prints them; running it under
// the harness's exact `strace -f -e trace=file,network,process` and feeding the trace to the regex
// decoder `observe.mjs` USED TO CARRY retained 18 of the 26 that executed, invented one path no
// process touched, and truncated another. This adapter retained all 26. That gap is why `observe.mjs`
// now imports `decode()` from here rather than carrying its own copy of the strace surface — the
// duplication is what let the two drift. Keeping the cases as literal strace lines rather than as a C
// program means the suite runs on any machine, with no compiler and no ptrace privilege: the C probe
// is the instrument that FINDS a new gap, this file the one that stops a fixed gap coming back.
//
// The classifier-side counterparts are in `observe.test.mjs` — same mechanisms, asserted through the
// synthesized GRANT instead of the event stream, because a path can be recovered here and still be
// billed to the wrong scope there.
import { test } from 'node:test';
import assert from 'node:assert';
import { decode } from './linux.mjs';

// The lifecycle shell every trace needs before the adapter attributes anything to a script.
const SH = '100   execve("/usr/bin/sh", ["sh", "-c", "node install.js"], 0x1 /* 9 vars */) = 0\n';
const run = (body, opts = {}) => decode(SH + body, { project: '/proj', ...opts });
const writes = (d) => {
  const s = new Set();
  for (const e of d.events) {
    if (!e.w || e.r !== 0) continue;
    if (e.f) s.add(e.f);
    if (e.g && (e.o === 'rename' || e.o === 'link')) s.add(e.g);
  }
  return s;
};

test('a dirfd-relative openat resolves through the fd table', () => {
  // observe.mjs's `^name\((?:AT_FDCWD,\s*)?"path"` matcher fails this line whole, because the first
  // argument is the NUMBER 3. The path is not mis-parsed, it is dropped.
  const d = run(
    '100   openat(AT_FDCWD, "/proj/build", O_RDONLY|O_DIRECTORY) = 3\n'
    + '100   openat(3, "out.o", O_WRONLY|O_CREAT, 0644) = 4\n');
  assert.ok(writes(d).has('/proj/build/out.o'), 'dirfd-relative write must resolve to an absolute path');
});

test('an UNRESOLVABLE dirfd is marked, never guessed', () => {
  // The opposite failure, and the worse one. observe.mjs resolves an unknown base against the
  // project root and INVENTS a path no process touched; a plausible wrong path in a retained log is
  // worse than an obviously incomplete one.
  const d = run('100   openat(9, "mystery", O_WRONLY|O_CREAT, 0644) = 4\n');
  const e = d.events.find((x) => x.f === 'mystery');
  assert.ok(e, 'the event must still be retained');
  assert.equal(e.u, '9', 'and must carry the unresolved base rather than a fabricated absolute path');
  assert.equal(d.stats.unresolvedDirfd, 1);
});

test('a rename retains BOTH ends', () => {
  // The macOS lane lost 100% of its rename destinations to a 32-bit truncation bug for as long as
  // that adapter existed. On Linux the same data is lost to a matcher that takes the first quoted
  // argument. A rename unlinks the source AND creates the destination: both are writes.
  const d = run('100   renameat(AT_FDCWD, "/proj/a.tmp", AT_FDCWD, "/proj/a") = 0\n');
  const w = writes(d);
  assert.ok(w.has('/proj/a.tmp'), 'source');
  assert.ok(w.has('/proj/a'), 'destination');
});

test('glibc-rewritten metadata syscalls are recognized', () => {
  // `chmod()` never reaches the kernel as `chmod` on glibc — it arrives as `fchmodat`, which
  // observe.mjs's anchored filter does not match. Measured live: 725 fchmodat + 728 fchownat in one
  // sharp@0.32.6 install, every one of them invisible.
  const d = run(
    '100   fchmodat(AT_FDCWD, "/proj/bin/x", 0755) = 0\n'
    + '100   fchownat(AT_FDCWD, "/proj/bin/y", 0, 0, 0) = 0\n'
    + '100   mknodat(AT_FDCWD, "/proj/fifo", S_IFIFO|0644) = 0\n');
  const w = writes(d);
  assert.ok(w.has('/proj/bin/x'), 'fchmodat');
  assert.ok(w.has('/proj/bin/y'), 'fchownat');
  assert.ok(w.has('/proj/fifo'), 'mknodat');
});

test('symlink content is not billed as a path, and the linkpath is', () => {
  // `symlink(target, linkpath)` creates LINKPATH; `target` is opaque content the kernel stores
  // verbatim and never resolves. Billing the first argument invents a path — the exact bug that
  // kept `write:{userHome}` alive on vanilla-cookieconsent.
  const d = run('100   symlinkat("../only-allow/bin.js", AT_FDCWD, "/proj/node_modules/.bin/only-allow") = 0\n');
  const w = writes(d);
  assert.ok(w.has('/proj/node_modules/.bin/only-allow'), 'the linkpath is created');
  assert.ok(!w.has('/proj/only-allow/bin.js'), 'the link CONTENT is not a path anything touched');
});

test('a path containing a quote survives intact', () => {
  const d = run('100   openat(AT_FDCWD, "/proj/od\\"d", O_WRONLY|O_CREAT, 0644) = 4\n');
  assert.ok(writes(d).has('/proj/od"d'), 'a C-escaped quote must not truncate the path');
});

test('an unfinished/resumed pair rejoins, keeping the clone edge', () => {
  // Stripping the leading `)` off the resumed half leaves `clone(flags=... = 151`, which parses as
  // nothing — and the pid a clone RETURNS is the process-tree edge, so losing it silently orphans a
  // whole subtree. Caught by the fixture as two unparsed lines.
  const d = run(
    '100   clone(child_stack=0x1, flags=CLONE_VM|SIGCHLD <unfinished ...>\n'
    + '100   <... clone resumed>)              = 151\n'
    + '151   openat(AT_FDCWD, "/proj/child-write", O_WRONLY|O_CREAT, 0644) = 4\n');
  assert.equal(d.stats.unparsed, 0);
  const child = d.procs.find((p) => p.pid === 151);
  assert.equal(child.ppid, 100, 'the clone edge must survive the rejoin');
  assert.equal(child.life, 1, 'a child of the lifecycle shell is lifecycle');
});

test('a failed call is retained with its errno, not silently dropped', () => {
  // ⛔ A REFUSAL IS THE SIGNAL THAT A GRANT IS MISSING, so it may never be filtered out. And an
  // ENOENT is not a refusal: it is the record of what the script LOOKED FOR, which on a different
  // machine may exist. Both are kept; the distinction lives in the errno.
  const d = run(
    '100   openat(AT_FDCWD, "/usr/include/bits/types.h", O_RDONLY) = -1 ENOENT (No such file or directory)\n'
    + '100   mkdirat(AT_FDCWD, "/etc/nope", 0755) = -1 EACCES (Permission denied)\n');
  const byPath = Object.fromEntries(d.events.map((e) => [e.f, e]));
  assert.equal(byPath['/usr/include/bits/types.h'].r, 'ENOENT');
  assert.equal(byPath['/etc/nope'].r, 'EACCES');
  assert.equal(writes(d).size, 0, 'a failed call is not a need');
});

test('a nested-paren argument does not shred the argument list', () => {
  // `sin_port=htons(443)` is a paren inside argument 1. A non-greedy `\\((.*?)\\)` stops there and
  // every later argument shifts by one, which silently mis-assigns the path.
  const d = run('100   connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.16.1.34")}, 16) = 0\n');
  const c = d.events.find((e) => e.o === 'connect');
  assert.equal(c.h, '104.16.1.34');
  assert.equal(c.pt, 443);
});

test('repeats collapse to a count rather than a line each', () => {
  // Dedup is the whole reason retention is affordable: 216,512 calls became 80,329 events on
  // lmdb-store@2.0.0-alpha2. It is lossless for a capability model, and `n` keeps the frequency.
  const d = run('100   statx(AT_FDCWD, "/proj/p.json", 0, 0, {}) = 0\n'.repeat(5));
  const e = d.events.find((x) => x.f === '/proj/p.json');
  assert.equal(e.n, 5);
});

test('the cwd is tracked per pid and inherited across clone', () => {
  const d = run(
    '100   chdir("/proj/pkg") = 0\n'
    + '100   clone(child_stack=NULL, flags=SIGCHLD) = 151\n'
    + '151   openat(AT_FDCWD, "rel.txt", O_WRONLY|O_CREAT, 0644) = 4\n');
  assert.ok(writes(d).has('/proj/pkg/rel.txt'));
});

// ── The cwd trust model — an absolute chdir establishes trust, a relative one preserves it ────────
//
// ⛔ THE DEFECT THIS REPLACES. `resolve()` falls back to `opts.project` for any cwd-relative path,
// and `unresolvedDirfd` only counts a NULL base — so with `project` set the unresolved case for a
// relative path COULD NOT FIRE, and a fabricated anchor was byte-identical in the output to an
// observed one. `chdir` then wrote that fabricated anchor back as an observed cwd (the `open` case
// beside it checked `unresolved`; `chdir` did not), compounding it through every later relative path.
// MEASURED on lmdb-store@2.0.0-alpha2: 126 relative chdirs against 2 absolute, one pid six deep.
// Direction is the forbidden one — a path wrongly anchored under the project bills `proj` and reads
// cheaper than it is.

/** Paths the decoder marked as resolved against a cwd it never observed. */
const assumed = (d) => new Set(d.events.filter((e) => e.ca).map((e) => e.f));

test('the ROOT process is trusted, so a normal run flags nothing', () => {
  // ⛔ THE CONTROL THAT KEEPS THE GUARD USEFUL RATHER THAN MERELY LOUD. The driver cds to $OBS before
  // exec'ing npm, so the root's cwd is a fact the driver established. Without seeding it, every path
  // in every normal run would flag, the marker would fire on every record, and a reader would learn
  // to ignore it — which is how a real warning dies.
  const d = run('100   openat(AT_FDCWD, "pkg/index.js", O_RDONLY) = 3\n');
  assert.equal(d.stats.cwdUnobserved, 0, `a normal run must not flag:\n${[...assumed(d)]}`);
  assert.ok([...writes(d), ...d.events.map((e) => e.f)].includes('/proj/pkg/index.js'),
    'the path must still resolve against the project');
});

test('a relative chdir from a TRUSTED cwd stays trusted — the guard is not blanket distrust', () => {
  // ⛔ Without this, "distrust every relative chdir" would satisfy the flag-fires test while making
  // the decoder useless: 126 of 128 chdirs in a real trace are relative, so blanket distrust would
  // flag essentially the whole run. Trust must PROPAGATE through the ordinary idiom.
  const d = run('100   chdir("build") = 0\n'
    + '100   openat(AT_FDCWD, "out.o", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.equal(d.stats.cwdUnobserved, 0, `cd build && … from a known cwd must not flag:\n${[...assumed(d)]}`);
  assert.ok(writes(d).has('/proj/build/out.o'), `the compounded path must resolve:\n${[...writes(d)]}`);
});

test('⛔ a process whose parent edge was LOST is flagged rather than silently re-anchored', () => {
  // The real failure: a child appears with no clone edge, so its cwd was never inherited and never
  // observed. It re-anchors on the project having never been seen to go there. Before this guard the
  // resulting path was indistinguishable from a measured one.
  const d = run('4242  chdir("build") = 0\n'
    + '4242  openat(AT_FDCWD, "artifact.node", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.ok(d.stats.cwdUnobserved > 0,
    `an orphan process's relative paths must be flagged, not billed as observed:\n${JSON.stringify(d.stats)}`);
  assert.ok(d.stats.cwdUnobservedWrites > 0,
    'the WRITE must be counted — writes are what move a grant');
});

test('an ABSOLUTE chdir REPAIRS a lost chain — trust is establishable, not just losable', () => {
  // Self-anchoring: an absolute target says where the process now IS regardless of what we believed.
  // Without this the flag would latch forever after one orphan, and every later path in a long-lived
  // build process would be flagged on the strength of a fault that had already been corrected.
  const d = run('4242  chdir("build") = 0\n'
    + '4242  chdir("/proj/pkg/build") = 0\n'
    + '4242  openat(AT_FDCWD, "real.o", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.ok(writes(d).has('/proj/pkg/build/real.o'), `the repaired path must resolve:\n${[...writes(d)]}`);
  assert.ok(!assumed(d).has('/proj/pkg/build/real.o'),
    `a path after an absolute chdir is OBSERVED and must not be flagged:\n${[...assumed(d)]}`);
});

test('a FAILED chdir neither moves the cwd nor changes trust', () => {
  const d = run('100   chdir("/nowhere") = -1 ENOENT (No such file or directory)\n'
    + '100   openat(AT_FDCWD, "still-here.js", O_RDONLY) = 3\n');
  assert.equal(d.stats.cwdUnobserved, 0, 'a failed chdir must not cost trust');
  assert.ok(d.events.some((e) => e.f === '/proj/still-here.js'),
    `a failed chdir must not move the cwd:\n${d.events.map((e) => e.f)}`);
});

test('an ABSOLUTE path is never flagged, whatever the cwd is believed to be', () => {
  const d = run('4242  openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n');
  assert.equal(d.stats.cwdUnobserved, 0, 'an absolute path does not depend on the cwd at all');
});
