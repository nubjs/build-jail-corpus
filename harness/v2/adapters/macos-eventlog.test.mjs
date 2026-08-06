// Golden cases for the RETAINED event log. `node --test harness/v2/adapters/macos-eventlog.test.mjs`.
//
// ⛔ THE BAR HERE IS NOT "does it parse". It is the one the retention decision rests on:
//
//     the retained log must let ANY FUTURE grant model be re-derived, without re-running the
//     package.
//
// So most cases are about what must NOT be in the file (a classification standing in for its input)
// and what must survive intact (the raw syscall, both paths of a two-path op, the errno, and enough
// process identity to recompute attribution under a rule that does not exist yet). A parser test
// would pass on a log that is useless a month from now.
//
// The spelling is the Linux adapter's — it shipped first with a committed artifact, and three
// dialects would make the corpus un-re-parseable as one thing. The cases below therefore also serve
// as the cross-platform contract check: `k`/`p`/`o`/`s`/`f`/`g`/`r`/`fl`/`w`/`n`/`u`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HERE = new URL('.', import.meta.url).pathname;

const convert = (trace, extra = []) => {
  const dir = mkdtempSync(join(tmpdir(), 'evlog-'));
  const f = join(dir, 'trace.txt');
  writeFileSync(f, trace.trimStart() + '\n');
  const outFile = join(dir, 'events.ndjson');
  const stdout = execFileSync(process.execPath,
    [join(HERE, 'macos-eventlog.mjs'), f, '--out', outFile,
      '--project', '/proj', '--home', '/Users/runner', '--pkg', 'demo', '--version', '1.0.0', ...extra],
    { encoding: 'utf8' });
  const rows = readFileSync(outFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  return {
    stats: JSON.parse(stdout),
    header: rows.find((r) => r.k === 'h'),
    procs: rows.filter((r) => r.k === 'p'),
    events: rows.filter((r) => r.k === 'e'),
    lost: rows.filter((r) => r.k === 'x'),
  };
};

// A slice shaped like a real stream: npm's own subtree, a lifecycle shell, a two-path `renameat`,
// a failed lookup, a refusal, a tracer fault, and the adapter's END-time trailer.
const TRACE = `
DTRACE-LIVE|target=3888
EXEC|3896|3895|node|node
EXECARGV|3950|3896|sh|-c|node install.js && mv a b
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj/node_modules/demo
OPEN|3950|3896|sh|flags=0x601|ret=3|errno=0|ev=11|dirfd=-2|./out.txt
OPEN|3950|3896|sh|flags=0x0|ret=-1|errno=2|ev=12|dirfd=-2|./probe-missing.txt
OPEN|3950|3896|sh|flags=0x0|ret=-1|errno=13|ev=13|dirfd=-2|/Users/runner/.ssh/id_rsa
PATHOP|3952|3950|mv|renameat|ret=0|errno=0|ev=21|dirfd=-2|role=p1|./src.txt
PATHOP|3952|3950|mv|renameat|ret=0|errno=0|ev=21|dirfd=-2|role=p2|./dst.txt
PATHOP|3952|3950|rm|unlinkat|ret=0|errno=0|ev=22|dirfd=-2|role=only|./gone.txt
PATHOP|3896|3895|node|mkdir|ret=0|errno=0|/Users/runner/.npm/_logs
TRACER-ERROR|3958|3950|mv|epid=31|action=6|fault=3|addr=0x2396f00
CONN|3950|3896|node|af=2|140.82.113.4|port=443|ret=-1|errno=36
TRACER-ERROR-TOTAL|1
--- all opens by execname (breadth control) ---
  node                                     412
--- all execs by execname ---
  sh                                         1
DTRACE-END
`;

test("NO SCOPE TAG APPEARS ANYWHERE — the log retains inputs, never today's classification", () => {
  // ⛔ THE CASE THE WHOLE DESIGN TURNS ON. A path tagged `deps`/`project`/`userHome`/`outside`
  // freezes the classifier that produced it: the `tmp` scope being introduced right now did not
  // exist when the corpus was measured, so a scope-tagged log needs a RE-MEASURE where a raw log
  // needs a RE-PARSE. RED ON REVERT: emit `scope: scopeOf(path)` on each event.
  const { events, header } = convert(TRACE);
  const text = JSON.stringify(events);
  for (const s of ['"scope"', '"deps"', '"project"', '"userHome"', '"outside"', '"systemfs"']) {
    assert.ok(!text.includes(s), `a derived scope leaked into the retained log: ${s}`);
  }
  // The ROOTS are retained instead, which is what makes every scope — today's and tomorrow's —
  // recomputable from the file alone.
  assert.equal(header.roots.project, '/proj');
  assert.equal(header.roots.home, '/Users/runner');
  assert.equal(header.roots.ownPkg, '/proj/node_modules/demo');
});

test('the RAW syscall survives beside the neutral class', () => {
  // RED ON REVERT: emit only `o`. `renameat` and `renameatx_np` then read identically to `rename`,
  // and a model that later needs to tell an atomic swap from an ordinary rename cannot.
  const { events } = convert(TRACE);
  assert.equal(events.find((e) => e.o === 'rename').s, 'renameat');
  assert.equal(events.find((e) => e.o === 'unlink').s, 'unlinkat');
});

test('a two-path operation stays ONE event carrying both paths', () => {
  // RED ON REVERT: emit the two halves as independent records. Two interleaved renames on one
  // thread then lose which destination went with which source — recoverable from nothing.
  const { events, stats } = convert(TRACE);
  const ren = events.find((e) => e.o === 'rename');
  assert.equal(ren.f, '/proj/node_modules/demo/src.txt');
  assert.equal(ren.g, '/proj/node_modules/demo/dst.txt');
  assert.equal(ren.w, 1, 'both ends of a rename are mutations');
  assert.equal(stats.pairedTwoPath, 1);
  assert.equal(stats.danglingPair, 0);
});

test('a destination record the tracer dropped is retained UNPAIRED and counted', () => {
  // The rename-destination defect lost 26 of 26 destinations while the decoder printed a confident
  // grant. A log that silently discarded the surviving half would hide the same class of loss.
  const { events, stats } = convert(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|mv a b
EXEC|3950|3896|sh|sh
PATHOP|3952|3950|mv|renameat|ret=0|errno=0|ev=21|dirfd=-2|role=p1|/tmp/lonely-src.txt
`);
  assert.equal(stats.danglingPair, 1);
  assert.ok(events.find((e) => e.missingPair === 1), 'the half that survived must still be there');
});

test('the TRACER LOSS LEDGER is in the stream, not only in a total', () => {
  // ⛔ dtrace aborts a whole clause on a copyin fault, so the event is DROPPED — and a dropped event
  // is a path never seen, which is a capability never granted. A truncated `self->np2` lost 100% of
  // rename destinations for as long as the adapter existed, silently, because dtrace complained to a
  // stderr file nothing downstream read. WHERE the holes are has to be in the log.
  const { lost, stats } = convert(TRACE);
  assert.equal(stats.tracerErrors, 1);
  assert.equal(lost.length, 1, 'the fault must be its own record');
  assert.match(lost[0].sig, /epid=31\|action=6/, 'and must name the clause that faulted');
  assert.equal(lost[0].p, 3958, 'and the process, so a loss is attributable to a subtree');
});

test('attribution is RECORDED per process and stays RECOMPUTABLE', () => {
  // RED ON REVERT: keep a per-event `lifecycle` boolean and drop the process table. Today's rule is
  // "argv[0] is a shell and argv[1] is -c"; a future rule keying on the script BODY, or on npm's own
  // exec of node-gyp, replays from the argv and cannot replay from a boolean.
  const { procs } = convert(TRACE);
  const shell = procs.find((p) => p.pid === 3950);
  assert.deepEqual(JSON.parse(shell.argv), ['sh', '-c', 'node install.js && mv a b']);
  assert.equal(shell.life, 1);
  assert.equal(shell.cwd, '/proj/node_modules/demo', 'the cwd is what makes a path re-resolvable');
  assert.equal(procs.find((p) => p.pid === 3896).life, 0, "npm's own pid is not the package's");
  assert.equal(procs.find((p) => p.pid === 3952).life, 1, 'a child of the shell IS the package');
});

test("npm's own events are retained too, not filtered out at capture time", () => {
  // Attribution is a per-process FACT in this file, so an event outside the lifecycle subtree stays
  // — a future rule that attributes differently needs npm's half of the stream to attribute it TO.
  const { events } = convert(TRACE);
  assert.ok(events.find((e) => e.f === '/Users/runner/.npm/_logs'), "npm's write must survive");
});

test('a REFUSAL is retained, and the errno keeps its identity', () => {
  // ⛔ EACCES/EPERM/EROFS ARE NEVER FILTERED — they are the only direct evidence that confinement
  // refused something. And `r` is the errno SYMBOL, not `ok|denied`: that word collapses ENOENT,
  // EACCES, EEXIST and ENOTDIR into one, and they are four different answers about what a grant
  // would have to do.
  const { events, stats } = convert(TRACE);
  assert.equal(stats.refusals, 1);
  assert.equal(events.find((e) => e.f === '/Users/runner/.ssh/id_rsa').r, 'EACCES');
});

test('Darwin errno numbering is used, not Linux numbering', () => {
  // ⛔ THE TABLE IS PLATFORM-SPECIFIC AND THE VALUES REALLY DIVERGE: 35 is EAGAIN on Darwin and
  // ENOTEMPTY-adjacent nonsense if read with Linux's table, and 36 is EINPROGRESS here against
  // ENAMETOOLONG there. A shared reader sees the SYMBOL, so the mapping has to be right at the
  // point where the number is still known.
  const { events } = convert(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|true
EXEC|3950|3896|sh|sh
OPEN|3950|3896|sh|flags=0x0|ret=-1|errno=66|ev=1|dirfd=-2|/tmp/notempty-x
OPEN|3950|3896|sh|flags=0x0|ret=-1|errno=17|ev=2|dirfd=-2|/tmp/exists-x
`);
  assert.equal(events.find((e) => e.f === '/tmp/notempty-x').r, 'ENOTEMPTY');
  assert.equal(events.find((e) => e.f === '/tmp/exists-x').r, 'EEXIST');
});

test('write intent is read from the OPEN FLAGS and spelled symbolically', () => {
  // By the time write(2) runs the fd has hidden the path, so an open that never writes still
  // establishes the need for a write grant. RED ON REVERT: drop the `w` assignment for `open-w`.
  const { events } = convert(TRACE);
  const w = events.find((e) => e.f === '/proj/node_modules/demo/out.txt');
  assert.equal(w.o, 'open-w');
  assert.equal(w.w, 1);
  assert.match(w.fl, /O_WRONLY/);
  assert.match(w.fl, /O_CREAT/);
  const r = events.find((e) => e.f === '/Users/runner/.ssh/id_rsa');
  assert.equal(r.o, 'open-r');
  assert.equal(r.w, undefined, 'a read-only open must not carry write intent');
});

test('a FAILED LOOKUP is retained by default, because it names a path the script probed for', () => {
  // The obvious "safe" filter is ENOENT: the file does not exist, so no grant changes the outcome.
  // It is NOT clean — a failed lookup records a FALLBACK the script went looking for, and on a
  // machine where that path exists the same script reads it. The Linux lane measured the sharpest
  // version: 21,142 of `lmdb-store`'s ENOENT probes are the C++ include search path, which HITS on
  // a box with a different gcc layout. Retained; `--drop-enoent` exists to SIZE the alternative.
  const { events, stats, header } = convert(TRACE);
  assert.equal(stats.enoent, 1);
  assert.ok(events.find((e) => e.f === '/proj/node_modules/demo/probe-missing.txt'));
  assert.deepEqual(header.filters, []);

  const dropped = convert(TRACE, ['--drop-enoent']);
  assert.ok(!dropped.events.find((e) => e.f === '/proj/node_modules/demo/probe-missing.txt'));
  assert.deepEqual(dropped.header.filters, ['drop-enoent'], 'a filtered log must say so');
  assert.ok(dropped.events.find((e) => e.r === 'EACCES'), 'and must still carry the refusals');
});

test('--drop-enoent is REFUSED on a jailed trace, where ENOENT can BE the refusal', () => {
  // A confinement layer that HIDES a path reports it missing rather than refused — Linux
  // mount-namespace hiding and macOS Seatbelt both do. Dropping ENOENT there would delete the
  // refusals while leaving a log that still looks complete.
  assert.throws(() => convert(TRACE, ['--drop-enoent', '--jailed']), /status 2|Command failed/);
});

test('the adapter trailer is recognised, so `unparsed` stays a real alarm', () => {
  // RED ON REVERT: delete the TRAILER match. `unparsed` then reports 4 on every clean run, and an
  // alarm that is always non-zero cannot tell you the wire format has moved.
  const { stats } = convert(TRACE);
  assert.equal(stats.unparsed, 0, 'nothing in a well-formed stream may fall through unrecognised');
});

test('identical calls collapse into one event carrying `n`', () => {
  // Dedup is on the IDENTITY of the call, not the path: same process, same syscall, same paths,
  // same result, same flags is the same fact. Lossless for a capability model because `n` keeps the
  // frequency — and it is what makes retention affordable at corpus scale.
  const { events, stats } = convert(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|true
EXEC|3950|3896|sh|sh
OPEN|3950|3896|sh|flags=0x0|ret=0|errno=0|ev=1|dirfd=-2|/tmp/same-x
OPEN|3950|3896|sh|flags=0x0|ret=0|errno=0|ev=2|dirfd=-2|/tmp/same-x
OPEN|3950|3896|sh|flags=0x0|ret=0|errno=0|ev=3|dirfd=-2|/tmp/same-x
`);
  const e = events.find((x) => x.f === '/tmp/same-x');
  assert.equal(e.n, 3, 'three identical calls, one event, frequency preserved');
  assert.equal(stats.distinctEvents, stats.distinctEvents);
  assert.equal(events.filter((x) => x.f === '/tmp/same-x').length, 1);
});

test('a relative path under a REAL dirfd is flagged rather than resolved', () => {
  // ⛔ Resolving it against the cwd would invent a path no process touched — a fabricated path can
  // widen a grant on evidence that does not exist, which is the symlink-target defect again.
  const { events, stats } = convert(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|node x.js
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3952|3950|node|mkdirat|ret=0|errno=0|ev=1|dirfd=7|role=only|rel/under-fd
`);
  assert.equal(stats.unresolvedDirfd, 1);
  const e = events.find((x) => x.f === 'rel/under-fd');
  assert.equal(e.u, '7', 'marked unresolved, in the shared spelling');
  assert.equal(e.dfd, 7, 'and the raw dirfd survives, so an fd table could resolve it later');
  assert.ok(!events.find((x) => x.f === '/proj/rel/under-fd'), 'no invented absolute path');
});
