// Golden cases for the RETAINED event log. `node --test harness/v2/adapters/macos-eventlog.test.mjs`.
//
// ⛔ THE BAR HERE IS NOT "does it parse". It is the one the retention decision rests on:
//
//     the retained log must let ANY FUTURE grant model be re-derived, without re-running the
//     package.
//
// So the cases below are mostly about what must NOT be in the file (a classification standing in
// for its input) and what must survive intact (the raw syscall, both paths of a two-path op, the
// errno, and enough process identity to recompute attribution under a rule that does not exist
// yet). A parser test would pass on a log that is useless a month from now.
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
      '--project', '/proj', '--home', '/Users/runner', '--pkg', 'demo@1.0.0', ...extra],
    { encoding: 'utf8' });
  const body = readFileSync(outFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  return { stats: JSON.parse(stdout), meta: body[0], events: body.slice(1) };
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

test('NO SCOPE TAG APPEARS ANYWHERE — the log retains inputs, never today\'s classification', () => {
  // ⛔ THE CASE THE WHOLE DESIGN TURNS ON. A path tagged `deps`/`project`/`userHome`/`outside`
  // freezes the classifier that produced it: the `tmp` scope being introduced right now did not
  // exist when the corpus was measured, so a scope-tagged log needs a RE-MEASURE where a raw log
  // needs a RE-PARSE. RED ON REVERT: emit `scope: scopeOf(path)` on each event.
  const { events } = convert(TRACE);
  const text = JSON.stringify(events);
  for (const s of ['"scope"', '"deps"', '"project"', '"userHome"', '"outside"', '"systemfs"']) {
    assert.ok(!text.includes(s), `a derived scope leaked into the retained log: ${s}`);
  }
  // The ROOTS are retained instead, which is what makes every scope — today's and tomorrow's —
  // recomputable from the file alone.
  const { meta } = convert(TRACE);
  assert.equal(meta.project, '/proj');
  assert.equal(meta.home, '/Users/runner');
});

test('the RAW syscall survives beside the neutral class', () => {
  // RED ON REVERT: emit only `op`. `renameat` and `renamex_np` then read identically to `rename`,
  // and a model that later needs to tell an atomic swap from an ordinary rename cannot.
  const { events } = convert(TRACE);
  const ren = events.find((e) => e.op === 'rename');
  assert.equal(ren.call, 'renameat', 'the kernel-level name must be recoverable');
  const un = events.find((e) => e.op === 'unlink');
  assert.equal(un.call, 'unlinkat');
});

test('a two-path operation stays ONE event carrying both paths', () => {
  // RED ON REVERT: emit the two halves as independent records. Two interleaved renames on one
  // thread then lose which destination went with which source — recoverable from nothing.
  const { events, stats } = convert(TRACE);
  const ren = events.find((e) => e.op === 'rename');
  assert.equal(ren.path, './src.txt');
  assert.equal(ren.path2, './dst.txt');
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
PATHOP|3952|3950|mv|renameat|ret=0|errno=0|ev=21|dirfd=-2|role=p1|./lonely-src.txt
`);
  assert.equal(stats.danglingPair, 1);
  assert.ok(events.find((e) => e.missingPair === true), 'the half that survived must still be there');
});

test('attribution is RECORDED and also RECOMPUTABLE — the argv and the pid tree both survive', () => {
  // RED ON REVERT: keep `lifecycle` but drop the exec records. Today's rule is "argv[0] is a shell
  // and argv[1] is -c"; a future rule keying on the script BODY, or on npm's own exec of node-gyp,
  // can be replayed from the argv and cannot be replayed from a boolean.
  const { events } = convert(TRACE);
  const shell = events.find((e) => e.kind === 'exec' && e.lifecycleShell);
  assert.deepEqual(shell.argv, ['sh', '-c', 'node install.js && mv a b']);
  assert.equal(events.find((e) => e.path === './out.txt').lifecycle, true, "the script's own write");
  assert.equal(events.find((e) => e.path === '/Users/runner/.npm/_logs').lifecycle, false,
    "npm's own write must be retained too, marked as not the package's");
});

test('a REFUSAL is retained — that is the signal a grant is missing', () => {
  // ⛔ EACCES/EPERM/EROFS ARE NEVER FILTERED. They are the only direct evidence that confinement
  // refused something, so a filter that removed them would delete the answer to the one question
  // the diagnose arm exists to ask.
  const { events, stats } = convert(TRACE);
  assert.equal(stats.refusals, 1);
  assert.ok(events.find((e) => e.errno === 13 && e.path === '/Users/runner/.ssh/id_rsa'));
});

test('a FAILED LOOKUP is retained by default, because it names a path the script probed for', () => {
  // The obvious "safe" filter is `= -1 ENOENT`: the file does not exist, so no grant changes the
  // outcome. It is NOT clean — a failed lookup records a FALLBACK the script went looking for, and
  // on a machine where that path exists the same script reads it. Retained; `--drop-enoent` exists
  // to SIZE the alternative, and the log states in `meta.filters` when it has been applied.
  const { events, stats, meta } = convert(TRACE);
  assert.equal(stats.enoent, 1);
  assert.ok(events.find((e) => e.path === './probe-missing.txt'), 'the probed path must survive');
  assert.deepEqual(meta.filters, []);

  const dropped = convert(TRACE, ['--drop-enoent']);
  assert.ok(!dropped.events.find((e) => e.path === './probe-missing.txt'));
  assert.deepEqual(dropped.meta.filters, ['drop-enoent'], 'a filtered log must say so');
  assert.ok(dropped.events.find((e) => e.errno === 13), 'and must still carry the refusals');
});

test('--drop-enoent is REFUSED on a jailed trace, where ENOENT can BE the refusal', () => {
  // A confinement layer that HIDES a path reports it missing rather than refused — Linux
  // mount-namespace hiding and macOS Seatbelt both do this. Dropping ENOENT there would delete the
  // refusals while leaving a log that looks complete.
  assert.throws(() => convert(TRACE, ['--drop-enoent', '--jailed']), /status 2|Command failed/);
});

test('the adapter trailer is recognised, so `unparsed` stays a real alarm', () => {
  // RED ON REVERT: delete the TRAILER match. `unparsed` then reports 4 on every clean run, and an
  // alarm that is always non-zero cannot tell you the wire format has moved.
  const { stats } = convert(TRACE);
  assert.equal(stats.unparsed, 0, 'nothing in a well-formed stream may fall through unrecognised');
  assert.equal(stats.tracerErrors, 1, 'and the tracer fault is still counted');
});

test('a relative path under a REAL dirfd is flagged rather than resolved', () => {
  const { events, stats } = convert(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|node x.js
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3952|3950|node|mkdirat|ret=0|errno=0|ev=1|dirfd=7|role=only|rel/under-fd
`);
  assert.equal(stats.unresolvableDirfd, 1);
  const e = events.find((x) => x.path === 'rel/under-fd');
  assert.equal(e.pathUnresolvable, true, 'the record is kept; only the RESOLUTION is withheld');
  assert.equal(e.dirfd, 7, 'and the dirfd survives, so an fd table could resolve it later');
});
