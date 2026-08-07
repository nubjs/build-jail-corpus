// The measure-step gate: a slice that measured NOTHING must fail; a slice that measured SOMETHING
// must not.
//
// ⛔ THE NEGATIVE CONTROLS ARE THE LOAD-BEARING TESTS HERE. "Fail when zero records were produced"
// is satisfiable by failing always, so the partial-slice and all-skipped cases are what prove the
// gate discriminates rather than just refusing. Deleting them would leave a green suite around a
// gate that can never let a real slice through.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { judgeSlice, countSpecs } from './assert-slice-measured.mjs';

const HERE = import.meta.dirname;
const summary = (a, r, s) => `v2 batch: ${a} attempted, ${r} recorded, ${s} skipped (already measured)`;

// ⛔ CONTROL FIRST: the summary regex must match the string `run-batch-v2.mjs` REALLY prints. A
// regex that matched nothing would report every run as "died before its loop" — a gate that fails
// always, which is the failure mode the negative controls below exist to exclude. Read the format
// out of the driver's own source rather than restating it, so the two cannot drift apart.
test('CONTROL: the summary the batch driver actually prints is the one this gate parses', () => {
  const src = fs.readFileSync(path.join(HERE, 'run-batch-v2.mjs'), 'utf8');
  assert.match(src, /v2 batch: \$\{attempted\} attempted, \$\{recorded\} recorded, \$\{skipped\} skipped/,
    'run-batch-v2.mjs no longer prints the summary this gate keys on — update both together');
  const parsed = judgeSlice({ requested: 4, log: summary(4, 4, 0), batchRc: 0 });
  assert.equal(parsed.ok, true);
  assert.deepEqual(
    { a: parsed.summary.attempted, r: parsed.summary.recorded, s: parsed.summary.skipped },
    { a: 4, r: 4, s: 0 },
    'the regex matched but extracted the wrong fields',
  );
});

test('⭑ run 31145732202: a batch that refused to start is a FAILURE, not a success', () => {
  // The real shape — the falsification control refuses, `run-batch-v2.mjs` exits non-zero before its
  // loop, and no summary line is ever printed.
  const log = [
    'falsify: FAIL — 0/1 case(s) detected their wrong grant, 1 FAILED',
    '⛔ The harness could not be shown capable of rejecting a known-insufficient grant.',
    '⛔ falsification control did not pass (rc=1) — refusing to start the batch.',
  ].join('\n');
  const v = judgeSlice({ requested: 10, log, batchRc: 1 });
  assert.equal(v.ok, false, 'a 10-row slice that produced no summary line must not pass');
  assert.match(v.reason, /no summary line/);
});

test('a slice whose every package failed to record is a FAILURE', () => {
  const v = judgeSlice({ requested: 10, log: summary(10, 0, 0), batchRc: 1 });
  assert.equal(v.ok, false, '10 attempted and 0 settled is the nothing-happened case');
  assert.match(v.reason, /NOTHING was settled/);
});

test('NEGATIVE CONTROL: a PARTIAL slice still passes, so the gate is not just "always fail"', () => {
  const v = judgeSlice({ requested: 10, log: summary(4, 3, 0), batchRc: 1 });
  assert.equal(v.ok, true,
    'a batch that recorded 3 of 10 and then died has three real measurements the commit step must keep');
  assert.match(v.reason, /PARTIAL/);
});

test('NEGATIVE CONTROL: an all-already-measured resume passes with zero NEW records', () => {
  const v = judgeSlice({ requested: 10, log: summary(0, 0, 10), batchRc: 0 });
  assert.equal(v.ok, true, 'every row is answered; recording nothing new is the correct outcome');
});

test('a deadline that cut off every package still fails, and the reason says so', () => {
  const log = [summary(0, 0, 0), 'DEADLINE: stopped before 10 package(s) — the job cap would have killed the run'].join('\n');
  const v = judgeSlice({ requested: 10, log, batchRc: 0 });
  assert.equal(v.ok, false, 'burning a slice on setup and measuring nothing is a defect, not a pass');
  assert.match(v.reason, /deadline/);
});

test('the LAST summary decides, so a retried invocation does not read off a stale line', () => {
  const log = [summary(10, 0, 0), 'retrying', summary(10, 6, 0)].join('\n');
  assert.equal(judgeSlice({ requested: 10, log, batchRc: 0 }).ok, true);
  const reversed = [summary(10, 6, 0), 'retrying', summary(10, 0, 0)].join('\n');
  assert.equal(judgeSlice({ requested: 10, log: reversed, batchRc: 0 }).ok, false);
});

test('an empty slice is not a failure — nothing was claimed', () => {
  assert.equal(judgeSlice({ requested: 0, log: '', batchRc: 0 }).ok, true);
});

test('countSpecs matches how the batch driver counts its own worklist', () => {
  assert.equal(countSpecs('a@1\n\n  b@2  \nc@3\n'), 3);
  assert.equal(countSpecs(''), 0);
});

// ⛔ THE CLI IS TESTED SEPARATELY FROM THE FUNCTION because the failure this gate exists to catch is
// an exit code, and a pure-function test cannot observe one. `cli-guard.test.mjs` covers the Windows
// entry-guard spelling; this covers that the guard's body actually runs and exits non-zero.
test('the CLI exits non-zero on a lost slice and zero on a partial one', (t) => {
  const dir = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || '/tmp', 'slice-gate-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const slice = path.join(dir, 'slice.txt');
  fs.writeFileSync(slice, 'a@1\nb@2\nc@3\n');
  const run = (log) => {
    const lp = path.join(dir, 'measure.log');
    fs.writeFileSync(lp, log);
    return spawnSync(process.execPath,
      [path.join(HERE, 'assert-slice-measured.mjs'), '--log', lp, '--slice', slice, '--rc', '1'],
      { encoding: 'utf8' });
  };
  const lost = run('⛔ refusing to start the batch.');
  assert.equal(lost.status, 1, `a lost slice must exit 1; got ${lost.status}\n${lost.stdout}${lost.stderr}`);
  assert.match(lost.stderr, /MEASURED NOTHING/);

  const partial = run(summary(2, 1, 0));
  assert.equal(partial.status, 0,
    `a partial slice must exit 0; got ${partial.status}\n${partial.stdout}${partial.stderr}`);
  assert.match(partial.stdout, /measure gate:/);
});

test('an unreadable worklist fails rather than reading as an empty slice', () => {
  const r = spawnSync(process.execPath,
    [path.join(HERE, 'assert-slice-measured.mjs'), '--log', '/nonexistent', '--slice', '/nonexistent/slice.txt'],
    { encoding: 'utf8' });
  assert.equal(r.status, 1, 'a missing worklist is the Windows path defect itself — it must not pass');
  assert.match(r.stderr, /cannot read the worklist/);
});
