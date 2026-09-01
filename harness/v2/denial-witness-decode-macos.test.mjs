// THE PRODUCER CHAIN ON DARWIN, END TO END WITHOUT A JAIL: raw dtrace text ->
// `adapters/macos-eventlog.mjs --jailed` -> `denial-witness.mjs` -> a marker `record.mjs` parses.
// `node --test harness/v2/denial-witness-decode-macos.test.mjs`.
//
// ⛔ WHY A SECOND FILE RATHER THAN MORE CASES IN `denial-witness-decode.test.mjs`. That file certifies
// the LINUX chain: strace syntax, `adapters/linux.mjs`, and an adapter that declares `netRefusals`.
// Nothing in it executes a line of the darwin decoder, and for the first day of the witness's life
// that was the whole story — the scorer was wired into `measure.sh` alone, so `denialWitness` was
// empty on all 2,293 committed darwin records and the keep-the-grant branch could not fire on this
// platform at all. Two things sit between the scorer and a darwin trace and both have broken silently
// before: the adapter's `life` attribution and its errno decode.
//
// ⛔ THE LINE FORMATS ARE COPIED FROM A COMMITTED TRACE, NOT INVENTED.
// `records-v2/runs/darwin-arm64/phantomjs/2.1.7/trace.txt.gz` contains, verbatim in shape:
//
//   DTRACE-LIVE|target=70708
//   EXECARGV|70750|70732|sh|-c|node install.js
//   PATHOP|70750|70732|node|link|ret=-1|errno=1|ev=2601695719083|dirfd=-2|role=only|/Users/runner/…
//
// That last line is a REAL refusal: a real `link()` that really returned EPERM to a real lifecycle
// process on a real macOS runner. Scored with that record's own roots it is CLEAN, because its path
// lies inside the arm's scratch tree, which the driver excludes. The cases below move the path, not
// the syntax.
//
// ⛔ WHAT THIS CANNOT PROVE, AND IT IS THE SAME ASSUMPTION THE LINUX FILE LEAVES OPEN. It shows the
// chain works when the arm's trace contains a lifecycle `-c` shell and a refusal the tracer saw.
// Whether SEATBELT's denial reaches the dtrace return probe on a jailed `nub install` is a property
// of the platform, and the evidence for it is the DIAGNOSE arm: 223 committed darwin records re-ran a
// failing grant jailed under dtrace, none printed "no diagnose trace produced", and 19 decoded a
// refusal on a path under the real user home. If it ever stops holding, the adapter attributes the
// refusal to nobody, the witness returns VOID, and the record keeps the wide grant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const HOME = '/Users/runner';
const ROOT = '/Users/runner/v2m-YsikFx';
const ARM = `${ROOT}/verify-nar-no-write-userHome`;

const LIVE = 'DTRACE-LIVE|target=70708';
// argv[0] is a shell and argv[1] is `-c` — the adapter's whole lifecycle rule, and the reason this
// file cannot re-derive attribution from pids.
const LIFECYCLE_EXEC = 'EXECARGV|70750|70732|sh|-c|node install.js';

const refusedLink = (path, pid = 70750) =>
  `PATHOP|${pid}|70732|node|link|ret=-1|errno=1|ev=2601695719083|dirfd=-2|role=only|${path}`;

// Enough successful opens to clear `MIN_EVENTS`. Distinct paths, because the adapter dedups.
const filler = (n) => Array.from({ length: n }, (_, i) =>
  `OPEN|70750|70732|node|flags=0x0|ret=3|errno=0|ev=${1000 + i}|dirfd=-2|${ARM}/node_modules/m${i}.js`);

// The chain: write a trace, decode it with the shipped adapter, score it, return the marker payload.
const chain = (traceLines, { jailed = true, cap = 'no-write-userHome' } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), 'dwdm-'));
  const trace = join(dir, 'trace.txt');
  writeFileSync(trace, `${traceLines.join('\n')}\n`);
  const events = join(dir, 'events.ndjson');
  execFileSync(process.execPath, [join(HERE, 'adapters', 'macos-eventlog.mjs'), trace,
    '--project', ARM, '--home', HOME, '--jail-home', `${ROOT}/jailhome`,
    '--pkg', 'phantomjs', '--version', '2.1.7',
    ...(jailed ? ['--jailed'] : []), '--out', events], { stdio: 'ignore' });
  const out = execFileSync(process.execPath, [join(HERE, 'denial-witness.mjs'),
    '--cap', cap, '--events', events, '--exclude', ROOT], { encoding: 'utf8' });
  // The CLI prints the marker and then `     <VERDICT> — <reason>`; the reason is NOT in the JSON
  // payload, so it is lifted here to keep a failure self-debugging.
  return { out,
    why: out.split('\n').find((l) => / — /.test(l))?.trim() ?? out,
    payload: JSON.parse(/DENIAL-WITNESS (\{.*\})/.exec(out)[1]) };
};

test('a refused write under the REAL home, by the lifecycle subtree, witnesses', () => {
  const { payload, why } = chain([
    LIVE, LIFECYCLE_EXEC, ...filler(250), refusedLink(`${HOME}/.cache/phantomjs/phantom`),
  ]);
  assert.equal(payload.verdict, 'WITNESSED', why);
  assert.equal(payload.refusalsInScope, 1, why);
  assert.equal(payload.lifecyclePids, 1, why);
  // The sample line is what a human reads out of `driver.out`; `undefined` in it reads as a broken
  // detector, so the path is asserted rather than just the count.
  assert.match(payload.sample[0], /link \/Users\/runner\/\.cache\/phantomjs\/phantom = -1 EPERM/);
});

test('the SAME refusal inside the arm\'s own scratch tree is CLEAN — the driver excludes $ROOT', () => {
  // This is the committed `phantomjs@2.1.7` case as it actually stands: the refused path is real and
  // under `/Users/runner`, and it scores CLEAN only because every arm directory lives under `$ROOT`.
  // Without the exclusion the harness would witness on its own scratch tree and never narrow again.
  const { payload, why } = chain([
    LIVE, LIFECYCLE_EXEC, ...filler(250),
    refusedLink(`${ARM}/node_modules/phantomjs/lib/phantom`),
  ]);
  assert.equal(payload.verdict, 'CLEAN', why);
  assert.equal(payload.refusalsInScope, 0, why);
});

test('a refusal OUTSIDE the lifecycle subtree does not witness — attribution is the adapter\'s', () => {
  // pid 70732 is the `npm` that spawned the lifecycle shell, so the adapter marks it life:0. It is
  // the tool process; billing its EPERM against the package would witness on every arm.
  const { payload, why } = chain([
    LIVE, LIFECYCLE_EXEC, ...filler(250),
    refusedLink(`${HOME}/.cache/phantomjs/phantom`, 70732),
  ]);
  assert.equal(payload.verdict, 'CLEAN', why);
  assert.equal(payload.refusalsInScope, 0, why);
});

test('an OBSERVE stream is VOID, never CLEAN — scoring one would license every narrowing', () => {
  // OBSERVE runs UNJAILED, so it contains no jail refusal at all and every arm would read CLEAN. The
  // guard is the header flag the adapter stamps from its own `--jailed`.
  const { payload, why } = chain([LIVE, LIFECYCLE_EXEC, ...filler(250)], { jailed: false });
  assert.equal(payload.verdict, 'VOID', why);
  assert.match(why, /not marked `jailed`/);
});

test('a trace too small to have observed an install is VOID', () => {
  const { payload, why } = chain([LIVE, LIFECYCLE_EXEC, ...filler(10)]);
  assert.equal(payload.verdict, 'VOID', why);
  assert.match(why, /decoded events/);
});

test('the network axis is UNSUPPORTED on darwin, because the probe cannot see the refusal', () => {
  // ⛔ RED ON REVERT: `adapters/macos-observe.d` has `connect` clauses and NO `socket` clause, so a
  // Seatbelt network denial leaves no event. If `macos-eventlog.mjs` ever declares `netRefusals`
  // without the probe growing that clause, this stream would score CLEAN and license dropping
  // `network` from a package that needs it.
  const { payload, why } = chain([LIVE, LIFECYCLE_EXEC, ...filler(250)], { cap: 'no-network' });
  assert.equal(payload.verdict, 'UNSUPPORTED', why);
  assert.ok(!readFileSync(join(HERE, 'adapters', 'macos-eventlog.mjs'), 'utf8').includes('netRefusals'),
    'the darwin adapter must not declare an axis its probe does not capture');
});

test('the emitted marker is the one record.mjs parses — producer and consumer agree', () => {
  const { out } = chain([
    LIVE, LIFECYCLE_EXEC, ...filler(250), refusedLink(`${HOME}/.cache/phantomjs/phantom`),
  ]);
  const line = out.split('\n').find((l) => l.startsWith('DENIAL-WITNESS'));
  const r = parseDriverLog([
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true}}',
    '  => VERIFIED {"write":{"userHome":true}}',
    `  ${line}`,
    "     ⛔ OVER-PREDICTED — the strictly narrower {} also verifies; 'no-write-userHome' was not needed",
  ].join('\n'));
  assert.deepEqual(r.denialWitness, { 'no-write-userHome': 'WITNESSED' });
  assert.deepEqual(r.grant, { write: { userHome: true } }, 'the wide grant must survive');
});
