// ⛔ THE FAILURE DUMP MUST SHOW NUB'S ERROR, NOT 30 LINES OF h2 FRAMES.
//
// When nub cannot materialize an arm's tree the drivers print the tail of `security-resolve.log`,
// because that is the ONLY place the reason exists — the record carries `verdict: HARNESS-ERROR` and
// nothing about why, and the log is parked outside `records-v2/` so it never reaches the artifact.
//
// The arm runs nub under `RUST_LOG=debug` for phase timings. MEASURED on run 33293351038: five
// `HARNESS-ERROR`s printed the header and then 30 unbroken lines of
// `DEBUG received frame=Data { stream_id: StreamId(37) }` — nub's actual error had scrolled out of
// the window, so the cause was invisible for the second time in three epochs. It had appeared to work
// one epoch earlier only because a trust refusal aborts EARLY, before any registry traffic: the
// diagnostic was never right, it was lucky.
//
// The second test is the one worth having. A filter that also ate the error line would look correct
// in the source and be worse than no filter at all, so both the shell ERE and the JS regex are run
// against input carrying every shape that matters.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');

/// The dump block in each driver: from the "nub's own words" header to the end of the statement.
function dumpBlock(file) {
  const lines = read(file).split('\n');
  const i = lines.findIndex((l) => l.includes("nub's own words (tail of security-resolve.log)"));
  // Wide enough to span the rationale comment that sits between the header and the command. The
  // first version used 6 lines and reported "no filtering step" for a driver that had one — the
  // extractor was short, not the driver.
  return i === -1 ? null : lines.slice(i, i + 14).join('\n');
}

for (const file of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
  test(`${file} strips RUST_LOG=debug lines before tailing the resolve log`, () => {
    const block = dumpBlock(file);
    // Control: without this every assertion below passes the moment the header is reworded.
    assert.ok(block, `no resolve-log dump found in ${file} — the anchor moved, so this asserts nothing`);
    assert.match(block, /DEBUG/,
      `${file} tails the resolve log unfiltered, so a failure after real registry traffic dumps 30 `
      + 'lines of h2 frames and no error — which is exactly what run 33293351038 did');
    assert.match(block, /(grep -av|filter\()/, `${file} has no filtering step in the dump`);
  });
}

/// Every shape that must survive, and the two that must not.
const SAMPLE = [
  'DEBUG received frame=Data { stream_id: StreamId(37) }',   // drop: unindented
  '  DEBUG send frame=Reset { error_code: CANCEL }',          // drop: indented
  'ERR_NUB_TRUST_DOWNGRADE',                                  // keep
  '  × failed to resolve dependencies',                       // keep
  '  ╰─▶ trust downgrade for fastq@1.20.2',                   // keep
  'not debugging at all',                                     // keep: substring, not the level
].join('\n');
const KEEP = ['ERR_NUB_TRUST_DOWNGRADE', 'failed to resolve dependencies', 'trust downgrade for fastq',
  'not debugging at all'];

test('the shell filter keeps every error line and drops only the frames', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-dump-')), 'log');
  fs.writeFileSync(f, `${SAMPLE}\n`);
  const r = spawnSync('bash', ['-c', `grep -avE '(^|[[:space:]])DEBUG[[:space:]]' ${JSON.stringify(f)}`],
    { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  for (const k of KEEP) assert.match(r.stdout, new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
    `the shell filter ate \`${k}\` — a filter that removes the error is worse than no filter`);
  assert.doesNotMatch(r.stdout, /stream_id/, 'the shell filter left the h2 frame spew in');
});

test('the JS filter agrees with the shell filter, line for line', () => {
  // The drivers are two languages implementing one rule; a divergence means Windows and POSIX
  // disagree about what a diagnosis looks like, which is how a platform-only blind spot starts.
  const js = SAMPLE.split('\n').filter((l) => !/(^|\s)DEBUG\s/.test(l));
  for (const k of KEEP) assert.ok(js.some((l) => l.includes(k)), `the JS filter ate \`${k}\``);
  assert.ok(!js.some((l) => l.includes('stream_id')), 'the JS filter left the h2 frame spew in');
  assert.equal(js.length, KEEP.length, `expected ${KEEP.length} surviving lines, got ${js.length}`);
});
