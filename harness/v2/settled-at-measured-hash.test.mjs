// ⛔ A WITHHELD ROW MUST BE SETTLED AT THE HASH IT WAS MEASURED UNDER.
//
// `settledAtHash` carries one promise, stated in `claim-slice.mjs` itself: "the attempt happened at
// THIS instrument", and the claim path reopens the row the moment the harness moves off that hash.
// That is the whole difference between a row that is SETTLED and one that is ABANDONED.
//
// The end-of-slice commit step breaks the promise by construction. It runs
// `git reset --hard origin/$GITHUB_REF_NAME`, which does two things at once: it pulls `harness/`
// forward to whatever landed on the branch WHILE the slice was measuring, and it restores
// `queue-v2.ndjson` from origin — discarding the correct settle the "Collect verdicts" step already
// wrote, so rows are `claimed` again and `--complete` re-runs against them from the reset tree.
//
// MEASURED 2026-08-28 on run 33167330698: it measured at epoch 12, three harness epochs landed on
// the branch while it ran, and it settled 16 withheld rows at the EPOCH-15 digest. Those rows are
// now frozen against an epoch-15 attempt that never happened — and specifically against the
// era-toolchain fixes in epochs 13/14/15, which are the likeliest thing to resolve why they
// regressed in the first place.
//
// Harness fixes landing mid-drain is DESIGNED behaviour here (the push gate exists to make it safe),
// so this is not a rare race — it is the normal case whenever anything is being fixed.
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = import.meta.dirname;
const CLAIM = path.join(HERE, '..', 'claim-slice.mjs');

/** A scratch queue with one CLAIMED row, plus the verdict and withhold files `--complete` reads. */
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'settle-'));
  // The file MUST be named queue-v2.ndjson: `currentSha` is null for any other queue, so a renamed
  // fixture would exercise nothing and pass no matter what.
  fs.writeFileSync(path.join(dir, 'queue-v2.ndjson'),
    `${JSON.stringify({ pkg: 'demo', version: '1.0.0', os: 'linux', status: 'claimed', run: 'RUNX' })}\n`);
  fs.writeFileSync(path.join(dir, 'verdicts.ndjson'),
    `${JSON.stringify({ pkg: 'demo', version: '1.0.0', verdict: 'UNKNOWN' })}\n`);
  fs.writeFileSync(path.join(dir, 'settled.ndjson'),
    `${JSON.stringify({ pkg: 'demo', version: '1.0.0', settled: 'publish-guard withheld the re-measure' })}\n`);
  return dir;
}

const complete = (dir, extra) => {
  execFileSync(process.execPath, [CLAIM, '--queue', 'queue-v2.ndjson',
    '--complete', 'verdicts.ndjson', '--run', 'RUNX', '--settled', 'settled.ndjson', ...extra],
  { cwd: dir, encoding: 'utf8', stdio: 'pipe' });
  return JSON.parse(fs.readFileSync(path.join(dir, 'queue-v2.ndjson'), 'utf8').trim());
};

test('--complete settles a withheld row at the hash it was told the slice measured under', () => {
  const dir = fixture();
  const row = complete(dir, ['--measured-harness-sha', 'deadbeefdeadbeef']);
  assert.equal(row.status, 'done', 'a withheld row should be settled, not left claimed');
  assert.equal(row.settledAtHash, 'deadbeefdeadbeef',
    'settledAtHash must be the MEASURED identity. Recomputing it from the tree records an '
    + 'instrument the measurement never ran under, and freezes the row against an attempt that '
    + 'never happened.');
  assert.match(row.settledReason, /withheld/, 'the settle should record why');
});

test('CONTROL: without the flag it falls back to the on-disk identity, so the flag is doing the work', () => {
  // Without this the assertion above could pass on a build where the flag is ignored and the scratch
  // dir happens to yield the same string — it cannot, but the control is what proves it cannot.
  const dir = fixture();
  let fellBack = false;
  try {
    const row = complete(dir, []);
    fellBack = row.settledAtHash !== 'deadbeefdeadbeef';
  } catch {
    // `computeHarnessIdentity()` throws in a scratch dir with no instrument inputs — which is itself
    // proof the fallback path ran, since the flag path never calls it.
    fellBack = true;
  }
  assert.ok(fellBack, 'the no-flag path produced the flag value — the flag is not being read at all');
});

test('the runner captures the measured identity BEFORE the reset loop, and passes it', () => {
  const wf = fs.readFileSync(path.join(HERE, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml'), 'utf8');
  const step = wf.slice(wf.indexOf('- name: Commit records and queue'));
  const capture = step.indexOf('MEASURED_SHA=$(');
  const reset = step.indexOf('git reset -q --hard "origin/$GITHUB_REF_NAME"');
  assert.notEqual(capture, -1, 'the commit step never captures the measured harness identity');
  assert.notEqual(reset, -1, 'the reset loop is gone — re-read the step');
  assert.ok(capture < reset,
    'the capture must precede the hard reset. After it, harness/ carries whatever landed on the '
    + 'branch during the slice, which is the entire bug.');
  assert.match(step.slice(0, step.indexOf('--settled "$NUB_CORPUS_SETTLED"')), /--measured-harness-sha/,
    'the captured identity is never passed to --complete');
});
