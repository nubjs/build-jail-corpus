// ⛔ A WITHHELD `HARNESS-*` MUST REACH THE RETRY ACCOUNTING, OR THE ROW CYCLES FOREVER.
//
// `publish-record-v2.sh` parks a `HARNESS-*` record outside `records-v2/` and puts ORIGIN'S PRIOR
// record back. `collect-verdicts.mjs` walks the records tree, so `--complete` then sees that prior
// REAL verdict, marks the row `done`, and stamps it from a record whose `harnessSha256` is stale.
// The next claim's invalidation pass reopens it, the next slice re-measures it, and it fails the
// same way — while the publisher prints "the row stays open; claim-slice --complete returns it to
// pending for retry", which was false for every package that had a prior record on origin.
//
// MEASURED 2026-08-30 across three linux slices 4.5 h apart (33272217260, 33278756575, 33283327384):
// each claimed 60, each withheld the SAME 42 package@versions -- `comm -12` gives 42 of 42 for every
// pair -- and each logged `0 instrument failure(s) returned to pending`. The stuck set grew 27 -> 48
// per slice over 15 hours as converging rows left the pool, and had taken 42 of the linux lane's
// last 105 rows. That lane could not have drained, so no later lane could ever have started.
//
// The second test is the one that keeps the rest honest: with the channel absent, the SAME inputs
// must reproduce the old broken close. Without it every assertion here could pass for some unrelated
// reason and the fix could be reverted silently.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';

const claim = path.join(import.meta.dirname, '..', 'claim-slice.mjs');
const read = (f) => fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map(JSON.parse);

/// One claimed row, a collected verdict carrying the RESTORED PRIOR record, and optionally the
/// withheld `HARNESS-*` this attempt actually produced.
function fixture({ attempts, withheld }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'withheld-if-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const verdicts = path.join(root, 'verdicts.ndjson');
  const failures = path.join(root, 'failures.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', os: 'linux', status: 'claimed', run: 'r1',
    ...(attempts === undefined ? {} : { attempts }),
  })}\n`);
  // The prior record origin still holds: a real verdict, and an identity from an older instrument.
  fs.writeFileSync(verdicts, `${JSON.stringify({
    pkg: 'demo', version: '1.0.0', verdict: 'MINIMUM', harnessVersion: 2,
    harnessEpoch: 3, harnessSha256: 'stale-hash', platform: 'linux-x64',
  })}\n`);
  if (withheld) fs.writeFileSync(failures, `${JSON.stringify({ pkg: 'demo', version: '1.0.0', verdict: withheld })}\n`);
  return { queue, verdicts, failures };
}

const complete = (f, { channel = true } = {}) => {
  const r = spawnSync(process.execPath, [claim, '--queue', f.queue, '--complete', f.verdicts,
    '--run', 'r1', ...(channel ? ['--instrument-failures', f.failures] : [])], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return { row: read(f.queue)[0], stderr: r.stderr };
};

test('a withheld HARNESS-* returns the row to pending instead of closing it on the prior verdict', () => {
  const f = fixture({ withheld: 'HARNESS-ERROR' });
  const { row, stderr } = complete(f);
  assert.equal(row.status, 'pending',
    'the row closed as done on the RESTORED PRIOR record, so the next claim reopens it and the slice '
    + 're-measures it forever — this is the non-convergence the channel exists to end');
  assert.equal(row.attempts, 1, 'the attempt was not counted, so the retry bound can never be reached');
  assert.equal(row.lastInstrumentFailure, 'HARNESS-ERROR');
  assert.match(stderr, /returned to pending/);
});

test('WITHOUT the channel the same inputs still close the row — the control that proves the fix is live', () => {
  // Known-answer control. This is the measured pre-fix behaviour; if it ever stops reproducing, the
  // assertions above are passing for a reason other than the one they name.
  const f = fixture({ withheld: 'HARNESS-ERROR' });
  const { row } = complete(f, { channel: false });
  assert.equal(row.status, 'done', 'the pre-fix path no longer closes the row, so the control is vacuous');
  assert.equal(row.harnessSha256, 'stale-hash',
    'the pre-fix path stamped a current identity, so the reopen-forever loop would not reproduce');
});

test('the retry is BOUNDED: the last attempt settles at this hash rather than cycling again', () => {
  // Two attempts already spent, so this one is the third and must terminate. An unbounded retry is
  // the same defect wearing different clothes: the row would still be re-measured every slice.
  const f = fixture({ attempts: 2, withheld: 'HARNESS-ERROR' });
  const { row } = complete(f);
  const instrument = computeHarnessIdentity();
  assert.equal(row.status, 'done', 'the third attempt did not terminate, so the row still cycles');
  assert.equal(row.settledAtHash, instrument.harnessSha256,
    'without settledAtHash the claim pass hands the row straight back out');
  assert.match(row.settledReason, /HARNESS-ERROR/,
    'the settle reason must name the instrument failure, not the prior verdict');
  assert.equal(row.verdict, 'MINIMUM',
    'the queue must keep reporting what the corpus actually holds — the prior measurement — rather '
    + 'than overwriting it with an attempt outcome');
});

test('a row with no withheld failure still closes normally', () => {
  const f = fixture({ withheld: null });
  const { row } = complete(f);
  assert.equal(row.status, 'done');
  assert.equal(row.verdict, 'MINIMUM');
  assert.equal(row.settledAtHash, undefined, 'an ordinary completion must not be settled');
});

test('the publisher writes the channel on the HARNESS-* branch', () => {
  const src = fs.readFileSync(path.join(import.meta.dirname, 'publish-record-v2.sh'), 'utf8');
  const branch = src.slice(src.indexOf('    HARNESS-*)'), src.indexOf('  esac'));
  assert.ok(branch.includes('note_instrument_failure'),
    'the HARNESS-* branch withholds the record without recording the verdict anywhere, so --complete '
    + 'only ever sees the restored prior and the retry never fires');
  assert.match(src, /NUB_CORPUS_INSTRUMENT_FAILURES/);
});

test('BOTH --complete call sites pass the channel', () => {
  // The commit step re-runs --complete after `git reset --hard origin`, which discards the queue the
  // collect step wrote. A flag on only one of them leaves the fix inert exactly where it counts.
  const yml = fs.readFileSync(path.join(import.meta.dirname, '..', '..', '.github', 'workflows',
    'corpus-v2-runner.yml'), 'utf8');
  const completes = (yml.match(/claim-slice\.mjs --queue queue-v2\.ndjson --complete/g) ?? []).length;
  const wired = (yml.match(/--instrument-failures/g) ?? []).length;
  assert.equal(completes, 2, `expected 2 --complete call sites, found ${completes}`);
  assert.equal(wired, completes,
    `${completes} --complete call site(s) but ${wired} carry --instrument-failures`);
});
