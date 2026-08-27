// ⛔ THE LOOP THAT SPENT 58% OF EVERY SLICE RE-DERIVING A REFUSAL THE CORPUS HAD ALREADY MADE.
//
// `publish-record-v2.sh` withholds a record the publish guard rejects and restores ORIGIN'S PRIOR
// copy, which carries an OLD `harnessSha256`. `collect-verdicts.mjs` then reads that restored prior,
// `--complete` stamps the row from it, and the next claim's invalidation pass sees a stale hash and
// returns the row to `pending`. Re-measuring cannot help: the same harness produces the same result
// and the guard withholds it again.
//
// MEASURED on four consecutive linux slices (33011883250, 33016334427, 33020269262, 33024052763):
// each claimed 60 and each withheld the SAME 35 package@versions — `comm -12` on the sorted name
// lists gave 35 of 35 for every pair — publishing 16 apiece. The stuck set only grows.
//
// These tests drive the real script as a subprocess, because the contract is what it leaves in the
// queue file.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity, loadInvalidationPolicy } from './instrument.mjs';
import { recordValidity } from './record-validity.mjs';

const claim = path.join(import.meta.dirname, '..', 'claim-slice.mjs');
const read = (file) => fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(JSON.parse);

// A claimed row plus the verdict `collect-verdicts.mjs` would read off origin's RESTORED prior —
// note the deliberately stale `harnessSha256`, which is the whole point of the fixture.
function scratch({ settledLine = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-settled-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const verdicts = path.join(root, 'verdicts.ndjson');
  const settled = path.join(root, 'settled.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'stuck', version: '1.0.0', os: 'linux', status: 'claimed', run: 'r1',
  })}\n`);
  fs.writeFileSync(verdicts, `${JSON.stringify({
    pkg: 'stuck', version: '1.0.0', verdict: 'MINIMUM', harnessVersion: 2,
    provenance: { harnessEpoch: 1, harnessSha256: 'a-stale-hash', platform: 'linux-x64' },
  })}\n`);
  if (settledLine) fs.writeFileSync(settled, `${JSON.stringify(settledLine)}\n`);
  return { root, queue, verdicts, settled };
}

const complete = (t, extra = []) => spawnSync(process.execPath,
  [claim, '--queue', t.queue, '--complete', t.verdicts, '--run', 'r1', ...extra],
  { encoding: 'utf8' });

test('a withheld row is settled at THIS hash, so the next claim leaves it alone', () => {
  const t = scratch({ settledLine: { pkg: 'stuck', version: '1.0.0', settled: 'publish-guard withheld the re-measure' } });
  const r = complete(t, ['--settled', t.settled]);
  assert.equal(r.status, 0, r.stderr);
  const [row] = read(t.queue);
  assert.equal(row.status, 'done');
  assert.equal(row.settledAtHash, computeHarnessIdentity().harnessSha256);
  assert.match(row.settledReason, /publish-guard/);

  // The claim pass must now decline to reopen it, DESPITE the row's stale record hash.
  const c = spawnSync(process.execPath, [claim, '--queue', t.queue, '--claim', '5',
    '--os', 'linux', '--run', 'r2'], { encoding: 'utf8' });
  assert.equal(c.status, 0, c.stderr);
  assert.equal(c.stdout.trim(), '', `the stuck row was handed out again: ${c.stdout}`);
  assert.equal(read(t.queue)[0].status, 'done');
});

test('WITHOUT the settled manifest the row still reopens — the control that proves the fix fires', () => {
  // ⛔ THE RED HALF. If this passed too, the assertion above would be measuring nothing: the row
  // would have been immune for some unrelated reason and the manifest would be decoration.
  const t = scratch();
  assert.equal(complete(t).status, 0);
  const [row] = read(t.queue);
  assert.equal(row.settledAtHash, undefined);
  const c = spawnSync(process.execPath, [claim, '--queue', t.queue, '--claim', '5',
    '--os', 'linux', '--run', 'r2'], { encoding: 'utf8' });
  assert.equal(c.stdout.trim(), 'stuck@1.0.0', 'the stale row should still be reclaimed unguarded');
});

test('settling is scoped to the exact instrument, so a real harness change reopens the row', () => {
  // "Settled" must not mean "abandoned". Only the hash expresses that difference, which is why the
  // field carries one rather than a boolean.
  const t = scratch({ settledLine: { pkg: 'stuck', version: '1.0.0', settled: 'withheld' } });
  assert.equal(complete(t, ['--settled', t.settled]).status, 0);
  const rows = read(t.queue);
  rows[0].settledAtHash = 'the-hash-of-a-different-harness';
  fs.writeFileSync(t.queue, `${rows.map(JSON.stringify).join('\n')}\n`);
  const c = spawnSync(process.execPath, [claim, '--queue', t.queue, '--claim', '5',
    '--os', 'linux', '--run', 'r2'], { encoding: 'utf8' });
  assert.equal(c.stdout.trim(), 'stuck@1.0.0', 'a row settled under a DIFFERENT harness must reopen');
});

test('an instrument failure out of retries settles instead of looping forever', () => {
  // `recordValidity` rejects a `HARNESS-*` verdict as "instrument failure is not a measurement", so
  // a row closed with one is reopened by the very next invalidation pass — the same loop, reached by
  // a different door. RETRY_LIMIT is 3, so the third attempt is the one that must settle.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-settled-hf-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const verdicts = path.join(root, 'verdicts.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'crasher', version: '1.0.0', os: 'linux', status: 'claimed', run: 'r1', attempts: 2,
  })}\n`);
  fs.writeFileSync(verdicts, `${JSON.stringify({
    pkg: 'crasher', version: '1.0.0', verdict: 'HARNESS-ERROR', harnessVersion: 2,
    provenance: { harnessEpoch: 1, harnessSha256: 'a-stale-hash', platform: 'linux-x64' },
  })}\n`);
  const r = spawnSync(process.execPath, [claim, '--queue', queue, '--complete', verdicts,
    '--run', 'r1'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const [row] = read(queue);
  assert.equal(row.status, 'done');
  assert.equal(row.settledAtHash, computeHarnessIdentity().harnessSha256);
  assert.match(row.settledReason, /instrument failure after 3 attempts/);
});

test('a row with retries LEFT still goes back to pending — the bound is not bypassed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-settled-hr-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  const verdicts = path.join(root, 'verdicts.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'crasher', version: '1.0.0', os: 'linux', status: 'claimed', run: 'r1',
  })}\n`);
  fs.writeFileSync(verdicts, `${JSON.stringify({
    pkg: 'crasher', version: '1.0.0', verdict: 'HARNESS-TIMEOUT', harnessVersion: 2,
    provenance: { harnessEpoch: 1, harnessSha256: 'a-stale-hash', platform: 'linux-x64' },
  })}\n`);
  assert.equal(spawnSync(process.execPath, [claim, '--queue', queue, '--complete', verdicts,
    '--run', 'r1'], { encoding: 'utf8' }).status, 0);
  const [row] = read(queue);
  assert.equal(row.status, 'pending');
  assert.equal(row.settledAtHash, undefined, 'a retryable failure must not be settled');
});

test('an ordinary published row is untouched by any of this', () => {
  const t = scratch({ settledLine: { pkg: 'someone-else', version: '9.9.9', settled: 'withheld' } });
  assert.equal(complete(t, ['--settled', t.settled]).status, 0);
  const [row] = read(t.queue);
  assert.equal(row.status, 'done');
  assert.equal(row.verdict, 'MINIMUM');
  assert.equal(row.settledAtHash, undefined, 'a row absent from the manifest must not be settled');
});

// ⛔ THE POLICY FILE IS THE ONLY THING STANDING BETWEEN A HARNESS EDIT AND A FULL RE-DRAIN, AND
// NOTHING ELSE CHECKS IT. `instrument.json`'s epoch and `invalidation.json`'s `currentEpoch` are two
// numbers in two files that must agree — `instrumentCompatibility` refuses EVERY record when they
// do not ("invalidation policy does not name the current harness epoch"), which reads in a slice log
// as the entire corpus having gone stale. The transition's `toHarnessSha256` is the same hazard one
// step further on: it names the hash the harness has AFTER the change, so any later edit to an
// instrument input silently invalidates it. Both were mistyped once while landing epoch 4.
test('the invalidation policy names the current epoch and the current harness digest', () => {
  const instrument = computeHarnessIdentity();
  const policy = loadInvalidationPolicy();
  assert.equal(policy.currentEpoch, instrument.harnessEpoch,
    'the policy and the instrument disagree about the epoch, so EVERY record reads as stale');
  const arriving = policy.transitions.filter((t) => t.toEpoch === instrument.harnessEpoch
    && typeof t.toHarnessSha256 === 'string');
  for (const t of arriving) {
    assert.equal(t.toHarnessSha256, instrument.harnessSha256,
      `the transition from epoch ${t.fromEpoch} targets a digest the harness no longer has — `
      + 'recompute it after every instrument edit, or every record it covers is re-measured');
  }
});

test('an epoch-3 record at the frozen digest survives into epoch 4', () => {
  // The 1,769 records the corpus held when epoch 4 landed all carry this digest. If this goes red,
  // the drain restarts from zero — which is the entire cost the targeted transition exists to avoid.
  const FROZEN = 'f9e4c4fde7a5ce7c86828b1c89d2bc24c671248f1db83584905ca3864c216db6';
  const record = {
    harnessVersion: 2, harnessEpoch: 3, pkg: 'demo', version: '1.0.0', verdict: 'MINIMUM',
    provenance: { harnessSha256: FROZEN, platform: 'linux-x64' },
  };
  const v = recordValidity(record, computeHarnessIdentity(), loadInvalidationPolicy());
  assert.equal(v.reusable, true, `a frozen-epoch-3 record was invalidated: ${v.reason}`);

  // ⛔ AND THE CONTROL: a record from some OTHER epoch-3 harness must STILL be refused, or the
  // assertion above is only measuring how permissive the policy is.
  const alien = { ...record, provenance: { ...record.provenance, harnessSha256: 'a-different-harness' } };
  assert.equal(recordValidity(alien, computeHarnessIdentity(), loadInvalidationPolicy()).reusable, false);
});

test('reopening a settled row clears its settled fields', () => {
  // Inert if left behind — a stale hash cannot match the guard — but a row that reads as "settled"
  // while sitting in `pending` is the kind of thing a later reader trusts and a later patch keys on.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-settled-clr-'));
  const queue = path.join(root, 'queue-v2.ndjson');
  fs.writeFileSync(queue, `${JSON.stringify({
    pkg: 'old', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM',
    harnessVersion: 2, harnessEpoch: 1, harnessSha256: 'a-long-dead-harness', platform: 'linux-x64',
    settledAtHash: 'the-hash-of-a-different-harness', settledReason: 'withheld',
  })}\n`);
  const c = spawnSync(process.execPath, [claim, '--queue', queue, '--claim', '5',
    '--os', 'linux', '--run', 'r1'], { encoding: 'utf8' });
  assert.equal(c.stdout.trim(), 'old@1.0.0', `the stale row should reopen: ${c.stderr}`);
  const [row] = read(queue);
  assert.equal(row.settledAtHash, undefined);
  assert.equal(row.settledReason, undefined);
});
