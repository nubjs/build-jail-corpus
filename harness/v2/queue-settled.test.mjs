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

// ⛔ THE FROZEN EPOCH-3 CHAIN ENDS AT EPOCH 82, AND THIS GUARD NO LONGER CLAIMS OTHERWISE.
//
// What stood here asserted against the LIVE policy that a synthetic epoch-3 `demo@1.0.0` record was
// still reusable, and said in its comment that this protected the 1,769 records the corpus held when
// epoch 4 landed. It protected none of them, and had stopped describing the corpus long before it
// went red. MEASURED over `records-v2/runs/**/results.json` at epoch 81, with the chain repaired so
// that the assertion passes: 1,267 records carry the frozen epoch-3 digest, and 972 of them were
// ALREADY invalidated while the guard read green — 723 by the epoch-59 package union alone. A record
// named `demo` matches no `packages` selector, so the selector that has done the most invalidating on
// this chain is the one the fixture could never feel.
//
// Epoch 82 invalidates `{"all": true}`, deliberately: the full-closure scaffold changes the tree the
// observe arm measures for 693 of the 907 records still valid at epoch 81, so a grant carried forward
// across it could only be too narrow. Frozen-epoch-3 reuse is therefore over, and a guard asserting
// that it survives asserts against the decision rather than against a defect.
//
// What is worth pinning is what the transition machinery actually promises, stated in
// `record-validity.mjs` above `settlementSurvives`: "re-measuring cannot change the outcome under
// instrument X" stays true when X changes in a way that invalidates nothing. So — a record walks a
// measurement-neutral chain, and is refused the instant a scope names it. The chain below is
// SYNTHETIC for the same reason `settlement-survives.test.mjs`'s is: a fixture pinned to today's
// digests stops testing the property and starts tracking the calendar. That file holds the settlement
// half of this pair; this is the record half.
test('a record survives a measurement-neutral chain and is refused the moment a scope names it', () => {
  const E7 = '7'.repeat(64);
  const E8 = '8'.repeat(64);
  const E9 = '9'.repeat(64);
  const current = { harnessEpoch: 9, harnessSha256: E9 };
  // Two hops, of the two shapes this chain is really built from: a `{verdicts: []}` bump that selects
  // nothing, then a `packages` bump — the shape the replaced fixture was structurally blind to.
  const policy = { schemaVersion: 1, currentEpoch: 9, transitions: [
    { fromEpoch: 7, fromHarnessSha256: E7, toEpoch: 8, toHarnessSha256: E8,
      invalidate: { verdicts: [] }, reason: 'comment and test only' },
    { fromEpoch: 8, fromHarnessSha256: E8, toEpoch: 9, toHarnessSha256: E9,
      invalidate: { packages: ['sharp'] }, reason: 'the sharp classifier changed' },
  ] };
  const record = (pkg) => ({
    harnessVersion: 2, harnessEpoch: 7, pkg, version: '1.0.0', verdict: 'MINIMUM',
    provenance: { harnessSha256: E7, platform: 'linux-x64' },
  });

  const kept = recordValidity(record('left-pad'), current, policy);
  assert.equal(kept.reusable, true, `a record no scope names was invalidated: ${kept.reason}`);
  assert.equal(kept.via, 'targeted-transition', 'the record must be WALKED, not matched outright');

  // ⛔ THE RED HALF. Preserving a record is only correct while nothing invalidates it; an assertion
  // that only proved records survive would pass against an engine that never drops one, and a record
  // whose measurement the instrument genuinely changed would then be reused forever.
  const dropped = recordValidity(record('sharp'), current, policy);
  assert.equal(dropped.reusable, false, 'a record the epoch-9 scope names must be re-measured');
  assert.equal(dropped.reason, 'the sharp classifier changed', 'refused, but by some OTHER hop');

  // ⛔ AND THE ALIEN CONTROL: a record from a different harness at the same epoch is still refused, so
  // the walk is keyed on instrument identity rather than on the epoch number alone.
  const alien = recordValidity({ ...record('left-pad'),
    provenance: { harnessSha256: 'a-different-harness', platform: 'linux-x64' } }, current, policy);
  assert.equal(alien.reusable, false, 'a foreign epoch-7 digest was accepted onto the chain');
  assert.match(alien.reason, /does not match transition source/);
});

// The live policy still deserves one assertion, and it is not about any particular record. A
// transition whose scope the engine cannot read, an epoch two transitions leave, or a hole in the run
// refuses EVERY record from that point onward — the same whole-corpus-looks-stale failure the epoch
// and digest test above guards against, reached through the selectors instead of through the digest.
// Each hop is probed on its own, so a scope is exercised even when no record in the corpus happens to
// traverse it, and the check keeps holding as the chain grows.
test('every hop of the live chain declares a scope the engine can read, and the hops form one run', () => {
  const policy = loadInvalidationPolicy();
  const leaving = new Map();
  for (const t of policy.transitions) {
    leaving.set(t.fromEpoch, [...(leaving.get(t.fromEpoch) ?? []), t]);
    const probe = {
      harnessVersion: 2, harnessEpoch: t.fromEpoch, pkg: 'no-such-package', version: '0.0.0',
      verdict: 'MINIMUM', provenance: { harnessSha256: t.fromHarnessSha256, platform: 'linux-x64' },
    };
    const { reason = '' } = recordValidity(probe,
      { harnessEpoch: t.toEpoch, harnessSha256: t.toHarnessSha256 },
      { schemaVersion: 1, currentEpoch: t.toEpoch, transitions: [t] });
    assert.doesNotMatch(reason, /^invalid policy:/,
      `the epoch-${t.toEpoch} transition declares a scope the engine cannot read: ${reason}`);
  }
  for (const [from, hops] of leaving) {
    assert.equal(hops.length, 1,
      `${hops.length} transitions leave epoch ${from}, so no record can be walked past it`);
  }
  // Walking the hops in order is also the only thing that sees them COMPOSED. `instrumentCompatibility`
  // carries each hop's `toHarnessSha256` into the next hop's source check, so a digest one hop
  // produces that the next hop does not expect strands every record behind it — invisible to any
  // single-hop probe. The root hop is the unversioned instrument and names no target digest, so the
  // run is walked from the first hop that does.
  let epoch = policy.transitions.find((t) => t.fromEpoch === null)?.toEpoch;
  assert.ok(Number.isInteger(epoch), 'the chain has no root transition to walk from');
  let digest = leaving.get(epoch)?.[0]?.fromHarnessSha256;
  for (let hop = 0; leaving.has(epoch) && hop <= policy.transitions.length; hop++) {
    const [t] = leaving.get(epoch);
    assert.equal(t.fromHarnessSha256, digest,
      `the epoch-${t.fromEpoch} hop starts from a digest the hop before it does not produce, `
      + 'so every record walked as far as it is stranded there');
    digest = t.toHarnessSha256;
    epoch = t.toEpoch;
  }
  assert.equal(epoch, policy.currentEpoch,
    `the chain runs out at epoch ${epoch}, so every record at or before it is stranded`);
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
