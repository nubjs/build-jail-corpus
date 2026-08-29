// ⛔ A DRAIN THAT DIES ON ONE TRANSIENT FAILURE CANNOT PRODUCE A COMPLETE CORPUS.
//
// `Dispatch the next slice` carries no `always()`, so a single failed step ends the chain for good.
// MEASURED 2026-08-29 on run 33256179837: the falsification pre-flight returned INCONCLUSIVE because
// `hugo-extended@0.141.0`'s CONTROL arm came back BROKEN-WITHOUT-JAIL-TOO -- the venue failed, so the
// question was never put. Refusing the batch was CORRECT and wrote no records; but the lane then sat
// idle with 60 rows stranded `claimed` until a human noticed. The same two cases had passed 2/2 on
// each of the four runs immediately before, so it was a download blip, not a broken case.
//
// Rate: 1 of the 18 drain runs that actually executed failed (5.6%). The windows lane is ~453 slices,
// so that is a stall roughly every 18 slices across 30-87 unattended days.
//
// The OTHER half is what these tests mostly guard: the revive must be BOUNDED. A bare `always()`
// re-dispatches a permanently-broken lane every ~100 s forever, so the retry is conditioned on the
// previous terminal run having SUCCEEDED -- and that check must exclude the CURRENT run by id. If it
// excluded by status alone, a run already recorded as `completed`/`failure` would be read as its own
// predecessor, `PREV` would always be `failure`, and the revive would never fire at all: a guard that
// looks present and does nothing.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const RUNNER = path.join(import.meta.dirname, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml');
const src = fs.readFileSync(RUNNER, 'utf8');

/// The revive step's body, from its `- name:` to the start of the next step at the same indent.
function reviveStep() {
  const lines = src.split('\n');
  const i = lines.findIndex((l) => l.includes('- name: Revive the chain after a transient failure'));
  if (i === -1) return null;
  const out = [];
  for (let j = i + 1; j < lines.length; j++) {
    if (/^      - name:/.test(lines[j])) break;
    out.push(lines[j]);
  }
  return out.join('\n');
}

test('the runner still has a revive step to check', () => {
  // Known-answer control. Without it every assertion below passes vacuously the moment the step is
  // renamed or removed -- which is exactly the regression they exist to catch.
  const step = reviveStep();
  assert.ok(step !== null, 'no "Revive the chain after a transient failure" step in corpus-v2-runner.yml');
  assert.ok(step.includes('gh workflow run'), 'the revive step no longer dispatches anything');
});

test('the revive fires ON FAILURE, which is the only time it is any use', () => {
  const step = reviveStep();
  assert.match(step, /if:\s*failure\(\)/,
    'the revive step must be gated on failure() — on success the ordinary chain hop already ran, and '
    + 'without it a transient failure ends the drain permanently');
});

test('the revive is BOUNDED: it stands down when the previous run also failed', () => {
  const step = reviveStep();
  // The runaway this prevents costs nothing in money (the repo is public, runners are free) and
  // everything in signal: a broken lane must stall loudly, not spin.
  assert.match(step, /conclusion/,
    'the revive does not consult any previous conclusion, so it is an unbounded always()-retry');
  assert.match(step, /\[\s*"\$PREV"\s*=\s*"failure"\s*\]/,
    'the revive does not stand down after a SECOND consecutive failure — a permanently-broken lane '
    + 'would re-dispatch itself every ~100 s forever');
});

test('the previous-run lookup EXCLUDES the current run by id, not by status', () => {
  const step = reviveStep();
  assert.match(step, /databaseId\s*\|\s*tostring\)\s*!=\s*\\"\$THIS_RUN/,
    'the lookup must exclude THIS run by databaseId. Excluding by status alone lets a run already '
    + 'recorded as completed/failure be read as its own predecessor, so PREV is always "failure" and '
    + 'the revive silently never fires');
  assert.match(step, /THIS_RUN:\s*"\$\{\{\s*github\.run_id\s*\}\}"/,
    'THIS_RUN is not wired to github.run_id, so the self-exclusion compares against nothing');
});

test('the revive never fires for a debug probe', () => {
  const step = reviveStep();
  // A probe measures named packages and chains nothing; reviving one would dispatch a QUEUE DRAIN
  // off the back of a probe failure, which is a different lane doing different work.
  assert.match(step, /inputs\.packages\s*==\s*''/,
    'the revive step is not scoped to queue drains, so a failed debug probe would start a drain');
});
