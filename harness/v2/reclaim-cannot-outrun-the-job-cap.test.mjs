// ⛔⛔ THE INVARIANT THAT STOPS A LIVE SLICE BEING RECLAIMED OUT FROM UNDER ITSELF.
//
// `claim-slice.mjs --reclaim-stale <minutes>` returns rows claimed longer ago than that to pending,
// so a runner that died without completing does not strand its slice forever. The hazard is the
// other direction: if the cutoff is SHORTER than a slice can legitimately run, the next claim hands
// a LIVE runner's rows to a second runner, both measure them, and the loser writes records over a
// queue that no longer agrees with them.
//
// `claim-cas.test.mjs` names this as one of two reasons its CAS proof "does not make parallel
// draining safe", citing a macos slice that measured 221 minutes on 2026-08-28 and observing that a
// slower one would cross the cutoff. That is right about the mechanism and wrong about the bound,
// because it does not account for the job cap: GitHub kills the job at `timeout-minutes`, and a row
// cannot stay claimed past the death of the runner holding it. Claiming also happens AFTER checkout,
// toolchain, test suite and binary restore, so the maximum age a LIVE claim can reach is strictly
// less than the cap.
//
// Measured at the time of writing: `timeout-minutes: 300`, `--reclaim-stale 360` — 60 minutes of
// margin. This pins the RELATION, not the numbers, so it fails if anyone lowers the cutoff, raises
// the cap, or drops either.
//
// ⛔ IT DOES NOT LICENSE PARALLEL DRAINING BY ITSELF; it closes one of the two named objections.
//
// ⛔ THE CHECK IS A PURE FUNCTION ON PURPOSE. Asserting directly against the workflow file gives a
// guard that cannot be shown to BITE — proving it would mean mutating a file this harness has no
// business writing. Extracting it means the negative controls run on synthetic input while the real
// workflow is still checked, which is the only version of this test worth having.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKFLOW = path.join(HERE, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml');

/**
 * The margin between the reclaim cutoff and the job cap, read out of a workflow's source.
 * `ok` is false when anything is missing, because a check that cannot find its inputs must fail
 * rather than pass vacuously.
 */
export const reclaimMargin = (src) => {
  const cap = /^\s*timeout-minutes:\s*(\d+)\s*$/m.exec(src);
  // ⛔ EVERY occurrence, not the first: a second, shorter `--reclaim-stale` elsewhere would defeat
  // the invariant while the first one still read as safe.
  const cutoffs = [...src.matchAll(/--reclaim-stale\s+(\d+)/g)].map((m) => Number(m[1]));
  if (!cap || cutoffs.length === 0) {
    return { ok: false, why: !cap ? 'no timeout-minutes' : 'no --reclaim-stale', cap: null, cutoffs };
  }
  const capMinutes = Number(cap[1]);
  const offenders = cutoffs.filter((c) => c <= capMinutes);
  return {
    ok: offenders.length === 0,
    why: offenders.length ? `cutoff ${offenders.join(',')} <= cap ${capMinutes}` : 'ok',
    cap: capMinutes,
    cutoffs,
  };
};

test('⭑ the real workflow reclaims only well past the job cap, so a live slice is never reclaimed', () => {
  const r = reclaimMargin(fs.readFileSync(WORKFLOW, 'utf8'));
  assert.equal(r.ok, true, `corpus-v2-runner.yml: ${r.why}`);
  // Pinned so a silently-empty regex cannot make the assertion above vacuous.
  assert.ok(r.cap > 0, 'the job cap did not parse');
  assert.ok(r.cutoffs.length > 0, 'no reclaim cutoff parsed');
});

test('⭑ CONTROL: a cutoff at or below the cap is REJECTED — the guard bites', () => {
  for (const [cap, cutoff] of [[300, 240], [300, 300], [600, 360]]) {
    const r = reclaimMargin(`    timeout-minutes: ${cap}\n      --reclaim-stale ${cutoff}\n`);
    assert.equal(r.ok, false, `cap ${cap} / cutoff ${cutoff} must be rejected`);
  }
});

test('⭑ CONTROL: a SECOND shorter cutoff is caught even when the first one is safe', () => {
  const r = reclaimMargin('    timeout-minutes: 300\n  --reclaim-stale 360\n  --reclaim-stale 120\n');
  assert.equal(r.ok, false, 'a shorter second cutoff must not hide behind a safe first one');
});

test('⭑ CONTROL: missing inputs FAIL rather than passing vacuously', () => {
  assert.equal(reclaimMargin('  --reclaim-stale 360\n').ok, false, 'no cap must fail');
  assert.equal(reclaimMargin('    timeout-minutes: 300\n').ok, false, 'no cutoff must fail');
  assert.equal(reclaimMargin('').ok, false, 'empty input must fail');
});

test('⭑ the claim runs AFTER setup, which is what makes the margin real rather than nominal', () => {
  // The bound is "max live claim age < cap", and it holds only because claiming is not the first
  // thing the job does. If the claim step moved to the top, the margin would collapse to exactly
  // cutoff - cap with nothing absorbing a slow runner.
  const src = fs.readFileSync(WORKFLOW, 'utf8');
  const claim = src.indexOf('- name: Claim a slice');
  assert.notEqual(claim, -1, 'the claim step is gone');
  let checked = 0;
  for (const earlier of ['uses: actions/checkout', 'Restore a feature-enabled nub binary']) {
    const at = src.indexOf(earlier);
    if (at === -1) continue;
    checked += 1;
    assert.ok(at < claim, `"${earlier}" must run before the claim, or the claim-age margin shrinks`);
  }
  assert.ok(checked > 0, 'neither setup anchor was found — this test would otherwise assert nothing');
});
