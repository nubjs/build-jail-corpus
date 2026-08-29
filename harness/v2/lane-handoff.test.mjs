// A drained lane must hand the chain to a lane that still has work, not end the whole drain.
//
// The chaining runner dispatches its successor with the SAME `os` it ran, and its claim loop sets
// `DRAINED=1` the moment its own lane claims nothing — which gated the dispatch step off entirely.
// So the FIRST lane to empty stopped the corpus for every lane.
//
// MEASURED 2026-08-29 on the live queue: linux held 850 pending rows, macos 1652, windows 2265. At
// the observed ~45 records per ~66-minute slice linux would have emptied in ~19 slices (~21 h) and
// halted the drain at roughly 41% coverage, leaving 3917 rows unmeasured — with nothing anywhere
// reporting that anything had stopped, because a drained lane exits 0 and looks like success.
//
// Both halves are pinned here. Testing only `--next-os` would leave the YAML free to keep gating
// the dispatch on `DRAINED` alone, which is the actual defect; testing only the YAML would not
// notice the query returning a drained lane forever.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const CLAIM = path.join(import.meta.dirname, '..', 'claim-slice.mjs');
const RUNNER = path.join(import.meta.dirname, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml');

/// Run `--next-os` against a throwaway queue and return its trimmed stdout.
function nextOs(rows, order) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lane-'));
  const q = path.join(dir, 'q.ndjson');
  fs.writeFileSync(q, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
  const r = spawnSync(process.execPath, [CLAIM, '--queue', q, '--next-os', order], { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return { out: r.stdout.trim(), code: r.status };
}

const row = (osName, status) => ({ pkg: `p-${osName}-${status}`, version: '1.0.0', os: osName, status });

test('--next-os picks the first listed lane that still holds pending rows', () => {
  const rows = [row('linux', 'pending'), row('macos', 'pending')];
  // A known-answer pair: the ONLY thing that differs is the order, so a query that ignored its
  // argument and returned some fixed lane would pass one of these and fail the other.
  assert.equal(nextOs(rows, 'linux,macos').out, 'linux');
  assert.equal(nextOs(rows, 'macos,linux').out, 'macos');
});

test('a drained lane hands off to one that still has work', () => {
  const rows = [row('linux', 'done'), row('macos', 'pending')];
  assert.equal(nextOs(rows, 'linux,macos').out, 'macos',
    'linux has no pending rows, so the chain must move to macos rather than stopping');
});

test('a fully drained corpus reports nothing, which is the one honest place to stop', () => {
  const rows = [row('linux', 'done'), row('macos', 'done')];
  assert.equal(nextOs(rows, 'linux,macos').out, '');
  // `claimed` is not `pending`: a row another runner is mid-measure on must not resurrect the chain.
  assert.equal(nextOs([row('linux', 'done'), row('macos', 'claimed')], 'linux,macos').out, '');
});

test('an empty lane order is a usage error, not a silent no-handoff', () => {
  assert.equal(nextOs([row('linux', 'pending')], '').code, 2);
});

test('the runner computes a successor lane when its own lane drains', () => {
  const yml = fs.readFileSync(RUNNER, 'utf8');
  assert.match(yml, /--next-os "\$LANE_ORDER"/,
    'the drained branch must ask which lane to hand to, using the declared LANE_ORDER');
  assert.match(yml, /^\s*LANE_ORDER:/m, 'LANE_ORDER must be declared for that lookup to resolve');
});

test('the dispatch is not gated off by DRAINED alone, and targets the chosen lane', () => {
  const yml = fs.readFileSync(RUNNER, 'utf8');
  // The defect verbatim: `env.DRAINED != '1'` with no NEXT_OS escape hatch on the dispatch step.
  const gate = yml.match(/if: inputs\.packages == '' && inputs\.chain && [^\n]+/);
  assert.ok(gate, 'the chain dispatch step no longer has a recognisable condition');
  assert.match(gate[0], /env\.NEXT_OS != ''/,
    "a drained lane with a successor must still dispatch — gating on DRAINED alone ends the drain");
  assert.match(yml, /-f os="\$\{NEXT_OS:-\$OS_NAME\}"/,
    'the dispatch must target NEXT_OS when one was chosen, falling back to the current lane');
});
