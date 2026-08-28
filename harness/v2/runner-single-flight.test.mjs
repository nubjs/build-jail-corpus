// ⛔ THE INVARIANT THIS FILE GUARDS IS THE ONE THE RUNNER SHOUTS ABOUT AND NOTHING ENFORCED.
// `corpus-v2-runner.yml`'s header carries a ⛔⛔ RUN ONE RUNNER AT A TIME block with the measurement
// behind it — two overlapping runners give `completed 0 row(s)`, because every runner rewrites the
// WHOLE queue and the second one's write is built on a pre-claim snapshot. Until 2026-08-28 that was
// enforced by discipline alone, and two doors were open:
//
//   1. `push: branches: [probe/corpus-v2-lane]` has NO paths filter, so any human or agent commit to
//      the drain branch dispatches a full drain. The runner's own record pushes are exempt only
//      because GitHub raises no workflow event for a `GITHUB_TOKEN` push — an accident, not a design.
//      MEASURED: a one-file commit to `harness/v2/invalidation.json` dispatched run 33139321538,
//      whose "Claim a slice" step reached `success` and took 10 rows before it was cancelled.
//   2. Two `workflow_dispatch` runs, which no trigger gate can catch.
//
// `concurrency:` cannot close either: it is keyed on `github.run_id` deliberately, so an interrupted
// job strands its claim instead of being cancelled — and that same choice means it dedupes nothing.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNNER = path.join(HERE, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml');
const src = fs.readFileSync(RUNNER, 'utf8');

// Anchored with the trailing newline: a bare prefix match still finds a step someone renamed to
// '...DISABLED', so a control that renames it away would pass and the guard would be gone.
const STEP_HEAD = '- name: Refuse to drain beside an older runner\n';
const CLAIM_HEAD = '- name: Claim a slice\n';

test('a push drains only when its head commit asks to', () => {
  // The trigger itself must survive: `workflow_dispatch` is inert until this file reaches the
  // default branch, so a push is the only way to test an edit to the runner.
  assert.match(src, /push:\s*\n(?:\s*#.*\n)*\s*branches: \[probe\/corpus-v2-lane\]/,
    'the push trigger was removed — that is not the fix; it is the only way to test this file');
  assert.match(src, /github\.event_name != 'push'\s*\n\s*\|\| contains\(github\.event\.head_commit\.message, '\[drain\]'\)/,
    'the slice job does not gate push-triggered drains behind a [drain] marker');
});

test('the whole-message trap is written down where the gate is', () => {
  // MEASURED by the commit that added the gate: its body explained the feature in prose, spelled the
  // opt-in token out while doing so, and thereby dispatched run 33139919598 — a real drain. The gate
  // read the marker it was given; `head_commit.message` is the ENTIRE message and `contains()` is a
  // plain substring test, and no GitHub expression can scope either to the subject line. Anyone who
  // documents this gate in a commit message repeats it, so the warning is part of the mechanism.
  const job = src.slice(src.indexOf('\n  slice:\n'), src.indexOf('\n      - name:'));
  assert.match(job, /MENTIONING THE MARKER ANYWHERE OPTS THE PUSH/,
    'the whole-message trap is undocumented — the next person to explain this gate will trip it');
  assert.ok(job.includes('33139919598'),
    'the warning cites no run — an unevidenced caution reads as speculation and gets deleted');
});

test('the gate sits on the JOB, so a gated push claims nothing at all', () => {
  // A step-level guard would still let checkout, provisioning and the binary restore burn a runner,
  // and — the part that matters — anything later that forgets the guard would claim.
  const job = src.slice(src.indexOf('\n  slice:\n'), src.indexOf('\n      - name:'));
  assert.ok(job.includes("github.event_name != 'push'"),
    'the push gate is not inside the `slice` job header');
  assert.ok(job.indexOf("github.event_name != 'push'") < job.indexOf('runs-on:'),
    'the gate must precede runs-on so the job is skipped, not merely short-circuited');
});

test('the single-flight preflight runs BEFORE the claim, or it guards nothing', () => {
  const pre = src.indexOf(STEP_HEAD);
  const claim = src.indexOf(CLAIM_HEAD);
  assert.ok(pre !== -1, 'the single-flight preflight step is gone');
  assert.ok(claim !== -1, 'the claim step is gone');
  assert.ok(pre < claim, 'the preflight must precede the claim — after it, the damage is done');
});

test('the preflight yields to older runs only, so a pair can never deadlock', () => {
  const step = src.slice(src.indexOf(STEP_HEAD),
    src.indexOf(CLAIM_HEAD));
  assert.ok(step.includes('select(.id < ($SELF|tonumber))'),
    'the preflight does not restrict itself to OLDER runs; a symmetric check deadlocks both');
  assert.ok(step.includes('exit 1'),
    'the preflight does not fail — a drain that did not happen must not read as one that found nothing');
});

test('the preflight cannot hang, and a zombie queued run cannot halt the corpus', () => {
  const step = src.slice(src.indexOf(STEP_HEAD),
    src.indexOf(CLAIM_HEAD));
  // MEASURED: `gh api --paginate .../runs` on this workflow ran past 60s without reaching a run from
  // two days earlier. A preflight that hangs stalls every drain it was written to protect.
  // ⛔ STRIP THE COMMENTS FIRST. The step's own note says "NO `--paginate`", so a raw substring
  // search on the whole block matches the warning and fails a correct workflow. Assert on the CODE.
  const code = step.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
  assert.ok(!code.includes('--paginate'),
    'the preflight paginates the whole run history — measured over 60s, and it only grows');
  assert.ok(code.includes('status=in_progress') && code.includes('status=queued'),
    'the preflight must ask the API for the two non-terminal states rather than filtering everything');
  // Run 32984175176 sat `queued` for two days. Yielding to it forever would refuse every drain,
  // silently, and read exactly like an empty queue.
  assert.ok(/select\(\(now - \(\.created_at\|fromdate\)\) < 7200\)/.test(code),
    'a stale queued run is not aged out — one zombie would halt the whole corpus');
  const queuedIdx = code.indexOf('status=queued');
  const inProgIdx = code.indexOf('status=in_progress');
  const ageIdx = code.indexOf('fromdate');
  assert.ok(ageIdx > queuedIdx && queuedIdx > inProgIdx,
    'the age window must apply to the queued query only — an in_progress run holds claims at any age');
});

test('the preflight survives the EMPTY case under `set -e` — the normal one', () => {
  const step = src.slice(src.indexOf(STEP_HEAD),
    src.indexOf(CLAIM_HEAD));
  // A bare `[ -n "$X" ] && VAR=...` whose test is false is a FAILING command, so under `set -eu` the
  // clean case — nothing else running — would exit non-zero and refuse every legitimate drain.
  assert.ok(!/\[ -n "\$HIT" \] &&/.test(step),
    'the accumulator form is back; it turns "nothing else is running" into a step failure');
  assert.ok(step.includes('|| true'),
    'the API calls are not failure-tolerant — a transient blip would refuse a legitimate drain');
});
