// A no-claim debug probe must not stop the drain.
//
// The single-flight preflight refuses to start when an OLDER run of this workflow is live, because
// two real drains erase each other's queue claims. A `packages:` debug probe is NOT a drain: it
// skips the claim step entirely (`if: inputs.packages == ''`) and commits no records, so it holds
// nothing another run could erase.
//
// MEASURED 2026-08-29, and it cost the corpus its self-sustaining drain: debug probe 33230149481 was
// still in_progress when the linux chain's successor 33230375263 started. The successor refused at
// the preflight and exited 1, so it never reached its own dispatch step and the chain simply stopped
// -- silently, because a refused run looks like a deliberate yield.
//
// A workflow_dispatch run's INPUTS are absent from the runs-list payload, so `display_title` -- set
// by `run-name:` -- is the only discriminator available to the preflight. Both halves are pinned
// here: the title must MARK a probe, and the queries must SKIP what it marks. Guarding either alone
// leaves the failure reachable.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const RUNNER = path.join(import.meta.dirname, '..', '..', '.github', 'workflows', 'corpus-v2-runner.yml');
const yml = () => fs.readFileSync(RUNNER, 'utf8');

test('the workflow titles its runs, marking a debug probe as one', () => {
  const src = yml();
  assert.match(src, /^run-name:/m,
    'without run-name every run is titled "corpus-v2-runner" and a probe is indistinguishable');
  const line = src.split('\n').find((l) => l.includes('[debug probe]'));
  assert.ok(line, 'run-name must mark a probe with a token the preflight can match');
  assert.match(src, /inputs\.packages != ''/,
    'the marker must key on `packages`, which is what makes a run a no-claim probe');
});

test('the preflight still queries for older runs at all', () => {
  // Known-answer control: if the queries disappear, the exclusion assertions below pass vacuously
  // and single-flight would be silently gone -- the failure this whole step exists to prevent.
  const queries = yml().match(/status=(in_progress|queued)/g) ?? [];
  assert.equal(queries.length, 2, `expected the in_progress and queued queries, found ${queries.length}`);
});

test('both preflight queries skip debug probes', () => {
  const src = yml();
  const skips = src.match(/contains\(\\"\[debug probe\]\\"\) \| not/g) ?? [];
  assert.equal(skips.length, 2,
    `both the in_progress and queued queries must exclude probes; found ${skips.length} exclusion(s). `
      + 'Yielding to a probe costs the whole chain.');
});
