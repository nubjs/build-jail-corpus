// The driver-time refusal on a MIXED harness tree.
//
// ⛔ THIS IS NOT A SECOND COPY OF `queue-settled.test.mjs`'s epoch assertion. That one runs when
// someone runs the suite; this one runs when a driver starts, which is the case the suite cannot
// reach — a driver invoked standalone on a tree assembled by hand.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { instrumentSelfCheck } from './instrument-selfcheck.mjs';

const HERE = import.meta.dirname;

/** A throwaway pair of instrument files. */
function tree(instrument, policy) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'selfcheck-'));
  if (instrument !== null) fs.writeFileSync(path.join(d, 'instrument.json'), instrument);
  if (policy !== null) fs.writeFileSync(path.join(d, 'invalidation.json'), policy);
  return d;
}

test('a coherent tree passes and names its epoch', () => {
  const r = instrumentSelfCheck(tree('{"harnessEpoch":81}', '{"currentEpoch":81,"transitions":[]}'));
  assert.equal(r.ok, true, r.marker);
  assert.equal(r.marker, 'HARNESS-INSTRUMENT epoch=81');
});

test('RED CONTROL: a mixed tree refuses, naming both numbers', () => {
  // The shape a copied `harness/` produces — code from one revision, config from another. Downstream
  // it presents as `instrumentCompatibility` refusing every record, which reads as the whole corpus
  // having gone stale rather than as the tree being wrong.
  const r = instrumentSelfCheck(tree('{"harnessEpoch":3}', '{"currentEpoch":81,"transitions":[]}'));
  assert.equal(r.ok, false);
  assert.match(r.marker, /epoch 3/);
  assert.match(r.marker, /currentEpoch 81/);
});

test('an absent or unparsable instrument file refuses rather than assuming coherence', () => {
  assert.equal(instrumentSelfCheck(tree(null, '{"currentEpoch":81}')).ok, false);
  assert.equal(instrumentSelfCheck(tree('{"harnessEpoch":81}', 'not json')).ok, false);
});

test('the live tree is coherent, and all three drivers refuse when it is not', () => {
  // ⛔ THE LIVE ASSERTION IS DELIBERATE. An epoch bump that edits one file and not the other would
  // otherwise be caught only by `queue-settled.test.mjs`, and this module would silently start
  // refusing every measurement on the next standalone driver run.
  const live = instrumentSelfCheck();
  assert.equal(live.ok, true, live.marker);
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('instrument-selfcheck'), `${d} does not run the mixed-tree check`);
  }
});
