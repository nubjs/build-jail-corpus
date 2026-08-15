// The era pin has to reach the RECORD, populated — not merely be emitted by a driver.
//
// ⛔ WHY "POPULATED" IS THE BAR AND NOT "PRESENT". v1 shipped an entire Linux run whose every record
// said `pinnedTo: null` because the selection silently fell through, and nothing in the record could
// distinguish that from a deliberate no-pin. A test that only asserted the field EXISTS would have
// passed on that whole run. So every case below asserts a real value, and the failure case asserts a
// stated REASON rather than a null.
//
// The marker contract (`marker-contract.test.mjs`) already proves the emit and parse sides agree on
// the NAME. This file covers what that one cannot: the value's shape once it lands.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseDriverLog } from './record.mjs';

/** A driver log carrying the two markers that together answer "which Node, and which was intended". */
const log = (selectionJson, interpreter = '/usr/local/node-18') => [
  '### demo@1.0.0   (/tmp/x)   nub=/tmp/nub',
  `  VENUE-INTERPRETER ${interpreter}`,
  `  VENUE-NODE-SELECTION ${selectionJson}`,
].join('\n');

test('a selection marker lands in the parsed record with its fields intact', () => {
  const sel = {
    pkg: 'demo', packageVersion: '1.0.0', major: 18, version: '18.20.8', npm: '10.8.2',
    engines: '>=18', publishedAt: '2023-09-15', eraMajor: 18, startMajor: 18,
    raisedByEngines: false, enginesUnsatisfiable: false, clampedToFloor: false,
    clampedToCeiling: false, matrixFloor: 18, matrixCeiling: 26,
  };
  const out = parseDriverLog(log(JSON.stringify(sel)));
  assert.ok(out.nodeSelection, 'the selection must reach the record, not be dropped');
  assert.equal(out.nodeSelection.version, '18.20.8', 'the chosen NODE version');
  assert.equal(out.nodeSelection.packageVersion, '1.0.0',
    'the PACKAGE version must survive — the CLI once let the Node version clobber this key');
  assert.equal(out.nodeSelection.eraMajor, 18);
  assert.equal(out.nodeSelection.clampedToFloor, false);
});

test('the era pick and the Node actually used are BOTH recorded, so a divergence is visible', () => {
  // This is the whole point of recording before enforcing: the pair is what tells us how often the
  // ambient Node differs from the era pick. One without the other answers nothing.
  const sel = { pkg: 'demo', packageVersion: '1.0.0', major: 18, version: '18.20.8', eraMajor: 18 };
  const out = parseDriverLog(log(JSON.stringify(sel), '/opt/node-22/bin/node'));
  assert.equal(out.nodeSelection.version, '18.20.8', 'what the era rule chose');
  // `interpreterPath`, which is what record.mjs actually calls it — checked against the parser
  // rather than assumed, since a wrong field name here would make this test vacuously green on the
  // half of the pair it exists to prove.
  assert.match(out.interpreterPath ?? '', /node-22/, 'what the arm actually ran on');
});

test('a FAILED selection is recorded as a stated error, never as a silent null', () => {
  // The drivers emit `{"error": …}` rather than skipping the marker, because an absent marker leaves
  // nodeSelection: null — which reads as "no pin was intended" instead of "we lost the answer".
  const out = parseDriverLog(log('{"error":"era-node selection failed"}'));
  assert.ok(out.nodeSelection, 'a failure must still populate the field');
  assert.match(out.nodeSelection.error, /era-node selection failed/);
});

test('unparsable selection JSON is noted rather than swallowed', () => {
  const out = parseDriverLog(log('{not json'));
  assert.equal(out.nodeSelection, null, 'a corrupt value must not be half-applied');
  assert.ok(out.notes.includes('node-selection-unparsable'),
    `the parse failure must be NOTED so the record says why the field is empty, got ${JSON.stringify(out.notes)}`);
});

test('a log with no selection marker leaves the field null, and that is distinguishable', () => {
  // The pre-wiring shape. Kept as an explicit case so the difference between "no marker" and
  // "marker said it failed" stays legible in the data rather than collapsing to one value.
  const out = parseDriverLog('### demo@1.0.0   (/tmp/x)   nub=/tmp/nub\n  VENUE-INTERPRETER /usr/bin/node');
  assert.equal(out.nodeSelection, null);
  assert.ok(!out.notes.includes('node-selection-unparsable'),
    'an absent marker is not a parse failure and must not be reported as one');
});
