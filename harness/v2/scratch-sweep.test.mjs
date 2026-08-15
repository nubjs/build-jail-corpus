// The sweep is an `rm -rf` on a path parsed from subprocess stdout, so each refusal is tested by name.
//
// What forced it: 75 measured packages left 658 driver roots and filled a 193 GB disk, killing both
// lanes of a 25% run with ENOSPC. What must not follow from fixing that: deleting a root that still
// holds the artifact of record, or deleting anything that is not a driver root at all.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { sweepDecision } from './scratch-sweep.mjs';

// The real header, from measure.sh:157. measure-macos.sh:205 appends ` nub=<path>`.
const header = (root, extra = '') => `### left-pad@1.3.0   (${root})${extra}\n  OBSERVE artifacts: 8 files\n`;

test('an ordinary completed record sweeps its root', () => {
  const d = sweepDecision({ log: header('/home/nub/v2-abc123'), notes: [], runs: '/home/nub/run25-runs' });
  assert.equal(d.root, '/home/nub/v2-abc123');
  assert.equal(d.sweep, true, d.reason);
});

test('the macOS header, which appends nub=, still yields the root', () => {
  // ⛔ THE SAME PARSE TRAP falsify.mjs ALREADY PAID FOR. Anchoring the root group to end-of-line made
  // `root` null on darwin there, which emptied the arm logs and fabricated refusal alarms. Here an
  // unparsed root means the sweep silently never runs and the disk fills instead.
  const d = sweepDecision({ log: header('/Users/nub/v2-XyZ', '   nub=/usr/local/bin/nub'), notes: [] });
  assert.equal(d.root, '/Users/nub/v2-XyZ');
  assert.equal(d.sweep, true, d.reason);
});

test('the win32 root shape is accepted under win32 path semantics', () => {
  const d = sweepDecision({ log: header('C:\\jail\\m-mozjpeg-msurhs09'), notes: [], p: path.win32 });
  assert.equal(d.root, 'C:\\jail\\m-mozjpeg-msurhs09');
  assert.equal(d.sweep, true, d.reason);
});

test('a win32 root judged with POSIX semantics is REFUSED, which is why `p` is injectable', () => {
  // ⛔ THE FAILURE MODE IS SILENT AND IT IS THE ONE THIS SEAM EXISTS FOR. POSIX `path.isAbsolute` says
  // false for `C:\...` and `basename` returns the whole string, so the guard rejects a perfectly good
  // win32 root as mis-shaped — no error, no log, the disk simply fills exactly as before. Asserting the
  // refusal (rather than only the acceptance above) is what documents that the platform must match.
  const d = sweepDecision({ log: header('C:\\jail\\m-mozjpeg-msurhs09'), notes: [], p: path.posix });
  assert.equal(d.sweep, false);
  assert.match(d.reason, /not shaped like/);
});

test('a root whose ARTIFACT COPY FAILED is kept, for every copy note', () => {
  // ⛔ THE ONE REFUSAL THAT PROTECTS EVIDENCE RATHER THAN THE FILESYSTEM. The raw trace is the archive:
  // with it a decoder bug is a re-parse, without it a permanent hole nobody can see. A full disk stops
  // the run loudly; a lost archive does not stop it at all, which is why this direction is the safe one.
  for (const note of ['rawlog-copy-failed', 'capture-copy-failed', 'eventlog-copy-failed']) {
    const d = sweepDecision({ log: header('/home/nub/v2-abc123'), notes: ['something-else', note] });
    assert.equal(d.sweep, false, `must keep the root when ${note} is present`);
    assert.match(d.reason, /evidence/);
  }
  // An unrelated note must NOT block the sweep, or the disk fills for no reason.
  const ok = sweepDecision({ log: header('/home/nub/v2-abc123'), notes: ['rawlog-missing', 'driver-timeout'] });
  assert.equal(ok.sweep, true, ok.reason);
});

test('anything not shaped like a driver root is refused', () => {
  // The blast-radius guard. `rm -rf` on a path from a subprocess's stdout gets the paranoid treatment.
  for (const bad of ['/home/nub', '/', '/home/nub/run25-runs', '/etc', '/home/nub/build-jail-corpus',
    'v2-relative', './v2-abc', '/home/nub/records-v2']) {
    const d = sweepDecision({ log: header(bad), notes: [] });
    assert.equal(d.sweep, false, `must refuse to delete ${bad}`);
  }
});

test('a root that CONTAINS the records tree is refused', () => {
  // Cheap, and the one mistake that deletes the run's output rather than its garbage.
  const d = sweepDecision({
    log: header('/home/nub/v2-abc123'), notes: [], runs: '/home/nub/v2-abc123/runs',
  });
  assert.equal(d.sweep, false, 'the records tree lives inside this root');
  assert.match(d.reason, /records tree/);
});

test('no header means no root and no deletion', () => {
  for (const log of ['', 'OBSERVE artifacts: 8 files\n', '# not a header (x)']) {
    const d = sweepDecision({ log, notes: [] });
    assert.equal(d.root, null);
    assert.equal(d.sweep, false);
  }
  assert.equal(sweepDecision({}).sweep, false, 'a call with no arguments must not decide to delete');
});

test('--keep-roots / NUB_V2_KEEP_ROOTS suppresses the sweep', () => {
  const d = sweepDecision({ log: header('/home/nub/v2-abc123'), notes: [], keepRoots: true });
  assert.equal(d.sweep, false);
  assert.match(d.reason, /keep-roots/);
});

test('run-batch-v2 acts on this decision and does not carry its own copy', () => {
  // ⛔ AND IT MUST SWEEP AFTER `record.mjs`, NOT BEFORE. record.mjs is what copies trace.txt.gz and
  // capture.json out of the root; sweeping first would delete the archive it is about to copy. Pinned
  // by ORDER in the source, because that ordering is the whole safety argument.
  const src = fs.readFileSync(path.join(import.meta.dirname, 'run-batch-v2.mjs'), 'utf8');
  assert.match(src, /import \{ sweepDecision \} from '\.\/scratch-sweep\.mjs'/);
  const recordCall = src.indexOf("path.join(HERE, 'record.mjs')");
  const sweepCall = src.indexOf('sweepDecision({');
  assert.ok(recordCall > 0 && sweepCall > recordCall,
    'the sweep must come AFTER record.mjs has copied the artifacts out of the root');
  assert.ok(!/rmSync\([^)]*rootMatch/.test(src), 'run-batch-v2 must not re-derive the root itself');
});
