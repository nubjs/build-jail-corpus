// ⛔ THE GATE THAT BINNED A DARWIN SLICE. `verify-corpus.mjs` runs BEFORE the commit step under
// `set -eu`, so a false red there does not merely mislead — it throws away every measurement in the
// slice. Run 32660365047 lost nine good darwin records because ONE unrelated record on disk was
// pre-epoch: `publish-record-v2.sh` had withheld this run's `unicode@0.2.1` and RESTORED ORIGIN'S
// PRIOR COPY in its place (deliberately — "the corpus keeps its prior grant"), and the gate then
// judged that restored copy as this slice's own failure.
//
// These tests drive the real script as a subprocess, because the thing under test is a GATE and its
// exit code is its whole contract. Each builds a throwaway records tree, so none of them depends on
// the state of the corpus in this checkout.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.join(HERE, '..', 'verify-corpus.mjs');

// A record with no provenance — the shape `recordValidity` rejects as predating epoch 3.
const preEpoch = (pkg, version) => JSON.stringify({ pkg, version, harnessVersion: 2, verdict: 'MINIMUM' });

function tree(records) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-scope-'));
  const runs = path.join(root, 'records-v2', 'runs');
  const dirs = [];
  for (const [rel, body] of Object.entries(records)) {
    const dir = path.join(runs, rel);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'results.json'), body);
    dirs.push(path.relative(root, dir));
  }
  fs.writeFileSync(path.join(root, 'queue-v2.ndjson'), '');
  return { root, runs, dirs };
}

const run = (root, args) => spawnSync(process.execPath, [GATE, ...args], { cwd: root, encoding: 'utf8' });

test('a pre-epoch record NOT in the manifest cannot fail the slice — the darwin case', () => {
  const t = tree({ 'darwin-arm64/withheld-pkg/0.2.1': preEpoch('withheld-pkg', '0.2.1') });
  const manifest = path.join(t.root, 'published.txt');
  fs.writeFileSync(manifest, '');            // this run published nothing; the record is origin's
  const r = run(t.root, ['--records', 'records-v2/runs', '--queue', 'queue-v2.ndjson',
    '--current-instrument', '--published', manifest]);
  assert.equal(r.status, 0, `gate should pass, said: ${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /judged NOTHING/);  // and it must SAY the check was vacuous
});

test('the same record IN the manifest still fails — the narrowing is not a hole', () => {
  const t = tree({ 'darwin-arm64/withheld-pkg/0.2.1': preEpoch('withheld-pkg', '0.2.1') });
  const manifest = path.join(t.root, 'published.txt');
  fs.writeFileSync(manifest, `${t.dirs[0]}\n`);
  const r = run(t.root, ['--records', 'records-v2/runs', '--queue', 'queue-v2.ndjson',
    '--current-instrument', '--published', manifest]);
  assert.equal(r.status, 1, `gate should fail, said: ${r.stdout}${r.stderr}`);
  // The verdict goes to stderr, the summary to stdout — match the pair, not one stream.
  assert.match(`${r.stdout}${r.stderr}`, /not valid under current harness epoch/);
});

test('without --published the gate judges everything, as it always did', () => {
  const t = tree({ 'darwin-arm64/withheld-pkg/0.2.1': preEpoch('withheld-pkg', '0.2.1') });
  const r = run(t.root, ['--records', 'records-v2/runs', '--queue', 'queue-v2.ndjson',
    '--current-instrument']);
  assert.equal(r.status, 1, 'the unscoped form must keep its old behaviour');
});

test('an unreadable manifest REFUSES rather than falling back either way', () => {
  const t = tree({ 'darwin-arm64/withheld-pkg/0.2.1': preEpoch('withheld-pkg', '0.2.1') });
  const r = run(t.root, ['--records', 'records-v2/runs', '--queue', 'queue-v2.ndjson',
    '--current-instrument', '--published', path.join(t.root, 'absent.txt')]);
  // Neither 0 (vacuous) nor 1 (whole-tree): a distinct refusal, so the mistake cannot be read as
  // a verdict about the corpus.
  assert.equal(r.status, 2, `expected REFUSED, said: ${r.stdout}${r.stderr}`);
  assert.match(r.stderr, /unreadable/);
});

test('the scope narrowing is reported, never silent', () => {
  const t = tree({
    'darwin-arm64/a/1.0.0': preEpoch('a', '1.0.0'),
    'darwin-arm64/b/1.0.0': preEpoch('b', '1.0.0'),
  });
  const manifest = path.join(t.root, 'published.txt');
  fs.writeFileSync(manifest, '');
  const r = run(t.root, ['--records', 'records-v2/runs', '--queue', 'queue-v2.ndjson',
    '--current-instrument', '--published', manifest]);
  assert.match(r.stdout, /2 pre-existing record\(s\) on disk were not judged/);
});
