import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { test } from 'node:test';

const script = path.join(import.meta.dirname, 'make-queue-v2.mjs');
const writeRows = (file, rows) => fs.writeFileSync(file, `${rows.map(JSON.stringify).join('\n')}\n`);
const readRows = (file) => fs.readFileSync(file, 'utf8').trim().split('\n').map(JSON.parse);

test('preserves v1 resolved-tree refusals while resetting ordinary v1 measurements', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'make-v2-'));
  const from = path.join(dir, 'v1.ndjson');
  const out = path.join(dir, 'v2.ndjson');
  writeRows(from, [
    { pkg: 'bad', version: '1.0.0', os: 'linux', status: 'done', verdict: 'REFUSED-MALICIOUS' },
    { pkg: 'good', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM' },
  ]);
  execFileSync(process.execPath, [script, '--from', from, '--out', out]);
  assert.deepEqual(readRows(out), [
    {
      pkg: 'bad', version: '1.0.0', os: 'linux', status: 'refused-malicious',
      verdict: 'REFUSED-MALICIOUS', sourceVerdict: 'v1-resolved-tree-screen',
    },
    { pkg: 'good', version: '1.0.0', os: 'linux', status: 'pending' },
  ]);
});

test('--preserve-existing repairs refusals without discarding unrelated v2 progress', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'make-v2-'));
  const from = path.join(dir, 'v1.ndjson');
  const out = path.join(dir, 'v2.ndjson');
  writeRows(from, [
    { pkg: 'bad', version: '1.0.0', os: 'linux', verdict: 'REFUSED-MALICIOUS' },
    { pkg: 'good', version: '1.0.0', os: 'linux', verdict: 'MINIMUM' },
  ]);
  writeRows(out, [
    { pkg: 'bad', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM' },
    { pkg: 'good', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM', run: 'kept' },
    { pkg: 'v2-only', version: '2.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM' },
  ]);
  execFileSync(process.execPath, [script, '--from', from, '--out', out, '--preserve-existing']);
  const rows = readRows(out);
  assert.equal(rows[0].status, 'refused-malicious');
  assert.equal(rows[0].sourceVerdict, 'v1-resolved-tree-screen');
  assert.deepEqual(rows[1],
    { pkg: 'good', version: '1.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM', run: 'kept' });
  assert.deepEqual(rows[2],
    { pkg: 'v2-only', version: '2.0.0', os: 'linux', status: 'done', verdict: 'MINIMUM' });
});
