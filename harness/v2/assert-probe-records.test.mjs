import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkRecord } from './assert-probe-records.mjs';

const expected = { pkg: 'fixture', version: '1.0.0', platform: 'win32-x64', nubGitSha: 'n', corpusGitSha: 'c', harnessSha256: 'h', nubSha256: 'b' };
const good = () => ({ pkg: 'fixture', version: '1.0.0', harnessVersion: 2, driverRc: 0, verdict: 'SUFFICIENT', verifiedBy: 'synth', provenance: { ...expected, nubBinary: { sha256: 'b' } } });
test('accepts a fully attributed verified record', () => assert.deepEqual(checkRecord(good(), expected), []));
test('rejects missing or mismatched source and instrument provenance', () => {
  for (const key of ['platform', 'nubGitSha', 'corpusGitSha', 'harnessSha256']) {
    for (const value of [null, 'other']) {
      const record = good(); record.provenance[key] = value;
      assert.ok(checkRecord(record, expected).includes(key));
    }
  }
});
test('rejects a changed or missing runtime binary', () => {
  const record = good(); record.provenance.nubBinary = null;
  assert.ok(checkRecord(record, expected).includes('nubSha256'));
  record.provenance.nubBinary = { sha256: 'different' };
  assert.ok(checkRecord(record, expected).includes('nubSha256'));
});
test('does not accept unverified, failed, refused, or mismatched records', () => {
  for (const patch of [{ pkg: 'other' }, { version: '2' }, { driverRc: 124 }, { verifiedBy: null }, { verdict: 'VOID' }, { verdict: 'REFUSED-MALICIOUS' }, { harnessVersion: 1 }]) {
    assert.ok(checkRecord({ ...good(), ...patch }, expected).length);
  }
});
test('CLI requires all records and preserves a partial summary on failure', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'probe-records-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const worklist = path.join(root, 'worklist.txt'), binding = path.join(root, 'expected.json');
  const runs = path.join(root, 'runs'), out = path.join(root, 'summary.json');
  fs.writeFileSync(worklist, 'fixture@1.0.0\nmissing@2.0.0\n');
  fs.writeFileSync(binding, JSON.stringify(expected));
  const dir = path.join(runs, expected.platform, 'fixture', '1.0.0');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(good()));
  const args = [fileURLToPath(new URL('./assert-probe-records.mjs', import.meta.url)), '--file', worklist, '--runs', runs, '--expected', binding, '--out', out];
  let result = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(result.status, 1, result.stderr);
  const summary = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(summary.records.length, 2);
  assert.deepEqual(summary.records[0].errors, []);
  assert.equal(summary.records[1].errors.length, 1);
  fs.writeFileSync(worklist, 'fixture@1.0.0\n');
  result = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
test('artifact-only workflow has no publication or queue-writing authority', () => {
  const workflow = fs.readFileSync(new URL('../../.github/workflows/zero-sandbox-records.yml', import.meta.url), 'utf8');
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /unset NUB_CORPUS_ON_RECORD NUB_CORPUS_REPO NUB_CORPUS_BRANCH NUB_CORPUS_MANIFEST/);
  assert.doesNotMatch(workflow, /contents: write|actions: write|git push|publish-record|claim-slice|--no-falsify/);
});
