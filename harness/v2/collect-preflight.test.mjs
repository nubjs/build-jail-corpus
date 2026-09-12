import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

test('preflight evidence retains only bounded arm logs, even before a record exists', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const arm = path.join(root, 'arm with spaces');
  const log = path.join(root, 'measure.log');
  const destination = path.join(root, 'evidence');
  fs.mkdirSync(path.join(arm, 'verify-at-grant'), { recursive: true });
  fs.mkdirSync(path.join(arm, 'observe'));
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'i.log'), 'real install refusal');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'private.txt'), 'not evidence');
  if (process.platform !== 'win32') {
    const outside = path.join(root, 'outside.log');
    fs.writeFileSync(outside, 'not an arm log');
    fs.symlinkSync(outside, path.join(arm, 'verify-at-grant', 'a.log'));
  }
  const large = fs.openSync(path.join(arm, 'observe', 'fetch.log'), 'w');
  fs.ftruncateSync(large, 8 * 1024 * 1024 + 1);
  fs.closeSync(large);
  fs.writeFileSync(log, `kept for inspection: ${arm}\nkept for inspection: ${arm}\n`);
  const run = (input, output) => {
    const result = spawnSync(process.execPath, [path.join(import.meta.dirname, 'collect-preflight.mjs'), input, output], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  };
  run(log, destination);
  assert.equal(fs.readFileSync(path.join(destination, '0', 'verify-at-grant', 'i.log'), 'utf8'), 'real install refusal');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(destination, 'manifest.json'), 'utf8')), [
    { root: arm, files: ['verify-at-grant/i.log'] },
  ]);
  assert.deepEqual(fs.readdirSync(path.join(destination, '0', 'verify-at-grant')), ['i.log']);
  run(path.join(root, 'missing.log'), path.join(root, 'missing-evidence'));
  assert.deepEqual(fs.readdirSync(path.join(root, 'missing-evidence')), []);
});
