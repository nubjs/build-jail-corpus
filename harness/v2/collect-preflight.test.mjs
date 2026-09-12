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
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'package.json'), '{"name":"arm"}');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'nub.jsonc'), '{"install":{"buildJail":true}}');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', '.npmrc'), 'side-effects-cache=false\n');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'cat.json'), '{"packages":{}}');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'security-resolve.log'), 'resolved');
  fs.writeFileSync(path.join(arm, 'verify-at-grant', 'rc'), '1\n');
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
  const evidence = JSON.parse(fs.readFileSync(path.join(destination, 'manifest.json'), 'utf8'));
  assert.equal(evidence.length, 1);
  assert.equal(evidence[0].root, arm);
  assert.deepEqual(evidence[0].store, { nodeModulesPresent: false, links: [], truncated: false });
  assert.deepEqual(evidence[0].cjpeg, { path: 'node_modules/mozjpeg/vendor/cjpeg.exe', status: 'missing' });
  assert.deepEqual(evidence[0].files, [
    'verify-at-grant/package.json', 'verify-at-grant/nub.jsonc',
    'verify-at-grant/.npmrc', 'verify-at-grant/cat.json', 'verify-at-grant/security-resolve.log',
    'verify-at-grant/i.log', 'verify-at-grant/rc', 'store-provenance.json',
  ]);
  assert.equal(fs.readFileSync(path.join(destination, '0', 'verify-at-grant', 'cat.json'), 'utf8'), '{"packages":{}}');
  assert.equal(fs.existsSync(path.join(destination, '0', 'store-provenance.json')), true);
  run(path.join(root, 'missing.log'), path.join(root, 'missing-evidence'));
  assert.deepEqual(fs.readdirSync(path.join(root, 'missing-evidence')), []);
});

test('preflight records only cjpeg metadata when a failed arm resolves through a GVS package link', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'preflight-cjpeg-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const arm = path.join(root, 'arm');
  const outside = path.join(root, 'shared-store', 'mozjpeg', 'vendor');
  const exe = path.join(outside, 'cjpeg.exe');
  const log = path.join(root, 'measure.log');
  const destination = path.join(root, 'evidence');
  fs.mkdirSync(path.dirname(path.join(arm, 'verify-at-grant', 'node_modules', 'mozjpeg')), { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(exe, 'known-cjpeg-bytes');
  const linked = path.join(arm, 'verify-at-grant', 'node_modules', 'mozjpeg');
  fs.symlinkSync(path.dirname(outside), linked, process.platform === 'win32' ? 'junction' : 'dir');
  fs.writeFileSync(log, `kept for inspection: ${arm}\n`);
  const result = spawnSync(process.execPath, [path.join(import.meta.dirname, 'collect-preflight.mjs'), log, destination], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const { cjpeg, store } = JSON.parse(fs.readFileSync(path.join(destination, 'manifest.json'), 'utf8'))[0];
  assert.deepEqual(cjpeg, {
    path: 'node_modules/mozjpeg/vendor/cjpeg.exe',
    status: 'present',
    realpath: fs.realpathSync(exe),
    bytes: Buffer.byteLength('known-cjpeg-bytes'),
    sha256: 'd5edb9cedc7eb9a0be5b01022815f617215b70f8b64394533ca10cdb3dea6197',
  });
  assert.deepEqual(store, {
    nodeModulesPresent: true,
    links: [{ path: 'verify-at-grant/node_modules/mozjpeg', target: fs.realpathSync(linked) }],
    truncated: false,
  });
  assert.equal(fs.existsSync(path.join(destination, '0', 'verify-at-grant', 'node_modules')), false);
});
