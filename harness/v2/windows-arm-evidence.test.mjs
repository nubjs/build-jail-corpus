import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createWindowsArmEvidence, MAX_FILE_BYTES } from './windows-arm-evidence.mjs';

const put = (root, relative, body) => {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
};

test('retains full manifests and bounded fixed diagnostics for a successful arm', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'win-evidence-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const arm = path.join(root, 'verify-synth');
  const pkg = path.join(arm, 'node_modules', 'fixture');
  put(pkg, 'index.js', 'package');
  put(pkg, '.npmignore', 'metadata');
  put(pkg, 'build/config.gypi', 'config');
  put(pkg, 'build/project.vcxproj', '<Project/>');
  put(pkg, 'build/large.props', Buffer.alloc(MAX_FILE_BYTES + 1));
  put(pkg, 'build/ignored.obj', 'object');
  put(arm, 'i.log', 'installed');
  put(arm, 'a.log', 'approved');
  const evidence = createWindowsArmEvidence({ destination: path.join(root, 'report'), fixtureRoot: root, pkg: 'fixture', ver: '1.0.0' });
  const result = evidence.capture({ label: 'verify-synth', armRoot: arm });
  assert.equal(result.package.status, 'present');
  assert.deepEqual(result.package.manifest.map((entry) => entry.path), ['.npmignore', 'build/config.gypi', 'build/ignored.obj', 'build/large.props', 'build/project.vcxproj', 'index.js']);
  assert.deepEqual(result.logs.map((entry) => [entry.path, entry.status]), [['fetch.log', 'missing'], ['security-resolve.log', 'missing'], ['i.log', 'copied'], ['a.log', 'copied']]);
  assert.deepEqual(result.package.build.map((entry) => [entry.path, entry.status]), [['build/config.gypi', 'copied'], ['build/large.props', 'too-large'], ['build/project.vcxproj', 'copied'], ['buildcheck.gypi', 'missing']]);
  assert.equal(fs.readFileSync(path.join(evidence.dir, 'verify-synth', 'i.log'), 'utf8'), 'installed');
});

test('retains timeout-stage logs and explicitly records missing output without following outside files', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'win-evidence-timeout-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const arm = path.join(root, 'verify-timeout');
  put(arm, 'i.log', 'partial install before timeout');
  const outside = path.join(root, 'outside.log'); put(root, 'outside.log', 'secret outside fixture arm');
  if (process.platform !== 'win32') fs.symlinkSync(outside, path.join(arm, 'a.log'));
  const evidence = createWindowsArmEvidence({ destination: path.join(root, 'report'), fixtureRoot: root, pkg: 'fixture', ver: '1.0.0' });
  const result = evidence.capture({ label: 'verify-timeout', armRoot: arm });
  assert.equal(result.package.status, 'missing');
  const install = result.logs.find((entry) => entry.path === 'i.log');
  assert.equal(install.status, 'copied');
  assert.equal(install.bytes, 30);
  assert.match(install.sha256, /^[0-9a-f]{64}$/);
  const approve = result.logs.find((entry) => entry.path === 'a.log');
  assert.equal(approve.status, process.platform === 'win32' ? 'missing' : 'not-regular');
});
