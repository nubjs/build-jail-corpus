import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { boundedText, CJPEG_PATH, MAX_CJPEG_BYTES, inspectCjpeg } from './cjpeg-oracle.mjs';

const fixture = (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cjpeg-oracle-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
};

test('allows a package-directory GVS link but hashes only the bounded final regular file', (t) => {
  const root = fixture(t);
  const base = path.join(root, 'arm');
  const gvs = path.join(root, 'gvs', 'mozjpeg');
  const artifact = path.join(gvs, 'vendor', 'cjpeg.exe');
  fs.mkdirSync(path.dirname(artifact), { recursive: true });
  fs.mkdirSync(path.join(base, 'node_modules'), { recursive: true });
  fs.writeFileSync(artifact, 'known-cjpeg-bytes');
  if (process.platform === 'win32') fs.cpSync(gvs, path.join(base, 'node_modules', 'mozjpeg'), { recursive: true });
  else fs.symlinkSync(gvs, path.join(base, 'node_modules', 'mozjpeg'), 'dir');
  assert.deepEqual(inspectCjpeg(base), {
    path: CJPEG_PATH,
    status: 'present',
    realpath: fs.realpathSync(artifact),
    bytes: Buffer.byteLength('known-cjpeg-bytes'),
    sha256: crypto.createHash('sha256').update('known-cjpeg-bytes').digest('hex'),
  });
});

test('captures executable output to an explicit byte limit', () => {
  assert.deepEqual(boundedText('é'.repeat(8), 5), {
    text: 'éé�',
    bytes: 16,
    capturedBytes: 5,
    truncated: true,
  });
});

test('refuses an oversized artifact without allocating or hashing it', (t) => {
  const root = fixture(t);
  const base = path.join(root, 'arm');
  const artifact = path.join(base, CJPEG_PATH);
  fs.mkdirSync(path.dirname(artifact), { recursive: true });
  const fd = fs.openSync(artifact, 'w');
  fs.ftruncateSync(fd, MAX_CJPEG_BYTES + 1);
  fs.closeSync(fd);
  const result = inspectCjpeg(base);
  assert.equal(result.status, 'too-large');
  assert.equal(result.bytes, MAX_CJPEG_BYTES + 1);
  assert.equal('sha256' in result, false);
});

test('refuses a final cjpeg symlink even when its target is a regular file', (t) => {
  if (process.platform === 'win32') return t.skip('file symlink creation needs an unavailable privilege on some Windows hosts');
  const root = fixture(t);
  const base = path.join(root, 'arm');
  const artifact = path.join(base, CJPEG_PATH);
  const outside = path.join(root, 'outside.exe');
  fs.mkdirSync(path.dirname(artifact), { recursive: true });
  fs.writeFileSync(outside, 'outside');
  fs.symlinkSync(outside, artifact);
  assert.deepEqual(inspectCjpeg(base), { path: CJPEG_PATH, status: 'final-symlink' });
});

test('refuses a vendor-directory link whose final executable escapes the resolved package root', (t) => {
  if (process.platform === 'win32') return t.skip('directory symlink creation needs an unavailable privilege on some Windows hosts');
  const root = fixture(t);
  const base = path.join(root, 'arm');
  const vendor = path.join(base, 'node_modules', 'mozjpeg', 'vendor');
  const outside = path.join(root, 'outside');
  fs.mkdirSync(path.dirname(vendor), { recursive: true });
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, 'cjpeg.exe'), 'outside');
  fs.symlinkSync(outside, vendor, 'dir');
  assert.equal(inspectCjpeg(base).status, 'outside-package');
});
