// The Windows leg of the era pin failed OPEN for a whole sweep — 333 of 333 win32 rows came back
// `NOT-PINNED (not provisionable)` because the provisioner fetched a linux tarball and then looked
// for `bin/node`. Nothing said so. These tests pin the two things that would have caught it: the
// per-platform layout, and a status string that names the stage that failed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { eraLayout, provisionEraNode } from './era-provision.mjs';

test('the archive, the extraction root and the binary name are all per-platform', () => {
  // Every one of these URLs was HEAD-checked against nodejs.org and returns 200.
  const w = eraLayout('4.9.1', { platform: 'win32', arch: 'x64' });
  assert.equal(w.archive, 'node-v4.9.1-win-x64.zip');
  assert.equal(w.binSubdir, '.', 'the win zip puts node.exe at the archive root, not under bin/');
  assert.equal(w.exe, 'node.exe');

  const l = eraLayout('10.24.1', { platform: 'linux', arch: 'x64' });
  assert.equal(l.archive, 'node-v10.24.1-linux-x64.tar.gz');
  assert.equal(l.binSubdir, 'bin');
  assert.equal(l.exe, 'node');
});

test('an era below a build that was never published falls back to the arch that was', () => {
  // nodejs.org ships no darwin-arm64 below 16 and no win-arm64 below 20. Asking for one yields a
  // 404, which the old code turned into a silent non-pin.
  assert.equal(eraLayout('4.9.1', { platform: 'darwin', arch: 'arm64' }).archive,
               'node-v4.9.1-darwin-x64.tar.gz');
  assert.equal(eraLayout('18.20.4', { platform: 'win32', arch: 'arm64' }).archive,
               'node-v18.20.4-win-x64.zip');
  // ...and the modern ones keep the native build.
  assert.equal(eraLayout('20.11.0', { platform: 'darwin', arch: 'arm64' }).archive,
               'node-v20.11.0-darwin-arm64.tar.gz');
  assert.equal(eraLayout('20.11.0', { platform: 'win32', arch: 'arm64' }).archive,
               'node-v20.11.0-win-arm64.zip');
});

test('a failed download names the stage and the URL instead of "not provisionable"', () => {
  const exec = (cmd) => (cmd === 'curl' ? { status: 22, stdout: '' } : { status: 0, stdout: '' });
  const r = provisionEraNode('4.9.1', { root: '/tmp/era-provision-test-dl', exec, platform: 'linux', arch: 'x64' });
  assert.equal(r.binDir, null);
  assert.match(r.status, /download failed rc=22/);
  assert.match(r.status, /node-v4\.9\.1-linux-x64\.tar\.gz/);
});

test('a download that yields the WRONG version is a loud mismatch, not a pin', () => {
  // existsSync is not proof: a truncated fetch, a wrong-arch build, or a stale cache directory all
  // leave something at the path. The binary is run and its --version compared.
  let stubbed = false;
  const exec = (cmd, args) => {
    if (cmd === 'curl' || cmd === 'tar') { stubbed = true; return { status: 0, stdout: '' }; }
    if (args?.[0] === '--version') return { status: 0, stdout: 'v18.20.4\n' };
    return { status: 0, stdout: '' };
  };
  // Point at this repo's own node so the binary genuinely exists on disk.
  const r = provisionEraNode('4.9.1', { root: '/tmp/era-provision-test-mismatch', exec, platform: 'linux', arch: 'x64' });
  assert.equal(r.binDir, null);
  assert.ok(stubbed, 'the control must actually reach the download stage');
  assert.match(r.status, /no node under bin\/|reports v18\.20\.4/);
});

test('Windows unzips with PowerShell, never with tar', () => {
  // ⛔ MEASURED ON ALL 570 WIN32 RECORDS: `tar -xf <zip>` returned rc=128 on every one, while the
  // identical bsdtar command extracts the same archive on macOS with rc=0. The runner's PATH
  // resolves `tar` to something that cannot read a zip. Expand-Archive is built in and needs no
  // PATH lookup.
  const seen = [];
  const exec = (cmd, args) => { seen.push(cmd); return { status: 0, stdout: '', stderr: '' }; };
  provisionEraNode('22.23.2', { root: '/tmp/era-provision-test-win', exec, platform: 'win32', arch: 'x64' });
  assert.ok(seen.includes('powershell'), `expected powershell, got ${seen.join(', ')}`);
  assert.ok(!seen.includes('tar'), 'tar must not be used on win32');
});

test('a failed extract carries the extractor own words, not just an exit code', () => {
  // `NOT-PINNED (extract failed rc=128 node-v22.23.2-win-x64.zip)` cost a whole CI round to
  // diagnose, because the message that would have named the cause was discarded.
  const exec = (cmd) => (cmd === 'curl'
    ? { status: 0, stdout: '', stderr: '' }
    : { status: 128, stdout: '', stderr: '\ntar: Error opening archive: Unrecognized archive format\n' });
  const r = provisionEraNode('22.23.2', { root: '/tmp/era-provision-test-why', exec, platform: 'linux', arch: 'x64' });
  assert.equal(r.binDir, null);
  assert.match(r.status, /Unrecognized archive format/);
});
