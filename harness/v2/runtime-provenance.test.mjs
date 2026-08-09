import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { endpointIdentity, fileIdentity, probeNodeRuntime, probeTool } from './runtime-provenance.mjs';

test('endpoint provenance distinguishes mirrors without retaining credentials or query secrets', () => {
  const endpoint = endpointIdentity('https://user:secret@mirror.example.test/node?token=private#fragment');
  assert.equal(endpoint.display, 'https://mirror.example.test/node');
  assert.equal(endpoint.sha256.length, 64);
  assert.doesNotMatch(JSON.stringify(endpoint), /user|secret|token|private|fragment/);
  assert.notEqual(endpoint.sha256, endpointIdentity('https://mirror.example.test/node').sha256);
});

test('the target runtime identity comes from the selected executable rather than PATH', () => {
  const identity = probeNodeRuntime(process.execPath);
  assert.equal(identity.version, process.version);
  assert.equal(identity.path, process.execPath);
  assert.equal(identity.sha256.length, 64);
});

test('tool provenance resolves and executes through the supplied lifecycle PATH', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'reference-profile-tool-'));
  const root = path.join(parent, 'tool path');
  fs.mkdirSync(root);
  const command = 'reference-profile-tool';
  const file = path.join(root, process.platform === 'win32' ? `${command}.cmd` : command);
  if (process.platform === 'win32') {
    fs.writeFileSync(path.join(root, command), '#!/bin/sh\necho wrong shim\n');
  }
  fs.writeFileSync(file, process.platform === 'win32'
    ? '@echo reference-profile-tool %~1\r\n' : '#!/bin/sh\necho reference-profile-tool "$1"\n');
  if (process.platform !== 'win32') fs.chmodSync(file, 0o755);
  const env = { ...process.env, PATH: [root, process.env.PATH].filter(Boolean).join(path.delimiter) };
  const result = probeTool(command, ['argument with spaces'], env);
  assert.equal(result.version, 'reference-profile-tool argument with spaces');
  assert.deepEqual(result.executable, fileIdentity(result.path));
  const expectedIdentity = fileIdentity(file);
  assert.equal(result.executable.sha256, expectedIdentity.sha256);
  assert.equal(result.executable.bytes, expectedIdentity.bytes);
});
