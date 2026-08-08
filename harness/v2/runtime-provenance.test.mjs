import assert from 'node:assert/strict';
import { test } from 'node:test';
import { endpointIdentity, probeNodeRuntime } from './runtime-provenance.mjs';

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
