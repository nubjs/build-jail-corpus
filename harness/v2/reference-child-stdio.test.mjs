import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { test } from 'node:test';

test('the diagnostic preload mirrors only otherwise-unconsumed child output', () => {
  const preload = path.join(import.meta.dirname, 'reference-child-stdio.cjs');
  const script = `
    const { spawn } = require('node:child_process');
    const child = spawn(process.execPath, ['-e',
      'console.log("hidden child stdout"); console.error("hidden child stderr")']);
    child.on('close', (code) => { console.error('parent saw close ' + code); });
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: `--require=${preload}` },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /REFERENCE-CHILD-STDOUT/);
  assert.match(result.stderr, /hidden child stdout/);
  assert.match(result.stderr, /REFERENCE-CHILD-STDERR/);
  assert.match(result.stderr, /hidden child stderr/);
  assert.match(result.stderr, /parent saw close 0/);
});

test('the diagnostic preload does not mirror a stream the parent consumes', () => {
  const preload = path.join(import.meta.dirname, 'reference-child-stdio.cjs');
  const script = `
    const { spawn } = require('node:child_process');
    const child = spawn(process.execPath, ['-e', 'console.log("consumed output")']);
    child.stdout.on('data', () => {});
    child.on('close', (code) => { console.error('parent saw close ' + code); });
  `;
  const result = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: `--require=${preload}` },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, /REFERENCE-CHILD-STDOUT|consumed output/);
  assert.match(result.stderr, /parent saw close 0/);
});
