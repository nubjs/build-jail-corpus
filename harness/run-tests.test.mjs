import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const runner = path.join(import.meta.dirname, 'run-tests.mjs');
const tempRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'harness-test-runner-'));
const run = (root) => {
  const env = { ...process.env };
  // A child launched by `node --test` otherwise joins its parent's test context. The workflow
  // launches this runner directly, so remove the test-runner transport marker to exercise that path.
  delete env.NODE_TEST_CONTEXT;
  return spawnSync(process.execPath, [runner, root], { encoding: 'utf8', env });
};

test('the harness runner discovers nested tests and preserves spaces in paths', () => {
  const root = tempRoot();
  const nested = path.join(root, 'nested fixture');
  fs.mkdirSync(nested);
  fs.writeFileSync(path.join(nested, 'passing.test.mjs'),
    "import { test } from 'node:test'; test('nested control', () => {});\n");

  const result = run(root);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /nested control/);
});

test('the harness runner fails rather than silently accepting an empty test tree', () => {
  const result = run(tempRoot());
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no harness tests discovered/);
});

test('the harness runner propagates a failing test status', () => {
  const root = tempRoot();
  fs.writeFileSync(path.join(root, 'failing.test.mjs'),
    "import { test } from 'node:test'; test('failing control', () => { throw new Error('control failure'); });\n");

  const result = run(root);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /failing control/);
});
