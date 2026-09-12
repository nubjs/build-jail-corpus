import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const HERE = import.meta.dirname;
const SCRIPT = path.join(HERE, 'arm-store-isolation.mjs');
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nub-arm-store-'));
const run = (arm, cache) => execFileSync(process.execPath, [SCRIPT, arm, cache, 'fixture'], { encoding: 'utf8' });

const fixture = () => {
  const root = temp();
  const arm = path.join(root, 'verify-at-grant');
  const cache = path.join(root, 'nubcache');
  fs.mkdirSync(path.join(arm, 'node_modules', '.store'), { recursive: true });
  fs.mkdirSync(path.join(cache, 'store', 'v1', 'package-a'), { recursive: true });
  return { root, arm, cache };
};

test('reports isolated only when observed .store links resolve inside this arm cache', () => {
  const { arm, cache } = fixture();
  fs.symlinkSync(path.join(cache, 'store', 'v1', 'package-a'), path.join(arm, 'node_modules', '.store', 'package-a'));
  assert.match(run(arm, cache), /^  STORE isolated label=fixture links=1 root=/m);
});

test('reports shared rather than accepting a link into another cache', () => {
  const { root, arm, cache } = fixture();
  const other = path.join(root, 'other-cache', 'store', 'v1', 'package-a');
  fs.mkdirSync(other, { recursive: true });
  fs.symlinkSync(other, path.join(arm, 'node_modules', '.store', 'package-a'));
  assert.match(run(arm, cache), /^  STORE shared label=fixture links=1 root=.* target=/m);
});

test('does not manufacture isolation when the arm has no observed store links', () => {
  const { arm, cache } = fixture();
  assert.match(run(arm, cache), /^  STORE unavailable label=fixture root=/m);
});
