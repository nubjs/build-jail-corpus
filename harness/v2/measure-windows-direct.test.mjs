// Contract checks for Windows DIRECT policy replay. These intentionally stop before OBSERVE: a
// valid catalog would start a real package install, while these checks only need to prove invalid
// caller input is refused before any workload and that the shipped driver keeps the catalog whole.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = import.meta.dirname;
const DRIVER = path.join(HERE, 'measure-windows.mjs');
const SOURCE = fs.readFileSync(DRIVER, 'utf8');
const run = (...args) => {
  const r = spawnSync(process.execPath, [DRIVER, 'fixture', '1.0.0', ...args], { encoding: 'utf8' });
  return { rc: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
};

test('Windows refuses mutually exclusive direct policy flags before a workload', () => {
  const catalog = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'win-atcat-')), 'catalog.json');
  fs.writeFileSync(catalog, '{"packages":{}}');
  const r = run('--at-grant', '{}', '--at-catalog', catalog);
  assert.equal(r.rc, 2, r.out);
  assert.match(r.out, /ask two different questions/);
});

test('Windows refuses missing and empty whole-catalog inputs before a workload', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-atcat-'));
  for (const catalog of [path.join(dir, 'missing.json'), path.join(dir, 'empty.json')]) {
    if (catalog.endsWith('empty.json')) fs.writeFileSync(catalog, '');
    const r = run('--at-catalog', catalog);
    assert.equal(r.rc, 2, `${catalog}: ${r.out}`);
    assert.match(r.out, /--at-catalog needs a non-empty catalog FILE/);
  }
});

test('a valid whole catalog is copied verbatim into the direct arm, never rebuilt as a target grant', () => {
  const preflight = SOURCE.slice(SOURCE.indexOf('const AT_GRANT'), SOURCE.indexOf('const NUB'));
  assert.match(preflight, /let AT_CATALOG = flag\('--at-catalog', ''\)/);
  assert.match(preflight, /const stat = fs\.statSync\(AT_CATALOG\)/);
  assert.match(preflight, /!stat\.isFile\(\) \|\| stat\.size === 0/);
  assert.match(preflight, /AT_CATALOG = path\.resolve\(AT_CATALOG\)/);
  assert.match(SOURCE, /fs\.copyFileSync\(wholeCatalog, cat\)/,
    'DIRECT catalog mode must retain the caller file rather than reconstruct a resolved grant');
  const wholeCatalogBranch = /if \(wholeCatalog\) \{([\s\S]*?)\n  \} else \{/.exec(SOURCE)?.[1] ?? '';
  assert.notEqual(wholeCatalogBranch, '', 'the whole-catalog branch must be present');
  assert.doesNotMatch(wholeCatalogBranch,
    /buildCatalog\(/, 'catalog mode must not inject scaffolds into the caller policy');
  assert.match(SOURCE, /const label = AT_CATALOG \? 'at-catalog' : 'at-grant'/);
  assert.match(SOURCE, /=> SUFFICIENT \$\{subject\}/);
  assert.match(SOURCE, /=> INSUFFICIENT \$\{subject\}/);
});

test('cache sharing remains restricted to either explicit direct-policy mode', () => {
  assert.match(SOURCE, /CACHE_HOME && !AT_GRANT && !AT_CATALOG/);
  assert.match(SOURCE, /direct --at-grant\/--at-catalog warm-state probes/);
});
