// Golden cases for `artifact-gate.mjs` — the arm that decides whether a jailed install actually
// produced what the unjailed one did, and therefore whether a synthesized grant VERIFIES.
//
// ⛔ THE GATE DECIDES VERDICTS, SO ITS FALSE NEGATIVES BECOME WRONG CATALOG ENTRIES. It has
// produced two already: it walked a nested `node_modules` and reported `missing=13181` for a
// package that verifies at `{"network":true}`, and it failed `truffle@5.11.5` on all four rungs
// over one `test/.npmignore` while every rung exited rc=0. Both were layout differences between
// npm's extraction and nub's store materialisation, never a denied write.
//
// So every exclusion needs BOTH polarities pinned: the thing it ignores must not fail the gate,
// AND a genuinely missing artifact must still fail it. An exclusion tested only in the direction
// that makes things pass is how the gate stops gating.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GATE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'artifact-gate.mjs');
const PKG = 'fixture-pkg';
const VER = '1.0.0';

/** Build an `<root>/node_modules/<pkg>` tree from a {relpath: contents} map. */
const tree = (label, files) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `agate-${label}-`));
  for (const [rel, body] of Object.entries(files)) {
    const p = path.join(root, 'node_modules', PKG, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
  }
  return root;
};

/** Run the gate. Returns {code, out} — never throws, so a failing gate is data rather than an error. */
const gate = (obs, arm) => {
  try {
    const out = execFileSync(process.execPath, [GATE, '--obs', obs, '--arm', arm, '--pkg', PKG, '--ver', VER], {
      encoding: 'utf8',
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
};

test('an identical tree passes — the positive control, without which every other case is vacuous', () => {
  const files = { 'index.js': 'x', 'bin/tool': 'BINARY' };
  const r = gate(tree('obs-same', files), tree('arm-same', files));
  assert.equal(r.code, 0, `identical trees must pass:\n${r.out}`);
  assert.match(r.out, /missing=0/);
});

test('a genuinely missing artifact FAILS — the gate can still gate', () => {
  const r = gate(
    tree('obs-miss', { 'index.js': 'x', 'bin/tool': 'BINARY' }),
    tree('arm-miss', { 'index.js': 'x' }),
  );
  assert.equal(r.code, 1, `a missing artifact must fail:\n${r.out}`);
  assert.match(r.out, /bin\/tool/, 'the failure must NAME the missing file, not just count it');
});

test('a TRUNCATED artifact fails — present-but-empty is the download-blocked shape', () => {
  const r = gate(
    tree('obs-trunc', { 'bin/tool': 'FULL-CONTENTS-HERE' }),
    tree('arm-trunc', { 'bin/tool': '' }),
  );
  assert.equal(r.code, 1, `a truncated artifact must fail:\n${r.out}`);
  assert.match(r.out, /0B < \d+B/, 'the failure must report the size shortfall');
});

test('packaging metadata missing from the arm does NOT fail — it is not an artifact', () => {
  // The measured `truffle@5.11.5` shape: every rung rc=0, failed on `test/.npmignore` alone.
  const r = gate(
    tree('obs-meta', { 'index.js': 'x', 'test/.npmignore': 'coverage', '.gitignore': 'node_modules' }),
    tree('arm-meta', { 'index.js': 'x' }),
  );
  assert.equal(r.code, 0, `packaging metadata must not gate a verdict:\n${r.out}`);
  assert.match(r.out, /missing=0/);
});

test('⛔ `.npmrc` is NOT excused — the one credential-bearing file the exclusion must not swallow', () => {
  const r = gate(
    tree('obs-npmrc', { 'index.js': 'x', '.npmrc': '//registry:_authToken=t' }),
    tree('arm-npmrc', { 'index.js': 'x' }),
  );
  assert.equal(r.code, 1, `.npmrc must stay visible to the manifest:\n${r.out}`);
  assert.match(r.out, /\.npmrc/);
});

test('a nested node_modules is not billed — the other layout dependency closure', () => {
  const r = gate(
    tree('obs-nested', { 'index.js': 'x', 'node_modules/dep/big.js': 'DEP'.repeat(100) }),
    tree('arm-nested', { 'index.js': 'x' }),
  );
  assert.equal(r.code, 0, `a nested node_modules must not gate a verdict:\n${r.out}`);
});

test('an absent package directory fails loudly rather than passing vacuously', () => {
  const arm = fs.mkdtempSync(path.join(os.tmpdir(), 'agate-arm-absent-'));
  const r = gate(tree('obs-absent', { 'index.js': 'x' }), arm);
  assert.equal(r.code, 1, `an absent package must fail:\n${r.out}`);
  assert.match(r.out, /absent/);
});

test('an empty reference refuses to gate rather than reporting success', () => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'agate-obs-empty-'));
  const r = gate(obs, tree('arm-forempty', { 'index.js': 'x' }));
  assert.equal(r.code, 3, `no reference must be its own outcome, not a pass:\n${r.out}`);
  assert.match(r.out, /NO-REFERENCE/);
});
