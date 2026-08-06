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

// ── `shortfall=<digest>`, the field the driver's grant-independence test compares across arms ──────
//
// ⛔ BOTH POLARITIES, FOR THE SAME REASON EVERY EXCLUSION ABOVE HAS BOTH. The digest exists so the
// driver can tell "the same shortfall four times" from "four different shortfalls", and a digest that
// only ever collides would report every failing ladder as grant-independent — which is the shape that
// publishes a grant for a package whose install was genuinely broken.

test('the same shortfall digests identically — what lets the driver call a shortfall invariant', () => {
  // ⛔ NOT a `.o.d`. The gate deliberately skips the shorter-but-non-empty comparison for `.d` files,
  // whose size tracks the length of the header paths they record rather than anything about the
  // build. This test is about DIGEST STABILITY and needs a file whose size still carries signal; an
  // object file does. (It used `.o.d` originally because that is the shape the real lmdb-store case
  // had — which is exactly the shape now excused, so the fixture had to move.)
  const obs = tree('obs-sigsame', { 'index.js': 'x', 'build/out.o': 'FULL-OBJECT-FILE' });
  const a = gate(obs, tree('arm-sigsame-a', { 'index.js': 'x', 'build/out.o': 'SHORT' }));
  const b = gate(obs, tree('arm-sigsame-b', { 'index.js': 'x', 'build/out.o': 'SHORT' }));
  assert.equal(a.code, 1, `the arm must still FAIL the gate — the digest is not a pass:\n${a.out}`);
  const sig = (o) => /shortfall=(\w+)/.exec(o)?.[1];
  assert.ok(sig(a.out), `line 1 must carry a shortfall digest:\n${a.out}`);
  assert.equal(sig(a.out), sig(b.out), 'two arms short by the same file at the same size must agree');
});

// The lmdb-store@2.0.0-alpha2 case, in miniature. A `.d` records the ABSOLUTE PATH of every header a
// compilation included, and node-gyp unpacks headers into a randomly-named temp directory — so the
// same successful build writes a different-LENGTH dep file every run. Comparing those sizes across
// arms declared the package INSUFFICIENT at every grant INCLUDING the empty one, while the arm had
// `rc=0`, all 182 artifacts, and a linked native addon.
test('a `.d` that is merely SHORTER does not fail — its size tracks header paths, not the build', () => {
  const obs = tree('obs-dshort', { 'index.js': 'x', 'build/out.o.d': 'DEPS-FROM-A-LONG-TMP-PATH' });
  const r = gate(obs, tree('arm-dshort', { 'index.js': 'x', 'build/out.o.d': 'DEPS-SHORTER' }));
  assert.equal(r.code, 0, `a shorter-but-present dep file must not be a shortfall:\n${r.out}`);
  assert.match(r.out, /missing=0 /, `and it must not be counted:\n${r.out}`);
});

// ⛔ The control that keeps the excusal honest. Without this, "skip `.d` size checks" would silently
// swallow the truncated-to-nothing shape the gate exists to catch — and no path-length difference can
// ever produce a zero-byte file, so excusing it would buy nothing and cost the signal.
test('⛔ a ZERO-BYTE `.d` still FAILS — emptiness is not a path-length artifact', () => {
  const obs = tree('obs-dempty', { 'index.js': 'x', 'build/out.o.d': 'REAL-DEPS' });
  const r = gate(obs, tree('arm-dempty', { 'index.js': 'x', 'build/out.o.d': '' }));
  assert.equal(r.code, 1, `an empty dep file against a non-empty reference must fail:\n${r.out}`);
  assert.match(r.out, /missing=1 /, `and be counted exactly once:\n${r.out}`);
});

test('⛔ a `.d` that is ABSENT still FAILS — the excusal is about size only, never presence', () => {
  const obs = tree('obs-dgone', { 'index.js': 'x', 'build/out.o.d': 'REAL-DEPS' });
  const r = gate(obs, tree('arm-dgone', { 'index.js': 'x' }));
  assert.equal(r.code, 1, `a missing dep file must still be a shortfall:\n${r.out}`);
});

test('⛔ two DIFFERENT single-file shortfalls digest differently — `missing=1` is not an identity', () => {
  // The measured `mozjpeg@6.0.1` hazard in miniature: a count-based comparison reads `missing=1` on
  // both arms and calls the shortfall invariant when it moved. Only the digest sees the difference.
  const obs = tree('obs-sigdiff', { 'a.bin': 'AAAA', 'b.bin': 'BBBB' });
  const a = gate(obs, tree('arm-sigdiff-a', { 'a.bin': 'AAAA' }));
  const b = gate(obs, tree('arm-sigdiff-b', { 'b.bin': 'BBBB' }));
  assert.match(a.out, /missing=1 /, `precondition: both arms must read missing=1:\n${a.out}`);
  assert.match(b.out, /missing=1 /, `precondition: both arms must read missing=1:\n${b.out}`);
  const sig = (o) => /shortfall=(\w+)/.exec(o)?.[1];
  assert.notEqual(sig(a.out), sig(b.out), 'a shortfall on a DIFFERENT file must not share an identity');
});

test('a passing arm reports `shortfall=none` rather than a digest of nothing', () => {
  const files = { 'index.js': 'x' };
  const r = gate(tree('obs-signone', files), tree('arm-signone', files));
  assert.equal(r.code, 0);
  assert.match(r.out, /shortfall=none/, `a clean arm must be distinguishable from a shortfall:\n${r.out}`);
});

test('an empty reference refuses to gate rather than reporting success', () => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'agate-obs-empty-'));
  const r = gate(obs, tree('arm-forempty', { 'index.js': 'x' }));
  assert.equal(r.code, 3, `no reference must be its own outcome, not a pass:\n${r.out}`);
  assert.match(r.out, /NO-REFERENCE/);
});
