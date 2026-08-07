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
  // ⛔ THE FIXTURE HAS NOW MOVED TWICE, FOR THE SAME REASON BOTH TIMES, SO IT HAS MOVED SOMEWHERE
  // STABLE. This test is about DIGEST STABILITY and needs a file whose size still carries signal.
  // It began as a `.o.d` — the real lmdb-store shape — which R4 then excused; it moved to a `build/`
  // `.o`, which R4 has now also excused (see the reversal below). Both times the fixture was a file
  // the gate had just stopped comparing, which makes the test vacuous rather than wrong.
  //
  // `build/Release/*.node` is the linked addon: the ONE file R4 states it must never excuse, at any
  // width. Anchoring here means a future exclusion cannot quietly hollow this test out without
  // failing the explicit truncated-addon controls first.
  const obs = tree('obs-sigsame', { 'index.js': 'x', 'build/Release/fixture.node': 'FULL-LINKED-ADDON' });
  const a = gate(obs, tree('arm-sigsame-a', { 'index.js': 'x', 'build/Release/fixture.node': 'SHORT' }));
  const b = gate(obs, tree('arm-sigsame-b', { 'index.js': 'x', 'build/Release/fixture.node': 'SHORT' }));
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

// ── R4 — toolchain-generated build files are excused from the SIZE comparison only ────────────────
//
// The `lmdb-store@2.0.0-alpha2` case: every arm from the synthesized grant up to `write:"disk"`
// reported `rc=0 artifacts=182/182` with the identical shortfall digest, and the package landed
// `ARTIFACT-GATE-SUSPECT` with its grant never descended. The two files responsible were
// `build/config.gypi` (18704B < 19199B) and `build/lmdb-store.target.mk` (5565B < 5939B) — node-gyp's
// record of WHO INVOKED IT and WHERE ITS HEADERS LIVED, neither of which says anything about whether
// the build worked. `build/Release/lmdb-store.node` was byte-identical at 429,328 B in both arms.
//
// ⛔ THE DANGEROUS DIRECTION FOR THIS GATE IS TOO WIDE, NOT TOO NARROW. The gate decides whether a
// REDUCED grant still installed, so excusing a file a denied write genuinely truncated lets a broken
// descent arm read as passing — and the catalog then publishes a grant SMALLER than the package
// needs. Every excusal below is therefore pinned in BOTH polarities, and the linked-output control is
// the one that must never be allowed to rot.

test('⛔ a TRUNCATED `build/Release/*.node` still FAILS — the exclusion must never reach the linked output', () => {
  // THE control for R4. The whole point of the artifact gate is to catch a build whose output never
  // materialised; if excusing toolchain files ever reached the linked addon, the gate would pass a
  // jailed arm that produced no working binary and the descent would publish an under-grant.
  const obs = tree('obs-node-trunc', {
    'build/config.gypi': 'THE-INVOKING-PM-CONFIG-SURFACE',
    'build/Release/lmdb.node': 'A'.repeat(4096),
  });
  const r = gate(obs, tree('arm-node-trunc', {
    'build/config.gypi': 'SHORTER-CONFIG',
    'build/Release/lmdb.node': 'A'.repeat(64),
  }));
  assert.equal(r.code, 1, `a truncated linked addon MUST fail the gate:\n${r.out}`);
  assert.match(r.out, /lmdb\.node \(64B < 4096B\)/, `the failure must name the addon and its shortfall:\n${r.out}`);
  assert.doesNotMatch(r.out, /config\.gypi/, `config.gypi must NOT be counted alongside it:\n${r.out}`);
});

test('the real lmdb-store shape passes: shorter toolchain files, identical addon', () => {
  // The acceptance case in miniature, with the measured sizes.
  const obs = tree('obs-lmdb', {
    'build/config.gypi': 'x'.repeat(19199),
    'build/lmdb-store.target.mk': 'x'.repeat(5939),
    'build/Makefile': 'x'.repeat(13934),
    'build/Release/.deps/Release/obj.target/src/misc.o.d': 'x'.repeat(1624),
    'build/Release/lmdb-store.node': 'x'.repeat(429328),
  });
  const r = gate(obs, tree('arm-lmdb', {
    'build/config.gypi': 'x'.repeat(18704),
    'build/lmdb-store.target.mk': 'x'.repeat(5565),
    'build/Makefile': 'x'.repeat(13847),
    'build/Release/.deps/Release/obj.target/src/misc.o.d': 'x'.repeat(1528),
    'build/Release/lmdb-store.node': 'x'.repeat(429328),
  }));
  assert.equal(r.code, 0, `the ARTIFACT-GATE-SUSPECT case must now pass:\n${r.out}`);
  assert.match(r.out, /missing=0 /, `and report a clean manifest:\n${r.out}`);
});

// ⛔ THE NESTED `.target.mk` IS THE ONE THE IMPLEMENTATION MISSED, AND IT IS NOT AN EDGE CASE.
// R4 names `*.target.mk`, but the pattern required the file DIRECTLY under `build/`. Any package
// that vendors a dependency emits its sub-targets at `build/deps/<lib>/<lib>.target.mk` — which is
// most real native builds — so they fell through and were size-compared.
//
// MEASURED on `cpu-features@0.0.10`, darwin-arm64: `rc=0`, all 156 artifacts PRESENT, and the arm
// scored UNDER-PREDICTED on three files that were merely smaller —
//     build/deps/cpu_features/cpu_features.target.mk  6315B < 6553B
//     build/gyp-mac-tool                             30502B < 30515B
//     build/Release/obj.target/cpufeatures/src/binding.o  314200B < 314288B
// `gyp-mac-tool` is emitted only by gyp's mac generator, which is why linux never surfaced it; a
// `.o` embeds the absolute path of every translation unit, so its size tracks path length exactly
// as a `.d` does. All three are gyp recording the invocation, not the package's output.
for (const f of ['build/config.gypi', 'build/lmdb-store.target.mk', 'build/Makefile',
  'build/deps/cpu_features/cpu_features.target.mk', 'build/gyp-mac-tool',
  'build/Release/obj.target/cpufeatures/src/binding.o']) {
  // Parametrised deliberately and narrowly: these three share ONE mechanism (a gyp-written record of
  // the invocation) and one rule, so asserting them separately would be three copies of one claim.
  // The per-file reasoning lives in `artifact-gate.mjs`; what varies here is only the path.
  test(`\`${f}\` that is merely SHORTER does not fail — it records the invocation, not the build`, () => {
    const obs = tree(`obs-tc-${f.replace(/\W/g, '')}`, { 'index.js': 'x', [f]: 'GENERATED-BY-NPM-INVOCATION' });
    const r = gate(obs, tree(`arm-tc-${f.replace(/\W/g, '')}`, { 'index.js': 'x', [f]: 'BY-NUB' }));
    assert.equal(r.code, 0, `a shorter toolchain record must not be a shortfall:\n${r.out}`);
    assert.match(r.out, /missing=0 /, `and must not be counted:\n${r.out}`);
  });

  test(`⛔ \`${f}\` that is ABSENT still FAILS — the excusal is about size only`, () => {
    const obs = tree(`obs-tcg-${f.replace(/\W/g, '')}`, { 'index.js': 'x', [f]: 'REAL' });
    const r = gate(obs, tree(`arm-tcg-${f.replace(/\W/g, '')}`, { 'index.js': 'x' }));
    assert.equal(r.code, 1, `a generator difference can change contents, never omit the file:\n${r.out}`);
  });

  test(`⛔ a ZERO-BYTE \`${f}\` still FAILS — emptiness is the download-blocked shape`, () => {
    const obs = tree(`obs-tce-${f.replace(/\W/g, '')}`, { 'index.js': 'x', [f]: 'REAL' });
    const r = gate(obs, tree(`arm-tce-${f.replace(/\W/g, '')}`, { 'index.js': 'x', [f]: '' }));
    assert.equal(r.code, 1, `an empty toolchain file against a non-empty reference must fail:\n${r.out}`);
    assert.match(r.out, /0B < \d+B/, `and report it as a size shortfall:\n${r.out}`);
  });
}

test('⛔ `build/binding.Makefile` is NOT excused — it was measured IDENTICAL, so nothing justifies it', () => {
  // The control that keeps the list honest. `binding.Makefile` sits beside the three files above and
  // looks exactly like them, but it measured 118 B in BOTH arms — so excusing it would be widening
  // the gate on resemblance rather than on evidence, and this gate under-grants when it is too wide.
  const obs = tree('obs-bmk', { 'index.js': 'x', 'build/binding.Makefile': 'REAL-CONTENTS' });
  const r = gate(obs, tree('arm-bmk', { 'index.js': 'x', 'build/binding.Makefile': 'SHORT' }));
  assert.equal(r.code, 1, `binding.Makefile must keep its size comparison:\n${r.out}`);
  assert.match(r.out, /binding\.Makefile/, `and be named in the shortfall:\n${r.out}`);
});

test('⛔ the excusal is scoped to `build/` — a `.d` shipped at the package root keeps its size check', () => {
  // `.d` is also the D-language source extension, and a `.d` outside `build/` was never written by
  // node-gyp. Scoping keeps a genuine source file's size comparison, which is signal.
  const obs = tree('obs-dscope', { 'index.js': 'x', 'src/mod.d': 'REAL-D-SOURCE-CONTENTS' });
  const r = gate(obs, tree('arm-dscope', { 'index.js': 'x', 'src/mod.d': 'TRUNC' }));
  assert.equal(r.code, 1, `only node-gyp's build/ output is excused, not every .d:\n${r.out}`);
});

// ⛔ REVERSED 2026-08-06, BY THE EVENT THE PREVIOUS RULE ASKED US TO WATCH FOR — recorded rather
// than quietly replaced, because the earlier decision was deliberate and correct on its evidence.
//
// This test used to assert the OPPOSITE: that an `.o` keeps its size comparison. Its reasoning was
// that on lmdb-store several `.o` files differed across arms (33240 vs 33400) from embedded paths,
// but "today they differ in the direction the gate ignores; that is a reason to WATCH them, not a
// reason to excuse them." That is exactly what happened. On `cpu-features@0.0.10`, darwin-arm64, an
// `.o` differed by 88 B in the direction the gate CATCHES — arm smaller than reference — on a build
// with `rc=0` and all 156 artifacts present. Same mechanism, opposite sign, and the outcome was a
// false `UNDER-PREDICTED`.
//
// So the excusal now covers `.o` SIZE, and the safety argument is structural rather than statistical:
// a denied write that truncated an object file fails the LINK, so `build/Release/*.node` is then
// ABSENT — and absence is checked for every file, toolchain-generated included. The two controls
// below are what keep that true, and they are the reason this is not a widening on resemblance.
test('⛔ a ZERO-BYTE `.o` still FAILS — the excusal covers shorter-by-path-length, never empty', () => {
  const obs = tree('obs-obj', { 'index.js': 'x', 'build/Release/obj.target/src/misc.o': 'X'.repeat(33400) });
  const r = gate(obs, tree('arm-obj', { 'index.js': 'x', 'build/Release/obj.target/src/misc.o': '' }));
  assert.equal(r.code, 1, `an empty object file is a real shortfall, not a path-length artifact:\n${r.out}`);
});

test('⛔ an ABSENT `.o` still FAILS — excusing size never excuses omission', () => {
  const obs = tree('obs-objabs', { 'index.js': 'x', 'build/Release/obj.target/src/misc.o': 'X'.repeat(33400) });
  const r = gate(obs, tree('arm-objabs', { 'index.js': 'x' }));
  assert.equal(r.code, 1, `a compile that never ran leaves no object file:\n${r.out}`);
});

test('⛔ the `.o` excusal is scoped to `build/` — an object shipped in the package keeps its check', () => {
  // Same scoping argument as `.d`: a prebuilt `.o` shipped in the tarball is a real artifact nobody
  // generated at install time, so its size is signal.
  const obs = tree('obs-objscope', { 'index.js': 'x', 'vendor/prebuilt.o': 'REAL-SHIPPED-OBJECT' });
  const r = gate(obs, tree('arm-objscope', { 'index.js': 'x', 'vendor/prebuilt.o': 'TRUNC' }));
  assert.equal(r.code, 1, `only node-gyp's build/ output is excused, not every .o:\n${r.out}`);
});

test('an empty reference refuses to gate rather than reporting success', () => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'agate-obs-empty-'));
  const r = gate(obs, tree('arm-forempty', { 'index.js': 'x' }));
  assert.equal(r.code, 3, `no reference must be its own outcome, not a pass:\n${r.out}`);
  assert.match(r.out, /NO-REFERENCE/);
});

// ⛔ THE WIDENED EXCLUSION MUST NOT REACH THE LINKED OUTPUT — the constraint R4 states on itself.
// Broadening `.target.mk` to any depth and admitting `.o` moves the boundary closer to
// `build/Release/*.node`, so the guard against it is re-asserted against the WIDENED list rather
// than assumed to still hold from the narrower one. Without this, a regexp that accidentally
// matched `build/Release/foo.node` would pass every other test in this file.
test('⛔ a truncated addon still FAILS alongside the newly-excused nested and object files', () => {
  const obs = tree('obs-r4wide', {
    'index.js': 'x',
    'build/deps/cpu_features/cpu_features.target.mk': 'x'.repeat(6553),
    'build/gyp-mac-tool': 'x'.repeat(30515),
    'build/Release/obj.target/cpufeatures/src/binding.o': 'x'.repeat(314288),
    'build/Release/cpufeatures.node': 'x'.repeat(4096),
  });
  const r = gate(obs, tree('arm-r4wide', {
    'index.js': 'x',
    'build/deps/cpu_features/cpu_features.target.mk': 'x'.repeat(6315),
    'build/gyp-mac-tool': 'x'.repeat(30502),
    'build/Release/obj.target/cpufeatures/src/binding.o': 'x'.repeat(314200),
    'build/Release/cpufeatures.node': 'x'.repeat(64),
  }));
  assert.equal(r.code, 1, `the addon shortfall must still gate:\n${r.out}`);
  assert.match(r.out, /cpufeatures\.node \(64B < 4096B\)/, `and must name it:\n${r.out}`);
  assert.match(r.out, /missing=1 /, `EXACTLY one — the three excused files must not be counted:\n${r.out}`);
});

// ⛔ A ZERO-BYTE OBJECT FILE IS NOT A PATH-LENGTH ARTIFACT. `.o` size tracks embedded paths, which
// can only ever make it shorter by a few dozen bytes; emptiness is the truncated/denied-write shape
// and must still fail. Same reasoning as the `.d` case above, re-asserted because `.o` is newly
// excused and an exclusion that swallowed a zero-byte file would hide exactly what the gate is for.
test('⛔ a ZERO-BYTE `.o` still FAILS — the excusal covers shorter, never empty', () => {
  const obs = tree('obs-r4zero', {
    'index.js': 'x',
    'build/Release/obj.target/cpufeatures/src/binding.o': 'x'.repeat(314288),
  });
  const r = gate(obs, tree('arm-r4zero', {
    'index.js': 'x',
    'build/Release/obj.target/cpufeatures/src/binding.o': '',
  }));
  assert.equal(r.code, 1, `an empty object file is a real shortfall:\n${r.out}`);
});
