// Golden cases for `gypSubtargetRelocations` — the half of the gyp sub-target spill that stays
// INSIDE `build/` and therefore cannot be keyed from the arm alone.
//
// ⛔ THE FIXTURES ARE THE MEASURED PATHS, NOT INVENTED ONES. `drivelist@12.0.2` +
// `node-addon-api@8.9.2`, `node-gyp@11 rebuild`, in a real `npm install` tree and a real
// `nub install` store tree:
//
//   reference (npm, flat)                                              arm (nub, isolated store)
//   node-addon-api/nothing.target.mk                                   2 levels ABOVE the package root
//   build/Release/obj.target/node-addon-api/nothing.o                  build/<slug>/node_modules/node-addon-api/nothing.o
//   build/Release/.deps/Release/obj.target/node-addon-api/nothing.o.d  build/Release/.deps/<slug>/node_modules/node-addon-api/nothing.o.d
//   build/Release/node-addon-api/nothing.a       (linux shape)         <slug>/node_modules/node-addon-api/nothing.a
//
// Every one of those is the SAME Δk = 2, applied to a different fixed prefix — which is the whole
// claim this file exists to pin.
//
// ⛔ THE FAILURE MODE IS "THE GATE PASSES SOMETHING IT SHOULD HAVE FAILED", so every case that makes
// a key resolve is paired with one that must not: a sub-target genuinely absent from an otherwise
// populated spill directory, a relocated file that is present but EMPTY, and a reference layout that
// ate nothing, whose keys must never be satisfied by a file that merely SHIPS in the dependency.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gypSubtargetRelocations } from './gyp-subtarget-spill.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const GATE = path.join(HERE, 'artifact-gate.mjs');
const PKG = 'drivelist';
const VER = '12.0.2';
const DEP = 'node-addon-api';
const SLUG = `${DEP}@8.9.2-c7cd573b7f3b7e92`;
/** The arm's descent: what survives after the `..` run is consumed. */
const S = `${SLUG}/node_modules/${DEP}`;

const OBJ = 'nothing.o placeholder\n';
const DEPD = 'nothing.o.d placeholder\n';
const LIB = 'nothing.a placeholder\n';
const MK = 'nothing.target.mk placeholder\n';
const NODE = 'drivelist.node placeholder\n';

const write = (p, body) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); };

/** npm's flat hoisted OBSERVE tree, at the four measured reference keys. */
const flat = (label) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `reloc-flat-${label}-`));
  const root = path.join(base, 'node_modules', PKG);
  write(path.join(root, 'package.json'), '{}');
  write(path.join(base, 'node_modules', DEP, 'index.js'), 'x');
  write(path.join(root, 'build', 'Release', 'drivelist.node'), NODE);
  write(path.join(root, 'build', 'Release', 'obj.target', DEP, 'nothing.o'), OBJ);
  write(path.join(root, 'build', 'Release', '.deps', 'Release', 'obj.target', DEP, 'nothing.o.d'), DEPD);
  write(path.join(root, 'build', 'Release', DEP, 'nothing.a'), LIB);
  write(path.join(root, DEP, 'nothing.target.mk'), MK);
  return base;
};

/**
 * nub's isolated store, with the project-level entry left as a SYMLINK on purpose — the walk has to
 * start from the realpath or the dependency is not a sibling and nothing resolves.
 */
const isolated = (label, { obj = OBJ, omit = [] } = {}) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `reloc-iso-${label}-`));
  const store = path.join(base, 'node_modules', '.store');
  const entry = path.join(store, `${PKG}@${VER}`);
  const own = path.join(entry, 'node_modules');
  const root = path.join(own, PKG);
  const depReal = path.join(store, SLUG, 'node_modules', DEP);
  write(path.join(root, 'package.json'), '{}');
  write(path.join(depReal, 'index.js'), 'x');
  fs.symlinkSync(path.relative(own, depReal), path.join(own, DEP));
  fs.symlinkSync(path.join('.store', `${PKG}@${VER}`, 'node_modules', PKG), path.join(base, 'node_modules', PKG));
  write(path.join(root, 'build', 'Release', 'drivelist.node'), NODE);
  const spills = {
    obj: [path.join(root, 'build', S, 'nothing.o'), obj],
    dep: [path.join(root, 'build', 'Release', '.deps', S, 'nothing.o.d'), DEPD],
    lib: [path.join(root, S, 'nothing.a'), LIB],
    mk: [path.join(entry, S, 'nothing.target.mk'), MK],
  };
  for (const [k, [p, body]] of Object.entries(spills)) if (!omit.includes(k)) write(p, body);
  return { base, root, depReal };
};

/** Run the real gate CLI. Never throws, so a failing gate is data rather than an error. */
const gate = (obs, arm) => {
  try {
    return { code: 0, out: execFileSync(process.execPath,
      [GATE, '--obs', obs, '--arm', arm, '--pkg', PKG, '--ver', VER], { encoding: 'utf8' }) };
  } catch (e) { return { code: e.status, out: `${e.stdout ?? ''}${e.stderr ?? ''}` }; }
};

test('all four measured spill kinds resolve, through the project symlink, at one Δk', () => {
  const { code, out } = gate(flat('all'), isolated('all').base);
  assert.equal(code, 0, `the arm produced every artifact; the gate must pass it:\n${out}`);
  assert.match(out, /missing=0 shortfall=none/, out);
});

test('⛔ a sub-target ABSENT from an otherwise populated spill directory still FAILS, and is NAMED', () => {
  const { code, out } = gate(flat('gap'), isolated('gap', { omit: ['obj'] }).base);
  assert.equal(code, 1, `an absent build output must never be resolved away:\n${out}`);
  assert.match(out, /missing=1 /, out);
  assert.match(out, /build\/Release\/obj\.target\/node-addon-api\/nothing\.o/,
    `the reference key must be named so the failure is self-debugging:\n${out}`);
});

test('⛔ a relocated sub-target that is present but ZERO BYTES still fails on size', () => {
  const { code, out } = gate(flat('empty'), isolated('empty', { obj: '' }).base);
  assert.equal(code, 1, `an empty object file is the truncated-write shape the gate exists to catch:\n${out}`);
  assert.match(out, /build\/Release\/obj\.target\/node-addon-api\/nothing\.o \(0B < \d+B\)/, out);
});

test('⛔ npm-shaped arm: the pass does not fire, and a real gap in one still fails', () => {
  const ref = flat('flatref');
  assert.equal(gate(ref, flat('flatarm')).code, 0, 'two flat trees agree and nothing relocates');
  const armBase = flat('flatgap');
  fs.rmSync(path.join(armBase, 'node_modules', PKG, 'build', 'Release', 'obj.target', DEP, 'nothing.o'));
  const { code, out } = gate(ref, armBase);
  assert.equal(code, 1, `a flat arm missing a real artifact must still fail:\n${out}`);
  assert.match(out, /build\/Release\/obj\.target\/node-addon-api\/nothing\.o/, out);
});

test('⛔ a dependency linked INTO the package is never satisfied by a file that merely SHIPS in it', () => {
  // The reference tree resolves `node-addon-api` to a directory INSIDE the measured package — the
  // shape an npm `file:`/workspace link produces — so the reference ate no `..` at all and the arm's
  // Δk lands the computation exactly on the dependency's own real directory. `nothing.target.mk`
  // sits there in both trees because it SHIPS, untouched by any build. Removing the `depReal` guard
  // makes the gate accept it as the arm's output.
  const obsBase = fs.mkdtempSync(path.join(os.tmpdir(), 'reloc-linked-'));
  const obsRoot = path.join(obsBase, 'node_modules', PKG);
  write(path.join(obsRoot, 'package.json'), '{}');
  write(path.join(obsRoot, 'vendored', DEP, 'nothing.target.mk'), MK);
  fs.symlinkSync(path.join(PKG, 'vendored', DEP), path.join(obsBase, 'node_modules', DEP));
  const { base: armBase, depReal } = isolated('linked', { omit: ['obj', 'dep', 'lib', 'mk'] });
  write(path.join(depReal, 'nothing.target.mk'), MK);

  const { code, out } = gate(obsBase, armBase);
  assert.equal(code, 1, `the arm wrote no sub-target; a shipped file must not stand in for one:\n${out}`);
  assert.match(out, /vendored\/node-addon-api\/nothing\.target\.mk/,
    `the unresolved key must stay missing and stay NAMED:\n${out}`);
});
