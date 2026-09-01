// Golden cases for `gyp-subtarget-spill.mjs` — the arithmetic that says where gyp put an included
// `.gyp` file's makefiles in THIS layout.
//
// ⛔ THIS MODULE ONLY EVER ADDS KEYS TO A MANIFEST, so its failure mode is not "the gate fails" but
// "the gate passes something it should have failed". Every case that makes a key appear is therefore
// paired with one that must NOT: a phantom that is not there, a file that is not a gyp sub-target,
// and the dependency's own real directory, which must never be mistaken for the phantom.
//
// The two fixtures below are the MEASURED layouts, not invented ones. `node-pty@1.1.0` +
// `node-addon-api@7.1.1` under `node-gyp configure`, darwin-arm64:
//
//   npm   node_modules/node-pty/node-addon-api/node_addon_api.target.mk
//   nub   <store>/node-pty@1.1.0-0ce22dabcaf0849e/node-addon-api@7.1.1-213592cd5b5ab75e/
//           node_modules/node-addon-api/node_addon_api.target.mk
//
// and the relative path node-addon-api hands gyp in each — `../node-addon-api` versus
// `../../../node-addon-api@7.1.1-213592cd5b5ab75e/node_modules/node-addon-api` — is reproduced here
// exactly, because it is the input the whole computation turns on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gypSubtargetSpill, isGypSubtargetFile } from './gyp-subtarget-spill.mjs';

const PKG = 'node-pty';
const DEP = 'node-addon-api';
const SUBTARGETS = ['node_addon_api.Makefile', 'node_addon_api.target.mk',
  'node_addon_api_except.target.mk', 'node_addon_api_maybe.target.mk'];

const write = (p, body) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); };

/**
 * npm's flat hoisted OBSERVE tree. The phantom lands INSIDE the package, which is exactly why the
 * reference manifest carries `node-addon-api/<file>` and why this module must find nothing here.
 */
const flat = (label, spill = SUBTARGETS) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `spill-flat-${label}-`));
  const root = path.join(base, 'node_modules', PKG);
  write(path.join(root, 'package.json'), '{}');
  write(path.join(base, 'node_modules', DEP, 'index.js'), 'x');
  for (const f of spill) write(path.join(root, DEP, f), `# ${f}\n`);
  return root;
};

/**
 * nub's isolated store: the package's own `node_modules` holds a SYMLINK to the dependency's own
 * store entry, so the dependency's realpath is three levels up and one slug over.
 */
const isolated = (label, { spill = SUBTARGETS, spillUnder = '', extra = {} } = {}) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), `spill-iso-${label}-`));
  const store = path.join(base, 'node_modules', '.store');
  const own = path.join(store, `${PKG}@1.1.0`, 'node_modules');
  const depReal = path.join(store, `${DEP}@7.1.1-213592cd5b5ab75e`, 'node_modules', DEP);
  write(path.join(own, PKG, 'package.json'), '{}');
  write(path.join(depReal, 'index.js'), 'x');
  fs.symlinkSync(path.relative(own, depReal), path.join(own, DEP));
  const phantom = path.join(store, `${PKG}@1.1.0`, `${DEP}@7.1.1-213592cd5b5ab75e`, 'node_modules', DEP, spillUnder);
  for (const f of spill) write(path.join(phantom, f), `# ${f} (jailed arm)\n`);
  for (const [rel, body] of Object.entries(extra)) write(path.join(phantom, rel), body);
  return { root: path.join(own, PKG), phantom, depReal };
};

test('the measured isolated-store layout: the spill is found, keyed by dependency name', () => {
  const { root } = isolated('found');
  const m = gypSubtargetSpill(root, PKG);
  assert.deepEqual([...m.keys()].sort(), SUBTARGETS.map((f) => `${DEP}/${f}`).sort(),
    'the four measured sub-target files must key exactly as npm\'s flat layout keys them');
  for (const [, size] of m) assert.ok(size > 0, 'a key must carry the size the gate compares against');
});

test('⛔ npm\'s flat layout yields NOTHING — its phantom is inside the package and already walked', () => {
  const m = gypSubtargetSpill(flat('noop'), PKG);
  assert.equal(m.size, 0,
    `the reference arm must be untouched, or this module would ADD reference keys the arm must match:\n${[...m.keys()]}`);
});

test('the node-addon-api 8.x shape keys through `src/` — 58 of the 243 archived sightings', () => {
  const { root } = isolated('srcshape', { spillUnder: 'src' });
  assert.deepEqual([...gypSubtargetSpill(root, PKG).keys()].sort(),
    SUBTARGETS.map((f) => `${DEP}/src/${f}`).sort());
});

test('⛔ a file that is not a gyp sub-target is NOT indexed, however it got into the phantom', () => {
  const { root } = isolated('narrow', { extra: { 'README.md': 'x', 'node_addon_api.node': 'BINARY' } });
  const keys = [...gypSubtargetSpill(root, PKG).keys()];
  assert.equal(keys.length, SUBTARGETS.length, `only the sub-target makefiles may be indexed:\n${keys}`);
  assert.ok(!keys.some((k) => /README|\.node$/.test(k)), `indexed something that is not a sub-target:\n${keys}`);
});

test('⛔ a build that spilled nothing produces no keys — the module invents no artifact', () => {
  const { root } = isolated('empty', { spill: [] });
  assert.equal(gypSubtargetSpill(root, PKG).size, 0);
});

test('⛔ CONTROL: the dependency\'s REAL directory is never indexed as the phantom', () => {
  // A `.Makefile` that SHIPS in the dependency's tarball must not be able to satisfy a reference key
  // the build never wrote. The arithmetic already puts the phantom one level shallower than the
  // dependency, so this asserts the guard that keeps it that way.
  const { root, depReal, phantom } = isolated('realdir', { spill: [] });
  assert.notEqual(path.resolve(phantom), path.resolve(depReal), 'fixture is wrong if these coincide');
  write(path.join(depReal, 'node_addon_api.Makefile'), '# shipped in the tarball\n');
  assert.equal(gypSubtargetSpill(root, PKG).size, 0,
    'a shipped makefile in the dependency itself must not enter the arm manifest');
});

test('a scoped dependency keys under its full name, scope included', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'spill-scoped-'));
  const store = path.join(base, 'node_modules', '.store');
  const own = path.join(store, 'consumer@1.0.0', 'node_modules');
  const depReal = path.join(store, '@scope+addon@2.0.0-abc', 'node_modules', '@scope', 'addon');
  write(path.join(own, 'consumer', 'package.json'), '{}');
  write(path.join(depReal, 'index.js'), 'x');
  fs.mkdirSync(path.join(own, '@scope'), { recursive: true });
  fs.symlinkSync(path.relative(path.join(own, '@scope'), depReal), path.join(own, '@scope', 'addon'));
  const root = path.join(own, 'consumer');
  const rel = path.relative(fs.realpathSync(root), fs.realpathSync(depReal)).split(path.sep);
  write(path.join(path.resolve(fs.realpathSync(root), rel.slice(1).join(path.sep)), 'addon.target.mk'), '# x\n');
  assert.deepEqual([...gypSubtargetSpill(root, 'consumer').keys()], ['@scope/addon/addon.target.mk']);
});

test('the sub-target predicate is the two files gyp\'s make generator emits, and nothing adjacent', () => {
  for (const f of ['node_addon_api.target.mk', 'pty.target.mk', 'node_addon_api.Makefile', 'binding.Makefile'])
    assert.ok(isGypSubtargetFile(f), `${f} must be recognised`);
  for (const f of ['Makefile', 'config.gypi', 'index.js', 'foo.mk', 'foo.o.d'])
    assert.ok(!isGypSubtargetFile(f), `${f} must NOT be recognised`);
});

test('⛔ the REAL nub shape: the package is reached through a symlink, and `..` must follow it first', () => {
  // ⛔ THE CASE EVERY SYNTHETIC FIXTURE ABOVE MISSES, AND IT MISSED IT ONCE FOR REAL. `pkgDir`
  // resolves a nub tree to `<project>/node_modules/<pkg>`, a SYMLINK into the store. `..` from the
  // LINK is the project's own `node_modules`, which holds the project's direct dependencies and not
  // `node-addon-api` — so a version of this module that skipped the realpath returned zero keys
  // against a live `nub install node-pty@1.1.0` while reporting four against the fixtures.
  const { root: storeRoot } = isolated('reallink');
  const project = fs.mkdtempSync(path.join(os.tmpdir(), 'spill-project-'));
  fs.mkdirSync(path.join(project, 'node_modules', '.store'), { recursive: true });
  // `<project>/node_modules/<pkg>` -> `.store/<pkg>@<ver>/node_modules/<pkg>`, exactly as aube links it.
  fs.symlinkSync(path.resolve(storeRoot, '..', '..'), path.join(project, 'node_modules', '.store', `${PKG}@1.1.0`));
  fs.symlinkSync(path.join('.store', `${PKG}@1.1.0`, 'node_modules', PKG), path.join(project, 'node_modules', PKG));
  const viaLink = path.join(project, 'node_modules', PKG);
  assert.deepEqual([...gypSubtargetSpill(viaLink, PKG).keys()].sort(), SUBTARGETS.map((f) => `${DEP}/${f}`).sort(),
    'reached through the project symlink, the spill must still be found');
});
