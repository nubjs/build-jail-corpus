// The single entry point the three drivers share. The last test is the one that matters most —
// `dep-scaffold.mjs` records TWO occasions when a v2 fix landed in one driver and was mistaken for
// done, so the cross-driver guard is what makes "wired" mean wired.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { prepareArm, installedManifest } from './arm-prepare.mjs';

const HERE = import.meta.dirname;

/** A throwaway observe tree holding one installed package. */
function tree(pkg, manifest) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'armprep-'));
  const dir = path.join(d, 'node_modules', ...pkg.split('/'));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
  return d;
}

test('reads the installed manifest, including a scoped name', () => {
  const d = tree('@antv/dom-util', { name: '@antv/dom-util', version: '2.0.0' });
  assert.equal(installedManifest(d, '@antv/dom-util').version, '2.0.0');
});

test('sanitises the PATH, probes it, and scaffolds from what is left', () => {
  const d = tree('p', { scripts: { postinstall: 'husky install' }, devDependencies: { husky: '^5.0.9' } });
  // ⛔ `path.delimiter`, NOT A LITERAL COLON. Windows separates PATH entries with `;`, so a
  // hardcoded `/usr/bin:/home/u/.bun/bin` arrives there as ONE entry and nothing is dropped. This
  // test failed on windows-latest for exactly that reason and, because the corpus runner gates on
  // the whole suite, it blocked every Windows measurement — a POSIX-shaped fixture holding up the
  // one platform it says nothing about.
  const ambient = ['/usr/bin', '/home/u/.bun/bin'].join(path.delimiter);
  const r = prepareArm({ observeDir: d, pkg: 'p', eraBin: '/era/bin',
                         ambient, resolve: () => null });
  assert.deepEqual(r.dropped, ['/home/u/.bun/bin']);
  assert.ok(r.armPath.startsWith(path.join(d, 'node_modules', '.bin')), 'the fixture bin leads');
  assert.deepEqual(r.scaffold.install, ['husky@^5.0.9']);
});

test('a LEAKED tool suppresses its scaffold entry — and is still named in the record', () => {
  // ⛔ THE ORDERING INVARIANT. If the scaffold ran against the unsanitised PATH the leak would hide
  // itself; here it is visible AND it stops a redundant install.
  const d = tree('p', { scripts: { postinstall: 'husky install' }, devDependencies: { husky: '^5.0.9' } });
  const r = prepareArm({ observeDir: d, pkg: 'p', ambient: '/usr/local/bin',
                         resolve: (n) => (n === 'husky' ? '/usr/local/bin/husky' : null) });
  assert.deepEqual(r.scaffold.install, [], 'already reachable');
  assert.deepEqual(r.ambientTools, { husky: '/usr/local/bin/husky' });
  assert.ok(r.markers.some((m) => m.includes('husky=/usr/local/bin/husky')), 'the record must say it leaked');
});

test('a fetch that did not land the package says so instead of silently scaffolding nothing', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'armprep-empty-'));
  const r = prepareArm({ observeDir: d, pkg: 'missing', ambient: '/usr/bin', resolve: () => null });
  assert.match(r.scaffold.note, /manifest absent/);
});

test('every marker is a single line, because driver.out is parsed line-wise', () => {
  const d = tree('p', { scripts: { postinstall: 'pulumi up' } });
  const r = prepareArm({ observeDir: d, pkg: 'p', ambient: '/usr/bin', resolve: () => null });
  for (const m of r.markers) assert.ok(!m.includes('\n'), `multi-line marker: ${m}`);
  assert.ok(r.markers.some((m) => m.startsWith('ARM-UNPROVIDABLE') && m.includes('pulumi')));
});

// ⛔ THE PARITY LIST IS EXTENDED HERE RATHER THAN RE-INVENTED PER MODULE, because the failure it
// guards is not about any one module: it is that this harness has now shipped THREE fixes into one
// driver and called them landed. Each entry names a shared module and what a driver missing it does
// WRONG — a bare "does not call X" says nothing to whoever reads the failure.
const SHARED_BY_ALL_DRIVERS = [
  ['arm-prepare', 'prepares the arm PATH, its leaked tools and its script scaffold'],
  ['dep-scaffold', "grants script-bearing DEPENDENCIES a fixed wide scaffold, so a dependency's "
    + "denial is not recorded as the target's verdict"],
  ['target-catalogued', "asserts the package under test is IN the arm's catalog; without it an "
    + 'uncatalogued target runs at the baseline, where egress is permitted, and a narrow rung is '
    + 'scored SUFFICIENT — an under-grant'],
  ['net-enforcement', 'records whether any falsification control proved a denied network is '
    + 'observable in this venue; without it a record cannot say the axis went unattested'],
  ['instrument-selfcheck', 'refuses to measure from a harness tree that disagrees with itself '
    + 'about its epoch'],
  ['never-spawned', 'treats a lifecycle script that never LAUNCHED as VOID rather than as a pass'],
];

test('⛔ EVERY SHARED MODULE IS WIRED INTO ALL THREE DRIVERS', () => {
  const missing = [];
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    for (const [mod, why] of SHARED_BY_ALL_DRIVERS) {
      if (!src.includes(mod)) missing.push(`${d} does not use ${mod}.mjs — it ${why}`);
    }
  }
  assert.deepEqual(missing, [], `\n  ${missing.join('\n  ')}\n`);
});

test('CONTROL: the parity scan can actually fail', () => {
  // ⛔ The scan above is a substring search over three files, which is exactly the shape that reports
  // everything clean when the file list or the read is wrong. Two ways it could pass vacuously: a
  // module name that matches nothing real (a typo in the list), and a search string so generic that
  // every driver contains it by accident.
  for (const [mod] of SHARED_BY_ALL_DRIVERS) {
    assert.ok(fs.existsSync(path.join(HERE, `${mod}.mjs`)),
      `${mod}.mjs is listed as shared but does not exist — the scan would pass on a typo`);
  }
  const src = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');
  assert.ok(!src.includes('a-module-that-was-never-written'),
    'the known-absent control string is present, so a green scan proves nothing');
});

test('⛔ ALL THREE DRIVERS CONSUME IT — the guard that makes landed mean landed', () => {
  // Two shell drivers and one JS driver cannot share a function, so this asserts they share the
  // PROCESS. A fix wired into one driver and mistaken for done has happened twice in this harness.
  const drivers = ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs'];
  for (const d of drivers) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('arm-prepare.mjs'), `${d} does not call arm-prepare.mjs — the fix is not landed there`);
  }
});
