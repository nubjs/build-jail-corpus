// ⛔⛔ `npm rebuild <BARE SCOPED NAME>` MATCHES NOTHING ON npm 6. It exits 0, prints nothing, and
// runs no script — so the observe arm traces a process that did nothing and the harness reads the
// resulting empty syscall set as a measurement of "this package needs no permissions".
//
// MEASURED 2026-08-31 against npm 6.14.12 on the era-dated tree the arm itself builds:
//
//   npm rebuild @sitespeed.io/edgedriver             -> rc=0, npm.log 0 bytes, install.js did NOT run
//   npm rebuild @sitespeed.io/edgedriver@86.0.622-69 -> rc=1, npm.log 1320 bytes, install.js RAN
//
// 3/3 on scoped registry packages; absent on unscoped ones (`bigint-buffer`, `ico-endec` — bare and
// versioned byte-identical); absent on npm 3.10.10 and npm 8.19.4, which both run the script from
// the bare scoped name. So it is npm 6 only, which is why the corpus zero-attribution rate is 13.0%
// on era npm 6 against 3.4% on npm 10 and 0.2% on npm 11 — numbers previously read as "modern npm
// stopped running scripts", which is this bug seen from the wrong end.
//
// These tests EXECUTE each driver's own derivation rather than asserting on its text, and they
// control BOTH directions: a scoped subject must produce a versioned spec, and an unreadable
// manifest must fall back to the bare name rather than to no argument at all — dropping the
// argument would rebuild the whole dependency tree and attribute its scripts to the subject.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const POSIX = ['measure.sh', 'measure-macos.sh'];

/** An observe tree holding `pkg` at `version`; `version: null` writes a manifest with no version. */
const observeTree = (pkg, version) => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'rebuild-spec-'));
  if (pkg) {
    const dir = path.join(obs, 'node_modules', ...pkg.split('/'));
    fs.mkdirSync(dir, { recursive: true });
    const manifest = { name: pkg, ...(version === null ? {} : { version }) };
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
  }
  return obs;
};

// ⛔ BOUND BY THE CODE, NOT BY A FIXED WIDTH. A 1,600-character window in a sibling test broke the
// moment a comment was added inside the branch it sliced, and every assertion then failed for a
// reason that had nothing to do with behaviour. Anchor on the first and last line of the block.
const derivation = (driver) => {
  const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
  const start = src.indexOf('REBUILD_VER=$(node -e ');
  assert.notEqual(start, -1, `${driver}: the rebuild-spec derivation is gone`);
  const marker = 'echo "  ARM-REBUILD-SPEC $REBUILD_SPEC"';
  const end = src.indexOf(marker, start);
  assert.notEqual(end, -1, `${driver}: the derivation does not reach its ARM-REBUILD-SPEC echo`);
  return src.slice(start, end + marker.length);
};

const runPosix = (driver, { obs, pkg }) => execFileSync('bash', ['-c',
  `set -u\nOBS=${JSON.stringify(obs)}\nPKG=${JSON.stringify(pkg)}\n${derivation(driver)}\n`,
], { encoding: 'utf8' }).trim();

for (const driver of POSIX) {
  test(`⭑ ${driver}: a scoped subject rebuilds by NAME@VERSION, which is the whole fix`, () => {
    const obs = observeTree('@x/scoped', '1.2.3');
    assert.equal(runPosix(driver, { obs, pkg: '@x/scoped' }), 'ARM-REBUILD-SPEC @x/scoped@1.2.3');
  });

  test(`⭑ ${driver}: an unscoped subject gets the same versioned spec — safe, and byte-identical in npm`, () => {
    const obs = observeTree('plain-pkg', '2.0.0');
    assert.equal(runPosix(driver, { obs, pkg: 'plain-pkg' }), 'ARM-REBUILD-SPEC plain-pkg@2.0.0');
  });

  test(`⭑ CONTROL ${driver}: the version comes from the INSTALLED manifest, not from what was asked for`, () => {
    // Resolution landing elsewhere than `$VER` is exactly the case where a hardcoded `$PKG@$VER`
    // would match nothing and reintroduce this bug pointing the other way.
    const obs = observeTree('@x/scoped', '9.9.9-actually-installed');
    assert.equal(runPosix(driver, { obs, pkg: '@x/scoped' }),
      'ARM-REBUILD-SPEC @x/scoped@9.9.9-actually-installed');
  });

  test(`⭑ CONTROL ${driver}: an absent subject falls back to the BARE NAME, never to no argument`, () => {
    const obs = observeTree(null, null);
    assert.equal(runPosix(driver, { obs, pkg: '@x/scoped' }), 'ARM-REBUILD-SPEC @x/scoped');
  });

  test(`⭑ CONTROL ${driver}: a manifest with no version field also falls back to the bare name`, () => {
    const obs = observeTree('@x/scoped', null);
    assert.equal(runPosix(driver, { obs, pkg: '@x/scoped' }), 'ARM-REBUILD-SPEC @x/scoped');
  });

  test(`⭑ ${driver}: the traced rebuild CONSUMES the derived spec — a reverted call site fails here`, () => {
    const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
    assert.match(src, /npm rebuild --no-audit --no-fund "\$REBUILD_SPEC" > "\$OBS\/npm\.log"/,
      `${driver}: the observe arm no longer passes the derived spec`);
    assert.doesNotMatch(src, /npm rebuild --no-audit --no-fund "\$PKG" > "\$OBS\/npm\.log"/,
      `${driver}: the observe arm is back on the bare name`);
  });
}

test('⭑ measure-windows.mjs: the derivation runs and yields NAME@VERSION from the installed manifest', () => {
  const src = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  const start = src.indexOf('const rebuildDir = pkgDir(OBS, PKG, VER);');
  assert.notEqual(start, -1, 'measure-windows.mjs: the rebuild-spec derivation is gone');
  const marker = 'console.log(`  ARM-REBUILD-SPEC ${rebuildSpec}`);';
  const end = src.indexOf(marker, start);
  assert.notEqual(end, -1, 'measure-windows.mjs: the derivation does not reach its ARM-REBUILD-SPEC log');
  const region = src.slice(start, end + marker.length);

  const obs = observeTree('@x/scoped', '4.5.6');
  const out = [];
  const fn = new Function('fs', 'path', 'pkgDir', 'OBS', 'PKG', 'VER', 'console',
    `${region}\nreturn rebuildSpec;`);
  const spec = fn(fs, path, (base, pkg) => path.join(base, 'node_modules', ...pkg.split('/')),
    obs, '@x/scoped', '4.5.6', { log: (m) => out.push(m) });
  assert.equal(spec, '@x/scoped@4.5.6');
  assert.deepEqual(out, ['  ARM-REBUILD-SPEC @x/scoped@4.5.6']);
});

test('⭑ CONTROL measure-windows.mjs: pkgDir finding nothing falls back to the bare name', () => {
  const src = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  const start = src.indexOf('const rebuildDir = pkgDir(OBS, PKG, VER);');
  const marker = 'console.log(`  ARM-REBUILD-SPEC ${rebuildSpec}`);';
  const region = src.slice(start, src.indexOf(marker, start) + marker.length);
  const fn = new Function('fs', 'path', 'pkgDir', 'OBS', 'PKG', 'VER', 'console',
    `${region}\nreturn rebuildSpec;`);
  assert.equal(fn(fs, path, () => null, '/nowhere', '@x/scoped', '4.5.6', { log() {} }), '@x/scoped');
});

test('⭑ measure-windows.mjs: the rebuild.cmd wrapper CONSUMES the derived spec', () => {
  const src = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(src, /rebuild --no-audit --no-fund \$\{rebuildSpec\}/,
    'measure-windows.mjs: the wrapper no longer passes the derived spec');
  assert.doesNotMatch(src, /rebuild --no-audit --no-fund \$\{PKG\}/,
    'measure-windows.mjs: the wrapper is back on the bare name');
});
