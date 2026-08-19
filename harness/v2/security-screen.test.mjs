import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const shellTest = (name, fn) => test(name, { skip: process.platform === 'win32' }, fn);

const here = import.meta.dirname;
const drivers = {
  linux: fs.readFileSync(path.join(here, 'measure.sh'), 'utf8'),
  macos: fs.readFileSync(path.join(here, 'measure-macos.sh'), 'utf8'),
  windows: fs.readFileSync(path.join(here, 'measure-windows.mjs'), 'utf8'),
};

const inOrder = (source, needles, label) => {
  let at = -1;
  for (const needle of needles) {
    const next = source.indexOf(needle, at + 1);
    assert.ok(next > at, `${label}: ${JSON.stringify(needle)} is absent or out of order`);
    at = next;
  }
};

test('every driver screens direct before fetch and the fetched tree before npm rebuild', () => {
  // ⛔ THE INVARIANT IS THE ORDER, NOT THE ARGUMENT LIST. Dated resolution inserted `--before` into
  // every fetch, so the old single needle `--ignore-scripts "$PKG@$VER"` stopped matching and this
  // test went red on a change that did not touch screening at all. The fetch is therefore pinned as
  // TWO ordered needles — the flags, then the target spec — which keeps "the target is fetched
  // between the two screens" while tolerating arguments added in between.
  inOrder(drivers.linux, [
    'security_screen_direct "$PKG@$VER"',
    'npm install --no-audit --no-fund --ignore-scripts',
    '"$PKG@$VER"',
    'security_screen_tree "$OBS" npm-observe-resolved',
    'npm rebuild --no-audit --no-fund "$PKG"',
  ], 'linux');
  inOrder(drivers.macos, [
    'security_screen_direct "$PKG@$VER"',
    'npm install --no-audit --no-fund --ignore-scripts',
    '"$PKG@$VER"',
    'security_screen_tree "$OBS" npm-observe-resolved',
    '"$NPM_BIN" rebuild --no-audit --no-fund "$PKG"',
  ], 'macos');
  inOrder(drivers.windows, [
    "securityScreen('direct', ['--spec', `${PKG}@${VER}`])",
    // The arg list moved into `era-resolution.mjs`; what must still sit HERE, between the screens,
    // is the fetch that consumes it.
    'run(NODE, [NPM, ...eraResolution.args]',
    "securityScreen('npm-observe-resolved', ['--tree', OBS])",
    'rebuild --no-audit --no-fund ${PKG}',
  ], 'windows');
});

test('the fetch every driver runs is still --ignore-scripts, dated or not', () => {
  // ⛔ THE GUARANTEE THE LOOSENED NEEDLE ABOVE COULD OTHERWISE DROP. Screening happens between the
  // fetch and the scripts precisely BECAUSE the fetch does not execute them; a fetch that lost
  // `--ignore-scripts` would run unscreened code and the ordering test would still pass.
  assert.match(drivers.linux, /npm install --no-audit --no-fund --ignore-scripts \$\{ERA_BEFORE[^\n]*"\$PKG@\$VER"/);
  assert.match(drivers.macos, /npm install --no-audit --no-fund --ignore-scripts \$\{ERA_BEFORE[^\n]*"\$PKG@\$VER"/);
  const eraRes = fs.readFileSync(path.join(here, 'era-resolution.mjs'), 'utf8');
  assert.match(eraRes, /'--ignore-scripts'/, 'the shared fetch arg builder must keep --ignore-scripts');
});

test('every verify arm resolves without scripts, screens that Nub tree, then runs lifecycle commands', () => {
  inOrder(drivers.linux, [
    '"$NUB" install --ignore-scripts > "$v/security-resolve.log"',
    'security_screen_tree "$v" "nub-$label-resolved"',
    '"$NUB" install > "$v/i.log"',
    '"$NUB" approve-builds --all > "$v/a.log"',
  ], 'linux verify');
  inOrder(drivers.macos, [
    "'$NUB' install --ignore-scripts > '$v/security-resolve.log'",
    'security_screen_tree "$v" "nub-$label-resolved"',
    '"$NUB" install > "$v/i.log"',
    "'$NUB' approve-builds --all > '$v/a.log'",
  ], 'macos verify');
  inOrder(drivers.windows, [
    "run(NUB, ['install', '--ignore-scripts']",
    'securityScreen(`nub-${label}-resolved`, [\'--tree\', v])',
    "run(NUB, ['install']",
    "run(NUB, ['approve-builds', '--all']",
  ], 'windows verify');
});

test('Windows records the Nub arm layout after safe resolution, not npm OBSERVE as hoisted', () => {
  assert.doesNotMatch(drivers.windows.slice(0, drivers.windows.indexOf('const verify =')),
    /VENUE-STORE-LAYOUT hoisted/);
  inOrder(drivers.windows, [
    "run(NUB, ['install', '--ignore-scripts']",
    'VENUE-STORE-LAYOUT ${isolated',
    'securityScreen(`nub-${label}-resolved`',
  ], 'windows layout provenance');
});

const runHelper = (rc) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-helper-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'node'), `#!/bin/sh\necho '  => REFUSED-MALICIOUS test-control'\nexit ${rc}\n`,
    { mode: 0o755 });
  const script = path.join(dir, 'run.sh');
  fs.writeFileSync(script, `#!/bin/bash
ROOT=${JSON.stringify(dir)}
HERE=${JSON.stringify(here)}
PATH=${JSON.stringify(bin)}:$PATH
. ${JSON.stringify(path.join(here, 'security-screen.sh'))}
security_screen_tree ${JSON.stringify(dir)} test-tree
touch ${JSON.stringify(path.join(dir, 'AFTER_SCREEN'))}
`, { mode: 0o755 });
  const result = spawnSync('bash', [script], { encoding: 'utf8' });
  return { ...result, reached: fs.existsSync(path.join(dir, 'AFTER_SCREEN')) };
};

shellTest('a malicious or failed screen terminates before the lifecycle boundary; a clean one continues', () => {
  const malicious = runHelper(42);
  assert.equal(malicious.status, 0);
  assert.equal(malicious.reached, false);
  assert.match(malicious.stdout, /REFUSED-MALICIOUS/);

  const failed = runHelper(2);
  assert.equal(failed.status, 1);
  assert.equal(failed.reached, false);
  assert.match(failed.stdout, /HARNESS-ERROR: fail-closed OSV test-tree screen did not complete/);

  const clean = runHelper(0);
  assert.equal(clean.status, 0);
  assert.equal(clean.reached, true);
});
