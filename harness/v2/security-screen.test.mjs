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
  inOrder(drivers.linux, [
    'security_screen_direct "$PKG@$VER"',
    'npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER"',
    'security_screen_tree "$OBS" npm-observe-resolved',
    'npm rebuild --no-audit --no-fund "$PKG"',
  ], 'linux');
  inOrder(drivers.macos, [
    'security_screen_direct "$PKG@$VER"',
    'npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER"',
    'security_screen_tree "$OBS" npm-observe-resolved',
    '"$NPM_BIN" rebuild --no-audit --no-fund "$PKG"',
  ], 'macos');
  inOrder(drivers.windows, [
    "securityScreen('direct', ['--spec', `${PKG}@${VER}`])",
    "'--ignore-scripts', `${PKG}@${VER}`",
    "securityScreen('npm-observe-resolved', ['--tree', OBS])",
    'rebuild --no-audit --no-fund ${PKG}',
  ], 'windows');
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
    'run_macos_verify "$v" "$cache"',
  ], 'macos verify');
  inOrder(drivers.windows, [
    "run(NUB, ['install', '--ignore-scripts']",
    'securityScreen(`nub-${label}-resolved`, [\'--tree\', v])',
    "run(NUB, ['install']",
    "run(NUB, ['approve-builds', '--all']",
  ], 'windows verify');
});

test('POSIX pre-lifecycle resolver failures retain their isolated arm and bounded stderr', () => {
  for (const [platform, source] of Object.entries({ linux: drivers.linux, macos: drivers.macos })) {
    const failure = source.indexOf('=> HARNESS-ERROR: Nub could not materialize the tree with --ignore-scripts');
    assert.ok(failure >= 0, `${platform}: missing resolver failure`);
    const retained = source.lastIndexOf('kept for inspection: $v', failure);
    const exit = source.lastIndexOf('SECURITY-RESOLVE-EXIT: $resolve_rc', failure);
    const tail = source.lastIndexOf('tail -n 200 "$v/security-resolve.log"', failure);
    assert.ok(retained >= 0 && exit >= retained && tail >= exit,
      `${platform}: resolver failure drops its diagnostic arm or exit status`);
  }
});

test('POSIX failed direct arms retain bounded lifecycle command logs', () => {
  for (const [platform, source] of Object.entries({ linux: drivers.linux, macos: drivers.macos })) {
    const guard = platform === 'macos'
      ? /\[ "\$rc" -ne 0 \] && \{ \[ "\$label" = at-catalog \] \|\| \[ "\$label" = at-grant \]; \}/
      : /\[ "\$rc" -ne 0 \] && \[ "\$label" = at-catalog \]/;
    assert.match(source, guard, `${platform}: direct failure does not select its diagnostic arm`);
    const failure = source.indexOf('VERIFY-EXIT: $rc');
    const install = source.indexOf('tail -n 200 "$v/i.log"', failure);
    const approve = source.indexOf('tail -n 200 "$v/a.log"', install);
    assert.ok(failure >= 0 && install > failure && approve > install,
      `${platform}: direct failure drops the bounded install/approve logs`);
  }
});

test('macOS forwards an opt-in policy dump without enabling it for ordinary arms', () => {
  const helper = drivers.macos.match(/^run_macos_verify \(\) \{([\s\S]*?)^\}/m)?.[1] ?? '';
  assert.match(helper, /if \[ -n "\$\{NUB_JAIL_DUMP_POLICY:-\}" \]; then/);
  assert.match(helper, /"NUB_JAIL_DUMP_POLICY=\$NUB_JAIL_DUMP_POLICY"/);
  assert.match(helper, /\/bin\/bash "\$HERE\/macos-verify\.sh" "\$verify_dir" "\$NUB"/);
  const ordinaryArm = helper.split(/\n  else\n/)[1] ?? '';
  assert.doesNotMatch(ordinaryArm, /NUB_JAIL_DUMP_POLICY/,
    'ordinary verifier arms must omit the variable rather than pass an empty assignment');
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
