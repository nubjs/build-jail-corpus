// Cases for the unfalsifiable-arm detector. `node --test harness/v2/arm-falsifiability.test.mjs`.
//
// ⛔ THE NEGATIVE CONTROLS CARRY THE WEIGHT HERE. A detector that flags everything satisfies every
// "this flags" assertion, and would then mark the whole corpus as weak evidence — which is exactly as
// useless as flagging nothing. So each discriminant is tested from both sides, and the rc pattern has
// a table with three cases that must NOT match.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ⛔ `import.meta.dirname`, NEVER `new URL(...).pathname`. On Windows that yields
// `/D:/a/repo/harness/v2/`, and `join`ing it produces `D:\D:\a\...` — a doubled drive
// letter, so every test in this file died with MODULE_NOT_FOUND the first time the suite ran
// on a windows-latest runner. It is wrong on POSIX too, just invisibly: `.pathname` keeps URL
// percent-encoding, so a checkout under a path with a space resolves to `%20` and fails there.
const HERE = import.meta.dirname;
const TOOL = join(HERE, 'arm-falsifiability.mjs');
const run = (a) => execFileSync(process.execPath, [TOOL, ...a], { encoding: 'utf8' });

// Builds a fixture, snapshots it, optionally lets the "script" produce a file, then reports.
const measure = ({ pkg, script, shipped, produces }) => {
  const base = mkdtempSync(join(tmpdir(), 'armfals-'));
  const dir = join(base, 'node_modules', pkg);
  mkdirSync(join(dir, 'build', 'Release'), { recursive: true });
  writeFileSync(join(dir, 'package.json'),
    JSON.stringify({ name: pkg, version: '1.0.0', scripts: script ? { install: script } : {} }));
  for (const f of shipped ?? []) writeFileSync(join(dir, 'build', 'Release', f), 'shipped');
  const pre = join(base, 'pre.json');
  run(['--snapshot', base, '--pkg', pkg, '--ver', '1.0.0', '--out', pre]);
  for (const f of produces ?? []) writeFileSync(join(dir, 'build', 'Release', f), 'produced-by-script');
  return run(['--obs', base, '--pre', pre, '--pkg', pkg, '--ver', '1.0.0']);
};

test('a package whose build output SHIPS prebuilt is flagged — the gate could not have failed', () => {
  // RED ON REVERT: drop the produced.length === 0 branch. ttf2woff2@1.2.3 is the real instance —
  // 124 published files including a working build/Release/addon.node, and an arm that reported
  // artifacts=122/122 while node-gyp never reached a compiler.
  const out = measure({ pkg: 'shipsprebuilt', shipped: ['addon.node'] });
  assert.match(out, /ARMS-UNFALSIFIABLE/);
  assert.match(out, /gate-vacuous/);
});

test('a package whose script genuinely produces its output is NOT flagged', () => {
  // The positive control, and the one that stops the detector being satisfied by flagging everything.
  const out = measure({ pkg: 'buildsitself', produces: ['addon.node'] });
  assert.doesNotMatch(out, /ARMS-UNFALSIFIABLE/);
  assert.match(out, /"filesTheScriptProduced":1/);
});

test('a file that GREW counts as produced — the gate can still fail on a size comparison', () => {
  // The boundary that is easy to get wrong: the discriminant is not "is the manifest a subset of the
  // tarball" but "could the gate's `>= size` check have failed on anything".
  const base = mkdtempSync(join(tmpdir(), 'armfals-'));
  const dir = join(base, 'node_modules', 'grows');
  mkdirSync(join(dir, 'build', 'Release'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'grows', version: '1.0.0' }));
  writeFileSync(join(dir, 'build', 'Release', 'addon.node'), 'stub');
  const pre = join(base, 'pre.json');
  run(['--snapshot', base, '--pkg', 'grows', '--ver', '1.0.0', '--out', pre]);
  writeFileSync(join(dir, 'build', 'Release', 'addon.node'), 'the real, much larger linked output');
  const out = run(['--obs', base, '--pre', pre, '--pkg', 'grows', '--ver', '1.0.0']);
  assert.doesNotMatch(out, /gate-vacuous/, 'a file that grew is something the script produced');
});

test('a trailing status swallow is flagged in each spelling, and a mid-chain one is not', () => {
  // ⛔ THE THREE NON-MATCHES ARE THE POINT. `prebuild-install || node-gyp rebuild` is a REAL fallback
  // whose rc is honest — flagging it would mark most native packages as weak evidence. And a swallow
  // in the MIDDLE of a chain does not swallow the script's final status.
  const cases = [
    ['(node-gyp rebuild > builderror.log) || (exit 0)', true],
    ['node-gyp rebuild || true', true],
    ['node-gyp rebuild || exit 0', true],
    ['node install.js; exit 0', true],
    ['node-gyp rebuild || :', true],
    ['prebuild-install --runtime napi || node-gyp rebuild', false],
    ['node postinstall.js', false],
    ['cmd || true && other', false],
  ];
  for (const [script, want] of cases) {
    // `produces` keeps the gate discriminant quiet so this asserts only on the rc one.
    const out = measure({ pkg: 'rccase', script, produces: ['addon.node'] });
    assert.equal(/rc-vacuous/.test(out), want, `rc-vacuous for: ${script}`);
  }
});

test('a missing pre-manifest reports rather than inventing a verdict', () => {
  // Retention of the pre-state is additive; losing it must not turn into a confident "falsifiable".
  const base = mkdtempSync(join(tmpdir(), 'armfals-'));
  const dir = join(base, 'node_modules', 'nopre');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'nopre', version: '1.0.0' }));
  const out = run(['--obs', base, '--pre', join(base, 'absent.json'), '--pkg', 'nopre', '--ver', '1.0.0']);
  assert.match(out, /"filesTheScriptProduced":null/, 'unknown is reported as null, not as 0');
  assert.doesNotMatch(out, /gate-vacuous/, 'and never flags the gate on an absent baseline');
});
