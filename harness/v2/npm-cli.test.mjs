// The same npm-invocation bug was fixed in one file and left standing in another, and the second
// copy silently cost every Windows record its era for two full sweeps: all 570 win32 rows carried
// eraMajor null AND before null while the ledger reported a confident `PINNED 22.23.2` — the
// harness default, not an era. One helper, and a test that the silent-null path is now loud.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { npmInvocation, npmArgv } from './npm-cli.mjs';
import { enginesAndDate } from './era-node.mjs';

test('npm is invoked as a JS entry point, never as the shim', () => {
  const { cmd, prefix } = npmInvocation();
  assert.equal(cmd, process.execPath, 'npm must run under THIS interpreter');
  assert.match(prefix[0], /npm-cli\.js$/);
});

test('a box with no discoverable JS entry falls back to the platform shim', () => {
  // Not a regression: on such a box the shim is the only option, and on POSIX it works.
  assert.deepEqual(npmArgv(path.join('/nonexistent', 'node'), 'linux'), ['npm']);
  assert.deepEqual(npmArgv(path.join('/nonexistent', 'node.exe'), 'win32'), ['npm.cmd']);
});

test('a lookup that cannot run npm says so instead of reporting no engines and no date', () => {
  // ⛔ THE EXACT WINDOWS FAILURE. `spawnSync('npm', ...)` returns 127 there because npm is a .cmd
  // shim. The old code mapped that to {engines: null, published: null}, which is indistinguishable
  // from a package that genuinely declares neither — so the caller pinned the harness default and
  // called it the era.
  const spawnSync = () => ({ status: 127, stdout: '', stderr: 'npm: command not found\n' });
  const r = enginesAndDate('x', '1.0.0', { spawnSync, npmArgv: ['npm'] });
  assert.equal(r.engines, null);
  assert.equal(r.published, null);
  assert.match(r.why, /npm view failed.*command not found/);
});

test('a successful lookup carries no failure reason', () => {
  const spawnSync = () => ({ status: 0, stdout: JSON.stringify({ time: { '1.0.0': '2020-01-01T00:00:00.000Z' } }) });
  const r = enginesAndDate('x', '1.0.0', { spawnSync, npmArgv: ['npm'] });
  assert.equal(r.published, '2020-01-01T00:00:00.000Z');
  assert.equal(r.why, undefined);
});

test('⭑ EVERY caller of enginesAndDate passes npmArgv — the default is a Windows trap', () => {
  // ⛔ THE GUARD THAT MAKES THE FIX STICK. This bug has appeared THREE times: observe-only.mjs (fixed
  // first), era-node.mjs's own CLI, and measure-windows.mjs — the jail driver, found only because I
  // went looking after the second. Each copy defaults to a bare `npm`, which on Windows is an
  // unspawnable `.cmd` shim, and each maps that to {engines: null, published: null} — silence
  // indistinguishable from a package that declares neither. In the observe lane it cost every win32
  // record its era across two COMPLETE sweeps.
  const here = import.meta.dirname;
  const offenders = [];
  for (const name of fs.readdirSync(here)) {
    if (!name.endsWith('.mjs') || name.endsWith('.test.mjs')) continue;
    const src = fs.readFileSync(path.join(here, name), 'utf8');
    for (const call of src.match(/enginesAndDate\([^;]*?\)/gs) ?? []) {
      // The definition itself and the doc'd default are not call sites.
      if (call.includes('npmArgv')) continue;
      offenders.push(`${name}: ${call.replace(/\s+/g, ' ').slice(0, 90)}`);
    }
  }
  assert.deepEqual(offenders, [], `these call sites would use a bare \`npm\`:\n  ${offenders.join('\n  ')}`);
});

test('CONTROL: the guard can actually fail', () => {
  // Without this, the sweep above could be matching nothing and reporting a clean bill.
  const bare = 'const r = enginesAndDate(pkg, version, { spawnSync });';
  assert.ok((bare.match(/enginesAndDate\([^;]*?\)/gs) ?? []).length === 1,
            'the pattern must match the exact shape the three offenders had');
});
