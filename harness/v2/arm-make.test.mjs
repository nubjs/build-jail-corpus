// The marker is the deliverable; the upgrade is opportunistic. Both directions are tested, because
// a record that cannot say which make ran cannot tell a package defect from a provisioning gap.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { chooseMake, gnuMakeMajor, MAKE_CANDIDATES } from './arm-make.mjs';

const SYSTEM_381 = { path: '/usr/bin/make', version: 'GNU Make 3.81' };
const BREW_44 = { path: '/opt/homebrew/bin/gmake', version: 'GNU Make 4.4.1' };

test('a box with only the system make SAYS a Make 4 build will fail here', () => {
  // ⛔ THE POINT OF THE WHOLE FILE. All 13 `GNU Make version is too old` records are
  // redis-memory-server on darwin-arm64, and macOS ships 3.81 frozen at the last GPLv2 release.
  // A record that does not name the make cannot distinguish that from a package defect.
  const r = chooseMake([SYSTEM_381]);
  assert.equal(r.path, '/usr/bin/make');
  assert.equal(r.upgraded, false);
  assert.match(r.marker, /GNU Make 3\.81.*WILL fail here/);
});

test('a newer gmake is preferred, and the marker says it was an upgrade', () => {
  const r = chooseMake([BREW_44, SYSTEM_381]);
  assert.equal(r.path, '/opt/homebrew/bin/gmake');
  assert.equal(r.major, 4);
  assert.equal(r.upgraded, true);
  assert.match(r.marker, /upgraded from the system GNU Make 3\.81/);
});

test('an equal-version gmake is NOT reported as an upgrade', () => {
  // Linux runners have `make` at 4.x already; claiming an upgrade there would be noise in every
  // Linux record and would make the darwin signal harder to find.
  const r = chooseMake([{ path: '/usr/bin/gmake', version: 'GNU Make 4.3' }, { path: '/usr/bin/make', version: 'GNU Make 4.3' }]);
  assert.equal(r.upgraded, false);
});

test('a non-GNU make is not silently ranked', () => {
  // BSD make prints no "GNU Make" line, so it has no comparable version. Ranking it would be
  // inventing an ordering the output does not support.
  assert.equal(gnuMakeMajor('bmake version 20200710'), null);
  assert.match(chooseMake([{ path: '/usr/bin/make', version: 'bmake' }]).marker, /NONE \(no GNU make found\)/);
});

test('no make at all is a named outcome, not an empty string', () => {
  assert.equal(chooseMake([]).path, null);
  assert.match(chooseMake([]).marker, /ARM-MAKE NONE/);
});

test('gmake is probed before make, because that is what Homebrew installs GNU Make 4 as', () => {
  assert.deepEqual(MAKE_CANDIDATES, ['gmake', 'make'],
    'gmake must be probed first — it deliberately does not shadow the system make');
});

test('⛔ ALL THREE DRIVERS record the make — the guard that makes landed mean landed', () => {
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(import.meta.dirname, d), 'utf8');
    assert.ok(/arm-make/.test(src), `${d} does not record which make its arm builds with`);
  }
});
