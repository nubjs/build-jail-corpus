// node-gyp's Python requirement INVERTS across the range the matrix carries, so the two directions
// are tested separately. Getting it wrong either way breaks a different population.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pythonForEra, pythonFamilyForEra, LAST_PYTHON2_ERA } from './era-python.mjs';

const CANDIDATES = [
  { path: '/usr/local/bin/python2', version: '2.7.9' },
  { path: '/usr/bin/python3', version: '3.9.6' },
];

test('an old era gets python2 — measured: heapdump@0.3.9 builds on Node 4 with 2.7.9', () => {
  // node-gyp 3.4.0 with PYTHON=/usr/bin/python3 reports
  //   "is v3.9.6, which is not supported by gyp ... point to Python >= v2.5.0 & < 3.0.0"
  // and with PYTHON=/usr/local/bin/python2 returns rc=0.
  assert.equal(pythonForEra(4, CANDIDATES).path, '/usr/local/bin/python2');
  assert.equal(pythonForEra(6, CANDIDATES).path, '/usr/local/bin/python2');
});

test('a modern era gets python3 — the OTHER direction, which a blanket export would break', () => {
  // ⛔ THE TEST THAT STOPS THE OBVIOUS WRONG FIX. Exporting PYTHON=python2 unconditionally would fix
  // 39 records and break every arm whose node-gyp requires Python 3 — a far larger population.
  assert.equal(pythonForEra(8, CANDIDATES).path, '/usr/bin/python3');
  assert.equal(pythonForEra(18, CANDIDATES).path, '/usr/bin/python3');
  assert.equal(pythonForEra(26, CANDIDATES).path, '/usr/bin/python3');
});

test('the boundary sits where the measurements put it', () => {
  assert.equal(pythonFamilyForEra(LAST_PYTHON2_ERA), 'python2');
  assert.equal(pythonFamilyForEra(LAST_PYTHON2_ERA + 1), 'python3');
  assert.equal(LAST_PYTHON2_ERA, 7, 'measured at 4, 6 and 8; 5 and 7 interpolate the node-gyp 3 family');
});

test('an unsatisfiable requirement is NAMED, never silently unset', () => {
  // ⛔ A silently-unset PYTHON is how these 39 records came to look like package defects: the arm
  // failed, nothing said the interpreter was missing, and the failure was filed against the package.
  const r = pythonForEra(4, [{ path: '/usr/bin/python3', version: '3.9.6' }]);
  assert.equal(r.path, null);
  assert.match(r.marker, /NOT-SATISFIED.*needs python2/);
});

test('no candidates at all is still a named outcome', () => {
  assert.match(pythonForEra(4, []).marker, /NOT-SATISFIED.*none of 0 candidate/);
});

test('an unusable era major defaults to python3 rather than throwing', () => {
  // A record with no usable publish date reaches here with null; refusing to decide would drop the
  // package from the corpus over metadata, which is strictly worse than measuring it modern.
  assert.equal(pythonFamilyForEra(null), 'python3');
  assert.equal(pythonFamilyForEra(undefined), 'python3');
});

test('the marker states the era and the family, so a record explains itself', () => {
  assert.match(pythonForEra(4, CANDIDATES).marker,
    /ERA-PYTHON \/usr\/local\/bin\/python2 \(2\.7\.9\) for era Node 4, whose node-gyp requires python2/);
});

test('⛔ ALL THREE DRIVERS choose an era Python — the guard that makes landed mean landed', async () => {
  const fs = await import('node:fs'); const path = await import('node:path');
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(import.meta.dirname, d), 'utf8');
    assert.ok(/era-python|ERA_PYTHON/.test(src), `${d} does not choose an era Python`);
  }
});

test('⛔ the POSIX drivers pass PYTHON through `env`, never as an expanded assignment prefix', () => {
  // A variable assignment prefix must be a LITERAL word at parse time; one produced by parameter
  // expansion is treated as a COMMAND NAME. `${ERA_PYTHON:+PYTHON="$ERA_PYTHON"}` therefore tries to
  // EXECUTE `PYTHON=/usr/bin/python3`. MEASURED on three platforms: every observe arm returned in
  // 2-5s with installRc=null and the batch refused to start.
  const linux = fs.readFileSync(path.join(import.meta.dirname, 'measure.sh'), 'utf8');
  assert.match(linux, /env \$\{ERA_PYTHON:\+PYTHON="\$ERA_PYTHON"\}/,
    'measure.sh must hand PYTHON to `env`, not use it as an assignment prefix');
  // macOS is correct by construction: its assignment is already an ARGUMENT to `sudo ... env ...`.
  const mac = fs.readFileSync(path.join(import.meta.dirname, 'measure-macos.sh'), 'utf8');
  assert.match(mac, /env "PATH=/, 'the macOS arm must keep its sudo/env chain');
});
