// Four attempts at capturing WHY nub fails produced, in order: an empty capture, a printf JSON
// SyntaxError, the OS banner `npm ERR! Linux 6.1`, and finally a null cause with an EMPTY tail on all
// 31 rows. The last one is what exposed the actual mistake — the workflow was reading the CONTROL's
// stdout, and nub's output is written by writeLogs() into the run directory. These tests pin both the
// file the emitter reads and the vocabulary it reads it with.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = import.meta.dirname;

const emit = (spec, rc, files) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'f9t-'));
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), body);
  const out = execFileSync(process.execPath,
    [path.join(HERE, 'f9-ledger-line.mjs'), spec, String(rc), path.join(dir, 'out.log'), dir],
    { encoding: 'utf8' });
  fs.rmSync(dir, { recursive: true, force: true });
  return JSON.parse(out);
};

const BANNER = '  jail-off control: resolved as nsptest (rc=1)\n  => BROKEN-UNJAILED-NUB npm installs this package but nub cannot\n';

test('the cause comes from nub own log, not from the control narration', () => {
  const r = emit('@google/clasp@1.0.7', 1, {
    'out.log': BANNER,
    'i.log': 'Resolving dependencies\nProgress: 12/40\nERR_NUB_LIFECYCLE_FAILED @google/clasp@1.0.7 postinstall exited with status 1\n',
  });
  assert.match(r.firstError, /ERR_NUB_LIFECYCLE_FAILED/);
  assert.equal(r.stillNubDefect, true);
});

test('nub vocabulary is not npm vocabulary — an npm-shaped filter matches none of it', () => {
  // firstCause() in observe-only.mjs requires `npm error` / `npm ERR!`. nub's PM output is rebranded
  // aube, so reusing that extractor here returned null on all 31 rows.
  const r = emit('x@1.0.0', 1, { 'out.log': BANNER, 'i.log': 'ERR_NUB_EPERM cannot write to /usr/lib\n' });
  assert.match(r.firstError, /ERR_NUB_EPERM/);
});

test('every log the control writes is carried on the row, so a wrong extractor is recoverable', () => {
  // The insurance that was missing: when the capture failed, nothing on disk held the text it should
  // have captured, so four rounds each needed a fresh CI run to learn anything.
  const r = emit('x@1.0.0', 1, {
    'out.log': BANNER, 'i.log': 'ERR_NUB_X boom\n', 'a.log': 'approved 1\n', 'fetch.log': 'fetched ok\n',
  });
  assert.deepEqual(Object.keys(r.logs).sort(), ['a.log', 'fetch.log', 'i.log']);
});

test('a package nub installs fine is not a defect and needs no cause', () => {
  const r = emit('ok@1.0.0', 0, { 'out.log': '  => INSTALLS-UNJAILED\n', 'i.log': 'added 4 packages\n' });
  assert.equal(r.stillNubDefect, false);
  assert.equal(r.firstError, null);
});
