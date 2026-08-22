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

test('nub refusing a package is an OUTCOME, not a defect to go and fix', () => {
  // ⛔ 5 OF THE 11 "NUB DEFECTS" WERE THIS. Until nub's own logs were readable every non-zero exit
  // looked identical, so the control reported eleven bugs where six existed. It also explains the
  // netlify-cli version boundary that read like a bisect target: 22.4.0 and 23.9.5 trip a trust
  // downgrade, 26.2.0 and 27.0.1 do not.
  const refused = emit('netlify-cli@22.4.0', 1, {
    'out.log': BANNER, 'security-resolve.log': 'ERR_NUB_TRUST_DOWNGRADE netlify-cli@22.4.0\n',
  });
  assert.equal(refused.outcome, 'NUB-REFUSED');
  assert.equal(refused.stillNubDefect, false, 'a deliberate refusal must never be filed as a bug');

  const malicious = emit('apollo-server@0.1.5', 1, {
    'out.log': BANNER, 'security-resolve.log': 'ERR_NUB_MALICIOUS_PACKAGE apollo-server@0.1.5\n',
  });
  assert.equal(malicious.outcome, 'NUB-REFUSED');
});

test('a policy block wrapped across lines is still a refusal', () => {
  // ⛔ TWO TRAPS IN ONE FIXTURE, AND BOTH COST A WRONG ANSWER. First, the CODE says
  // ERR_NUB_REGISTRY_ERROR, which reads like a fetch failure — only the body says nub chose this.
  // Second, nub renders the body as a hanging-indent block, so "blocked by" and the policy name
  // land on different lines when the specifier is long. Matching raw text found 6 refusals where 9
  // exist: node-libcurl happened to wrap late and matched, the two baileys and web3 wrapped early
  // and were silently filed as nub bugs.
  const r = emit('baileys@6.7.24', 1, {
    'out.log': BANNER,
    'security-resolve.log': [
      'ERR_NUB_REGISTRY_ERROR',
      '  × failed to resolve dependencies',
      '  ╰─▶ registry error for libsignal: uses exotic specifier "git+https://',
      '      github.com/whiskeysockets/libsignal-node.git" which is blocked by',
      '      blockExoticSubdeps (declared by baileys)',
    ].join('\n'),
  });
  assert.equal(r.outcome, 'NUB-REFUSED');
  assert.equal(r.stillNubDefect, false);
});

test('a failure that is NOT a refusal stays a defect', () => {
  // The other direction, which matters just as much: a registry error with no policy block in it is
  // nub failing to fetch what npm fetches fine, and a permission error on a bin script is a real
  // mechanism bug.
  const registry = emit('some-pkg@1.0.0', 1, {
    'out.log': BANNER, 'security-resolve.log': 'ERR_NUB_REGISTRY_ERROR\n  × 503 from the registry\n',
  });
  assert.equal(registry.outcome, 'NUB-DEFECT');

  const perms = emit('@progress/kendo-licensing@0.1.2', 1, {
    'out.log': BANNER, 'i.log': 'sh: 1: ./bin/update-kendo-license.js: Permission denied\n',
  });
  assert.equal(perms.outcome, 'NUB-DEFECT');
  assert.equal(perms.stillNubDefect, true);
});

test('a package nub installs is NUB-INSTALLS whatever its logs say', () => {
  const r = emit('ok@1.0.0', 0, { 'out.log': BANNER, 'i.log': 'added 4 packages\n' });
  assert.equal(r.outcome, 'NUB-INSTALLS');
});
