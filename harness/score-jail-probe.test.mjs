// ⛔ THE CONTROLS ARE THE POINT. A scorer that only ever says PASS is indistinguishable from no
// gate at all, so every tier that MUST fail is asserted here alongside the ones that must pass.
// The linux/win32 payloads are real captured CI output, not invented fixtures.

import { test } from 'node:test';
import assert from 'node:assert';
import { scoreProbe } from './score-jail-probe.mjs';

const res = (name, status, detail) => ({ name, status, detail });
const ACTIONS = ['read npmrc', 'read gitconfig', 'read aws creds', 'read ssh key', 'list real home', 'write persistence'];
const mk = (results, envLeaked = 0) =>
  `PROBE_RESULT ${JSON.stringify({ allowed: results.filter((r) => r.status === 'ALLOWED').length, total: results.length, envLeaked, results })}`;

const allBlocked = ACTIONS.map((n) => res(n, 'BLOCKED', 'EACCES'));
const enumAllowed = ACTIONS.map((n) => (n === 'list real home' ? res(n, 'ALLOWED', '42 entries enumerated') : res(n, 'BLOCKED', 'EPERM')));

test('linux: every action denied -> PASS', () => {
  assert.equal(scoreProbe(mk(allBlocked), 'linux').code, 0);
});

test('win32: enumeration allowed is TOLERATED and named', () => {
  const { code, lines } = scoreProbe(mk(enumAllowed), 'windows');
  assert.equal(code, 0);
  assert.ok(lines.some((l) => /KNOWN \+ DELIBERATE/.test(l)), 'the toleration must be stated, not silent');
});

// ── the controls: each MUST fail ────────────────────────────────────────────────────────────────
test('CONTROL enumeration on linux is a REGRESSION, not tolerated', () => {
  const { code, lines } = scoreProbe(mk(enumAllowed), 'linux');
  assert.equal(code, 1);
  assert.ok(lines.some((l) => /REGRESSION/.test(l)));
});

test('CONTROL a credential READ that succeeds is a hard fail on every platform', () => {
  for (const os of ['linux', 'macos', 'windows']) {
    const leaked = allBlocked.map((r) => (r.name === 'read aws creds' ? res(r.name, 'ALLOWED', '48 bytes STOLEN') : r));
    assert.equal(scoreProbe(mk(leaked), os).code, 1, `${os} must fail on a credential read`);
  }
});

test('CONTROL the persistence WRITE succeeding is a hard fail on every platform', () => {
  for (const os of ['linux', 'macos', 'windows']) {
    const leaked = allBlocked.map((r) => (r.name === 'write persistence' ? res(r.name, 'ALLOWED', 'persisted') : r));
    assert.equal(scoreProbe(mk(leaked), os).code, 1, `${os} must fail on a persistence write`);
  }
});

test('CONTROL env secrets visible is a hard fail even when every file action is blocked', () => {
  assert.equal(scoreProbe(mk(allBlocked, 3), 'windows').code, 1);
});

test('CONTROL a NEW untiered action that is ALLOWED fails rather than passing unnoticed', () => {
  const withNew = [...allBlocked, res('read kubeconfig', 'ALLOWED', 'slurped')];
  const { code, lines } = scoreProbe(mk(withNew), 'windows');
  assert.equal(code, 1);
  assert.ok(lines.some((l) => /needs a tier/.test(l)));
});

// ── the "never ran" seam ────────────────────────────────────────────────────────────────────────
test('default-deny with nubs own notice is the STRONGEST pass', () => {
  assert.equal(scoreProbe('WARN ignored build scripts ... run `nub approve-builds`', 'linux').code, 0);
});

test('CONTROL silence with no default-deny notice FAILS — absence is not evidence', () => {
  assert.equal(scoreProbe('some unrelated output', 'linux').code, 1);
});
