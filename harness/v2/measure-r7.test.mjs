// R7 — OBSERVE must run with FULL USER PERMISSIONS, and the driver must say so and refuse otherwise.
//
// ⛔ WHY THIS ASSERTION IS FATAL RATHER THAN ADVISORY, restated here because a future reader will be
// tempted to soften it: if OBSERVE is LESS privileged than a real developer, a script that tries its
// primary path, is refused, and falls back is measured ON THE FALLBACK. The real user takes the
// primary path and needs a capability the trace never saw. That is an under-grant — the one
// direction this project forbids — and nothing in the resulting record looks wrong.
//
// As with `measure-provenance.test.mjs`, the shell under test is EXTRACTED from `measure.sh` at run
// time rather than transcribed, and the extractor asserts it found its block so a drifted anchor
// fails loudly instead of silently testing the empty string.

import { test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ⛔ SKIPPED ON WINDOWS, WITH A REASON, RATHER THAN LEFT TO FAIL THERE. This file extracts a bash
// function out of `measure.sh` and drives it with POSIX permission bits — `chmod 0500` for an
// unwritable HOME, a `noexec` mount for the exec check. `measure.sh` has no Windows caller, `bash`
// is not the shell there, and `chmod` is a no-op on NTFS, so on Windows the guard PASSES every
// negative case and the tests fail for a reason that says nothing about R7. The Windows lane asserts
// R7 in `measure-windows.mjs` against the ETW capture's own recorded identity and privilege drop,
// which is the same requirement expressed in the terms that platform actually has.
//
// ⛔ A SKIP IS NOT A PASS, so it is spelled as one: `node --test` reports these as skipped with this
// reason attached, where deleting them or loosening the assertions would have read as coverage.
const SKIP = process.platform === 'win32'
  ? 'POSIX-only: drives a bash guard with chmod/noexec, neither of which means anything on Windows'
  : false;
const test = (name, fn) => nodeTest(name, { skip: SKIP }, fn);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8').split('\n');

const i = SRC.findIndex((l) => /^assert_real_user\(\) \{/.test(l));
assert.notEqual(i, -1, 'ANCHOR DRIFT: measure.sh has no `assert_real_user()` definition');
const j = SRC.slice(i).findIndex((l) => /^assert_real_user$/.test(l));
assert.notEqual(j, -1, 'ANCHOR DRIFT: `assert_real_user` is defined but never called');
const R7_BLOCK = SRC.slice(i, i + j + 1).join('\n');

/** Run the extracted guard with a chosen ROOT/HOME. Returns {code, err} — never throws. */
const runGuard = ({ root, home = os.homedir() }) => {
  const script = `set -u\nROOT='${root}'\nHOME='${home}'\nexport HOME\n${R7_BLOCK}\necho R7-PASSED\n`;
  try {
    const out = execFileSync('bash', ['-c', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, out, err: '' };
  } catch (e) {
    return { code: e.status, out: e.stdout ?? '', err: e.stderr ?? '' };
  }
};

const usableRoot = (label) => fs.mkdtempSync(path.join(os.tmpdir(), `r7-${label}-`));

test('the extracted R7 guard is the real one — the instrument check', () => {
  assert.match(R7_BLOCK, /id -u/, `extraction missed the root check:\n${R7_BLOCK}`);
  assert.match(R7_BLOCK, /R7 FAILED/, `extraction missed the fatal arm:\n${R7_BLOCK}`);
  assert.match(R7_BLOCK, /exit 3/, 'the guard must EXIT, not warn — an advisory R7 buys nothing');
});

test('POSITIVE CONTROL: an ordinary user with a writable home and an exec-capable root passes', () => {
  // Without this the failure cases below are equally consistent with a guard that refuses
  // everything, which would be a different bug wearing the same green.
  const r = runGuard({ root: usableRoot('ok') });
  assert.equal(r.code, 0, `an ordinary developer environment must pass R7:\n${r.err}${r.out}`);
  assert.match(r.out, /R7-PASSED/, 'execution must continue past the guard');
});

test('⛔ an unwritable HOME fails the run — the signature of a restricted service account', () => {
  const home = usableRoot('badhome');
  fs.chmodSync(home, 0o500);
  try {
    const r = runGuard({ root: usableRoot('ok2'), home });
    assert.equal(r.code, 3, `a non-writable home must be fatal, not a warning:\n${r.err}${r.out}`);
    assert.match(r.err, /R7: the real HOME/, `the failure must name what is wrong:\n${r.err}`);
    assert.doesNotMatch(r.out, /R7-PASSED/, 'the run must STOP, not continue past a failed guard');
  } finally {
    fs.chmodSync(home, 0o700);
  }
});

test('⛔ a HOME that does not exist at all fails the run', () => {
  const r = runGuard({ root: usableRoot('ok3'), home: path.join(os.tmpdir(), 'r7-no-such-home-xyz') });
  assert.equal(r.code, 3, `a missing home must be fatal:\n${r.err}${r.out}`);
  assert.match(r.err, /R7: the real HOME/, `the failure must name what is wrong:\n${r.err}`);
});

test('⛔ a run root that cannot host an executable fails — the `noexec` shape', () => {
  // A real `noexec` mount needs privilege to create, so this drives the same branch through an
  // unwritable root: in both cases the guard cannot create-and-run a file where a build would stage
  // one. What is being pinned is that the guard EXECUTES its probe rather than assuming it could —
  // a `[ -w ]` check alone would pass on a writable `noexec` mount, which is the case that matters.
  //
  // VERIFIED against the real thing on the corpus VM, which is what makes the substitution honest:
  // `mount -t tmpfs -o noexec` gives `rw,noexec,relatime` — WRITABLE and not executable — and the
  // guard exited 3 on it. A permissions-read check would have passed that mount.
  const root = usableRoot('noexec');
  fs.chmodSync(root, 0o500);
  try {
    const r = runGuard({ root });
    assert.equal(r.code, 3, `an unusable run root must be fatal:\n${r.err}${r.out}`);
    assert.match(r.err, /cannot create and execute/, `the failure must name the exec probe:\n${r.err}`);
  } finally {
    fs.chmodSync(root, 0o700);
  }
});

test('the guard actually EXECUTES its probe rather than only stat-ing it', () => {
  // The check that keeps the previous test from being satisfiable by a permissions read. If the
  // guard ever degraded to `[ -w "$d" ]`, a writable-but-noexec mount would sail through — and that
  // is precisely the environment that silently converts a prebuilt-binary install into a
  // build-from-source one. Pinned structurally because a noexec mount is not creatable in a test.
  assert.match(R7_BLOCK, /R7OK/, 'the exec probe must run a script and check its OUTPUT');
  assert.match(R7_BLOCK, /chmod \+x/, 'the exec probe must make its file executable');
});

test('root is refused rather than tolerated as merely-more-privileged', () => {
  // ⛔ Pinned structurally, and here is why that is the honest choice rather than a dodge: the test
  // process is not root and must not become root, and a guard that only fires under `sudo` cannot be
  // exercised in an ordinary suite. What IS checkable is that the guard tests uid 0 and treats it as
  // fatal. The behavioural half was verified by hand on the corpus VM under `sudo` — see the commit.
  //
  // Root matters because it is NOT a superset: npm de-escalates to the owning uid when run as root,
  // so the lifecycle script runs as a different user than the one measured, and root bypasses the
  // refusals a developer would hit.
  assert.match(R7_BLOCK, /\[ "\$\(id -u\)" -eq 0 \]/, 'the guard must test for uid 0');
  assert.match(R7_BLOCK, /must not run as root/, 'and must say so in the failure');
});
