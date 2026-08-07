// The two-command arm — EXECUTED, with `nub` stubbed.
//
// ⛔ WHY THIS FILE EXISTS SEPARATELY FROM `linux-ladder.test.mjs`. That file executes the real
// driver but STUBS `verify` wholesale, because `verify` needs strace, an override-capable nub and a
// live registry. The block under test here lives INSIDE `verify`, so it is precisely the part that
// every other executing test replaces with a stub. It was never covered, and two defects lived in
// it in every arm of every published record.
//
// ⛔ THE ORACLE IS THE STUB `nub`. Each case says what `install` prints and what each command
// exits with; the test reads what the block concluded from that. `approve-builds` records its own
// invocation in a sentinel file, which is the only way to see a command that DIDN'T run.
//
// ⛔ AND THE FALSIFICATION CONTROL IS IN THE FILE. `PRE_FIX` is the block as it was — a bare
// `( install; approve-builds )` — run against the identical stubs. The cases at the bottom assert
// it exhibits both defects. Without that, every assertion above would keep passing if the fix were
// reverted tomorrow, which is the failure mode this repo keeps rediscovering.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = import.meta.dirname;
const DRIVER = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');

// Anchored on the code itself, not a line number, so an edit above cannot silently shift the slice.
const REGION = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => /^\s*\( cd "\$v"$/.test(l));
  const end = lines.findIndex((l, i) => i > start && /^\s*local rc=\$\?$/.test(l));
  assert.ok(start > 0 && end > start, 'could not locate the arm block in measure.sh');
  // `local` is only legal inside a function, so drop it — `rc` is read by the caller below.
  return lines.slice(start, end + 1).join('\n').replace(/^\s*local rc=/m, '  rc=');
})();

test('the extracted region is the real thing, not an empty slice', () => {
  // A region that failed to match would make every case below vacuously green.
  assert.match(REGION, /"\$NUB" install/, 'the slice does not contain the install command');
  assert.match(REGION, /approve-builds --all/, 'the slice does not contain approve-builds');
});

// The block as it stood before the fix. Kept verbatim so the controls test the ACTUAL prior
// behaviour rather than my description of it.
const PRE_FIX = `  ( cd "$v"
    "$NUB" install > "$v/i.log" 2>&1
    "$NUB" approve-builds --all > "$v/a.log" 2>&1 )
  rc=$?`;

/**
 * Run a block with a stub `nub`.
 * @param installLine what `nub install` prints
 * @param installRc   what `nub install` exits with
 * @param approveRc   what `nub approve-builds` exits with
 */
function runArm(block, { installLine, installRc = 0, approveRc = 0 }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'arm-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const nub = path.join(bin, 'nub');
  // The sentinel is what makes a command that did NOT run observable.
  fs.writeFileSync(nub, `#!/bin/sh
case "$1" in
  install)        printf '%s\\n' ${JSON.stringify(installLine)}; exit ${installRc} ;;
  approve-builds) : > "${dir}/APPROVE_RAN"; exit ${approveRc} ;;
esac
exit 99
`, { mode: 0o755 });

  const script = `#!/bin/bash
v=${JSON.stringify(dir)}
NUB=${JSON.stringify(nub)}
tracer=""
rc=x
${block}
echo "ARM_RC=$rc"
`;
  const sh = path.join(dir, 'run.sh');
  fs.writeFileSync(sh, script, { mode: 0o755 });
  const out = execFileSync('bash', [sh], { encoding: 'utf8' });
  return {
    rc: Number(/ARM_RC=(\d+)/.exec(out)?.[1]),
    approveRan: fs.existsSync(path.join(dir, 'APPROVE_RAN')),
    aLog: fs.readFileSync(path.join(dir, 'a.log'), 'utf8'),
  };
}

const TRUSTED = 'WARN defaultTrust: running build scripts for 1 default-trusted package(s): p@1.0.0';
const DEFERRED = 'WARN ignored build scripts for 1 package(s): p@1.0.0. Run `nub approve-builds` to review';

test('⭑ a DEFAULT-TRUSTED package does not get its build scripts run a second time', () => {
  // MEASURED on `gentype@3.9.1`: install runs the postinstall, which fetches
  // `vendor-linux/gentype.exe` and consumes it; approve-builds then runs it again and dies
  // `executable not found`. Every rung of the ladder failed for a reason unrelated to the grant.
  const r = runArm(REGION, { installLine: TRUSTED });
  assert.equal(r.approveRan, false,
    'approve-builds ran even though install already executed the build scripts — this is the double-run');
  assert.equal(r.rc, 0);
  assert.match(r.aLog, /SKIPPED/, 'a.log must say why it is empty, not just be empty');
});

test('⭑ a DEFERRED package still gets approve-builds — the skip must not swallow the normal path', () => {
  // The paired positive control. Without it, "never run approve-builds" would satisfy the case
  // above while making the harness measure packages whose scripts never ran at all.
  const r = runArm(REGION, { installLine: DEFERRED });
  assert.equal(r.approveRan, true, 'the deferred path MUST run approve-builds or nothing is built');
  assert.equal(r.rc, 0);
});

test('⭑ an unrecognised trust path keeps the old behaviour rather than skipping', () => {
  // The skip is keyed on POSITIVE evidence. A package printing neither marker must still get
  // approve-builds, so a future change to nub's wording costs a redundant no-op, never a silently
  // unbuilt package.
  const r = runArm(REGION, { installLine: 'installed 1 package in 0.4s' });
  assert.equal(r.approveRan, true);
});

test('⭑ a FAILED install fails the arm even when approve-builds succeeds', () => {
  // `ctrlc-windows@0.1.9` measured install=1 approve=0. Reported as rc=0, that is an arm which
  // installed nothing being read as sufficient — and in the `grc==3` branch, which gates on rc
  // alone, it would have been published at whatever narrow grant was under test.
  const r = runArm(REGION, { installLine: 'error: tarball extraction error', installRc: 1, approveRc: 0 });
  assert.equal(r.rc, 1, 'the install failure was masked by approve-builds succeeding');
});

test('a failing approve-builds still fails the arm', () => {
  const r = runArm(REGION, { installLine: DEFERRED, approveRc: 1 });
  assert.equal(r.rc, 1);
});

// ── the falsification controls ───────────────────────────────────────────────
test('CONTROL: the pre-fix block DOES double-run, so the first case can fail', () => {
  const r = runArm(PRE_FIX, { installLine: TRUSTED });
  assert.equal(r.approveRan, true,
    'the pre-fix block did not double-run — then the fix guards nothing and this suite is theatre');
});

test('CONTROL: the pre-fix block DOES mask a failed install, so that case can fail', () => {
  const r = runArm(PRE_FIX, { installLine: 'error', installRc: 1, approveRc: 0 });
  assert.equal(r.rc, 0, 'the pre-fix block did not mask the install failure — re-check the claim');
});
