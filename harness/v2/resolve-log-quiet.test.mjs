// ⛔ THE SECURITY-RESOLVE PRE-STEP MUST NOT RUN UNDER `RUST_LOG=debug`, AND THE ARMS MUST.
//
// When that install fails, the drivers tail `security-resolve.log` — the only place the reason exists.
// Under debug the tail is engine trace instead of nub's error, and this has now hidden the cause twice:
//
//   run 33293351038 — 30 lines of `DEBUG received frame=Data { stream_id: StreamId(37) }`
//   run 33299339164 — epoch 31 filtered ` DEBUG `, and the tail became 30 lines of hickory-resolver
//                     DNS records (`;; registry.npmjs.org. IN AAAA`, `; answers 12`, twelve AAAA rows)
//
// The second one is the lesson: the CONTINUATION lines of a multi-line debug record carry no level
// prefix, so no level filter can catch them. Filtering was whack-a-mole against a log the harness never
// wanted in the first place. `measure-macos.sh` has never set debug on this call and its dumps have
// always been readable — the fix is parity with the driver that was already right.
//
// ⛔ AND THE OVERSHOOT IS THE REAL RISK, WHICH IS WHY THE LAST TEST EXISTS. `RUST_LOG=debug` IS
// load-bearing on the MEASURED arms: `side-effects-cache: restored` is a `tracing::debug!` and is the
// only line distinguishing a built arm from a replayed one. A well-meaning sweep that removed debug
// everywhere would silently make the replay assertion unfalsifiable, which is a correctness loss, not
// a diagnostic one. So this file pins both directions: quiet on the pre-step, debug on the arms.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const here = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(here, f), 'utf8');

/// The subshell that runs the pre-step in `measure.sh`, EXECUTED with `env` standing in for nub, so
/// the assertion is about what the child actually receives rather than about the source text.
test('measure.sh runs the security-resolve pre-step with no RUST_LOG in the child env', () => {
  const lines = read('measure.sh').split('\n');
  const i = lines.findIndex((l) => l.includes('install --ignore-scripts > "$v/security-resolve.log"'));
  // Control: without this the test passes the moment the invocation is reworded or moved.
  assert.notEqual(i, -1, 'the security-resolve invocation was not found in measure.sh');
  const open = lines.lastIndexOf('  ( cd "$v"', i);
  assert.notEqual(open, -1, 'the pre-step subshell opener was not found above the invocation');
  // Close the subshell here rather than taking the driver's own `) || { ... }`: that line opens a
  // brace group whose body is the failure dump, and slicing it in without its closing `}` is a bash
  // syntax error — which is how this test first failed, with rc=2 and nothing executed.
  const block = `${lines.slice(open, i + 1).join('\n')}\n  )`;

  const v = fs.mkdtempSync(path.join(os.tmpdir(), 'resolve-quiet-'));
  // A stub that IGNORES its arguments and dumps its environment. Plain `/usr/bin/env` will not do:
  // the driver calls `"$NUB" install --ignore-scripts`, so env execs macOS's real `/usr/bin/install`,
  // which exits 64 on a usage error having printed no environment at all.
  const stub = path.join(v, 'nub-stub.sh');
  fs.writeFileSync(stub, '#!/bin/sh\nexec /usr/bin/env\n', { mode: 0o755 });
  // ⛔ A SENTINEL, NOT `debug`, AND NOT ABSENT. The question is whether the DRIVER exports the
  // variable, so the parent carries a value nothing else would produce: if the driver is quiet the
  // child still shows the sentinel, and if it sets debug the sentinel is overwritten. Seeding the
  // parent with `debug` instead — the first version of this test — made the assertion fire on the
  // value the test itself had injected, which proves nothing about the driver either way.
  const r = spawnSync('bash', ['-c', `set -e\nv=${JSON.stringify(v)}\nNUB=${JSON.stringify(stub)}\n${block}`],
    { encoding: 'utf8', env: { ...process.env, RUST_LOG: 'corpus-sentinel' } });
  assert.equal(r.status, 0, `the extracted pre-step did not run: ${r.stderr}`);
  const child = fs.readFileSync(path.join(v, 'security-resolve.log'), 'utf8');

  // Positive control: the child env really was captured, so an absence below means something.
  assert.match(child, /NUB_BUILD_JAIL_CATALOG=/,
    'the extracted block did not reach the child env at all — this test proves nothing');
  assert.match(child, /^RUST_LOG=corpus-sentinel$/m,
    'the sentinel did not survive into the child, so this test cannot tell a quiet driver from a '
    + 'noisy one');
  assert.doesNotMatch(child, /^RUST_LOG=debug$/m,
    'the security-resolve pre-step still exports RUST_LOG=debug, so a failure here dumps engine '
    + 'trace instead of nub\'s error — twice measured, on runs 33293351038 and 33299339164');
});

test('measure-macos.sh has never set debug on the pre-step, and still does not', () => {
  const lines = read('measure-macos.sh').split('\n');
  const i = lines.findIndex((l) => l.includes("install --ignore-scripts > '$v/security-resolve.log'"));
  assert.notEqual(i, -1, 'the security-resolve invocation was not found in measure-macos.sh');
  // The whole `sudo -u ... env ... sh -c "..."` statement, which is where an env would be spelled.
  const block = lines.slice(Math.max(0, i - 4), i + 1).join('\n');
  assert.match(block, /sudo -u/, 'the macOS pre-step no longer runs under sudo — the anchor moved');
  assert.doesNotMatch(block, /RUST_LOG/,
    'the macOS pre-step gained RUST_LOG; it is the driver whose dumps have always been readable');
});

test('measure-windows.mjs removes RUST_LOG from the pre-step env only', () => {
  const src = read('measure-windows.mjs');
  // ⛔ THE LAST ONE, NOT THE FIRST. `measure-windows.mjs` has TWO `run(NUB, ['install',
  // '--ignore-scripts'])` sites: the unjailed OBSERVE arm around line 400, whose `ARM_ENV` is PATH +
  // PYTHON and never carried RUST_LOG, and the verify pre-step near the end, which is this one. The
  // first anchor written here matched the OBSERVE arm and reported the fix missing.
  const i = src.lastIndexOf("run(NUB, ['install', '--ignore-scripts']");
  assert.notEqual(i, -1, 'the Windows security-resolve invocation was not found');
  assert.ok(src.slice(i, i + 300).includes('security-resolve.log'),
    'the anchor landed on an install that does not write security-resolve.log — wrong arm');
  const block = src.slice(Math.max(0, i - 900), i + 200);
  assert.match(block, /delete resolveEnv\.RUST_LOG/,
    'the Windows pre-step still inherits the arm env, which carries RUST_LOG=debug');
  assert.match(block, /env: resolveEnv/,
    'RUST_LOG is deleted from a copy that the invocation does not actually use');
});

test('the MEASURED arms still run under RUST_LOG=debug', () => {
  // The control that keeps the fix targeted. `side-effects-cache: restored` is a `tracing::debug!`,
  // so without debug on these arms the replay assertion cannot observe what it asserts on.
  const sh = read('measure.sh');
  const armDebug = sh.split('\n').filter((l) => /RUST_LOG=debug/.test(l) && /"\$NUB" (install|approve-builds)/.test(l));
  assert.ok(armDebug.length >= 2,
    `expected the install and approve-builds arms to keep RUST_LOG=debug, found ${armDebug.length}`);
  assert.match(read('measure-windows.mjs'), /RUST_LOG: 'debug'/,
    'the Windows arm env lost RUST_LOG=debug, so its replay predicate is now unfalsifiable');
});
