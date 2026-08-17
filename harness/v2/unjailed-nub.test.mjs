// The control decides whether a ladder of failures is a JAIL finding at all, so a wrong answer here
// mislabels every rung above it. Two directions matter and they mislead differently: a false PASS
// files a jail finding against a package the jail never touched, and a false FAIL buries a real jail
// defect as "not the jail". Both are pinned below.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  OFF_SWITCH_CLAIM, VERDICT, classify, offSwitchEngaged, uniqueRootName, writeFixture,
  unjailedNubOk, npmOk,
} from './unjailed-nub.mjs';

const engagedLog = `warning: pkg ${OFF_SWITCH_CLAIM} (install.buildJail is false in nub.jsonc)`;

test('nub installs it unjailed → the jail IS the difference', () => {
  const r = classify({ nub: { rc: 0, engaged: true } });
  assert.equal(r.verdict, VERDICT.noStatePassed);
});

test('nub fails unjailed but npm succeeds → a nub install defect, NOT an under-grant', () => {
  // ⛔ THE DISTINCTION THAT KEEPS THE CATALOG HONEST. This verdict must never read as "the package
  // needs more capabilities": the jail was OFF, so the ladder's failures say nothing about
  // capabilities and widening the catalog for it would grant reach nothing asked for.
  const r = classify({ nub: { rc: 1, engaged: true }, npm: { rc: 0 } });
  assert.equal(r.verdict, VERDICT.brokenUnjailedNub);
  assert.match(r.why, /not an under-grant/);
});

test('neither nub nor npm installs it → nothing to measure', () => {
  const r = classify({ nub: { rc: 1, engaged: true }, npm: { rc: 1 } });
  assert.equal(r.verdict, VERDICT.brokenWithoutJailToo);
});

test('⛔⛔ an off-switch that did not engage is a HARNESS ERROR, outranking any rc', () => {
  // THE FAILURE THIS MODULE EXISTS FOR. A cell whose off-switch never engaged ran JAILED, so its rc
  // describes the jail rather than its absence — and rc=0 would be read as "installs fine unjailed",
  // exonerating the jail using a jailed run as the evidence. v1 shipped exactly this for months.
  const passed = classify({ nub: { rc: 0, engaged: false } });
  assert.equal(passed.verdict, VERDICT.harnessError, 'rc=0 must NOT become a verdict');
  const failed = classify({ nub: { rc: 1, engaged: false }, npm: { rc: 0 } });
  assert.equal(failed.verdict, VERDICT.harnessError, 'and neither must rc=1, npm notwithstanding');
});

test('a timeout is its own outcome, never a failure', () => {
  // Calling a timeout a failure files a nub install defect for a package that merely compiles
  // slowly, and `BROKEN-UNJAILED-NUB` is the most misleading place for it to land.
  const r = classify({ nub: { rc: null, timedOut: true, engaged: true } });
  assert.equal(r.verdict, VERDICT.harnessTimeout);
});

test('a timeout outranks a disengaged off-switch, because nothing ran to completion', () => {
  const r = classify({ nub: { rc: null, timedOut: true, engaged: false } });
  assert.equal(r.verdict, VERDICT.harnessTimeout);
});

test('the off-switch claim is detected from the real notice text', () => {
  assert.equal(offSwitchEngaged({ i: engagedLog }), true);
  assert.equal(offSwitchEngaged({ i: 'installed 1 package' }), false, 'an ordinary log means it did NOT engage');
});

test('the per-package opt-out notice satisfies the SAME claim', () => {
  // Two different gates unconfine a script and they print different reasons. The control must accept
  // either, or a cell driven by the per-package opt-out would report a broken off-switch.
  const perPackage = `warning: pkg ${OFF_SWITCH_CLAIM} (allowBuilds has "pkg": "no-jail" in package.json)`;
  assert.equal(offSwitchEngaged({ a: perPackage }), true);
});

test('⛔ NO logs is `null`, not `false` — absence is not disproof', () => {
  // Conflating them files every unreadable cell as a broken off-switch, which is a flood of
  // HARNESS-ERROR rows that hides the real ones.
  assert.equal(offSwitchEngaged({}), null);
  assert.equal(offSwitchEngaged({ i: '   ' }), null);
  assert.equal(offSwitchEngaged(undefined), null);
  // And `null` must not trip the harness-error branch, which tests `=== false`.
  assert.equal(classify({ nub: { rc: 0, engaged: null } }).verdict, VERDICT.noStatePassed);
});

test('the root package name is unique per fixture, so a fixture cannot replay another arm', () => {
  assert.notEqual(uniqueRootName('verify-a1'), uniqueRootName('verify-b2'));
  assert.match(uniqueRootName('Verify-A1'), /^nsp[a-z0-9]+$/, 'and must be a legal package name');
});

test('the fixture states the switch and disables the side-effects cache', () => {
  // ⛔ ALL THREE REPLAY GUARDS OR THE CELL MEASURES NOTHING. Verified independently while testing the
  // nub side of this feature: a rerun with a warm cache showed the marker file present and no notice
  // printed, because the built tree was RESTORED and the lifecycle script never spawned. That is a
  // false PASS, and it looks exactly like a healthy run.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  writeFixture({ dir, pkg: 'left-pad', version: '1.0.0', seed: 'seed1' });
  assert.match(fs.readFileSync(path.join(dir, 'nub.jsonc'), 'utf8'), /"buildJail":\s*false/);
  assert.match(fs.readFileSync(path.join(dir, '.npmrc'), 'utf8'), /side-effects-cache=false/);
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  assert.equal(manifest.dependencies['left-pad'], '1.0.0');
  assert.notEqual(manifest.name, 'nsp', 'a FIXED root name is the replay hazard this guards');
});

test('the control stops at the first failing step and reports which one', async () => {
  const calls = [];
  const run = async ({ args }) => {
    calls.push(args[0]);
    return { rc: args[0] === 'install' && args.length === 1 ? 1 : 0, out: engagedLog };
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  const r = await unjailedNubOk({ nub: 'nub', pkg: 'p', version: '1.0.0', dir, run });
  assert.equal(r.rc, 1);
  assert.equal(r.step, 'i.log');
  assert.deepEqual(calls, ['install', 'install'], 'approve-builds must not run after install failed');
});

test('⛔ the off-switch is judged from the SCRIPT-RUNNING steps, not the --ignore-scripts one', async () => {
  // nub announces the decision not to confine once per package, AT SPAWN TIME. The
  // `--ignore-scripts` step spawns nothing, so it cannot carry the claim — judging from its log
  // would report every cell as a broken off-switch, i.e. blanket HARNESS-ERROR.
  const run = async ({ args }) => ({
    rc: 0,
    out: args.includes('--ignore-scripts') ? 'resolved 1 package' : engagedLog,
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  const r = await unjailedNubOk({ nub: 'nub', pkg: 'p', version: '1.0.0', dir, run });
  assert.equal(r.rc, 0);
  assert.equal(r.engaged, true, 'the claim is in i.log/a.log, which is where it must be read from');
});

test('⛔ a package with NO lifecycle script cannot testify — that is `null`, not a broken off-switch', () => {
  // Grounded in a live run: nub prints "No ignored builds to approve." for a tree with nothing to
  // approve. Reading that silence as a broken off-switch turns every script-less cell into a
  // HARNESS-ERROR, and that flood is what hides the real ones.
  assert.equal(offSwitchEngaged({ a: 'No ignored builds to approve.' }), null);
  assert.equal(classify({ nub: { rc: 0, engaged: null } }).verdict, VERDICT.noStatePassed);
});

test('⛔ a FETCH failure leaves the off-switch unknowable, so it is not a harness error', async () => {
  // The asymmetry that matters: nub ignores build scripts pending approval, so neither the resolve
  // step nor the plain install spawns one. Nothing could have printed the claim, and reporting
  // `false` would file HARNESS-ERROR for a fetch failure whose verdict the npm arm decides.
  const run = async () => ({ rc: 1, out: 'ERR_PNPM_FETCH_404  GET https://registry.npmjs.org/nope' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  const r = await unjailedNubOk({ nub: 'nub', pkg: 'nope', version: '9.9.9', dir, run });
  assert.equal(r.step, 'security-resolve.log');
  assert.equal(r.engaged, null, 'a log that could never carry the claim must not disprove it');
  assert.equal(
    classify({ nub: r, npm: { rc: 1 } }).verdict,
    VERDICT.brokenWithoutJailToo,
    'so it falls through to the real verdict rather than HARNESS-ERROR',
  );
});

test('⛔⛔ but approve-builds failing WITHOUT the claim IS a broken off-switch', async () => {
  // That step is the one that actually runs the scripts. If it ran them and the claim never
  // appeared, the cell ran JAILED and its rc describes the jail rather than its absence.
  const run = async ({ args }) => (args[0] === 'approve-builds'
    ? { rc: 1, out: 'Approved 1 package(s) in package.json:\n  pkg\ngyp ERR! not ok' }
    : { rc: 0, out: 'installed 1 package' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  const r = await unjailedNubOk({ nub: 'nub', pkg: 'p', version: '1.0.0', dir, run });
  assert.equal(r.step, 'a.log');
  assert.equal(r.engaged, false, 'scripts ran and the claim is absent — the switch did not engage');
  assert.equal(classify({ nub: r, npm: { rc: 0 } }).verdict, VERDICT.harnessError);
});

test('the security screen runs on the RESOLVED tree, before anything executes', async () => {
  // ⛔ THE WINDOW IS THE POINT. After `--ignore-scripts` the tree is materialised and no script has
  // touched it; screening any later is screening the aftermath. It is injected because each driver
  // already has its own screen and they are not interchangeable — and a rewire that quietly dropped
  // it would remove a safety property while every verdict stayed identical.
  const order = [];
  const run = async ({ args }) => { order.push(`run:${args.join(' ')}`); return { rc: 0, out: engagedLog }; };
  const screen = async ({ label }) => { order.push(`screen:${label}`); };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  await unjailedNubOk({ nub: 'nub', pkg: 'p', version: '1.0.0', dir, run, screen });
  assert.deepEqual(order, [
    'run:install --ignore-scripts',
    'screen:nub-unjailed-resolved',
    'run:install',
    'run:approve-builds --all',
  ]);
});

test('a resolve failure does not screen a tree that was never materialised', async () => {
  const order = [];
  const run = async () => { order.push('run'); return { rc: 1, out: 'E404' }; };
  const screen = async () => { order.push('screen'); };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-'));
  await unjailedNubOk({ nub: 'nub', pkg: 'p', version: '1.0.0', dir, run, screen });
  assert.deepEqual(order, ['run'], 'screening a failed resolve would scan nothing and claim it clean');
});

test('the npm arm installs BEFORE rebuilding, so rebuild cannot no-op to success', async () => {
  // ⛔ `npm rebuild <pkg>` ON A TREE WHERE THE PACKAGE IS NOT INSTALLED EXITS 0. That false success
  // is what made the harness's older control unsound, and it is why this arm owns a fresh directory
  // and installs into it first.
  const seen = [];
  const run = async ({ args }) => { seen.push(args.join(' ')); return { rc: 0, out: '' }; };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-npm-'));
  const r = await npmOk({ pkg: 'p', version: '1.0.0', dir, run });
  assert.equal(r.rc, 0);
  assert.equal(seen.length, 2);
  assert.match(seen[0], /^install .*--ignore-scripts p@1\.0\.0$/);
  assert.match(seen[1], /^rebuild/);
  assert.ok(!/rebuild.* p(@|$)/.test(seen[1]), 'rebuild must cover the WHOLE tree, not just the target');
});

test('a failed npm fetch does not go on to rebuild', async () => {
  const seen = [];
  const run = async ({ args }) => { seen.push(args[0]); return { rc: 1, out: 'E404' }; };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ujn-npm-'));
  const r = await npmOk({ pkg: 'nope', version: '9.9.9', dir, run });
  assert.equal(r.rc, 1);
  assert.deepEqual(seen, ['install'], 'rebuilding an unfetched tree would exit 0 and read as success');
});
