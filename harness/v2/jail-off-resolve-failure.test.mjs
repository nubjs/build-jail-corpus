// ⛔ "NUB CANNOT RESOLVE IT UNJAILED" IS A MEASUREMENT. FILING IT AS A BROKEN INSTRUMENT LOSES IT.
//
// `unjailed_nub_ok` runs `unjailed-nub.mjs --phase resolve` first. That phase deliberately prints NO
// verdict — its own comment explains why: a `=>` emitted before the security screen could be
// overwritten, and `record.mjs` takes the LAST match. The caller then did `|| return 1`, while the
// branch that reads its exit code says "any other non-zero code means the module already printed the
// verdict". For this one code that was false, so the driver ended with no verdict marker anywhere and
// `record.mjs:794` fell back to `HARNESS-ERROR`.
//
// MEASURED on run 33309505516: `botframework-connector@4.0.0-m1.5` climbed the whole ladder, failed
// every rung, reached this control, printed `jail-off control: resolved as nspjailoffcontrol (rc=1)`
// and then stopped. It was the last withheld package the harness itself could fix — the other four
// were three nub resolver bugs and one real timeout.
//
// 3 is the correct code because it routes to the branch that ASKS NPM, which ends in
// `BROKEN-UNJAILED-NUB` (npm manages it, so nub is at fault) or `BROKEN-WITHOUT-JAIL-TOO` (nothing
// installs it). Both are measurements. `HARNESS-ERROR` is neither, and it also costs three retries.
//
// The tests EXECUTE the real function, lifted out of the driver with `node` and the screen stubbed.
// The ladder suites cannot cover this: they stub `unjailed_nub_ok` wholesale, so its interior is
// exactly the region no existing test can reach.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const here = import.meta.dirname;

/// The real `unjailed_nub_ok`, anchored on its header and closed on the first column-0 `}`.
function extractFunction() {
  const lines = fs.readFileSync(path.join(here, 'measure.sh'), 'utf8').split('\n');
  const start = lines.findIndex((l) => l.startsWith('unjailed_nub_ok () {'));
  if (start === -1) return null;
  const end = lines.findIndex((l, i) => i > start && l === '}');
  return end === -1 ? null : lines.slice(start, end + 1).join('\n');
}

/// Runs the extracted function with `node` stubbed to fail (or not) on the resolve phase.
/// Returns { rc, out } for the whole call.
function runControl({ resolveFails }) {
  const body = extractFunction();
  assert.ok(body, 'unjailed_nub_ok not found in measure.sh — the anchor moved and this asserts nothing');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'jail-off-'));
  const script = [
    'set -u',
    `ROOT=${JSON.stringify(root)}`,
    'HERE=/nonexistent  NUB=/nonexistent  ARM_PATH="$PATH"',
    // `node` is the only thing the function shells out to besides the screen. The resolve phase is
    // identified by its own flag rather than by call order, so re-ordering the phases cannot make
    // this stub answer the wrong question.
    `node () { case "$*" in *"--phase resolve"*) return ${resolveFails ? 1 : 0} ;;`,
    '                     *"--phase run"*) echo "  => NO-STATE-PASSED"; return 0 ;;',
    '                     *) return 0 ;; esac; }',
    'security_screen_tree () { :; }',
    body,
    'unjailed_nub_ok demo 1.0.0',
    'echo "RC=$?"',
  ].join('\n');
  const r = spawnSync('bash', ['-c', script], { encoding: 'utf8' });
  fs.rmSync(root, { recursive: true, force: true });
  const m = /RC=(\d+)/.exec(r.stdout ?? '');
  assert.ok(m, `the extracted function did not run to completion: ${r.stderr}`);
  return { rc: Number(m[1]), out: r.stdout };
}

test('a failed resolve returns 3 (ask npm), not 1', () => {
  const { rc, out } = runControl({ resolveFails: true });
  assert.equal(rc, 3,
    'a resolve failure returned 1, which the caller reads as "the module already printed a verdict" — '
    + 'it did not, so the driver ends with no verdict marker and record.mjs files HARNESS-ERROR');
  assert.match(out, /asking npm before naming a culprit/,
    'the control must say WHY it is handing back, or the driver log records a silent hand-off');
});

test('a successful resolve still proceeds to the run phase', () => {
  // The control that keeps the fix targeted: routing EVERY outcome to 3 would send packages nub
  // installs fine to the npm arm, which is a different wrong answer.
  const { rc, out } = runControl({ resolveFails: false });
  assert.equal(rc, 0, 'a successful resolve must run the second phase and return its result');
  assert.match(out, /NO-STATE-PASSED/, 'the run phase did not execute after a successful resolve');
  assert.doesNotMatch(out, /asking npm before naming a culprit/,
    'the hand-back line leaked onto the success path');
});

test('the caller routes 3 to the npm arm', () => {
  // The fix is only worth anything if 3 lands somewhere. Asserted against the driver source because
  // the branch itself runs a real npm install.
  const src = fs.readFileSync(path.join(here, 'measure.sh'), 'utf8');
  assert.match(src, /if \[ "\$NSP_RC" -eq 3 \]; then/,
    'nothing consumes exit 3, so the resolve failure now returns a code no branch handles');
});
