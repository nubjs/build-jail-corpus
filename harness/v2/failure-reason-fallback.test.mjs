// ⛔ A FAILURE WITH NO VERDICT MARKER IS THE ONE WHOSE LOG IS THE ONLY EVIDENCE — AND IT PRINTED NOTHING.
//
// `record.mjs:794` assigns `HARNESS-ERROR` as a FALLBACK: no verdict marker matched anywhere in the
// driver log, so the driver died before printing one. `show_failure_reason` greps for `=> HARNESS-`,
// which for that class matches nothing — and the old form piped the empty match straight to `sed`, so
// the publisher emitted no reason, and not the "no driver log stashed" line either, because the log is
// present. The reader saw a WITHHELD line, a Parked line, and silence.
//
// MEASURED on run 33293351038 (the first epoch-30 slice): 4 of the 11 withheld instrument failures did
// exactly that — `@aws-amplify/cli` 1.12.0, 2.0.0 and 3.9.0, and `@nuxt/content@3.0.0-alpha.3`. They
// ran 51-137 s, so no timeout explains them, and the runner was destroyed with the only copy of the log.
//
// The tests EXECUTE the real function rather than reading its source: the whole lesson of epoch 29 is
// that a source assertion passes for code that does nothing. The second test is the control — the
// pre-fix body is reconstructed from this file and must still go silent on the same input, so a
// regression cannot hide behind the first test passing.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const here = import.meta.dirname;
const PUBLISHER = path.join(here, 'publish-record-v2.sh');

/// The real `show_failure_reason`, lifted out of the publisher so it can be run without running the
/// publisher. Anchored on the function header and closed on the first column-0 `}`.
function extractFunction(name) {
  const lines = fs.readFileSync(PUBLISHER, 'utf8').split('\n');
  const start = lines.findIndex((l) => l.startsWith(`${name} () {`));
  if (start === -1) return null;
  const end = lines.findIndex((l, i) => i > start && l === '}');
  return end === -1 ? null : lines.slice(start, end + 1).join('\n');
}

/// Runs a shell function body against a stash holding `log`, and returns what it wrote to stderr.
function runReason(body, log) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'failure-reason-'));
  fs.mkdirSync(path.join(dir, 'rec'), { recursive: true });
  if (log !== null) fs.writeFileSync(path.join(dir, 'rec', '.driver.out'), log);
  const r = spawnSync('bash', ['-c', `STASH=${JSON.stringify(dir)}\n${body}\nshow_failure_reason`],
    { encoding: 'utf8' });
  assert.equal(r.status, 0, `the reason printer must never fail the publish: ${r.stderr}`);
  return r.stderr;
}

/// A driver that died without ever printing `=> HARNESS-...`. This is the shape of all four measured
/// cases: real output, a real cause in it, and no marker for a grep to anchor on.
///
/// It is 40 lines DELIBERATELY, with the cause 9 from the end. A five-line sample cannot tell `tail -2`
/// from `tail -30` — both keep the cause — so the depth assertion below passed for a printer truncated
/// to two lines, which is a test that cannot fail. Real driver logs are hundreds of lines; the sample
/// has to be deeper than the window to measure the window at all.
const NO_MARKER = [
  '  era node: v10.24.1',
  '  ARM-PREPARE ok',
  ...Array.from({ length: 28 }, (_, i) => `  npm http fetch GET 200 https://registry.npmjs.org/pkg-${i}`),
  '  npm ERR! code EBADENGINE',
  '  npm ERR! notsup Unsupported engine for @aws-amplify/cli@2.0.0',
  ...Array.from({ length: 7 }, (_, i) => `  npm ERR! A complete log of this run: /tmp/eresolve-${i}.txt`),
  'the last line, which a tail must reach',
].join('\n');

const WITH_MARKER = [
  '  era node: v22.23.2',
  '  => HARNESS-ERROR: Nub could not materialize the tree with --ignore-scripts',
  "  ── nub's own words (tail of security-resolve.log) ──",
  '     ERR_NUB_TRUST_DOWNGRADE',
].join('\n');

test('the printer is never silent about a marker-less failure', () => {
  const body = extractFunction('show_failure_reason');
  // Control: without this the assertions below pass vacuously the moment the function is renamed.
  assert.ok(body, 'show_failure_reason not found in publish-record-v2.sh — this test asserts nothing');
  const out = runReason(body, NO_MARKER);
  assert.match(out, /WHY:/,
    'a HARNESS-ERROR with no verdict marker printed NO reason at all — the exact hole run 33293351038 '
    + 'left in four packages, whose logs died with the runner');
  assert.match(out, /Unsupported engine/, 'the cause was in the log and did not reach the reader');
  assert.match(out, /the last line, which a tail must reach/, 'the tail did not reach the end of the log');
});

test('the pre-fix body goes silent on the same input', () => {
  // Verbatim epoch-28..31 body. If the fix is reverted, the first test must fail — this proves the
  // input discriminates, rather than being one the old code would have handled anyway.
  const old = 'show_failure_reason () {\n'
    + '  [ -f "$STASH/rec/.driver.out" ] || { echo "     (no driver log stashed)" >&2; return 0; }\n'
    + "  grep -aA 14 -E '=> HARNESS-' \"$STASH/rec/.driver.out\" | tail -30 | sed 's/^ */     WHY: /' >&2 || true\n"
    + '}';
  assert.equal(runReason(old, NO_MARKER), '',
    'the reconstructed pre-fix body printed something, so it is not the code the fix replaced and '
    + 'this control proves nothing');
});

test('a marked failure still reports the marker and the lines under it', () => {
  const out = runReason(extractFunction('show_failure_reason'), WITH_MARKER);
  assert.match(out, /could not materialize the tree/, 'the marker line was lost');
  assert.match(out, /ERR_NUB_TRUST_DOWNGRADE/,
    "nub's own words under the marker are the difference between a class and a cause");
  assert.doesNotMatch(out, /era node/,
    'the marked path must stay anchored on the marker, not degrade into a plain tail');
});

test('a missing driver log still says so', () => {
  const out = runReason(extractFunction('show_failure_reason'), null);
  assert.match(out, /no driver log stashed/,
    'an absent log and a log with no marker are different facts and must read differently');
});
