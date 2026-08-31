// ⛔⛔ THE HARNESS MUST NOT CONVICT NUB OF ITS OWN ASYMMETRY. FALSE-ATTRIBUTION GUARD.
//
// The jail-off control compares two arms and names a culprit. `unjailed-nub.mjs` states the doctrine
// in its own comments: "a spurious failure here does not exonerate nub, it CONVICTS it." It has been
// fixed for that class TWICE — epoch 4 gave the npm reference the era toolchain, epoch 13 gave it the
// era Python, and a later fix gave the plain-spawn path the era Node.
//
// The DATING axis is the third instance and it is the one that cannot be closed by equalising the
// arms. The npm reference resolves with `--before <the package's publish date + 1d>` (`measure.sh`);
// the nub arm cannot, because nub has no `--before` and `minimumReleaseAge` is a FLOOR on a package's
// age rather than a ceiling on its publish date. So the nub arm always resolves TODAY's dependency
// tree onto an ERA Node, and that difference was being filed as `BROKEN-UNJAILED-NUB`.
//
// MEASURED 2026-08-31: 27 records currently VALID in the corpus carry that verdict, and
// `spectron@11.1.0` / `spectron@12.0.0` are already PROVEN fabricated by exactly this mechanism. The
// remainder are almost entirely 2016-2018 native packages — `@stdlib/math-base-*@0.0.x`, `gc-stats`,
// `lzo`, `hiredis`, `farmhash`, `nodejieba`, `node-zopfli`, `lzma-native` — the precise profile where
// today's dependency tree cannot build on the package's own era Node.
//
// The control is therefore INVERTED: ask npm to fail the same way, undated.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { classify, VERDICT } from './unjailed-nub.mjs';

const HERE = import.meta.dirname;
const NUB_FAILED = { rc: 1, engaged: true };

test('npm failing UNDATED exonerates nub — the difference is the date, not nub', () => {
  const r = classify({ nub: NUB_FAILED, npm: { rc: 0 }, npmUndated: { rc: 1 } });
  assert.equal(r.verdict, VERDICT.unknown,
    'npm installs it dated and fails undated, which is the condition the nub arm ran under — naming '
    + 'nub here is a false attribution');
  assert.match(r.why, /not attributable to nub/);
});

// ⛔ THE CONTROL, AND IT IS THE HALF THAT MATTERS. A real nub install defect must still be reported.
// Blanket-exonerating would destroy the whole point of this arm — it exists to find nub bugs — and
// that is the mirror image of the mistake being fixed. Pinned from the start, because epoch 44 shipped
// exactly this shape in the other direction and epoch 45 had to undo it.
test('npm succeeding UNDATED still convicts nub — a real install defect is still reported', () => {
  const r = classify({ nub: NUB_FAILED, npm: { rc: 0 }, npmUndated: { rc: 0 } });
  assert.equal(r.verdict, VERDICT.brokenUnjailedNub,
    'npm installs this package undated too, so the date is NOT the difference and nub is at fault');
});

test('an unasked second arm changes nothing — `undefined` means NOT ASKED, never PASSED', () => {
  // A driver that has not been taught to run the undated arm keeps the old behaviour rather than
  // silently gaining an exoneration it never measured. Same when there is no `--before` to drop.
  assert.equal(classify({ nub: NUB_FAILED, npm: { rc: 0 } }).verdict, VERDICT.brokenUnjailedNub);
  assert.equal(classify({ nub: NUB_FAILED, npm: { rc: 1 }, npmUndated: { rc: 1 } }).verdict,
    VERDICT.brokenWithoutJailToo,
    'npm failing even DATED means nothing installs it; the undated arm must not override that');
});

test('the earlier clauses still outrank it — soundness and the nub-succeeds case come first', () => {
  // The order of clauses is the contract: an unsound control's rc is not evidence of anything.
  assert.equal(classify({ nub: { rc: 1, engaged: false }, npm: { rc: 0 }, npmUndated: { rc: 1 } }).verdict,
    VERDICT.harnessError, 'a control that ran jailed must not be reclassified by the dating arm');
  assert.equal(classify({ nub: { rc: 1, timedOut: true }, npm: { rc: 0 }, npmUndated: { rc: 1 } }).verdict,
    VERDICT.harnessTimeout);
  assert.equal(classify({ nub: { rc: 0, engaged: true }, npm: { rc: 0 }, npmUndated: { rc: 1 } }).verdict,
    VERDICT.noStatePassed, 'nub succeeding unjailed is a jail finding and the dating arm is irrelevant');
});

test('the CLI carries the third value through to the printed verdict', () => {
  // Executed, not asserted structurally: `record.mjs` matches the `=> ` token, so a driver passing
  // `dating` must actually PRINT `UNKNOWN` and not merely compute it.
  const run = (npm) => execFileSync('node',
    [path.join(HERE, 'unjailed-nub.mjs'), '--phase', 'verdict', '--npm', npm],
    { encoding: 'utf8' });
  const dating = (() => { try { return run('dating'); } catch (e) { return e.stdout ?? ''; } })();
  assert.match(dating, /=> UNKNOWN/, '`--npm dating` does not print UNKNOWN');
  assert.match(dating, /nub has no `--before`/);
  const ok = (() => { try { return run('ok'); } catch (e) { return e.stdout ?? ''; } })();
  assert.match(ok, /=> BROKEN-UNJAILED-NUB/, '`--npm ok` stopped convicting nub');
  const fail = (() => { try { return run('fail'); } catch (e) { return e.stdout ?? ''; } })();
  assert.match(fail, /=> BROKEN-WITHOUT-JAIL-TOO/);
});

for (const driver of ['measure.sh', 'measure-macos.sh']) {
  test(`${driver} runs the undated arm, and ONLY when there is a date to drop`, () => {
    // Structural: the second arm needs a registry and an era Node. What is pinned is that the driver
    // asks at all, that it is gated on `ERA_BEFORE` being non-empty (asking twice with no date to
    // drop costs an install and answers nothing), and that the result reaches the module.
    const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
    const at = src.indexOf('NPM_VERDICT=ok');
    assert.notEqual(at, -1, `${driver}: the undated npm arm is gone`);
    const branch = src.slice(at, at + 900);
    assert.match(branch, /if \[ -n "\$\{ERA_BEFORE:-\}" \]; then/,
      `${driver}: the undated arm is not gated on there being a date to drop`);
    assert.match(branch, /ERA_BEFORE=""; npm_ok/,
      `${driver}: the second arm does not actually drop the date`);
    assert.match(branch, /NPM_VERDICT=dating/, `${driver}: the dating outcome is never produced`);
    assert.match(branch, /--npm "\$NPM_VERDICT"/,
      `${driver}: the outcome is computed and then not passed to the module`);
  });
}

test('the windows driver asks the same question', () => {
  // Structural for the same reason as its half of `subject-survives-scaffold.test.mjs`: running this
  // driver end to end needs an ETW capture and a Windows host.
  const win = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(win, /const npmOk = \(\{ dated = true \} = \{\}\) =>/,
    'measure-windows.mjs npmOk can no longer be asked to drop the date');
  assert.match(win, /filter\(\(a\) => !String\(a\)\.startsWith\('--before'\)\)/,
    'measure-windows.mjs does not actually drop the --before argument');
  const at = win.indexOf('const npmDated = npmOk();');
  assert.notEqual(at, -1, 'measure-windows.mjs no longer runs the dated arm separately');
  const branch = win.slice(at, at + 1200);
  assert.match(branch, /if \(npmDated && hasDate\)/,
    'the undated arm is not gated on npm having succeeded WITH the date and there being one to drop');
  assert.match(branch, /npmUndated \}\);/, 'the second arm never reaches classify');

  // ⛔ AND IT MUST NOT HAVE BROKEN THE FIVE-LINE WINDOW. `measure-windows.mjs`'s own comment records a
  // guard that scans FORWARD from the verdict line to the exit; a comment block parked between them
  // once tripped it. The new work is computed ABOVE the verdict line for exactly that reason.
  const verdictAt = win.indexOf('console.log(`  => ${verdict}`);');
  assert.notEqual(verdictAt, -1);
  const after = win.slice(verdictAt).split('\n').slice(0, 6).join('\n');
  assert.match(after, /emitBinaryProvenance\(\)/,
    'the provenance call no longer sits within five lines of the verdict');
});
