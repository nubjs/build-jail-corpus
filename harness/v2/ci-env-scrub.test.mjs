// The CI-detection scrub, and the guard that keeps its key list identical across all three drivers.
//
// ⛔ THE DEFECT. A package that branches on `CI` runs LESS code on a runner, so a CI-measured record
// omits capabilities a developer hits — an under-grant, the one direction this project forbids. v1
// has scrubbed this family since its own sweeps (`tests/build-jail-search/search.mjs`); v2 did not,
// so every v2 record measured on a runner carried it.
//
// MEASURED on the corpus VM, reproducing the research lane's `node:22-slim` result exactly:
//   CI unset -> core-js@3.50.0 writes $TMPDIR/core-js-banners
//   CI=1     -> it writes NOTHING
//
// ⛔ WHY THE LIST IS DUPLICATED AT ALL. The POSIX drivers SOURCE `ci-env-scrub.sh`; Windows cannot
// source a shell file, so `measure-windows.mjs` mirrors the list in JS. The mirror is the risk, and
// the cross-driver test below is what makes it safe — a family that drifts apart per-driver is the
// same defect class as the four half-wired markers found today.

import { test, test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ⛔ SKIPPED ON WINDOWS — BUT ONLY THE CASES THAT EXECUTE `bash`, NOT THE FILE. MEASURED on the
// corpus Windows VM: `where bash` finds nothing and no Git-for-Windows `bash.exe` exists, so the
// five `runScrub` cases die `spawnSync bash ENOENT` — a failure that says nothing about the scrub.
// 14 of the 20 cases across this file and `measure-provenance.test.mjs` fail for exactly that.
//
// ⛔ A FILE-LEVEL SKIP WOULD COST THE ONE CASE THIS FILE EXISTS FOR ON THIS PLATFORM. The four
// cases above `runScrub` only read source text, pass on Windows today, and include the cross-driver
// check that `measure-windows.mjs`'s MIRRORED `CI_KEYS` list still matches `ci-env-scrub.sh`. That
// mirror is a Windows-only hazard — the POSIX drivers source the shell file and cannot drift — so
// skipping the whole file would disarm the drift guard precisely where drift is possible.
// `measure-r7.test.mjs` skips at file level correctly: every one of its cases drives bash.
//
// ⛔ A SKIP IS NOT A PASS, so it is spelled as one and carries its reason into the TAP output.
const SHELL_SKIP = process.platform === 'win32'
  ? 'no bash on Windows: this case executes the shared scrub as a shell script'
  : false;
const shellTest = (name, fn) => nodeTest(name, { skip: SHELL_SKIP }, fn);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

/** Run the shared scrub with a chosen environment and report what it did. */
const runScrub = (env) => {
  const script = `set -u\n. '${path.join(HERE, 'ci-env-scrub.sh')}'\n`
    + 'echo "SCRUBBED=[$CI_SCRUBBED]"\n'
    + 'printf "INHERITED=[%s]\\n" "$(printf %s "$CI_INHERITED" | tr "\\n" ",")"\n'
    + 'echo "CI_NOW=[${CI-<unset>}]"\n';
  return execFileSync('bash', ['-c', script], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });
};

// ── The key list must be the SAME in all three drivers ────────────────────────────────────────────

const shellKeys = () => {
  const m = /CI_KEYS="([^"]+)"/.exec(read('ci-env-scrub.sh'));
  assert.ok(m, 'ANCHOR DRIFT: ci-env-scrub.sh no longer defines CI_KEYS');
  return m[1].trim().split(/\s+/);
};

const windowsKeys = () => {
  const m = /const CI_KEYS = \[([^\]]+)\]/.exec(read('measure-windows.mjs'));
  assert.ok(m, 'ANCHOR DRIFT: measure-windows.mjs no longer defines CI_KEYS');
  return m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
};

test('INSTRUMENT: both key extractors find a plausible list', () => {
  // Without this, "the lists are equal" is satisfied by two empty arrays.
  assert.ok(shellKeys().length >= 10, `the shell extractor found ${shellKeys().length} keys — it is broken`);
  assert.ok(windowsKeys().length >= 10, `the Windows extractor found ${windowsKeys().length} keys — it is broken`);
  assert.ok(shellKeys().includes('CI'), 'the shell list must contain CI');
});

test('all three drivers scrub the SAME CI key family', () => {
  // The POSIX pair share one file by construction; Windows mirrors it, and this is the mirror check.
  assert.deepEqual(windowsKeys(), shellKeys(),
    'the Windows CI key list has drifted from ci-env-scrub.sh — a package would be scrubbed on one platform and not another');
});

test('both POSIX drivers SOURCE the shared scrub rather than copying it', () => {
  for (const d of ['measure.sh', 'measure-macos.sh']) {
    assert.match(read(d), /\.\s+"\$HERE\/ci-env-scrub\.sh"/,
      `${d} does not source ci-env-scrub.sh, so its list can drift`);
  }
});

test('the v1 list is matched exactly, so the two harnesses cannot disagree about what "CI" means', () => {
  // v1 is the reference: it has been scrubbing this family across full sweeps for far longer. The
  // file is `harness/search.mjs` in this repo (the nub tree spells the same file
  // `tests/build-jail-search/search.mjs`).
  const v1 = read("../search.mjs");
  const m = /for \(const k of \[([^\]]+)\]\)\s*\{\s*\n\s*delete env\[k\];/.exec(v1);
  assert.ok(m, 'ANCHOR DRIFT: v1 search.mjs no longer has the CI delete loop');
  const v1Keys = m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
  assert.deepEqual(shellKeys(), v1Keys, 'v2 scrubs a different set than v1');
});

// ── Behaviour ─────────────────────────────────────────────────────────────────────────────────────

shellTest('the family is scrubbed by default, and what was removed is reported', () => {
  const out = runScrub({ CI: 'true', GITHUB_ACTIONS: 'true', TRAVIS: '1' });
  assert.match(out, /CI_NOW=\[<unset>\]/, `CI must be gone from the environment:\n${out}`);
  for (const k of ['CI', 'GITHUB_ACTIONS', 'TRAVIS']) {
    assert.match(out, new RegExp(`SCRUBBED=\\[[^\\]]*${k}`), `${k} must be reported as scrubbed:\n${out}`);
  }
});

shellTest('⛔ the ORIGINAL values are captured BEFORE the scrub, or a CI record claims it was not CI', () => {
  // The subtle half. If `passedThrough` were read after the scrub, a real runner would file
  // `CI: null` — asserting the venue was not CI precisely because we removed the proof.
  const out = runScrub({ CI: 'true', GITHUB_ACTIONS: 'true' });
  assert.match(out, /INHERITED=\[[^\]]*CI=true/, `the venue's real CI value must survive:\n${out}`);
  assert.match(out, /INHERITED=\[[^\]]*GITHUB_ACTIONS=true/, `and so must GITHUB_ACTIONS:\n${out}`);
});

shellTest('NUB_CORPUS_CI_ENV=inherit keeps the axis MEASURABLE instead of normalising it away', () => {
  // This is what separates the scrub from the one-line `CI=1` that VENUE-PORTABILITY.md forbids:
  // that hides the axis and leaves one state unmeasured, this measures both and records which.
  const out = runScrub({ CI: 'true', NUB_CORPUS_CI_ENV: 'inherit' });
  assert.match(out, /CI_NOW=\[true\]/, `inherit must leave the real CI path intact:\n${out}`);
  assert.match(out, /SCRUBBED=\[\]/, `and must scrub nothing:\n${out}`);
});

shellTest('CONTROL: on a developer machine with nothing set, the scrub is a no-op and stays silent', () => {
  const out = runScrub({});
  assert.match(out, /SCRUBBED=\[\]/, `nothing to scrub must report nothing:\n${out}`);
  assert.match(out, /INHERITED=\[\]/, `and capture nothing:\n${out}`);
  assert.doesNotMatch(out, /CI-ENV scrubbed/, 'a no-op must not print a scrub line');
});

shellTest('⛔ the scrub REMOVES rather than setting a falsy value', () => {
  // MEASURED and load-bearing: the value semantics are inconsistent across packages. `ci-info` reads
  // `CI=0` as CI-ON while `core-js` reads it as CI-OFF, so no value means "not CI" to everyone —
  // only absence does. A future "simplification" to `CI=0` or `CI=""` would silently re-open this.
  const out = runScrub({ CI: 'true' });
  assert.match(out, /CI_NOW=\[<unset>\]/, `CI must be UNSET, not blanked:\n${out}`);
  assert.doesNotMatch(out, /CI_NOW=\[\]/, 'an empty CI still reads as CI to ci-info');
});
