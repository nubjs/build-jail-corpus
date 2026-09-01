// The win32 driver's PER-RUN npm CACHE: that the directory it REDIRECTS npm to is the same one it
// DECLARES as a root, from one constant, so the two cannot drift.
//
// ⛔ WHY THIS IS A SEPARATE FILE FROM `classify.test.mjs`. That file pins the CLASSIFIER half —
// given a declared `npmCache` root, which bucket a path lands in and what it earns. This one pins
// the DRIVER half, and the two fail differently and independently. A classifier that reads the
// right bucket against a root nothing was ever redirected to produces an EMPTY bucket, which is
// byte-identical to a package whose script never shelled out to npm; the record then reads as a
// measured zero rather than as a redirect nobody declared. Same shape, and the same argument, as
// `win-jail-home.test.mjs` makes for the private home.
//
// ⛔ THE DEFECT THIS EXISTS TO STOP HAPPENING AGAIN. `OBS_ENV` set `npm_config_cache` at
// `<run-root>\npm-cache` from the day the OBSERVE arm was given a cold cache, and `capture.json`
// declared no root for it. That directory is a SIBLING of `observe`, `tmp` and `jailhome`, so every
// write npm made under it fell through to `outside` — the classifier billing its own apparatus as a
// write it could not account for. MEASURED on the committed corpus before the fix: of the 805
// `outside` write paths the 135 win32 records with an `outside` row print, 728 were under this
// directory. `outside` exists to surface a genuinely surprising write, and at ~90% noise it could
// not do that job.
//
// ⛔ AND THE DRIVER CANNOT BE RUN HERE — it is Windows-only end to end, so this asserts against its
// SOURCE, in the extraction idiom `win-jail-home.test.mjs` uses.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const DRIVER = path.join(import.meta.dirname, 'measure-windows.mjs');
const src = fs.readFileSync(DRIVER, 'utf8');

// ⛔ `assert.ok(re.test(src), …)` RATHER THAN `assert.match(src, re)`, DELIBERATELY. `assert.match`
// embeds the SUBJECT in its failure output, and the subject here is a 170 KB driver — so a failure
// buries its own one-line explanation under the whole file. Measured while writing the red control
// for this test. The message below is the entire diagnosis, which is the point.
const declares = (re) => re.test(src);

test('the driver declares the npm cache it redirects to, from the same constant', () => {
  // ONE definition. The redirect and the declaration must name the same binding, because a literal
  // retyped on either side is a second spelling of one path — and `dep-scaffold.mjs` records what
  // happened the last time this harness grew one of those.
  assert.ok(declares(/^const NPM_CACHE = path\.join\(ROOT, 'npm-cache'\);$/m),
    'the per-run npm cache is no longer a single named constant `NPM_CACHE = ROOT/npm-cache`');
  assert.ok(declares(/^\s*npm_config_cache: NPM_CACHE,$/m),
    'OBS_ENV must redirect npm at the NPM_CACHE constant, not at a retyped literal');
  // ⛔ PINNED TO `NPM_CACHE` BY NAME, WHICH IS ALSO WHAT KEEPS THE ROOT A LEAF. The two ways to get
  // this wrong are `null` — a false answer, since this driver DOES redirect — and `ROOT`, which
  // would make the free bucket swallow `observe`, `tmp` and `jailhome` wholesale, project tree
  // included, and the project tree's writes ARE the grant. Both are refused by requiring the
  // constant rather than by listing them: a separate `doesNotMatch` for each would be a case that
  // cannot fail on its own, since this line already forbids every other value. Verified by making
  // each substitution in turn and watching THIS assertion go red.
  assert.ok(declares(/^\s*npmCache: NPM_CACHE,$/m),
    'capture.json must DECLARE `npmCache: NPM_CACHE` — the same directory the driver redirects npm '
    + 'to. Undeclared, every write npm makes there falls through to `outside`.');
});
