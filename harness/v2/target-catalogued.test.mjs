// The assertion that an arm's catalog names the package the arm is about to measure.
//
// ⛔ THE FIRST TEST IS A NEGATIVE CONTROL AND IT IS THE ONLY REASON THE REST MEAN ANYTHING. It
// reconstructs the exact `dep-scaffold.mjs` line that shipped on `origin/main` at harnessEpoch 3 and
// requires it to come back `no(…)`. A guard written against a hazard nobody can still produce is a
// guard nobody can show is live.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { targetCatalogued, targetCataloguedMarker } from './target-catalogued.mjs';
import { buildCatalog } from './dep-scaffold.mjs';

const HERE = import.meta.dirname;
const TARGET = 'hugo-extended';

/** Write a catalog document to a throwaway file and return its path. */
function catFile(doc) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'targetcat-'));
  const p = path.join(d, 'cat.json');
  fs.writeFileSync(p, typeof doc === 'string' ? doc : JSON.stringify(doc));
  return p;
}

/**
 * `origin/main`'s construction, verbatim, as the thing this module exists to catch.
 *
 *     if (Object.keys(grant).length) packages[target] = { default: grant };
 *     if (!Object.keys(packages).length) packages.__v2_empty_grant_sentinel__ = { default: { network: true } };
 */
function epoch3BuildCatalog(target, grant) {
  const packages = {};
  if (Object.keys(grant).length) packages[target] = { default: grant };
  if (!Object.keys(packages).length) packages.__v2_empty_grant_sentinel__ = { default: { network: true } };
  return { packages };
}

test('RED CONTROL: the retired empty-grant construction is rejected, and its non-empty twin is not', () => {
  // ⛔ THE PAIR IS THE TEST. At a non-empty grant the two constructions are byte-identical, so a
  // module that rejected everything would satisfy the first assertion alone. The second is what shows
  // the check discriminates rather than merely refuses.
  const empty = targetCatalogued(catFile(epoch3BuildCatalog(TARGET, {})), TARGET);
  assert.equal(empty.present, false,
    'the epoch-3 empty-grant catalog omits the target, and that is the under-grant this guards');
  assert.match(targetCataloguedMarker(empty), /^TARGET-CATALOGUED=no\(/);

  const withNetwork = targetCatalogued(catFile(epoch3BuildCatalog(TARGET, { network: true })), TARGET);
  assert.equal(withNetwork.present, true, 'a non-empty grant was always catalogued and must still pass');
});

test('the current builder catalogues the empty rung, so the modal measurement is not VOIDed', () => {
  // The zero rung is roughly half the corpus. If this ever goes red the fix is in `dep-scaffold.mjs`,
  // never here — an empty `default` is the deliberate spelling of "grants nothing".
  const observe = fs.mkdtempSync(path.join(os.tmpdir(), 'targetcat-obs-'));
  const { catalog } = buildCatalog(TARGET, {}, observe);
  const r = targetCatalogued(catFile(catalog), TARGET);
  assert.equal(r.present, true, `the current builder produced an uncatalogued target: ${r.why}`);
  assert.equal(targetCataloguedMarker(r), 'TARGET-CATALOGUED=yes');
});

test('an entry that resolves to nothing is absence, not presence', () => {
  // `v2_grant_for` resolves through `default`/`versions`; an entry carrying neither lands the arm on
  // the baseline exactly as if the name were missing, so the key alone is not the invariant.
  const r = targetCatalogued(catFile({ packages: { [TARGET]: {} } }), TARGET);
  assert.equal(r.present, false);
  assert.match(r.why, /neither 'default' nor 'versions'/);
});

test('an unreadable or unparsable catalog is `no`, never a silent pass', () => {
  const missing = targetCatalogued(path.join(os.tmpdir(), 'targetcat-does-not-exist', 'cat.json'), TARGET);
  assert.equal(missing.present, false);
  const junk = targetCatalogued(catFile('{ not json'), TARGET);
  assert.equal(junk.present, false);
  const shapeless = targetCatalogued(catFile({ baseline: [] }), TARGET);
  assert.equal(shapeless.present, false);
  for (const r of [missing, junk, shapeless]) {
    const m = targetCataloguedMarker(r);
    assert.ok(!m.includes('\n'), `multi-line marker: ${m}`);
    assert.match(m, /^TARGET-CATALOGUED=no\(/);
  }
});

test('`--at-catalog` absence is neither `yes` nor `no`, because it VOIDs nothing', () => {
  // ⛔ `collate.mjs` deliberately emits NO entry for a package that needs nothing, so an absent target
  // in that mode is the shipped answer under test rather than a defect. Reporting `no` would VOID a
  // correct arm; reporting `yes` would be false. It must read as neither.
  const absent = targetCatalogued(catFile(epoch3BuildCatalog(TARGET, {})), TARGET);
  const m = targetCataloguedMarker(absent, { atCatalog: true });
  assert.match(m, /^TARGET-CATALOGUED=at-catalog\(absent: /);
  assert.ok(!/=yes|=no\(/.test(m), `the at-catalog value must not collide with either verdict: ${m}`);
});

test('⛔ ALL THREE DRIVERS ASSERT IT — the guard that makes landed mean landed', () => {
  // `dep-scaffold.mjs` records TWO occasions when a v2 fix landed in one driver and was mistaken for
  // done. This defect is the third of that family and its cost was an under-grant, so the parity
  // assertion sits beside the module rather than only in `arm-prepare.test.mjs`.
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('target-catalogued'),
      `${d} does not consult target-catalogued — the arm can still run at the baseline there`);
  }
});
