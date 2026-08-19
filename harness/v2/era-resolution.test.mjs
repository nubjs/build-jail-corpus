// Dated resolution is the half of an era the Node pin cannot supply. The margin test is the one
// that matters: without it the target package excludes itself and the error reads as a missing
// version rather than an off-by-one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { beforeFor, fetchArgs, PUBLISH_MARGIN_MS } from './era-resolution.mjs';

test('the margin puts --before AFTER the publish instant, not on it', () => {
  // electron-chromedriver@0.33.4, published 2015-10-11T21:02:00.345Z. Measured: `--before=2015-10-11`
  // returns ETARGET because npm floors a bare date to local midnight, which is BEFORE that instant.
  const before = beforeFor('2015-10-11T21:02:00.345Z');
  assert.ok(Date.parse(before) > Date.parse('2015-10-11T21:02:00.345Z'), 'must not exclude the target itself');
  assert.equal(before, '2015-10-12T21:02:00.345Z');
});

test('a full ISO instant is emitted, so npm has nothing left to floor', () => {
  assert.match(beforeFor('2015-10-11T21:02:00.345Z'), /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
});

test('no usable date means UNDATED, stated in the marker rather than silently skipped', () => {
  assert.equal(beforeFor(null), null);
  assert.equal(beforeFor('not-a-date'), null);
  const r = fetchArgs({ spec: 'x@1.0.0', publishedAt: null });
  assert.ok(!r.args.some((a) => a.startsWith('--before')));
  assert.match(r.marker, /UNDATED.*no usable publish date/);
});

test('the fetch keeps --ignore-scripts, because resolution and execution are separate steps', () => {
  const r = fetchArgs({ spec: 'optipng-bin@0.2.6', publishedAt: '2014-05-01T00:00:00.000Z' });
  assert.ok(r.args.includes('--ignore-scripts'), 'the era Node runs the scripts, not this fetch');
  assert.equal(r.args.at(-1), 'optipng-bin@0.2.6', 'the spec stays last');
  assert.ok(r.args.includes(`--before=${r.before}`));
});

test('dated:false is expressible and SAYS so — the two measurements mean different things', () => {
  const r = fetchArgs({ spec: 'x@1.0.0', publishedAt: '2015-01-01T00:00:00.000Z', dated: false });
  assert.equal(r.before, null);
  assert.match(r.marker, /UNDATED \(disabled\).*TODAY/);
});

test('the margin is a whole day, because npm floors in the RUNNER timezone', () => {
  assert.equal(PUBLISH_MARGIN_MS, 86400000);
});

test('⛔ ALL THREE DRIVERS RESOLVE DATED — the guard that makes landed mean landed', () => {
  // `dep-scaffold.mjs` records TWO v2 fixes that landed in `measure.sh` alone and were mistaken for
  // done. A driver still fetching undated would silently measure a modern tree while the other two
  // measured an era one, and the records would be incomparable with nothing saying so.
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(import.meta.dirname, d), 'utf8');
    assert.ok(/era-resolution/.test(src), `${d} does not use era-resolution — the fix is not landed there`);
    assert.ok(!/install'?,? '?--no-audit'?,? '?--no-fund'?,? '?--ignore-scripts'?,? [`"']\$\{?PKG/.test(src)
      || /eraResolution\.args|ERA_BEFORE/.test(src), `${d} still has an undated fetch of the target`);
  }
});
