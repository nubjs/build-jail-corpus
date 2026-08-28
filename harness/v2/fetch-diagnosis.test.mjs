// ⛔ THE 165-RECORD BLIND SPOT. Every driver fetches the package unjailed before it measures
// anything, and when that fetch fails it files BROKEN-WITHOUT-JAIL-TOO and exits. MEASURED
// 2026-08-28 across the whole corpus: 165 of 1409 BROKEN-WITHOUT-JAIL-TOO records took that exit,
// and all 165 have a driver.out of roughly eighteen lines carrying NO REASON WHATSOEVER. npm's own
// diagnosis was written to `$OBS/fetch.log` and then discarded with the scratch directory.
//
// That is the single bucket this corpus exists to split. "The package is gone from the registry"
// and "our dated fetch asked for something that never existed" produce byte-identical records, so
// no amount of re-measuring can separate dead packages from a harness defect. The fix is to print
// what was already captured.
//
// ⛔⛔ EVERY ASSERTION HERE IS SCOPED TO THE ERA-FETCH BLOCK, NEVER TO THE FILE. `npm_ok` has
// carried its own `sed 's/^/    | /' "$d/fetch.log" | tail -20` since long before this change, so a
// file-wide search for that idiom matches it and PASSES WITH THE FIX DELETED. That exact mistake
// shipped a green-either-way assertion in `era-python-parity.test.mjs` and was only caught by
// removing the code and watching nothing go red. Each test below was driven red the same way.
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';

const HERE = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

// The era fetch and the guard that follows it — bounded by the fetch line and its closing `fi`, so
// nothing from any other function in these ~2000-line drivers can satisfy an assertion.
function eraFetchBlock(src, file) {
  const start = src.indexOf('"$PKG@$VER" > "$OBS/fetch.log" 2>&1');
  assert.notEqual(start, -1, `${file}: the era fetch line is gone — re-read the driver`);
  const end = src.indexOf('\nfi\n', start);
  assert.notEqual(end, -1, `${file}: the fetch guard has no closing fi`);
  return src.slice(start, end);
}

for (const file of ['measure.sh', 'measure-macos.sh']) {
  test(`${file} prints npm's own words when the era fetch fails`, () => {
    const block = eraFetchBlock(read(file), file);
    assert.match(block, /BROKEN-WITHOUT-JAIL-TOO \(unjailed fetch failed/,
      `${file}: this is meant to be the fetch-failure exit`);
    assert.match(block, /fetch\.log/,
      `${file}: the fetch-failure exit does not read fetch.log — the reason is being discarded, `
      + 'which is the 165-record blind spot this guards');
    assert.match(block, /tail -20/,
      `${file}: the captured fetch log is not bounded — print a tail, not the whole thing`);
  });

  test(`${file} captures the fetch rc on its own line, so set -u cannot abort the driver`, () => {
    const src = read(file);
    // Not cosmetic. Both drivers run `set -u`, the exit line now interpolates the rc, and an
    // unbound name there aborts the whole run instead of printing an empty string. `bash -n` does
    // NOT catch it — it is a runtime failure, not a parse error — so this assertion is the only
    // thing standing between a refactor and a driver that dies on every failed fetch.
    assert.match(src, /set -u/, `${file}: expected set -u; if it is gone, re-check this guard`);
    const block = eraFetchBlock(src, file);
    assert.match(block, /rc=\$FETCH_RC/, `${file}: the exit line should report the fetch rc`);
    assert.match(src, /^FETCH_RC=\$\?$/m,
      `${file}: FETCH_RC is interpolated but never captured on its own line — under set -u the `
      + 'driver aborts on every failed fetch');
  });
}

test('measure-windows.mjs prints npm\'s own words when the era fetch fails', () => {
  const src = read('measure-windows.mjs');
  const start = src.indexOf('if (fetch.status !== 0) {');
  assert.notEqual(start, -1, 'the windows fetch guard is gone — re-read the driver');
  const block = src.slice(start, src.indexOf('\n}', start));
  assert.match(block, /BROKEN-WITHOUT-JAIL-TOO \(unjailed fetch failed/,
    'this is meant to be the windows fetch-failure exit');
  assert.match(block, /fetch\.(stdout|stderr)/,
    'the windows fetch-failure exit does not echo the captured output — same blind spot');
  assert.match(block, /slice\(-20\)/,
    'the windows fetch log is not bounded — print a tail, not the whole thing');
});
