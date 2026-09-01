import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ARTIFACT_CACHE_LEAVES, TOOLING_LEAVES, purgeArmReplayRoots, marker, sideEffectsSlug,
} from './arm-artifact-cache.mjs';

/** A `<cache>/nub` root carrying whichever roots a case needs. */
const jailCache = ({ tools = {}, homes = [], se = [] } = {}) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'aac-'));
  for (const [name, file] of Object.entries(tools)) {
    fs.mkdirSync(path.join(d, 'pm', 'tools', name), { recursive: true });
    fs.writeFileSync(path.join(d, 'pm', 'tools', name, file), 'x');
  }
  for (const name of homes) fs.mkdirSync(path.join(d, 'jail-home', name), { recursive: true });
  for (const name of se) fs.mkdirSync(path.join(d, 'pm', 'side-effects-v1', name), { recursive: true });
  return d;
};

test('the artefact caches go, so a drop arm cannot read the previous arm\'s download', () => {
  const d = jailCache({ tools: { 'electron-cache': 'electron-v33.4.11-darwin-arm64.zip', 'ms-playwright': 'chromium-1234' } });
  const r = purgeArmReplayRoots(d, 'electron');
  assert.deepEqual([...r.removed].sort(), ['electron-cache', 'ms-playwright'],
    `expected both artefact leaves removed, got ${JSON.stringify(r)}`);
  for (const l of ARTIFACT_CACHE_LEAVES) {
    assert.equal(fs.existsSync(path.join(d, 'pm', 'tools', l)), false,
      `${l} still on disk — the next arm would still find the previous arm's download`);
  }
});

// ⛔ RED CONTROL. Widening this to an `rm -rf` on `tools` is the obvious simplification and it
// reintroduces the exact failure the STORE eviction already spares for: nub bootstraps node-gyp under
// this parent, and an amputated tree yields `gyp ERR! Cannot find module 'semver'` — which reads as
// INSUFFICIENT and INFLATES the grant, the one direction this harness may not move. This test goes
// red the moment the allowlist stops being one.
test('⛔ nub\'s own tooling leaves survive — taking them would inflate every native grant', () => {
  const d = jailCache({ tools: { 'electron-cache': 'z.zip', 'node-gyp': 'v12', 'npm-prefix': 'bin' } });
  const r = purgeArmReplayRoots(d, 'electron');
  for (const l of TOOLING_LEAVES) {
    assert.equal(fs.existsSync(path.join(d, 'pm', 'tools', l)), true,
      `${l} was removed; nub bootstraps its tooling here and dangling it fails every native build`);
    assert.ok(r.spared.includes(l), `${l} not reported as spared: ${JSON.stringify(r)}`);
  }
});

test('an unrecognized leaf is spared rather than swept, so the allowlist stays the only policy', () => {
  const d = jailCache({ tools: { 'some-future-tool': 'f' } });
  const r = purgeArmReplayRoots(d, 'x');
  assert.deepEqual(r.removed, []);
  assert.deepEqual(r.spared, ['some-future-tool']);
  assert.equal(fs.existsSync(path.join(d, 'pm', 'tools', 'some-future-tool')), true);
});

// ⛔ RED CONTROL FOR THE SLUG ANCHOR. `measure.sh`'s glob is `"$(basename "$PKG")"-*`, which matches
// `electron-chromedriver-<hash>` while measuring `electron` — and those two names carry 6 and 38 of
// the 44 affected records between them, so this is the live case rather than a constructed one. The
// fixture holds two real slugs observed on disk plus the sibling; a prefix match returns 3.
test('the private home is anchored on the 16-hex slug, so a sibling package keeps its home', () => {
  const d = jailCache({ homes: ['electron-f8e8ba60aef880e5', 'electron-1a10d23ee60a1933', 'electron-chromedriver-aa11d23ee60a1933'] });
  const r = purgeArmReplayRoots(d, 'electron');
  assert.equal(r.homes, 2, `expected exactly the two electron homes removed, got ${r.homes}`);
  assert.equal(fs.existsSync(path.join(d, 'jail-home', 'electron-chromedriver-aa11d23ee60a1933')), true,
    'the sibling electron-chromedriver home was swept by an unanchored electron- prefix');
});

// The mirror: a leaf that is NOT a slug is left alone, so a stray directory under `jail-home` is
// never mistaken for a package's home.
test('a directory under jail-home that is not a <name>-<16 hex> slug is left alone', () => {
  const d = jailCache({ homes: ['electron-nothexadecimal', 'electron-f8e8ba60aef880e5'] });
  const r = purgeArmReplayRoots(d, 'electron');
  assert.equal(r.homes, 1, `expected only the real slug removed, got ${r.homes}`);
  assert.equal(fs.existsSync(path.join(d, 'jail-home', 'electron-nothexadecimal')), true);
});

// ⛔ `__`, NOT `+`. `measure.sh` records what the `+` spelling cost: a purge that silently no-ops for
// every scoped package while reading as a working guard. This is the assertion that would have caught it.
test('a scoped package\'s side-effects entry is purged, because the slug uses __ and not +', () => {
  assert.equal(sideEffectsSlug('@scarf/scarf'), '@scarf__scarf');
  const d = jailCache({ se: ['@scarf__scarf@1.4.0', '@scarf+scarf@1.4.0-abc'] });
  const r = purgeArmReplayRoots(d, '@scarf/scarf');
  assert.equal(r.sideEffects, 1, `the __ spelling was not matched: ${JSON.stringify(r)}`);
  assert.equal(fs.existsSync(path.join(d, 'pm', 'side-effects-v1', '@scarf__scarf@1.4.0')), false);
});

test('a box with none of the three roots reports that, rather than an eviction that happened', () => {
  const r = purgeArmReplayRoots(path.join(os.tmpdir(), 'aac-does-not-exist-ha8f'), 'x');
  assert.equal(r.toolsPresent, false);
  assert.match(marker('synth', r), /no tools dir yet/);
});

test('the marker names what went and what stayed, so a reader can check the allowlist on disk', () => {
  const d = jailCache({ tools: { 'electron-cache': 'z.zip', 'node-gyp': 'v12' }, homes: ['electron-b667e16f85d15e8c'] });
  const line = marker('nar-no-network', purgeArmReplayRoots(d, 'electron'));
  assert.match(line, /EVICT-REPLAY\[nar-no-network\]/);
  assert.match(line, /1 artefact cache\(s\) removed \(electron-cache\)/);
  assert.match(line, /1 spared as nub tooling/);
  assert.match(line, /1 private home\(s\)/);
});

// ⛔ ALL THREE DRIVERS, AND THIS ASSERTION IS THE WHOLE POINT OF THE MODULE. The guard existed in
// `measure.sh` alone; the committed corpus shows the consequence as 44 empty-grant records in the
// electron/playwright families, 44 of 44 on darwin. Nothing but a cross-driver assertion stops that
// recurring — it has already recurred three times in this harness under different names.
test('all three drivers purge the replay roots through this shared module', () => {
  const here = import.meta.dirname;
  for (const driver of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(here, driver), 'utf8');
    assert.ok(/arm-artifact-cache/.test(src),
      `${driver} does not reference arm-artifact-cache — a drop arm there still reads the previous arm's download`);
  }
});

test('the artefact leaves are exactly the two nub redirects a confined script at', () => {
  assert.deepEqual([...ARTIFACT_CACHE_LEAVES].sort(), ['electron-cache', 'ms-playwright']);
});
