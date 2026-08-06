// Known-answer cases for the enumerated directory grant (`pathgrant.mjs`).
//
// EVERY FIXTURE HERE IS A REAL MEASURED PATH SET, copied out of a published record's
// `driver.out` (`records-v2/runs/linux-x64/…`) or its retained `events.ndjson.gz`. A synthetic
// fixture would agree with a predicate that is wrong in exactly the way the fixture was invented.
//
// THE TWO CONTROLS ARE OPPOSITE, and having both is what makes a green run mean anything:
//   POSITIVE  `playwright-chromium@0.17.0` — 653 writes, one directory, a build-numbered segment
//             BELOW it. Must enumerate.
//   NEGATIVE  `hugo-extended@0.141.0` — a fresh 32-hex directory name every run, measured. Must
//             refuse. If this one ever passes, the predicate is under-detecting volatility and
//             every enumeration it produces is pinned to one run.
//
//   node --test harness/v2/pathgrant.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { enumerateGrant, rollUp, volatileSegment, agree } from './pathgrant.mjs';

test('a segment carrying a build number, version, hash or mktemp tail is volatile', () => {
  for (const seg of [
    'chromium-764964', // playwright's browser build number
    'resource-gcp-v0.16.9', // pulumi's plugin dir — the v1 version-stamping hazard
    '22.23.1', // a node-gyp header tree
    'ca2223935f4dec08eea62524ef6923e6', // hugo's per-run download dir
    'node-gyp-tmp-5xuClF', // mktemp
    'playwright-download-8zlprA',
    'electron-tmp-download-2881-1786023227333',
    'pulumi-20260806T124738-2822-plugin_install.log',
  ]) {
    assert.equal(volatileSegment(seg), true, `${seg} must read as volatile`);
  }
});

test('an ordinary vendor or cache directory name is stable', () => {
  for (const seg of ['.cache', 'nub', 'pm', 'tools', 'ms-playwright', '.pulumi', 'plugins', 'logs', '.config', 'netlify', 'node-gyp', 'electron-cache']) {
    assert.equal(volatileSegment(seg), false, `${seg} must read as stable`);
  }
});

test('roll-up stops at the first volatile segment and grants its parent', () => {
  assert.equal(
    rollUp('.cache/nub/pm/tools/ms-playwright/chromium-764964/chrome-linux/locales/sk.pak'),
    '.cache/nub/pm/tools/ms-playwright',
  );
  // No volatile segment: grant the PARENT, never the leaf. A rule cannot attach to a file that
  // does not exist yet, and creating it needs write on the directory regardless.
  assert.equal(rollUp('.config/netlify/autocompletion.json'), '.config/netlify');
});

test('playwright-chromium@0.17.0 enumerates to the one directory it downloads into', () => {
  // MEASURED: the full 653-path userHome set, sampled down to its distinct shapes — the ancestor
  // chain the runner's fresh `$HOME` made the script create, plus leaves under the build dir.
  const observed = [
    '.cache',
    '.cache/nub',
    '.cache/nub/pm',
    '.cache/nub/pm/tools',
    '.cache/nub/pm/tools/ms-playwright',
    '.cache/nub/pm/tools/ms-playwright/.links',
    '.cache/nub/pm/tools/ms-playwright/.links/288743bfc460ff510c77fa4dbfa44d7c4dcaabab',
    '.cache/nub/pm/tools/ms-playwright/chromium-764964',
    '.cache/nub/pm/tools/ms-playwright/chromium-764964/chrome-linux',
    '.cache/nub/pm/tools/ms-playwright/chromium-764964/chrome-linux/icudtl.dat',
    '.cache/nub/pm/tools/ms-playwright/chromium-764964/chrome-linux/locales/sk.pak',
  ];
  const out = enumerateGrant(observed);
  assert.deepEqual(out, { ok: true, dirs: ['.cache/nub/pm/tools/ms-playwright'] });
});

test('the ancestor chain is dropped only because nub creates the granted directory', () => {
  // ⛔ THE LOAD-BEARING HALF OF THE PREVIOUS TEST, ASSERTED ON ITS OWN. `mkdir(~/.cache)` really
  // did succeed in the trace, so a naive roll-up bills `$HOME` — the whole scope, which is what
  // this tier exists to avoid. Dropping it is legitimate ONLY under the enforcement precondition
  // that nub `create_dir_all`s the granted directory. Without that precondition this assertion is
  // wrong and the tier is unsound, which is why it is pinned separately.
  const out = enumerateGrant(['.cache', '.cache/foo', '.cache/foo/bar-901234/x']);
  assert.deepEqual(out, { ok: true, dirs: ['.cache/foo'] });
});

test('a real file written into an ancestor still bills that ancestor', () => {
  // The evidence-based half of the same rule, and the reason it is not a blanket "ignore parents".
  // MEASURED divergence between two records of one family: `@pulumi/kubernetes@0.14.0` writes
  // `.pulumi/.cachedVersionInfo` and `@pulumi/gcp@0.16.9` does not.
  const gcp = enumerateGrant([
    '.pulumi',
    '.pulumi/logs',
    '.pulumi/logs/pulumi-20260806T124738-2822-plugin_install.log',
    '.pulumi/plugins',
    '.pulumi/plugins/resource-gcp-v0.16.9.lock',
    '.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp',
  ]);
  assert.deepEqual(gcp, { ok: true, dirs: ['.pulumi/logs', '.pulumi/plugins'] });

  const kubernetes = enumerateGrant([
    '.pulumi',
    '.pulumi/.cachedVersionInfo',
    '.pulumi/logs',
    '.pulumi/logs/pulumi-20260806T144254-3357-plugin_install.log',
    '.pulumi/plugins',
    '.pulumi/plugins/resource-kubernetes-v0.14.0.lock',
  ]);
  assert.deepEqual(kubernetes, { ok: true, dirs: ['.pulumi'] });
});

test('hugo-extended@0.141.0 is REFUSED — its directory name is fresh every run', () => {
  // The negative control. MEASURED across runs: the 32-hex name differs every time, so any
  // enumeration derived from one run under-grants the next.
  const out = enumerateGrant([
    'ca2223935f4dec08eea62524ef6923e6',
    'ca2223935f4dec08eea62524ef6923e6/hugo_extended_0.141.0_linux-amd64.tar.gz',
    'ca2223935f4dec08eea62524ef6923e6/hugo_0.141.0_checksums.txt',
  ]);
  assert.equal(out.ok, false);
  assert.match(out.reason, /scope root/);
});

test('a camelCase directory name costs one level, not correctness', () => {
  // The mixed-case rule over-detects on an ordinary camelCase name, which is deliberate. Assert
  // what the over-detection COSTS: the roll-up stops one segment early and grants the parent —
  // wider, still installs. If this ever asserted the narrow answer instead, the predicate would
  // have been tightened in the direction that lets a real mktemp tail through.
  assert.deepEqual(enumerateGrant(['.local/myCoolCache/data.json']), {
    ok: true,
    dirs: ['.local'],
  });
});

test('an enumeration wider than the cap is refused rather than emitted', () => {
  const many = Array.from({ length: 20 }, (_, i) => `dir-${String.fromCharCode(97 + i)}/f`);
  assert.equal(enumerateGrant(many).ok, false);
  assert.equal(enumerateGrant(many, { max: 40 }).ok, true);
});

test('two OBSERVE runs of electron@31.7.7 agree on the DIRECTORY, not on the paths', () => {
  // ⛔ THE ONLY REAL TWO-RUN EVIDENCE IN THIS REPO, and it is the whole argument for the roll-up.
  // MEASURED 2026-08-06, `node:22-slim` under `strace -f`, with the parity environment
  // (`HOME`/`TMPDIR`/`ELECTRON_CACHE`/`npm_config_prefix` stamped as `measure.sh` stamps them) and
  // the persistent tool cache evicted between runs. Run 1 saw seven paths, run 2 saw four — the
  // `.cache`/`nub`/`pm` chain already existed the second time — and both roll up to one directory.
  //
  // ⛔ THE EVICTION IS LOAD-BEARING AND IS THE CONTROL, not hygiene. The same pair run WITHOUT it
  // has run 2 finding run 1's download and synthesizing `{}` — no writes, no network — so the
  // oracle reports UNSTABLE for a package whose directory never moved. A repeat-run stability
  // check that does not evict measures the cache, not the package.
  const run1 = enumerateGrant([
    '.cache',
    '.cache/nub',
    '.cache/nub/pm',
    '.cache/nub/pm/tools',
    '.cache/nub/pm/tools/electron-cache',
    '.cache/nub/pm/tools/electron-cache/c94f2fc32e1fb05767f75322ea533eeb9828155f017ec184140930a3ec825e81',
    '.cache/nub/pm/tools/electron-cache/c94f2fc32e1fb05767f75322ea533eeb9828155f017ec184140930a3ec825e81/electron-v31.7.7-linux-arm64.zip',
  ]);
  const run2 = enumerateGrant([
    '.cache/nub/pm/tools',
    '.cache/nub/pm/tools/electron-cache',
    '.cache/nub/pm/tools/electron-cache/c94f2fc32e1fb05767f75322ea533eeb9828155f017ec184140930a3ec825e81',
    '.cache/nub/pm/tools/electron-cache/c94f2fc32e1fb05767f75322ea533eeb9828155f017ec184140930a3ec825e81/electron-v31.7.7-linux-arm64.zip',
  ]);
  assert.deepEqual(agree(run1, run2), {
    stable: true,
    dirs: ['.cache/nub/pm/tools/electron-cache'],
  });
});

test('two runs that disagree on directories are NOT stable', () => {
  const a = enumerateGrant(['.cache/x/f']);
  const b = enumerateGrant(['.cache/y/f']);
  assert.equal(agree(a, b).stable, false);
});
