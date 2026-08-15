// Per-OS overlays: the collator must narrow a grant to the platform that actually needed it.
//
// WHY THESE TESTS EXIST AND WHAT THEY GUARD. `byVersion` unions grants ACROSS platforms, so before
// this a need measured only on win32 became the answer everywhere. Measured on the shipped catalog:
// 0 of 453 bands carried an overlay, and 45 of the 65 whole-disk grants are win32-ONLY by record —
// 45 packages reading the whole filesystem on macOS and Linux because Windows needed it.
//
// The failure direction that matters is UNDER-granting, and it is SILENT twice over: a grant the
// generator narrows too far surfaces as the package dying on a laundered ENOENT, and a malformed
// overlay makes nub print REJECTED and keep running on its compiled-in table — so one bad entry
// discards all 338 packages while every record beside it is sound. Hence the negative cases below
// are as load-bearing as the positive one.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';

const collate = path.join(import.meta.dirname, '..', 'collate.mjs');
const instrument = computeHarnessIdentity();

/** One results.json for `pkg@version` on `platform`, carrying `grant`. */
function record({ pkg, version, platform, grant, latest }) {
  return {
    pkg,
    version,
    harnessVersion: 2,
    harnessEpoch: instrument.harnessEpoch,
    verdict: 'MINIMUM',
    grant,
    grantSource: 'synthesized',
    minimality: 'MINIMAL',
    standing: { latestVersion: latest ?? version },
    securityScreens: [],
    resolvedTrees: [{
      digest: 'tree', specCount: 1, specs: [`${pkg}@${version}`], lockfiles: { digest: 'lock', files: [] },
      kinds: ['direct', 'npm-observe-resolved', 'nub-verify-resolved'],
    }],
    provenance: {
      platform,
      harnessEpoch: instrument.harnessEpoch,
      harnessSha256: instrument.harnessSha256,
      node: process.version,
      nubBinary: { sha256: 'nub' },
      runtime: {
        node: { version: process.version, sha256: 'node' },
        npm: { version: '10.0.0' }, python: [], buildTools: {},
        os: { release: 'test' }, runner: {}, environment: {},
      },
    },
  };
}

/** Collate a set of records and return the parsed catalog (asserting a clean exit). */
function collateRecords(records) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'collate-overlays-'));
  for (const r of records) {
    const dir = path.join(root, 'runs', r.provenance.platform, r.pkg, r.version);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(r, null, 2)}\n`);
  }
  const out = path.join(root, 'catalog.json');
  const result = spawnSync(process.execPath, [collate, '--runs', path.join(root, 'runs'),
    '--overrides', path.join(root, 'overrides'), '--out', out], { encoding: 'utf8' });
  assert.equal(result.status, 0, `collate failed: ${result.stderr}`);
  return { catalog: JSON.parse(fs.readFileSync(out, 'utf8')), out, stderr: result.stderr };
}

test('a need measured only on win32 narrows the other platforms instead of spreading', () => {
  // The exact corpus shape: Windows needs the whole disk, POSIX needs only its project.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: 'disk', network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { write: { project: true }, network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { write: { project: true }, network: true } }),
  ]);
  const d = catalog.packages.demo.default;

  // The BASE stays the union, so any platform that never reported still gets the safe answer.
  assert.equal(d.write, 'disk', 'the base must remain the cross-platform union');

  // …and the two platforms that measured less get their own answer back.
  for (const key of ['macos', 'linux']) {
    assert.ok(d[key], `expected a ${key} overlay; base-only means the win32 need still spreads`);
    assert.deepEqual(d[key].write, { project: true },
      `${key} measured project-only write and must not inherit the win32 whole-disk grant`);
  }
  // Windows agrees with the base, so restating it would be a REDUNDANT overlay — which the parser
  // rejects outright, taking the whole catalog with it.
  assert.equal(d.win, undefined, 'the platform that matches the base must carry no overlay');
  // network was unanimous, so no overlay may mention it.
  for (const key of ['macos', 'linux']) {
    assert.equal(d[key].network, undefined, `${key} agrees on network; emitting it would be redundant`);
  }
});

test('platforms that agree produce no overlays at all', () => {
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
  ]);
  const d = catalog.packages.demo.default;
  assert.equal(d.network, true);
  for (const key of ['macos', 'linux', 'win']) {
    assert.equal(d[key], undefined, `unanimous grants must stay base-only, got a ${key} overlay`);
  }
});

test('a platform that measured NOTHING gets no overlay and keeps the union', () => {
  // THE UNDER-GRANT GUARD. Only Windows ran. Silence from macOS and Linux is not evidence that they
  // need less, so they must inherit the union — narrowing them here would break real packages on
  // platforms the corpus never measured.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: 'disk' } }),
  ]);
  const d = catalog.packages.demo.default;
  assert.equal(d.write, 'disk');
  for (const key of ['macos', 'linux']) {
    assert.equal(d[key], undefined,
      `${key} never reported, so it must inherit the union rather than be narrowed on silence`);
  }
});

test('a platform that measured the version and needed nothing is narrowed to the base profile', () => {
  // The other half of the previous test: MEASURED-and-needed-nothing is real evidence, unlike
  // silence, so every axis the union carries is removed for that platform with an explicit null.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: 'disk', network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: {} }),
  ]);
  const d = catalog.packages.demo.default;
  assert.equal(d.write, 'disk');
  assert.ok(d.macos, 'a measured-and-needed-nothing platform must still be narrowed');
  assert.equal(d.macos.write, null, 'the schema removes an axis with an explicit null, not by omission');
  assert.equal(d.macos.network, null, 'network measured unnecessary on macOS must be removed too');
});

test('an overlay never restates the outer value, on any package in a mixed catalog', () => {
  // A REDUNDANT overlay is rejected by nub's parser, and rejection is SILENT — it falls back to the
  // compiled-in table and prints REJECTED, so a single restated axis discards the entire catalog.
  // Asserted across every emitted overlay rather than one hand-picked entry.
  const { catalog } = collateRecords([
    record({ pkg: 'alpha', version: '2.0.0', platform: 'win32-x64', grant: { write: 'disk', network: true } }),
    record({ pkg: 'alpha', version: '2.0.0', platform: 'darwin-arm64', grant: { write: { project: true } } }),
    record({ pkg: 'beta', version: '1.0.0', platform: 'linux-x64', grant: { read: { userHome: true } } }),
    record({ pkg: 'beta', version: '1.0.0', platform: 'darwin-arm64', grant: { read: { userHome: true } } }),
  ]);
  const OS_KEYS = ['macos', 'linux', 'win'];
  const AXES = ['read', 'write', 'network', 'writePaths', 'env'];
  const norm = (v) => JSON.stringify(v ?? null);
  for (const [pkg, entry] of Object.entries(catalog.packages)) {
    for (const [label, band] of [['default', entry.default], ...Object.entries(entry.versions ?? {})]) {
      for (const key of OS_KEYS) {
        const overlay = band?.[key];
        if (!overlay) continue;
        for (const axis of AXES) {
          if (!(axis in overlay)) continue;
          assert.notEqual(norm(overlay[axis]), norm(band[axis]),
            `${pkg} ${label} ${key}.${axis} restates the outer value — the parser rejects that and `
            + 'discards the whole catalog silently');
        }
      }
    }
  }
});

test('an overlay is never wider than the base it sits under', () => {
  // The base is the union of every platform, so no overlay can legitimately widen it. If one did,
  // the union itself would be broken and every OTHER platform would be under-granted. Nesting is
  // also exactly one level in the schema, so an overlay must never carry an OS key of its own.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: 'disk', network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { write: { project: true } } }),
  ]);
  const d = catalog.packages.demo.default;
  for (const key of ['macos', 'linux', 'win']) {
    const overlay = d[key];
    if (!overlay) continue;
    assert.notEqual(overlay.write, 'disk', `${key} overlay restates or widens to whole-disk`);
    for (const nested of ['macos', 'linux', 'win']) {
      assert.equal(overlay[nested], undefined, `${key} overlay nests ${nested}; the schema allows one level`);
    }
  }
});
