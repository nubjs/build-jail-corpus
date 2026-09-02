// The two gates that stand between a regeneration and a silent under-grant.
//
// WHY THESE EXIST, MEASURED. `collate.mjs` is a pure function of the records it is handed, so a
// platform that has not been RE-measured under the current instrument contributes nothing — and
// contributing nothing reads everywhere downstream as "needs nothing". On 2026-09-01, scored at the
// epoch the invalidation policy pins, 0 of 2,270 win32 records were valid (macOS 1430/2293, linux
// 1531/2324). A regeneration therefore removed 155 of 206 over-broad grant cells while only ONE of
// those removals survived a per-cell evidence check: 107 of 131 wide Windows cells narrowed on the
// strength of no Windows evidence at all, and 86 of the removals were a package dropping out of the
// catalog entirely — which is not a narrower grant but NO grant, so the package fails to install.
//
// Both gates apply to the NARROWING direction only, and that asymmetry is the whole design:
// narrowing on weak evidence breaks installs, widening on weak evidence cannot.
//
// ⛔ EVERY REFUSAL CASE BELOW IS PAIRED WITH A PUBLISH CASE THAT DIFFERS IN EXACTLY ONE TERM. A gate
// that refuses everything satisfies every "this was preserved" assertion, freezes the catalog at its
// current grants, and looks correct doing it — which is the failure `publish-guard.test.mjs` names
// in its own header and the one most worth guarding here, because this gate runs over 294 packages
// at once rather than one record at a time.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { computeHarnessIdentity } from './instrument.mjs';

const collate = path.join(import.meta.dirname, '..', 'collate.mjs');
const instrument = computeHarnessIdentity();

/** A complete, CURRENT, `MINIMUM` record — i.e. one `recordValidity` accepts, which is what Gate 1
 *  counts. `extra` is where a test makes it stale or unfalsifiable. */
function record({ pkg, version, platform, grant, latest }, extra = {}) {
  return {
    pkg,
    version,
    harnessVersion: 2,
    harnessEpoch: instrument.harnessEpoch,
    verdict: 'MINIMUM',
    grant,
    grantSource: 'synthesized',
    minimality: 'MINIMAL',
    notes: [],
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
    ...extra,
  };
}

/** Collate `records` against a shipped `prior` catalog, asserting a clean exit. Pass `prior: null`
 *  to run the generator ungated. */
function collateRecords(records, prior) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'collate-gates-'));
  for (const r of records) {
    const dir = path.join(root, 'runs', r.provenance.platform, r.pkg, r.version);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(r, null, 2)}\n`);
  }
  const args = [collate, '--runs', path.join(root, 'runs'),
    '--overrides', path.join(root, 'overrides'), '--out', path.join(root, 'catalog.json')];
  if (prior) {
    fs.writeFileSync(path.join(root, 'prior.json'),
      `${JSON.stringify({ packages: prior, baseline: [], env: [] }, null, 2)}\n`);
    args.push('--prior', path.join(root, 'prior.json'));
  }
  const result = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(result.status, 0, `collate failed: ${result.stderr}`);
  return { catalog: JSON.parse(fs.readFileSync(path.join(root, 'catalog.json'), 'utf8')), out: result.stdout };
}

/** What ONE platform is actually granted, resolving the overlay the way `catalog_v2.rs` does. The
 *  assertions below are written against this rather than the outer fields, because a `win`-only
 *  overlay is invisible to an outer-field reading — which is the exact blindness under test. */
function effective(grant, plat) {
  const out = {};
  for (const axis of ['read', 'write', 'network', 'writePaths', 'env']) {
    if (grant?.[axis] !== undefined && grant[axis] !== null) out[axis] = grant[axis];
  }
  const overlay = grant?.[plat];
  if (overlay && typeof overlay === 'object') {
    for (const axis of ['read', 'write', 'network', 'writePaths', 'env']) {
      if (!(axis in overlay)) continue;
      if (overlay[axis] === null) delete out[axis];
      else out[axis] = overlay[axis];
    }
  }
  return out;
}

const SHIPPED_WIDE = { demo: { default: { write: 'disk', network: true, notes: 'shipped' } } };

// ── Gate 1: coverage ──────────────────────────────────────────────────────────────────────────

test('GATE 1: a platform with no record keeps the shipped grant instead of inheriting the others', () => {
  // The 107-cell Windows failure in miniature. macOS and Linux measure `network` only; win32 has
  // measured nothing at all. Ungated, the base collapses to the POSIX answer and Windows silently
  // loses whole-disk write.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
  ], SHIPPED_WIDE);
  const d = catalog.packages.demo.default;

  assert.equal(effective(d, 'win').write, 'disk',
    'win32 measured nothing, so it must keep the shipped whole-disk write');
  // …and the gate must not cost the platforms that DID report their narrowing.
  for (const plat of ['macos', 'linux']) {
    assert.equal(effective(d, plat).write, undefined,
      `${plat} measured project-free and must still narrow — a floor that freezes everyone is not a gate`);
    assert.equal(effective(d, plat).network, true, `${plat} keeps what it did measure`);
  }
});

test('GATE 1 CONTROL: the same narrowing publishes once win32 has one valid record', () => {
  // Exactly one thing changes from the case above: win32 reports. The shipped whole-disk write must
  // then go, on all three platforms — otherwise the gate is a freeze wearing a gate's name.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } }),
  ], SHIPPED_WIDE);
  const d = catalog.packages.demo.default;
  for (const plat of ['macos', 'linux', 'win']) {
    assert.equal(effective(d, plat).write, undefined,
      `${plat} must narrow: every platform reported, falsifiably, that it needs no write`);
  }
  assert.equal(d.network, true);
});

test('GATE 1: a STALE record is not coverage — the gate counts validity, not presence', () => {
  // ⛔ THE CASE THE WHOLE MEASUREMENT TURNED ON. All 2,270 win32 records exist on disk; none is
  // valid at the pinned epoch. A gate that asked "is there a record?" would have passed all 107
  // false narrowings while looking exactly like this one.
  const stale = record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } });
  stale.provenance.harnessSha256 = 'stale';
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    stale,
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk',
    'a record from a superseded instrument is not evidence about the current one');
});

// ── Gate 2: falsifiability ────────────────────────────────────────────────────────────────────

test('GATE 2: a narrowing measured on arms that could not have failed is refused', () => {
  // `@pulumi/gcp@0.16.9`'s shape, at catalog scale: the note is present, the descent announced no
  // red arm, and `OVER-PREDICTED` denies the `MINIMAL` inference too. Nothing could have gone red,
  // so the narrowing rests on nothing.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { notes: ['arms-unfalsifiable'], minimality: 'OVER-PREDICTED' }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk',
    'win32 reported, but on a measurement that could not have gone red');
});

test('GATE 2 CONTROL: the identical vacuous record publishes once a drop arm went red', () => {
  // `playwright-chromium@0.17.0`'s shape. ONE field differs from the case above — the driver's own
  // per-arm announcement — and it is the whole difference between "gate-vacuous, so the exit code is
  // still a live detector" and "no detector at all". A two-term rule that refused on the note alone
  // would refuse this correct narrowing, which is the trap `publish-guard.mjs` names by measurement.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { notes: ['arms-unfalsifiable'], minimality: 'OVER-PREDICTED', descentRedArm: true }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, undefined,
    'a descent arm that went red IS the detector firing — this narrowing must publish');
});

test('GATE 2: a record whose arms never saw the subject is blind, though nothing flagged it', () => {
  // ⛔ THE SHAPE THE OTHER TWO GATE-2 CASES CANNOT SEE. Both of those key on `arms-unfalsifiable`,
  // and all 39 of the measured records here carry `notes: []` with `reasons: []` — the vacuity
  // detectors are silent because there was no arm for them to judge. `subjectInObserveTree: false`
  // is the only field that says so, and without it win32 reads as a clean falsifiable measurement.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { subjectInObserveTree: false }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk',
    'win32 reported, but `npm rebuild` ran against a tree with no subject in it');
  // The gate must not cost the two platforms that measured the package for real.
  for (const plat of ['macos', 'linux']) {
    assert.equal(effective(catalog.packages.demo.default, plat).write, undefined,
      `${plat} measured the subject and must still narrow`);
  }
});

test('GATE 2 CONTROL: the identical record publishes once the subject was in the tree', () => {
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { subjectInObserveTree: true }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, undefined,
    'one field differs from the case above; a gate that refused both would freeze the catalog');
});

test('GATE 2: one blind record among sound ones still refuses, because the cell is a UNION', () => {
  // 1.0.0 narrows on a red arm; 2.0.0 narrows on nothing. The cell takes the WIDEST of the two, so a
  // capability 2.0.0 vacuously failed to observe is one the union can never recover — `every`, not
  // `some`, is the only sound aggregation over a union.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { notes: ['arms-unfalsifiable'], minimality: 'OVER-PREDICTED', descentRedArm: true }),
    record({ pkg: 'demo', version: '2.0.0', platform: 'win32-x64', grant: { network: true }, latest: '2.0.0' },
      { notes: ['arms-unfalsifiable'], minimality: 'OVER-PREDICTED' }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk',
    'one record that could not have failed makes the whole cell unproven');
});

// ── the floor's own properties ────────────────────────────────────────────────────────────────

test('the floor only ever WIDENS — a measured widening on a gated platform survives it', () => {
  // The floor is unioned in, never assigned. Pinning a gated platform TO the shipped value would
  // discard a re-measure that found the package needs MORE, which is evidence in the safe direction
  // and the thing a re-measure most reliably produces.
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
  ], { demo: { default: { write: { deps: true }, notes: 'shipped' } } });
  const d = catalog.packages.demo.default;
  assert.equal(effective(d, 'win').network, true, 'the measured network need must reach the gated platform');
  assert.deepEqual(effective(d, 'win').write, { deps: true }, 'and the shipped write must survive beside it');
});

/** The grant a catalog entry resolves at `version` — narrowest `<` bound wins, exactly as nub does.
 *  ⛔ ASSERT ON THE VERSION LINE, NEVER ON A BAND KEY. Two catalogs express the same policy with
 *  different bounds: the generator keeps the WIDEST bound per distinct grant, so a shipped `<2.0.0`
 *  legitimately re-emerges as `<3.0.0` carrying the same caps. A key-wise assertion reads that as a
 *  regression and would have been fixed by weakening the generator. */
function resolveAt(entry, version) {
  const cmp = (a, b) => {
    const part = (v) => String(v).split('.').map((n) => parseInt(n, 10) || 0);
    const [x, y] = [part(a), part(b)];
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  };
  const bounds = Object.keys(entry.versions ?? {}).map((k) => k.slice(1))
    .filter((b) => cmp(version, b) < 0).sort(cmp);
  return bounds.length ? entry.versions[`<${bounds[0]}`] : entry.default;
}

test('a grant the shipped catalog gives only in a BAND still reaches a gated platform', () => {
  // ⛔ THE LEAK THIS PINS, MEASURED ON `@pulumi/gcp`. A first cut floored each version at the
  // shipped grant FOR THAT VERSION, which needs a band to carry the lower interval — and a band is
  // emitted only where the BASE differs from `default`, so a sibling platform's floor lifting the
  // base silently swallowed it. The gated platform's `default` overlay, computed from `latest`
  // alone, then applied all the way down and dropped `write.userHome` below 0.16.9 on macOS, under
  // an entry whose own note said macOS was floored.
  const shipped = {
    default: { network: true, notes: 'shipped' },
    versions: { '<2.0.0': { write: 'disk', network: true, notes: 'shipped band' } },
  };
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '3.0.0', platform: 'darwin-arm64', grant: { network: true } }),
  ], { demo: shipped });
  const entry = catalog.packages.demo;

  // NEVER NARROWER THAN SHIPPED, at every point on the line — the invariant stated as itself rather
  // than as one band key. Wider IS allowed and does occur: the floor is version-uniform, so win32
  // carries the band's whole-disk write above 2.0.0 too. Over-granting is the accepted direction.
  for (const v of ['0.5.0', '1.9.9', '2.0.0', '3.0.0', '9.9.9']) {
    const got = effective(resolveAt(entry, v), 'win');
    const want = effective(resolveAt(shipped, v), 'win');
    for (const [axis, value] of Object.entries(want)) {
      assert.deepEqual(got[axis], value,
        `win32 at ${v} lost the shipped ${axis} — a gated platform may never end up narrower`);
    }
  }
  // …and it must not drag the whole-disk write onto macOS, which measured and reported.
  assert.equal(effective(entry.default, 'macos').write, undefined,
    'macOS measured 3.0.0 and needs no write; the floor is win32-only');
});

// ── the package-level failure, which is the widest under-grant of all ─────────────────────────

test('a package these records say NOTHING about is carried forward, not silently dropped', () => {
  // An absent entry is not a narrower grant, it is NO grant: the override replaces the compiled-in
  // table, so the package falls to the base profile and fails to install. 86 of the 155 measured
  // removals were exactly this.
  const { catalog } = collateRecords([
    record({ pkg: 'other', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
  ], { ...SHIPPED_WIDE, other: { default: { network: true, notes: 'shipped' } } });
  assert.ok(catalog.packages.demo, 'a package with no record at all must keep its shipped entry');
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk');
});

test('CONTROL: a package every platform measured as needing nothing IS dropped', () => {
  // The carve-out that keeps the carry-forward from being a freeze. All three platforms reported,
  // falsifiably, that the package needs nothing — so its removal is a measurement and must stand.
  const { catalog } = collateRecords(
    ['darwin-arm64', 'linux-x64', 'win32-x64'].map((platform) =>
      record({ pkg: 'demo', version: '1.0.0', platform, grant: {} })),
    SHIPPED_WIDE,
  );
  assert.equal(catalog.packages.demo, undefined,
    'an evidenced "needs nothing" must not be resurrected by the floor');
});

test('a "needs nothing" measured on a tree with no subject in it does NOT earn the removal', () => {
  // ⛔⛔ THE SAME FIXTURE AS THE CONTROL ABOVE, DIFFERING IN EXACTLY ONE FIELD, AND IT IS THE WIDEST
  // UNDER-GRANT THE `manifestFiles` DEFECT CAN REACH. The observe arm is `npm rebuild <pkg>`: run
  // against a tree that does not hold `<pkg>` it executes nothing and the synthesized grant is `{}`
  // — byte-identical to a package that genuinely needs nothing. `evidencedDrop` then reads that as
  // an EARNED removal and lets it past the carry-forward floor, and an absent entry runs at the base
  // profile, so the package does not get a narrower grant, it gets none.
  //
  // MEASURED over all 6,887 committed logs: 39 records report `manifestFiles: null`, 13 of them
  // `MINIMUM` at `grant: {}`. None carries `arms-unfalsifiable` — every one reports `reasons: []` —
  // so Gate 2's other terms are all silent on them and this is the term that has to see it.
  const { catalog } = collateRecords(
    ['darwin-arm64', 'linux-x64', 'win32-x64'].map((platform) =>
      record({ pkg: 'demo', version: '1.0.0', platform, grant: {} },
        platform === 'linux-x64' ? { subjectInObserveTree: false } : {})),
    SHIPPED_WIDE,
  );
  assert.notEqual(catalog.packages.demo, undefined,
    'one arm that never saw the package is enough to un-earn the removal — the shipped entry stays');
  assert.equal(effective(catalog.packages.demo.default, 'linux').write, 'disk',
    'and the platform whose arm measured an empty tree keeps the widest grant that ever shipped');
});

// ── the flag itself ───────────────────────────────────────────────────────────────────────────

test('an empty --prior is REFUSED, because it would arm both gates and pass every one', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'collate-gates-'));
  fs.writeFileSync(path.join(root, 'prior.json'), '{"packages":{},"baseline":[],"env":[]}\n');
  const result = spawnSync(process.execPath, [collate, '--runs', path.join(root, 'runs'),
    '--overrides', path.join(root, 'overrides'), '--out', path.join(root, 'catalog.json'),
    '--prior', path.join(root, 'prior.json')], { encoding: 'utf8' });
  assert.equal(result.status, 2, result.stdout);
  assert.match(result.stderr, /carries no non-empty `packages` object/);
});

// ── Gate 3: version coverage ──────────────────────────────────────────────────────────────────
//
// The hole that made the `--prior` re-bake NON-MONOTONE, and neither gate above could see it: the
// platform reported, validly and falsifiably, so gates 1 and 2 both stood aside — and the narrowing
// came from the BAND STRUCTURE moving underneath a per-OS overlay, which neither gate models.

test('GATE 3: a `default` built from a non-latest version cannot narrow the whole line', () => {
  // `@apollo/rover` in miniature. The shipped entry measured npm's `latest` (2.0.0) as needing
  // nothing and carried a band granting `write.deps` below it. This corpus no longer has 2.0.0, so
  // `latest` falls back to 1.0.0, every band collapses into `default`, and `default`'s linux overlay
  // — computed from 1.0.0 ALONE, which linux measured as needing no write — would apply to the whole
  // version line. Linux would lose `write.deps` everywhere, on one release's evidence.
  const prior = {
    demo: {
      default: { notes: 'measured 2.0.0, needs nothing' },
      versions: { '<2.0.0': { write: { deps: true }, network: true, notes: 'shipped band' } },
    },
  };
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true }, latest: '2.0.0' }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { write: { deps: true }, network: true }, latest: '2.0.0' }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: { deps: true }, network: true }, latest: '2.0.0' }),
  ], prior);
  const d = catalog.packages.demo.default;
  assert.deepEqual(effective(d, 'linux').write, { deps: true },
    'linux never measured npm\'s latest, so it may not narrow the shipped band on the strength of 1.0.0');
  assert.match(d.notes, /latest 2\.0\.0 was never measured/,
    'the preservation must be stated in the artefact, not only on stdout');
});

test('GATE 3 CONTROL: the identical narrowing publishes once latest IS measured', () => {
  // Exactly one term changes: the records now carry `latest: 1.0.0`, so the version line reaches
  // npm's real latest and the regeneration speaks for the whole of it. Linux must narrow — a gate
  // that refuses either way is a freeze wearing a gate's name.
  const prior = {
    demo: {
      default: { notes: 'measured 1.0.0' },
      versions: { '<1.0.0': { write: { deps: true }, network: true, notes: 'shipped band' } },
    },
  };
  const { catalog } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true }, latest: '1.0.0' }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { write: { deps: true }, network: true }, latest: '1.0.0' }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { write: { deps: true }, network: true }, latest: '1.0.0' }),
  ], prior);
  const d = catalog.packages.demo.default;
  assert.equal(effective(d, 'linux').write, undefined,
    'linux measured the real latest and needed no write there, so the narrowing is evidenced');
  assert.doesNotMatch(d.notes ?? '', /was never measured/,
    'nothing was floored on version grounds, so nothing may claim to have been');
});

// ── the baseline floor: a FIRST entry may never resolve below `baseline_caps()` ────────────────
//
// 165 of the 166 cells the 2026-09-01 re-bake narrowed were first entries, 72 of them dropping
// egress outright. Both gates above compare against a prior ENTRY, and a new package has none — so
// neither could see it. The floor for such a package is what nub grants it today: the baseline.

test('BASELINE FLOOR: a package with no prior entry cannot be published below the baseline', () => {
  // `node-sass`-shaped: the measurement says "needs a project write and nothing else". Published
  // verbatim that ENTRY REPLACES the baseline, so the package loses egress, the deps write and the
  // whole promotion list — capabilities it held yesterday by being uncatalogued.
  const { catalog } = collateRecords([
    ...['darwin-arm64', 'linux-x64', 'win32-x64'].map((platform) =>
      record({ pkg: 'fresh', version: '1.0.0', platform, grant: { write: { project: true } } })),
  ], { other: { default: { write: 'disk', network: true, notes: 'unrelated' } } });
  for (const plat of ['macos', 'linux', 'win']) {
    const eff = effective(catalog.packages.fresh.default, plat);
    assert.equal(eff.network, true, `${plat}: a first entry may not withdraw the baseline's egress`);
    assert.deepEqual(eff.write, { project: true, deps: true },
      `${plat}: it keeps the measured project write AND the baseline deps write`);
    for (const p of ['.cache', '.npm', '.electron', 'AppData/Local', 'Library/Caches']) {
      assert.ok(eff.writePaths?.includes(p),
        `${plat}: the baseline promotes ${p}, and an entry that omits it strands whatever landed there`);
    }
  }
});

test('BASELINE FLOOR CONTROL: it raises an entry, and never conjures one', () => {
  // A package every platform measured as needing nothing must still be ABSENT, because absence
  // already resolves to exactly this baseline. Flooring it into existence would emit an entry
  // granting precisely what its absence grants — measured at 301 such entries on the real corpus.
  const { catalog } = collateRecords(
    ['darwin-arm64', 'linux-x64', 'win32-x64'].map((platform) =>
      record({ pkg: 'fresh', version: '1.0.0', platform, grant: {} })),
    { other: { default: { write: 'disk', network: true, notes: 'unrelated' } } },
  );
  assert.equal(catalog.packages.fresh, undefined,
    'absence IS the baseline, so a "needs nothing" package must not be floored into the catalog');
});

test('BASELINE FLOOR CONTROL: a package WITH a prior entry may still sit below the baseline', () => {
  // The deliberate-tightening capability `catalog_v2.rs` documents — "a widely-depended-on package
  // may deliberately be granted LESS than an unknown one" — must survive. The floor for a
  // CATALOGUED package is its shipped grant, not the baseline, so a shipped sub-baseline entry that
  // every platform re-measures as still needing nothing more is preserved rather than widened.
  const { catalog } = collateRecords(
    ['darwin-arm64', 'linux-x64', 'win32-x64'].map((platform) =>
      record({ pkg: 'demo', version: '1.0.0', platform, grant: { network: true } })),
    { demo: { default: { network: true, notes: 'deliberately no write, no promotion' } } },
  );
  for (const plat of ['macos', 'linux', 'win']) {
    const eff = effective(catalog.packages.demo.default, plat);
    assert.equal(eff.write, undefined,
      `${plat}: a catalogued package's floor is its shipped grant — the baseline must not widen it`);
    assert.equal(eff.writePaths, undefined, `${plat}: nor restore promotion it deliberately declines`);
  }
});

// ── Gate 4: every floor this run CLAIMED must hold in the emitted catalog ──────────────────────

// Gate 4 re-resolves every floor the run RECORDED against the FINISHED entry, and refuses the whole
// bake when one did not survive. It guards the shape `floorFor`'s header records: `@pulumi/gcp` lost
// `write.userHome` below 0.16.9 on macOS *while its entry carried a note saying macOS was floored*,
// because the floor went into the base and the band model then dropped it. A note asserting a
// preservation that did not happen is worse than no note at all.
//
// ⛔ THE FIXTURE GIVES THE GATED PLATFORM A RECORD, AND THAT IS WHAT MAKES THE TEST FALSIFIABLE. A
// platform with NO record is floored only into the shared base, which it then inherits — so it
// cannot detect a floor that fails to reach a platform's OWN row, and a first draft of this test
// used exactly that fixture and stayed green under the mutation it was written to catch. win32 here
// reports, unfalsifiably, so it is gated by Gate 2 while still owning a row.
//
// MEASURED: deleting the `byVersionOs` union inside the floor loop makes this bake exit 3 naming
// `demo windows`, and takes 12 of this file's bakes down with it.
test('GATE 4: a floor that does not reach the platform\'s own row REFUSES the bake', () => {
  const { catalog, out } = collateRecords([
    record({ pkg: 'demo', version: '1.0.0', platform: 'darwin-arm64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'linux-x64', grant: { network: true } }),
    record({ pkg: 'demo', version: '1.0.0', platform: 'win32-x64', grant: { network: true } },
      { notes: ['arms-unfalsifiable'], minimality: 'OVER-PREDICTED' }),
  ], SHIPPED_WIDE);
  assert.equal(effective(catalog.packages.demo.default, 'win').write, 'disk',
    'win32 was floored and owns a row, so its OWN resolved grant must carry the floor');
  assert.match(out, /gate 4 — every applied floor holds in the output/,
    'the gate must announce that it RAN — a silent gate is indistinguishable from a removed one');
});
