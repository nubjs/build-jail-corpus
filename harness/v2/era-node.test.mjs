// Era-Node selection: the cases that cost v1 real verdicts, plus the ones that make the shape safe.
//
// The two failure directions under test are both from v1's measured record: a stale `engines` floor
// pinning a modern package to an ancient Node, and a missing `engines` letting an old package meet a
// V8 that removed the API its C++ calls. Anything that only tests the happy path would have passed
// while both were broken.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chooseEraNode, eraMajorAt, enginesAndDate } from './era-node.mjs';
import { loadNodeMatrix } from './node-matrix.mjs';

const { matrix } = loadNodeMatrix();

test('the era table maps a publish date to the ACTIVE-LTS major, not the newest released one', () => {
  // ⛔ THE SEMANTICS ARE ACTIVE LTS, AND THIS IS THE TEST THAT SAYS SO. Node 20 was RELEASED in
  // April 2023 but only became active LTS on 2023-10-24, so a package published Sept 2023 maps to
  // 18. That is deliberate — package authors target LTS, not current — and it looks like an
  // off-by-one to anyone who reaches for release dates instead. I wrote this expectation as 20
  // first and the table was right.
  assert.equal(eraMajorAt('2023-09-15'), 18, 'Sept 2023: Node 20 exists but 18 is the active LTS');
  assert.equal(eraMajorAt('2023-11-01'), 20, 'just after the Node 20 LTS promotion');
  assert.equal(eraMajorAt('2022-11-01'), 18, 'just after the Node 18 boundary');
  assert.equal(eraMajorAt('2022-10-01'), 16, 'just before it');
  assert.equal(eraMajorAt('2026-01-10'), 24, 'after the Node 24 boundary');
  assert.equal(eraMajorAt(null), null, 'no date is not a date');
  assert.equal(eraMajorAt('not-a-date'), null, 'an unparseable date must not silently become 1970');
});

test('a stale engines floor does NOT drag a modern package onto an ancient Node', () => {
  // @tailwindcss/oxide@4.1.14: published 2025-10, declares `>= 10`. v1's smallest-major heuristic
  // read that as a floor of 10; the publish date is the signal that cannot be stale boilerplate.
  const pick = chooseEraNode({ engines: '>= 10', publishedAt: '2025-10-01', matrix });
  assert.equal(pick.eraMajor, 22, 'Oct 2025 predates the Node 24 boundary');
  assert.equal(pick.major, 22, `a >=10 floor must not lower the era pick, got ${pick.major}`);
  assert.equal(pick.raisedByEngines, false);
});

test('a package with NO engines is measured on its era, not on the newest Node', () => {
  // better-sqlite3@8.7.0 (2023-09) and @rspack/core@0.0.26 (2023-03) had no engines and fell to the
  // newest default, where their C++ met a V8 that had removed `SetAccessor`.
  const pick = chooseEraNode({ engines: null, publishedAt: '2023-09-15', matrix });
  assert.equal(pick.major, 18, `expected the Sept-2023 active LTS (18), got ${pick.major}`);
  assert.notEqual(pick.major, pick.matrixCeiling, 'the era pick must not collapse to the newest major');
});

test('engines RAISES the pick when it genuinely requires newer than the era', () => {
  const pick = chooseEraNode({ engines: '>=24.0.0', publishedAt: '2022-11-01', matrix });
  assert.equal(pick.eraMajor, 18, 'the era is 18');
  assert.equal(pick.major, 24, 'engines is a LOWER bound and must be able to raise');
  assert.equal(pick.raisedByEngines, true);
});

test('a disjunctive range is evaluated, not floored at its smallest major', () => {
  // THE v1 HEURISTIC BUG. `14 || 16 || 18` mentions 14, so a smallest-major read picks 14 — but the
  // range EXCLUDES 15, 17 and everything above 18, so 14 is only right if 14 is reachable at all.
  // With a matrix flooring at 18, the only satisfying candidate is 18.
  const pick = chooseEraNode({ engines: '14 || 16 || 18', publishedAt: '2021-06-01', matrix });
  assert.equal(pick.major, 18, `expected the only satisfying candidate (18), got ${pick.major}`);
  assert.equal(pick.clampedToFloor, true, 'a 2021 package wants Node 16, which the matrix lacks');
});

test('a pre-floor package is clamped to 18 and MARKED, never silently retargeted', () => {
  // uuid@0.0.2 is from 2011. v1 could measure Node 10; v2's matrix starts at 18, so the pin is
  // bounded by what the matrix carries rather than by evidence — and the record must say so.
  const pick = chooseEraNode({ engines: null, publishedAt: '2011-05-01', matrix });
  assert.equal(pick.major, 18);
  assert.equal(pick.clampedToFloor, true,
    'clamping to the matrix floor must be visible in the record, or the corpus silently claims a '
    + '2011 package was measured on the Node it targeted');
});

test('an unsatisfiable engines string still yields a pin, and says it could not be honoured', () => {
  // Refusing to measure would drop the package from the corpus over a bad metadata string, which is
  // strictly worse than measuring it on its era and recording that engines was unsatisfiable.
  const pick = chooseEraNode({ engines: '>=99', publishedAt: '2023-09-15', matrix });
  assert.equal(pick.major, 18, 'falls back to the era pick (Sept 2023 active LTS)');
  assert.equal(pick.enginesUnsatisfiable, true);
  assert.equal(pick.raisedByEngines, false, 'nothing was raised — the range accepts no candidate');
});

test('no publish date falls back to the harness Node, not the newest available', () => {
  const pick = chooseEraNode({ engines: null, publishedAt: null, matrix });
  const harnessMajor = Number(String(matrix.harnessNode).split('.')[0]);
  assert.equal(pick.major, harnessMajor, 'the least surprising default is the Node we already run');
  assert.equal(pick.eraMajor, null);
});

test('every pick names a real matrix entry', () => {
  // A pin naming a version the matrix does not carry cannot be provisioned, and would fail at run
  // time rather than here.
  for (const date of ['2011-05-01', '2019-01-01', '2023-09-15', '2026-02-02', null]) {
    const pick = chooseEraNode({ engines: null, publishedAt: date, matrix });
    assert.ok(matrix.versions.some((v) => v.major === pick.major && v.version === pick.version),
      `pick ${pick.major}/${pick.version} for ${date} is not in the matrix`);
  }
});

test('npm view is read in BOTH of its output shapes', () => {
  // `npm view` collapses to the bare time map when the package has no `engines`, which is exactly
  // the case that needs the date most. A parser handling only the wrapped shape returns
  // published: null there, and the whole date-aware pin goes inert where it matters.
  const wrapped = { 'engines.node': '>=18', time: { '1.2.3': '2023-04-05T00:00:00.000Z' } };
  const bare = { '1.2.3': '2023-04-05T00:00:00.000Z', '1.2.2': '2023-01-01T00:00:00.000Z' };
  const fake = (payload) => () => ({ status: 0, stdout: JSON.stringify(payload) });

  const a = enginesAndDate('demo', '1.2.3', { spawnSync: fake(wrapped) });
  assert.deepEqual(a, { engines: '>=18', published: '2023-04-05T00:00:00.000Z' });

  const b = enginesAndDate('demo', '1.2.3', { spawnSync: fake(bare) });
  assert.equal(b.engines, null, 'the bare shape carries no engines');
  assert.equal(b.published, '2023-04-05T00:00:00.000Z', 'the date must still be recovered');

  const fail = enginesAndDate('demo', '1.2.3', { spawnSync: () => ({ status: 1, stdout: '' }) });
  assert.deepEqual(fail, { engines: null, published: null }, 'a failed view is not an exception');
});
