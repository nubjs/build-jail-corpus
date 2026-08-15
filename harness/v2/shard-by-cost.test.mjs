// Sharding decides whether a slice takes 23 h or 93 h, so the balance property is load-bearing.
//
// ⛔ THE FAILURE THIS GUARDS is not "the shards are uneven" in the abstract — it is a lane that drew the
// native-build tail and runs hours past the others while they idle. Measured on win32 records: p50 45 s,
// p90 628 s, 11.89% over ten minutes. So the tests below weight the HEAVY-ROW placement, not the row
// counts, because equal counts are exactly the split that fails.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { shard } from './shard-by-cost.mjs';

const seconds = (lane) => lane.seconds;

test('the HEAVIEST row is placed FIRST, which is what keeps lanes even', () => {
  // ⛔ THE ONE CASE THAT DISCRIMINATES THE ORDERING, found by search rather than intuition. My first
  // attempt at this test passed with the sort REVERSED — four heavies across four lanes balances either
  // way, so it proved nothing. Costs [10,4,4,1,1] over 2 lanes do separate them:
  //   descending (LPT): 10 | 4+4+1+1  -> spread 0
  //   ascending:        1+1+4+4+10    -> spread 10
  // If this ever passes with the sort flipped, it has gone vacuous again.
  const costs = new Map([['h@1', 10], ['m1@1', 4], ['m2@1', 4], ['l1@1', 1], ['l2@1', 1]]);
  const lanes = shard([...costs.keys()], costs, 2, 1);
  const spread = Math.max(...lanes.map(seconds)) - Math.min(...lanes.map(seconds));
  assert.equal(spread, 0,
    `LPT must balance these exactly (10 | 4+4+1+1); a spread of ${spread} means the heavy row was `
    + 'placed after the light ones');
});

test('heavy rows are spread across lanes rather than clustered by count', () => {
  // Four 40-minute rows and twelve 10-second ones. An equal-COUNT split can put all four heavies in one
  // lane; a cost split cannot.
  const heavy = ['a@1', 'b@1', 'c@1', 'd@1'];
  const light = Array.from({ length: 12 }, (_, i) => `l${i}@1`);
  const costs = new Map([...heavy.map((s) => [s, 2400]), ...light.map((s) => [s, 10])]);
  const lanes = shard([...light, ...heavy], costs, 4, 60);
  for (const lane of lanes) {
    const heavies = lane.specs.filter((s) => heavy.includes(s)).length;
    assert.equal(heavies, 1, `each lane must take exactly one heavy row, got ${heavies}`);
  }
  const spread = Math.max(...lanes.map(seconds)) - Math.min(...lanes.map(seconds));
  assert.ok(spread <= 30, `lane spread must stay small, got ${spread}s`);
});

test('an unknown package is priced at the fallback, never at zero', () => {
  // ⛔ ZERO IS THE DANGEROUS DEFAULT. Unknown rows priced free all pile into one lane, which then runs
  // long — the exact imbalance this module exists to prevent, reintroduced by the fallback.
  const lanes = shard(['known@1', 'unknown@1'], new Map([['known@1', 100]]), 2, 100);
  assert.deepEqual(lanes.map(seconds).sort(), [100, 100],
    'the unknown row must carry the fallback cost, so the lanes balance');
});

test('every input spec lands in exactly one lane', () => {
  // A sharder that drops or duplicates rows silently under- or over-measures the corpus.
  const specs = Array.from({ length: 50 }, (_, i) => `p${i}@1`);
  const lanes = shard(specs, new Map(specs.map((s, i) => [s, i])), 7, 1);
  const placed = lanes.flatMap((l) => l.specs);
  assert.equal(placed.length, specs.length, 'no row may be dropped');
  assert.equal(new Set(placed).size, specs.length, 'no row may be duplicated');
});

test('one lane is a valid degenerate case and keeps every row', () => {
  const specs = ['a@1', 'b@1', 'c@1'];
  const lanes = shard(specs, new Map([['a@1', 5], ['b@1', 5], ['c@1', 5]]), 1, 1);
  assert.equal(lanes.length, 1);
  assert.equal(lanes[0].specs.length, 3);
  assert.equal(lanes[0].seconds, 15);
});
