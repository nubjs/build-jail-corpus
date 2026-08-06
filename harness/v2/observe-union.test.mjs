// Known-answer cases for the OBSERVE repeat-and-union step.
//
// SCOPE, deliberately narrow: the two properties a wrong answer here would be SILENT about.
//   1. a union of ONE run reproduces that run's own grant exactly — the property that makes the
//      default `NUB_V2_OBSERVE_RUNS=1` a no-op for every existing caller.
//   2. a scope that reaches the grant WIDENS the union, and a scope that does not CANNOT.
// The second is the whole point of reporting a grant-level rate rather than a path-level one: two
// runs differing on hundreds of `outside`/`jailHome` paths produce an identical grant.
//
//   node --test harness/v2/observe-union.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { parseObserved, synthesize, union, grantAgreement, onlyIn } from './observe-union.mjs';

const observed = (writes, grant, sockets = 0) => [
  '== ATTRIBUTION == attributed pids: 3',
  `== NETWORK ==`,
  `  AF_INET sockets: ${sockets}   distinct peers: 0`,
  '== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  '  ' + grant,
  ...writes.map(([s, p]) => `WRITE\t${s}\t${p}`),
].join('\n');

test('a union of one run reproduces that run\'s own grant', () => {
  const r = parseObserved(observed([['deps', '/p/node_modules/a/x'], ['outside', '/tmp/y']],
    '{"write":{"deps":true}}'));
  assert.strictEqual(JSON.stringify(union([r]).grant), r.grant);
});

test('a grant-bearing scope seen in only one run widens the union', () => {
  const a = parseObserved(observed([['deps', '/p/node_modules/a/x']], '{"write":{"deps":true}}'));
  const b = parseObserved(observed([['deps', '/p/node_modules/a/x'], ['userHome', '/h/.cache/z']],
    '{"write":{"deps":true,"userHome":true}}'));
  assert.strictEqual(JSON.stringify(union([a, b]).grant), '{"write":{"deps":true,"userHome":true}}');
  assert.strictEqual(grantAgreement([a, b]).agree, false);
});

test('a difference confined to non-grant-bearing scopes leaves the grant alone', () => {
  // `jailHome`, `ownPkg`, `kernelfs` and `outside` are reported by observe.mjs and billed to
  // nothing, so run-to-run churn there — a pid-stamped temp name is the common case — must not read
  // as a disagreement.
  const a = parseObserved(observed([['deps', '/p/node_modules/a/x'], ['outside', '/tmp/t.1234']],
    '{"write":{"deps":true}}'));
  const b = parseObserved(observed([['deps', '/p/node_modules/a/x'], ['outside', '/tmp/t.5678'],
    ['jailHome', '/jh/.npm/_cacache/q']], '{"write":{"deps":true}}'));
  assert.strictEqual(JSON.stringify(union([a, b]).grant), '{"write":{"deps":true}}');
  assert.strictEqual(grantAgreement([a, b]).agree, true);
  // The path-level diff still REPORTS the churn — it is real, it just decides nothing. Counting it
  // as decisive is the failure this asserts against, because that is what would inflate the rate.
  assert.strictEqual(onlyIn([a, b], 1).only.length, 2);
  assert.strictEqual(onlyIn([a, b], 1).decisive.length, 0);
});

test('network unions across runs even when the later run opens no socket', () => {
  const a = parseObserved(observed([], '{"network":true}', 7));
  const b = parseObserved(observed([], '{}', 0));
  assert.strictEqual(JSON.stringify(union([a, b]).grant), '{"network":true}');
});

test('an unparseable run REFUSES agreement rather than silently supporting it', () => {
  // A run whose grant line never appeared yields `null`, which can never equal another run's text.
  // The safe direction: an unreadable run must not be able to certify two runs as identical.
  const a = parseObserved(observed([], '{}'));
  const b = parseObserved('garbage with no grant line');
  assert.strictEqual(grantAgreement([a, b]).agree, false);
});

test('the whole-tree totals are read off the report, not re-derived', () => {
  // The eviction check is only as good as this parse: a silent `null` here would print `?` and the
  // check would skip itself, which reads as "no problem found".
  const r = parseObserved([
    '  writes  script 12  /  whole traced tree 1088',
    '  sockets script 0  /  whole traced tree 3',
    '  ⛔ 4 trace lines the decoder could not parse',
    '  ⛔ 2 arguments strace TRUNCATED — those paths are incomplete',
  ].join('\n'));
  assert.strictEqual(r.treeWrites, 1088);
  assert.strictEqual(r.treeSockets, 3);
  assert.strictEqual(r.unparsed, 4);
  assert.strictEqual(r.truncated, 2);
});

test('synthesize emits the same key order observe.mjs does', () => {
  assert.strictEqual(
    JSON.stringify(synthesize(new Set(['userHome', 'deps', 'project']), true)),
    '{"write":{"deps":true,"project":true,"userHome":true},"network":true}');
});
