// The verify arm must grant the target's RUNG and scaffold its script-bearing DEPENDENCIES.
//
// ⛔ WHY THIS EXISTS. Granting only the target meant a dependency with its own lifecycle script ran
// under the default deny; when it failed, every rung failed and the driver recorded
// `NO-STATE-PASSED` against the TARGET. Measured on `@hyperjump/json-schema@0.22.0`: target-only
// `{network:true}` rc=1, and so did the widest grant the ladder can express; the same grant applied
// to the target AND its three `@hyperjump/*` deps gave rc=0.
//
// ⛔⛔ AND THE LAST TEST HERE IS THE ONE THAT MATTERS MOST. The fix first landed in `measure.sh`
// alone and was mistaken for done while two drivers still carried the old construction — the SECOND
// such miss (the `T3` tripwire was blind on macOS for the same reason). The cross-driver guard is
// what makes "landed" mean landed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildCatalog, scriptBearingDeps, SCAFFOLD } from './dep-scaffold.mjs';

const HERE = import.meta.dirname;
const RUNG = { write: { deps: true }, network: true };

/** Build a throwaway observe tree. */
function tree(deps) {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'scaf-'));
  for (const [name, scripts] of Object.entries(deps)) {
    const dir = path.join(obs, 'node_modules', ...name.split('/'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', scripts }));
  }
  fs.mkdirSync(path.join(obs, 'node_modules'), { recursive: true });
  return obs;
}

test('⭑ a dependency with a postinstall is scaffolded, and the target keeps its own rung', () => {
  const obs = tree({
    '@hyperjump/json-schema': { postinstall: 'npm install' },
    '@hyperjump/json-schema-core': { postinstall: 'npm install' },
    '@hyperjump/pact': { postinstall: 'echo hi' },
  });
  const { catalog: { packages } } = buildCatalog('@hyperjump/json-schema', RUNG, obs);
  assert.ok(packages['@hyperjump/json-schema-core'], 'the dependency that caused the false verdict must be granted');
  assert.ok(packages['@hyperjump/pact'], 'every script-bearing dependency must be granted, not just the noisy one');

  // ⛔ THE ATTRIBUTION PROPERTY. If deps got the RUNG, dropping a capability during the descent
  // would fail because a DEP still needed it, and the target would keep a capability it never used.
  assert.deepEqual(packages['@hyperjump/json-schema'].default, RUNG, 'the target carries the rung under test');
  assert.deepEqual(packages['@hyperjump/json-schema-core'].default, SCAFFOLD,
    'a dependency must carry the CONSTANT scaffold, never the rung — else the descent cannot attribute');
});

test('⭑ CONTROL: the pre-fix construction granted the target ONLY, so the dependency was denied', () => {
  // The exact shape all three drivers used before this module. It must NOT mention the dependency,
  // otherwise the bug this file guards never existed and every assertion above is theatre.
  const p = '@hyperjump/json-schema';
  const old = { [p]: { default: RUNG } };
  assert.equal(old['@hyperjump/json-schema-core'], undefined);
  assert.deepEqual(Object.keys(old), [p]);
});

test('a dependency with NO lifecycle script is not scaffolded', () => {
  // Otherwise this is an over-grant generator rather than a targeted repair.
  const obs = tree({ a: { postinstall: 'x' }, plain: {}, 'also-plain': { test: 'jest' } });
  assert.deepEqual(scriptBearingDeps(obs, 'a'), [], 'only lifecycle scripts count');
});

test('⭑ the empty grant is CATALOGUED, because omission stopped meaning "nothing"', () => {
  // ⛔ THIS TEST USED TO ASSERT THE OPPOSITE, AND THAT COST THE CORPUS FIVE DAYS. Expressing "grant
  // nothing" by omitting the target was correct until 2026-08-16, when `4001cec5c5` gave an
  // UNCATALOGUED package a baseline grant on the filesystem axis and `ff16f6888d` did the same for
  // egress — and `catalog_v2::baseline_caps()` returns `network: true`. From that day an omitted
  // target was granted the network, so falsify's `hugo-extended@0.141.0` arm downloaded happily and
  // reported `refusal=—`. The runner went red on 2026-08-17 and gated every batch since.
  //
  // nub already supports the right spelling — catalog_v2.rs:807 says an empty grant "is a positive
  // statement under this shape", and the grant parser says of the network key "omit it to grant no
  // egress". So `{ default: {} }` denies everything, which is what the zero rung has always meant.
  const obs = tree({ a: { postinstall: 'x' }, dep: { install: 'node-gyp rebuild' } });
  const { catalog: { packages } } = buildCatalog('a', {}, obs);
  assert.deepEqual(packages.a, { default: {} },
    'an empty grant must be CATALOGUED as an explicitly empty one, never omitted');
  assert.ok(packages.dep, 'dependencies still need scaffolding when the target needs nothing');
});

test('with no dependencies at all, the target alone makes the override engage', () => {
  // The `__v2_empty_grant_sentinel__` existed only because an empty grant left the catalog with
  // nothing in it, so the override would not engage and the arm was VOID. Cataloguing the target
  // removes that hole at its source.
  const obs = tree({ a: { postinstall: 'x' } });
  const { catalog: { packages } } = buildCatalog('a', {}, obs);
  assert.deepEqual(Object.keys(packages), ['a'], 'the target alone is enough for the override to engage');
  assert.equal(packages.__v2_empty_grant_sentinel__, undefined,
    'the sentinel is unreachable now that the target is always present');
});

test('⭑⭑ ALL THREE DRIVERS use the shared builder — none constructs a catalog inline', () => {
  // ⛔ THE GUARD THAT MAKES "LANDED" MEAN LANDED. The scaffold fix went into `measure.sh` and was
  // treated as done while `measure-macos.sh` and `measure-windows.mjs` still had the target-only
  // construction — so the defect it fixed stayed live on two of three platforms. That is the second
  // fix to reach one driver and stop there. A driver that grows its own catalog builder again fails
  // here rather than in the corpus six hours later.
  const DRIVERS = ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs'];
  for (const d of DRIVERS) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.match(src, /dep-scaffold\.mjs/, `${d} must build its catalog through the shared module`);
    // The pre-fix shape, in either language's spelling. Comments are stripped so the explanatory
    // prose quoting the old construction does not trip the guard.
    const code = src.split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l)).join('\n');
    assert.doesNotMatch(code, /packages:\s*\{\s*\[\s*(PKG|p)\s*\]/,
      `${d} builds a target-only catalog inline — that is the exact defect dep-scaffold.mjs exists to prevent`);
  }
});

test('⭑ CONTROL: the inline-catalog pattern the guard looks for is one it can actually detect', () => {
  // Without this the guard could be matching nothing at all and would pass on any input.
  const preFixJs = 'const catalog = { packages: { [PKG]: { default: grant } } };';
  const preFixSh = 'const cat = {packages:{[p]:{default:grant}}};';
  for (const s of [preFixJs, preFixSh]) {
    assert.match(s, /packages:\s*\{\s*\[\s*(PKG|p)\s*\]/, 'the guard pattern must match the real pre-fix code');
  }
});
