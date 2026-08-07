// The verify arm must grant the target's RUNG and scaffold its script-bearing DEPENDENCIES.
//
// ⛔ WHY THIS EXISTS. Granting only the target meant a dependency with its own lifecycle script ran
// under the default deny; when it failed, every rung failed and the driver recorded
// `NO-STATE-PASSED` against the TARGET. Measured on `@hyperjump/json-schema@0.22.0`: target-only
// `{network:true}` rc=1, and so did the widest grant the ladder can express; the same grant applied
// to the target AND its three `@hyperjump/*` deps gave rc=0.
//
// The script is EXTRACTED FROM `measure.sh` rather than copied, so a test that passes cannot be
// testing a different construction from the one the driver runs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = import.meta.dirname;
const SH = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');

/** The catalog-building `node -e` body, taken from the driver itself. */
function catalogBuilder() {
  const start = SH.indexOf("const [r,p,g,obs]=process.argv.slice(1);");
  assert.ok(start > 0, 'could not find the catalog builder in measure.sh — this test would be vacuous');
  const open = SH.lastIndexOf("node -e '", start);
  const close = SH.indexOf("' \"$v\" \"$PKG\" \"$grant\" \"$OBS\"", start);
  assert.ok(open > 0 && close > start, 'could not delimit the catalog builder');
  return SH.slice(open + "node -e '".length, close);
}

/** Build a throwaway observe tree, then run the extracted builder against it. */
function build({ target, grant, deps }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'scaf-'));
  const obs = path.join(root, 'observe');
  for (const [name, scripts] of Object.entries(deps)) {
    const dir = path.join(obs, 'node_modules', ...name.split('/'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', scripts }));
  }
  fs.mkdirSync(path.join(obs, 'node_modules'), { recursive: true });
  const arm = path.join(root, 'arm');
  fs.mkdirSync(arm, { recursive: true });
  execFileSync(process.execPath, ['-e', catalogBuilder(), arm, target, JSON.stringify(grant), obs]);
  return JSON.parse(fs.readFileSync(path.join(arm, 'cat.json'), 'utf8')).packages;
}

const RUNG = { write: { deps: true }, network: true };

test('⭑ a dependency with a postinstall is scaffolded, and the target keeps its own rung', () => {
  const pkgs = build({
    target: '@hyperjump/json-schema',
    grant: RUNG,
    deps: {
      '@hyperjump/json-schema': { postinstall: 'npm install' },
      '@hyperjump/json-schema-core': { postinstall: 'npm install' },
      '@hyperjump/pact': { postinstall: 'echo hi' },
    },
  });
  assert.ok(pkgs['@hyperjump/json-schema-core'], 'the dependency that caused the false verdict must be granted');
  assert.ok(pkgs['@hyperjump/pact'], 'every script-bearing dependency must be granted, not just the noisy one');

  // ⛔ THE ATTRIBUTION PROPERTY. If deps got the RUNG, dropping a capability during the descent
  // would fail because a DEP still needed it, and the target would keep a capability it never used.
  assert.deepEqual(pkgs['@hyperjump/json-schema'].default, RUNG,
    'the target must carry the rung under test, unchanged');
  assert.notDeepEqual(pkgs['@hyperjump/json-schema-core'].default, RUNG,
    'a dependency must NOT carry the rung — that would make the descent unable to attribute');
});

test('⭑ CONTROL: the pre-fix construction granted the target ONLY, so the dependency was denied', () => {
  // The exact shape measure.sh used before this fix. It must NOT mention the dependency — otherwise
  // the bug this test guards never existed and every assertion above is theatre.
  const grant = RUNG, p = '@hyperjump/json-schema';
  const old = Object.keys(grant).length
    ? { [p]: { default: grant } }
    : { __v2_empty_grant_sentinel__: { default: { network: true } } };
  assert.equal(old['@hyperjump/json-schema-core'], undefined,
    'the pre-fix construction must be shown to omit the dependency');
  assert.deepEqual(Object.keys(old), [p]);
});

test('a dependency with NO lifecycle script is not scaffolded', () => {
  // Otherwise this is an over-grant generator rather than a targeted repair.
  const pkgs = build({
    target: 'a', grant: RUNG,
    deps: { a: { postinstall: 'x' }, plain: {}, 'also-plain': { test: 'jest' } },
  });
  assert.equal(pkgs.plain, undefined, 'a script-less dependency must not be granted');
  assert.equal(pkgs['also-plain'], undefined, 'a non-lifecycle script must not count');
});

test('the empty grant still OMITS the target, and still scaffolds its dependencies', () => {
  // The needs-nothing case is the modal one; expressing it by omission is what makes it measurable.
  const pkgs = build({
    target: 'a', grant: {},
    deps: { a: { postinstall: 'x' }, dep: { install: 'node-gyp rebuild' } },
  });
  assert.equal(pkgs.a, undefined, 'an empty grant must be expressed by omitting the target');
  assert.ok(pkgs.dep, 'dependencies still need scaffolding when the target needs nothing');
});

test('with no dependencies at all, the sentinel still makes the override engage', () => {
  const pkgs = build({ target: 'a', grant: {}, deps: { a: { postinstall: 'x' } } });
  assert.ok(pkgs.__v2_empty_grant_sentinel__,
    'without the sentinel the override would not engage and the arm would be VOID');
});
