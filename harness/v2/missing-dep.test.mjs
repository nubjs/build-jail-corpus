// Every fixture here is a REAL firstError or tail line from records-v2/observe-only/ledger-2026-08-22,
// with the answer known before the test was written. The point of the module is to convert a failure
// into the one package that would fix it — so a wrong answer installs something unrelated and makes
// the record lie, which is worse than the failure it replaces.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { namesMissingDependency as m } from './missing-dep.mjs';

test('a bare missing module is installable, and a subpath resolves to its package', () => {
  assert.deepEqual(m("Error: Cannot find module 'rollup'"), { kind: 'module', name: 'rollup', install: 'rollup' });
  // `typescript/lib/tsc` and `cypress/package.json` both appear in the ledger.
  assert.equal(m("Cannot find module 'typescript/lib/tsc'").install, 'typescript');
  assert.equal(m("Cannot find module 'cypress/package.json'").install, 'cypress');
  // A scope keeps both segments.
  assert.equal(m("Cannot find module '@babel/core'").install, '@babel/core');
});

test("⛔ the package's OWN missing file is NOT installable", () => {
  // 25 of the 59 missing-module rows name an ABSOLUTE path: the package did not ship its own file,
  // and installing anything is a guess that would make the record wrong.
  assert.equal(m("Cannot find module '/tmp/obs-x/observe/node_modules/@babylonlabs-io/babylon-proto-ts/scripts/build-proto.js'"), null);
  assert.equal(m("Cannot find module 'C:\\\\Users\\\\RUNNER~1\\\\AppData\\\\Local\\\\Temp\\\\obs-cXYNe2\\\\observe\\\\node_modules\\\\jest-stare\\\\lib\\\\render\\\\view.js'"), null);
  assert.equal(m("Cannot find module './generateParams.ts'"), null);
});

test('a runtime-discovered binary resolves to its provider', () => {
  // These are the tools the scaffold never sees, because the manifest script says `node build.js`
  // and the binary is reached from inside that file.
  assert.deepEqual(m("sh: 1: bower: not found"), { kind: 'bin', name: 'bower', install: 'bower' });
  assert.equal(m("'tsc' is not recognized as an internal or external command,").install, 'typescript');
  assert.equal(m("'node-pre-gyp' is not recognized as an internal or external command,").install, '@mapbox/node-pre-gyp');
  assert.equal(m("sh: grunt: command not found").install, 'grunt-cli');
});

test('⛔ a POSIX path invoked under cmd.exe is NOT a package', () => {
  // 22 rows are `'.' is not recognized` / `'scripts' is not recognized` — a `./bin/x` invocation on
  // Windows. There is no package called `.`, and the script genuinely cannot run there; installing
  // something would replace an accurate verdict with a fabricated environment.
  assert.equal(m("'.' is not recognized as an internal or external command,"), null);
  assert.equal(m("'scripts' is not recognized as an internal or external command,"), null);
  assert.equal(m("'node_modules' is not recognized as an internal or external command,"), null);
});

test('⛔ names no npm package supplies stay unprovidable', () => {
  assert.equal(m("'node-waf' is not recognized as an internal or external command,"), null);
  assert.equal(m("sh: pulumi: command not found"), null);
  assert.equal(m("sh: 1: pg_config: not found"), null);
});

test('the package MANAGERS are installable — they are npm packages', () => {
  // 18 rows die on pnpm/yarn/bun. They were on the unprovidable list as "a corpus policy call", but
  // a package whose postinstall shells out to pnpm genuinely needs pnpm, and npm can supply it.
  assert.equal(m("sh: 1: pnpm: not found").install, 'pnpm');
  assert.equal(m("'yarn' is not recognized as an internal or external command,").install, 'yarn');
  assert.equal(m("sh: bun: command not found").install, 'bun');
});

test('a log naming nothing missing yields null', () => {
  assert.equal(m('npm error code 1\nnpm error command failed'), null);
  assert.equal(m(''), null);
  assert.equal(m(null), null);
});
