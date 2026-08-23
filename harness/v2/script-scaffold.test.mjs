// The scaffold decides what the observe arm installs so a lifecycle script can RUN.
//
// ⛔ THE TWO CASES THAT DROVE THE DESIGN ARE PINNED FIRST, because both were measured and both
// refuted a simpler shape. `@paypal/paypal-js@2.1.8` proves the surgical selection (29 devDeps
// declared, exactly ONE needed, and installing all 29 measured rc=1 with an EMPTY `.bin`).
// `@antv/dom-util@2.0.0` proves the fallback map is required at all: its `postinstall` needs `tsc`
// and `typescript` appears NOWHERE in its manifest, so a devDependency-only scaffold finds nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scriptScaffold, commandsIn, resolveScriptCommands, BIN_TO_PACKAGE, UNPROVIDABLE } from './script-scaffold.mjs';

test('takes the version from the package\'s OWN devDependencies, not the bare name', () => {
  // Verbatim from @paypal/paypal-js@2.1.8 (trimmed to the fields that matter).
  const r = scriptScaffold({
    scripts: { postinstall: 'husky install', build: 'rm -rf dist && rollup --config' },
    devDependencies: { husky: '^5.0.9', rollup: '^2.39.0', puppeteer: '^7.1.0', jest: '^26.6.3' },
  });
  assert.deepEqual(r.install, ['husky@^5.0.9'],
    'only the postinstall\'s own binary, at the range the package declares — husky 9 removed `husky install`');
});

test('a MAPPED bin takes the version the package declares for its PROVIDER', () => {
  // ⛔ THE CASE MUTATION TESTING EXPOSED. Where the bin name EQUALS its package name the two
  // resolution branches are redundant, so disabling the provider branch changed nothing and the
  // suite stayed green. The branch only earns its place when the names DIFFER — `tsc` is supplied
  // by `typescript` — and that is exactly where era-correctness lives: TS 3 and TS 5 reject
  // different code, so a bare `typescript` measures a compiler this package never saw.
  const r = scriptScaffold({
    scripts: { postinstall: 'tsc -p .' },
    devDependencies: { typescript: '^3.5.0' },
  });
  assert.deepEqual(r.install, ['typescript@^3.5.0'], 'not bare "typescript"');
});

test('falls back to the bin->package map when no manifest declares the provider', () => {
  // Verbatim from @antv/dom-util@2.0.0: postinstall chains through `build`, and typescript is absent.
  const r = scriptScaffold({
    scripts: { postinstall: 'npm run build', build: 'rm -rf lib && tsc' },
    devDependencies: { '@antv/torch': '^1.0.0', less: '^3.9.0' },
  });
  assert.deepEqual(r.install, ['typescript'], 'tsc resolves through BIN_TO_PACKAGE; `rm` is ambient');
});

test('never scaffolds a binary the tree already provides', () => {
  const r = scriptScaffold(
    { scripts: { postinstall: 'patch-package' }, devDependencies: { 'patch-package': '^6.0.0' } },
    { has: (b) => b === 'patch-package' });
  assert.deepEqual(r.install, [], 'already reachable, so adding it would change the measured environment for nothing');
});

test('a dependency of the package itself is not scaffolded', () => {
  const r = scriptScaffold({ scripts: { install: 'node-gyp-build' }, dependencies: { 'node-gyp-build': '^4.0.0' } });
  assert.deepEqual(r.install, []);
});

test('names what it CANNOT provide rather than guessing a provider', () => {
  const r = scriptScaffold({ scripts: { postinstall: 'pulumi version' } });
  assert.deepEqual(r.install, []);
  assert.equal(r.unprovidable[0].bin, 'pulumi');
  assert.match(r.unprovidable[0].why, /external CLI/);
});

test('node-waf is unprovidable at every era, not a pin we are missing', () => {
  // Removed from Node in 0.8 (2012) — earlier than any Node this corpus can provision, so it must
  // NOT read as a toolchain gap an era pin could close.
  const r = scriptScaffold({ scripts: { install: 'node-waf configure build' } });
  assert.deepEqual(r.install, []);
  assert.equal(r.unprovidable[0].bin, 'node-waf');
});

test('shell builtins and coreutils are ambient, never installed', () => {
  const r = scriptScaffold({ scripts: { postinstall: 'mkdir -p lib && cp -r src lib && echo done' } });
  assert.deepEqual(r.install, []);
  assert.deepEqual(r.ambient.sort(), ['cp', 'echo', 'mkdir']);
});

test('a path-form command is ambient — it ships in the tarball or it does not', () => {
  const r = scriptScaffold({ scripts: { install: './scripts/build.sh' } });
  assert.deepEqual(r.install, [], 'installing a package named "./scripts/build.sh" is nonsense');
});

test('follows an npm run chain, and does not loop on a self-referential script', () => {
  // The two layers are deliberate: `resolveScriptCommands` reports every command it SEES, including
  // the package-manager word, and `scriptScaffold` is what decides ambient vs installable. Asserting
  // on the raw resolver would pin the wrong layer — `npm` legitimately appears there.
  const scripts = { postinstall: 'npm run a', a: 'npm run b', b: 'npm run a && rollup -c' };
  const raw = [...new Set(resolveScriptCommands(scripts, 'postinstall'))];
  assert.deepEqual(raw.sort(), ['npm', 'rollup'], 'terminates on the a -> b -> a cycle and still reaches rollup');
  assert.deepEqual(scriptScaffold({ scripts }).install, ['rollup'], 'and npm is filtered as ambient');
});

test('follows npm\'s pre<x> wrapper, which an install really does run', () => {
  // Verbatim shape from postcss-cssnext@3.0.1, whose record says `sh: rimraf: command not found`.
  // Following only `babelify` never reaches rimraf, and the first version of this module did not.
  const r = scriptScaffold({
    scripts: { postinstall: 'npm run babelify', prebabelify: 'rimraf lib', babelify: 'babel src --out-dir lib' },
    devDependencies: { rimraf: '^2.6.1', 'babel-cli': '^6.6.5' },
  });
  assert.deepEqual(r.install.sort(), ['babel-cli@^6.6.5', 'rimraf@^2.6.1']);
});

test('a package manager at the head of a script is a chain AND a requirement — and is INSTALLED', () => {
  // @rspack/core@0.0.26: the chain leads to plain `node`, so `pnpm` itself is the only real need.
  // Dropping the PM name as noise loses the whole requirement.
  //
  // ⛔ THIS TEST USED TO ASSERT `pnpm` WAS UNPROVIDABLE, and that policy cost 18 rows of the
  // 2026-08-22 ledger their capability profile. pnpm, yarn and bun are npm packages; a package
  // whose postinstall shells out to one genuinely needs it on any machine that installs it, so
  // withholding it measures our refusal rather than the package.
  const r = scriptScaffold({
    scripts: { postinstall: 'pnpm precompile-schema', 'precompile-schema': 'node ./scripts/precompile-schema.js' },
  });
  assert.deepEqual(r.install, ['pnpm'], 'the package manager is the requirement, and npm can supply it');
  assert.deepEqual(r.unprovidable, [], 'nothing here is unprovidable any more');
});

test('npm itself is ambient — it is the installer running the script', () => {
  const r = scriptScaffold({ scripts: { postinstall: 'npm run build', build: 'tsc' }, devDependencies: { typescript: '^4.0.0' } });
  assert.deepEqual(r.install, ['typescript@^4.0.0'], 'npm must not appear as something to install');
});

test('node-gyp is ambient — npm bundles it', () => {
  const r = scriptScaffold({ scripts: { install: 'node-gyp rebuild' } });
  assert.deepEqual(r.install, [], 'libpq@1.9.0 measured this: proposing node-gyp is noise');
});

test('commandsIn steps over env assignments and npx', () => {
  assert.deepEqual(commandsIn('NODE_ENV=production npx tsc -p .'), ['tsc']);
  assert.deepEqual(commandsIn('rm -rf lib && tsc'), ['rm', 'tsc']);
});

test('every BIN_TO_PACKAGE entry maps a bin whose name differs from its package', () => {
  // A self-mapping entry is dead weight: the default already resolves bin -> same-named package.
  for (const [bin, pkg] of Object.entries(BIN_TO_PACKAGE))
    assert.notEqual(bin, pkg, `${bin} maps to itself — delete it, the default covers it`);
});

test('UNPROVIDABLE and BIN_TO_PACKAGE never disagree about the same binary', () => {
  for (const bin of Object.keys(UNPROVIDABLE))
    assert.ok(!(bin in BIN_TO_PACKAGE), `${bin} is both providable and not`);
});
