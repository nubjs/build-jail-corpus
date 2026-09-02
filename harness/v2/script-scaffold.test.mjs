// The scaffold decides what the observe arm installs so a lifecycle script can RUN.
//
// ⛔ THE TWO CASES THAT DROVE THE DESIGN ARE PINNED FIRST, because both were measured and both
// refuted a simpler shape. `@paypal/paypal-js@2.1.8` proves the surgical selection (29 devDeps
// declared, exactly ONE needed, and installing all 29 measured rc=1 with an EMPTY `.bin`).
// `@antv/dom-util@2.0.0` proves the fallback map is required at all: its `postinstall` needs `tsc`
// and `typescript` appears NOWHERE in its manifest, so a devDependency-only scaffold finds nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scriptScaffold, commandsIn, resolveScriptCommands, nodeScriptTargets, spawnedCommandsIn, BIN_TO_PACKAGE, UNPROVIDABLE } from './script-scaffold.mjs';

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
  // ⛔ `pg_config`, NOT `pulumi`. This asserted `pulumi` was unprovidable — "external CLI distributed
  // outside npm" — and on 2026-09-01 that reason turned out to be false: `npm view pulumi bin` returns
  // `{"pulumi":"run.js"}`. It was the largest single remaining `command not found` blocker in the
  // corpus, 11 rows of the 2026-08-22 ledger out of 67 in that whole class, refused on a premise
  // nobody rechecked. The RULE this test guards is still right; its example had to become a binary npm
  // genuinely cannot supply, and a PostgreSQL system tool is one.
  const r = scriptScaffold({ scripts: { postinstall: 'pg_config --libdir' } });
  assert.deepEqual(r.install, []);
  assert.equal(r.unprovidable[0].bin, 'pg_config');
  assert.match(r.unprovidable[0].why, /not an npm package/);
});

test('an external launcher is supplied UNDATED, because its dated artifact is a stub', () => {
  // The other half of the pulumi correction, and why it needs a tier of its own rather than joining
  // `install`. Measured on `@pulumi/kubernetes@0.12.0` (`install: "pulumi plugin install …"`, published
  // 2018-04-25): DATED, `pulumi` resolves 0.0.1 — deprecated, no bin at all — and the arm stays at
  // rc=127 exactly as if nothing had been scaffolded. UNDATED it resolves a real launcher, rc goes
  // 127 -> 1, and the script actually runs.
  const r = scriptScaffold({ scripts: { install: 'pulumi plugin install resource kubernetes v0.12.0' } });
  assert.deepEqual(r.tools, ['pulumi']);
  assert.deepEqual(r.install, [], 'a spec belongs to exactly one tier, or the two race to overwrite');
  assert.deepEqual(r.unprovidable, []);
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
  // ⛔ `tools`, NOT `install` — it moved tiers on 2026-09-01 without changing what it means. A package
  // manager is supplied by BARE NAME and UNDATED for the same reason `pulumi` is: what a script needs
  // is a working PM, and an era-dated one is a period artifact rather than a tool.
  assert.deepEqual(r.tools, ['pnpm'], 'the package manager is the requirement, and npm can supply it');
  assert.deepEqual(r.install, [], 'a spec belongs to exactly one tier');
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

// ── The one-hop `node <file>` scan ────────────────────────────────────────────────────────────────
//
// ⛔ THE CASE THAT DROVE IT, PINNED VERBATIM. `@pulumi/awsx@2.9.0`'s `install` is
// `node scripts/install-pulumi-plugin.js resource awsx v2.9.0`, and the CLI it needs is spawned from
// inside that file. MEASURED over all 86 `@pulumi/*` cells in `records-v2/runs` against their published
// manifests: the script-string parser alone reaches 12; with this scan it reaches 86.

/** The real body of `scripts/install-pulumi-plugin.js`, as published in @pulumi/awsx@2.9.0. */
const PULUMI_WRAPPER = `"use strict";
var childProcess = require("child_process");
var args = process.argv.slice(2);
var res = childProcess.spawnSync("pulumi", ["plugin", "install"].concat(args), {
    stdio: ["ignore", "inherit", "inherit"]
});
process.exit(0);`;

const AWSX = {
  scripts: { install: 'node scripts/install-pulumi-plugin.js resource awsx v2.9.0', build: 'tsc' },
  dependencies: { '@pulumi/pulumi': '^3.0.0' },
};

test('a tool spawned from inside a `node <file>` script is unreachable without a reader, and reached with one', () => {
  assert.deepEqual(scriptScaffold(AWSX).tools, [],
    'the script names only `node`, which is ambient — this is the 74-of-86 miss');
  const withReader = scriptScaffold(AWSX, {
    readFile: (rel) => (rel === 'scripts/install-pulumi-plugin.js' ? PULUMI_WRAPPER : null),
  });
  assert.deepEqual(withReader.tools, ['pulumi'],
    'following the file the script names finds the spawned CLI');
});

test('the reader defaults to absent, so no existing caller sees a changed plan', () => {
  assert.deepEqual(scriptScaffold(AWSX), scriptScaffold(AWSX, {}),
    'an omitted reader and an empty options object must produce the same plan');
});

test('nodeScriptTargets takes only a relative JS file after a bare `node`', () => {
  assert.deepEqual(nodeScriptTargets('node scripts/x.js a b'), ['scripts/x.js']);
  assert.deepEqual(nodeScriptTargets('node ./build.mjs'), ['build.mjs'], 'a leading ./ is normalised away');
  assert.deepEqual(nodeScriptTargets('node -e "require(\'x\')"'), [],
    'an inline -e body is not a file to open');
  assert.deepEqual(nodeScriptTargets('node /etc/passwd.js'), [], 'absolute paths are refused');
  assert.deepEqual(nodeScriptTargets('node ../../outside.js'), [],
    '`..` is refused — the path comes from an untrusted published manifest');
  assert.deepEqual(nodeScriptTargets('tsc && node scripts/post.js'), ['scripts/post.js'],
    'each && segment is considered');
});

test('spawnedCommandsIn reads literal command names and ignores computed ones', () => {
  assert.deepEqual(spawnedCommandsIn(PULUMI_WRAPPER), ['pulumi']);
  assert.deepEqual(spawnedCommandsIn('execSync("pg_config --includedir")'), ['pg_config'],
    'exec takes a whole command line, so only its first word is the binary');
  assert.deepEqual(spawnedCommandsIn('spawnSync(bin, args)'), [],
    'a computed name is deliberately invisible — guessing installs an unrelated package');
  assert.deepEqual(spawnedCommandsIn('spawnSync("./local/tool")'), [],
    'a path is the caller\'s own file, not a PATH lookup');
  assert.deepEqual(spawnedCommandsIn(null), []);
});

test('a reader that throws or returns nothing leaves the plan exactly as it was', () => {
  const thrower = scriptScaffold(AWSX, { readFile: () => { throw new Error('ENOENT'); } });
  assert.deepEqual(thrower.tools, [], 'a missing file must never convert a measurable package into an error');
  assert.deepEqual(scriptScaffold(AWSX, { readFile: () => null }).tools, []);
});

test('a bin whose real provider is scoped never falls through to the squatted bare name', () => {
  // Each bare name is a real published package that would install cleanly and provide nothing:
  // `nuxt-module-build` is a dependency-confusion placeholder, `pkg-utils` is an unrelated browser
  // tool whose bin is `pkg`, and `kiota` is a security holding package with no bin.
  const cases = [
    ['nuxt-module-build', { '@nuxt/module-builder': '0.8.1' }, '@nuxt/module-builder@0.8.1'],
    ['pkg-utils', { '@sanity/pkg-utils': '^7.8.4' }, '@sanity/pkg-utils@^7.8.4'],
    ['kiota', { '@kiota-community/kiota-gen': '^1.0.2' }, '@kiota-community/kiota-gen@^1.0.2'],
  ];
  for (const [bin, devDependencies, expected] of cases) {
    const r = scriptScaffold({ scripts: { prepare: `${bin} --stub` }, devDependencies });
    assert.deepEqual(r.install, [expected],
      `${bin} must resolve through its declared scoped provider, not the bare name`);
  }
});
