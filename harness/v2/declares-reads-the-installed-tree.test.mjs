// ⛔⛔ THE PROBE THAT DECIDES "IS `{}` A MEASUREMENT OR A GAP" MUST READ THE INSTALLED TREE.
//
// When the observe arm attributes zero lifecycle pids the drivers ask one question: does this
// package declare an install-time script (or ship a binding.gyp)? "No" means the empty grant is the
// answer; "yes" means the arm measured nothing and the record must be UNKNOWN. Getting that probe
// wrong is not a cosmetic error -- it decides between a real MINIMUM and a fabricated one.
//
// ⛔ `npm view <pkg> scripts` IS NOT AN ORACLE FOR THIS. The registry's `versions[v].scripts` is
// captured from the DEVELOPMENT package.json at publish time; the tarball carries whatever
// `npm pack` produced, and publishing pipelines routinely strip an install-time script before
// packing -- a `postinstall: husky` above all. Only the tarball's copy can ever execute.
//
// MEASURED 2026-08-31, installing each with `--ignore-scripts` and reading what npm actually wrote:
//
//   @stdlib/math-base-special-erfc@0.1.0   registry `install: node-gyp rebuild`   installed: NONE, no binding.gyp
//   eslint-plugin-diff@1.0.9               registry `postinstall`                 installed: NONE
//   @react-hookz/deep-equal@3.0.2          registry `postinstall`                 installed: NONE
//
// An audit that used `npm view` as the oracle flagged 16 valid darwin records as false MINIMUMs on
// exactly this basis. They were correct. This test pins the probe to the tree so the next such audit
// fails here instead of "fixing" a branch that was already right.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const POSIX = ['measure.sh', 'measure-macos.sh'];

/** An observe tree; `scripts: null` writes no scripts field, `pkg: null` installs nothing at all. */
const tree = ({ pkg = 'p', scripts = null, gyp = false } = {}) => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'declares-'));
  if (pkg) {
    const dir = path.join(obs, 'node_modules', ...pkg.split('/'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'),
      JSON.stringify({ name: pkg, version: '1.0.0', ...(scripts ? { scripts } : {}) }));
    if (gyp) fs.writeFileSync(path.join(dir, 'binding.gyp'), '{}');
  }
  return obs;
};

// ⛔ Bound by the code, not a fixed width: the assignment's own closing line is the anchor.
const probe = (driver) => {
  const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
  const start = src.indexOf("  DECLARES=$(node -e '");
  assert.notEqual(start, -1, `${driver}: the declares probe is gone`);
  const close = `' "$OBS" "$PKG" 2>/dev/null)`;
  const end = src.indexOf(close, start);
  assert.notEqual(end, -1, `${driver}: the declares probe does not close as expected`);
  return src.slice(start, end + close.length);
};

const run = (driver, obs, pkg = 'p') => execFileSync('bash', ['-c',
  `set -u\nOBS=${JSON.stringify(obs)}\nPKG=${JSON.stringify(pkg)}\n${probe(driver)}\nprintf '%s' "$DECLARES"`,
], { encoding: 'utf8' });

for (const driver of POSIX) {
  test(`⭑ ${driver}: an install-time script in the INSTALLED manifest reads yes`, () => {
    for (const key of ['preinstall', 'install', 'postinstall']) {
      assert.equal(run(driver, tree({ scripts: { [key]: 'node x.js' } })), 'yes', `${key} must count`);
    }
  });

  test(`⭑ ${driver}: a binding.gyp counts even with no script — npm runs node-gyp anyway`, () => {
    assert.equal(run(driver, tree({ scripts: { test: 'jest' }, gyp: true })), 'yes');
  });

  test(`⭑ CONTROL ${driver}: non-install scripts read NO — this is what makes {} a measurement`, () => {
    assert.equal(run(driver, tree({ scripts: { test: 'make test', build: 'tsc', prepare: 'husky' } })), 'no');
    assert.equal(run(driver, tree({ scripts: null })), 'no');
  });

  test(`⭑ CONTROL ${driver}: the registry cannot influence the answer — a stripped manifest reads NO`, () => {
    // The exact shape of `@stdlib/math-base-special-erfc@0.1.0`: the registry advertises
    // `install: node-gyp rebuild`, the tarball ships neither the script nor a binding.gyp. The probe
    // must answer for the tarball. It is pure fs by construction, which the assertion below pins.
    const obs = tree({ pkg: '@stdlib/math-base-special-erfc', scripts: { test: 'make test' } });
    assert.equal(run(driver, obs, '@stdlib/math-base-special-erfc'), 'no');
    const src = probe(driver);
    for (const forbidden of ['npm view', 'registry', 'https:', 'fetch(']) {
      assert.ok(!src.includes(forbidden),
        `${driver}: the declares probe must not consult ${forbidden} — the tree is the only oracle`);
    }
  });

  test(`⭑ CONTROL ${driver}: an absent subject FAILS CLOSED, never "no"`, () => {
    // "no" would publish an empty grant for a package the arm never even found.
    assert.equal(run(driver, tree({ pkg: null })), 'unreadable');
  });
}

test('⭑ measure-windows.mjs: the same probe, reading `own` from the tree and never the registry', () => {
  const src = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  const at = src.indexOf("declares = named || fs.existsSync(path.join(own, 'binding.gyp')) ? 'yes' : 'no';");
  assert.notEqual(at, -1, 'measure-windows.mjs: the declares decision is gone');
  // The surrounding branch, bounded by code rather than by a character count.
  const from = src.lastIndexOf('try {', at);
  const to = src.indexOf('\n  }', at);
  // ⛔ COMMENTS STRIPPED FIRST. The check is about what the branch DOES, and the note sitting in it
  // explains at length why the registry must not be consulted — so scanning the raw text matches the
  // warning against the thing it warns about, and the test fails on its own documentation.
  const branch = src.slice(from, to).split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  assert.match(branch, /readFileSync/, 'it must read the manifest off disk');
  for (const forbidden of ['npm view', 'registry', 'https:']) {
    assert.ok(!branch.includes(forbidden),
      `measure-windows.mjs: the declares branch must not consult ${forbidden}`);
  }
});
