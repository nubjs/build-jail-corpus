// Golden cases for the Linux adapter+classifier (`observe.mjs`), in the shape `classify.test.mjs`
// established for the shared EVENT classifier.
//
// SCOPE, deliberately narrow: the syscall-argument semantics that decide WHICH path a line bills.
// Those are the ones that produce a confident wrong answer rather than a crash — a path that no
// process ever touched still classifies into some scope and still earns a grant.
//
//   node --test harness/v2/observe.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const PROJ = '/home/u/root/observe';
const HOME = '/home/u';
const JAIL = '/home/u/root/jailhome';

// Every case carries the lifecycle shell exec first: attribution runs before scope assignment, so a
// case without one attributes nothing and would pass while asserting nothing.
const SHELL = '100 execve("/usr/bin/sh", ["sh", "-c", "postinstall"], 0x1 /* 1 vars */) = 0\n';

const run = (body, pkg = 'p') => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-')), 'trace.txt');
  fs.writeFileSync(f, SHELL + body);
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, PROJ, HOME, JAIL, pkg], {
    encoding: 'utf8',
  });
  return {
    out,
    grant: JSON.parse(out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim()),
  };
};

// Same as `run`, but the caller picks the project root. Only the scope-classification case below
// needs it: every other case asserts syscall-argument semantics, which the root cannot influence.
// ⛔ Returns the PARSED grant, never the raw text. Asserting `/deps/` against the output substring
// matches the literal header `writePaths FEASIBILITY (distinct writes outside project/deps)` and
// so fails on a correct run — measured, while writing this test.
const grantAtRoot = (body, projRoot, pkg = 'p') => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-')), 'trace.txt');
  fs.writeFileSync(f, SHELL + body);
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, projRoot, HOME, JAIL, pkg], {
    encoding: 'utf8',
  });
  return JSON.parse(out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim());
};

test('a project SOURCE write bills `project` even when the fixture ROOT contains /node_modules/', () => {
  // MAPPING.md rule 2, which names this anti-pattern by example: testing the WHOLE path for
  // `/node_modules/` makes the answer depend on where the fixture happened to live. Under a root
  // that itself sits inside a `node_modules` the same source write flips to `deps`.
  //
  // ⛔ The direction is why this is a test and not a comment: `deps` costs 3 against `project`'s 5,
  // so the misclassification synthesizes the CHEAPER grant — an UNDER-grant. Asserted BOTH ways so
  // the case cannot pass by classifying everything the same: a real dependency under the same
  // awkward root must still bill `deps`.
  const root = '/tmp/x/node_modules/fx';
  const src = grantAtRoot(`200 openat(AT_FDCWD, "${root}/index.js", O_WRONLY|O_CREAT, 0644) = 3\n`, root);
  assert.equal(src.write?.project, true, 'a source write under a root containing /node_modules/ must bill project');
  assert.equal(
    src.write?.deps,
    undefined,
    'billing project source as deps is an UNDER-grant: deps costs 3, project costs 5',
  );

  const dep = grantAtRoot(
    `200 openat(AT_FDCWD, "${root}/node_modules/sibling/i.js", O_WRONLY|O_CREAT, 0644) = 3\n`,
    root,
  );
  assert.equal(dep.write?.deps, true, 'a genuine dependency write must still bill deps under the same root');
});

test('symlink bills the LINKPATH it creates, not the opaque target it stores', () => {
  // The regression that kept `write:{userHome}` alive on vanilla-cookieconsent@3.0.0-rc.9. Taking
  // the first quoted argument resolved `../only-allow/bin.js` against the cwd fallback and invented
  // `/home/u/root/only-allow/bin.js` — under $HOME, so `userHome`, so a grant. The linkpath is in
  // the jail's own private HOME, which the base profile already grants.
  const { grant, out } = run(
    '100 symlink("../only-allow/bin.js", "/home/u/root/jailhome/.npm/_npx/ab/node_modules/.bin/only-allow") = 0\n',
  );
  assert.deepStrictEqual(grant, {}, `expected no capability, got ${JSON.stringify(grant)}\n${out}`);
  assert.match(out, /jailHome\s+1/);
});

test('a symlink into the REAL user home still earns userHome — the fix is a parse, not a filter', () => {
  // The under-prediction this fix must not introduce. A path-prefix exclusion would swallow this.
  const { grant } = run('100 symlink("payload", "/home/u/.config/autostart/x.desktop") = 0\n');
  assert.deepStrictEqual(grant, { write: { userHome: true } });
});

test('link bills the new path, not the existing one it reads', () => {
  const { grant } = run(
    '100 link("/home/u/secret", "/home/u/root/jailhome/copy") = 0\n',
  );
  assert.deepStrictEqual(grant, {});
});

test('rename bills its FIRST argument too — it unlinks the old path as well as creating the new', () => {
  // Deliberately NOT treated like symlink/link: both of rename's arguments are genuine writes, so
  // the old path must keep earning a grant. Asserting this pins the asymmetry as intentional.
  const { grant } = run('100 rename("/home/u/old", "/home/u/root/jailhome/new") = 0\n');
  assert.deepStrictEqual(grant, { write: { userHome: true } });
});

test('a failed call is not a need', () => {
  const { grant } = run(
    '100 symlink("t", "/home/u/.ssh/authorized_keys") = -1 EACCES (Permission denied)\n',
  );
  assert.deepStrictEqual(grant, {});
});

test('the package own directory is not billed; a sibling dependency is', () => {
  // `@apollo/rover@0.2.1`'s real shape: it writes into `binary-install/`, a SIBLING, which the jail
  // does NOT grant (`store_entry_write_root` covers the package's own store entry only). Measured on
  // the real package — the network-only arm exits 1 and produces none of its three artifacts.
  const own = run(
    `100 openat(AT_FDCWD, "${PROJ}/node_modules/@apollo/rover/build/x.node", O_WRONLY|O_CREAT) = 3\n`,
    '@apollo/rover',
  );
  assert.deepStrictEqual(own.grant, {}, 'the package own dir maps to the granted store entry');
  const sibling = run(
    `100 openat(AT_FDCWD, "${PROJ}/node_modules/binary-install/bin/rover", O_WRONLY|O_CREAT) = 3\n`,
    '@apollo/rover',
  );
  assert.deepStrictEqual(sibling.grant, { write: { deps: true } });
});

test('a stream with no lifecycle shell reports UNKNOWN rather than an empty grant', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-')), 'trace.txt');
  fs.writeFileSync(f, '100 openat(AT_FDCWD, "/home/u/x", O_WRONLY|O_CREAT) = 3\n');
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, PROJ, HOME, JAIL, 'p'], {
    encoding: 'utf8',
  });
  assert.match(out, /NO LIFECYCLE SHELL FOUND/);
});
