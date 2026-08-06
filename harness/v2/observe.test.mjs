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

// `NUB_V2_DUMP_WRITES` is set on every case on purpose. The human report prints a COUNT plus ten
// examples per bucket, so a case asserting only on the grant cannot tell "the decoder retained this
// path" from "it retained some other path in the same scope" — and several of the losses below are
// exactly that shape: a path that is WRONG rather than absent still bills a plausible scope.
const run = (body, pkg = 'p') => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-')), 'trace.txt');
  fs.writeFileSync(f, SHELL + body);
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, PROJ, HOME, JAIL, pkg], {
    encoding: 'utf8',
    env: { ...process.env, NUB_V2_DUMP_WRITES: '1' },
  });
  return {
    out,
    grant: JSON.parse(out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim()),
    writes: out.split('\n').filter((l) => l.startsWith('WRITE\t')).map((l) => l.split('\t')[2]),
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

// ── The decoding losses, each measured against `probes/syscall-coverage.c` on 2026-08-06 ─────────
//
// The old decoder carried its own strace regexes and retained 18 of the 26 writes that fixture
// actually executed. Each case below pins one mechanism it lost, and each one FAILS against that
// decoder — verified by running this file against it before the fix. They are grouped by mechanism
// rather than by syscall on purpose: `mkdirat`/`unlinkat`/`renameat2` all failed for the single
// reason that their first argument is a number, so they are one case, not three.

test('a rename DESTINATION earns its own grant, not just the source it unlinks', () => {
  // The old matcher took the FIRST quoted argument. `rename(a, b)` touches BOTH — and when only `a`
  // is in already-granted space, taking it alone is a silent UNDER-grant. Measured in the wild: 11
  // rename destinations in lmdb-store@2.0.0-alpha2, 2 in sharp@0.32.6.
  const { grant, writes } = run('100 rename("/home/u/root/jailhome/tmp", "/home/u/.config/persist") = 0\n');
  assert.deepStrictEqual(grant, { write: { userHome: true } });
  assert.ok(writes.includes('/home/u/.config/persist'), `destination missing from ${JSON.stringify(writes)}`);
});

test("glibc's *at rewrites are decoded: chmod/chown/mknod reach the kernel under another name", () => {
  // `chmod()` reaches the kernel as `fchmodat` and `chown()` as `fchownat`, so a filter listing
  // `chmod`/`chown` matches NEITHER. `mknod` was absent from the filter entirely. Measured live: 725
  // fchmodat + 728 fchownat in one sharp@0.32.6 install. A mode or owner change IS a write.
  for (const call of [
    'fchmodat(AT_FDCWD, "/home/u/.ssh/id_rsa", 0600) = 0',
    'fchownat(AT_FDCWD, "/home/u/.ssh/id_rsa", 0, 0, 0) = 0',
    'mknodat(AT_FDCWD, "/home/u/.ssh/fifo", S_IFIFO|0644) = 0',
  ]) {
    const { grant } = run(`100 ${call}\n`);
    assert.deepStrictEqual(grant, { write: { userHome: true } }, `${call} did not bill a write`);
  }
});

test('a *at syscall with a REAL dirfd resolves against that fd, not the project root', () => {
  // strace prints a real dirfd as a NUMBER, and the old matcher required `AT_FDCWD` or a quoted
  // first argument — so it failed the line WHOLE and lost the path. Asserted through a dirfd that
  // points OUTSIDE the project, which is what makes the failure a real capability rather than a
  // relabelling: dropping the line loses a `userHome` grant entirely.
  const open = '100 openat(AT_FDCWD, "/home/u/.local", O_RDONLY|O_DIRECTORY) = 7\n';
  const { grant, writes } = run(`${open}100 openat(7, "share/x", O_WRONLY|O_CREAT, 0644) = 8\n`);
  assert.deepStrictEqual(grant, { write: { userHome: true } });
  assert.ok(writes.includes('/home/u/.local/share/x'), `got ${JSON.stringify(writes)}`);
});

test('symlinkat under a real dirfd bills the linkpath there — and INVENTS nothing', () => {
  // The worst of the five losses, because it does not drop a path, it FABRICATES one. The old code
  // took the last quoted argument and resolved it against the cwd fallback, so a link created inside
  // the jail's own private home was billed at `<project>/link` — a path no process ever touched,
  // which still classified into a scope and still earned a grant on evidence that does not exist.
  const open = '100 openat(AT_FDCWD, "/home/u/root/jailhome/d", O_RDONLY|O_DIRECTORY) = 5\n';
  const { grant, writes } = run(`${open}100 symlinkat("../../secret", 5, "link") = 0\n`);
  assert.deepStrictEqual(grant, {}, 'the linkpath is inside the base-granted private home');
  assert.ok(writes.includes('/home/u/root/jailhome/d/link'), `got ${JSON.stringify(writes)}`);
  assert.ok(!writes.includes(`${PROJ}/link`), 'resolved the linkpath against the project root — a FABRICATED path');
});

test('a path containing a double quote is retained whole, not truncated at the C escape', () => {
  // `"([^"]*)"` stops at the backslash of `\"`, silently and mid-path. The grant does not move here
  // — both halves classify `userHome` — which is exactly why this asserts on the retained PATH:
  // a case checking only the grant would pass while the decoder mangled every path it saw.
  const { writes } = run('100 openat(AT_FDCWD, "/home/u/we\\"ird", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.ok(writes.includes('/home/u/we"ird'), `got ${JSON.stringify(writes)}`);
});

test('cwd survives a clone edge split across `<unfinished ...>`', () => {
  // ⛔ THE ONLY ONE OF THESE THAT MOVED A REAL PACKAGE'S GRANT. strace splits a syscall that blocks
  // into an `<unfinished ...>` / `<... clone resumed>` pair, and the old single-line clone regex
  // matched neither — MEASURED on lmdb-store@2.0.0-alpha2, 287 of its 363 clone edges (79%) are
  // split that way. Losing the edge loses the child's inherited cwd, so node-gyp's relative
  // `./Release/...` writes resolved against the PROJECT ROOT instead of `<pkg>/build`. That
  // fabricated 70 `project` paths and earned the package a `write:{project:true}` it does not need;
  // the real files are under the package's own directory, which the base profile already grants.
  const body =
    `100 chdir("${PROJ}/node_modules/p") = 0\n`
    + '100 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID <unfinished ...>\n'
    + '100 <... clone resumed>)                = 200\n'
    + '200 chdir("build") = 0\n'
    + '200 openat(AT_FDCWD, "./Release/out.o", O_WRONLY|O_CREAT, 0644) = 3\n';
  const { grant, writes } = run(body);
  assert.ok(
    writes.includes(`${PROJ}/node_modules/p/build/Release/out.o`),
    `relative write resolved against the wrong base: ${JSON.stringify(writes)}`,
  );
  assert.deepStrictEqual(grant, {}, 'the package own directory is already base-granted');
});

// ── The private-tmp redirect (`TmpMode::Private`) ────────────────────────────────────────────────

// The private per-run tmp `measure.sh` creates and exports as `TMPDIR`, mirroring
// `backend/mod.rs::make_private_tmp` + `backend/linux.rs::apply_landlock`.
const JTMP = '/tmp/nub-tmp-obsAb12Cd';
const TOOLS = `${HOME}/.cache/nub/pm/tools`;
const runTmp = (body, pkg = 'p') => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-')), 'trace.txt');
  fs.writeFileSync(f, SHELL + body);
  return execFileSync(
    'node',
    [path.join(HERE, 'observe.mjs'), f, PROJ, HOME, JAIL, pkg, JTMP, `${TOOLS}/npm-prefix`],
    { encoding: 'utf8' },
  );
};
const grantOf = (out) => JSON.parse(out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim());

test('a write under the private per-run TMPDIR is base-granted, not an unclassifiable `outside`', () => {
  // ⛔ THE GRANT CANNOT CARRY THIS ASSERTION, so it asserts on the BUCKET. An `outside` write earns
  // no scope either, so both the broken and the fixed classifier emit `{}` — the difference is that
  // the broken one files the path under `outside` and prints "writes OUTSIDE project/home — no scope
  // covers these", which is a standing false alarm on every package that stages a download through
  // `os.tmpdir()`. MEASURED on `playwright-chromium@0.17.0`, whose sole such warning was
  // `/tmp/playwright-download-chromium-linux-764964.zip` — a path the jail grants read-write and
  // points TMPDIR at.
  const out = runTmp(`100 openat(AT_FDCWD, "${JTMP}/dl.zip", O_WRONLY|O_CREAT, 0644) = 3\n`);
  assert.match(out, /jailTmp\s+1/, `the private tmp write was not billed to jailTmp:\n${out}`);
  assert.doesNotMatch(out, /writes OUTSIDE/, `a base-granted tmp write raised the OUTSIDE alarm:\n${out}`);
});

test('the SHARED /tmp stays `outside` — the Landlock arm grants the per-run dir, never /tmp', () => {
  // The control that stops the case above from degenerating into "anything under /tmp is free".
  // There is no mount namespace on the Landlock arm, so `/tmp` itself is bound by nothing and a
  // script hardcoding `/tmp/foo` is genuinely refused. Reporting it is the honest output; absorbing
  // it into a base-covered bucket would be an UNDER-prediction with no rung that repairs it.
  const out = runTmp('100 openat(AT_FDCWD, "/tmp/hardcoded.lock", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.match(out, /outside\s+1/, `a hardcoded /tmp write was not reported as outside:\n${out}`);
  assert.match(out, /writes OUTSIDE/, `the OUTSIDE alarm was suppressed for a genuinely refused path:\n${out}`);
});

test("nub's tool cache is READ-ONLY except the npm prefix, and the classifier splits them", () => {
  // ⛔ BOTH POLARITIES IN ONE CASE, because the failure is a false EQUIVALENCE between four paths
  // that all sit under `$cache/nub/pm/tools`. `grant_build_jail_dependency_reads` grants that
  // directory read-only and then `push_rw_path`s `tools/npm-prefix` alone. Billing the whole
  // directory free is an UNDER-grant on the two redirects that really are refused; billing all of
  // it is a spurious `userHome` on every package whose npm invocation creates a prefix.
  const refused = grantOf(runTmp(
    `100 mkdir("${TOOLS}/ms-playwright/chromium-764964", 0777) = 0\n`,
  ));
  assert.deepStrictEqual(refused, { write: { userHome: true } },
    'a write into the READ-ONLY tool cache is refused in the jail and must earn userHome');

  const granted = runTmp(
    `100 mkdir("${TOOLS}/npm-prefix/lib/node_modules", 0777) = 0\n`,
  );
  assert.match(granted, /npmPrefix\s+1/, `the rw carve-out was not recognised:\n${granted}`);
  assert.deepStrictEqual(grantOf(granted), {},
    'the npm prefix is push_rw_path-granted, so billing it manufactures a userHome grant');
});

test('an UNRESOLVABLE dirfd is reported as UNKNOWN and never guessed into a scope', () => {
  // The honest counterpart to the symlinkat case. When a dirfd was never seen being opened — passed
  // over SCM_RIGHTS, or inherited across an exec the decoder did not witness — there is no base to
  // resolve against. The old code's fallback-to-project-root is what turned that into a fabricated
  // path. A path we cannot place is a DECODING GAP to close, not a capability to grant, so it is
  // counted and printed rather than classified.
  const { grant, out, writes } = run('100 openat(9, "mystery", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.match(out, /1 WRITES with an UNRESOLVED dirfd/);
  assert.deepStrictEqual(grant, {});
  assert.ok(!writes.some((p) => p.endsWith('/mystery')), `invented a path for an unresolvable dirfd: ${JSON.stringify(writes)}`);
});

// ── Python bytecode is never billed ─────────────────────────────────────────────────────────────
//
// Grounds, both required and both stated in `observe.mjs` beside the predicate: MEASURED — 10 of 10
// `mkdir __pycache__` refused EACCES under a real Landlock jail with `rc=0` regardless (lmdb-store,
// caches cleared first, controls in-trace) — and LANGUAGE-LEVEL, since CPython compiles in memory
// when it cannot write the cache. The second is what licenses generalizing from the first.

test('a __pycache__ write under the REAL user home is not billed', () => {
  // The case that motivated this: with Node installed under `$HOME` — `~/.nvm`, and this corpus VM
  // until it was moved — node-gyp's bundled `gyp/pylib` sits inside the home, so CPython writing
  // bytecode beside it billed `write:{userHome}` on every node-gyp package. MEASURED on
  // `@pulumi/gcp@0.16.9`, whose whole grant was that and which needs nothing.
  const { grant, out } = run(
    `100 mkdir("${HOME}/node/lib/node_modules/npm/node_modules/node-gyp/gyp/pylib/gyp/__pycache__", 0777) = 0\n`
    + `100 openat(AT_FDCWD, "${HOME}/node/lib/node_modules/npm/node_modules/node-gyp/gyp/pylib/gyp/__pycache__/input.cpython-312.pyc", O_WRONLY|O_CREAT, 0644) = 3\n`,
  );
  assert.deepStrictEqual(grant, {},
    `bytecode beside a home-installed toolchain manufactured a grant:\n${out}`);
  assert.match(out, /bytecode\s+2/, `the writes were not routed to the bytecode bucket:\n${out}`);
  // The report must say the jail REFUSES these, not that it grants them — the two exclusions have
  // different reasons and collapsing them would make the report claim something untrue.
  assert.match(out, /bytecode.*jail REFUSES these/, `bytecode was reported as base-granted:\n${out}`);
});

test('bytecode is dropped wherever it lands, so the grant does not depend on where Node is installed', () => {
  // The property that makes this a classifier rule rather than a VM configuration detail. The same
  // package built against `/opt/node` and against `~/node` must synthesize the SAME grant; before
  // this rule the first billed `outside` and the second billed `userHome`.
  const inHome = run(`100 openat(AT_FDCWD, "${HOME}/node/lib/x/__pycache__/m.cpython-312.pyc", O_WRONLY|O_CREAT, 0644) = 3\n`);
  const inOpt = run('100 openat(AT_FDCWD, "/opt/node/lib/x/__pycache__/m.cpython-312.pyc", O_WRONLY|O_CREAT, 0644) = 3\n');
  assert.deepStrictEqual(inHome.grant, {}, `home-installed Node still bills:\n${inHome.out}`);
  assert.deepStrictEqual(inOpt.grant, {}, `opt-installed Node still bills:\n${inOpt.out}`);
  assert.deepStrictEqual(inHome.grant, inOpt.grant, 'the grant still depends on the Node install location');
});

test('POSITIVE CONTROL: a non-bytecode write into a sibling dependency still bills `deps`', () => {
  // ⛔ WITHOUT THIS THE TWO CASES ABOVE PASS FOR A CLASSIFIER THAT DROPS EVERYTHING. They assert an
  // ABSENCE, and an absence assertion is satisfied by a predicate that is far too wide as readily as
  // by the correct one. This pins the other side: an ordinary write into the very same
  // `node_modules` tree, differing only in that it is not bytecode, must still earn its scope.
  const { grant, out } = run(
    `100 openat(AT_FDCWD, "${PROJ}/node_modules/node-gyp/gyp/pylib/gyp/generator/make.py", O_WRONLY|O_CREAT, 0644) = 3\n`,
  );
  assert.deepStrictEqual(grant, { write: { deps: true } },
    `the bytecode predicate swallowed an ordinary dependency write — it is too wide:\n${out}`);
});

test('POSITIVE CONTROL: a `.py` SOURCE write is not mistaken for bytecode', () => {
  // `.pyc`/`.pyo` only. A `.py` is source a build may legitimately generate, and dropping it would
  // be an under-grant. Guards the predicate against being loosened to a bare `.py` prefix match.
  const { grant } = run(`100 openat(AT_FDCWD, "${HOME}/gen/thing.py", O_WRONLY|O_CREAT, 0644) = 3\n`);
  assert.deepStrictEqual(grant, { write: { userHome: true } },
    'a generated .py source was dropped as if it were bytecode');
});
