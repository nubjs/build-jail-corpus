// Golden cases for the macOS OBSERVE decoder. `node --test harness/v2/observe-macos.test.mjs`.
//
// Every fixture below is a VERBATIM slice of a real dtrace stream from run 31087159355 — a real
// `npm rebuild` of a fixture package whose lifecycle script we authored, so the right answer was
// known before the tracer ran. The pids are the real ones: 3896 is node (npm), 3950 is the
// lifecycle shell, 3952/3954/3958 are its children.
//
// ⛔ EACH CASE MUST GO RED ON REVERT. The two it guards are silent-wrong-answer defects — the
// decoder returned a confident result that was wrong, with no error — so a test that passes either
// way is worse than none. Verified by reverting each fix in turn; see the comment on each case.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const HERE = new URL('.', import.meta.url).pathname;

// Runs the decoder over a literal trace and returns its stdout.
// `pkg` is optional on purpose, mirroring the decoder: every case written before the `ownPkg`
// bucket existed still exercises the no-package path, which is the path a re-parse of an archive
// recorded without one has to keep taking.
// Roots reach the classifier ONLY through a capture.json (portability R2), so every case writes one.
// `rootsOverride` is how the undeclared-root cases express a capture that fails to say.
const decode = (trace, { proj = '/proj', home = '/Users/runner', pkg = null, rootsOverride = null } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), 'obsmac-'));
  const f = join(dir, 'trace.txt');
  writeFileSync(f, trace.trimStart() + '\n');
  const roots = rootsOverride ?? {
    project: proj, home, jailHome: null, temp: null, npmPrefix: null, toolsDir: null,
    globalStore: null, projectStore: null, interpreter: null, cwd: null,
    ownPkg: pkg ? `${proj}/node_modules/${pkg}` : null,
  };
  const cap = join(dir, 'capture.json');
  writeFileSync(cap, JSON.stringify({ v: 1, kind: 'capture', pkg, roots }));
  return execFileSync(process.execPath,
    [join(HERE, 'observe-macos.mjs'), f, '--capture', cap], { encoding: 'utf8' });
};

const attributed = (out) => Number(/lifecycle pids: (\d+)/.exec(out)?.[1] ?? -1);
const grant = (out) => /== SYNTHESIZED GRANT[^\n]*==\n\s*(.+)/.exec(out)?.[1]?.trim();

// ── 1. ATTRIBUTION ────────────────────────────────────────────────────────────────────────────
// RED ON REVERT: point isLifecycleShell back at the EXEC record's psargs. macOS pr_psargs carries
// only the command name, so every EXEC line below reads `sh`/`node` with no argv, nothing matches,
// and lifecycle pids goes to 0.
const REAL_SUBTREE = `
DTRACE-LIVE|target=3888
EXEC|3895|3888|sudo|sudo
EXEC|3896|3895|node|node
EXECARGV|3950|3896|sh|-c|echo KAF_LIFECYCLE_7f3a && mkdir -p ./kaf-marker-dir
EXEC|3950|3896|sh|sh
EXEC|3950|3896|bash|bash
CHDIR|3950|3896|bash|ret=0|/proj/node_modules/kaf-lifecycle
EXECARGV|3952|3950|mkdir|-p|./kaf-marker-dir
EXEC|3952|3950|mkdir|mkdir
PATHOP|3952|3950|mkdir|mkdir|ret=0|errno=0|./kaf-marker-dir
`;

test('identifies the lifecycle shell from EXECARGV, which is the only argv source macOS provides', () => {
  const out = decode(REAL_SUBTREE);
  assert.equal(attributed(out), 1, 'exactly the `sh -c` pid should be attributed');
});

test('attributes a child of the lifecycle shell, not just the shell itself', () => {
  // pid 3952 (mkdir) is the package's work; its write must be billed to the script.
  const out = decode(REAL_SUBTREE);
  assert.match(out, /writes\s+script 1\b/, 'the mkdir under the lifecycle shell should be billed');
});

test("does NOT attribute npm's own subtree", () => {
  // node (3896) writing on its own behalf is npm, not the package. Without the filter every
  // package synthesizes network+userHome regardless of behaviour.
  const out = decode(`
DTRACE-LIVE|target=3888
EXEC|3896|3895|node|node
PATHOP|3896|3895|node|mkdir|ret=0|errno=0|/Users/runner/.npm/_logs
`);
  assert.equal(attributed(out), 0, 'no lifecycle shell present');
  assert.match(out, /writes\s+script 0\b/, "npm's own write must not be billed to the package");
});

test('the driver wrapper is a shell but carries no -c, so it must never match', () => {
  // The driver deliberately passes a FILE, never `-c`, precisely to keep this true.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3888|3887|/bin/bash|-x|/Users/runner/v2m-x/observe/run.sh
EXEC|3888|3887|bash|bash
`);
  assert.equal(attributed(out), 0, 'the wrapper must not be mistaken for the lifecycle script');
});

test('a script body containing a pipe survives field-splitting', () => {
  // The record is `|`-delimited and the body is free-form, which is why it is emitted LAST.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|cat foo | grep bar > baz
EXEC|3950|3896|sh|sh
`);
  assert.equal(attributed(out), 1, 'a pipe in the script body must not break attribution');
});

// ── 2. PATH-OP SELECTION ──────────────────────────────────────────────────────────────────────
// RED ON REVERT: take arg0 for symlink in macos-observe.d and the phantom target reappears. This
// case is a decoder-level guard on the same contract — the adapter now reports the LINKPATH, and
// the decoder must bill that path and only that path.
test('a symlink bills the linkpath, and the dangling target is never a write', () => {
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|ln -sf KAFSYMTGT_9c1d_never_created ./kaf-sym-link-4e2b
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3954|3950|ln|symlink|ret=0|errno=0|./kaf-sym-link-4e2b
`);
  assert.match(out, /writes\s+script 1\b/, 'the linkpath is one write');
  assert.doesNotMatch(out, /KAFSYMTGT_9c1d/,
    'the link TARGET is opaque content, never a path any process wrote');
});

test('a rename bills both ends — old is unlinked as well as new being created', () => {
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|mv ./old ./new
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|mv|rename|ret=0|errno=0|./kaf-ren-old-e5f6
PATHOP|3958|3950|mv|rename|ret=0|errno=0|./kaf-ren-new-g7h8
`);
  assert.match(out, /writes\s+script 2\b/, 'rename is a write at both paths');
});

// ── 3. THE LOSS LEDGER ────────────────────────────────────────────────────────────────────────
// RED ON REVERT: drop the TRACER-ERROR branch from observe-macos.mjs. The records then fall through
// the `kind !== …` filter exactly as they did before the adapter emitted them, no warning prints,
// and the decoder reports the same confident grant off a stream it knows is incomplete.
//
// Shaped on run 31109041194, where a 32-bit-truncated `self->np2` made `copyinstr` fault on EVERY
// rename destination: 26 renames, 26 faults, 0 destinations recorded, and
// `{"write":{"deps":true},"network":true}` printed as though nothing were missing.
const LOST_RENAME_DEST = `
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|mv ./old ./new
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|mv|rename|ret=0|errno=0|./kaf-ren-old-e5f6
TRACER-ERROR|3958|3950|mv|epid=31|action=6|fault=3|addr=0x2396f00
TRACER-ERROR-TOTAL|1
`;

test('a dropped event is reported, because a silent drop can only UNDER-predict the grant', () => {
  const out = decode(LOST_RENAME_DEST);
  assert.match(out, /dropped-events=1/, 'the drop must appear in the tracer census');
  assert.match(out, /THE TRACER DROPPED 1 EVENT/,
    'a stream with a known gap must say so loudly, not just synthesize from what survived');
  assert.match(out, /epid=31 action=6/, 'the faulting clause must be named so it can be fixed');
});

test('a clean run says dropped-events=0 and stays quiet', () => {
  // The positive control for the case above. Without it, an assertion that fired on ANY run would
  // read as coverage while proving nothing.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|true
EXEC|3950|3896|sh|sh
TRACER-ERROR-TOTAL|0
`);
  assert.match(out, /dropped-events=0/);
  assert.doesNotMatch(out, /THE TRACER DROPPED/, 'no warning may fire on a complete stream');
});

// ── 4. THE FAILURE VALUE ──────────────────────────────────────────────────────────────────────
// RED ON REVERT: emit JSON.stringify(g) unconditionally and this returns `{}`, which is
// indistinguishable from a package that genuinely needs nothing — already a verified real answer
// on another platform.
test('an unattributed run yields UNKNOWN, never an empty grant', () => {
  const out = decode(`
DTRACE-LIVE|target=3888
EXEC|3896|3895|node|node
`);
  assert.equal(grant(out), 'UNKNOWN-ATTRIBUTION-FAILED');
  assert.match(out, /NO LIFECYCLE SHELL FOUND/, 'the refusal guard must still fire');
});

test('a genuinely empty grant is still expressible as {}', () => {
  // The positive control for the case above: attribution SUCCEEDED and the script needed nothing.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|true
EXEC|3950|3896|sh|sh
`);
  assert.equal(attributed(out), 1);
  assert.equal(grant(out), '{}', 'needing nothing is a real answer and must remain distinct');
});

// ── 5. THE `*at` FAMILY AND THE EXTENDED RECORD ───────────────────────────────────────────────
// MEASURED on run 31116027627: of 86 path-mutating syscalls a realistic install-script workload
// issues, 46 were invisible to the adapter — `unlinkat`, `linkat`, `clonefileat`, `fchmodat` and
// `setattrlistat` among them. Each is a path a grant must cover, so every miss is an UNDER-grant.
// The adapter now subscribes them and carries three new fields; these cases pin both halves.

test('the trailing fields are read by KEY, so a new adapter field cannot shift the path', () => {
  // RED ON REVERT: restore the positional reader (`ret` at 5, `errno` at 6, path at 7+). The path
  // then comes back as `ev=1730…`, which is billed as a written file with a plausible-looking name
  // and no error anywhere — the exact silent-wrong-answer shape this decoder keeps paying for.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|mv ./old ./new
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|mv|renameat|ret=0|errno=0|ev=1730000000|dirfd=-2|role=p1|/opt/at-old-x1
PATHOP|3958|3950|mv|renameat|ret=0|errno=0|ev=1730000000|dirfd=-2|role=p2|/opt/at-new-x2
`);
  assert.match(out, /writes\s+script 2\b/, 'both ends of the renameat are writes');
  // ⛔ THE PATHS ARE ABSOLUTE AND OUTSIDE BOTH ROOTS ON PURPOSE. Only the `outside` bucket is
  // DUMPED; a bucket that is merely COUNTED lets a mangled path pass unseen, and the first draft of
  // this case did exactly that — it stayed green against a deliberately broken reader, because the
  // mangled `/proj/ev=1730…` classified as `project` and was therefore never printed.
  assert.match(out, /\/opt\/at-old-x1/, 'the real path must survive the metadata scan');
  assert.match(out, /\/opt\/at-new-x2/);
  assert.doesNotMatch(out, /ev=1730000000/, 'a metadata token must never be billed as a path');
});

test('unlinkat is a write, exactly as unlink is', () => {
  // RED ON REVERT: drop `unlinkat` from PATH_MUTATOR. The path is then billed as a READ, and a
  // package whose script only removes files synthesizes an empty write grant.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|rm ./gone
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|rm|unlinkat|ret=0|errno=0|ev=1|dirfd=-2|role=only|./at-gone-x3
`);
  assert.match(out, /writes\s+script 1\b/, 'unlinkat destroys a path, so it is a write');
});

test('a relative path under a REAL dirfd is not scope-assigned, because it cannot be resolved', () => {
  // RED ON REVERT: delete the dirfd guard. `abs()` then resolves `rel/phantom-x4` against the cwd
  // and produces `/proj/rel/phantom-x4` — a path no process touched, in a bucket that earns a
  // grant. Same class as billing a symlink's TARGET, which cost a whole capability once already.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|node x.js
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|node|mkdirat|ret=0|errno=0|ev=2|dirfd=7|role=only|rel/phantom-x4
`);
  assert.doesNotMatch(out, /phantom-x4/, 'an unresolvable path must not appear anywhere');
  assert.match(out, /NOTE 1 relative path/, 'and the drop must be reported, not silent');
});

test('the SAME relative path under AT_FDCWD is billed normally', () => {
  // The positive control for the case above. Without it that assertion would pass on a decoder
  // that had simply stopped billing `mkdirat` at all, which is the failure it exists to prevent.
  const out = decode(`
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|node x.js
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj
PATHOP|3958|3950|node|mkdirat|ret=0|errno=0|ev=2|dirfd=-2|role=only|rel/phantom-x4
`);
  assert.match(out, /writes\s+script 1\b/, 'AT_FDCWD resolves against the cwd, so this is billable');
  assert.doesNotMatch(out, /NOTE 1 relative path/, 'and nothing is dropped');
});

// ── 6. THE `ownPkg` BUCKET ────────────────────────────────────────────────────────────────────
//
// The pair below is one boundary, tested from both sides. Only the pair is meaningful: the
// negative case alone would pass on a decoder that had stopped billing writes entirely.
const OWN_VS_SIBLING = `
DTRACE-LIVE|target=3888
EXECARGV|3950|3896|sh|-c|node install.js
EXEC|3950|3896|sh|sh
CHDIR|3950|3896|bash|ret=0|/proj/node_modules/kaf-lifecycle
PATHOP|3952|3950|node|mkdir|ret=0|errno=0|/proj/node_modules/kaf-lifecycle/build
PATHOP|3952|3950|node|mkdir|ret=0|errno=0|/proj/node_modules/sibling-dep/bin
`;

test('a write into the package\'s OWN directory is not billed — the base profile already grants it', () => {
  // RED ON REVERT: drop the `ownPkg` arm from `scope()` and this write buckets as `deps`, which
  // synthesizes `write.deps` — authority over every sibling dependency, manufactured out of a
  // package writing its own build output. MEASURED on hugo-extended@0.141.0, the first
  // darwin-arm64 record: all four of its billed writes were its own `vendor/*`.
  const out = decode(OWN_VS_SIBLING, { pkg: 'kaf-lifecycle' });
  assert.match(out, /ownPkg\s+1\s+\(base profile already grants this/, 'own write is free and says so');
  assert.equal(grant(out), '{"write":{"deps":true}}', 'and ONLY the sibling write survives into the grant');
});

test('a write into a SIBLING dependency is still billed, because the jail genuinely refuses it', () => {
  // The positive control. `store_entry_write_root` grants the package's OWN entry only, so a
  // sibling write is a real refusal in the jail and a real capability here. Without this case the
  // assertion above is satisfied by a decoder that bills nothing at all.
  const out = decode(OWN_VS_SIBLING, { pkg: 'kaf-lifecycle' });
  assert.match(out, /deps\s+1$/m, 'exactly the sibling write lands in deps');
});

test('a capture declaring ownPkg null produces no ownPkg bucket, and says so rather than guessing', () => {
  // `null` is the capture ANSWERING "this run has no such root" — distinct from an absent key, which
  // is the capture failing to answer and is fatal. The bucket must then not exist at all.
  // ⛔ Asserted against the WRITES section, not the whole output: the ROOTS echo prints every root
  // NAME including the null ones, so a whole-output match here would pass on any decoder.
  const out = decode(OWN_VS_SIBLING);
  const writes = out.slice(out.indexOf('== WRITES'), out.indexOf('== READS'));
  assert.doesNotMatch(writes, /ownPkg/, 'a null ownPkg root means no ownPkg write bucket');
  assert.match(out, /ownPkg\s+\(null/, 'but the ROOTS echo still declares it, so R2 stays auditable');
  assert.equal(grant(out), '{"write":{"deps":true}}', 'both writes fall to deps');
});

// ── 7. THE CWD GUARD ──────────────────────────────────────────────────────────────────────────
//
// macOS spawns lifecycle scripts with posix_spawn's in-kernel `addchdir_np`, so no `chdir` syscall
// fires and the decoder's inherited cwd is silently stale. Resolving a relative path against it
// invents one. These cases pin the guard AND the two properties that keep it honest: a pid that
// really did chdir is still resolved normally, and the basename detector may never upgrade a
// resolution to "verified".
const REL_WRITE = `
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj
EXECARGV|3950|3900|sh|-c|node-gyp rebuild > builderror.log
EXEC|3950|3900|sh|sh
OPEN|3952|3950|bash|flags=0x601|ret=3|errno=0|dirfd=-2|builderror.log
`;

test('a relative write from a lifecycle pid that never chdir\'d is not billed to the inherited cwd', () => {
  // RED ON REVERT: drop the guard and `builderror.log` resolves to `/proj/builderror.log` — a path
  // no process touched — and bills `write.project`. MEASURED on ttf2woff2@1.2.3, whose real file is
  // `/proj/node_modules/ttf2woff2/builderror.log`, exactly where Linux recorded it.
  const out = decode(REL_WRITE, { pkg: 'ttf2woff2' });
  assert.doesNotMatch(out, /\/proj\/builderror\.log/, 'the invented absolute path must not appear');
  assert.match(out, /CWD-UNOBSERVED/, 'and the record must be flagged');
});

test('an unplaceable write WIDENS the grant rather than dropping it', () => {
  // Dropping an observed write is an under-grant, the one forbidden direction. We know a write
  // happened and not where, so the grant must cover everywhere it could have landed.
  const out = decode(REL_WRITE, { pkg: 'ttf2woff2' });
  assert.equal(grant(out), '{"write":{"deps":true,"project":true,"userHome":true}}');
});

test('a pid that DID chdir is resolved normally — the guard is not a blanket drop', () => {
  // The positive control. Without it both assertions above are satisfied by a decoder that has
  // simply stopped resolving relative paths at all, which would flag every package on the platform.
  const out = decode(`
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj
EXECARGV|3950|3900|sh|-c|node build.js
EXEC|3950|3900|sh|sh
CHDIR|3950|3900|bash|ret=0|/proj/node_modules/kaf/sub
OPEN|3950|3900|bash|flags=0x601|ret=3|errno=0|dirfd=-2|out.txt
`, { pkg: 'kaf' });
  assert.doesNotMatch(out, /CWD-UNOBSERVED/, 'an observed cwd must not trip the guard');
  assert.match(out, /ownPkg\s+1/, 'and the path resolves into the package dir, which is free');
  assert.equal(grant(out), '{}', 'so nothing is billed');
});

test('a cwd basename MISMATCH proves the inherited cwd wrong and raises severity to STALE', () => {
  const out = decode(REL_WRITE.replace('|dirfd=-2|builderror.log', '|dirfd=-2|cwd=ttf2woff2|builderror.log'), { pkg: 'ttf2woff2' });
  assert.match(out, /Severity: STALE/, 'a mismatch against the believed basename is proof');
});

test('a cwd basename MATCH never downgrades billing — it is "not disproven", not "verified"', () => {
  // ⛔ THE SOUNDNESS PROPERTY. `/a/Observe` and `/b/Observe` share a basename, so a match is equally
  // consistent with a resolution that is still wrong — and that error runs in the under-grant
  // direction. The detector may set severity and may never decide billing.
  const out = decode(`
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj/Observe
EXECARGV|3950|3900|sh|-c|node-gyp rebuild > builderror.log
EXEC|3950|3900|sh|sh
OPEN|3952|3950|bash|flags=0x601|ret=3|errno=0|dirfd=-2|cwd=Observe|builderror.log
`, { proj: '/proj/Observe', pkg: 'ttf2woff2' });
  assert.doesNotMatch(out, /Severity: STALE/, 'a match is not a mismatch');
  assert.match(out, /CWD-UNOBSERVED/, 'but the write is still unplaceable');
  assert.equal(grant(out), '{"write":{"deps":true,"project":true,"userHome":true}}',
    'and it still bills the widest scope — a match must never buy a narrower grant');
});

// ── 8. ROOTS COME ONLY FROM THE CAPTURE (portability R2) ──────────────────────────────────────
const ONE_WRITE = `
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj
EXECARGV|3950|3900|sh|-c|node build.js
EXEC|3950|3900|sh|sh
PATHOP|3952|3950|node|mkdir|ret=0|errno=0|/proj/node_modules/other/x
`;
const ALL_ROOTS = {
  project: '/proj', home: '/Users/runner', jailHome: null, temp: null, npmPrefix: null,
  toolsDir: null, globalStore: null, projectStore: null, interpreter: null, cwd: null, ownPkg: null,
};
const decodeRaw = (roots) => {
  try { decode(ONE_WRITE, { rootsOverride: roots }); return { rc: 0, err: '' }; }
  catch (e) { return { rc: e.status, err: String(e.stderr ?? '') }; }
};

test('an UNDECLARED root is a hard error, not a silent fallback to ambient state', () => {
  // RED ON REVERT: make the check a no-op and the decoder happily classifies against `undefined`
  // roots — producing a plausible grant on the machine whose layout happens to match and a wrong one
  // everywhere else, with nothing in the record saying which happened.
  const { interpreter, ...missing } = ALL_ROOTS;
  const r = decodeRaw(missing);
  assert.equal(r.rc, 3, 'an undeclared root must exit(3)');
  assert.match(r.err, /does not DECLARE these roots: interpreter/, 'and must name the one missing');
});

test('an explicitly null root is ACCEPTED — absent and inapplicable are different answers', () => {
  // The paired case, and it is what stops the guard above being satisfied by a decoder that rejects
  // every capture. `null` is the capture SAYING this platform has no such root; that is an answer.
  const r = decodeRaw(ALL_ROOTS);
  assert.equal(r.rc, 0, 'every root declared, some null, must run');
});

// ── 9. RELATIVE chdir DOES NOT ESTABLISH TRUST ────────────────────────────────────────────────
//
// A fresh-eyes review found the cwd guard re-opened through a side door: `abs()` resolved a relative
// chdir against the untrusted inherited base and then marked the fabricated result OBSERVED. No case
// covered it, which is why the suite stayed green — `cd build && …` is one of the commonest idioms
// in a native install script.
const REL_CHDIR = `
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj
EXECARGV|3950|3900|sh|-c|cd build && node gen.js
EXEC|3950|3900|sh|sh
CHDIR|3950|3900|bash|ret=0|build
OPEN|3950|3900|bash|flags=0x601|ret=3|errno=0|dirfd=-2|out.txt
`;

test('a RELATIVE chdir does not make a fabricated cwd count as observed', () => {
  // RED ON REVERT: restore the unconditional `cwdTrusted.add(pid)` in the CHDIR branch and this
  // yields an unflagged {"write":{"project":true}} billed against the invented /proj/build/out.txt.
  const out = decode(REL_CHDIR, { pkg: 'kaf' });
  assert.match(out, /CWD-UNOBSERVED/, 'the shell chdir\'d relative to a base we never trusted');
  assert.equal(grant(out), '{"write":{"deps":true,"project":true,"userHome":true}}');
});

test('an ABSOLUTE chdir DOES establish trust — the fix is not a blanket distrust of chdir', () => {
  // The positive control. Without it the case above is satisfied by a decoder that stopped trusting
  // chdir entirely, which would flag every package that legitimately changes directory.
  const out = decode(REL_CHDIR.replace('ret=0|build', 'ret=0|/proj/node_modules/kaf/build'),
                     { pkg: 'kaf' });
  assert.doesNotMatch(out, /CWD-UNOBSERVED/, 'an absolute target is self-describing');
  assert.match(out, /ownPkg\s+1/, 'and resolves into the package dir, which is free');
  assert.equal(grant(out), '{}');
});

test('a relative chdir PRESERVES trust once the base is known', () => {
  // The third cell, and the reason the rule is "absolute establishes, relative preserves" rather
  // than "relative is always untrusted": after an absolute chdir the base IS known, so a subsequent
  // relative one resolves correctly and must not re-flag.
  const out = decode(`
DTRACE-LIVE|target=3888
CHDIR|3900|3888|bash|ret=0|/proj
EXECARGV|3950|3900|sh|-c|cd /proj/node_modules/kaf && cd build && node gen.js
EXEC|3950|3900|sh|sh
CHDIR|3950|3900|bash|ret=0|/proj/node_modules/kaf
CHDIR|3950|3900|bash|ret=0|build
OPEN|3950|3900|bash|flags=0x601|ret=3|errno=0|dirfd=-2|out.txt
`, { pkg: 'kaf' });
  assert.doesNotMatch(out, /CWD-UNOBSERVED/, 'the base was established absolutely first');
  assert.match(out, /ownPkg\s+1/, 'so /proj/node_modules/kaf/build/out.txt resolves correctly');
});
