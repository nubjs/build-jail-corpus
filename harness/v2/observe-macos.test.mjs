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
const decode = (trace, { proj = '/proj', home = '/Users/runner' } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), 'obsmac-'));
  const f = join(dir, 'trace.txt');
  writeFileSync(f, trace.trimStart() + '\n');
  return execFileSync(process.execPath, [join(HERE, 'observe-macos.mjs'), f, proj, home], {
    encoding: 'utf8',
  });
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
