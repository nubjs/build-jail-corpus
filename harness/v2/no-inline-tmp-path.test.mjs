// No workflow may bake a POSIX temp path into a `node -e` program body.
//
// ⛔ THE DEFECT THIS GUARDS, AND WHY GREPPING FOR `/tmp` IS THE WRONG INSTRUMENT. Workflow steps run
// under Git-bash, whose msys2 runtime rewrites POSIX-looking ARGUMENTS and ENV-VAR VALUES into
// Windows paths when spawning a native child. MEASURED in run 31145732202: `--nub /tmp/nub/.../nub.exe`
// reached node.exe as `C:/Users/RUNNER~1/AppData/Local/Temp/nub/.../nub.exe`, and
// `NUB_BUILD_JAIL_CATALOG=/tmp/cat-good.json` reached nub.exe as the rewritten path it then printed.
// So nearly every `/tmp` in these files is CORRECT, and a blanket ban would be a false positive ~30
// times over in `corpus-v2-runner.yml` alone.
//
// What msys2 cannot rewrite is a path buried inside a longer string. A `node -e` program body is one
// argument that does not look like a path, so it arrives verbatim and Node resolves `/tmp/x`
// DRIVE-RELATIVE: `ENOENT ... open 'D:\tmp\verdicts.ndjson'`. That single line is what took the
// Windows lane down on the first run it was ever given.
//
// ⛔ AND THE CRASH WAS THE LUCKY OUTCOME. Had `D:\tmp` existed, a bash writer and a `node -e` reader
// of the identical `/tmp/x` spelling would have used two different files, silently.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const WORKFLOWS = path.join(import.meta.dirname, '..', '..', '.github', 'workflows');
const files = fs.readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));

/** The body of a `node -e '...'` / `node -e "..."` invocation, single- or multi-line. */
const NODE_E = /\bnode\s+(?:--[\w-]+(?:=\S+)?\s+)*-e\s+(['"])([\s\S]*?)\1/g;
const POSIX_TMP = /(?:^|[^\w.-])\/tmp\//;

const bodies = (text) => [...text.matchAll(NODE_E)].map((m) => m[2]);

// ⛔ CONTROL FIRST: a scan that matched no `node -e` at all would report every workflow clean, which
// is exactly the vacuous green this repo keeps getting caught by. Prove the extractor works on a
// string whose answer is known before believing any result it produces.
test('CONTROL: the `node -e` extractor finds a body, and flags a known-bad one', () => {
  const bad = `        run: |\n          node -e '\n            fs.writeFileSync("/tmp/verdicts.ndjson", x);\n          '\n`;
  const found = bodies(bad);
  assert.equal(found.length, 1, 'the extractor did not find the `node -e` body in a known sample');
  assert.ok(POSIX_TMP.test(found[0]), 'the extractor found the body but the /tmp pattern missed it');

  // …and the pattern must NOT fire on the spellings msys2 rewrites correctly, or the guard would
  // demand ~30 pointless edits and be turned off.
  const good = 'node harness/collect-verdicts.mjs --runs records-v2 --out /tmp/verdicts.ndjson';
  assert.equal(bodies(good).length, 0, 'a plain argument is not a `node -e` body and must not match');
});

test('⭑ no workflow embeds a /tmp path inside a `node -e` program', () => {
  const offenders = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(WORKFLOWS, f), 'utf8');
    for (const body of bodies(text)) {
      if (POSIX_TMP.test(body)) offenders.push(`${f}: ${body.trim().split('\n').find((l) => POSIX_TMP.test(l))?.trim()}`);
    }
  }
  assert.deepEqual(offenders, [],
    'these embed a POSIX temp path in a `node -e` body, which msys2 cannot rewrite — Node then '
    + 'resolves it drive-relative on Windows (`D:\\tmp\\...`) and the step dies, or worse, silently '
    + `uses a different file than the bash side does:\n  ${offenders.join('\n  ')}\n`
    + 'Pass the path as an ARGUMENT, or move the program into a real script under `harness/`.');
});

test('CONTROL: the workflow scan is actually reading files that contain `node` invocations', () => {
  // Guards against a wrong WORKFLOWS path making the assertion above pass over an empty set.
  assert.ok(files.length >= 2, `only ${files.length} workflow file(s) found — the path is wrong`);
  const withNode = files.filter((f) => /\bnode\s/.test(fs.readFileSync(path.join(WORKFLOWS, f), 'utf8')));
  assert.ok(withNode.length >= 1, 'no workflow contains a `node` invocation — the scan is not reading them');
});

// ── the same defect class, one layer down: JS SOURCE ──────────────────────────
// The guard above covers workflow YAML. It does NOT cover a POSIX temp path baked into harness JS,
// which is where this bit next: `path.join(process.env.RUNNER_TEMP || '/tmp', …)` appeared in
// `verify-corpus.mjs` and `assert-slice-measured.test.mjs`. Both were GREEN on a GitHub Windows
// runner, which sets RUNNER_TEMP, and both threw `ENOENT … mkdtemp '\tmp\slice-gate-XXXXXX'` on a
// plain Windows box — so CI could never have caught it. `os.tmpdir()` is the portable answer and
// already the idiom in 10+ files here; it honours TMPDIR/TEMP/TMP, so it covers the runner too.
//
// The pattern is deliberately the EXACT literal `'/tmp'`, not any mention of `/tmp`: ~15 harness
// files discuss `/tmp/foo` in prose, and a substring match would fire on all of them and be turned
// off within a day. A path BASE is what gets written as the bare literal.
const HARNESS = path.join(import.meta.dirname, '..');
const SELF = 'no-inline-tmp-path.test.mjs';
const jsFiles = [
  ...fs.readdirSync(HARNESS).filter((f) => f.endsWith('.mjs')).map((f) => ['harness/' + f, path.join(HARNESS, f)]),
  ...fs.readdirSync(import.meta.dirname).filter((f) => f.endsWith('.mjs') && f !== SELF)
    .map((f) => ['harness/v2/' + f, path.join(import.meta.dirname, f)]),
];
const TMP_LITERAL = /(['"])\/tmp\1/;

// ⛔ SCAN CODE, NOT PROSE — and this cost a false positive on the first run. The banned literal
// necessarily appears in the COMMENT that explains the ban (in `verify-corpus.mjs`) and in this
// file's own controls, so a raw line scan flags the documentation of the rule as a violation of it.
// Comment lines are dropped, and this file is exempt for the same reason a lint rule's own fixtures
// are: it must contain the bad spelling to prove the matcher sees it.
const isComment = (line) => /^\s*(\/\/|\*|\/\*)/.test(line);

test('CONTROL: the source scan flags a bare /tmp base and ignores /tmp inside prose or a longer string', () => {
  assert.ok(TMP_LITERAL.test(`path.join(process.env.RUNNER_TEMP || '/tmp', 'x-')`),
    'the pattern missed the exact defect it exists to catch');
  assert.ok(TMP_LITERAL.test('const d = "/tmp";'), 'the pattern must match either quote style');
  // …and must NOT fire on the legitimate spellings, or it is noise that gets switched off:
  assert.equal(TMP_LITERAL.test(`'### thing@1.0.0   (/tmp/v2m-xxxx)   nub=' + on`), false,
    'a /tmp inside a longer literal is a fixture string, not a path base');
  // ⛔ THE CASE MY FIRST ATTEMPT GOT WRONG: real prose here QUOTES the literal while explaining it.
  // A control using unquoted prose passed while the guard was broken, so use the quoted form.
  assert.equal(isComment("// ⛔ `os.tmpdir()`, never `RUNNER_TEMP || '/tmp'`: the fallback is POSIX-only"), true,
    'a comment quoting the banned literal must be recognised as a comment, not scanned as code');
  assert.equal(isComment(`  const dir = fs.mkdtempSync(path.join('/tmp', 'x-'));`), false,
    'real code must NOT be mistaken for a comment, or the guard scans nothing');
});

test('⭑ no harness JS uses a bare `/tmp` literal as a path base — use os.tmpdir()', () => {
  const offenders = [];
  for (const [label, file] of jsFiles) {
    fs.readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
      if (!isComment(line) && TMP_LITERAL.test(line)) offenders.push(`${label}:${i + 1}: ${line.trim()}`);
    });
  }
  assert.deepEqual(offenders, [],
    'these hardcode a POSIX temp path that does not exist on Windows. It survives CI because the '
    + 'GitHub runner sets RUNNER_TEMP, and fails on every other Windows box. Use `os.tmpdir()`, which '
    + `honours TMPDIR/TEMP/TMP:\n  ${offenders.join('\n  ')}`);
});

test('CONTROL: the source scan is reading a real, non-empty set of harness files', () => {
  assert.ok(jsFiles.length >= 20, `only ${jsFiles.length} harness .mjs file(s) found — the path is wrong`);
  // An absence is only meaningful if the scanner can see the construct at all. `os.tmpdir()` is the
  // CORRECT form of the very thing being banned, so its presence proves these files were read.
  const withTmpdir = jsFiles.filter(([, f]) => /os\.tmpdir\(\)/.test(fs.readFileSync(f, 'utf8')));
  assert.ok(withTmpdir.length >= 5,
    `only ${withTmpdir.length} file(s) mention os.tmpdir() — the scan is not reading real sources`);
});
