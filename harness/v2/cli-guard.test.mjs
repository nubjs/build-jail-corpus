// Every shared script's CLI entry guard must fire on WINDOWS as well as POSIX.
//
// ⛔ THIS GUARD IS WHERE ONE WRONG COMPARISON COSTS A WHOLE PLATFORM'S CORPUS, SILENTLY. The idiom
// is `if (import.meta.url === <this file>) { ...the entire CLI... }`, and the naive spelling is
// `` `file://${process.argv[1]}` ``. On Windows `process.argv[1]` is
// `D:\a\repo\harness\v2\record.mjs` while `import.meta.url` is
// `file:///D:/a/repo/harness/v2/record.mjs` — backslashes, and one slash versus three. It NEVER
// matches, so the CLI is skipped, nothing is printed, and the process EXITS 0.
//
// ⛔ AND EVERY CALLER READS THAT AS SUCCESS. `run-batch-v2.mjs` checks `if (w.status !== 0)`, so a
// Windows batch would close every queue row while writing no `results.json` at all: a total loss of
// the measurement with an entirely green log. It was found by a `record.test.mjs` case failing on a
// real runner with `ENOENT ... \repo\results.json` — an empty stdout joined against the CWD — and
// not by anything that was looking for it.
//
// `adapters/windows-retain.mjs` had already been bitten and carried the fix in a comment; the fix
// had not been carried across to the shared files. This test is what makes "carried across" checkable.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';


const HERE = import.meta.dirname;

// ⛔ THE EXEMPTION IS PER-FILE AND NEEDS A REASON, because "this one only runs on Linux" is a claim
// about the file's callers, not about its syntax — and it stops being true the moment someone points
// a second platform at it.
const POSIX_ONLY = new Map([
  ['adapters/linux.mjs', 'the Linux strace adapter; it is invoked only by measure.sh on Linux and has'
    + ' no Windows or macOS caller, so the string form is correct there and only there'],
]);

const SCRIPTS = [];
for (const dir of ['', 'adapters']) {
  const abs = path.join(HERE, dir);
  for (const f of fs.readdirSync(abs)) {
    if (!f.endsWith('.mjs') || f.endsWith('.test.mjs')) continue;
    SCRIPTS.push({ rel: dir ? `${dir}/${f}` : f, abs: path.join(abs, f) });
  }
}

// Both spellings of the guard's opening: the bare comparison, and the `process.argv[1] &&` form the
// import-safety fix introduced. A regex that only knew the first silently stopped finding any guard
// the moment that fix landed — caught by this file's own control, which is what it is for.
const GUARD_LINE = /^\s*if \((?:process\.argv\[1\] && )?import\.meta\.url ===/m;
const NAIVE = /import\.meta\.url === `file:\/\/\$\{process\.argv\[1\]\}`/;

test('CONTROL: the scan finds real CLI guards, so a green result is not vacuous', () => {
  // Without this a typo in GUARD_LINE would make every assertion below pass by matching nothing —
  // the same false negative the guards themselves suffer from.
  const withGuards = SCRIPTS.filter((s) => GUARD_LINE.test(fs.readFileSync(s.abs, 'utf8')));
  assert.ok(withGuards.length >= 4,
    `only ${withGuards.length} CLI guards found across ${SCRIPTS.length} scripts; the scan is broken`);
  const names = withGuards.map((s) => s.rel);
  for (const expect of ['record.mjs', 'adapters/windows-retain.mjs']) {
    assert.ok(names.includes(expect), `the scan missed the known CLI guard in ${expect}`);
  }
});

test('⭑ no shared script uses the CLI guard that silently never fires on Windows', () => {
  const broken = SCRIPTS
    .filter((s) => NAIVE.test(fs.readFileSync(s.abs, 'utf8')) && !POSIX_ONLY.has(s.rel))
    .map((s) => s.rel);
  assert.deepEqual(broken, [],
    'these scripts skip their entire CLI on Windows and exit 0 while doing so, which every caller'
    + ` reads as success:\n  ${broken.join('\n  ')}\n`
    + 'Use `pathToFileURL(process.argv[1]).href`, or add a reasoned POSIX_ONLY entry.');
});

test('a POSIX_ONLY exemption is real and reasoned', () => {
  for (const [rel, why] of POSIX_ONLY) {
    const s = SCRIPTS.find((x) => x.rel === rel);
    assert.ok(s, `POSIX_ONLY names ${rel}, which does not exist — delete the entry`);
    assert.ok(NAIVE.test(fs.readFileSync(s.abs, 'utf8')),
      `${rel} no longer uses the naive guard; remove it from POSIX_ONLY`);
    assert.ok(why.length > 40, `${rel} needs a real reason, not a placeholder`);
  }
});

// ⛔ THE BEHAVIOURAL HALF. The scan above is a grep and could be satisfied by a guard that is
// differently-wrong; this drives the real script the way a caller does and requires it to DO
// something. It cannot reproduce Windows argv on POSIX, so it pins the property that actually
// matters on every platform: invoked as a CLI, `record.mjs` writes a record and names it on stdout.
test('record.mjs invoked as a CLI actually produces a record and prints its path', async () => {
  const { spawnSync } = await import('node:child_process');
  const os = await import('node:os');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cliguard-'));
  const log = path.join(dir, 'd.txt');
  fs.writeFileSync(log, '  => MINIMUM {"write":{"deps":true}}   (observed, then verified)\n');
  const r = spawnSync(process.execPath, [path.join(HERE, 'record.mjs'),
    '--log', log, '--pkg', 'demo', '--version', '1.0.0', '--out', dir, '--platform', 'win32-x64'],
  { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  // ⛔ THE ASSERTION THAT WOULD HAVE CAUGHT THE BUG. A skipped CLI exits 0 with EMPTY stdout, so
  // checking only the exit code is exactly what let this survive.
  assert.notEqual(r.stdout.trim(), '', 'record.mjs printed nothing — its CLI block did not run');
  const out = path.join(r.stdout.trim(), 'results.json');
  assert.ok(fs.existsSync(out), `record.mjs printed ${r.stdout.trim()} but wrote no results.json`);
  const rec = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(rec.verdict, 'MINIMUM');
  assert.equal(rec.provenance.platform, 'win32-x64');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('⭑ a shared script can still be IMPORTED with no argv[1] — the fix\'s own regression', () => {
  // ⛔ THE CORRECT COMPARISON INTRODUCED A NEW FAILURE MODE AND THE TESTS DID NOT CATCH IT.
  // `pathToFileURL(undefined)` THROWS, where the naive string form was wrong on Windows but TOTAL —
  // it simply returned false. So swapping one in without a `process.argv[1] &&` guard means merely
  // IMPORTING the module from a context with no argv[1] dies before any caller runs. `node --test`
  // always supplies argv[1], which is exactly why the suite stayed green; it was found by an
  // unrelated `node -e` one-liner blowing up. Every guarded file is checked, not just record.mjs.
  const guarded = SCRIPTS.filter((s) => /pathToFileURL\(process\.argv\[1\]\)/.test(fs.readFileSync(s.abs, 'utf8')));
  assert.ok(guarded.length >= 2, `only ${guarded.length} scripts use pathToFileURL; the scan is broken`);
  for (const s of guarded) {
    const src = fs.readFileSync(s.abs, 'utf8');
    assert.match(src, /process\.argv\[1\] &&\s*\n?\s*import\.meta\.url ===/,
      `${s.rel} calls pathToFileURL(process.argv[1]) without guarding against argv[1] being absent,`
      + ' so importing it from a context with no argv[1] throws');
  }
});

// ⛔ ONLY THE PORTABLE HALF OF THIS CLAIM IS ASSERTED, DELIBERATELY. `pathToFileURL` applies the
// HOST's path rules and Node exposes no `pathToFileURL.win32`, so "pathToFileURL produces exactly
// the spelling import.meta.url uses on Windows" cannot be checked from macOS or Linux — an attempt
// at it here produced `file:///Users/.../D:%5Ca%5C...`, i.e. it tested the wrong platform's rules
// while looking authoritative. What IS checkable everywhere is the defect itself: the naive form
// does not equal the URL spelling for a native Windows path. The behavioural test above covers the
// positive direction on whichever platform is running.
test('the naive guard cannot match on a native Windows argv, whatever host runs this', () => {
  const winArgv = 'D:\\a\\repo\\harness\\v2\\record.mjs';
  const asImportMetaUrl = 'file:///D:/a/repo/harness/v2/record.mjs';
  assert.notEqual(`file://${winArgv}`, asImportMetaUrl,
    'the naive form matched, so this test no longer describes the failure it guards against');
  // And it is not merely the slash count: the backslashes alone are disqualifying.
  assert.ok(`file://${winArgv}`.includes('\\'),
    'the naive form is expected to carry backslashes, which a file URL never does');
});
