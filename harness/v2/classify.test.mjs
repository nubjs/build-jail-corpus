// Known-answer tests for the shared classifier's ROOT handling (VENUE-PORTABILITY R1 + R2).
//
// ⛔ THIS FILE EXISTS BECAUSE THE ENFORCEMENT POINT WAS THE UNTESTED PART. `classify.mjs` decides
// what every path in a trace MEANS, and it used to take `--project`/`--home` as arguments that the
// Windows driver filled from `process.env.USERPROFILE` — so the same events classified against
// different roots on different machines, and nothing anywhere would have said so. The refusal to
// run without a declared root is the mechanism that makes that impossible, and a mechanism whose
// failure path is never exercised is a mechanism nobody has checked.
//
// ⛔ WHAT THESE CAN AND CANNOT PROVE. They pin the CONTRACT: every required root declared or the run
// dies, `null` distinguished from absent, and the same events under two capture files with
// correspondingly-shaped roots producing the same grant. They prove nothing about which bucket is
// CORRECT for a given path — that is a grant-semantics question settled by measurement against the
// real jail, not by a synthetic event stream.
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const CLASSIFY = path.join(import.meta.dirname, 'classify.mjs');
const REQUIRED = ['project', 'home', 'jailHome', 'globalStore', 'projectStore',
                  'interpreter', 'toolsDir', 'temp', 'npmPrefix', 'npmCache', 'ownPkg'];
const ROOT_PID = 100, SHELL_PID = 200;

// The minimum event stream that produces a non-empty grant: a cmd.exe that is not the root PID is a
// lifecycle shell, and a write attributed to it lands in a scope.
const stream = (writePath, project) => [
  { op: 'exec', path: 'C:\\Windows\\System32\\cmd.exe', pid: ROOT_PID, ppid: 1 },
  { op: 'exec', path: 'C:\\Windows\\System32\\cmd.exe', pid: SHELL_PID, ppid: ROOT_PID },
  { op: 'write', path: writePath, pid: SHELL_PID, result: 'ok' },
  { op: 'read', path: `${project}\\package.json`, pid: SHELL_PID, result: 'ok' },
];

function classify(events, roots, { expectFail = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'classify-'));
  const nd = path.join(dir, 'events.ndjson');
  const cap = path.join(dir, 'capture.json');
  const jsonOut = path.join(dir, 'observed.json');
  fs.writeFileSync(nd, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
  // `roots === null` writes a capture with NO roots key at all, which is its own failure mode.
  fs.writeFileSync(cap, JSON.stringify(roots === null ? { v: 1 } : { v: 1, roots }));
  const r = spawnSync(process.execPath,
    [CLASSIFY, nd, '--capture', cap, '--platform', 'win32', '--root-pid', String(ROOT_PID), '--json', jsonOut],
    { encoding: 'utf8' });
  const report = r.status === 0 ? JSON.parse(fs.readFileSync(jsonOut, 'utf8')) : null;
  fs.rmSync(dir, { recursive: true, force: true });
  if (!expectFail) assert.equal(r.status, 0, `classify exited ${r.status}\n${r.stderr}`);
  return { status: r.status, stderr: r.stderr, stdout: r.stdout, report };
}

// A complete, well-formed root set. `null` where the platform genuinely has none — which is an
// ANSWER, and the tests below prove it is accepted as one.
const fullRoots = (project = 'C:\\obs', home = 'C:\\Users\\nub') => ({
  project,
  home,
  jailHome: null,
  globalStore: `${home}\\AppData\\Local\\nub\\pm\\store`,
  projectStore: `${project}\\node_modules\\.store`,
  interpreter: 'C:\\Program Files\\nodejs\\node.exe',
  toolsDir: `${home}\\AppData\\Local\\nub\\pm\\tools`,
  temp: `${home}\\AppData\\Local\\Temp`,
  npmPrefix: null,
  // `null` by default so every case below keeps exercising the shape a capture has when it did not
  // redirect npm's cache; the section at the foot of this file supplies a real one.
  npmCache: null,
  ownPkg: `${project}\\node_modules\\thing`,
  cwd: null,
});

test('a complete capture classifies, and the report says what it was classified against', () => {
  const r = classify(stream('C:\\obs\\node_modules\\thing\\build\\x.node', 'C:\\obs'), fullRoots());
  assert.deepEqual(r.report.grant, { write: { deps: true } });
  // The record must carry its own roots, or a grant that disagrees across two venues cannot be
  // explained without going back to runs that no longer exist.
  assert.deepEqual(Object.keys(r.report.roots).sort(), REQUIRED.slice().sort());
  // `jailTmp` is keyed on whenever the capture declares a temp root, which `fullRoots` does.
  assert.deepEqual(r.report.keyedOn.sort(), ['deps', 'jailTmp', 'project', 'userHome']);
});

test('⭑ an UNDECLARED root is a hard error, not a fallback', () => {
  // ⛔ THE WHOLE OF R2 IS THIS ASSERTION. A fallback keeps running and emits a plausible grant, so
  // the failure surfaces as a wrong catalog entry on one machine rather than as a crash on every
  // machine. Each required root is dropped in turn, because a check that only ever sees one missing
  // key is a check that could be keyed on that key.
  for (const missing of REQUIRED) {
    const roots = fullRoots();
    delete roots[missing];
    const r = classify(stream('C:\\obs\\x', 'C:\\obs'), roots, { expectFail: true });
    assert.equal(r.status, 3, `dropping \`${missing}\` did not fail the run (rc=${r.status})`);
    assert.match(r.stderr, new RegExp(`does not DECLARE these roots.*\\b${missing}\\b`),
      `dropping \`${missing}\` failed for some other reason:\n${r.stderr}`);
  }
});

test('an explicit null is an ANSWER and is accepted; a capture with no roots at all is not', () => {
  // The distinction is the point: `null` is the capture SAYING this platform has no such root, an
  // absent key is the capture failing to say. Collapsing them would let a stale writer opt out.
  const withNulls = fullRoots();
  assert.equal(withNulls.jailHome, null);
  assert.equal(classify(stream('C:\\obs\\x', 'C:\\obs'), withNulls).status, 0);

  const r = classify(stream('C:\\obs\\x', 'C:\\obs'), null, { expectFail: true });
  assert.equal(r.status, 3);
  assert.match(r.stderr, /does not DECLARE these roots/);
});

test('a null on a root the classifier KEYS ON is refused rather than matched as the string "null"', () => {
  // ⛔ THE SILENT-MISCLASSIFICATION TRAP. A `null` reaching `startsWith` becomes the literal text
  // "null", which matches nothing and sends every path to `outside` — reported, never granted, i.e.
  // an under-grant, with no error anywhere. Ten roots may be null; the two keyed on may not.
  for (const keyed of ['project', 'home']) {
    const roots = fullRoots();
    roots[keyed] = null;
    const r = classify(stream('C:\\obs\\x', 'C:\\obs'), roots, { expectFail: true });
    assert.equal(r.status, 3, `a null \`${keyed}\` was accepted`);
    assert.match(r.stderr, new RegExp(`declares \`${keyed}\` as null`));
  }
});

test('⭑ THE VENUE CONTROL: correspondingly-shaped roots on two machines give the SAME grant', () => {
  // ⛔ THIS IS THE ACCEPTANCE TEST'S CLAIM, REDUCED TO ONE ASSERTION. Two venues have different
  // absolute paths and must produce an identical grant; a harness whose LOGS matched would be one
  // that had flattened a real difference, so the grant is what has to agree.
  //
  // The negative half is in the same test on purpose: a run that only ever reports a match has not
  // been shown able to find a mismatch.
  const vm = classify(stream('C:\\obs\\node_modules\\thing\\build\\x.node', 'C:\\obs'),
    fullRoots('C:\\obs', 'C:\\Users\\nub'));
  const ci = classify(stream('D:\\a\\w\\obs\\node_modules\\thing\\build\\x.node', 'D:\\a\\w\\obs'),
    fullRoots('D:\\a\\w\\obs', 'C:\\Users\\runneradmin'));
  assert.deepEqual(ci.report.grant, vm.report.grant,
    'the same write classified differently under two venues\' roots');

  // NEGATIVE CONTROL, and it perturbs a root this stream ACTUALLY USES. Pointing `project` at a
  // directory the write does not sit under moves it from `deps` to `outside`, so the grant changes.
  // A control that perturbed a root the events never touch would pass while detecting nothing.
  const wrong = classify(stream('C:\\obs\\node_modules\\thing\\build\\x.node', 'C:\\obs'),
    fullRoots('C:\\somewhere-else', 'C:\\Users\\nub'));
  assert.notDeepEqual(wrong.report.grant, vm.report.grant,
    'a deliberately wrong project root produced the SAME grant — the comparison cannot detect a difference');
  assert.deepEqual(wrong.report.grant, {}, 'the wrong-root write should fall to `outside`, which grants nothing');
  assert.equal(wrong.report.writes.outside, 1);
});

test('roots are longest-prefix, so the package dir nested in the project resolves to deps', () => {
  // Rule 2. `deps` is inside `project`, so a substring or first-match rule would bill a dependency
  // write to the project and quietly widen every native package's grant.
  const r = classify(stream('C:\\obs\\node_modules\\thing\\build\\x.node', 'C:\\obs'), fullRoots());
  assert.deepEqual(r.report.grant, { write: { deps: true } });
  const p = classify(stream('C:\\obs\\out.txt', 'C:\\obs'), fullRoots());
  assert.deepEqual(p.report.grant, { write: { project: true } });
});

test('classification is case-insensitive on Windows, as the filesystem is', () => {
  // Rule 1. The kernel reports whichever casing the caller used, so a case-sensitive comparison
  // sends a real dependency write to `outside` — reported, never granted.
  const r = classify(stream('C:\\OBS\\Node_Modules\\thing\\build\\X.node', 'C:\\obs'), fullRoots());
  assert.deepEqual(r.report.grant, { write: { deps: true } });
});

// ── The declared private temp (`jailTmp`) ───────────────────────────────────────────────────────
//
// ⛔ THE RULE HAS TWO HALVES AND THE SECOND IS THE ONE THAT KEEPS IT SAFE. A write under the
// DECLARED temp root is not billed, because the build-jail preset sets `fs["$tmp"] = "rw"`
// unconditionally — every confined script gets a writable private temp with no catalog entry, so a
// write there can never require a grant. A write to a temp-LOOKING path that is NOT the declared
// root still bills, because the jail hides the shared temp and that write is genuinely refused.
const TEMP_ROOT = 'C:\\jailv\\m-x\\tmp';

test('a write into the DECLARED private temp is not billed', () => {
  const roots = { ...fullRoots(), temp: TEMP_ROOT };
  const r = classify(stream(`${TEMP_ROOT}\\phase1\\download.tgz`, 'C:\\obs'), roots);
  assert.deepEqual(r.report.grant, {},
    'a write the jail grants unconditionally must not widen the grant');
  assert.equal(r.report.writes.jailTmp, 1, 'the write must still be COUNTED and reported, not lost');
  // All THREE base-covered buckets are named whether or not this stream reached them: the field
  // tells a reader which writes were FREE, and a list that shrank to what one run happened to touch
  // would make an empty grant unreadable. `jailHome` is the private home the jail also grants
  // unconditionally (its writePaths half is pinned in `write-paths.test.mjs`); `npmCache` is the
  // per-run npm cache this driver redirects, which the jail resolves into that same private home.
  assert.deepEqual(r.report.baseCovered, ['jailTmp', 'jailHome', 'npmCache']);
});

test('⭑ POSITIVE CONTROL: the USER\'S OWN %TEMP%, once it is no longer the declared root, STILL BILLS', () => {
  // ⛔ THIS IS THE SHARP FORM OF THE UNDER-GRANT HAZARD, and it is the one the redirect creates.
  // After the driver points `TMP`/`TEMP` at its own directory, the user's real
  // `%USERPROFILE%\AppData\Local\Temp` is just another path under the home — and a script that
  // HARDCODES it, rather than reading the variable, is writing somewhere the jail does not grant.
  // That write is a real capability need and must still produce `write.userHome`.
  //
  // A "looks like temp" heuristic would drop it and under-grant exactly those packages. Keying on
  // the exact declared root is what keeps this billing. If this assertion ever goes green by the
  // grant becoming `{}`, the rule has silently become a heuristic.
  const home = 'C:\\Users\\nub';
  const r = classify(stream(`${home}\\AppData\\Local\\Temp\\hardcoded.bin`, 'C:\\obs'),
    { ...fullRoots('C:\\obs', home), temp: TEMP_ROOT });
  assert.deepEqual(r.report.grant, { write: { userHome: true } },
    'a hardcoded write to the real %TEMP% stopped billing — this is an under-grant');
  assert.equal(r.report.writes.jailTmp, undefined, 'a hardcoded temp path was absorbed into jailTmp');
});

test('a hardcoded SYSTEM temp is not absorbed into jailTmp — it stays visible for inspection', () => {
  // ⛔ THE HONEST FORM FOR A PATH NO SCOPE BILLS. `C:\Windows\Temp` is world-writable on Windows, so
  // a script really can write there and the jail really does refuse it — but no catalog scope covers
  // it, so rule 3 REPORTS it rather than rounding it up to `write:"disk"`. The hazard here is
  // therefore not "stops billing" (it never billed) but "stops being SEEN": absorbed into `jailTmp`
  // it would vanish from the systemfs warning and nobody would ever inspect it.
  const r = classify(stream('C:\\Windows\\Temp\\hardcoded.bin', 'C:\\obs'),
    { ...fullRoots(), temp: TEMP_ROOT });
  assert.equal(r.report.writes.jailTmp, undefined, 'a system temp path was absorbed into jailTmp');
  assert.equal(r.report.writes.systemfs, 1, 'the write must stay visible in the systemfs bucket');
  assert.deepEqual(r.report.systemWrites, ['c:\\windows\\temp\\hardcoded.bin']);
});

test('the declared temp nested INSIDE the home still wins, by longest prefix', () => {
  // ⛔ THE WINDOWS-SHAPED CASE, AND THE REASON THIS MATTERS AT ALL. `%TEMP%` is
  // `%USERPROFILE%\AppData\Local\Temp`, so before the redirect every temp write billed
  // `write.userHome`. Even with the redirect, a declared temp under the home must beat `userHome`
  // — first-match-wins on an unsorted list would bill it as home and undo the whole change.
  const home = 'C:\\Users\\nub';
  const nested = `${home}\\AppData\\Local\\Temp`;
  const r = classify(stream(`${nested}\\x.bin`, 'C:\\obs'), { ...fullRoots('C:\\obs', home), temp: nested });
  assert.deepEqual(r.report.grant, {}, 'a temp nested inside the home was billed as userHome');
  assert.equal(r.report.writes.jailTmp, 1);
});

test('a null temp root leaves the bucket out entirely rather than matching everything', () => {
  // A capture that declares no temp must not acquire a `jailTmp` root spelled "null", which would
  // match nothing — or, worse, everything, if the null ever reached a prefix test as a bare string.
  const r = classify(stream('C:\\obs\\out.txt', 'C:\\obs'), { ...fullRoots(), temp: null });
  assert.deepEqual(r.report.grant, { write: { project: true } });
  assert.ok(!r.report.keyedOn.includes('jailTmp'), 'a null temp must not become a keyed root');
});

test('a relative path is never anchored to a working directory', () => {
  // ⛔ THE macOS DEFECT, CHECKED FOR HERE. That decoder resolved a relative path against an
  // inherited cwd and marked the result observed, billing a fabricated path — an under-grant on
  // `cd build && node gen.js`, one of the commonest install-script idioms. This classifier declares
  // `cwd: null` and must have no way to use one: a path with no drive letter matches no root and
  // falls to `outside`, which rule 3 REPORTS rather than rounding up.
  const r = classify(stream('build\\Release\\thing.node', 'C:\\obs'), fullRoots());
  assert.deepEqual(r.report.grant, {}, 'a relative path was resolved against something');
  assert.equal(r.report.writes.outside, 1);
  // Reported case-folded, because rule 1 normalizes every path on Windows before anything looks at
  // it — but with NO drive letter and no leading root, which is what says it was never anchored.
  assert.deepEqual(r.report.outsideWrites, ['build\\release\\thing.node']);
  assert.doesNotMatch(r.report.outsideWrites[0], /^[a-z]:\\/,
    'a relative path acquired a drive letter, so something resolved it against a base');
});

// ── The declared per-run npm cache (`npmCache`) ─────────────────────────────────────────────────
//
// ⛔ THE DEFECT THESE GUARD IS A REDIRECT WITHOUT A DECLARATION, which is the one shape this
// classifier cannot recover from. `measure-windows.mjs` sets `npm_config_cache` at
// `<run-root>\npm-cache` so the OBSERVE arm gets the cold cache a real user has — and for a long
// time declared no root for it. That directory is a SIBLING of `observe`, `tmp` and `jailhome`, so
// every write npm made under it fell through to `outside`: the classifier billing its own
// apparatus as a write it could not account for. MEASURED on the committed corpus before the fix:
// of the 805 `outside` write paths the 135 win32 records with an `outside` row print, 728 were
// under this directory, and in the `write:"disk"` population 2,896 of 2,906 `outside` writes came
// from records whose entire printed list was npm-cache. The bucket that exists to surface a
// genuinely surprising write was ~90% noise, so a real one could not be seen in it.
const RUN_ROOT = 'D:\\jail\\m-thing-abc';
const NPM_CACHE = `${RUN_ROOT}\\npm-cache`;
const cacheRoots = (over = {}) => ({ ...fullRoots(), npmCache: NPM_CACHE, ...over });

test('⭑ the DECLARED per-run npm cache is its own bucket, and it bills nothing', () => {
  // RED ON REVERT: drop the `npmCache` entry from the `ROOTS` list in `classify.mjs` — the state
  // this file was in — and `writes.npmCache` is `undefined` while `writes.outside` is 1, because
  // the redirect target matches no other root. The grant is `{}` either way, which is exactly why
  // this went unnoticed: `outside` never reaches the grant, so the damage is entirely to the
  // REPORT, and the report is the only place a human audits what a package touched.
  const r = classify(stream(`${NPM_CACHE}\\_cacache\\index-v5\\8a\\a3\\1235b`, 'C:\\obs'), cacheRoots());
  assert.equal(r.report.writes.npmCache, 1, `the declared npm cache was not recognised:\n${r.stdout}`);
  assert.equal(r.report.writes.outside, undefined,
    'an npm-cache write was still billed as an unaccounted write');
  assert.deepEqual(r.report.outsideWrites, []);
  assert.ok(r.report.keyedOn.includes('npmCache'), 'a declared npmCache must become a keyed root');
});

test('⭑ npm-cache writes are BASE-COVERED, and the report says so in words', () => {
  // The other half of the claim, and it is a claim about NUB rather than about the harness: nub
  // sets no `npm_config_cache` at all, and `preset.rs` repoints `APPDATA` at the `AppData\Roaming`
  // leaf of the READ-WRITE private jail home precisely so npm's cache lands in granted space (its
  // own comment names `%APPDATA%\npm-cache` and the `EPERM` it used to cause). So the corresponding
  // write costs no catalog scope in the real jail.
  //
  // RED ON REVERT, and the two assertions below are guarded by DIFFERENT reverts, which is why both
  // are here. Removing `'npmCache'` from `BASE_COVERED` reddens the first: the report then carries a
  // bucket with no statement of whether the jail covers it, the ambiguity that field exists to
  // remove. It does NOT redden the second — the NOTE print is gated on the bucket being non-empty,
  // not on the list — so the stdout assertion is guarded instead by dropping `npmCache` from the
  // `ROOTS` list, where the write reverts to `outside` and the NOTE is never reached. Verified both
  // ways rather than assumed; the first draft of this comment claimed one revert reddened both.
  const r = classify(stream(`${NPM_CACHE}\\_logs\\2026-08-08t04_28_27_703z-debug-0.log`, 'C:\\obs'),
    cacheRoots());
  assert.ok(r.report.baseCovered.includes('npmCache'),
    `baseCovered does not name npmCache: ${JSON.stringify(r.report.baseCovered)}`);
  assert.match(r.stdout, /NOTE 1 writes into the DECLARED per-run npm cache/,
    `the report does not say the jail already covers this:\n${r.stdout}`);
  assert.deepEqual(r.report.grant, {}, 'a base-covered write must earn no scope');
});

test('⭑ only the EXACT declared cache is free — the real user\'s npm cache still bills', () => {
  // ⛔ THE SECURITY CONTROL, and without it the two cases above are satisfied by a classifier that
  // frees anything cache-shaped. nub redirects `APPDATA` AWAY from the user's profile, so a script
  // that spells `%USERPROFILE%\AppData\Roaming\npm-cache` out absolutely is writing somewhere the
  // jail does NOT grant: that write is genuinely refused and genuinely needs `userHome`. Keying on
  // "looks like an npm cache" instead of on the declared path would silently under-grant it.
  const home = 'C:\\Users\\nub';
  const real = classify(stream(`${home}\\AppData\\Roaming\\npm-cache\\_cacache\\x`, 'C:\\obs'),
    cacheRoots({ ...fullRoots('C:\\obs', home), npmCache: NPM_CACHE }));
  assert.deepEqual(real.report.grant, { write: { userHome: true } },
    'the REAL user npm cache was absorbed into the free bucket');
  assert.equal(real.report.writes.npmCache, undefined);

  // RED ON REVERT: loosen `under()` to a bare `startsWith(root)` and this sibling is swallowed,
  // because its name merely STARTS WITH the declared root's. It is a different directory.
  const sibling = classify(stream(`${RUN_ROOT}\\npm-cache-old\\stray.bin`, 'C:\\obs'), cacheRoots());
  assert.equal(sibling.report.writes.npmCache, undefined,
    'a sibling sharing the cache root\'s NAME PREFIX was absorbed into it');
  assert.equal(sibling.report.writes.outside, 1);
});

test('a null npmCache leaves the bucket out entirely rather than matching the string "null"', () => {
  // The POSIX shape, which both `measure.sh` and `measure-macos.sh` have: no `npm_config_cache` is
  // set, npm resolves its cache to `$HOME/.npm`, and `HOME` is already redirected at the jail home
  // — so there is no separate root and the existing bucket carries those writes. A `null` must
  // yield no root at all; reaching `startsWith` it would become the literal text "null".
  const r = classify(stream('C:\\obs\\out.txt', 'C:\\obs'), { ...fullRoots(), npmCache: null });
  assert.deepEqual(r.report.grant, { write: { project: true } });
  assert.ok(!r.report.keyedOn.includes('npmCache'), 'a null npmCache must not become a keyed root');
});
