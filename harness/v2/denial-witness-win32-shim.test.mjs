// The win32 axis's nub-own-plumbing subtraction.
// `node --test harness/v2/denial-witness-win32-shim.test.mjs`.
//
// ⛔⛔ THIS FILE GUARDS A TWO-SIDED PROPERTY AND EITHER SIDE ALONE IS WORTHLESS. The subtraction
// added to `win32PathAxis` must remove nub's OWN shim-teardown refusals (which produced a measured
// false WITNESSED) and must remove NOTHING ELSE (because a false CLEAN publishes an under-grant,
// the one direction this project forbids). A test that only checked the first half would be
// satisfied by deleting the axis; a test that only checked the second by deleting the fix. So every
// case below pairs a subtraction with a survivor in the SAME stream.
//
// ⛔ THE DIRECTIONALITY, because it is the reason the defect went unnoticed for so long. WITNESSED
// KEEPS the wide grant and only CLEAN licenses a narrowing, so a false WITNESSED fails in the
// direction that looks safe: it silently pins packages to an over-broad grant forever and nothing
// downstream complains. Measured through `record.mjs` on the real `electron-chromedriver@44.1.1`
// driver log: WITNESSED publishes `grantSource: "synthesized"` with the whole-home grant, while the
// identical log with the verdict CLEAN publishes `grantSource: "descended"` and `{"network":true}`.
//
//   MUTATION                                                             CAUGHT BY
//   drop the subtraction entirely                                        shim-only stream
//   subtract by `witnessRoots({ temp })` instead                         package under ambient temp
//   drop 0xc0000121 from REFUSAL_STATUS instead                          package CANNOT_DELETE
//   loosen the name to a `nub-node-shim-*` glob                          lookalike directory
//   collapse all four spellings into one ownership test                  rename out of the shim
//   test only `f`, never the `fx` expansion                              8.3 short spelling
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { witness } from './denial-witness.mjs';

const CAP = 'no-write-userHome';

// ⛔ THE DRIVER'S OWN ROOTS BLOCK, NOT AN INVENTED ONE — `witnessRoots()` in `win32-witness.mjs`,
// as the real `electron-chromedriver` run declared it. `temp` is `null` there DELIBERATELY (the
// ambient `%TEMP%` sits inside the home, so declaring it would carve a hole in the scope and silence
// every package that stages through temp), and these cases depend on it staying that way.
const ROOTS = {
  project: 'C:\\jail\\ecd\\m-electronchromedriver-mtjc59gn\\verify-nar-no-write-userHome',
  home: 'C:\\Users\\nub',
  jailHome: null, globalStore: null, projectStore: null, interpreter: null,
  toolsDir: null, temp: null, npmPrefix: null, npmCache: null,
  ownPkg: 'C:\\jail\\ecd\\m-electronchromedriver-mtjc59gn\\verify-nar-no-write-userHome'
    + '\\node_modules\\electron-chromedriver',
  cwd: null,
};
const header = () => ({ k: 'h', v: 1, platform: 'win32-x64', jailed: true, winRefusals: true, roots: ROOTS });
const proc = (pid = 2416) => ({ k: 'p', pid, ppid: 4276, ts: null, life: 1, data: {} });

// ⛔ THE POSITIVE CONTROL THE AXIS DEMANDS, AND IT MUST NOT BE IN SCOPE. `win32PathAxis` refuses any
// stream carrying no Create refused with STATUS_ACCESS_DENIED, so without this row every case below
// would score VOID and pass for the wrong reason. Lifted verbatim from the premise capture
// (`etw1/events.ndjson`), where `C:\` is outside the home and so contributes no refusal of its own.
const CONTROL = { k: 'e', p: 2340, o: 'open-r', s: 'Create', f: 'C:\\', st: '0xc0000022', d: 1, n: 1 };

// ⛔ VERBATIM FROM THE FALSE POSITIVE. These four are the ENTIRE in-scope refusal set that scored
// `electron-chromedriver@44.1.1` WITNESSED on a real Windows box — nub deleting its own just-exited
// PATH-shim binary under the un-redirected `%LOCALAPPDATA%\Temp`, with the package denied nothing.
const SHIM_A = 'C:\\Users\\nub\\AppData\\Local\\Temp\\nub-node-shim-2416-2bac1298058628f06fd87fdafbc23749\\node.exe';
const SHIM_B = 'C:\\Users\\nub\\AppData\\Local\\Temp\\nub-node-shim-6004-0aaecf5d6e8944eb29c0e23cd5bbc2b5\\node.exe';
const shimNoise = () => [
  { k: 'e', p: 2416, o: 'unlink', s: 'DeletePath', f: SHIM_A, st: '0xc0000121', n: 1 },
  { k: 'e', p: 2416, o: 'unlink', s: 'SetDelete', f: SHIM_A, st: '0xc0000121', n: 1 },
  { k: 'e', p: 2416, o: 'unlink', s: 'DeletePath', f: SHIM_B, st: '0xc0000121', n: 1 },
  { k: 'e', p: 2416, o: 'unlink', s: 'SetDelete', f: SHIM_B, st: '0xc0000121', n: 1 },
];

// ⛔ VERBATIM FROM THE PREMISE CAPTURE (`etw1/events.ndjson`), where the confined child's write into
// the ungranted home was refused by the AppContainer DACL. This is the row whose survival the whole
// axis exists for, and every case below that subtracts something must still find it.
const GENUINE = {
  k: 'e', p: 2340, o: 'open-w', s: 'Create',
  f: 'C:\\Users\\nub\\wp-ungranted\\u-e1-confined.txt', st: '0xc0000022', d: 5, n: 1,
};

// Filler so a stream clears MIN_EVENTS with nothing in scope and nothing refused — same construction
// and same reason as `denial-witness-win32.test.mjs`. Without it every case scores VOID, which would
// satisfy any assertion phrased as "not WITNESSED" while testing nothing at all.
const filler = (n) => Array.from({ length: n }, (_, i) => ({
  k: 'e', p: 2416, o: 'open-r', s: 'Create', st: '0x00000000', n: 1,
  f: `C:\\jail\\ecd\\m-electronchromedriver-mtjc59gn\\tmp\\f${i}`,
}));

const score = (rows) => witness(
  [header(), proc(), proc(2340), ...filler(250), CONTROL, ...rows], { cap: CAP });

test('⛔ nub\'s own shim teardown alone is NOT a witness', () => {
  // RED WITHOUT THE FIX: this is the measured `electron-chromedriver@44.1.1` stream, which scored
  // WITNESSED off exactly these four rows and kept a whole-home grant the descent had shown was
  // droppable. Nothing here is the package being refused anything.
  const w = score(shimNoise());
  assert.equal(w.refusalsInScope, 0,
    `nub's own shim-teardown refusals were counted as the package's: ${JSON.stringify(w.sample)}`);
  assert.equal(w.verdict, 'CLEAN',
    'a stream whose only in-scope refusals are nub tidying up its own shim must license the narrowing');
});

test('⛔ a genuine package refusal in the SAME stream still witnesses', () => {
  // ⛔ THE HALF THAT STOPS THE FIX FROM BECOMING A FALSE CLEAN. If the subtraction ever widened to
  // "any refusal near the shim", or to the whole ambient temp, this goes green with the wrong
  // verdict and an under-grant ships. The shim noise and the real denial are deliberately in ONE
  // stream, because that is the shape the real driver produces.
  const w = score([...shimNoise(), GENUINE]);
  assert.equal(w.verdict, 'WITNESSED',
    'a real DACL refusal on the ungranted home must survive the nub-plumbing subtraction');
  assert.equal(w.refusalsInScope, 1, `only the genuine refusal counts, got ${JSON.stringify(w.sample)}`);
  assert.match(w.sample.join(' '), /wp-ungranted/, 'the surviving sample must be the package\'s own reach');
});

test('a package staging under the ambient %TEMP% is still witnessed', () => {
  // ⛔ THE FIX THAT WAS REJECTED, ASSERTED AS A PROPERTY. Declaring `witnessRoots({ temp })` would
  // also have silenced the false positive — by carving the whole ambient temp out of the scope, which
  // silences every real package that stages through it. `win32-witness.test.mjs` names the same
  // property from the roots side; this names it from the scorer side, so neither fix can be swapped
  // in without a red test.
  const w = score([{ k: 'e', p: 2416, o: 'open-w', s: 'Create', st: '0xc0000022',
    f: 'C:\\Users\\nub\\AppData\\Local\\Temp\\phantomjs\\bin\\phantomjs.exe' }]);
  assert.equal(w.verdict, 'WITNESSED', 'the ambient %TEMP% lives inside the home and is in scope');
});

test('STATUS_CANNOT_DELETE on a path the PACKAGE owns is still a refusal', () => {
  // ⛔ THE OTHER REJECTED FIX. Dropping `0xc0000121` from `REFUSAL_STATUS` would have cleared the
  // false positive too, by making the witness quieter for every stream at once — and a package
  // refused a delete inside the home is a package that needed the home.
  const w = score([{ k: 'e', p: 2416, o: 'unlink', s: 'DeletePath', st: '0xc0000121',
    f: 'C:\\Users\\nub\\.electron\\chromedriver-v44.1.1-win32-x64.zip' }]);
  assert.equal(w.verdict, 'WITNESSED',
    'the discriminant is whose path it was, not which status it carried');
});

test('a lookalike directory a package created is NOT subtracted', () => {
  // ⛔ THE NAME IS MATCHED STRICTLY BECAUSE THE SUBTRACTION'S WHOLE LICENCE IS THAT NUB CREATED THE
  // PATH. `parse_shim_dir_name` (crates/nub-core/src/node/spawn.rs) accepts the prefix plus a pid
  // with no leading zero and an optional 32-char lower-case hex nonce, and nothing else. A loose
  // `nub-node-shim-*` glob would let a package hide its own refusals under a lookalike name.
  for (const seg of [
    'nub-node-shim-evil',                                    // no pid
    'nub-node-shim-0123',                                    // leading zero
    'nub-node-shim-2416-deadbeef',                           // nonce too short
    'nub-node-shim-2416-2bac1298058628f06fd87fdafbc23749-x', // trailing junk
    'nub-node-shim',                                         // bare prefix, no tail
  ]) {
    const w = score([{ k: 'e', p: 2416, o: 'open-w', s: 'Create', st: '0xc0000022',
      f: `C:\\Users\\nub\\AppData\\Local\\Temp\\${seg}\\payload.exe` }]);
    assert.equal(w.verdict, 'WITNESSED', `a lookalike directory "${seg}" was treated as nub's own`);
  }
});

test('the shim name is matched case-INSENSITIVELY, because NTFS is', () => {
  // ⛔ AN UPPER-CASE NONCE IS NOT A LOOKALIKE, IT IS THE SAME DIRECTORY. `parse_shim_dir_name` is
  // Rust reading a name nub itself wrote, so it can demand lower-case hex; this predicate reads
  // whatever spelling the KERNEL reported for that same directory, and NTFS is case-insensitive, so
  // the two are one path. Matching case-sensitively here would miss nub's own teardown whenever the
  // caller used another spelling and re-open the false WITNESSED. Same reasoning, and the same
  // direction, as this file's `winKey` case fold.
  const w = score([{ k: 'e', p: 2416, o: 'unlink', s: 'DeletePath', st: '0xc0000121',
    f: 'C:\\Users\\nub\\AppData\\Local\\Temp\\NUB-NODE-SHIM-2416-2BAC1298058628F06FD87FDAFBC23749\\node.exe' }]);
  assert.equal(w.verdict, 'CLEAN', 'a differently-cased spelling of nub\'s own shim dir must subtract');
});

test('a rename OUT of the shim dir INTO the home is still a witness', () => {
  // ⛔ WHY OWNERSHIP IS ASKED PER END RATHER THAN OVER ALL FOUR SPELLINGS AT ONCE. The source here is
  // nub's own shim path, so a fix that subtracted the event whenever ANY spelling looked like nub's
  // would drop it — and the destination is a write into the ungranted home, which is precisely what
  // the axis must catch.
  const w = score([{ k: 'e', p: 2416, o: 'rename', s: 'Rename', st: '0xc0000022',
    f: SHIM_A, g: 'C:\\Users\\nub\\.config\\stolen.exe' }]);
  assert.equal(w.verdict, 'WITNESSED', 'the rename destination is in the home and must count');
});

test('the 8.3 short spelling of the shim dir is subtracted through its expansion', () => {
  // The kernel reports whichever spelling the caller used, so nub's own teardown can arrive as
  // `NUB-NO~1`. `fx` carries the expansion, and consulting both spellings within the source end is
  // what keeps the short form from reading as a stranger's path and re-opening the false positive.
  const w = score([{ k: 'e', p: 2416, o: 'unlink', s: 'DeletePath', st: '0xc0000121',
    f: 'C:\\Users\\nub\\AppData\\Local\\Temp\\NUB-NO~1\\node.exe', fx: SHIM_A }]);
  assert.equal(w.refusalsInScope, 0, 'the short-spelled shim path was counted as the package\'s');
  // ⛔ THE VERDICT TOO, NOT ONLY THE COUNT. `refusalsInScope` is 0 in a VOID stream as well, so the
  // count alone is satisfied by a stream nobody scored — which is how this case first passed while
  // the six around it were failing for a structural reason that applied to it equally.
  assert.equal(w.verdict, 'CLEAN', 'the stream must have been SCORED, not voided');
});
