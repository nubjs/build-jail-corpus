// The win32 denial-witness CAPTURE half. `node harness/run-tests.mjs` (from the repo root).
//
// ⛔⛔ THIS FILE'S JOB IS TO PROVE ONE NEGATIVE ON A HOST THAT CANNOT RUN THE THING UNDER TEST: that
// no capture-side fault can reach `denial-witness.mjs` and come back CLEAN. A CLEAN licenses
// `record.mjs` to drop `write.userHome` — authority over the entire user home — off a green drop arm,
// and an under-grant breaks real installs, which is the one direction this project forbids. The
// scorer already refuses a stream it cannot read; what it structurally CANNOT see is everything about
// the CAPTURE. A session that lost 60% of its events, a `.etl` cut off at its size cap, a traced token
// that kept SeBackupPrivilege and therefore bypassed the DACL the jail refuses through — every one of
// those decodes into a stream that looks entirely healthy and contains no refusals, because there
// were none to record. So the gate lives here and every clause of it is a case below.
//
// ⛔ WRITTEN AS A MUTATION TABLE, NOT A HAPPY PATH. For each way the capture half could be wrong there
// is a case that goes RED under that mutation, and each names the mutation in as many words — a test
// whose failure mode is not written down gets "fixed" by loosening the assertion.
//
//   MUTATION                                                        CAUGHT BY
//   accept a capture with no meta.json / a foreign schema           no meta, foreign schema
//   drop the elevation check                                        unelevated capture
//   drop the privilege-drop check                                   ⛔ THE DACL BYPASS
//   accept eventsLost > 0 (or the -1 "could not parse")             lossy session, unparsed loss
//   drop the .etl truncation cap check                              ⛔ THE SILENT TRUNCATION
//   accept a non-zero tracerptExit                                  failed conversion
//   accept 8.3 expansion OFF                                        ⛔ THE SHORT SPELLING
//   accept a missing/zero rootPid                                   unattributable capture
//   compose the arm rc as `a` alone, or default a missing rc to 0   rc composition, unreadable rc
//   `echo %ERRORLEVEL%> f` with no space before the redirect        ⛔ THE HANDLE-DIGIT FOOTGUN
//   emit the batch for a path carrying `"` or `%`                   cmd reparse refusal
//   copy OBSERVE's roots onto the drop arm                          the roots subtract nothing
//
// ⛔ AND A POSITIVE CONTROL RUNS IN THE OTHER DIRECTION. A capture that is genuinely fit must be
// ACCEPTED, or the whole table above is satisfied by a gate that refuses everything and is useless
// rather than merely safe.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  WITNESS_CAP, WITNESS_MAX_MB, CAPTURE_SCHEMA,
  jailScript, armRc, witnessRoots, captureIsScoreable, headerIsScoreable, voidWitness,
} from './win32-witness.mjs';
import { axisFor, witness } from './denial-witness.mjs';
import { shortNameMode } from './adapters/windows-shortnames.mjs';

const HERE = import.meta.dirname;

// ⛔ A CAPTURE THAT PASSES EVERY CLAUSE, SO EACH CASE BELOW BREAKS EXACTLY ONE THING. Its values are
// the ones `windows.ps1` actually writes: the schema literal it stamps, `removed` per privilege from
// its `Drop()` helper, `eventsLost` parsed out of tracerpt's summary, `tracerptExit` from
// `$LASTEXITCODE`. A fixture with invented field shapes would test this gate against a capture no
// script produces.
const GOOD = {
  meta: {
    schema: CAPTURE_SCHEMA,
    elevated: true,
    privDropped: { SeBackupPrivilege: 'removed', SeRestorePrivilege: 'removed', SeTakeOwnershipPrivilege: 'already-absent' },
    tracerptExit: 0,
    eventsLost: 0,
    eventsTotal: 412_338,
    rootPid: 5116,
  },
  etlBytes: 214_000_000,
  xmlBytes: 1_900_000_000,
  shortNameMode: 'resolve',
};
const withMeta = (over) => ({ ...GOOD, meta: { ...GOOD.meta, ...over } });

// ── INSTRUMENT ────────────────────────────────────────────────────────────────────────────────────

test('INSTRUMENT: the known-good capture is ACCEPTED, so a refusal below means something', () => {
  // ⛔ WITHOUT THIS EVERY CASE BELOW PASSES VACUOUSLY. A gate that answers "not scoreable" to
  // everything satisfies the entire mutation table and licenses nothing — and is also worthless,
  // because it makes the witness permanently inert while looking rigorous.
  const r = captureIsScoreable(GOOD);
  assert.equal(r.ok, true, `the known-good capture was refused: ${r.reason}`);
  assert.equal(r.reason, null);
});

test('INSTRUMENT: every refusal names a reason a human can act on', () => {
  // A refusal reaches `driver.out` as the whole explanation of why a whole-home grant was kept. An
  // empty or one-word reason is the shape that gets read as a broken lane and ignored.
  for (const bad of [
    { ...GOOD, meta: null },
    withMeta({ elevated: false }),
    withMeta({ eventsLost: 7 }),
    { ...GOOD, shortNameMode: 'off' },
  ]) {
    const r = captureIsScoreable(bad);
    assert.equal(r.ok, false);
    assert.ok(typeof r.reason === 'string' && r.reason.length > 40, `thin refusal reason: ${r.reason}`);
  }
});

// ── THE CAPTURE GATE ──────────────────────────────────────────────────────────────────────────────

test('no meta.json, and a meta.json from something other than windows.ps1, are both refused', () => {
  // MUTATION: skip the schema check. A capture directory left by another tool has unknown field
  // meanings, so reading `eventsLost` off it yields `undefined` — which is not 0, but a gate written
  // as `if (meta.eventsLost > 0)` would have treated it as "no loss".
  //
  // ⛔ THE SCHEMA CASES CARRY AN OTHERWISE-PERFECT meta, WHICH IS THE WHOLE POINT AND WAS THE BUG IN
  // THIS TEST'S FIRST DRAFT. It built each case as `{ meta: { schema: X } }` — a meta with nothing
  // else in it — so every case was refused by the ELEVATION clause further down and the mutation
  // "delete the schema check entirely" stayed GREEN. Measured: 30 mutations run, and this was one of
  // two that the table did not catch. Isolating a term means varying that term ALONE.
  for (const m of [null, {}, 'nub-obs-win/2', 'nub-obs-win/1 ', 'NUB-OBS-WIN/1', 1]) {
    assert.equal(captureIsScoreable(withMeta({ schema: m })).ok, false,
      `a capture with schema ${JSON.stringify(m)} was accepted`);
  }
  assert.equal(captureIsScoreable({ ...GOOD, meta: null }).ok, false, 'no meta.json at all');
  assert.equal(captureIsScoreable({ ...GOOD, meta: 'nub-obs-win/1' }).ok, false, 'a meta that is not an object');
  // The control in the other direction: the schema windows.ps1 really stamps must be ACCEPTED, or
  // this clause refuses every capture and the witness is inert rather than safe.
  assert.equal(captureIsScoreable(withMeta({ schema: CAPTURE_SCHEMA })).ok, true);
});

test('an UNELEVATED capture is refused — ETW kernel providers are administrator-only', () => {
  // MUTATION: drop the elevation clause. An unelevated `logman` session records nothing, and nothing
  // is silence, and silence read as "no refusal happened" is the catastrophe this file exists for.
  for (const v of [false, null, undefined, 'true', 1]) {
    assert.equal(captureIsScoreable(withMeta({ elevated: v })).ok, false,
      `elevated=${JSON.stringify(v)} was accepted`);
  }
});

test('⛔ THE DACL BYPASS: a capture whose privilege drop failed is refused', () => {
  // MUTATION: drop the privDropped clause. This is the sharpest case in the file and the one that
  // looks most like paranoia. libuv sets FILE_FLAG_BACKUP_SEMANTICS on every open; combined with a
  // retained SeBackupPrivilege that BYPASSES THE DACL OUTRIGHT — measured on nub-win3, where a write
  // into a directory carrying an explicit Deny ACE succeeded with the privilege and was refused
  // without it, nothing else changed. Under an AppContainer jail the refusal IS a DACL check, so a
  // traced token holding SeBackup makes every home write SUCCEED: a green arm, a trace with no
  // refusals in it, and a CLEAN verdict produced by an instrument structurally unable to see a denial.
  assert.equal(captureIsScoreable(withMeta({ privDropped: null })).ok, false);
  assert.equal(captureIsScoreable(withMeta({ privDropped: {} })).ok, true,
    'an empty drop record is the shape windows.ps1 writes when it was asked for nothing; it is the '
    + 'VALUES that are checked, and inventing a failure for an empty object would refuse a valid capture');
  const r = captureIsScoreable(withMeta({
    privDropped: { SeBackupPrivilege: 'AdjustTokenPrivileges:1300', SeRestorePrivilege: 'removed' },
  }));
  assert.equal(r.ok, false);
  assert.match(r.reason, /SeBackupPrivilege/, 'the refusal must name WHICH privilege survived');
  assert.match(r.reason, /DACL/, 'the refusal must say why a surviving privilege blinds the witness');
});

test('a LOSSY session is refused, and so is one whose loss could not be parsed', () => {
  // MUTATION: accept eventsLost > 0. A trace that dropped events cannot support "nothing inside the
  // scope was refused", which is the ONLY claim a CLEAN verdict makes. The scorer has no equivalent
  // check — its `MIN_EVENTS` floor is satisfied by a trace that lost most of its events.
  //
  // ⛔ AND `-1` IS THE ONE THAT A `> 0` TEST WOULD LET THROUGH. windows.ps1 initialises `$lost = -1`
  // and only overwrites it when it finds tracerpt's `Total Events Lost` line, so -1 means "the summary
  // could not be read" — strictly less knowledge than a positive count, and it must not read as zero.
  for (const v of [1, 62, -1, null, undefined, '0']) {
    assert.equal(captureIsScoreable(withMeta({ eventsLost: v })).ok, false,
      `eventsLost=${JSON.stringify(v)} was accepted`);
  }
  assert.equal(captureIsScoreable(withMeta({ eventsLost: 0 })).ok, true);
});

test('⛔ THE SILENT TRUNCATION: a .etl sitting at its size cap is refused', () => {
  // MUTATION: drop the truncation clause. The session runs in SEQUENTIAL mode, so reaching `-max`
  // stops the writing with NO error and with eventsLost still 0 — nothing was lost, it was never
  // recorded. A trace cut off part way through an arm is missing exactly the late writes a postinstall
  // makes, and the resulting stream is a healthy-looking one with no refusals in it.
  const cap = WITNESS_MAX_MB * 1024 * 1024;
  assert.equal(captureIsScoreable({ ...GOOD, etlBytes: cap - 1 }).ok, true);
  assert.equal(captureIsScoreable({ ...GOOD, etlBytes: cap }).ok, false, 'a trace exactly at the cap was accepted');
  assert.equal(captureIsScoreable({ ...GOOD, etlBytes: cap + 4096 }).ok, false);
  // `sizeOf` returns -1 when the stat fails, which is "no readable etl", not "a small one".
  for (const v of [-1, null, undefined, '0']) {
    assert.equal(captureIsScoreable({ ...GOOD, etlBytes: v }).ok, false, `etlBytes=${JSON.stringify(v)} was accepted`);
  }
});

test('the cap the gate compares against is the cap the session is given', () => {
  // ⛔ ONE LITERAL, TWO USES. The driver hands `WITNESS_MAX_MB` to windows.ps1 as `-MaxMB` and the
  // gate compares against the same constant. Two copies would let the gate pass a trace that filled a
  // smaller session, which is the silent-truncation case wearing the gate's own approval.
  const drv = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /'-MaxMB', String\(WITNESS_MAX_MB\)/,
    'the driver no longer sizes the witness session from WITNESS_MAX_MB, so the truncation gate is '
    + 'comparing against a cap the session does not use');
});

test('a failed tracerpt conversion is refused — the XML is what the decoder reads', () => {
  for (const v of [1, -1, null, undefined]) {
    assert.equal(captureIsScoreable(withMeta({ tracerptExit: v })).ok, false,
      `tracerptExit=${JSON.stringify(v)} was accepted`);
  }
});

test('an empty or absent trace.xml is refused, not decoded to zero events', () => {
  for (const v of [0, -1, null, undefined]) {
    assert.equal(captureIsScoreable({ ...GOOD, xmlBytes: v }).ok, false, `xmlBytes=${JSON.stringify(v)} was accepted`);
  }
});

test('a capture with no usable rootPid is refused — nothing could be attributed to the script', () => {
  // MUTATION: drop the rootPid clause. `windows-retain.mjs` attributes events by subtree of this pid,
  // so without it every process is out of subtree, the stream carries no `life:1` row, and "no refusal
  // was attributed to the lifecycle subtree" says nothing about what the script did.
  for (const v of [0, -1, null, undefined, '5116', 5116.5]) {
    assert.equal(captureIsScoreable(withMeta({ rootPid: v })).ok, false, `rootPid=${JSON.stringify(v)} was accepted`);
  }
});

test('⛔ THE SHORT SPELLING: 8.3 expansion OFF is refused', () => {
  // MUTATION: accept `shortNameMode: 'off'`. The kernel reports whichever spelling the caller used,
  // and a GitHub runner's `%TEMP%` is literally `C:\Users\RUNNER~1\AppData\Local\Temp` — a spelling
  // that does NOT prefix-match the long home root `C:\Users\runneradmin`. The scorer checks `f` and
  // its expansion `fx`; with expansion off there is no `fx`, so a short-spelled home refusal falls out
  // of scope and the stream reads CLEAN. That is a false CLEAN produced with no mapping error
  // anywhere and nothing in the output hinting the matcher missed a path.
  assert.equal(captureIsScoreable({ ...GOOD, shortNameMode: 'off' }).ok, false);
  for (const m of ['resolve', 'map']) {
    assert.equal(captureIsScoreable({ ...GOOD, shortNameMode: m }).ok, true, `mode ${m} was refused`);
  }
});

test('the driver asks for the 8.3 pass and reads the mode back from the same module', () => {
  // ⛔ THE FLAG AND THE CHECK MUST BE THE SAME FACT. A driver that passed `--resolve-shortnames` and
  // then assumed it worked would be back to guessing; one that computed the mode from
  // `process.platform` would answer for the HOST rather than for the decode. It asks
  // `shortNameMode` with the argument list it is about to hand the adapter.
  //
  // ⛔ AND THE RESULT MUST BE WHAT FEEDS THE GATE, NOT MERELY A CALL THAT HAPPENS SOMEWHERE. This
  // test's first draft asserted only that `shortNameMode({ dir: wit, args: retainArgs, … })` appeared
  // in the source, and the mutation "compute `sn` some other way and leave the call dead" stayed
  // GREEN — one of two holes a 30-mutation pass found in this file. A call whose value nothing reads
  // is exactly the half-wired shape the harness's own registry rules exist to catch.
  const drv = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /'--jailed', '--resolve-shortnames'/,
    'the retain invocation no longer asks for the 8.3 pass');
  assert.match(drv, /const sn = shortNameMode\(\{\s*\n?\s*dir: wit,\s*\n?\s*args: retainArgs,/,
    'the driver no longer computes the 8.3 mode from the same arguments it passes the adapter');
  assert.match(drv, /shortNameMode: sn\.mode,/,
    'the driver no longer feeds the computed 8.3 mode into the capture gate, so the mode it asked for '
    + 'is not the mode it checks');
});

test('OFF-WINDOWS CONTROL: the 8.3 pass cannot be resolved on this host, so the witness is VOID here', () => {
  // ⛔ THE CASE THAT PROVES THE OFF-WINDOWS PATH FAILS CLOSED RATHER THAN BEING UNTESTED. Running the
  // real `shortNameMode` with the real flag on a non-Windows host returns `off` — it refuses to invent
  // a map — and `captureIsScoreable` then refuses the capture. So even if every other gate were
  // somehow satisfied on a machine that cannot take an ETW trace, the verdict is VOID and not CLEAN.
  const args = ['/tmp/wit', '--jailed', '--resolve-shortnames'];
  const mode = shortNameMode({ dir: '/tmp/wit', args, val: () => null });
  if (process.platform === 'win32') {
    assert.equal(mode.mode, 'resolve', 'on Windows the pass must actually resolve, or fx is never populated');
    return;
  }
  assert.equal(mode.mode, 'off');
  assert.equal(captureIsScoreable({ ...GOOD, shortNameMode: mode.mode }).ok, false);
});

// ── THE ARM'S EXIT CODE ───────────────────────────────────────────────────────────────────────────

test('the traced rc is composed by the UNTRACED arm\'s rule, not by either half alone', () => {
  // MUTATION: return `a` alone, or `i` alone. The untraced arm computes
  // `i.status === 0 ? (a.status ?? 0) : i.status`, and a traced arm scored any other way is not
  // comparable with the arms the descent compares it against.
  assert.equal(armRc('0 \r\n', '0 \r\n').rc, 0);
  assert.equal(armRc('0 \r\n', '1 \r\n').rc, 1, 'an install that passed must yield approve-builds\' rc');
  assert.equal(armRc('1 \r\n', '0 \r\n').rc, 1, 'a FAILED install must not be masked by a passing approve-builds');
  assert.equal(armRc('3 \r\n', '9 \r\n').rc, 3);
  // Windows exit codes are signed: `-1073741819` is an access violation, and refusing to parse it
  // would turn a genuine crash into an unmeasured arm.
  assert.equal(armRc('0', '-1073741819').rc, -1073741819);
});

test('⛔ AN UNREADABLE rc IS null, NEVER ZERO — a missing capture must not read as a pass', () => {
  // MUTATION: default a missing rc to 0. The batch writes `%ERRORLEVEL%` after each command, so an
  // absent or garbled capture means the batch did not finish. Reading that as rc 0 reports a PASS for
  // an arm whose commands may never have run — and a PASSING drop arm is exactly what narrows a grant.
  for (const [i, a] of [[null, '0'], ['0', null], [undefined, undefined], ['', '0'], ['0', ''],
    ['%ERRORLEVEL%', '0'], ['0', 'ECHO is off.'], ['\r\n', '0'], [{}, '0']]) {
    const r = armRc(i, a);
    assert.equal(r.rc, null, `armRc(${JSON.stringify(i)}, ${JSON.stringify(a)}) returned ${r.rc}`);
    assert.ok(r.reason, 'an unreadable rc must say which half could not be read');
  }
  assert.match(armRc(null, '0').reason, /install/);
  assert.match(armRc('0', null).reason, /approve-builds/);
});

test('the driver turns an unreadable rc into a VOID arm and not into a verdict', () => {
  // ⛔ THE HALF THAT LIVES IN THE DRIVER. `armRc` can only return null; it is the driver that must
  // answer VOID rather than falling through to `rc === 0 && missing.length === 0`.
  const drv = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /if \(rc === null\) \{[\s\S]{0,400}?return \{ ok: false, void: true,/,
    'the driver no longer voids an arm whose traced rc could not be read, so a batch that never '
    + 'finished can reach the artifact gate');
});

// ── THE BATCH FILE ────────────────────────────────────────────────────────────────────────────────

const SCRIPT = () => jailScript({
  nub: 'C:\\nub-ci.exe',
  dir: 'C:\\jail\\m-x-abc\\verify-nar-no-write-userHome',
  iLog: 'C:\\jail\\m-x-abc\\verify-nar-no-write-userHome\\i.log',
  aLog: 'C:\\jail\\m-x-abc\\verify-nar-no-write-userHome\\a.log',
  iRc: 'C:\\jail\\m-x-abc\\wit-nar-no-write-userHome\\i.rc',
  aRc: 'C:\\jail\\m-x-abc\\wit-nar-no-write-userHome\\a.rc',
});

test('the traced arm runs the SAME two commands as the untraced one, in order', () => {
  // ⛔ THE BUG `measure-macos.sh` SHIPPED. Its traced branch ran `nub install` ALONE and took the
  // arm's rc from it, so a traced arm was a DIFFERENT EXPERIMENT from an untraced one for every
  // package whose build is deferred to `approve-builds` — which is why darwin was refused a witness
  // until that was repaired. `a.log` did not exist either, so the OVERRIDDEN/REJECTED assertions read
  // one log where the untraced arm reads two.
  const s = SCRIPT();
  const install = s.indexOf('" install >');
  const approve = s.indexOf('" approve-builds --all >');
  assert.ok(install > 0, 'the batch does not run `nub install`');
  assert.ok(approve > install, 'the batch does not run `nub approve-builds --all` after `install`');
  assert.match(s, /> "C:\\jail\\m-x-abc\\verify-nar-no-write-userHome\\i\.log" 2>&1/);
  assert.match(s, /> "C:\\jail\\m-x-abc\\verify-nar-no-write-userHome\\a\.log" 2>&1/);
});

test('⛔ THE HANDLE-DIGIT FOOTGUN: every rc capture has a space before its redirect', () => {
  // MUTATION: write `echo %ERRORLEVEL%> "f"`. cmd parses a digit written IMMEDIATELY before a
  // redirection operator as a FILE HANDLE, so an rc of 1 becomes `echo` with handle 1 redirected and
  // the file receives an empty line. That is an unreadable rc, which the driver correctly voids — so
  // the cost is not a wrong verdict but a witness that is silently inert on every arm that fails,
  // which is most of them. With the space, `1` is an argument and `armRc` trims the result.
  const s = SCRIPT();
  const captures = s.split('\r\n').filter((l) => l.includes('%ERRORLEVEL%'));
  assert.equal(captures.length, 2, 'expected exactly two rc captures, one per command');
  for (const l of captures) {
    assert.match(l, /^echo %ERRORLEVEL% > "/, `no space before the redirect: ${l}`);
    assert.doesNotMatch(l, /%ERRORLEVEL%>/, `handle-digit redirection in: ${l}`);
  }
});

test('⛔ the rc captures are NOT inside a parenthesised block, where %ERRORLEVEL% would freeze', () => {
  // MUTATION: wrap the batch body in `( … )`. cmd expands `%VAR%` when it PARSES a line, and it parses
  // a whole block at once — so both captures would freeze at the value before the first command ran
  // and the arm would report the rc of whatever preceded it. `setlocal enabledelayedexpansion` plus
  // `!ERRORLEVEL!` is the other repair and is deliberately not used: per-line expansion needs neither.
  const s = SCRIPT();
  assert.doesNotMatch(s, /^\s*\(/m, 'the batch opens a block, which freezes %ERRORLEVEL% expansion');
  assert.doesNotMatch(s, /enabledelayedexpansion/i);
  assert.doesNotMatch(s, /!ERRORLEVEL!/);
});

test('the batch cds into the arm directory with /d, so a cross-drive arm still runs there', () => {
  // The committed win32 corpus runs its arms from `D:\jail\…` while the harness lives on `C:`, so a
  // bare `cd` — which does not change drive — would leave the install running in the wrong tree.
  assert.match(SCRIPT(), /\r\ncd \/d "C:\\jail\\m-x-abc\\verify-nar-no-write-userHome"\r\n/);
});

test('the batch is CRLF and starts with @echo off', () => {
  const s = SCRIPT();
  assert.ok(s.startsWith('@echo off\r\n'));
  assert.equal(s.split('\n').length - 1, s.split('\r\n').length - 1, 'the batch contains a bare LF');
  assert.ok(s.endsWith('\r\n'), 'cmd can skip an unterminated final line');
});

test('a path cmd.exe would REPARSE refuses to produce a script at all', () => {
  // MUTATION: emit the script anyway. A `"` ends the quoted argument and a `%` is an environment
  // expansion — both legal in an NTFS path — so a script built from one runs a command nobody chose,
  // against a directory nobody named. Refusing is the only safe answer; the driver turns the throw
  // into a VOID arm.
  const base = {
    nub: 'C:\\nub-ci.exe', dir: 'C:\\jail\\a', iLog: 'C:\\jail\\a\\i.log',
    aLog: 'C:\\jail\\a\\a.log', iRc: 'C:\\jail\\w\\i.rc', aRc: 'C:\\jail\\w\\a.rc',
  };
  assert.doesNotThrow(() => jailScript(base), 'the ordinary case must still build');
  for (const k of Object.keys(base)) {
    for (const bad of ['C:\\jail\\a"b', 'C:\\jail\\%TEMP%', 'C:\\jail\\a\r\nshutdown', '', null]) {
      assert.throws(() => jailScript({ ...base, [k]: bad }),
        `jailScript accepted ${k}=${JSON.stringify(bad)}`);
    }
  }
});

// ── THE ROOTS THE WITNESS DECLARES ────────────────────────────────────────────────────────────────

const ARM = 'C:\\jail\\m-x-abc\\verify-nar-no-write-userHome';
const HOME = 'C:\\Users\\runneradmin';

test('⛔ the drop arm\'s roots SUBTRACT NOTHING from the home scope', () => {
  // ⛔⛔ THE WHOLE REASON THIS FUNCTION EXISTS RATHER THAN REUSING OBSERVE'S BLOCK. `scopeMatcher`
  // builds `userHome` as "under `roots.home`, minus every OTHER root the header declares", so a root
  // that sits INSIDE the home carves a hole in the scope and a refusal in that hole stops counting —
  // the CLEAN direction. OBSERVE's block declares a `globalStore` and a `toolsDir` under
  // `%LOCALAPPDATA%`, i.e. under the home, plus a `temp` and a `jailHome` that describe a different
  // run entirely. Copying it onto a drop arm would silence refusals under `AppData\Local`.
  const roots = witnessRoots({ project: ARM, home: HOME, pkg: 'victory-voronoi' });
  // ⛔ THROUGH `axisFor` WITH A WIN32 HEADER, WHICH IS THE REAL CALL PATH. Calling `scopeMatcher`
  // directly would use its DEFAULT POSIX comparator and namespace, against which a `C:\…` home is not
  // absolute at all — it returns null, and a test written that way would be asserting on a code path
  // no win32 stream ever takes.
  const ax = axisFor('no-write-userHome', { jailed: true, winRefusals: true, roots }, []);
  assert.ok(ax, 'the roots must express a userHome scope on the win32 axis at all');
  assert.equal(ax.scope, 'userHome');
  for (const p of [
    'C:\\Users\\runneradmin\\.pulumi\\bin\\pulumi.exe',
    'C:\\Users\\runneradmin\\AppData\\Local\\nub\\pm\\store\\x\\y',
    'C:\\Users\\runneradmin\\AppData\\Local\\Temp\\phantomjs\\bin',
    'C:\\Users\\runneradmin\\AppData\\Roaming\\npm-cache\\_cacache',
  ]) {
    // A refused Create on each of these must be a HIT. Under OBSERVE's roots the second and third are
    // carved out by `globalStore`/`toolsDir` and `temp`, so this is the assertion that would go red if
    // the witness ever copied that block.
    assert.equal(ax.hit({ st: '0xc0000022', s: 'Create', f: p }), true,
      `a refused access at ${p} is out of scope — a declared root carved it out of the home`);
  }
  assert.equal(roots.jailHome, null, 'a declared jailHome would subtract from the scope');
  assert.equal(roots.temp, null, 'the ambient %TEMP% lives inside the home; declaring it silences it');
  assert.equal(roots.globalStore, null);
  assert.equal(roots.toolsDir, null);
});

test('the roots still name project, home and ownPkg, because they are true of this arm', () => {
  const roots = witnessRoots({ project: ARM, home: HOME, pkg: '@scope/pkg' });
  assert.equal(roots.project, ARM);
  assert.equal(roots.home, HOME);
  assert.equal(roots.ownPkg, `${ARM}\\node_modules\\@scope\\pkg`, 'a scoped name must split into two components');
  assert.equal(witnessRoots({ project: ARM, home: HOME, pkg: '' }).ownPkg, null);
  for (const bad of [{ project: '', home: HOME }, { project: ARM, home: '' }, { project: ARM }]) {
    assert.throws(() => witnessRoots(bad), 'a witness with no project or no home root must refuse');
  }
});

test('every key `scopeMatcher` iterates is present, so an absent key cannot read as an answer', () => {
  // `capture.json`'s own rule: an ABSENT key and an INAPPLICABLE root read the same downstream, so
  // `null` is written wherever this platform genuinely has no such root and a key is never omitted.
  const roots = witnessRoots({ project: ARM, home: HOME, pkg: 'x' });
  for (const k of ['project', 'home', 'jailHome', 'globalStore', 'projectStore', 'interpreter',
    'toolsDir', 'temp', 'npmPrefix', 'npmCache', 'ownPkg', 'cwd']) {
    assert.ok(k in roots, `the witness roots omit ${k}`);
  }
});

// ── THE DECODED STREAM'S HEADER ───────────────────────────────────────────────────────────────────

test('a header missing `jailed` or `winRefusals` is refused before the scorer sees it', () => {
  // ⛔ A GATE ON THE WIRING, NOT ON THE VERDICT. The scorer refuses both cases by itself, so this
  // changes no verdict — it turns a permanently VOID witness that reads like a package property into
  // one that names the broken flag. `--jailed` silently not reaching the header is exactly the shape
  // that would leave this whole feature inert while every test stayed green.
  const ok = { k: 'h', jailed: true, winRefusals: true, roots: { home: HOME } };
  assert.equal(headerIsScoreable(ok).ok, true);
  assert.equal(headerIsScoreable(null).ok, false);
  assert.equal(headerIsScoreable({ k: 'e' }).ok, false);
  assert.equal(headerIsScoreable({ ...ok, jailed: false }).ok, false);
  assert.equal(headerIsScoreable({ ...ok, jailed: 'true' }).ok, false);
  assert.equal(headerIsScoreable({ ...ok, winRefusals: undefined }).ok, false);
  assert.equal(headerIsScoreable({ ...ok, roots: { home: '' } }).ok, false);
  assert.equal(headerIsScoreable({ ...ok, roots: {} }).ok, false);
});

// ── THE MARKER ────────────────────────────────────────────────────────────────────────────────────

test('a refused capture emits a VOID marker record.mjs parses, with the reason beneath it', () => {
  // ⛔ THE MARKER IS THE SCORER'S OWN `marker()`, not a second copy of its JSON. Both shell drivers
  // hand-write theirs because they cannot import JS, and a hand-written third copy is how the descent
  // vocabulary came to be spelled two ways with both sides' tests green.
  const [markerLine, reasonLine] = voidWitness(WITNESS_CAP, 'the session lost 62 events');
  const m = /DENIAL-WITNESS\s+(\{.*\})\s*$/.exec(markerLine);
  assert.ok(m, `record.mjs would not parse this line: ${markerLine}`);
  const p = JSON.parse(m[1]);
  assert.equal(p.cap, WITNESS_CAP);
  assert.equal(p.verdict, 'VOID');
  assert.equal(p.refusalsInScope, 0);
  assert.equal(p.lifecyclePids, 0);
  assert.equal(p.events, 0);
  assert.deepEqual(p.sample, []);
  assert.match(reasonLine, /VOID — the session lost 62 events/);
});

test('⛔ NO PATH IN THE CAPTURE HALF CAN EMIT A NON-VOID VERDICT', () => {
  // ⛔⛔ THE NEGATIVE THIS FILE EXISTS FOR, ASSERTED OVER THE SOURCE RATHER THAN CASE BY CASE. Only
  // `denial-witness.mjs` may say CLEAN or WITNESSED; everything the driver emits on its own must be
  // VOID. A future "helpful" shortcut — say, treating a capture with zero refusals as clean without
  // running the scorer — is precisely the blanket licence to narrow, and it would look like a
  // simplification in review.
  for (const f of ['win32-witness.mjs', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, f), 'utf8')
      .split('\n').filter((l) => !l.trimStart().startsWith('//')).join('\n');
    for (const verdict of ['CLEAN', 'WITNESSED']) {
      assert.doesNotMatch(src, new RegExp(`verdict:\\s*'${verdict}'`),
        `${f} constructs a ${verdict} verdict of its own — only the scorer may`);
    }
  }
});

// ── END TO END, AS FAR AS THIS HOST CAN GO ────────────────────────────────────────────────────────

test('a stream built from the witness roots is scored on the WIN32 axis, and is VOID without the control', () => {
  // ⛔ THE HANDOFF, EXERCISED. The roots this module declares have to produce a stream the win32 axis
  // accepts as expressible — a Windows home root that the POSIX comparator would silently find empty
  // is the live false-CLEAN the scorer was repaired for. And with no Create refused by
  // STATUS_ACCESS_DENIED anywhere in it, the axis must answer VOID rather than CLEAN, because that
  // premise has never been measured on any real runner.
  const roots = witnessRoots({ project: ARM, home: HOME, pkg: 'x' });
  const rows = [
    { k: 'h', v: 1, platform: 'win32-x64', jailed: true, winRefusals: true, roots },
    { k: 'p', pid: 8736, ppid: 5116, life: 1 },
    ...Array.from({ length: 300 }, (_, n) => ({
      k: 'e', p: 8736, o: 'open-r', s: 'Create', f: `C:\\Users\\runneradmin\\x${n}`, st: null, n: 1,
    })),
  ];
  const r = witness(rows, { cap: WITNESS_CAP, exclude: ['C:\\jail\\m-x-abc'] });
  assert.equal(r.scope, 'userHome', 'the win32 axis did not express a scope from these roots');
  assert.equal(r.verdict, 'VOID', `expected VOID with no ACCESS_DENIED control, got ${r.verdict}`);
  assert.match(r.reason, /STATUS_ACCESS_DENIED/);
});

test('the driver traces the userHome drop arm and ONLY that one', () => {
  // ⛔ TRACING AN ARM THE SCORER CANNOT EXPRESS BUYS AN ETW SESSION AND A tracerpt CONVERSION FOR AN
  // UNSUPPORTED VERDICT, inside a package budget this platform already strains — `run-batch-v2.mjs`
  // caps the driver at 2400 s against a 1800 s arm timeout. `no-network` is refused on win32 outright:
  // `windows-retain.mjs` writes `st: null` on every Kernel-Network event, so a refused socket leaves
  // no outcome and its absence is not evidence.
  const drv = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /const traced = !NO_WITNESS && name === WITNESS_CAP;/,
    'the driver no longer scopes tracing to the one capability the scorer expresses');
  assert.match(drv, /if \(traced\) denialWitness\(`nar-\$\{name\}`, name\);/,
    'the driver no longer emits a marker for the traced arm');
  assert.equal(WITNESS_CAP, 'no-write-userHome');
});

test('declining the witness cannot license a narrowing, only lose one', () => {
  // `--no-witness` exists because the capture has a real cost. With no marker emitted, `record.mjs`
  // falls back to the rule it had before the witness existed — the state every committed win32 record
  // was measured under — so the flag can only ever keep a grant wider.
  const drv = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(drv, /const NO_WITNESS = argv\.includes\('--no-witness'\);/);
  const rec = fs.readFileSync(path.join(HERE, 'record.mjs'), 'utf8');
  assert.match(rec, /out\.overPredictedBy\.every\(\(c\) => witnessOf\(c\) === 'CLEAN'\)/,
    'record.mjs no longer requires a CLEAN on EVERY dropped capability, so an absent marker might now '
    + 'license a narrowing rather than block one');
});
