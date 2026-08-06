// Parser tests for `record.mjs`, against REAL driver output.
//
// ⛔ THE FIXTURES ARE CAPTURED FROM A LIVE RUN, NOT HAND-WRITTEN FROM THE DRIVER SOURCE. A fixture
// reconstructed from the `echo` statements in `measure-macos.sh` tests the parser against my reading
// of the driver rather than against the driver, and would agree with a parser that is wrong in
// exactly the way my reading was. These three blocks are `macos-v2-measure` run 31088841052's VERIFY
// step verbatim, and they happen to cover the three outcomes that matter: a grant that verified and
// then narrowed (over-prediction), and two that did not verify at all.
//
//   node --test harness/v2/record.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDriverLog, firstObject } from './record.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const load = (f) => fs.readFileSync(path.join(FIX, f), 'utf8');

test('a verified grant that narrows records the VERIFIED grant, not the narrower one', () => {
  const r = parseDriverLog(load('macos-_apollo_protobufjs-1.2.7.txt'));
  assert.equal(r.verdict, 'MINIMUM');
  assert.deepEqual(r.grant, { write: { deps: true } });
  assert.equal(r.verifiedBy, 'synth');
  // ⛔ THE RECORDED GRANT IS THE ONE WHOSE ARM PASSED, AND `{}` IS NOT IT even though a `{}` arm also
  // passed here. Leave-one-out proves each capability droppable INDIVIDUALLY, never jointly, so
  // adopting the narrowest observed variant as the grant would under-grant the moment a package has
  // two capabilities — the one direction that breaks a real install. The over-prediction is recorded
  // beside the grant instead, which is the honest shape.
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(r.overPredictedBy, ['no-write-deps']);
});

test('a grant that did not verify is UNDER-PREDICTED with no grant, not a harness error', () => {
  for (const f of ['macos-_nuxt_components-2.1.0.txt', 'macos-codeceptjs-1.1.3.txt']) {
    const r = parseDriverLog(load(f));
    assert.equal(r.verdict, 'UNDER-PREDICTED', f);
    assert.equal(r.grant, null, f);
    // The hypothesis is still worth keeping: it is what the next fix has to explain.
    assert.ok(r.synthesized, f);
    assert.ok(r.notes.includes('under-predicted'), f);
  }
});

test('the synthesized grant survives even when the driver only observed', () => {
  const r = parseDriverLog(load('macos-codeceptjs-1.1.3.txt'));
  assert.deepEqual(r.synthesized, { write: { deps: true }, network: true });
});

// ⛔ THE NEGATIVE CONTROL. Silence must not read as an empty grant: a driver killed by a deadline or
// dying before its first `=>` has measured NOTHING, and emitting `{}` for it would record "this
// package needs no capabilities" — an under-grant manufactured out of an instrument failure.
test('a log with no terminal line yields no verdict, so the caller must call it HARNESS-*', () => {
  const r = parseDriverLog('### foo@1.0.0\n  OBSERVE   rc=0 files=3\n');
  assert.equal(r.verdict, null);
  assert.equal(r.grant, null);
});

test('a trailing paren does not get swallowed into the grant', () => {
  assert.deepEqual(
    firstObject('  => VERIFIED {"write":{"deps":true}}   (observed, then verified)'),
    { write: { deps: true } },
  );
});

// The Windows and Linux drivers are not exercised by a captured fixture — no v2 run on either has
// produced one this lane could read back. These assert only the vocabulary difference the parser
// exists to resolve, and are marked as such rather than presented as end-to-end coverage.
test('MINIMUM via the ladder is distinguished from MINIMUM via synthesis', () => {
  const synth = parseDriverLog('  => MINIMUM {"write":{"deps":true}}   (observed, then verified)');
  assert.equal(synth.verifiedBy, 'synth');
  const ladder = parseDriverLog('  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)');
  assert.equal(ladder.verifiedBy, 'ladder');
  assert.equal(ladder.verdict, 'MINIMUM');
});

test('a VOID arm is never reported as a grant of any width', () => {
  const r = parseDriverLog('  => ⛔ VOID — the override did not engage on the verdict arm; NOTHING was measured.');
  assert.equal(r.verdict, 'VOID');
  assert.equal(r.grant, null);
});

// ── `events-lost` must fire on EVERY driver's wording, not just the one it was written against ────
//
// ⛔ A NOTE THAT FIRES ON ONE VENUE OF THREE IS WORSE THAN ABSENT, because its silence reads as a
// clean trace. `record.mjs` keyed on `events LOST`, which is the WINDOWS spelling and genuinely live
// there — so the note was never dead, and that is precisely why nobody caught it. macOS and Linux
// announce event loss in their own words and were never noted at all: both darwin records dropped an
// event and shipped `notes: []`. A dropped event is a path never seen, which UNDER-predicts the
// grant, so this is the record's only warning that its own evidence is incomplete.

const HARNESS = path.dirname(fileURLToPath(import.meta.url));

// The rendered form of each driver's loss line, with its interpolations filled in. Hand-rendered
// rather than captured, because no fixture we hold has ever lost an event — so the drift guard below
// is what keeps these honest, by asserting each wording is still the one its driver emits.
const LOSS_LINES = {
  'windows / measure-windows.mjs':
    '  !! 7 events LOST -- exact-set claims are not supported by this trace',
  'macos / observe-macos.mjs (tracer drop)':
    '  ⛔ THE TRACER DROPPED 7 EVENT(S). A dropped event is a path never',
  'macos / observe-macos.mjs (loss ledger)':
    '  ⛔ LOSS LEDGER DISAGREES: END says 7, 5 per-event records survived',
  'linux / observe.mjs':
    '  ⛔ 7 trace lines the decoder could not parse',
};

test('DRIFT GUARD: each wording under test is still the one its driver actually emits', () => {
  // Without this, the hardcoded strings above could drift away from the drivers and every case below
  // would keep passing while the real note went dead again — the same failure, one level up.
  const src = (f) => fs.readFileSync(path.join(HARNESS, f), 'utf8');
  assert.match(src('measure-windows.mjs'), /events LOST -- exact-set claims/,
    'the Windows driver no longer emits the wording these tests pin');
  assert.match(src('observe-macos.mjs'), /THE TRACER DROPPED \$\{/,
    'the macOS adapter no longer emits THE TRACER DROPPED');
  assert.match(src('observe-macos.mjs'), /LOSS LEDGER DISAGREES: END says/,
    'the macOS adapter no longer emits LOSS LEDGER DISAGREES');
  assert.match(src('observe.mjs'), /trace lines the decoder could not parse/,
    'the Linux decoder no longer emits its unparsed-lines line');
});

for (const [driver, line] of Object.entries(LOSS_LINES)) {
  test(`\`events-lost\` fires on the ${driver} wording`, () => {
    // Injected into a REAL driver log so the note is exercised on a record that otherwise parses
    // completely, rather than on a synthetic stub that could pass for unrelated reasons.
    const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
    base.splice(1, 0, line);
    const r = parseDriverLog(base.join('\n'));
    assert.ok(r.notes.includes('events-lost'),
      `a dropped event went unnoted for ${driver} — the record claims complete evidence it does not have:\n${JSON.stringify(r.notes)}`);
  });
}

test('CONTROL: a driver log that lost NOTHING carries no `events-lost` note', () => {
  // The control without which every case above is consistent with a detector that fires on any line
  // at all. All three real fixtures are clean traces, verified: none contains a loss line.
  for (const f of ['macos-_apollo_protobufjs-1.2.7.txt', 'macos-_nuxt_components-2.1.0.txt', 'macos-codeceptjs-1.1.3.txt']) {
    const r = parseDriverLog(load(f));
    assert.ok(!r.notes.includes('events-lost'),
      `${f} lost no events but was noted as if it had — the detector is too wide:\n${JSON.stringify(r.notes)}`);
  }
});

test('a driver that trips TWO loss lines still yields exactly one note', () => {
  // macOS emits both of its wordings on the same run. `out.notes` is de-duplicated, and this pins it.
  const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
  base.splice(1, 0, LOSS_LINES['macos / observe-macos.mjs (tracer drop)'],
                    LOSS_LINES['macos / observe-macos.mjs (loss ledger)']);
  const r = parseDriverLog(base.join('\n'));
  assert.equal(r.notes.filter((n) => n === 'events-lost').length, 1,
    `one loss must produce one note:\n${JSON.stringify(r.notes)}`);
});

// ── Venue provenance (R3) ───────────────────────────────────────────────────────────────────────

test('the venue markers are learned from stdout, and absent markers stay null', () => {
  const r = parseDriverLog([
    '  VENUE-OBSERVE-USER NUB-WIN3\\nub elevated=True privDropped={"SeBackupPrivilege":"removed"}',
    '  VENUE-JAIL-ROOT C:\\jailv\\m-thing-abc',
    '  VENUE-INTERPRETER C:\\Program Files\\nodejs\\node.exe',
    '  VENUE-STORE-LAYOUT hoisted',
    '  => MINIMUM {"write":{"deps":true}}   (observed, then verified)',
  ].join('\n'));
  assert.equal(r.observeUser, 'NUB-WIN3\\nub elevated=True privDropped={"SeBackupPrivilege":"removed"}');
  // ⛔ THE JAIL ROOT MUST SURVIVE A SPACE. `(\S+)` would truncate `C:\Program Files\...` to
  // `C:\Program` and record a root that never existed — and this field exists precisely because a
  // path-dependent ACL failure is what it has to let a reader diagnose.
  assert.equal(r.jailRoot, 'C:\\jailv\\m-thing-abc');
  assert.equal(r.interpreterPath, 'C:\\Program Files\\nodejs\\node.exe');
  assert.equal(r.storeLayout, 'hoisted');

  const bare = parseDriverLog('  => MINIMUM {}   (observed, then verified)');
  assert.equal(bare.jailRoot, null, 'an unreported jail root must be null, never a guess');
  assert.equal(bare.observeUser, null, 'an unasserted R7 identity must be null — that IS the finding');
});

test('a jail root containing a space is recorded whole', () => {
  const r = parseDriverLog('  VENUE-JAIL-ROOT C:\\Program Files\\jail\\m-x\n');
  assert.equal(r.jailRoot, 'C:\\Program Files\\jail\\m-x');
});

// ⛔ THIS IS A REGRESSION TEST FOR A FIELD THAT WAS SILENTLY FALSE ON EVERY WINDOWS RECORD. The
// containment test was `interpreterPath.startsWith(`${home}/`)` — a forward slash, case-sensitive —
// which is unsatisfiable on win32 where the separator is `\` and the filesystem folds case. `false`
// is a claim rather than an absence, so nothing downstream could tell it from a measurement.
//
// `insideHome` is not exported (record.mjs is a script with a CLI tail), so this drives the CLI,
// which is also the only way to prove the platform actually reaches the comparison.
test('interpreterInsideHome is computed with the RECORD platform\'s path rules', async () => {
  const { spawnSync } = await import('node:child_process');
  const os = await import('node:os');
  const REC = path.join(path.dirname(fileURLToPath(import.meta.url)), 'record.mjs');

  const run = (platform, interpreter, home) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rec-'));
    const log = path.join(dir, 'd.txt');
    fs.writeFileSync(log, `  VENUE-INTERPRETER ${interpreter}\n  => MINIMUM {}   (observed, then verified)\n`);
    const r = spawnSync(process.execPath, [REC, '--log', log, '--pkg', 'p', '--version', '1.0.0',
      '--out', dir, '--platform', platform], {
      encoding: 'utf8',
      // The home is read from the environment, so the two platforms' conventions are supplied the
      // way each really arrives.
      env: { ...process.env, HOME: platform.startsWith('win32') ? undefined : home, USERPROFILE: home },
    });
    assert.equal(r.status, 0, r.stderr);
    const rec = JSON.parse(fs.readFileSync(path.join(r.stdout.trim(), 'results.json'), 'utf8'));
    fs.rmSync(dir, { recursive: true, force: true });
    return rec.provenance;
  };

  // The exact shape that used to report `false`: Node under the user profile, backslashes, and a
  // capital `Users` the kernel may spell either way.
  const win = run('win32-x64', 'C:\\Users\\nub\\AppData\\Local\\nodejs\\node.exe', 'C:\\Users\\nub');
  assert.equal(win.interpreterInsideHome, true,
    'a Windows interpreter under the user profile must be recognised as inside the home');
  const winFolded = run('win32-x64', 'c:\\users\\NUB\\scoop\\node.exe', 'C:\\Users\\nub');
  assert.equal(winFolded.interpreterInsideHome, true, 'Windows containment must fold case');
  const winOut = run('win32-x64', 'C:\\Program Files\\nodejs\\node.exe', 'C:\\Users\\nub');
  assert.equal(winOut.interpreterInsideHome, false, 'a system-wide Node must NOT read as inside the home');

  // POSIX is unchanged, including the boundary that a prefix match without a separator gets wrong.
  const posix = run('linux-x64', '/home/nub/.nvm/versions/node/v22.15.0/bin/node', '/home/nub');
  assert.equal(posix.interpreterInsideHome, true);
  const sibling = run('linux-x64', '/home/nubbins/bin/node', '/home/nub');
  assert.equal(sibling.interpreterInsideHome, false,
    '/home/nubbins must not read as inside /home/nub — the separator boundary is load-bearing');
});

// ── THE grant-SOURCE RULE ─────────────────────────────────────────────────────────────────────
//
// `collate.mjs` keys on `grant`, so this decides what the shipped catalog contains for every record
// on every platform. The branches that REFUSE to narrow carry the weight: narrowing is the
// under-grant direction, and a rule that always narrowed would satisfy every "narrows" assertion.
const drv = (lines) => parseDriverLog(lines.join('\n'));

test('a single dropped capability narrows the grant — one arm verified exactly that grant', () => {
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true},"network":true}',
    '  => VERIFIED {"write":{"userHome":true},"network":true}',
    "     ⛔ OVER-PREDICTED — the strictly narrower {\"network\":true} also verifies; 'no-write-userHome' was not needed",
  ]);
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { network: true });
  assert.deepEqual(r.descendedGrant, { network: true });
});

test('TWO dropped capabilities do NOT narrow — leave-one-out never measured the joint drop', () => {
  // ⛔ THE GUARD THAT THE OBVIOUS IMPLEMENTATION MISSES. Each capability has an arm proving it drops
  // ALONE; the joint grant is strictly narrower than any arm that ran. measure.sh says as much in its
  // own summary — "each named capability drops on its own".
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"write":{"project":true},"network":true}',
    "     ⛔ OVER-PREDICTED — the strictly narrower x also verifies; 'no-network' was not needed",
    "     ⛔ OVER-PREDICTED — the strictly narrower y also verifies; 'no-write-project' was not needed",
  ]);
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.grant, { write: { project: true }, network: true }, 'keeps the WIDE grant');
  assert.deepEqual(r.descendedGrant, {}, 'but still records what the descent pointed at');
  assert.match(r.grantSourceReason, /never run/);
});

test('two dropped capabilities DO narrow once a JOINT-NARROW arm verifies them together', () => {
  // The positive control for the guard above: it must be possible to earn the narrow grant, or the
  // guard is just a permanent refusal wearing a reason.
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"write":{"project":true},"network":true}',
    "     ⛔ OVER-PREDICTED — the strictly narrower x also verifies; 'no-network' was not needed",
    "     ⛔ OVER-PREDICTED — the strictly narrower y also verifies; 'no-write-project' was not needed",
    '  => JOINT-NARROW VERIFIED {} — all 2 capabilities drop TOGETHER, measured',
  ]);
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, {});
});

test('an unfalsifiable package never narrows, however many arms passed', () => {
  // A passing narrow arm for a package whose arms could not have failed is not evidence.
  const r = drv([
    '  ⛔ ARMS-UNFALSIFIABLE — a green arm for this package carries no evidence:',
    '  => VERIFIED {"write":{"deps":true}}',
    "     ⛔ OVER-PREDICTED — the strictly narrower {} also verifies; 'no-write-deps' was not needed",
  ]);
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.grant, { write: { deps: true } }, 'the wide grant survives');
  assert.match(r.grantSourceReason, /could not have failed/);
});

test('a MINIMAL record is unaffected — there is nothing to narrow', () => {
  const r = drv([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"network":true}',
    '  => MINIMAL — every capability in {"network":true} is independently necessary',
  ]);
  assert.equal(r.grantSource, 'synthesized');
  assert.deepEqual(r.grant, { network: true });
});

test('the nub binary identity is parsed, so a record says WHAT measured it and not only which commit', () => {
  // ⛔ `nubGitSha` provably cannot answer this. MEASURED 2026-08-06: a `--release` build of the right
  // commit, missing only `build-jail-catalog-override`, VOIDed four measurement cells while reporting
  // a `nubGitSha` identical to the working binary's. The content hash is also the only identity that
  // survives a shared mutable binary path, which is how that mix-up happened in the first place.
  const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
  base.splice(1, 0, '  VENUE-NUB-BINARY {"path":"/n/nub","sha256":"abc123","bytes":49484400,'
    + '"features":{"buildJailCatalogOverride":true,"pythonDontWriteBytecodeEnv":false}}');
  const r = parseDriverLog(base.join('\n'));
  assert.equal(r.nubBinary?.sha256, 'abc123', `the binary hash must survive into the record:\n${JSON.stringify(r.nubBinary)}`);
  assert.equal(r.nubBinary.features.buildJailCatalogOverride, true);
  assert.equal(r.nubBinary.features.pythonDontWriteBytecodeEnv, false,
    'a MISSING feature must be recorded as false, not dropped — absent and false read the same otherwise');
});

test('CONTROL: a driver log with no binary marker records null rather than inventing a binary', () => {
  const r = parseDriverLog(load('macos-_apollo_protobufjs-1.2.7.txt'));
  assert.equal(r.nubBinary, null, 'an unreported binary must stay null, not become a fabricated identity');
});

test('a malformed binary marker is NOTED rather than silently dropped', () => {
  const base = load('macos-_apollo_protobufjs-1.2.7.txt').split('\n');
  base.splice(1, 0, '  VENUE-NUB-BINARY {this is not json');
  const r = parseDriverLog(base.join('\n'));
  assert.equal(r.nubBinary, null);
  assert.ok(r.notes.includes('nub-binary-unparsable'),
    `a marker that failed to parse must leave a trace:\n${JSON.stringify(r.notes)}`);
});

// ── THE CLI MUST CARRY THE grant-SOURCE FIELDS THROUGH ────────────────────────────────────────
//
// ⛔ EVERY PARSE-LEVEL TEST ABOVE PASSED WHILE THE PUBLISHED RECORD CARRIED NONE OF THESE FIELDS.
// `rec` in the CLI block is an explicit whitelist, so `parseDriverLog` set `grantSource` and the CLI
// silently dropped it — while still writing the NARROWED `grant` it justified. A record whose grant
// has been narrowed with nothing saying on what basis is the exact silent-narrowing shape the rule
// exists to prevent, and no test that stops at `parseDriverLog` can see it. MEASURED on
// kerberos@7.0.0 at 76c25673: grant {} as the rule intended, grantSource absent.
test('the CLI writes grantSource, grantSourceReason and descendedGrant into the record', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reccli-'));
  const log = path.join(dir, 'driver.out');
  fs.writeFileSync(log, [
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"write":{"userHome":true},"network":true}',
    "     ⛔ OVER-PREDICTED — the strictly narrower {\"network\":true} also verifies; 'no-write-userHome' was not needed",
  ].join('\n'));
  // `--out` is a ROOT; the CLI appends <platform>/<pkg>/<version>/results.json under it.
  const outRoot = path.join(dir, 'out');
  execFileSync(process.execPath, [path.join(HARNESS, 'record.mjs'),
    '--log', log, '--pkg', 'p', '--version', '1.0.0', '--out', outRoot, '--rc', '0'], { encoding: 'utf8' });
  const found = fs.globSync
    ? fs.globSync(path.join(outRoot, '**', 'results.json'))
    : [path.join(outRoot, process.platform === 'darwin' ? `darwin-${process.arch}` : '', 'p', '1.0.0', 'results.json')];
  assert.ok(found.length === 1, `exactly one record should be written, got ${found.length}`);
  const rec = JSON.parse(fs.readFileSync(found[0], 'utf8'));
  assert.deepEqual(rec.grant, { network: true }, 'the narrowed grant is written');
  assert.equal(rec.grantSource, 'descended', 'AND the record says which value it is');
  assert.match(rec.grantSourceReason, /verified in the real jail/, 'AND why');
  assert.deepEqual(rec.descendedGrant, { network: true });
});
