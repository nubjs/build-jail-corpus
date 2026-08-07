// A descent killed at its budget must not report that it completed.
//
// ⛔ THE DEFECT, MEASURED on `mozjpeg@6.0.1` (win32), deliberately not published:
//
//   REC mozjpeg@6.0.1 [2400s] MINIMUM {"write":{"project":true,"userHome":true},"network":true} via=ladder
//   notes: ["under-predicted","driver-timeout"]  overPredictedBy: ["no-write-deps"]  minimality: "OVER-PREDICTED"
//
// `[2400s]` is exactly `NUB_CORPUS_PKG_BUDGET`. The descent finished `no-network` and `no-write-deps`
// and was then killed — `no-write-project`, `no-write-userHome` and the joint arm never ran. So the
// record published `write.userHome`, the PERSISTENCE capability, with `grantSource: "descended"`,
// having never tested it.
//
// ⛔ AND `collate.mjs` EXCLUDES ON VERDICT ALONE (its chain is a run of `r.verdict === ...` tests), so
// a truncated record whose verdict is `MINIMUM` reaches the catalog with nothing stopping it. The
// `driver-timeout` note was already recorded and already honest; it simply had no consumer.
//
// ⛔ THIS IS SYSTEMATIC. A ladder record costs ~3.4x a synth record (MEASURED: `iedriver` 693s ->
// 2376s once the descent ran), so ladder records are exactly the ones that hit a 2400s cap — and a
// Windows sweep is mostly ladder records.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseDriverLog, applyTruncationClaim, isTruncatedRc } from './record.mjs';

const HERE = import.meta.dirname;

/** The mozjpeg shape: a synth arm verifies (so `=> MINIMUM` is already printed), then ONE leave-one-out
 *  arm completes and narrows, and the driver is killed before the rest of the descent runs. */
const partialDescent = () => parseDriverLog([
  '  ARM-FALSIFIABILITY {"reasons":[]}',
  '  VERIFY[fb0] rc=0 grant={"write":{"deps":true,"project":true,"userHome":true},"network":true}',
  '  => VERIFIED {"write":{"deps":true,"project":true,"userHome":true},"network":true}',
  "     ⛔ OVER-PREDICTED — the strictly narrower q also verifies; 'no-write-deps' was not needed",
].join('\n'));

// ⛔ CONTROL FIRST. Every assertion below is about what a TRUNCATED record says, so if the fixture
// did not produce a genuinely descended record to begin with, the whole file would be asserting
// against a shape that never occurs.
test('CONTROL: the fixture really is a completed, narrowed descent before truncation is applied', () => {
  const r = partialDescent();
  assert.equal(r.grantSource, 'descended', 'the fixture must start as a descended record');
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(r.grant, { write: { project: true, userHome: true }, network: true },
    'and `write.deps` must really have been dropped, or there is no narrowing to mislabel');
});

test('⭑ mozjpeg@6.0.1: a budget-killed descent no longer reports `descended`', () => {
  const r = applyTruncationClaim(partialDescent(), 124);
  assert.equal(r.grantSource, 'descended-incomplete',
    'a descent that was killed mid-way must not claim it ran to completion');
  assert.equal(r.minimality, 'UNPROVEN',
    'minimality was never established — `OVER-PREDICTED` asserts a completed leave-one-out sweep');
  assert.ok(r.notes.includes('driver-timeout'));
  assert.match(r.grantSourceReason, /KILLED AT ITS BUDGET/);
  assert.match(r.grantSourceReason, /UNTESTED/);
});

test('⭑ the GRANT is untouched — the fix changes the claim, never the capability set', () => {
  // ⛔ THE SAFETY PROPERTY, AND IT POINTS THE OPPOSITE WAY TO INTUITION. Every drop that was APPLIED
  // had a verifying arm, so the narrowed grant is a real measurement. Widening it back would discard
  // verified narrowing; discarding the record would leave the package at the base profile, which is a
  // BROKEN install — the one error this corpus may not make. Over-granting is safe; under-granting is not.
  const before = partialDescent();
  const grantBefore = JSON.parse(JSON.stringify(before.grant));
  const r = applyTruncationClaim(before, 124);
  assert.deepEqual(r.grant, grantBefore, 'the truncation marker must not widen or narrow the grant');
  assert.deepEqual(r.grant, { write: { project: true, userHome: true }, network: true });
});

test('NEGATIVE CONTROL: a descent that COMPLETED still reports `descended`', () => {
  // Without this, "mark truncated descents" is satisfiable by marking every record.
  const r = applyTruncationClaim(partialDescent(), 0);
  assert.equal(r.grantSource, 'descended', 'rc=0 is a completed run and must be left alone');
  assert.equal(r.minimality, 'OVER-PREDICTED', 'a completed descent keeps its measured minimality');
  assert.ok(!r.notes.includes('driver-timeout'));
  assert.doesNotMatch(r.grantSourceReason ?? '', /BUDGET/);
});

test('NEGATIVE CONTROL: an ordinary non-zero rc is not a truncation', () => {
  // A driver that ran to completion and exited 1 has a complete descent; only a budget/kill rc means
  // arms were never run. Treating every failure as truncation would mark most of the corpus.
  const r = applyTruncationClaim(partialDescent(), 1);
  assert.equal(r.grantSource, 'descended');
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(isTruncatedRc(1), false);
  assert.deepEqual([isTruncatedRc(124), isTruncatedRc(137)], [true, true], 'both kill conventions count');
});

test('a truncated SYNTHESIZED record keeps its grant source but loses its minimality claim', () => {
  // The `duckdb@1.4.4` shape: killed before any capability dropped, so `grantSource` is honestly
  // `synthesized` and must stay that way — but "no capability was droppable" is a claim the run never
  // earned, so the reason has to say the descent was cut off.
  const base = parseDriverLog([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"write":{"deps":true},"network":true}',
  ].join('\n'));
  assert.equal(base.grantSource, 'synthesized', 'CONTROL: the fixture starts synthesized');
  const r = applyTruncationClaim(base, 124);
  assert.equal(r.grantSource, 'synthesized', 'nothing was narrowed, so nothing is mislabelled');
  assert.equal(r.minimality, 'UNPROVEN');
  assert.match(r.grantSourceReason, /KILLED AT ITS BUDGET/);
  assert.deepEqual(r.grant, { write: { deps: true }, network: true }, 'the wide grant stands');
});

// ⛔ THE END-TO-END LEG, AND IT IS THE ONE THAT MATTERS. The assertions above are about a parsed
// object; this is about what a reader of a real collate run actually sees. `collate.mjs` excludes on
// VERDICT alone, so a truncated record's verdict of `MINIMUM` carries it into the catalog with
// nothing stopping it — which is CORRECT (the grant installs, and dropping it would leave the package
// at the base profile), but was previously SILENT. The `driver-timeout` note existed all along and
// had no consumer, which is the same shape as the measure step that reported success having measured
// nothing.
test('⭑ collate SHIPS a truncated record and WARNS about it, and stays silent on a healthy one', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trunc-collate-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const log = path.join(dir, 'driver.out');
  fs.writeFileSync(log, [
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => MINIMUM {"write":{"deps":true,"project":true,"userHome":true},"network":true}   (ladder fallback; synthesized grant was insufficient)',
    "     ⛔ OVER-PREDICTED — the strictly narrower q also verifies; 'no-write-deps' was not needed",
  ].join('\n'));

  const rec = (pkg, version, rc) => spawnSync(process.execPath, [
    path.join(HERE, 'record.mjs'), '--log', log, '--pkg', pkg, '--version', version,
    '--out', path.join(dir, 'runs'), '--rc', String(rc), '--platform', 'win32-x64',
    '--duration-ms', '2400105', '--driver', 'measure-windows.mjs',
  ], { encoding: 'utf8' });
  // NEGATIVE CONTROL BAKED IN: the SAME driver log at rc=0. Any warning that names `healthy` is
  // firing on the log rather than on the truncation.
  assert.equal(rec('mozjpeg', '6.0.1', 124).status, 0);
  assert.equal(rec('healthy', '1.0.0', 0).status, 0);

  const c = spawnSync(process.execPath, [
    path.join(HERE, '..', 'collate.mjs'), '--runs', path.join(dir, 'runs'), '--out', path.join(dir, 'cat.json'),
  ], { encoding: 'utf8' });
  assert.equal(c.status, 0, `collate failed:\n${c.stdout}${c.stderr}`);
  assert.match(c.stdout, /DESCENT KILLED AT ITS BUDGET/, 'the truncation must be reported, not silent');
  assert.match(c.stdout, /mozjpeg@6\.0\.1/);

  const warned = c.stdout.slice(c.stdout.indexOf('DESCENT KILLED AT ITS BUDGET'));
  assert.doesNotMatch(warned, /healthy@1\.0\.0/,
    'a COMPLETED descent must not be warned about — otherwise the warning means nothing');

  const cat = JSON.parse(fs.readFileSync(path.join(dir, 'cat.json'), 'utf8'));
  assert.ok(cat.packages.mozjpeg, 'the truncated record must still SHIP — excluding it breaks the install');
  assert.deepEqual(cat.packages.mozjpeg.default.write, { project: true, userHome: true },
    'and it ships the same grant it measured');
});

test('the marker is idempotent, so a re-parse cannot stack reasons or notes', () => {
  const once = applyTruncationClaim(partialDescent(), 124);
  const twice = applyTruncationClaim(applyTruncationClaim(partialDescent(), 124), 124);
  assert.equal(twice.notes.filter((n) => n === 'driver-timeout').length, 1);
  assert.equal(twice.grantSource, once.grantSource);
});
