// ⛔⛔ THE SCORING HALF OF THE EVICTED-SUBJECT DEFECT. UNDER-PREDICTION GUARD.
//
// `subject-survives-scaffold.test.mjs` pins the DRIVER half: all three drivers re-install the
// subject after the scaffold and REFUSE a tree that still lacks it. This file pins the READING half,
// which is a separate defect and was still open after that one closed.
//
// `arm-falsifiability.mjs` has reported `manifestFiles` since it was written — the size of the
// manifest it walked under the subject's own directory, or `null` when `pkgDir()` resolved no such
// directory at all. Nothing read it. `record.mjs` gated the whole grant-source rule on the marker
// LINE EXISTING, so a payload of `{"manifestFiles":null,…}` scored as "the question was asked and
// answered" while the arm behind it had measured a tree the package was never in.
//
// MEASURED over all 6,887 committed `driver.out` files: 5,667 carry exactly one parseable
// `ARM-FALSIFIABILITY` payload and 39 of those report `manifestFiles: null` — 36 linux-x64, 3
// darwin-arm64, 0 win32. Every one of the 39 carries an `ARM-SCAFFOLD` line, and every one carries
// `reasons: []` and no `arms-unfalsifiable` note, so NOT ONE is caught by the vacuity machinery that
// already existed. 15 are `MINIMUM`; 13 of those publish `grant: {}` and one — `p5@0.7.0` — publishes
// `grantSource: "descended"`. `{}` from an arm that ran nothing is byte-identical to `{}` from a
// package that genuinely needs nothing, and it is an under-grant, which breaks installs.
//
// ⛔ THE FALSE-NEGATIVE AND THE FALSE-POSITIVE ARE BOTH FATAL, so every refusal below is paired with
// a control differing in exactly one term. 1,220 of the 6,887 logs carry no marker at all: a gate
// that read "absent" as "absent SUBJECT" would floor the entire corpus while satisfying every
// refusal assertion here.
//
//   node --test harness/v2/subject-absent-is-not-a-measurement.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDriverLog } from './record.mjs';
import { decide, narrowingEvidence, subjectAbsent } from './publish-guard.mjs';

const HARNESS = import.meta.dirname;

// ⛔ VERBATIM FROM `records-v2/runs/linux-x64/p5/0.7.0/driver.out:21`, and identical in all 39. A
// payload hand-written from `arm-falsifiability.mjs`'s source would test this parser against a
// reading of the emitter rather than against the emitter. Note `reasons: []` — the vacuity terms are
// silent here, which is precisely why a new one was needed.
const EVICTED = '  ARM-FALSIFIABILITY {"manifestFiles":null,"filesTheScriptProduced":null,"reasons":[]}';
const PRESENT = '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":3,"reasons":[]}';
// A marker from before the field existed. Must score exactly as a missing marker does.
const PREFIELD = '  ARM-FALSIFIABILITY {"reasons":[]}';

// A one-capability over-prediction, so the grant-source rule has something real to refuse. Mirrors
// the shape `record.test.mjs` already drives the CLI with.
const NARROWS = [
  '  => VERIFIED {"write":{"userHome":true},"network":true}',
  "     ⛔ OVER-PREDICTED — the strictly narrower {\"network\":true} also verifies; 'no-write-userHome' was not needed",
];

// ── the parser ────────────────────────────────────────────────────────────────────────────────

test('the recorder reads manifestFiles into a tri-state, and only the null is an alarm', () => {
  assert.equal(parseDriverLog(EVICTED).subjectInObserveTree, false,
    'manifestFiles:null means pkgDir() resolved no directory — the arms ran against a tree with no subject in it');
  assert.equal(parseDriverLog(PRESENT).subjectInObserveTree, true);
  // ⛔ THE TWO SHAPES THAT MUST NOT REFUSE. `null` here is "not established", and it covers both a
  // marker predating the field and the 1,220 logs with no marker at all.
  assert.equal(parseDriverLog(PREFIELD).subjectInObserveTree, null,
    'a marker predating the field is UNKNOWN, never absent-subject');
  assert.equal(parseDriverLog('  => VERIFIED {}').subjectInObserveTree, null,
    'a log with no marker is UNKNOWN — reading it as absent-subject would floor 1,220 records');
});

test('an evicted subject leaves a human-readable note beside the typed field', () => {
  assert.ok(parseDriverLog(EVICTED).notes.includes('subject-absent'));
  assert.ok(!parseDriverLog(PRESENT).notes.includes('subject-absent'));
});

// ── the record ────────────────────────────────────────────────────────────────────────────────

test('the CLI writes subjectInObserveTree into results.json', () => {
  // ⛔ THE HALF `confinedWide` GOT WRONG, AND THE HALF THIS WHOLE DEFECT IS. `rec` in the CLI block
  // is an explicit whitelist: a field parsed and not listed there is computed on every run and then
  // thrown away, which is exactly what happened to `manifestFiles` at the emitter. Parsing it and
  // dropping it here would move the defect one step along rather than close it —
  // `publish-guard.mjs` reads records and never logs, so this field is the only route by which the
  // fact reaches `decide()` and `collate.mjs`'s Gate 2.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'subjabs-'));
  const log = path.join(dir, 'driver.out');
  fs.writeFileSync(log, [EVICTED, ...NARROWS].join('\n'));
  const outRoot = path.join(dir, 'out');
  execFileSync(process.execPath, [path.join(HARNESS, 'record.mjs'),
    '--log', log, '--pkg', 'p', '--version', '1.0.0', '--out', outRoot, '--rc', '0'], { encoding: 'utf8' });
  const [found] = fs.globSync(path.join(outRoot, '**', 'results.json'));
  const rec = JSON.parse(fs.readFileSync(found, 'utf8'));
  assert.equal(rec.subjectInObserveTree, false, 'the field must survive the whitelist');
  assert.equal(subjectAbsent(rec), true, 'and the guard must see it on a record round-tripped through JSON');
});

// ── the grant-source rule ─────────────────────────────────────────────────────────────────────

test('a descent measured on an evicted subject keeps the wider synthesized grant', () => {
  // `p5@0.7.0`'s shape — the one record of the 39 that published `grantSource: "descended"`.
  const r = parseDriverLog([EVICTED, ...NARROWS].join('\n'));
  assert.equal(r.grantSource, 'synthesized');
  assert.match(r.grantSourceReason, /did not contain the subject/);
  assert.deepEqual(r.grant, { write: { userHome: true }, network: true },
    'the record keeps the WIDE grant — a narrowing off an empty tree is the under-grant being refused');
});

test('CONTROL: the identical descent publishes its narrowing once the subject was present', () => {
  // Exactly one thing differs from the case above: `manifestFiles` is a number. A rule that refused
  // both would freeze every falsifiable narrowing in the corpus and look correct doing it.
  const r = parseDriverLog([PRESENT, ...NARROWS].join('\n'));
  assert.equal(r.grantSource, 'descended', 'a real measurement must still be allowed to narrow');
  assert.deepEqual(r.grant, { network: true });
});

// ── the shared narrowing predicate ────────────────────────────────────────────────────────────

/** A record carrying every licence `narrowingEvidence` recognises, so the only thing the assertions
 *  below can be turning on is the subject term. */
const fullyLicensed = (subjectInObserveTree) => ({
  subjectInObserveTree,
  grant: { network: true },
  notes: [],
  minimality: 'MINIMAL',
  descentRedArm: true,
  promotionProbe: { verdict: 'PROVEN', entries: [{ entry: 'Library/Preferences/x', control: true, drop: false }] },
});

test('an evicted subject outranks every licence, including a red arm and a PROVEN promotion probe', () => {
  // ⛔ THE ORDERING IS THE TEST. Every other term in `narrowingEvidence` answers "could this arm have
  // gone red?"; a red arm in a tree with no subject in it proves the jail fires, not that this
  // package needs the capability. So the refusal has to sit above all of them — and above the
  // `arms-unfalsifiable` early return too, since all 39 measured records carry `notes: []` and a
  // term placed below it is unreachable for every one of them.
  const e = narrowingEvidence(fullyLicensed(false), ['write.userHome']);
  assert.equal(e.evidence, false, 'no licence may survive an arm that never saw the package');
  assert.match(e.why, /did not contain the subject/);
});

test('CONTROL: unknown and present both still license exactly what they did before', () => {
  for (const v of [true, null, undefined]) {
    assert.equal(narrowingEvidence(fullyLicensed(v), ['write.userHome']).evidence, true,
      `subjectInObserveTree=${v} must not refuse — only an explicit false is the alarm`);
  }
  // The same falsy-shape check on the predicate itself: `0` and `''` are not `false`.
  assert.equal(subjectAbsent({ subjectInObserveTree: 0 }), false);
  assert.equal(subjectAbsent({}), false);
  assert.equal(subjectAbsent(null), false);
});

// ── the publish guard ─────────────────────────────────────────────────────────────────────────

const measured = (grant, extra = {}) => ({ verdict: 'MINIMUM', grant, notes: [], minimality: 'MINIMAL', ...extra });

test('a FIRST {} measured on an evicted subject is withheld, though it drops no token', () => {
  // ⛔ THIS IS THE MODAL CASE AND IT DROPS NOTHING. 13 of the 15 MINIMUM records in this population
  // publish `{}` with no prior record, so `narrows()` returns an empty set for every one of them —
  // a term gated on `dropped.length > 0` alone lets all 13 through. An empty entry is TIGHTER than
  // no entry: `build_jail.rs` falls back to `baseline_caps()` on an ABSENT entry and disables the
  // write-path promotion outright on an EMPTY one.
  const d = decide(null, measured({}, { subjectInObserveTree: false }));
  assert.equal(d.publish, false);
  assert.match(d.reason, /no package directory in the observe tree/);
});

test('CONTROL: the identical first {} publishes when the subject was in the tree', () => {
  assert.equal(decide(null, measured({}, { subjectInObserveTree: true })).publish, true,
    'a package genuinely measured as needing nothing must still be able to say so');
});

test('a narrowing measured on an evicted subject is withheld', () => {
  const d = decide(measured({ write: { userHome: true }, network: true }),
    measured({ network: true }, { subjectInObserveTree: false, minimality: 'OVER-PREDICTED', descentRedArm: true }));
  assert.equal(d.publish, false);
  assert.match(d.reason, /write\.userHome/);
});

test('a WIDENING measured on an evicted subject still publishes — flag, never fail', () => {
  // ⛔ THE ASYMMETRY IS DELIBERATE AND IT IS THE SAME ONE `publish-guard.mjs` OPENS WITH. Widening or
  // confirming on weak evidence cannot break an install, so the flag refuses narrowings only. A
  // blanket refusal here would discard a wider, safer grant to buy nothing — and would be the
  // epoch-44 mistake epoch 45 had to undo, in a new place.
  const d = decide(measured({ network: true }),
    measured({ write: 'disk', network: true }, { subjectInObserveTree: false }));
  assert.equal(d.publish, true, 'a subject-absent record that only ADDS capability is still safe to publish');
});
