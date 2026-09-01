// Repairing a committed UNDER-GRANT offline, and the three properties that make writing to an
// archive safe: it may only ever WIDEN, it may touch only the four fields the repair is about, and it
// must be idempotent.
//
// ⛔ EVERY FIXTURE HERE IS A REAL CORPUS SHAPE. The widening log is the browser-downloader shape —
// a positive `userHome` write census with a red sibling arm and a passing `no-write-userHome` drop
// arm — which is what all 115 repaired records look like. The narrowing log is the same log with a
// clear census, which is what the 132 records `stale-adjudication --scan` calls STALE look like.
//
//   node --test harness/v2/rerecord.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  REFUSED, REPAIRED_FIELDS, UNCHANGED, WIDENED, fieldDiff, rerecord, rerecordRecordDir,
} from './rerecord.mjs';
import { CURRENT, replay } from './stale-adjudication.mjs';
import { parseDriverLog } from './record.mjs';

const CAPTURE = { roots: { home: '/home/runner', jailHome: '/home/runner/v2-x/jailhome' } };

// The driver log every one of the 115 has: a descent that names `no-write-userHome`, a red sibling
// arm on `network`, and — the term epoch 70 added — a census attributing real writes to the user's
// REAL home. `artifact-gate.mjs` never walks outside the package dir, so the drop arm passed with the
// product missing.
const lines = ({ writes = ['    userHome    629'] } = {}) => [
  '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":0,"reasons":["gate-vacuous"],"declaresInstallWork":true}',
  '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
  '  == WRITES ==',
  ...writes,
  '  == READS ==',
  '    deps          1',
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  '    {"write":{"project":true,"userHome":true},"network":true}',
  '  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true},"network":true}',
  '  => MINIMUM {"write":{"project":true,"userHome":true},"network":true}   (observed, then verified)',
  '  VERIFY[nar-no-network] rc=1 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true}}',
  "     'no-network' is NECESSARY — dropping it fails to verify",
  '  VERIFY[nar-no-write-userHome] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true},"network":true}',
  '  => OVER-PREDICTED by: no-write-userHome  (synthesized {"write":{"project":true,"userHome":true},"network":true}; each named capability drops on its own)',
];
const WIDEN_LOG = lines().join('\n');
// The same log with the home census CLEAR — so today's rule really does narrow, and the repair must
// refuse it. This is the shape of the 132 STALE records.
const NARROW_LOG = lines({ writes: ['    jailTmp       3'] }).join('\n');

/** A committed record in the state the 115 are in: the DESCENDED (too narrow) grant, `grantSource:
 *  "descended"`, and none of the epoch-58+ evidence fields, which did not exist when it was written.
 *  Fields the repair must preserve untouched are included deliberately. */
const committedRec = (over = {}) => ({
  pkg: 'demo-under', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM',
  grant: { write: { project: true }, network: true },
  synthesized: { write: { project: true, userHome: true }, network: true },
  verifiedBy: 'observed', minimality: 'OVER-PREDICTED', overPredictedBy: ['no-write-userHome'],
  grantSource: 'descended',
  grantSourceReason: '1 capability was dropped and each drop arm verified on its own',
  descendedGrant: { write: { project: true }, network: true },
  notes: [],
  eventLog: { events: 41022, dropped: 0 },
  driverRc: 0, durationMs: 91234,
  provenance: { platform: 'linux-x64', venue: 'ci', node: 'v22.15.0' },
  ...over,
});

// ── the widening arm fires ────────────────────────────────────────────────────────────────────────

test('⭑ a committed UNDER-GRANT is repaired from its own archived log', () => {
  // ⛔ THE MEASURED CASE. `ibm_db@2.8.2` (win32) attributed 3337 real-home writes against a committed
  // grant of `{"network":true}` — no write scope at all. The drop arm passed because the artifact
  // gate cannot see a home write, so the grant narrowed off an arm that proved nothing.
  const r = rerecord({ committed: committedRec(), log: WIDEN_LOG, capture: CAPTURE });
  assert.equal(r.verdict, WIDENED, r.reason);
  // ⛔ ONE CAPABILITY, TWO TOKENS. `write` implies read at its own scope, and the parser REJECTS a
  // grant that spells the implied half out, so `capsOf` materialises `read.userHome` rather than
  // reading it off the text. Taking the home write adds both; it is not a second capability.
  assert.deepEqual(r.widened, ['write.userHome', 'read.userHome']);
  assert.deepEqual(r.rewritten.grant, { write: { project: true, userHome: true }, network: true });
  // The grant never travels without the recorder's own account of why it is what it is.
  assert.equal(r.rewritten.grantSource, 'synthesized');
  assert.match(r.rewritten.grantSourceReason, /OBSERVE attributed 629 write\(s\) to the REAL home/);
  assert.ok(r.rewritten.notes.includes('home-write-attributed'));
});

test('⭑ the repair touches the four fields it is about and NOTHING else', () => {
  // ⛔ `record.mjs`'s `rec` IS AN EXPLICIT WHITELIST, and a field missing from it is computed and then
  // thrown away — `confinedWide` shipped in that state, so the arm adjudicating the write axis of a
  // `write:"disk"` record left no trace in the corpus. A rewrite that rebuilt the record instead of
  // patching it would reproduce that loss against the archive, where nothing re-reads it.
  const committed = committedRec();
  const r = rerecord({ committed, log: WIDEN_LOG, capture: CAPTURE });
  assert.deepEqual(r.touched.slice().sort(), REPAIRED_FIELDS.slice().sort());
  assert.deepEqual(fieldDiff(committed, r.rewritten).slice().sort(), REPAIRED_FIELDS.slice().sort());
  // Key SET and key ORDER both, because the committed files round-trip byte-for-byte through the
  // recorder's serialization and a reordered key would hide the repair inside a whole-file diff.
  assert.deepEqual(Object.keys(r.rewritten), Object.keys(committed));
  for (const k of Object.keys(committed)) {
    if (REPAIRED_FIELDS.includes(k)) continue;
    assert.deepEqual(r.rewritten[k], committed[k], `${k} was not preserved`);
  }
  // And the fields today's recorder emits that this archive predates are NOT backfilled: they are
  // provenance about the ORIGINAL measurement's evidence, and writing them would make the record
  // claim a recorder generation it was not produced by.
  for (const k of ['falsifiabilityReasons', 'descentRedArm', 'denialWitness', 'observedEffect']) {
    assert.ok(!(k in r.rewritten), `${k} was backfilled into an archived record`);
  }
});

// ── the widening arm refuses ──────────────────────────────────────────────────────────────────────

test('⭑ a replay that NARROWS the committed grant is refused, which is the whole law', () => {
  // ⛔ MEASURED: this gate fires on the 132 records `stale-adjudication --scan` reports STALE at
  // `2e2a672db`. Those narrowings may well be correct — but a narrowing is scored by
  // `publish-guard.decide()` against a descent that ran, never applied offline by a repair tool.
  // Narrowing a committed grant with no arm re-run is precisely the under-grant being repaired.
  const committed = committedRec({ grant: { write: { project: true, userHome: true }, network: true } });
  // The control: this same pair IS a narrowing that stale-adjudication publishes, so the refusal
  // below is this module's own and not an artefact of a log nothing can read.
  assert.equal(replay({ committed, log: NARROW_LOG, capture: CAPTURE }).verdict, 'STALE');
  const r = rerecord({ committed, log: NARROW_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /may only ever WIDEN/);
  assert.match(r.reason, /would DROP write\.userHome/);
  assert.equal(r.rewritten, undefined, 'a refused record must not carry a rewrite');
});

test('⭑ a non-repaired field that the archive already answers differently is refused, not patched', () => {
  // The waiver is for a field the archive does not carry at all — it predates the field, and the
  // repair leaves it as it found it. A field that IS present and DISAGREES means the log is being
  // read differently on something this repair does not claim to fix.
  const committed = committedRec({ denialWitness: { 'no-write-userHome': 'WITNESSED' } });
  assert.deepEqual(parseDriverLog(WIDEN_LOG).denialWitness ?? {}, {}, 'the fixture must actually disagree');
  const r = rerecord({ committed, log: WIDEN_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /also changes denialWitness/);
});

test('a log today\'s parser reads differently is refused before any repair', () => {
  // ⛔ G1 IN `stale-adjudication.mjs`. If the parser does not reproduce the committed `verdict` /
  // `minimality` / `overPredictedBy` / `synthesized` / `writePaths`, the grant delta is not
  // attributable to the RULE, and a repair justified by "the rule changed" has no standing.
  // 25 committed records are in this state.
  const r = rerecord({ committed: committedRec({ minimality: 'UNPROVEN' }), log: WIDEN_LOG, capture: CAPTURE });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /before a record could be built/);
  assert.match(r.reason, /parse-drift on minimality/);
});

// ── the no-op ─────────────────────────────────────────────────────────────────────────────────────

test('⭑ a record the current rule already agrees with is left alone', () => {
  const committed = committedRec({
    grant: { write: { project: true, userHome: true }, network: true },
    grantSource: 'synthesized', notes: ['home-write-attributed'],
    grantSourceReason: parseDriverLog(WIDEN_LOG).grantSourceReason,
  });
  const r = rerecord({ committed, log: WIDEN_LOG, capture: CAPTURE });
  assert.equal(r.verdict, UNCHANGED, r.reason);
  assert.equal(r.rewritten, undefined, 'an agreeing record must not be rewritten');
});

// ── on disk ───────────────────────────────────────────────────────────────────────────────────────

const layDown = (rec, log) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rerecord-'));
  fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, 'driver.out'), log);
  fs.writeFileSync(path.join(dir, 'capture.json'), JSON.stringify(CAPTURE));
  return dir;
};

test('⭑ an applied repair round-trips: re-reading it is a no-op and the replay now agrees', () => {
  const dir = layDown(committedRec(), WIDEN_LOG);
  const before = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  const first = rerecordRecordDir(dir, { apply: true });
  assert.equal(first.verdict, WIDENED, first.reason);
  assert.equal(first.applied, true);

  const after = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  assert.notEqual(after, before, 'apply wrote nothing');
  // Byte-identical to the recorder's own serialization, so the on-disk diff is the repair alone.
  assert.equal(after, `${JSON.stringify(JSON.parse(after), null, 2)}\n`);

  // Idempotent: running the repair again finds nothing to do and does not touch the file.
  const second = rerecordRecordDir(dir, { apply: true });
  assert.equal(second.verdict, UNCHANGED, second.reason);
  assert.equal(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'), after);

  // ⛔ AND THE INSTRUMENT THAT FOUND THE DEFECT NOW REPORTS IT CLEAN. `--scan`'s `underGranted` tally
  // counts exactly this: a CURRENT verdict carrying a non-empty `widens`.
  const r = replay({ committed: JSON.parse(after), log: WIDEN_LOG, capture: CAPTURE });
  assert.equal(r.verdict, CURRENT);
  assert.deepEqual(r.widens, [], 'the repaired record still reads as an under-grant');

  // The three fields `collate.mjs` keys on survive the rewrite.
  const rec = JSON.parse(after);
  assert.equal(rec.verdict, 'MINIMUM');
  assert.equal(rec.provenance.platform, 'linux-x64');
  assert.deepEqual(rec.grant, { write: { project: true, userHome: true }, network: true });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a dry run writes nothing', () => {
  const dir = layDown(committedRec(), WIDEN_LOG);
  const before = fs.readFileSync(path.join(dir, 'results.json'), 'utf8');
  const r = rerecordRecordDir(dir);
  assert.equal(r.verdict, WIDENED, r.reason);
  assert.equal(r.applied, false);
  assert.equal(fs.readFileSync(path.join(dir, 'results.json'), 'utf8'), before);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('⭑ a results.json the recorder\'s serialization does not reproduce is refused, not reformatted', () => {
  // Reformatting an archive would bury the four-field repair inside a whole-file diff, and a reviewer
  // reading that diff has no way to see what actually changed.
  const dir = layDown(committedRec(), WIDEN_LOG);
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(committedRec()));
  const r = rerecordRecordDir(dir, { apply: true });
  assert.equal(r.verdict, REFUSED);
  assert.match(r.reason, /does not round-trip/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── the diff helper ───────────────────────────────────────────────────────────────────────────────

test('the field diff sees a key ADDED or REMOVED, not only a value changed', () => {
  // ⛔ A `for (const k of Object.keys(a))` LOOP MISSES A KEY THE OTHER SIDE ADDED, and it is the
  // direction that loses a field — the one failure this whole module is built to make impossible.
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 1 }), []);
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 2 }), ['a']);
  assert.deepEqual(fieldDiff({ a: 1 }, { a: 1, b: 2 }), ['b']);
  assert.deepEqual(fieldDiff({ a: 1, b: 2 }, { a: 1 }), ['b']);
  // ⛔ AND A KEY PRESENT WITH `undefined` IS NOT THE SAME AS AN ABSENT ONE. `JSON.stringify` erases
  // the difference; the archive's whole "this record predates the field" waiver turns on it.
  assert.deepEqual(fieldDiff({ a: undefined }, {}), ['a']);
});
