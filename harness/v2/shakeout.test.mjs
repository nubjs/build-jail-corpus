// The shakeout evaluator's own controls.
//
// ⛔ WHY THIS FILE EXISTS. `shakeout.mjs` decides whether a round of the randomized sweep is CLEAN.
// If a tripwire cannot fire, every round it judges reports clean and the whole phase becomes a
// progress bar that measures nothing. Four separate vacuous checks were shipped in this repo before
// anyone thought to break the thing a check guards, so each tripwire below is driven against a
// record engineered to trip it AND a record engineered not to.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TRIPWIRES, recordPath } from './shakeout.mjs';

// ⛔ THE SCOPED-SPEC CASE, which the first version of the reader got wrong and which cost a whole
// shakeout round its verdict: it reported 4 of 10 specs "not measured" while the batch had recorded
// all 10. A reader that under-finds records turns a DIRTY round into an INCOMPLETE one.
test('⭑ a scoped spec resolves to the `@scope+name/version` record path, not `@scope/name/version`', () => {
  assert.deepEqual(recordPath('@sitespeed.io/chromedriver@84.0.4147-30'),
    ['@sitespeed.io+chromedriver', '84.0.4147-30']);
  assert.deepEqual(recordPath('taiko@0.8.0'), ['taiko', '0.8.0']);
  // a prerelease version carries its own `-`, and the SPLIT is on the LAST `@`
  assert.deepEqual(recordPath('@fission-ai/openspec@1.6.0'), ['@fission-ai+openspec', '1.6.0']);
  assert.deepEqual(recordPath('foo@0.0.1-dev.1556840842'), ['foo', '0.0.1-dev.1556840842']);
});

// A record that SHOULD trip nothing: narrow grant, attributable, verified by synthesis.
const CLEAN = {
  verdict: 'MINIMUM',
  grant: { write: { project: true }, network: true },
  grantSource: 'descended',
  verifiedBy: 'synthesized',
  driverRc: 0,
  provenance: { nubGitSha: '20c069588', venue: 'vm' },
};

test('CONTROL: a clean record trips NOTHING — otherwise every round reads dirty and the signal is gone', () => {
  const fired = Object.entries(TRIPWIRES).filter(([, fn]) => fn(CLEAN)).map(([n]) => n);
  assert.deepEqual(fired, [], `these fired on a deliberately clean record: ${fired.join(', ')}`);
});

// Each entry: the ONE field change that should trip exactly that tripwire.
const DIRTY = {
  T1_harness: { verdict: 'HARNESS-TIMEOUT' },
  T2_disk: { grant: { write: 'disk', network: true } },
  T3_noState: { verdict: 'NO-STATE-PASSED' },
  T4_ladder: { verifiedBy: 'ladder' },
  T5_provenance: { provenance: { nubGitSha: null, venue: 'vm' } }, // no sha256 either -> unattributable
  T6_truncated: { grantSource: 'descended-incomplete' },
  T7_rc: { driverRc: 3221225477 },
};

for (const [name, patch] of Object.entries(DIRTY)) {
  test(`⭑ ${name} FIRES on a record built to trip it`, () => {
    const rec = { ...CLEAN, ...patch };
    const why = TRIPWIRES[name](rec);
    assert.ok(why, `${name} did not fire on ${JSON.stringify(patch)} — it cannot detect what it exists to detect`);
    // …and it must not fire on the clean record, or it is an alarm stuck on rather than a detector.
    assert.equal(TRIPWIRES[name](CLEAN), null, `${name} also fires on the clean record`);
  });
}

test('⭑ read:"disk" trips T2 as well as write:"disk" — both are the disabled-confinement case', () => {
  assert.ok(TRIPWIRES.T2_disk({ ...CLEAN, grant: { read: 'disk' } }));
});

// ⛔ THE CASE THAT MADE T5 A FALSE POSITIVE IN SHAKEOUT ROUND 1. Linux records carry a null
// `nubGitSha` (the binary is copied onto the box, so there is no checkout to ask) but a full
// `nubBinary.sha256`. The first T5 demanded the git sha and flagged 6 of 10 healthy records.
test('⭑ a binary sha256 IS attribution — T5 must not demand the git sha when the hash is present', () => {
  const byHash = { ...CLEAN, provenance: { nubGitSha: null, venue: 'vm', nubBinary: { sha256: '0698559949ffbc' } } };
  assert.equal(TRIPWIRES.T5_provenance(byHash), null,
    'a record naming the exact bytes that ran is attributable, however the git sha is spelled');
});

test('T5 still fires when NEITHER identifier is present, and says so distinctly from the venue case', () => {
  const noId = { ...CLEAN, provenance: { nubGitSha: null, venue: 'vm' } };
  assert.match(TRIPWIRES.T5_provenance(noId), /cannot tell which binary ran/);
  const noVenue = { ...CLEAN, provenance: { nubGitSha: 'abc123', venue: 'unknown' } };
  assert.match(TRIPWIRES.T5_provenance(noVenue), /venue is unknown/);
});

test('T7 does not fire on the budget timeout, which T6 already names', () => {
  // Otherwise one truncated run reports as two independent findings and the count is inflated.
  assert.equal(TRIPWIRES.T7_rc({ ...CLEAN, driverRc: 124 }), null);
});

// ── the draw ─────────────────────────────────────────────────────────────────
const HERE = import.meta.dirname;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shakeout-'));
const queue = path.join(tmp, 'q.ndjson');
fs.writeFileSync(queue, Array.from({ length: 200 }, (_, i) =>
  JSON.stringify({ pkg: `p${i}`, version: '1.0.0', os: 'linux', status: 'pending' })).join('\n') + '\n');

const drawTo = (seed, out) => {
  execFileSync(process.execPath, [path.join(HERE, 'shakeout.mjs'), 'draw',
    '--os', 'linux', '--sets', '3', '--per-set', '4', '--seed', String(seed),
    '--queue', queue, '--out', path.join(tmp, out)], { encoding: 'utf8' });
  return JSON.parse(fs.readFileSync(path.join(tmp, out), 'utf8'));
};

test('⭑ the draw is REPRODUCIBLE from its seed — a finding you cannot re-run is not a finding', () => {
  assert.deepEqual(drawTo(42, 'a.json').set, drawTo(42, 'b.json').set);
});

test('⭑ a different seed draws a different sample — otherwise every round tests the same packages', () => {
  assert.notDeepEqual(drawTo(42, 'c.json').set, drawTo(43, 'd.json').set);
});

test('the draw partitions without repeats — a set that samples one package twice covers less than it claims', () => {
  const m = drawTo(7, 'e.json');
  const all = m.set.flat();
  assert.equal(new Set(all).size, all.length, 'a spec was drawn more than once');
  assert.equal(all.length, 12);
});

test('the draw refuses rather than silently shrinking when the pool is too small', () => {
  assert.throws(() => execFileSync(process.execPath, [path.join(HERE, 'shakeout.mjs'), 'draw',
    '--os', 'linux', '--sets', '100', '--per-set', '10', '--seed', '1',
    '--queue', queue, '--out', path.join(tmp, 'f.json')], { stdio: 'pipe' }));
});

test('the draw only considers PENDING rows for the requested OS', () => {
  const mixed = path.join(tmp, 'mixed.ndjson');
  fs.writeFileSync(mixed, [
    ...Array.from({ length: 8 }, (_, i) => ({ pkg: `keep${i}`, version: '1.0.0', os: 'linux', status: 'pending' })),
    { pkg: 'wrong-os', version: '1.0.0', os: 'windows', status: 'pending' },
    { pkg: 'already-done', version: '1.0.0', os: 'linux', status: 'done' },
  ].map((r) => JSON.stringify(r)).join('\n') + '\n');
  execFileSync(process.execPath, [path.join(HERE, 'shakeout.mjs'), 'draw',
    '--os', 'linux', '--sets', '2', '--per-set', '4', '--seed', '5',
    '--queue', mixed, '--out', path.join(tmp, 'g.json')], { encoding: 'utf8' });
  const all = JSON.parse(fs.readFileSync(path.join(tmp, 'g.json'), 'utf8')).set.flat();
  assert.ok(all.every((s) => s.startsWith('keep')), `drew a row it should have filtered out: ${all.join(' ')}`);
});

process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));
