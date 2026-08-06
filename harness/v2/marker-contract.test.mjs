// THE BIDIRECTIONAL MARKER CONTRACT: every marker a driver EMITS has a parser, and every marker
// `record.mjs` PARSES is emitted by at least one driver.
//
// ⛔ WHY THIS EXISTS AS ONE SHARED GUARD RATHER THAN THREE PER-LANE ONES. The drivers communicate
// with `record.mjs` through a vocabulary of stdout markers, and nothing has ever checked that the two
// sides agree on it. Three separate half-wired markers were found BY ACCIDENT on a single day, each
// having silently degraded records in the meantime:
//
//   1. `record.mjs` keyed on `events LOST`, which only the WINDOWS driver emits — so macOS and Linux
//      event loss was never noted, and two darwin records that dropped an event shipped `notes: []`.
//   2. Linux emitted `VENUE-PERMISSIONS` for R7 while Windows emitted `VENUE-OBSERVE-USER` for the
//      same fact. One parser, two spellings, so the Linux assertion was invisible in every record.
//   3. `=> MINIMAL` was parsed but never emitted by the macOS driver, so its strongest descent result
//      filed as `null`.
//
// Each of those is the SAME defect class, and each was cheap to prevent and expensive to find. A new
// marker can no longer land half-wired, and a renamed one now fails loudly instead of going quiet.
//
// ⛔ THE EXTRACTORS ARE VALIDATED AGAINST KNOWN CASES BEFORE ANY CONTRACT ASSERTION RUNS. A regex
// that silently matches nothing would turn this whole file into a vacuous pass — which is precisely
// the failure it exists to catch, one level up. The `INSTRUMENT` tests below are that check, and
// they are why the assertions underneath can be trusted.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

// The drivers, by the name a failure should print. Each is the one file its platform runs.
const DRIVERS = {
  linux: 'measure.sh',
  macos: 'measure-macos.sh',
  windows: 'measure-windows.mjs',
};

// ⛔ SCOPED TO THE MARKER FAMILIES, NOT TO EVERY UPPERCASE TOKEN. These files are dense with
// hyphenated uppercase prose in comments (`LEAVE-ONE-OUT`, `OBSERVE/VERIFY`, `BROKEN-WITHOUT-JAIL-TOO`
// as narrative), and a token-shaped regex would harvest those as markers and produce a confident,
// entirely fictional contract. The families below are the ones `record.mjs` turns into FIELDS, which
// is exactly the set where a mismatch silently costs a record something.
const FAMILIES = /^(VENUE|RAWLOG|EVENTLOG)-[A-Z0-9-]+$/;

/**
 * Markers a file EMITS, taken from emission sites only — `echo "  MARKER …"` (shell) and
 * ``console.log(`  MARKER …`)`` (node). Keying on the emission form rather than on any occurrence is
 * what keeps a marker NAMED IN A COMMENT from counting as emitted.
 */
const emitted = (src) => {
  const found = new Set();
  for (const m of src.matchAll(/(?:echo|console\.log)\s*\(?\s*["'`]\s{2}([A-Z][A-Z0-9-]*)\b/g)) {
    if (FAMILIES.test(m[1])) found.add(m[1]);
  }
  return found;
};

/** Markers `record.mjs` PARSES, taken from the regex literals it matches lines against. */
const parsed = (src) => {
  const found = new Set();
  for (const m of src.matchAll(/\/\\?\^?([A-Z][A-Z0-9-]*)\\s\+/g)) if (FAMILIES.test(m[1])) found.add(m[1]);
  for (const m of src.matchAll(/\/([A-Z][A-Z0-9-]*)\\s\*/g)) if (FAMILIES.test(m[1])) found.add(m[1]);
  return found;
};

const RECORD = read('record.mjs');
const PARSED = parsed(RECORD);
const EMITTED = Object.fromEntries(Object.entries(DRIVERS).map(([k, f]) => [k, emitted(read(f))]));
const ALL_EMITTED = new Set(Object.values(EMITTED).flatMap((s) => [...s]));

// ── INSTRUMENT CHECKS — these run first and everything below is worthless without them ────────────

test('INSTRUMENT: the parse extractor finds markers record.mjs is known to handle', () => {
  // If this ever returns an empty set, every contract assertion below passes vacuously.
  assert.ok(PARSED.size >= 4, `the parse extractor found only ${PARSED.size} markers — it is broken:\n${[...PARSED]}`);
  for (const known of ['VENUE-STORE-LAYOUT', 'VENUE-INTERPRETER', 'VENUE-OVERRIDES', 'RAWLOG-FILE']) {
    assert.ok(PARSED.has(known), `the parse extractor missed the known marker ${known}:\n${[...PARSED]}`);
  }
});

test('INSTRUMENT: the emit extractor finds markers each driver is known to emit', () => {
  for (const [platform, set] of Object.entries(EMITTED)) {
    assert.ok(set.size > 0, `the emit extractor found nothing in ${DRIVERS[platform]} — it is broken`);
  }
  assert.ok(EMITTED.linux.has('VENUE-STORE-LAYOUT'), 'the emit extractor missed a known Linux marker');
  assert.ok(EMITTED.windows.has('VENUE-OBSERVE-USER'), 'the emit extractor missed a known Windows marker');
});

test('INSTRUMENT: a marker mentioned only in a COMMENT does not count as emitted', () => {
  // The negative control for the emit extractor. Without it, "every parsed marker is emitted" could
  // be satisfied by a marker that appears only in prose, which is exactly a half-wired marker.
  assert.equal(emitted('# see VENUE-STORE-LAYOUT for why\n// VENUE-INTERPRETER is parsed\n').size, 0,
    'the emit extractor counts comments as emissions, so it cannot detect an unemitted marker');
  assert.ok(emitted('echo "  VENUE-STORE-LAYOUT isolated"').has('VENUE-STORE-LAYOUT'),
    'the emit extractor misses a real emission — it is too strict to be trusted either');
});

// ── THE CONTRACT, BOTH DIRECTIONS ─────────────────────────────────────────────────────────────────

// ⛔ LOG-ONLY BY DELIBERATE DECISION, AND ADDING TO THIS LIST IS A CONSCIOUS ACT, NOT A WAY TO GET
// GREEN. An entry here asserts that a human decided the marker belongs in the driver log and NOT in
// the record; the reason is required, because an undocumented allowlist is just the half-wired state
// with a rubber stamp on it. The guard's whole value is that the default answer is "wire it up".
const LOG_ONLY = new Map([
  ['RAWLOG-BYTES',
   'Raw and gzipped sizes of the retained trace. `rawLogPath` is already recorded and the record ' +
   'stores the archive itself, so both numbers are recoverable by stat-ing the file — this line ' +
   'exists so a human reading a driver log can see the archive is non-trivial without fetching it.'],
]);

test('every marker a driver EMITS is parsed by record.mjs', () => {
  // Defect 2's direction: Linux emitted VENUE-PERMISSIONS, record.mjs parsed VENUE-OBSERVE-USER, so
  // the R7 assertion was invisible in every Linux record.
  const orphans = [];
  for (const [platform, set] of Object.entries(EMITTED)) {
    for (const m of set) {
      if (PARSED.has(m) || LOG_ONLY.has(m)) continue;
      orphans.push(`${m} (emitted by ${DRIVERS[platform]}, parsed by nothing)`);
    }
  }
  assert.deepEqual(orphans, [], `markers emitted into the void — a record silently loses each one:\n  ${orphans.join('\n  ')}`);
});

test('every marker record.mjs PARSES is emitted by at least one driver', () => {
  // Defect 3's direction: a parser for a spelling no driver produces is a field that is always null,
  // and it reads as "the driver did not measure this" rather than as "nobody wired it up".
  const dead = [...PARSED].filter((m) => !ALL_EMITTED.has(m));
  assert.deepEqual(dead, [], `record.mjs parses markers no driver emits, so these fields can never fill:\n  ${dead.join('\n  ')}`);
});

test('the R7 marker is the SAME spelling on every platform that asserts it', () => {
  // Pinned by name because this is the one that already diverged, and because "each lane guards its
  // own spelling" is what produced the divergence. Windows is canonical: it had the parser first.
  const asserting = Object.entries(EMITTED).filter(([, s]) => [...s].some((m) => /OBSERVE-USER|PERMISSION/.test(m)));
  assert.ok(asserting.length > 0, 'no driver emits an R7 marker at all');
  for (const [platform, set] of asserting) {
    assert.ok(set.has('VENUE-OBSERVE-USER'),
      `${DRIVERS[platform]} spells the R7 marker differently from Windows — one fact needs one name:\n${[...set]}`);
  }
});

test('every LOG_ONLY exemption is real, reasoned, and still emitted', () => {
  // Keeps the allowlist from silently becoming a graveyard: an entry for a marker no driver emits any
  // more is a stale exemption that would mask a genuine orphan sharing its name later.
  for (const [m, why] of LOG_ONLY) {
    assert.ok(ALL_EMITTED.has(m), `LOG_ONLY names ${m}, which no driver emits — delete the exemption`);
    assert.ok(!PARSED.has(m), `LOG_ONLY names ${m}, but record.mjs parses it — delete the exemption`);
    assert.ok(why && why.length > 60, `the LOG_ONLY exemption for ${m} has no real reason recorded`);
  }
});
