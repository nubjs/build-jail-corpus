// A non-measurement verdict must keep its driver log, because the record does not carry the reason.
//
// What forced this: five HARNESS-ERROR records were investigated as a per-package budget problem and
// re-run at a 90-minute budget before anyone read a driver log. They were nub refusals (exit 23
// trust-policy, exit 21 age-gate) failing in 5-41 s, so a budget could never have been the cause. And
// `unicode@0.6.1` VOIDs on win32 with the reason still unknown, because both attempts deleted their
// own evidence. Asserted on source because run-batch-v2.mjs runs a whole slice at import.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const SRC = fs.readFileSync(path.join(import.meta.dirname, 'run-batch-v2.mjs'), 'utf8');

test('the retention predicate covers every verdict whose reason lives only in the log', () => {
  // Pull the literal set out of the source so the test reads what ships, not a copy of it.
  const m = /KEEP_LOG_VERDICTS = new Set\(\[([^\]]*)\]\)/.exec(SRC);
  assert.ok(m, 'KEEP_LOG_VERDICTS is gone — the retention rule has been rewritten');
  const set = m[1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  // The non-HARNESS verdicts that state no reason in the record.
  //
  // ⛔ BROKEN-WITHOUT-JAIL-TOO WAS MISSING HERE AND THIS TEST ASSERTED THE OPPOSITE. The first
  // version of this file listed it as must-NOT-retain "because the record already explains it".
  // Checked 2026-08-16 against a real record: `notes: []`, `eventLog: null`, `grantSourceReason:
  // null`, `driverRc: 0` — nothing explains anything. It is also the LARGEST failure bucket (17.8%
  // of linux records, 30.8% of win32) and the one that decides whether nub can install a package at
  // all, so it was the worst possible verdict to be discarding evidence for.
  for (const v of ['VOID', 'NO-STATE-PASSED', 'BROKEN-WITHOUT-JAIL-TOO']) {
    assert.ok(set.includes(v), `${v} must retain its driver log — its record carries no reason`);
  }
  // Every HARNESS-* verdict is covered by prefix, not enumeration, so a new one is covered on arrival.
  assert.match(SRC, /startsWith\('HARNESS-'\)/,
    'HARNESS-* must be matched by PREFIX; enumerating them means the next one silently loses its log');
});

test('a MINIMUM does NOT retain its log', () => {
  // ⛔ THE DIRECTION THAT MATTERS FOR COST. A MINIMUM's grant, minimality and provenance are all in
  // the record, so its log adds nothing — and there are ~6,100 of them against ~850 verdicts that do
  // retain. Retaining all of them would dwarf the records this corpus exists to produce.
  //
  // BROKEN-WITHOUT-JAIL-TOO is deliberately NOT in this list any more — see the test above. ~600 of
  // those is an order of magnitude under the MINIMUM figure that motivates this exclusion.
  const m = /KEEP_LOG_VERDICTS = new Set\(\[([^\]]*)\]\)/.exec(SRC);
  const set = m[1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  for (const v of ['MINIMUM', 'REFUSED-MALICIOUS']) {
    assert.ok(!set.includes(v), `${v} must NOT retain its log — the record already explains it`);
  }
  assert.match(SRC, /fs\.rmSync\(tmpLog, \{ force: true \}\)/,
    'the delete path must still exist, or every verdict retains and the tree bloats');
});

test('a record.mjs FAILURE keeps the log, because nothing else survives it', () => {
  // On `w.status !== 0` there is no results.json to read, so the log is the entire evidence — and it
  // used to be deleted one line ABOVE that branch.
  const rm = SRC.indexOf('fs.rmSync(tmpLog');
  const fail = SRC.indexOf('record.mjs rc=');
  assert.ok(rm > fail,
    'the tmpLog delete must come AFTER the record.mjs-failure branch, or a FAIL loses its only evidence');
  assert.match(SRC, /record\.mjs rc=\$\{w\.status\} \(driver log kept/,
    'the FAIL line must report the retained log path — an unreported artifact is one nobody reads');
});

test('the delete happens only after the verdict is known', () => {
  // The original bug in shape: the log was removed before results.json was read, so the code could
  // not have consulted the verdict even if it wanted to.
  const rm = SRC.indexOf('fs.rmSync(tmpLog');
  const readRec = SRC.indexOf("readFileSync(path.join(dir, 'results.json')");
  assert.ok(readRec > 0 && rm > readRec,
    'the verdict must be read BEFORE the log is deleted, or retention cannot depend on it');
});
