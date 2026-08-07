// Golden cases for the two provenance emissions in `measure.sh` that `record.mjs` turns into
// record FIELDS — `VENUE-STORE-LAYOUT`, `VENUE-INTERPRETER` and `VENUE-OVERRIDES`.
//
// ⛔ THESE TESTS REPLAY THE REAL SHELL, EXTRACTED FROM `measure.sh` AT RUN TIME. A hand-copied
// transcription of the block would pass forever while the shipped driver rotted beside it — which is
// precisely the failure mode being tested here, since both defects below were INVISIBLE in the
// record and cost a whole package's field each. Extraction means an edit to the driver is an edit to
// what these tests run. Each extractor therefore asserts it actually FOUND its block: a regex that
// silently matches nothing would turn every case below into a vacuous pass.
//
// Why a shell replay rather than a full `measure.sh` run: the driver does an unjailed npm install, a
// traced rebuild and a jail ladder per package. The decidable logic here is a dozen lines of `[ -d ]`
// and `echo`, and it is reachable in milliseconds by running those lines over fixture directories —
// which is also exactly how the reviewer reproduced the store-layout defect.

import { test, test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ⛔ SKIPPED ON WINDOWS — BUT ONLY THE CASES THAT REPLAY THE SHELL, NOT THE FILE. Every case below
// that drives an extracted `measure.sh` block runs it through `bash`, and MEASURED on the corpus
// Windows VM there is no bash at all: `where bash` finds nothing and Git-for-Windows is absent, so
// they die `spawnSync bash ENOENT` — a failure that says nothing about the provenance emissions.
//
// ⛔ THE TWO INSTRUMENT CHECKS ARE DELIBERATELY NOT SKIPPED. They assert the extractors actually
// FOUND their block in `measure.sh`, which is pure text and passes on Windows today. They are also
// the checks that stop a drifted anchor from turning every case here into a test of the empty
// string, so a file-level skip would disarm the anti-vacuity guard on one platform and leave it
// armed on the others — the asymmetry this file exists to prevent.
//
// ⛔ A SKIP IS NOT A PASS, so it is spelled as one and carries its reason into the TAP output.
const SHELL_SKIP = process.platform === 'win32'
  ? 'no bash on Windows: this case replays a block extracted from measure.sh'
  : false;
const shellTest = (name, fn) => nodeTest(name, { skip: SHELL_SKIP }, fn);

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8').split('\n');

/**
 * Slice `measure.sh` between the first line matching `from` and the next line matching `to`.
 * Throws rather than returning an empty block, so a drifted anchor fails the suite LOUDLY instead of
 * turning the assertions that follow into a test of the empty string.
 */
const slice = (from, to, label) => {
  const i = SRC.findIndex((l) => from.test(l));
  assert.notEqual(i, -1, `ANCHOR DRIFT: no line of measure.sh matches ${from} (${label})`);
  const j = SRC.slice(i).findIndex((l) => to.test(l));
  assert.notEqual(j, -1, `ANCHOR DRIFT: no closing line matches ${to} after line ${i} (${label})`);
  return SRC.slice(i, i + j + 1).join('\n');
};

const sh = (script, env = {}) =>
  execFileSync('bash', ['-c', script], { encoding: 'utf8', env: { ...process.env, ...env } });

const tmp = (label) => fs.mkdtempSync(path.join(os.tmpdir(), `mprov-${label}-`));

// ── VENUE-STORE-LAYOUT — the latch that silenced a whole package ────────────────────────────────
//
// The defect: `STORE_LAYOUT_REPORTED=1` sat AFTER the inner `if/elif` rather than inside its
// branches. An arm with no `node_modules` — a failed install, the normal shape of a descent ladder's
// first rung — matched neither branch, emitted nothing, and latched anyway. Every later arm was then
// skipped and `record.mjs` wrote `storeLayout: null` for the package even though a later arm had the
// answer sitting on disk.

const LAYOUT_BLOCK = slice(
  /^\s*if \[ -z "\$\{STORE_LAYOUT_REPORTED/,
  /^\s{2}fi\s*$/,
  'store-layout emission',
);

/** Replay the real block over `arms` in ONE shell, so the latch behaves as it does across arms. */
const replayLayout = (arms) => {
  const script = `set -u\nfor v in ${arms.map((a) => `'${a}'`).join(' ')}; do\n${LAYOUT_BLOCK}\ndone\n`;
  return sh(script);
};

const armWith = (label, kind) => {
  const d = tmp(label);
  if (kind === 'isolated') fs.mkdirSync(path.join(d, 'node_modules', '.store'), { recursive: true });
  if (kind === 'hoisted') fs.mkdirSync(path.join(d, 'node_modules'), { recursive: true });
  return d; // 'none' => a failed install: no node_modules at all
};

test('the extracted store-layout block is the real one — the instrument check', () => {
  assert.match(LAYOUT_BLOCK, /VENUE-STORE-LAYOUT isolated/, `extraction missed the block:\n${LAYOUT_BLOCK}`);
  assert.match(LAYOUT_BLOCK, /VENUE-STORE-LAYOUT hoisted/, `extraction missed the block:\n${LAYOUT_BLOCK}`);
});

shellTest('POSITIVE CONTROL: a single arm with a store reports the layout', () => {
  const out = replayLayout([armWith('ctl', 'isolated')]);
  assert.match(out, /VENUE-STORE-LAYOUT isolated/, `the block must report at all:\n${out}`);
});

shellTest('⛔ an arm with NO node_modules does not latch — a later arm still reports the layout', () => {
  // The reviewer's reproduction, verbatim in shape: a failed first arm followed by a good one.
  const out = replayLayout([armWith('fail', 'none'), armWith('good', 'isolated')]);
  assert.match(
    out,
    /VENUE-STORE-LAYOUT isolated/,
    `a failed first arm swallowed the layout for the whole package — this is the defect:\n${out}`,
  );
});

shellTest('the marker is still emitted exactly ONCE across many arms — the latch still latches', () => {
  // Without this, "move the latch inside the branches" could be satisfied by deleting the latch,
  // which would emit a line per arm and let a later arm contradict an earlier one.
  const out = replayLayout([armWith('a', 'isolated'), armWith('b', 'isolated'), armWith('c', 'isolated')]);
  assert.equal(
    out.match(/VENUE-STORE-LAYOUT/g)?.length,
    1,
    `the layout must be reported once, not once per arm:\n${out}`,
  );
});

shellTest('a hoisted tree reports hoisted, and a run of failed arms before it changes nothing', () => {
  const out = replayLayout([armWith('f1', 'none'), armWith('f2', 'none'), armWith('h', 'hoisted')]);
  assert.match(out, /VENUE-STORE-LAYOUT hoisted/, `hoisted must be reachable after failed arms:\n${out}`);
  assert.doesNotMatch(out, /isolated/, `a hoisted tree must not report isolated:\n${out}`);
});

shellTest('all-failed arms report NO layout rather than guessing one', () => {
  // The honest outcome when nothing on disk answers the question. `storeLayout: null` is correct
  // HERE; the defect was reaching it while an arm still held the answer.
  const out = replayLayout([armWith('n1', 'none'), armWith('n2', 'none')]);
  assert.doesNotMatch(out, /VENUE-STORE-LAYOUT/, `an unanswerable layout must not be invented:\n${out}`);
});

// ── VENUE-INTERPRETER / VENUE-OVERRIDES — provenance coupled to an unrelated artifact ───────────
//
// The defect: both markers were echoed INSIDE the `[ -s trace.txt.gz ] && [ -s $CAPTURE ]` retention
// block. That block is about whether the ARCHIVE survived; these markers are about the RUN. A gzip
// failure or a zero-byte `capture.json` therefore stripped `interpreterPath`,
// `interpreterInsideHome` and the whole `overrides` object from an otherwise-good record — and
// `overrides: null` reads as "nothing was overridden", not as "the answer was lost".

const RETENTION_BLOCK = slice(
  /^gzip -9 -c /,
  // ⛔ Matches the CLOSE of the `node -e` invocation rather than its last ARGUMENT. Anchoring on a
  // specific variable name broke the moment the CI-scrub work added two arguments — the guard caught
  // it loudly, which is the point, but an anchor that survives an argument change is better.
  /^' .*2>\/dev\/null\)"$/,
  'retention + venue provenance',
);

/** Replay the retention region with a fixture OBSERVE dir. `traceBody: null` => no trace at all. */
const replayRetention = ({ traceBody = 'line\n', captureBody = '{"v":1}' }) => {
  const obs = tmp('ret');
  if (traceBody !== null) fs.writeFileSync(path.join(obs, 'trace.txt'), traceBody);
  const capture = path.join(obs, 'capture.json');
  fs.writeFileSync(capture, captureBody);
  const script = [
    'set -u',
    `OBS='${obs}'`,
    `CAPTURE='${capture}'`,
    "INTERPRETER='/opt/nodejs'",
    `JAIL_HOME='${obs}/jailhome'`,
    `JAIL_TMP='${obs}/jailtmp'`,
    `JAIL_TOOLS='${obs}/tools'`,
    `NUB_CACHE_DIR='${obs}/nubcache'`,
    // Set by the CI-detection scrub, which runs earlier in the driver than this region.
    "CI_SCRUBBED=''",
    "CI_INHERITED=''",
    RETENTION_BLOCK,
  ].join('\n');
  return sh(script);
};

test('the extracted retention block is the real one — the instrument check', () => {
  assert.match(RETENTION_BLOCK, /VENUE-INTERPRETER/, `extraction missed the markers:\n${RETENTION_BLOCK}`);
  assert.match(RETENTION_BLOCK, /VENUE-OVERRIDES/, `extraction missed the markers:\n${RETENTION_BLOCK}`);
  assert.match(RETENTION_BLOCK, /RAW TRACE NOT RETAINED/, 'extraction missed the failure arm');
});

shellTest('POSITIVE CONTROL: a good archive emits the archive lines AND the venue provenance', () => {
  const out = replayRetention({});
  assert.match(out, /RAWLOG-FILE /, `a good archive must be retained:\n${out}`);
  assert.match(out, /VENUE-INTERPRETER \/opt\/nodejs/, `provenance must be emitted:\n${out}`);
  assert.match(out, /VENUE-OVERRIDES \{/, `overrides must be emitted:\n${out}`);
});

shellTest('⛔ a lost archive does NOT strip the venue provenance — they are independent facts', () => {
  // No `trace.txt`, so `gzip` writes an empty `.gz` and the retention predicate is false. That is a
  // real and reported loss of the ARCHIVE; it must cost nothing else.
  const out = replayRetention({ traceBody: null });
  assert.match(out, /RAW TRACE NOT RETAINED/, `precondition: the archive must actually be lost:\n${out}`);
  assert.match(out, /VENUE-INTERPRETER \/opt\/nodejs/, `a gzip failure stripped interpreterPath:\n${out}`);
  assert.match(out, /VENUE-OVERRIDES \{/, `a gzip failure stripped the whole overrides object:\n${out}`);
});

shellTest('⛔ a zero-byte capture.json does NOT strip the venue provenance either', () => {
  const out = replayRetention({ captureBody: '' });
  assert.match(out, /RAW TRACE NOT RETAINED/, `precondition: retention must actually fail:\n${out}`);
  assert.match(out, /VENUE-INTERPRETER \/opt\/nodejs/, `an empty capture stripped interpreterPath:\n${out}`);
  assert.match(out, /VENUE-OVERRIDES \{/, `an empty capture stripped the overrides object:\n${out}`);
});

shellTest('the emitted overrides are parseable JSON naming the variables the driver set', () => {
  // `record.mjs` does `JSON.parse` on this line and files `overrides-unparsable` when it throws, so a
  // malformed emission degrades silently into a note. Pin the shape here instead.
  const out = replayRetention({ traceBody: null });
  const json = /VENUE-OVERRIDES (\{.*)/.exec(out);
  assert.ok(json, `no overrides line to parse:\n${out}`);
  const o = JSON.parse(json[1]);
  assert.ok(o.set.HOME, 'the redirected HOME must be recorded');
  assert.ok(o.set.TMPDIR, 'the redirected TMPDIR must be recorded');
  assert.equal(o.set.NODE_COMPAT, '1');
  assert.ok('CI' in o.passedThrough, '`CI` must be recorded as passed through, not omitted');
});
