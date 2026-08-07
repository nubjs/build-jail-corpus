// Golden cases for the `VENUE-NUB-BINARY` emission in `measure-macos.sh` — the marker that says
// WHICH BINARY answered a darwin record.
//
// ⛔ WHY THIS FILE EXISTS. MEASURED across the corpus before the emission was added:
// `provenance.nubBinary` was present on 119/119 linux-x64 records and 0/120 darwin-arm64, because
// only `measure.sh` emitted the marker `record.mjs` learns it from — and `provenance.nubGitSha` was
// null on all 240 records besides. So every darwin record named NOTHING about the program that
// produced it, and `corpus-v2-runner.yml` was meanwhile justifying a prefix cache fallback on the
// premise that "each record names the binary that answered it".
//
// ⛔ THE ASSERTION THAT MATTERS IS THAT THE MARKER *DISCRIMINATES*, NOT THAT IT APPEARS. A marker
// that prints the same thing for every binary satisfies "the field is populated" while carrying no
// information, which is the dominant failure mode in this area. So every case below runs the
// extracted block against TWO artifacts that genuinely differ and asserts the values differ —
// checking the hash against an independent implementation, never against itself.
//
// ⛔ THE BLOCK IS EXTRACTED FROM THE SHIPPED DRIVER AT RUN TIME, as `measure-provenance.test.mjs`
// does for `measure.sh`. A hand-copied transcription would pass forever while the driver rotted
// beside it — the exact failure being guarded. The extractor asserts it FOUND the block, because a
// silently-empty slice turns every case here into a test of the empty string.
import { test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// ⛔ A SKIP IS NOT A PASS, so it carries its reason into the TAP output. These cases replay a bash
// block; MEASURED on the corpus Windows VM there is no bash at all, so they would die
// `spawnSync bash ENOENT` — a failure that says nothing about the emission.
const SHELL_SKIP = process.platform === 'win32'
  ? 'no bash on Windows: this case replays a block extracted from measure-macos.sh'
  : false;
const test = (name, fn) => nodeTest(name, { skip: SHELL_SKIP }, fn);

const HERE = import.meta.dirname;
const SRC = fs.readFileSync(path.join(HERE, 'measure-macos.sh'), 'utf8').split('\n');

/**
 * The `if [ -f "$NUB" ]` guard around the `VENUE-NUB-BINARY` emission, sliced out of the driver.
 * Throws rather than returning an empty block, so a drifted anchor fails LOUDLY instead of turning
 * every assertion below into a test of nothing.
 */
const markerBlock = () => {
  const emit = SRC.findIndex((l) => /^\s*echo "  VENUE-NUB-BINARY/.test(l));
  assert.notEqual(emit, -1, 'ANCHOR DRIFT: measure-macos.sh emits no VENUE-NUB-BINARY line');
  let open = emit;
  while (open >= 0 && !/^if \[ -f "\$NUB" \]; then$/.test(SRC[open])) open--;
  assert.notEqual(open, -1, 'ANCHOR DRIFT: no `if [ -f "$NUB" ]` guard precedes the emission');
  let close = emit;
  while (close < SRC.length && SRC[close] !== 'fi') close++;
  assert.notEqual(close, SRC.length, 'ANCHOR DRIFT: the guard around the emission is never closed');
  const block = SRC.slice(open, close + 1).join('\n');
  assert.match(block, /VENUE-NUB-BINARY/, 'the extracted block lost the marker');
  return `set -uo pipefail\n${block}\n`;
};

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'macprov-'));

/** Run the extracted block with `$NUB` set to `bin`, and return its stdout. */
const emit = (bin) =>
  execFileSync('bash', ['-c', markerBlock()], { encoding: 'utf8', env: { ...process.env, NUB: bin } });

/** The JSON payload of the marker line, or null when no marker was printed. */
const parseMarker = (out) => {
  const m = /VENUE-NUB-BINARY\s+(\{.*)/.exec(out);
  return m ? JSON.parse(m[1]) : null;
};

/**
 * Stand-in binaries that DIFFER in every field the marker reports: whether they act on
 * `NUB_BUILD_JAIL_CATALOG`, whether they contain the bytecode env constant, and their bytes.
 * Executable stubs rather than real nub builds because a test may not assume a feature-enabled nub
 * is present on the machine running it — the discrimination claim is about the EMITTER.
 *
 * ⛔ THERE ARE THREE CLASSES, NOT TWO, AND THE THIRD IS THE ONE THAT WAS MISSING. `off` REFUSES the
 * variable (built from a tree carrying the feature, without enabling it); `absent` IGNORES it
 * (built from a tree predating the seam entirely). Those two are indistinguishable by exit code —
 * MEASURED 2026-08-06, nine of the eleven nub binaries on the dev host were `absent`, and every one
 * of them satisfied a probe that read `rc == 0`. `absent` is what makes this file guard the defect
 * rather than only its neighbour.
 *
 * ⛔ THE `on` STUB EMITS THE REAL BANNER, VERBATIM, AND USED NOT TO. It printed
 * `catalog OVERRIDDEN from …`, which no nub ever prints — the true text carries a `build-jail `
 * prefix and goes to STDERR. A stub that invents its own wording tests the stub: it would keep
 * passing against a driver searching for a string no binary produces. Captured from a nub built
 * with the feature.
 */
const stubs = (dir) => {
  const off = path.join(dir, 'nub-nofeature');
  const on = path.join(dir, 'nub-feature');
  const absent = path.join(dir, 'nub-preseam');
  fs.writeFileSync(off, '#!/bin/sh\n'
    + 'if [ -n "$NUB_BUILD_JAIL_CATALOG" ]; then\n'
    + '  echo "Error: NUB_BUILD_JAIL_CATALOG is set, but this binary was not built with the'
    + ' \\`build-jail-catalog-override\\` feature, so it cannot honour it." >&2\n'
    + '  exit 1\n'
    + 'fi\n'
    + 'echo v0.0.0-nofeature\n');
  // The literal constant, so the content search has something true to find. Kept on one line so the
  // file also differs from its sibling in length.
  fs.writeFileSync(on, '#!/bin/sh\n# BUILD_JAIL_BASELINE_ENV: PYTHONDONTWRITEBYTECODE\n'
    + 'echo "warning: build-jail catalog OVERRIDDEN from $NUB_BUILD_JAIL_CATALOG'
    + ' (v2: 1 packages, 1 grants, 0 baseline paths, 0 env)'
    + ' — development-only, not a shipped configuration" >&2\n'
    + 'echo v0.0.0-feature\n');
  // Predates the seam: the variable is not merely unhonoured, it is unknown. Byte-identical output
  // whether or not it is set, which is exactly why an exit code cannot see it.
  fs.writeFileSync(absent, '#!/bin/sh\necho v0.0.0-preseam\n');
  fs.chmodSync(off, 0o755);
  fs.chmodSync(on, 0o755);
  fs.chmodSync(absent, 0o755);
  return { off, on, absent };
};

test('INSTRUMENT: the block extractor finds a real emission in the shipped driver', () => {
  const block = markerBlock();
  assert.ok(block.split('\n').length > 5, `the extracted block is implausibly short:\n${block}`);
  assert.match(block, /NUB_BUILD_JAIL_CATALOG/,
    'the extracted block does not exercise the override — the anchors caught the wrong lines');
});

test('the marker DISCRIMINATES: two different binaries report two different hashes', () => {
  const dir = tmp();
  const { off, on } = stubs(dir);
  const a = parseMarker(emit(off));
  const b = parseMarker(emit(on));
  assert.ok(a && b, 'the block printed no marker for an existing binary');

  // ⛔ THE WHOLE POINT. A marker that always prints the same thing populates the field and carries
  // no information, which reads exactly like provenance until someone needs it.
  assert.notEqual(a.sha256, b.sha256,
    `two different binaries reported the SAME hash — the marker carries no identity:\n${a.sha256}`);
  assert.notEqual(a.bytes, b.bytes, 'two different binaries reported the same size');

  // Checked against an independent implementation rather than against itself: a hash the emitter
  // computes and the test recomputes the same wrong way agrees perfectly and proves nothing.
  for (const [bin, got] of [[off, a], [on, b]]) {
    const want = crypto.createHash('sha256').update(fs.readFileSync(bin)).digest('hex');
    assert.equal(got.sha256, want, `the reported hash for ${path.basename(bin)} is not its sha256`);
    assert.equal(got.bytes, fs.statSync(bin).size, `the reported size for ${path.basename(bin)} is wrong`);
    assert.equal(got.path, bin, 'the marker names a different path than the binary it measured');
  }
});

test('both feature flags DISCRIMINATE, and the override is decided by EXERCISING the binary', () => {
  const dir = tmp();
  const { off, on } = stubs(dir);
  const a = parseMarker(emit(off));
  const b = parseMarker(emit(on));

  // ⛔ A GREP FOR THE FEATURE NAME WOULD BE EXACTLY INVERTED — Rust embeds no feature names, and the
  // literal `build-jail-catalog-override` appears only in the error a binary built WITHOUT the
  // feature prints. So the capability is asked of the ARTIFACT by running it. These stubs encode
  // that: the one that REFUSES the catalog must report false.
  assert.equal(a.features.buildJailCatalogOverride, false,
    'a binary that refuses NUB_BUILD_JAIL_CATALOG was reported as having the override feature');
  assert.equal(b.features.buildJailCatalogOverride, true,
    'a binary that accepts NUB_BUILD_JAIL_CATALOG was reported as lacking the override feature');

  assert.equal(a.features.pythonDontWriteBytecodeEnv, false);
  assert.equal(b.features.pythonDontWriteBytecodeEnv, true,
    'the bytecode env constant is present in the binary but was not detected');
});

test('a binary that IGNORES the catalog is not credited with the feature', () => {
  // ⛔ THE CASE EXIT CODE CANNOT SEE, and the reason this file needed a third stub. A binary
  // predating the seam neither honours nor refuses the variable: it exits 0 with output identical
  // to a run where the variable was never set. Asking `rc == 0` therefore credits it with the
  // feature, which is how nine binaries on the dev host passed a check built to refuse them.
  const dir = tmp();
  const { on, absent } = stubs(dir);
  assert.equal(parseMarker(emit(absent)).features.buildJailCatalogOverride, false,
    'a binary that ignored NUB_BUILD_JAIL_CATALOG entirely was reported as honouring it — the probe '
    + 'is reading silence as consent');

  // ⛔ THE POSITIVE CONTROL, IN THE SAME CASE. Without it "we detect the feature" is satisfiable by
  // reporting false for everything, which would pass the assertion above and fail every real run.
  assert.equal(parseMarker(emit(on)).features.buildJailCatalogOverride, true,
    'the feature-enabled stub was refused — the probe now rejects good binaries, which is the more '
    + 'expensive direction of this bug');
});

test('no binary means NO marker, never a fabricated identity', () => {
  // The OBSERVE-only invocation passes no nub at all. A marker with null fields would read as "we
  // measured something and could not identify it", which is a different and false claim.
  const out = execFileSync('bash', ['-c', markerBlock()], { encoding: 'utf8', env: { ...process.env, NUB: '' } });
  assert.equal(parseMarker(out), null, `an absent binary produced a marker:\n${out}`);
});

test('the emitted line survives into provenance.nubBinary in a real record', () => {
  // End-to-end across the seam that actually matters: the driver's stdout and `record.mjs`'s parse.
  // A unit test of either side alone steps over exactly the gap that left darwin at 0/120.
  const dir = tmp();
  const { on } = stubs(dir);
  const marker = emit(on).trim();
  const log = path.join(dir, 'driver.txt');
  fs.writeFileSync(log, [
    '### thing@1.0.0   (/tmp/v2m-xxxx)   nub=' + on,
    marker,
    '  VENUE-INTERPRETER /Users/runner/hostedtoolcache/node/22.23.1/arm64',
    '  VENUE-STORE-LAYOUT isolated',
    '  => MINIMUM {"network":true}   (observed, then verified)',
  ].join('\n'));

  execFileSync(process.execPath, [path.join(HERE, 'record.mjs'),
    '--log', log, '--pkg', 'thing', '--version', '1.0.0',
    '--out', path.join(dir, 'runs'), '--rc', '0',
    '--platform', 'darwin-arm64', '--duration-ms', '1000'],
  { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: dir } });

  const rec = JSON.parse(fs.readFileSync(
    path.join(dir, 'runs', 'darwin-arm64', 'thing', '1.0.0', 'results.json'), 'utf8'));
  const want = crypto.createHash('sha256').update(fs.readFileSync(on)).digest('hex');
  assert.equal(rec.provenance.nubBinary?.sha256, want,
    `a darwin record still does not name its binary:\n${JSON.stringify(rec.provenance.nubBinary)}`);
  assert.equal(rec.provenance.nubBinary.features.buildJailCatalogOverride, true);
});
