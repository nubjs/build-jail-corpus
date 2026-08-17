// The slim provenance mode must drop ONLY what is derivable, and must never touch a grant.
//
// What forced this: the shipped catalog was 98.6% provenance that no Rust code reads. Measured on the
// 294-package catalog, `packages` -- the whole policy -- was 62 KB while `provenance` was 4,405 KB
// (`runtimeCells` 4,055 KB, `resolvedTreeDigests` 349 KB), and it had DOUBLED as the corpus grew while
// the grants shrank. `catalog_override.rs` embeds the file with `include_str!`, so all of it compiles
// into every nub binary. Slimming saves 98.2% of the file.
//
// The risk this guards is the one that would matter: a size optimisation that quietly changes policy.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import { test } from 'node:test';

const HERE = import.meta.dirname;
const COLLATE = path.join(HERE, 'collate.mjs');
const SRC = fs.readFileSync(COLLATE, 'utf8');

// A one-record tree is enough: this tests the provenance SHAPE, not grant derivation.
function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'slimprov-'));
  const rec = path.join(dir, 'runs', 'linux-x64', 'demo', '1.0.0');
  fs.mkdirSync(rec, { recursive: true });
  fs.writeFileSync(path.join(rec, 'results.json'), JSON.stringify({
    pkg: 'demo', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM',
    grant: { network: true }, minimality: 'MINIMAL', writePaths: [],
    resolvedTrees: [{ kinds: ['direct'], digest: 'deadbeef' }],
    provenance: { platform: 'linux-x64', harness: 'measure.sh' },
  }));
  return dir;
}

const bake = (dir, extra = []) => {
  const out = path.join(dir, `cat${extra.length}.json`);
  execFileSync(process.execPath, [COLLATE, '--runs', path.join(dir, 'runs'), '--out', out, ...extra],
    { encoding: 'utf8', stdio: 'pipe' });
  return JSON.parse(fs.readFileSync(out, 'utf8'));
};

test('slim mode changes no grant, no baseline and no env', () => {
  // ⛔ THE ASSERTION THAT MATTERS. Everything else here is about bytes; this is about policy. A
  // provenance change that shifted a grant would be the worst possible outcome of a size fix.
  const dir = fixture();
  const full = bake(dir);
  const slim = bake(dir, ['--slim-provenance']);
  assert.deepEqual(slim.packages, full.packages, 'slim mode altered a GRANT — abort the optimisation');
  assert.deepEqual(slim.baseline, full.baseline, 'slim mode altered the baseline paths');
  assert.deepEqual(slim.env, full.env, 'slim mode altered the env set');
});

test('slim mode keeps the audit anchor and drops only the derivable projections', () => {
  const dir = fixture();
  const full = bake(dir);
  const slim = bake(dir, ['--slim-provenance']);
  // The anchor: recordsSha256 hashes every record's path and bytes, so the catalog stays provable
  // against the records. runtimeCells and resolvedTreeDigests are computed FROM those records, so
  // they add no verifiability the anchor lacks — which is the whole justification for dropping them.
  assert.equal(slim.provenance.recordsSha256, full.provenance.recordsSha256,
    'recordsSha256 must survive — it is the only thing tying the catalog to its records');
  for (const k of ['schemaVersion', 'harnessEpoch', 'harnessSha256', 'invalidationPolicySha256',
    'recordCount', 'sourceHarnesses']) {
    assert.deepEqual(slim.provenance[k], full.provenance[k], `${k} must survive slimming`);
  }
  assert.equal(slim.provenance.runtimeCells, undefined, 'runtimeCells must be omitted in slim mode');
  assert.equal(slim.provenance.resolvedTreeDigests, undefined,
    'resolvedTreeDigests must be omitted in slim mode');
  // Full mode must still emit them, or this flag has become the only mode and the corpus loses detail.
  assert.ok(Array.isArray(full.provenance.runtimeCells), 'full mode must still emit runtimeCells');
  assert.ok(Array.isArray(full.provenance.resolvedTreeDigests),
    'full mode must still emit resolvedTreeDigests');
});

test('the omission is STATED, so an absence is never misdiagnosed', () => {
  // A reader finding no runtimeCells must be able to tell "omitted deliberately" from "written by an
  // older collator" or "file truncated". An unexplained absence is what gets investigated as a bug.
  const dir = fixture();
  assert.equal(bake(dir, ['--slim-provenance']).provenance.provenanceSlim, true,
    'slim output must carry provenanceSlim: true');
  assert.equal(bake(dir).provenance.provenanceSlim, undefined,
    'full output must NOT claim to be slim');
});

test('the flag is registered, or collate refuses the run outright', () => {
  // collate REFUSES unknown flags by design — every option has a default, so an ignored flag
  // silently collates the wrong thing and exits 0. An unregistered flag would abort the bake.
  assert.match(SRC, /'--slim-provenance'/,
    '--slim-provenance must appear in the KNOWN set or collate refuses it');
  const dir = fixture();
  let refused = false;
  try { bake(dir, ['--slim-provenanc']); } catch { refused = true; }
  assert.ok(refused, 'a typo of the flag must be REFUSED, not silently ignored');
});
