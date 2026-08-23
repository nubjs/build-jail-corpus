// ⛔ THE MUTUAL-DESTRUCTION LOOP THAT STOPPED THE CORPUS CONVERGING. `claim-slice.mjs` invalidates
// stale `done` rows before selecting a slice, and it was applying THIS runner's runtime identity —
// `process.version`, this box's Node hash — to rows of EVERY platform. A macOS row was thereby asked
// whether the Linux runner holding the queue had produced it. It had not, so the row was returned to
// pending and re-measured.
//
// MEASURED 2026-08-23: `setup-node` pins `node-version: '22'`, a floating major, and the hosted
// images had drifted — every darwin epoch-3 record carried v22.23.1 and every linux one v22.23.2. So
// each linux claim reopened all 89 darwin rows and each darwin claim reopened all 141 linux rows;
// `done` oscillated around one platform's worth (200 -> 100) while 230 valid records sat on disk.
// One macOS slice re-measured 43 of its 50 rows, and one record was written three times.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { computeHarnessIdentity } from './instrument.mjs';
import { fileIdentity } from './runtime-provenance.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const claim = path.join(HERE, '..', 'claim-slice.mjs');
const read = (q) => fs.readFileSync(q, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

// The OS this runner is NOT, so the row under test can never be one it could have measured.
const FOREIGN = process.platform === 'linux' ? 'macos' : 'linux';

// ⛔ THE SUBJECT HASH IN THE ROW MUST BE THE REAL FILE'S. A placeholder makes every row invalidate
// as "Nub binary changed", so all three tests would pass or fail for a reason that has nothing to do
// with the platform scoping under test — a control that cannot fail.
function queueWith(build) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'queue-xplat-'));
  const q = path.join(root, 'queue-v2.ndjson');
  const nub = path.join(root, 'nub');
  fs.writeFileSync(nub, 'subject binary');
  fs.writeFileSync(q, `${JSON.stringify(build(fileIdentity(nub).sha256))}\n`);
  return { root, q, nub };
}

const doneRow = (NUB_SHA, over = {}) => {
  const i = computeHarnessIdentity();
  return {
    pkg: 'demo', version: '1.0.0', os: FOREIGN, status: 'done', verdict: 'MINIMUM',
    harnessVersion: 2, harnessEpoch: i.harnessEpoch, harnessSha256: i.harnessSha256,
    platform: FOREIGN === 'macos' ? 'darwin-arm64' : 'linux-x64',
    nubSha256: NUB_SHA, nubGitSha: 'subject-commit',
    // A Node version this runner definitely does NOT have — the drift that caused the loop.
    node: 'v0.0.1-not-this-runner', nodeSha256: 'foreign-node-hash',
    ...over,
  };
};

test('a foreign-platform row survives a claim, however different this runner\'s Node', () => {
  const { q, nub } = queueWith((h) => doneRow(h));
  const r = spawnSync(process.execPath, [claim, '--queue', q, '--claim', '1', '--os', FOREIGN,
    '--run', 'test-run', '--subject-nub', nub, '--subject-nub-git-sha', 'subject-commit'],
  { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const row = read(q)[0];
  assert.equal(row.status, 'done', `a foreign row was reopened as ${row.status} — the loop is back`);
  assert.equal(row.invalidated, undefined,
    `invalidated with: ${row.invalidated?.reason} — this runner judged a platform it cannot measure`);
});

test('a CHANGED NUB SUBJECT still reopens a foreign row — the subject is global', () => {
  const { q, nub } = queueWith((h) => doneRow(h));
  const r = spawnSync(process.execPath, [claim, '--queue', q, '--claim', '1', '--os', FOREIGN,
    '--run', 'test-run', '--subject-nub', nub, '--subject-nub-git-sha', 'a-DIFFERENT-commit'],
  { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const row = read(q)[0];
  // Reopened THEN claimed by this same invocation, so the terminal state is `claimed`, not
  // `pending`. What matters is that it was reopened at all — the `invalidated` stamp is the evidence.
  assert.notEqual(row.status, 'done', 'a new nub commit must reopen every platform, not just this one');
  assert.match(row.invalidated?.reason ?? '', /Nub binary|Nub commit/);
});

test('this runner\'s OWN platform is still judged on its Node', () => {
  const mine = process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'linux';
  const { q, nub } = queueWith((h) => doneRow(h, {
    os: mine,
    platform: `${process.platform}-${process.arch}`,
    nodeSha256: fileIdentity(process.execPath).sha256,
  }));
  const r = spawnSync(process.execPath, [claim, '--queue', q, '--claim', '1', '--os', mine,
    '--run', 'test-run', '--subject-nub', nub, '--subject-nub-git-sha', 'subject-commit'],
  { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const row = read(q)[0];
  assert.notEqual(row.status, 'done', 'own-platform rows must still reopen when this runner\'s Node differs');
  assert.match(row.invalidated?.reason ?? '', /Node runtime changed/);
});
