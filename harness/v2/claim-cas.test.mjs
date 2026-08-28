// ⛔ THE PROPERTY THE WHOLE "ONE RUNNER GLOBALLY" RULE RESTS ON, EXERCISED AGAINST THE REAL SHELL.
//
// `corpus-v2-runner.yml`'s header says two concurrent runners erase each other's claims, because
// "every runner rewrites the WHOLE queue file: it takes origin's copy, stamps its own claims,
// pushes", so the second write is built on a pre-claim snapshot. That is a real failure mode for a
// last-write-wins push — and this lane does not have one. The claim step re-claims against the new
// head when its push is rejected, which is a compare-and-swap.
//
// The distinction matters because the serial drain is the corpus's schedule: at measured rates the
// remaining macos + linux work is ~133 h serial against ~89 h parallel. So the claim is worth
// PINNING rather than believing, and pinning it is free — this test drives the step's OWN shell,
// extracted from the workflow, against two clones of a scratch repo. It touches no corpus.
//
// ⛔ IT DOES NOT MAKE PARALLEL DRAINING SAFE, AND MUST NOT BE CITED AS THOUGH IT DOES. It covers the
// CLAIM path only. Two things the header's measurement recorded are still unexplained and are NOT
// tested here: a publish gap ("50 measured, 43 published"), and `--reclaim-stale 360` returning a
// LIVE slice's rows to pending — a macos slice measured 221 minutes on 2026-08-28, and a slower one
// would cross that cutoff underneath itself.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..', '..');

const sh = (cmd, cwd) => execFileSync('bash', ['-c', cmd], { cwd, encoding: 'utf8' });
const git = (args, cwd) => execFileSync('git', args, { cwd, encoding: 'utf8' });

// The claim step's shell, taken from the workflow rather than paraphrased: a paraphrase would drift
// from the thing it claims to cover, and the drift would be invisible.
const claimShell = () => {
  const src = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'corpus-v2-runner.yml'), 'utf8');
  const start = src.indexOf('      - name: Claim a slice\n');
  assert.notEqual(start, -1, 'the claim step is gone from the workflow');
  const runAt = src.indexOf('        run: |\n', start) + '        run: |\n'.length;
  const end = src.indexOf('\n      - name:', runAt);
  const body = src.slice(runAt, end).split('\n').map((l) => l.replace(/^ {10}/, '')).join('\n');
  // GitHub expressions the harness cannot evaluate. `github.run_id` is the one under test, so it is
  // left as a placeholder the caller substitutes per simulated runner.
  return body
    .replace(/\$\{\{ inputs\.slice \|\| 10 \}\}/g, '$SLICE_IN')
    .replace(/\$\{\{ github\.run_id \}\}/g, '$RUN_ID')
    .replace(/\$\{\{ github\.ref_name \}\}/g, '$GITHUB_REF_NAME');
};

const scratch = (rows) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'claimcas-'));
  const origin = path.join(root, 'origin.git');
  const seed = path.join(root, 'seed');
  fs.mkdirSync(seed);
  git(['init', '-q', '--bare', '--initial-branch=main', origin], root);
  git(['init', '-q', '--initial-branch=main'], seed);
  git(['config', 'user.email', 't@t'], seed);
  git(['config', 'user.name', 't'], seed);
  const queue = Array.from({ length: rows }, (_, i) => JSON.stringify({
    pkg: `p${i}`, version: '1.0.0', os: 'linux', status: 'pending',
  })).join('\n');
  fs.writeFileSync(path.join(seed, 'queue-v2.ndjson'), `${queue}\n`);
  // The claim step runs `node harness/claim-slice.mjs`, so the harness must be present at that path.
  // COPIED, never symlinked: `import.meta.filename === process.argv[1]` CLI guards disagree through
  // a link, which once made a guard exit 0 printing nothing and a test assert the wrong thing.
  fs.cpSync(path.join(REPO, 'harness'), path.join(seed, 'harness'), { recursive: true });
  // ⛔ THE INSTRUMENT INPUTS COME TOO, ALL OF THEM. `claim-slice.mjs` calls `computeHarnessIdentity()`
  // on the claim path, and `instrument.mjs:69` throws `instrument input is absent` on the first one
  // missing — so a scratch repo holding only `harness/` cannot run the real step at all. Read the
  // list from `instrument.json` rather than hardcoding it, or adding an input silently breaks this.
  const inputs = JSON.parse(fs.readFileSync(path.join(REPO, 'harness', 'v2', 'instrument.json'), 'utf8')).inputs;
  for (const rel of inputs) {
    if (rel === 'harness') continue;
    const from = path.join(REPO, rel);
    if (!fs.existsSync(from)) continue;
    fs.mkdirSync(path.join(seed, path.dirname(rel)), { recursive: true });
    fs.cpSync(from, path.join(seed, rel), { recursive: true });
  }
  git(['add', '-A'], seed);
  git(['commit', '-qm', 'seed'], seed);
  git(['push', '-q', origin, 'main'], seed);
  // ⛔ A REAL FILE, NOT `/bin/true`. The claim path hashes the subject binary via `fileIdentity`,
  // and MEASURED on macOS `fileIdentity('/bin/true')` returns NULL — the guard then refuses the
  // claim with "requires readable Node/Nub binaries", which reads exactly like a code defect and is
  // a fixture defect. Any readable file satisfies it; the contents are never executed here.
  const nubBin = path.join(root, 'fake-nub');
  fs.writeFileSync(nubBin, '#!/bin/sh\nexit 0\n');
  return { root, origin, nubBin };
};

const clone = (origin, root, name) => {
  const dir = path.join(root, name);
  git(['clone', '-q', origin, dir], root);
  git(['config', 'user.email', 't@t'], dir);
  git(['config', 'user.name', 't'], dir);
  return dir;
};

const claimed = (dir, runId) => fs.readFileSync(path.join(dir, 'queue-v2.ndjson'), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l))
  .filter((r) => r.status === 'claimed' && r.run === runId).map((r) => r.pkg);

test('an interleaved second claim cannot erase the first — the push is rejected and it re-claims', () => {
  const { root, origin, nubBin } = scratch(40);
  const A = clone(origin, root, 'runnerA');
  const B = clone(origin, root, 'runnerB');
  const body = claimShell();

  // ⛔ THE INTERLEAVE IS THE WHOLE POINT. B is cloned BEFORE A claims, so B starts from a snapshot
  // that predates A's claims — precisely the "pre-claim snapshot" the header warns about. If the
  // step were last-write-wins, B's push would silently drop A's 10 rows.
  const run = (dir, runId) => sh(
    `set -e\nexport GITHUB_REF_NAME=main OS_NAME=linux SLICE_IN=10 RUN_ID=${runId} `
    + `NUB_BIN=${nubBin} NUB_GIT_SHA=deadbeef\n${body}`, dir);

  run(A, 'RUNA');
  const aAfterA = claimed(A, 'RUNA');
  assert.equal(aAfterA.length, 10, 'runner A did not claim its slice at all');

  run(B, 'RUNB');
  const bRows = claimed(B, 'RUNB');
  assert.equal(bRows.length, 10, 'runner B did not claim a slice');

  // Read the AUTHORITY — origin — not either working tree.
  const verify = clone(origin, root, 'verify');
  const aFinal = claimed(verify, 'RUNA');
  const bFinal = claimed(verify, 'RUNB');
  assert.equal(aFinal.length, 10,
    `runner A's claims were ERASED: ${aFinal.length} of 10 survive on origin`);
  assert.equal(bFinal.length, 10, "runner B's claims did not land on origin");
  assert.equal(new Set([...aFinal, ...bFinal]).size, 20,
    'the two runners claimed OVERLAPPING rows — the slices are not disjoint');
  fs.rmSync(root, { recursive: true, force: true });
});

test('the control: a last-write-wins push WOULD erase, so the assertion above is not vacuous', () => {
  // ⛔ WITHOUT THIS, THE TEST ABOVE PROVES NOTHING. It would pass just as happily if the two runners
  // never contended at all. Here B force-pushes its pre-claim snapshot — the last-write-wins
  // behaviour the header describes — and A's claims must vanish. If this does not go red, the
  // fixture is not reproducing contention and the green above is meaningless.
  const { root, origin, nubBin } = scratch(40);
  const A = clone(origin, root, 'runnerA');
  const B = clone(origin, root, 'runnerB');
  const body = claimShell();
  sh(`set -e\nexport GITHUB_REF_NAME=main OS_NAME=linux SLICE_IN=10 RUN_ID=RUNA `
    + `NUB_BIN=${nubBin} NUB_GIT_SHA=deadbeef\n${body}`, A);
  assert.equal(claimed(clone(origin, root, 'mid'), 'RUNA').length, 10);

  // B never fetches; it stamps its stale snapshot and forces it over A's.
  execFileSync('node', ['harness/claim-slice.mjs', '--queue', 'queue-v2.ndjson',
    '--claim', '10', '--os', 'linux', '--run', 'RUNB',
    '--subject-nub', nubBin, '--subject-nub-git-sha', 'deadbeef'],
  { cwd: B, encoding: 'utf8' });
  git(['add', 'queue-v2.ndjson'], B);
  git(['commit', '-qm', 'stale claim'], B);
  git(['push', '-q', '--force', 'origin', 'HEAD:main'], B);

  const after = clone(origin, root, 'verify2');
  assert.equal(claimed(after, 'RUNA').length, 0,
    'the last-write-wins control did NOT erase — the fixture is not reproducing contention');
  fs.rmSync(root, { recursive: true, force: true });
});
