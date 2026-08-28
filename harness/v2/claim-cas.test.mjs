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
import { execFileSync, spawnSync } from 'node:child_process';
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
  // ⛔ NO AUTO-GC ON THE BARE ORIGIN, OR ITS TEARDOWN RACES A PROCESS THIS TEST DOES NOT WAIT FOR.
  // `receive-pack` runs `git gc --auto` after every push it accepts, and `gc.autoDetach` defaults
  // to true, so the gc is a DETACHED child that outlives the synchronous `git push` this fixture
  // blocks on. It then writes into origin.git — lock files, gc.log — while `discard()` is walking
  // the same tree. MEASURED 2026-08-28 on run 33202504594: the last-write-wins control asserted
  // correctly and then died in teardown with
  // `ENOTEMPTY: directory not empty, rmdir '/tmp/claimcas-ClEEqA/origin.git'`, taking the whole
  // suite step down and with it the slice — the runner never reached "Claim a slice". Three config
  // keys because each closes the hole alone only on some git versions.
  for (const [k, v] of [['receive.autogc', 'false'], ['gc.auto', '0'], ['gc.autoDetach', 'false']]) {
    git(['-C', origin, 'config', k, v], root);
  }
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

/// Teardown for a scratch root. Retries are Node's own documented handling for a transient
/// ENOTEMPTY (`fs.rm` maxRetries names that exact errno), and this is TEARDOWN — it guards no
/// assertion and cannot turn a red test green. It is the belt to the `receive.autogc` braces in
/// `scratch()`: that removes the one background writer we can name, and this survives one we
/// cannot. If a teardown ever exhausts these retries, something is still writing and the config
/// above is not the whole story — do not raise the number, find the writer.
const discard = (root) => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });

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
  discard(root);
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
  discard(root);
});

// ⛔ THE FULL CYCLE, NOT JUST THE CLAIM. The test above covers only the claim push. This one runs two
// runners all the way through claim -> record -> publish -> `--complete`, with their publishes
// INTERLEAVED, and asserts that origin ends up holding every record and every closed row from both.
// It is the difference between "the claim path is a compare-and-swap" and "two runners can drain the
// corpus without losing work", and only the second answers whether the serial rule is necessary.
//
// What it deliberately does NOT do is measure anything: the records are synthesised. The measuring
// arms cannot run here and are not what the one-runner rule is about — the rule is about the QUEUE.
//
// ⛔⛔ IT DOES NOT EXPLAIN THE 2026-08-23 OBSERVATION, AND IT IS NOT A LICENCE TO RUN TWO RUNNERS.
// The header's measurement is real, and disabling the publisher's `git checkout origin/$BRANCH --
// "$QUEUE"` makes THIS test reproduce it exactly — "rows whose record published never closed". That
// looked like the answer: the bug was real and had since been fixed. It was not. That line has been
// in the publisher since its FIRST commit (b39a8507, 2026-08-06), seventeen days before the
// measurement, so it was never the fix and the reproduction is a different failure with the same
// signature.
//
// So the honest scope is: the CURRENT code survives two runners through the queue mechanics MODELLED
// HERE. Three things are not modelled, and any of them could carry the real cause — synthesised
// records skip `--reconcile --require-current-instrument` mismatches, withholds and `HARNESS-*`
// verdicts entirely; the slices are 5 rows against the measured 50; and `--complete` is called
// DIRECTLY, so the end-of-slice commit step's hard reset, record restore and 12-attempt retry loop —
// the very step that printed `completed 0 row(s)` — never runs. Closing that third gap is what would
// actually settle the question.
const instrumentNow = async (repo) => {
  const { computeHarnessIdentity } = await import(`${repo}/harness/v2/instrument.mjs`);
  return computeHarnessIdentity();
};

const writeRecord = (dir, pkg, ident) => {
  const rel = `records-v2/runs/linux-x64/${pkg}/1.0.0`;
  const abs = path.join(dir, rel);
  fs.mkdirSync(abs, { recursive: true });
  fs.writeFileSync(path.join(abs, 'results.json'), JSON.stringify({
    pkg, version: '1.0.0', harnessVersion: 2, harnessEpoch: ident.harnessEpoch, verdict: 'MINIMUM',
    grant: {}, provenance: { platform: 'linux-x64', harnessSha256: ident.harnessSha256 },
  }));
  return abs;
};

const publishOne = (dir, abs) => execFileSync('bash',
  [path.join(dir, 'harness', 'v2', 'publish-record-v2.sh'), abs], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...process.env,
      NUB_CORPUS_REPO: dir,
      NUB_CORPUS_BRANCH: 'main',
      NUB_CORPUS_MANIFEST: path.join(dir, '.manifest'),
      NUB_CORPUS_WITHHELD: path.join(dir, 'withheld-records'),
    },
  });

test('two runners interleaved through claim, publish and complete lose no record and no row', async () => {
  const { root, origin, nubBin } = scratch(40);
  const A = clone(origin, root, 'cycleA');
  const B = clone(origin, root, 'cycleB');
  const body = claimShell();
  const ident = await instrumentNow(A);

  const runClaim = (dir, runId) => sh(
    `set -e\nexport GITHUB_REF_NAME=main OS_NAME=linux SLICE_IN=5 RUN_ID=${runId} `
    + `NUB_BIN=${nubBin} NUB_GIT_SHA=deadbeef\n${body}`, dir);

  runClaim(A, 'CYCA');
  runClaim(B, 'CYCB');
  const aPkgs = claimed(A, 'CYCA');
  const bPkgs = claimed(B, 'CYCB');
  assert.equal(aPkgs.length, 5);
  assert.equal(bPkgs.length, 5);
  assert.equal(new Set([...aPkgs, ...bPkgs]).size, 10, 'the two runners claimed overlapping rows');

  // ⛔ INTERLEAVED, ALTERNATING. Publishing A's five and then B's five would serialise the very
  // contention this exists to reproduce, and would pass without proving anything.
  for (let i = 0; i < 5; i++) {
    publishOne(A, writeRecord(A, aPkgs[i], ident));
    publishOne(B, writeRecord(B, bPkgs[i], ident));
  }

  // Each runner closes its own rows, exactly as the end-of-slice step does.
  for (const [dir, runId] of [[A, 'CYCA'], [B, 'CYCB']]) {
    execFileSync('node', ['harness/collect-verdicts.mjs', '--runs', 'records-v2',
      '--out', path.join(dir, '.verdicts')], { cwd: dir, encoding: 'utf8' });
    execFileSync('node', ['harness/claim-slice.mjs', '--queue', 'queue-v2.ndjson',
      '--complete', path.join(dir, '.verdicts'), '--run', runId], { cwd: dir, encoding: 'utf8' });
  }

  // ⛔ ASSERT ON ORIGIN, NEVER ON EITHER WORKING TREE. Each runner's own tree necessarily holds its
  // own work; the question is whether BOTH survived the other's pushes.
  const verify = clone(origin, root, 'cycleVerify');
  const records = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === 'results.json') records.push(JSON.parse(fs.readFileSync(p, 'utf8')).pkg);
    }
  })(path.join(verify, 'records-v2'));

  const missing = [...aPkgs, ...bPkgs].filter((p) => !records.includes(p));
  assert.deepEqual(missing, [],
    `records LOST on origin — published by a runner and absent upstream: ${missing.join(', ')}`);

  const rows = fs.readFileSync(path.join(verify, 'queue-v2.ndjson'), 'utf8')
    .split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(rows.length, 40, 'the queue lost or gained rows outright');
  const stillOpen = rows.filter((r) => [...aPkgs, ...bPkgs].includes(r.pkg) && r.status !== 'done');
  assert.deepEqual(stillOpen.map((r) => `${r.pkg}:${r.status}`), [],
    'rows whose record published never closed — the `completed 0 row(s)` failure, reproduced');
  discard(root);
});

// ⛔ GAP 3 CLOSED: the END-OF-SLICE COMMIT STEP, which is the step that actually printed
// `completed 0 row(s)` in the 2026-08-23 two-runner measurement. Everything above called
// `--complete` directly and so never exercised it. It is also the least-covered high-consequence
// code in the lane: it hard-resets to origin, restores this run's records from a stash, re-runs
// `--complete`, and retries twelve times.
//
// Reading it supplies a mechanism for `completed 0 row(s)` that needs NO erasure. The hard reset
// takes ORIGIN's queue — including whatever the other runner's per-package `--reconcile` has already
// closed. `--reconcile` closes any row with a matching record, checks neither run id nor `claimed`,
// and `delete r.run`s. So by the time runner B's commit step runs `--complete --run B`, B's rows can
// already be `done` with no `run` field, and `--complete` correctly touches nothing.
//
// The rows are NOT lost: reconcile stamped them from the record. What IS lost is the `--settled`
// bookkeeping, because reconcile has no notion of it — so a WITHHELD row is reopened instead of
// settled, which is the re-measure loop epoch 4 exists to stop. That is a real cost and a bounded
// one, and it is the thing to weigh if parallel draining is ever enabled.
const commitShell = () => {
  const src = fs.readFileSync(path.join(REPO, '.github', 'workflows', 'corpus-v2-runner.yml'), 'utf8');
  const start = src.indexOf('      - name: Commit records and queue\n');
  assert.notEqual(start, -1, 'the end-of-slice commit step is gone from the workflow');
  const runAt = src.indexOf('        run: |\n', start) + '        run: |\n'.length;
  const end = src.indexOf('\n      - name:', runAt);
  return src.slice(runAt, end).split('\n').map((l) => l.replace(/^ {10}/, '')).join('\n')
    .replace(/\$\{\{ github\.run_id \}\}/g, '$RUN_ID')
    // ⛔ THE STEP HARDCODES /tmp/slice.txt AND /tmp/verdicts.ndjson. On a runner each job owns its VM
    // so they cannot collide; two simulated runners in one tmpdir would silently share them and the
    // test would prove nothing about either.
    .replace(/\/tmp\/slice\.txt/g, '$SLICE_FILE')
    .replace(/\/tmp\/verdicts\.ndjson/g, '$VERDICTS_FILE');
};

test('the real commit step: a reconcile-closed row makes --complete report 0, and loses no row', async () => {
  const { root, origin, nubBin } = scratch(40);
  const A = clone(origin, root, 'ceA');
  const B = clone(origin, root, 'ceB');
  const ident = await instrumentNow(A);
  const body = claimShell();

  const runClaim = (dir, runId) => sh(
    `set -e\nexport GITHUB_REF_NAME=main OS_NAME=linux SLICE_IN=5 RUN_ID=${runId} `
    + `NUB_BIN=${nubBin} NUB_GIT_SHA=deadbeef\n${body}`, dir);
  runClaim(A, 'CEA');
  runClaim(B, 'CEB');
  const aPkgs = claimed(A, 'CEA');
  const bPkgs = claimed(B, 'CEB');

  for (let i = 0; i < 5; i++) {
    publishOne(A, writeRecord(A, aPkgs[i], ident));
    publishOne(B, writeRecord(B, bPkgs[i], ident));
  }

  const commitStep = (dir, runId, pkgs) => {
    fs.writeFileSync(path.join(dir, '.slice'), `${pkgs.join('\n')}\n`);
    execFileSync('node', ['harness/collect-verdicts.mjs', '--runs', 'records-v2',
      '--out', path.join(dir, '.verdicts')], { cwd: dir, encoding: 'utf8' });
    return sh(`set +e\nexport GITHUB_REF_NAME=main OS_NAME=linux RUN_ID=${runId} `
      + `NUB_CORPUS_MANIFEST=${path.join(dir, '.manifest')} NUB_CORPUS_SETTLED=${path.join(dir, '.settled')} `
      + `SLICE_FILE=${path.join(dir, '.slice')} VERDICTS_FILE=${path.join(dir, '.verdicts')}\n`
      + `${body2}\n`, dir);
  };
  const body2 = commitShell();
  const outA = commitStep(A, 'CEA', aPkgs);
  const outB = commitStep(B, 'CEB', bPkgs);

  // ⛔ THE PREDICTION, WRITTEN AS AN ASSERTION: at least one runner reports `completed 0 row(s)`,
  // because the other's reconcile already closed its rows. If neither does, the mechanism above is
  // wrong and the 2026-08-23 observation needs a different explanation.
  const zero = [outA, outB].filter((o) => /completed 0 row\(s\)/.test(o)).length;

  const verify = clone(origin, root, 'ceVerify');
  const rows = fs.readFileSync(path.join(verify, 'queue-v2.ndjson'), 'utf8')
    .split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const open = rows.filter((r) => [...aPkgs, ...bPkgs].includes(r.pkg) && r.status !== 'done');
  assert.deepEqual(open.map((r) => `${r.pkg}:${r.status}`), [],
    `a row whose record published did not close, ${zero} runner(s) reported "completed 0 row(s)"`);
  assert.equal(rows.length, 40, 'the queue lost or gained rows outright');
  // Every closed row carries the verdict from its record, whichever path closed it.
  const wrong = rows.filter((r) => [...aPkgs, ...bPkgs].includes(r.pkg) && r.verdict !== 'MINIMUM');
  assert.deepEqual(wrong.map((r) => `${r.pkg}:${r.verdict}`), [],
    'a row closed WITHOUT its record\'s verdict — reconcile and --complete disagree');
  discard(root);
});

test('the guard still FATALs when a published record is genuinely absent from HEAD', async () => {
  // ⛔ THE CONTROL THAT KEEPS THE FIX HONEST. Loosening the guard so a fully-landed slice stops
  // failing is only correct if it still catches the case it was written for: the manifest names a
  // record, nothing staged, and the record is NOT on the branch — a sparse add that silently
  // dropped it. Without this, "make the FATAL stop firing" and "delete the safety check" are the
  // same commit.
  const { root, origin } = scratch(4);
  const A = clone(origin, root, 'fatalA');
  const manifest = path.join(A, '.manifest');
  // A record the manifest claims was published, which exists nowhere: not on disk, not in HEAD.
  fs.writeFileSync(manifest, 'records-v2/runs/linux-x64/ghost/1.0.0\n');
  fs.writeFileSync(path.join(A, '.slice'), 'ghost@1.0.0\n');
  fs.writeFileSync(path.join(A, '.verdicts'), '');
  const out = spawnSync('bash', ['-c',
    `set +e\nexport GITHUB_REF_NAME=main OS_NAME=linux RUN_ID=FATAL `
    + `NUB_CORPUS_MANIFEST=${manifest} NUB_CORPUS_SETTLED=${path.join(A, '.settled')} `
    + `SLICE_FILE=${path.join(A, '.slice')} VERDICTS_FILE=${path.join(A, '.verdicts')}\n${commitShell()}`],
  { cwd: A, encoding: 'utf8' });
  assert.equal(out.status, 1,
    `the guard did not FATAL on a missing record — it exited ${out.status}; the safety check is gone`);
  assert.match(out.stderr, /absent from HEAD/,
    'the guard failed for some other reason than the missing record');
  assert.match(out.stderr, /ghost/, 'the guard does not NAME what is missing, so nobody can act on it');
  discard(root);
});
