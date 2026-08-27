// ⛔ THE BUG THAT BINNED 49 GOOD RECORDS. `publish-record-v2.sh` published a record whose verdict was
// an instrument failure; the slice gate then correctly refused it ("instrument failure is not a
// measurement") and, because that gate runs BEFORE the commit step under `set -eu`, took the whole
// slice with it. Measured on run 32665285301: `netlify-cli@23.9.5` came back `HARNESS-*` and 49
// unrelated measurements were thrown away.
//
// Driven as a subprocess against a real scratch git repo, because the thing under test is a shell
// script whose contract is what it leaves in the tree and in the manifest.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLISH = path.join(HERE, 'publish-record-v2.sh');

const git = (cwd, ...args) => spawnSync('git', args, { cwd, encoding: 'utf8' });

// A repo with an `origin` it can actually fetch: publish-record-v2.sh fetches and resets to
// `origin/$BRANCH` before deciding anything, so a repo with no remote exercises none of the path.
function scratchRepo(record, prior = null) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pub-if-'));
  const origin = path.join(root, 'origin');
  const work = path.join(root, 'work');
  fs.mkdirSync(origin);
  git(origin, 'init', '-q', '--bare', '-b', 'main');
  fs.mkdirSync(work);
  git(work, 'init', '-q', '-b', 'main');
  git(work, 'config', 'user.email', 't@t');
  git(work, 'config', 'user.name', 't');
  fs.writeFileSync(path.join(work, 'queue-v2.ndjson'), '');
  const rel = 'records-v2/runs/linux-x64/somepkg/1.0.0';
  const dir = path.join(work, rel);
  // A PRIOR in origin is what makes the publish guard run at all — it reads the prior with
  // `git show origin/$BRANCH:$REL/results.json` and publishes unguarded when there is none.
  if (prior) {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(prior));
  }
  git(work, 'add', '-A');
  git(work, 'commit', '-qm', 'init');
  git(work, 'remote', 'add', 'origin', origin);
  git(work, 'push', '-q', 'origin', 'main');
  // ⛔ THE GUARD IS INVOKED AS `node harness/v2/publish-guard.mjs`, RELATIVE TO THE REPO ROOT, so a
  // scratch repo without it makes the publisher FAIL OPEN — correct behaviour, and it silently turns
  // a withholding test into a publishing one.
  //
  // ⛔⛔ COPIED, NEVER SYMLINKED, AND THIS IS NOT A STYLE CHOICE. `publish-guard.mjs:157` guards its
  // CLI with `import.meta.filename === process.argv[1]`. Through a symlink those two disagree —
  // argv[1] is the link path, `import.meta.filename` the real one — so the CLI block never runs and
  // the guard exits 0 having printed NOTHING. The publisher reads that as PUBLISH. Measured: this
  // test passed its `publish` assertion for exactly that reason before the symlink was replaced.
  // Excluded from git so the publisher's reset cannot sweep it away mid-run.
  fs.appendFileSync(path.join(work, '.git', 'info', 'exclude'), '\n/harness\n');
  fs.cpSync(path.join(HERE, '..'), path.join(work, 'harness'), { recursive: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(record));
  return { root, work, dir, rel };
}

// ⛔ POSIX PATHS, BECAUSE THAT IS WHAT PRODUCTION HANDS IT. `publish-record-v2.sh` guards with
// `case "$REL" in records-v2/*)`, and $REL is derived by stripping $NUB_CORPUS_REPO off the record
// dir. Give it Node's `path.join` output on Windows and REL is `records-v2\runs\...` with
// BACKSLASHES, which never matches that glob — so the script exits 0 having done nothing and every
// assertion here saw an empty stderr. On a real runner every path reaches it through Git-bash in
// POSIX form. Driving it any other way tests a calling convention that does not exist.
const posix = (p) => p.replace(/\\/g, '/');

function publish({ work, dir }, manifest, settled = null) {
  return spawnSync('bash', [posix(PUBLISH), posix(dir)], {
    cwd: work,
    encoding: 'utf8',
    env: {
      ...process.env,
      NUB_CORPUS_REPO: posix(work),
      NUB_CORPUS_BRANCH: 'main',
      NUB_CORPUS_MANIFEST: posix(manifest),
      NUB_CORPUS_WITHHELD: posix(path.join(work, 'withheld-records')),
      ...(settled ? { NUB_CORPUS_SETTLED: posix(settled) } : {}),
    },
  });
}

test('a HARNESS-* verdict is withheld and never reaches the manifest', () => {
  const t = scratchRepo({ pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'HARNESS-ERROR' });
  const manifest = path.join(t.root, 'published.txt');
  const r = publish(t, manifest);
  assert.equal(r.status, 0, 'the publisher always exits 0 by design');
  assert.match(r.stderr, /WITHHELD \(instrument failure/);
  // The manifest is what the slice gate reads. An entry here is what binned the slice.
  const listed = fs.existsSync(manifest) ? fs.readFileSync(manifest, 'utf8') : '';
  assert.equal(listed.trim(), '', `manifest must stay empty, held: ${listed}`);
  // And the record must leave the tree, or the end-of-slice bulk commit sweeps it in anyway.
  assert.equal(fs.existsSync(path.join(t.dir, 'results.json')), false,
    'the withheld record is still in records-v2/ where a bulk commit will publish it');
});

test('the withheld record is parked where it stays inspectable', () => {
  const t = scratchRepo({ pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'HARNESS-TIMEOUT' });
  publish(t, path.join(t.root, 'published.txt'));
  const parked = path.join(t.work, 'withheld-records');
  assert.equal(fs.existsSync(parked), true, 'nothing was parked, so the failure is unexaminable');
});

test('an ordinary verdict still publishes — the guard is not a blanket refusal', () => {
  const t = scratchRepo({ pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM' });
  const manifest = path.join(t.root, 'published.txt');
  const r = publish(t, manifest);
  assert.equal(r.status, 0);
  assert.doesNotMatch(r.stderr, /WITHHELD/);
  const listed = fs.existsSync(manifest) ? fs.readFileSync(manifest, 'utf8') : '';
  assert.match(listed, /records-v2\/runs\/linux-x64\/somepkg\/1\.0\.0/,
    'a real measurement stopped reaching the manifest — this check would hide the corpus filling up');
});

// ⛔ THE OTHER HALF OF THE RECLAIM LOOP, AND THE ONE THAT COSTS A SLICE 58% OF ITS SLOTS. Withholding
// restores origin's PRIOR record, whose `harnessSha256` is OLD — so `--complete` stamps the row
// stale and the next claim's invalidation pass hands it straight back. `queue-settled.test.mjs`
// owns the queue half; this pins that the publisher NAMES the row so that half has an input at all.
test('a guard-withheld record is named in the settled manifest', () => {
  const t = scratchRepo(
    { pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'NO-STATE-PASSED' },
    { pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM', grant: { network: true } },
  );
  const settled = path.join(t.root, 'settled.ndjson');
  const r = publish(t, path.join(t.root, 'published.txt'), settled);
  assert.match(r.stderr, /WITHHELD \(not published/, `the guard did not fire: ${r.stderr}`);
  const lines = fs.existsSync(settled) ? fs.readFileSync(settled, 'utf8').trim() : '';
  assert.notEqual(lines, '', 'the withheld row reached no manifest, so the queue will reclaim it forever');
  const row = JSON.parse(lines.split('\n')[0]);
  assert.equal(row.pkg, 'somepkg');
  assert.equal(row.version, '1.0.0');
});

test('a PUBLISHED record is never named as settled', () => {
  const t = scratchRepo(
    { pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM', grant: { network: true } },
    { pkg: 'somepkg', version: '1.0.0', harnessVersion: 2, verdict: 'MINIMUM', grant: { network: true } },
  );
  const settled = path.join(t.root, 'settled.ndjson');
  publish(t, path.join(t.root, 'published.txt'), settled);
  const lines = fs.existsSync(settled) ? fs.readFileSync(settled, 'utf8').trim() : '';
  assert.equal(lines, '', `a published row was settled, which would strand it: ${lines}`);
});
