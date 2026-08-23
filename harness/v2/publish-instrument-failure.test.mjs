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
function scratchRepo(record) {
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
  git(work, 'add', '-A');
  git(work, 'commit', '-qm', 'init');
  git(work, 'remote', 'add', 'origin', origin);
  git(work, 'push', '-q', 'origin', 'main');
  const rel = 'records-v2/runs/linux-x64/somepkg/1.0.0';
  const dir = path.join(work, rel);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), JSON.stringify(record));
  return { root, work, dir, rel };
}

function publish({ work, dir }, manifest) {
  return spawnSync('bash', [PUBLISH, dir], {
    cwd: work,
    encoding: 'utf8',
    env: {
      ...process.env,
      NUB_CORPUS_REPO: work,
      NUB_CORPUS_BRANCH: 'main',
      NUB_CORPUS_MANIFEST: manifest,
      NUB_CORPUS_WITHHELD: path.join(work, 'withheld-records'),
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
