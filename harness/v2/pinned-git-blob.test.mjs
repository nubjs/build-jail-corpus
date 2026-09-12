import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { materializePinnedGitBlob } from './pinned-git-blob.mjs';

const git = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

test('materializes exact blob bytes despite a CRLF-converted checkout and rejects a wrong ref', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pinned-git-blob-'));
  const source = path.join(root, 'source');
  const checkout = path.join(root, 'checkout');
  fs.mkdirSync(source);
  git(source, ['init', '-q']);
  git(source, ['config', 'user.email', 'test@example.com']);
  git(source, ['config', 'user.name', 'Test']);
  const canonical = Buffer.from('{\n  "catalog": "canonical"\n}\n');
  fs.writeFileSync(path.join(source, 'catalog-v2.json'), canonical);
  git(source, ['add', 'catalog-v2.json']);
  git(source, ['commit', '-qm', 'initial catalog']);
  const commit = git(source, ['rev-parse', 'HEAD']);

  execFileSync('git', ['clone', '-q', source, checkout]);
  git(checkout, ['config', 'core.autocrlf', 'true']);
  git(checkout, ['rm', '-q', '--cached', 'catalog-v2.json']);
  git(checkout, ['reset', '-q', '--hard', 'HEAD']);
  const checkoutBytes = fs.readFileSync(path.join(checkout, 'catalog-v2.json'));
  assert.notDeepEqual(checkoutBytes, canonical);
  assert.ok(checkoutBytes.includes(Buffer.from('\r\n')));

  const out = path.join(root, 'reports', 'candidate-catalog-v2.json');
  assert.deepEqual(materializePinnedGitBlob({ repo: checkout, ref: 'HEAD', commit, file: 'catalog-v2.json', sha256: hash(canonical), out }), {
    commit, path: 'catalog-v2.json', sha256: hash(canonical), bytes: canonical.length,
  });
  assert.deepEqual(fs.readFileSync(out), canonical);

  const badDigest = path.join(root, 'reports', 'bad-digest.json');
  assert.throws(() => materializePinnedGitBlob({ repo: checkout, ref: 'HEAD', commit, file: 'catalog-v2.json', sha256: '0'.repeat(64), out: badDigest }), /pinned blob hash does not match/);
  assert.equal(fs.existsSync(badDigest), false);

  fs.writeFileSync(path.join(checkout, 'catalog-v2.json'), '{\n  "catalog": "wrong ref"\n}\n');
  git(checkout, ['add', 'catalog-v2.json']);
  git(checkout, ['commit', '-qm', 'wrong ref']);
  const withheld = path.join(root, 'reports', 'withheld.json');
  assert.throws(() => materializePinnedGitBlob({ repo: checkout, ref: 'HEAD', commit, file: 'catalog-v2.json', sha256: hash(canonical), out: withheld }), /does not match pinned commit/);
  assert.equal(fs.existsSync(withheld), false);
});
