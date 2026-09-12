import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { materializePinnedGitBlob } from './pinned-git-blob.mjs';

const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function convertedCheckout(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pinned-git-blob-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  // Git's config reader does not accept Windows' \\.\nul device spelling from os.devNull.
  const globalConfig = path.join(root, 'empty.gitconfig');
  fs.writeFileSync(globalConfig, '');
  assert.ok(fs.statSync(globalConfig).isFile());
  const cleanGitEnvironment = { ...process.env, GIT_CONFIG_GLOBAL: globalConfig, GIT_CONFIG_NOSYSTEM: '1' };
  const git = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', env: cleanGitEnvironment }).trim();
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

  execFileSync('git', ['clone', '-q', source, checkout], { env: cleanGitEnvironment });
  git(checkout, ['config', 'user.email', 'test@example.com']);
  git(checkout, ['config', 'user.name', 'Test']);
  git(checkout, ['config', 'core.autocrlf', 'true']);
  git(checkout, ['rm', '-q', '--cached', 'catalog-v2.json']);
  git(checkout, ['reset', '-q', '--hard', 'HEAD']);
  const checkoutBytes = fs.readFileSync(path.join(checkout, 'catalog-v2.json'));
  assert.notDeepEqual(checkoutBytes, canonical);
  assert.ok(checkoutBytes.includes(Buffer.from('\r\n')));
  return { root, checkout, canonical, commit, git, cleanGitEnvironment };
}

test('materializes exact blob bytes despite a CRLF-converted checkout and rejects a wrong ref', (t) => {
  const { root, checkout, canonical, commit, git } = convertedCheckout(t);

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

test('CLI materializes the canonical blob through a path that requires file-URL escaping', (t) => {
  const { root, checkout, canonical, commit, cleanGitEnvironment } = convertedCheckout(t);
  const toolDir = path.join(root, 'tool # directory');
  fs.mkdirSync(toolDir);
  const cli = path.join(toolDir, 'pinned-git-blob.mjs');
  fs.copyFileSync(fileURLToPath(new URL('./pinned-git-blob.mjs', import.meta.url)), cli);
  const out = path.join(root, 'reports', 'candidate-catalog-v2.json');
  const stdout = execFileSync(process.execPath, [
    cli, '--repo', checkout, '--ref', 'HEAD', '--commit', commit, '--path', 'catalog-v2.json', '--sha256', hash(canonical), '--out', out,
  ], { encoding: 'utf8', env: cleanGitEnvironment });
  assert.deepEqual(JSON.parse(stdout), { commit, path: 'catalog-v2.json', sha256: hash(canonical), bytes: canonical.length });
  assert.deepEqual(fs.readFileSync(out), canonical);
});
