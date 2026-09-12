// Materialize a pinned repository blob without inheriting checkout line-ending conversion.
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function requireCommit(commit) {
  if (!/^[0-9a-f]{40}$/i.test(commit ?? '')) throw new Error('commit must be a 40-hex commit');
  return commit.toLowerCase();
}

function requirePath(file) {
  if (!file || path.posix.isAbsolute(file) || file.includes('\\') || file.split('/').some((part) => !part || part === '.' || part === '..')) {
    throw new Error('path must be a safe repository-relative path');
  }
  return file;
}

function git(repo, args) {
  return execFileSync('git', ['-C', repo, ...args], { encoding: 'buffer' });
}

export function materializePinnedGitBlob({ repo, ref, commit, file, sha256: expectedSha256, out }) {
  const expectedCommit = requireCommit(commit);
  const candidatePath = requirePath(file);
  if (!/^[0-9a-f]{64}$/i.test(expectedSha256 ?? '')) throw new Error('sha256 must be a 64-hex digest');
  if (!repo || !ref || !out) throw new Error('repo, ref, and out are required');

  const actualCommit = git(repo, ['rev-parse', `${ref}^{commit}`]).toString('utf8').trim().toLowerCase();
  if (actualCommit !== expectedCommit) throw new Error(`repository ref does not match pinned commit: ${actualCommit}`);
  const bytes = git(repo, ['cat-file', 'blob', `${expectedCommit}:${candidatePath}`]);
  const actualSha256 = sha256(bytes);
  if (actualSha256 !== expectedSha256.toLowerCase()) {
    throw new Error(`pinned blob hash does not match: expected ${expectedSha256}, got ${actualSha256}`);
  }
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, bytes);
  return { commit: actualCommit, path: candidatePath, sha256: actualSha256, bytes: bytes.length };
}

function cli(argv) {
  const option = (name) => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
  const result = materializePinnedGitBlob({
    repo: option('--repo'), ref: option('--ref'), commit: option('--commit'), file: option('--path'), sha256: option('--sha256'), out: option('--out'),
  });
  console.log(JSON.stringify(result));
}

const invokedPath = process.argv[1] && (() => {
  try { return fs.realpathSync(process.argv[1]); } catch { return path.resolve(process.argv[1]); }
})();
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`PINNED-GIT-BLOB-ERROR ${error.message}`); process.exitCode = 2; }
}
