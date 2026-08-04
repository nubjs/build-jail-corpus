#!/usr/bin/env node
// Which nub fixes has the corpus actually EXERCISED?
//
// ⛔ THE QUESTION THIS EXISTS TO ANSWER, because getting it wrong is the single most repeated
// error in this effort: "the fix didn't work" is almost always "the records predate the fix".
// A record carries `provenance.nubGitSha`, and a flat post-fix/pre-fix split is NOT good enough —
// the fixes land in a chain, so a sha can carry three of them and lack the fourth. Reading
// `00daf3b67a` as "post-fix" nearly produced a false refutation of the env-allowlist fix, which
// that sha predates entirely.
//
// So this resolves each record's sha against EACH named fix by real git ancestry
// (`git merge-base --is-ancestor`), and reports per-fix how many records could possibly have
// exercised it. A fix with 0 exercised records has not been tested, however many records exist.
//
// Usage, from a checkout of this repo, with a nub checkout to resolve ancestry against:
//   node harness/fix-coverage.mjs --nub ~/.cache/nub/worktrees/integ [--records records]
//
// FIXES is deliberately hand-maintained: a fix worth tracking is one whose effect you intend to
// read off the corpus, and that judgement is not derivable from the log.

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const FIXES = [
  { sha: '8f7d5adb67', name: 'AC\\Temp created' },
  { sha: '0d9c2c575b', name: 'DELETE on AC leaves' },
  { sha: '9c73c07337', name: 'tool-cache env allowlist' },
  { sha: 'ec15074bc2', name: 'stamped-env guard' },
];

const argv = process.argv.slice(2);
const arg = (k, d) => {
  const i = argv.indexOf(k);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : d;
};
const nubRepo = arg('--nub', process.env.NUB_REPO);
const recordsDir = arg('--records', 'records');

if (!nubRepo || !fs.existsSync(path.join(nubRepo, '.git'))) {
  console.error('need --nub <path-to-a-nub-checkout> (or NUB_REPO) to resolve ancestry');
  process.exit(2);
}

// Ancestry is asked of git ONCE per (fix, sha) pair and memoized — a corpus has thousands of
// records over a few dozen distinct shas, so the naive per-record call is ~100x the work.
const ancestryCache = new Map();
function carries(fixSha, recSha) {
  const key = `${fixSha} ${recSha}`;
  if (ancestryCache.has(key)) return ancestryCache.get(key);
  let out;
  try {
    execFileSync('git', ['merge-base', '--is-ancestor', fixSha, recSha], {
      cwd: nubRepo,
      stdio: 'ignore',
    });
    out = true;
  } catch {
    // Non-zero means "not an ancestor" OR "unknown sha" — both mean the record cannot be
    // credited with the fix, which is the conservative reading and the one we want.
    out = false;
  }
  ancestryCache.set(key, out);
  return out;
}

const records = [];
(function walk(d) {
  for (const e of fs.readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name === 'results.json') {
      try {
        records.push(JSON.parse(fs.readFileSync(p, 'utf8')));
      } catch {
        /* a half-written record during a live publish is expected, not an error */
      }
    }
  }
})(recordsDir);

const minimum = records.filter((r) => r.verdict === 'MINIMUM');
const isDisk = (r) => r.grant && r.grant.write === 'disk';
const platformOf = (r) => ((r.provenance || {}).platform || '?').toLowerCase();
const platforms = [...new Set(minimum.map(platformOf))].sort();

console.log(`records: ${records.length}  MINIMUM: ${minimum.length}\n`);

for (const fix of FIXES) {
  console.log(`${fix.sha}  ${fix.name}`);
  let anyExercised = 0;
  for (const p of platforms) {
    const rs = minimum.filter((r) => platformOf(r) === p);
    const ex = rs.filter((r) => {
      const s = (r.provenance || {}).nubGitSha;
      return s && carries(fix.sha, s);
    });
    anyExercised += ex.length;
    const d = ex.filter(isDisk).length;
    const rate = ex.length ? `${((100 * d) / ex.length).toFixed(1)}%` : '   - ';
    console.log(
      `    ${p.padEnd(13)} exercised ${String(ex.length).padStart(4)}/${String(rs.length).padStart(4)}   disk among exercised ${String(d).padStart(3)} = ${rate}`,
    );
  }
  // ⛔ The whole point: zero exercised records means the fix is UNTESTED by the corpus, no
  // matter how large the corpus is. Say so loudly rather than letting a 0.0% rate read as a win.
  if (anyExercised === 0) console.log('    ⛔ NOT EXERCISED BY ANY RECORD — this fix is untested');
  console.log();
}
