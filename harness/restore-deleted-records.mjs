#!/usr/bin/env node
// Restore every record that has EVER been committed and is now absent from the tree.
//
// ⛔ WHY THIS EXISTS. `git add <dir>` is `git add -A <dir>` in modern git: it stages DELETIONS of
// tracked files missing from the working tree. `publish-record.sh` keeps the runner's own records
// rather than resetting the working tree to origin, so every record another runner pushed after this
// runner's checkout was tracked on origin and absent locally — and got staged as a deletion. One
// publish commit was measured deleting 14 other runners' records while adding one of its own.
//
// That is fixed at source (the publish stages only its own path), but the deletions that already
// happened are still deletions. Nothing is LOST, because git keeps every blob ever committed — the
// records just are not in the current tree. This walks the history, finds every record path that
// existed at some point, and restores the ones missing now.
//
// ⛔ RESTORES THE NEWEST VERSION OF EACH PATH, which matters: a record can legitimately be rewritten
// (a re-measure after a fix, an instrument-failure retry), and resurrecting a stale one would put an
// OLD verdict back into the corpus while the queue believes the new one. `git log -1` per path gives
// the newest commit that touched it.
//
// Usage:
//   node harness/restore-deleted-records.mjs --dry-run     # report only
//   node harness/restore-deleted-records.mjs               # write the files back

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const DRY = argv.includes('--dry-run');
const REF = argv.includes('--ref') ? argv[argv.indexOf('--ref') + 1] : 'HEAD';

// ⛔ REJECT AN UNKNOWN ARGUMENT rather than falling through to a live run. `--help` used to be
// unrecognised, so asking this tool for help RAN IT — and with the enumeration below fixed that
// would have written files into the working tree instead of printing usage.
{
  const KNOWN = new Set(['--dry-run', '--ref']);
  const refIdx = argv.indexOf('--ref');
  const bad = argv.filter((a, i) => !KNOWN.has(a) && !(refIdx !== -1 && i === refIdx + 1));
  if (bad.length) {
    console.error(`unknown argument(s): ${bad.join(' ')}`);
    console.error('usage: restore-deleted-records.mjs [--dry-run] [--ref <ref>]');
    process.exit(2);
  }
}

const sh = (cmd) => execSync(cmd, { maxBuffer: 1 << 28 }).toString();

// Every record path that has ever appeared in the history of this ref.
//
// ⛔ `--no-renames` IS LOAD-BEARING, and without it this tool CANNOT SEE THE RECORDS IT EXISTS TO
// RECOVER. Records are same-schema JSON, so git's default rename detection happily pairs an
// unrelated deleted record with an unrelated added one and reports the pair as a single `R`:
//
//     R055  records/runs/darwin-arm64/@openrouter+sdk/0.12.9/results.json
//           records/runs/linux-x64/bootstrap-vue/2.23.1/results.json
//
// `R` is neither `A` nor `M`, so `--diff-filter=AM` dropped the path entirely and the tool reported
// "nothing to restore" while records were genuinely missing.
//
// THE TELL WAS PRINTED ON EVERY RUN AND NOBODY READ IT: "ever committed: 1774 / present: 1780".
// Ever-committed cannot be smaller than present-in-HEAD. That inversion IS the broken enumeration —
// measured on origin/main, and with `--no-renames` it becomes 1797 ever-committed and 17 missing.
const everSeen = new Set(
  sh(
    `git log ${REF} --no-renames --pretty=format: --name-only --diff-filter=AM -- 'records/**/results.json'`,
  )
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.endsWith('results.json')),
);

const present = new Set(
  sh(`git ls-tree -r ${REF} --name-only`)
    .split('\n')
    .filter((l) => l.endsWith('results.json')),
);

const missing = [...everSeen].filter((p) => !present.has(p));

console.log(`  record paths ever committed: ${everSeen.size}`);
console.log(`  present in ${REF}:            ${present.size}`);
console.log(`  MISSING (deleted):           ${missing.length}`);

if (!missing.length) {
  console.log('  nothing to restore');
  process.exit(0);
}

// ⛔ Group the report by verdict so a restore is not a blind bulk write — a run of restored
// HARNESS-* records would say something different about the corpus than a run of MINIMUMs.
const byVerdict = {};
const restored = [];
for (const p of missing) {
  // ⛔ --diff-filter=AM IS LOAD-BEARING. Without it, `git log -1 -- <path>` returns the commit that
  // DELETED the path — the newest commit touching it — and the file does not exist there, so every
  // single read fails with "does not exist in <sha>". Restricting to Add/Modify gives the last commit
  // where the record was actually present, which is the version to bring back.
  // ⛔ AND `--no-renames` FOR THE SAME REASON AS THE ENUMERATION ABOVE: without it the commit that
  // added this path can be reported as an `R` pairing it with an unrelated record, which `AM` drops,
  // so a path that IS in the missing list silently `continue`s and never gets restored.
  let sha;
  try {
    sha = sh(`git log -1 --format=%H --no-renames --diff-filter=AM ${REF} -- "${p}"`).trim();
  } catch {
    continue;
  }
  if (!sha) continue;
  let body;
  try {
    body = sh(`git show ${sha}:"${p}"`);
  } catch {
    continue;   // never actually present; nothing to bring back
  }
  let v = '(unparsed)';
  try { v = JSON.parse(body).verdict ?? '(none)'; } catch { /* keep the placeholder */ }
  byVerdict[v] = (byVerdict[v] || 0) + 1;
  restored.push({ p, body });
}

for (const [v, n] of Object.entries(byVerdict).sort((a, b) => b[1] - a[1])) {
  console.log(`      ${String(n).padStart(4)}  ${v}`);
}

if (DRY) {
  console.log('  --dry-run: nothing written');
  process.exit(0);
}

for (const { p, body } of restored) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, body);
}
console.log(`  restored ${restored.length} record(s) to the working tree`);
console.log('  now: git add records && git commit');
