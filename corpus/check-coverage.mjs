// Is the corpus COMPLETE against `corpus/packages.txt`, and if not, what should be dispatched?
//
// ⛔ COMPLETENESS IS RECORDS ON DISK. Nothing else counts — not a line in the list, not a green job, not
// a claim in a PR body. This reads the list, resolves each package's CURRENT latest version, and looks
// for a record. Everything it cannot find is a gap, and a gap is dispatchable work.
//
// ⛔⛔ WHY THE LIST HOLDS NAMES AND NOT VERSIONS, which is the design decision this file exists to
// enforce. Every catalog entry's `default` grant is generated from the package's LATEST, so a list that
// pinned versions would go stale the instant anything published and nothing would notice. Evaluating
// against today's latest instead means a new release AUTOMATICALLY opens a gap, and the coverage job
// automatically dispatches the re-measure. Freshness stops being a thing anyone has to remember.
//
// ⛔ THE RECURSION IS SAFE BY CONSTRUCTION, and it is the question a self-dispatching checker has to
// answer. Measurement runs commit records; records land in the repo; the checker reads records. So why
// does it not loop forever?
//   1. PATH FILTER. The dispatcher fires only on changes to `corpus/packages.txt` and `harness/**` —
//      never on `records-v2/**`. A results commit therefore cannot trigger a dispatch. This alone
//      breaks the cycle; the rest is belt.
//   2. THE CLAIM MECHANISM already prevents double-dispatch: a `claimed` queue row carries its run id,
//      and `make-queue.mjs` documents `pending`/`claimed`/`done` for exactly this.
//   3. IT IS MONOTONE. The gap set is a pure function of (list, records, today's latest) and every
//      measurement strictly shrinks it, so even a checker that re-ran on every commit converges rather
//      than thrashing.
//   4. RESULTS LAND AS A BOT PR, not a push to main — reviewable, and PR CI validates record shape
//      before it becomes evidence.
//
//   usage: node corpus/check-coverage.mjs [--json] [--platform macos|linux|windows]
//   exit 0 = complete for the requested platforms; exit 1 = gaps (listed on stdout)
import fs from 'node:fs';
import path from 'node:path';

export const PLATFORMS = ['macos', 'linux', 'windows'];

/** The record tree directory name each platform's records live under. */
const RECORD_DIR = { macos: 'darwin-arm64', linux: 'linux-x64', windows: 'win32-x64' };

/** Package names from the list, comments and blanks stripped. */
export function readList(text) {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

/** A scoped name's on-disk form: `@scope/name` is stored as `@scope+name`. */
export const recordSlug = (name) => name.replace('/', '+');

/** Does a committed record exist for this (package, version, platform)? */
export function hasRecord(root, name, version, platform, exists = fs.existsSync) {
  const dir = RECORD_DIR[platform];
  if (!dir) throw new Error(`unknown platform: ${platform}`);
  return exists(path.join(root, 'records-v2', 'runs', dir, recordSlug(name), version, 'results.json'));
}

/** The gap set: every (package, version, platform) the list demands and the records lack.
 *
 * `latestOf` is injected rather than reached for, so the unit tests never touch the network — a
 * coverage checker whose own tests need the registry is one that cannot run in a sandbox or offline,
 * and it would be tested against whatever the ecosystem published this morning.
 */
export async function gaps({ root, names, platforms, latestOf, exists = fs.existsSync }) {
  const out = [];
  const unresolved = [];
  for (const name of names) {
    let version;
    try {
      version = await latestOf(name);
    } catch (error) {
      // ⛔ AN UNRESOLVABLE NAME IS REPORTED, NEVER SILENTLY SKIPPED. A typo'd or unpublished line would
      // otherwise read as "covered" forever, which is the exact failure mode this file exists to stop.
      unresolved.push({ name, why: String(error?.message ?? error) });
      continue;
    }
    if (!version) { unresolved.push({ name, why: 'no latest version' }); continue; }
    for (const platform of platforms) {
      if (!hasRecord(root, name, version, platform, exists)) out.push({ name, version, platform });
    }
  }
  return { gaps: out, unresolved };
}
