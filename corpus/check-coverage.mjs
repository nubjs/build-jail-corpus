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

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────────
//
// The only place that touches the network. Everything above takes `latestOf` as a parameter precisely
// so the unit tests never reach the registry — a coverage checker whose own tests need npm cannot run
// offline, and it would be tested against whatever the ecosystem published that morning.

/** Today's `latest` for one package, straight from the registry. */
async function latestFromRegistry(name) {
  // The abbreviated document is a fraction of the full packument and carries `dist-tags`, which is all
  // this needs. Asking for the full metadata of 784 packages would move hundreds of megabytes.
  const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
    headers: { accept: 'application/vnd.npm.install-v1+json' },
  });
  if (!res.ok) throw new Error(`registry ${res.status}`);
  const body = await res.json();
  return body?.['dist-tags']?.latest ?? null;
}

if (import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1] ?? '').href) {
  const argv = process.argv.slice(2);
  const asJson = argv.includes('--json');
  const only = argv.includes('--platform') ? [argv[argv.indexOf('--platform') + 1]] : PLATFORMS;
  for (const p of only) {
    if (!PLATFORMS.includes(p)) {
      console.error(`unknown --platform ${p}; expected one of ${PLATFORMS.join(', ')}`);
      process.exit(2);
    }
  }
  const root = path.resolve(import.meta.dirname, '..');
  const names = readList(fs.readFileSync(path.join(root, 'corpus', 'packages.txt'), 'utf8'));

  // ⛔ BOUNDED CONCURRENCY, and a failure resolves to `unresolved` rather than killing the run. 784
  // sequential round-trips would take minutes; 784 parallel ones get rate-limited, and a rate-limit
  // read as "no latest version" would report real packages as unresolvable — a false gap, which sends
  // the dispatcher after work that does not exist.
  const cache = new Map();
  let cursor = 0;
  const latestOf = async (name) => {
    if (cache.has(name)) {
      const hit = cache.get(name);
      if (hit instanceof Error) throw hit;
      return hit;
    }
    try {
      const v = await latestFromRegistry(name);
      cache.set(name, v);
      return v;
    } catch (error) {
      cache.set(name, error);
      throw error;
    }
  };
  const workers = Array.from({ length: 8 }, async () => {
    while (cursor < names.length) {
      const name = names[cursor++];
      try { await latestOf(name); } catch { /* recorded in the cache; `gaps` reports it */ }
    }
  });
  await Promise.all(workers);

  const { gaps: found, unresolved } = await gaps({ root, names, platforms: only, latestOf });
  if (asJson) {
    console.log(JSON.stringify({ platforms: only, packages: names.length, gaps: found, unresolved }, null, 2));
  } else {
    console.log(`packages ${names.length}   platforms ${only.join(',')}`);
    console.log(`gaps ${found.length}   unresolvable ${unresolved.length}`);
    for (const u of unresolved.slice(0, 20)) console.log(`  UNRESOLVED ${u.name} — ${u.why}`);
    for (const g of found.slice(0, 40)) console.log(`  GAP ${g.name}@${g.version} ${g.platform}`);
  }
  // Non-zero when incomplete, so the job fails loudly rather than reporting a gap set nobody reads.
  process.exit(found.length || unresolved.length ? 1 : 0);
}
