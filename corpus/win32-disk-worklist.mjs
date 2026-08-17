// Which whole-disk write grants exist ONLY because a win32 record asked for them?
//
// ⛔⛔ WHY THIS MATTERS MORE THAN ITS SIZE SUGGESTS. `write: "disk"` is the widest capability the jail
// hands out — it is the one grant that makes confinement nearly meaningless for the package holding it.
// And on Windows it is worse than wide: a full-disk grant cannot be rendered inside an AppContainer, so
// the backend DECLINES the LowBox token, and because egress is an AppContainer capability the child
// loses NETWORK confinement too. A win32 whole-disk grant is therefore not "a loose filesystem policy";
// it is no filesystem policy and no network policy at all.
//
// ⛔ THE TELL THAT ONE IS AN ARTIFACT: the SAME package at the SAME version was measured needing far
// less on macOS and Linux. A package that genuinely needs the whole disk needs it because of what its
// install script does, and install scripts are not usually that platform-specific. So a
// disk-on-win32-only row is evidence about the HARNESS — most likely a descent that failed to narrow —
// rather than about the package, and each one is a candidate to re-measure and narrow.
//
// ⛔ IT DOES NOT NARROW ANYTHING ITSELF, AND THAT RESTRAINT IS THE POINT. An unverified NARROW grant is
// the UNDER-granting direction, which is the direction that breaks real installs — a package that
// silently loses a capability it needed fails at install time on a user's machine. So this emits a
// re-measure WORKLIST with each row's POSIX grant as the candidate target, and the narrowing lands only
// once a win32 record measures it. Hand-editing a grant from this output would be the exact mistake the
// catalog's provenance rules exist to prevent.
//
// ⛔⛔ AND WHEN THE RE-MEASURE RUNS, AN EXIT CODE IS NOT ENOUGH TO NARROW ON. Measured directly: with
// `network` stripped from `gifsicle@4.0.1`'s grant — a fresh HOME and cache, so no promoted cache could
// satisfy it — the install still returned rc=0. The log says why: `⚠ gifsicle pre-build test failed`
// then `✔ gifsicle built successfully`. The download WAS denied and the package fell back to compiling
// from source, which needs no network. So "it succeeded at the narrower grant" can mean a fallback
// absorbed the denial and silently traded a binary download for a source build — slower, and dependent
// on a C toolchain that is not always present. A grant narrowed on exit code alone can break on a
// machine without a compiler while every measurement said it was fine. Judge a narrowing by the ARTIFACT
// GATE, which is exactly what that gate exists for.
//
//   usage: node corpus/win32-disk-worklist.mjs --catalog <path> [--json] [--queue]
import fs from 'node:fs';
import path from 'node:path';

/** Record-tree directory per platform. */
export const PLATFORM_DIRS = { macos: 'darwin-arm64', linux: 'linux-x64', windows: 'win32-x64' };

/** `@scope/name` is stored `@scope+name`. */
export const recordSlug = (name) => name.replace('/', '+');

/** Is this grant a whole-disk WRITE?
 *
 * `write` takes exactly two shapes in the catalog — the string `"disk"` or an object of per-scope
 * booleans — verified across every entry, so the string test is complete rather than a heuristic.
 */
export const isWholeDisk = (grant) => !!grant && grant.write === 'disk';

/** Every package carrying a whole-disk grant anywhere in its entry: the default, or any version band.
 *
 * ⛔ VERSION BANDS ARE SEARCHED TOO, AND MISSING THEM UNDERCOUNTS BY MOST OF THE SET. Measured on the
 * shipped catalog: 13 whole-disk grants sit on a `default` and 21 inside bands, so a scan of defaults
 * alone would report a third of the problem and look thorough doing it.
 */
export function wholeDiskPackages(catalog) {
  const out = new Set();
  for (const [name, entry] of Object.entries(catalog?.packages ?? {})) {
    const consider = (g) => { if (isWholeDisk(g)) out.add(name); };
    consider(entry.default);
    for (const os of ['macos', 'linux', 'win']) consider(entry[os]);
    for (const banded of Object.values(entry.versions ?? {})) {
      // A band is either a grant or a `{default, <os>}` group; both shapes appear.
      consider(banded?.default ?? banded);
      for (const os of ['macos', 'linux', 'win']) consider(banded?.[os]);
    }
  }
  return [...out].sort();
}

/** Every measured grant for one package, per platform, from the record tree. */
export function recordedGrants({ root, name, exists = fs.existsSync, readdir = fs.readdirSync, read = fs.readFileSync }) {
  const per = {};
  for (const [platform, dir] of Object.entries(PLATFORM_DIRS)) {
    const base = path.join(root, 'records-v2', 'runs', dir, recordSlug(name));
    if (!exists(base)) continue;
    for (const version of readdir(base)) {
      const file = path.join(base, version, 'results.json');
      if (!exists(file)) continue;
      let record;
      try { record = JSON.parse(read(file, 'utf8')); } catch { continue; }
      // A record with no grant measured nothing to compare — a refusal, a timeout, a package nothing
      // installs. Including it as "did not need disk" would manufacture an artifact finding.
      if (!record.grant) continue;
      (per[platform] ??= []).push({ version, grant: record.grant, verdict: record.verdict });
    }
  }
  return per;
}

/** Classify one package's records: is its whole-disk grant win32-only? */
export function classify(per) {
  const demanded = (platform) => (per[platform] ?? []).some((r) => isWholeDisk(r.grant));
  const measured = (platform) => (per[platform] ?? []).length > 0;
  if (!measured('windows')) return { verdict: 'no-win32-record', posixNarrow: [] };
  if (!demanded('windows')) return { verdict: 'win32-did-not-ask', posixNarrow: [] };
  if (demanded('macos') || demanded('linux')) return { verdict: 'posix-needs-disk-too', posixNarrow: [] };

  // The artifact candidate. Carry the POSIX grants for the SAME versions win32 called disk, because a
  // re-measure needs a target and "something narrower" is not one.
  const diskVersions = new Set((per.windows ?? []).filter((r) => isWholeDisk(r.grant)).map((r) => r.version));
  const posixNarrow = [];
  for (const platform of ['macos', 'linux']) {
    for (const r of per[platform] ?? []) {
      // ⛔ A NULL GRANT IS NOT A NARROWING TARGET, AND FILTERING IT HERE RATHER THAN ONLY IN THE READER
      // IS THE FAIL-SAFE. A refusal, a timeout, or a package nothing installs measures no grant; reading
      // that absence as "this platform managed without the disk" manufactures an artifact finding out of
      // a missing measurement, and it would aim a re-measure at `null`. The reader already drops these,
      // so this is defence in depth for the one function a future caller is most likely to reach for on
      // its own.
      if (r.grant && diskVersions.has(r.version)) {
        posixNarrow.push({ platform, version: r.version, grant: r.grant });
      }
    }
  }
  return {
    verdict: posixNarrow.length ? 'win32-only-with-posix-target' : 'win32-only-no-posix-overlap',
    posixNarrow,
    diskVersions: [...diskVersions],
  };
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const arg = (k) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : undefined);
  const catalogPath = arg('--catalog');
  if (!catalogPath) {
    console.error('usage: win32-disk-worklist.mjs --catalog <path> [--json] [--queue]');
    process.exit(2);
  }
  const root = path.resolve(import.meta.dirname, '..');
  const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'));
  const names = wholeDiskPackages(catalog);

  const rows = names.map((name) => ({ name, ...classify(recordedGrants({ root, name })) }));
  const buckets = {};
  for (const r of rows) (buckets[r.verdict] ??= []).push(r);

  if (argv.includes('--queue')) {
    // Queue rows for the win32 re-measure, in `make-queue`'s shape. Emitted rather than appended: the
    // claim mechanism belongs to the runner, and this script has no business writing the queue.
    for (const r of buckets['win32-only-with-posix-target'] ?? []) {
      for (const version of r.diskVersions) {
        console.log(JSON.stringify({ pkg: r.name, version, os: 'windows', status: 'pending' }));
      }
    }
  } else if (argv.includes('--json')) {
    console.log(JSON.stringify({ total: names.length, buckets }, null, 2));
  } else {
    console.log(`whole-disk packages in the catalog: ${names.length}`);
    for (const [verdict, list] of Object.entries(buckets).sort()) {
      console.log(`  ${verdict}: ${list.length}`);
    }
    console.log('\nnarrowing candidates (win32 asked for disk, POSIX measured less at the same version):');
    for (const r of buckets['win32-only-with-posix-target'] ?? []) {
      const target = r.posixNarrow.map((p) => `${p.platform}@${p.version} ${JSON.stringify(p.grant)}`)[0];
      console.log(`  ${r.name}  win32 disk at ${r.diskVersions.join(', ')}  →  ${target}`);
    }
  }
}
