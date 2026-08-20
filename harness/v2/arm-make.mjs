// Which `make` an arm will build with — recorded, and upgraded when the box offers a newer one.
//
// ⛔ THE MEASURED CLASS IS SMALL AND ENTIRELY ONE PACKAGE, WHICH IS WORTH SAYING PLAINLY. All 13
// `GNU Make version is too old` records are `redis-memory-server`, 13 versions, darwin-arm64 only.
// It builds Redis modules from source (redisbloom, redisearch, rejson, redistimeseries) through
// RedisLabs' `deps/readies` build system, which refuses GNU Make 3.x outright.
//
// ⛔ macOS SHIPS GNU MAKE 3.81, FROM 2006, AND WILL NOT SHIP NEWER. Apple froze it at the last
// GPLv2 release. So this is not a runner that happens to be stale — every macOS box in the world
// has it, and any package whose build system requires Make 4 fails identically for every user on
// the platform. Whether that is a package defect or a provisioning gap is EXACTLY the question the
// corpus exists to answer, and it cannot be answered by a record that never says which make ran.
//
// ⛔ SO THE PRIMARY JOB HERE IS THE MARKER, NOT THE UPGRADE. Recording the make is provable now;
// provisioning a newer one is a CI change whose effect only a re-measure can show. Shipping the
// upgrade without the marker would repeat the era pin's original defect — a normalisation nobody
// can read back. `measure.sh` already argues this for the era Node: "normalisation that is RECORDED
// is a covered axis, normalisation that is INVISIBLE is a silent bet it did not matter."

/** Candidate `make` binaries, newest-first by convention rather than by probing every path.
 *
 *  `gmake` is what Homebrew and MacPorts install GNU Make 4 as, precisely because it must not
 *  shadow the system one. A box with no `gmake` simply reports its system make. */
export const MAKE_CANDIDATES = ['gmake', 'make'];

/** Parse `GNU Make 4.4.1` / `GNU Make 3.81` into a comparable major. Null when unrecognised —
 *  a non-GNU make (BSD) has no version to compare and must not be silently ranked. */
export function gnuMakeMajor(versionText) {
  const m = /GNU Make (\d+)\./.exec(String(versionText ?? ''));
  return m ? Number(m[1]) : null;
}

/** Choose the make an arm should use.
 *
 *  Returns `{ path, version, major, upgraded, marker }`. `upgraded` is true only when a candidate
 *  BEATS the system make, so the marker distinguishes "this box has a modern make" from "this box
 *  has 3.81 and the arm will build with it" — two records that must not read alike. */
export function chooseMake(candidates) {
  const ranked = candidates
    .filter((c) => c?.path)
    .map((c) => ({ ...c, major: gnuMakeMajor(c.version) }))
    .filter((c) => c.major !== null);
  if (!ranked.length) {
    return { path: null, version: null, major: null, upgraded: false, marker: 'ARM-MAKE NONE (no GNU make found)' };
  }
  const system = ranked.find((c) => c.path.endsWith('/make')) ?? ranked[ranked.length - 1];
  const best = ranked.reduce((a, b) => (b.major > a.major ? b : a));
  const upgraded = best.path !== system.path && best.major > system.major;
  return {
    path: best.path,
    version: best.version,
    major: best.major,
    upgraded,
    marker: upgraded
      ? `ARM-MAKE ${best.path} (GNU Make ${best.major}) — upgraded from the system ${system.version}`
      : `ARM-MAKE ${best.path} (${best.version}) — the system make; a build needing GNU Make 4 WILL fail here`,
  };
}

if (import.meta.filename === process.argv[1]) {
  const { execFileSync } = await import('node:child_process');
  const sh = (s) => { try { return execFileSync('/bin/sh', ['-c', s], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; } };
  const candidates = MAKE_CANDIDATES
    .map((n) => { const p = sh(`command -v ${n}`); return p ? { path: p, version: sh(`"${p}" --version 2>&1 | head -1`) } : null; })
    .filter(Boolean);
  const chosen = chooseMake(candidates);
  process.stdout.write(`${chosen.path ?? ''}\n${chosen.marker}\n`);
}
