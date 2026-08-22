// Which Python an era arm's node-gyp needs — because node-gyp's Python requirement INVERTED across
// the range the matrix now carries, and getting it wrong fails in both directions.
//
// ⛔ MEASURED, on this box, reading node-gyp's own words rather than recalling them:
//
//   node v4.9.1  npm 2.15.11  node-gyp 3.4.0   PYTHON unset  -> Can't find Python executable "python"
//   node v6.17.1 npm 3.10.10  node-gyp 3.4.0   PYTHON unset  -> Can't find Python executable "python"
//   node v8.17.0 npm 6.13.4   node-gyp 5.0.5   PYTHON unset  -> rc=0   (finds /usr/bin/python3)
//
//   node v4.9.1  PYTHON=/usr/bin/python3 (3.9.6)
//     -> Python executable "/usr/bin/python3" is v3.9.6, which is not supported by gyp.
//        You can pass the --python switch to point to Python >= v2.5.0 & < 3.0.0.
//   node v4.9.1  PYTHON=/usr/local/bin/python2 (2.7.9)  -> rc=0, heapdump@0.3.9 BUILDS
//
// ⛔ THE FIRST ERROR IS A NAME PROBLEM MASKING A VERSION REQUIREMENT, AND IT COST A WRONG DIAGNOSIS.
// `Can't find Python executable "python"` reads as "put something called python on PATH" — and macOS
// removed `/usr/bin/python` entirely, so the name really is absent. But satisfying the NAME with a
// python3 does not satisfy gyp: node-gyp 3.x hard-rejects >= 3.0.0. Only the second experiment,
// pointing PYTHON at each version in turn, distinguishes the two.
//
// ⛔ SO THIS MUST BE ERA-CONDITIONAL, NEVER A BLANKET EXPORT. Setting PYTHON to a 2.7 for a modern
// arm breaks it exactly as hard in the other direction — node-gyp 9+ requires Python 3. An
// unconditional `PYTHON=python2` would trade 39 broken records for a far larger number.
//
// 39 records in the BROKEN-* buckets are native builds whose era is Node 6 or older, so they are the
// population this decides: abstract-socket, cld, farmhash, ffi, fs-xattr, hashring, heapdump,
// hiredis, libpq, lzma-native, and the rest.

/** The last era major whose bundled node-gyp is the Python-2-only 3.x/4.x family.
 *
 *  ⛔ MEASURED AT 4, 6 AND 8; 5 AND 7 ARE INTERPOLATED and the interpolation is stated rather than
 *  hidden. Node 5 ships npm 3.x and Node 7 ships npm 4.x, both of which carry the same node-gyp 3
 *  family as the measured 4 and 6. If a record ever shows a 5 or 7 arm failing on Python, this
 *  boundary is the first thing to re-measure. */
export const LAST_PYTHON2_ERA = 7;

/** What `pythonForEra` reports when it cannot satisfy the requirement. */
export const UNSATISFIED = null;

/** The last era whose bundled node-gyp cannot run on a MODERN Python 3.
 *
 *  ⛔ MEASURED, NOT RECALLED. In the 2026-08-22 sweep, 55 CONFIRMED rows died inside gyp itself on a
 *  perfectly healthy python3 — 24 at era 8, 15 at 10, 10 at 12, 6 at 14, and NONE at 16 or above:
 *    AttributeError: module 'collections' has no attribute 'MutableMapping'   (removed in Python 3.10)
 *    ValueError: invalid mode: 'rU' while trying to load binding.gyp          (removed in Python 3.11)
 *  Treating "python3" as one family is what produced them: the selector saw a 3.x, called the
 *  requirement satisfied, and handed old gyp an interpreter it cannot parse its own source with. */
export const LAST_PYTHON39_ERA = 14;

/** Which Python family an era major's node-gyp accepts. `python3-legacy` means a 3.x no NEWER than
 *  3.9 — a distinct requirement from python2, and one a bare "is it 3.x?" test cannot express. */
export function pythonFamilyForEra(major) {
  if (!Number.isInteger(major)) return 'python3';
  if (major <= LAST_PYTHON2_ERA) return 'python2';
  return major <= LAST_PYTHON39_ERA ? 'python3-legacy' : 'python3';
}

/** Pick the interpreter for an era arm.
 *
 *  `candidates` is an ordered list of `{ path, version }` the caller discovered, so this stays a pure
 *  decision and the probing lives with the driver. Returns `{ family, path, marker }`; `path` is null
 *  when nothing on the box satisfies the family, and the marker SAYS so — a silently-unset PYTHON is
 *  how these 39 records came to look like package defects in the first place. */
export function pythonForEra(major, candidates = []) {
  const family = pythonFamilyForEra(major);
  const wantMajor = family === 'python2' ? 2 : 3;
  // A legacy era needs 3.x AND <= 3.9; anything newer removed the stdlib names old gyp reads.
  const ceiling = family === 'python3-legacy' ? 9 : Infinity;
  const hit = candidates.find((c) => {
    const m = /(\d+)\.(\d+)/.exec(String(c.version ?? ''));
    return m && Number(m[1]) === wantMajor && Number(m[2]) <= ceiling;
  });
  if (!hit) {
    return {
      family,
      path: UNSATISFIED,
      marker: `ERA-PYTHON NOT-SATISFIED (era Node ${major} needs ${family}; none of ${candidates.length} candidate(s) matched)`,
    };
  }
  return {
    family,
    path: hit.path,
    marker: `ERA-PYTHON ${hit.path} (${hit.version}) for era Node ${major}, whose node-gyp requires ${family}`,
  };
}

/** Interpreter names worth probing, most specific first.
 *
 *  ⛔ `python` IS PROBED LAST AND ON PURPOSE. It is the name node-gyp 3.x asks for, but on a modern
 *  box it is either absent (macOS removed it) or a PYTHON 3 wearing the old name — and a python3
 *  under that name is exactly what produces gyp's "is v3.9.6, which is not supported" rejection. The
 *  VERSION decides, never the name, so the probe reports what each candidate actually says. */
// Ordered oldest-first so a legacy era finds its ceiling-satisfying interpreter before the
// newest python3 on the box. `python3.9`/`python3.8` are named explicitly because a runner that
// has them installed alongside a modern default exposes them ONLY under the versioned name.
export const PROBE_NAMES = ['python2.7', 'python2', 'python3.8', 'python3.9', 'python3', 'python'];

/** Discover interpreters on this box. `run` is injected so the decision stays testable offline. */
export function discoverPythons(run, names = PROBE_NAMES) {
  const out = [];
  const seen = new Set();
  for (const name of names) {
    const found = run(name);
    if (!found?.path || seen.has(found.path)) continue;
    seen.add(found.path);
    out.push(found);
  }
  return out;
}

if (import.meta.filename === process.argv[1]) {
  const { execFileSync } = await import('node:child_process');
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? undefined : process.argv[i + 1]; };
  const era = Number(arg('era'));
  // ⛔ NEVER `shell: true` WITH AN ARGS ARRAY. It emits a DeprecationWarning on stderr, which the
  // shell drivers capture into `driver.out` alongside the marker — noise in the one file a reader
  // uses to tell a package defect from a toolchain gap. `/bin/sh -c` invoked directly is the same
  // capability with none of that.
  const sh = (script) => {
    try { return execFileSync('/bin/sh', ['-c', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
    catch { return ''; }
  };
  const probe = (name) => {
    const path = sh(`command -v ${name}`);
    if (!path) return null;
    // ⛔ REDIRECT STDERR INTO STDOUT. Python 2 prints `--version` to STDERR and Python 3 to stdout.
    // Reading only stdout reports every python2 as version-less, so the version match fails and the
    // box looks like it has no python2 — dropping the exact candidate this exists to find.
    const version = sh(`"${path}" --version 2>&1`);
    return version ? { path, version } : null;
  };
  // An interpreter the CALLER provisioned wins the search. A legacy era needs a Python no newer than
  // 3.9 and no runner ships one by default, so CI installs it off-PATH and passes the path in —
  // setup-python exposes it as `python3`, never as `python3.9`, so name-probing alone misses it.
  const injected = process.env.ERA_PYTHON_LEGACY
    ? [probe(process.env.ERA_PYTHON_LEGACY)].filter(Boolean) : [];
  const candidates = [...injected, ...discoverPythons(probe)]
    .filter((c, i, all) => all.findIndex((o) => o.path === c.path) === i);
  const chosen = pythonForEra(Number.isInteger(era) ? era : null, candidates);
  process.stdout.write(`${chosen.path ?? ''}\n${chosen.marker}\n`);
}
