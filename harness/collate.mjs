// Turn a directory of per-package run records into a v2 build-jail catalog.
//
// The catalog is COLLATED from measurements, never edited in place. One record per
// package@version means a single package can be re-measured without disturbing anything else,
// and this step is pure: it reads records and writes a catalog, so it can be re-run at any time
// and produces the same file from the same inputs.
//
// Usage:
//   node collate.mjs [--runs <dir>] [--baseline <file>] [--out <file>] [--platform <p>]
//                    [--only-platform <p>]   keep only records whose PROVENANCE names <p>
//
// `--baseline` names a JSON file carrying the `baseline` and `env` arrays. Those are NOT
// measured — they are the floor every jailed script gets — so they are authored once and merged
// in here rather than being derived from any package's record.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
// The state space, for reconstructing a grant a record never serialised — see the backfill below.
import { STATES, grantForState } from './states.mjs';
import { computeHarnessIdentity, loadInvalidationPolicy } from './v2/instrument.mjs';
import { recordValidity } from './v2/record-validity.mjs';
// The falsifiability rule, IMPORTED rather than restated — see `narrowingEvidence`'s own header for
// why a second copy of a three-term rule is how the two consumers drift apart.
import { narrowingEvidence, narrows } from './v2/publish-guard.mjs';

const argv = process.argv.slice(2);
const opt = (name, dflt) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : dflt);
// `new URL(...).pathname` yields `/D:/...` on Windows, which resolves to `D:\D:\...`.
// fileURLToPath is the only correct conversion; identical on POSIX.
const here = path.dirname(fileURLToPath(import.meta.url));

// Several --runs may be given: the catalog is reconciled from runs on different machines and
// operating systems, so merging result sets is the normal case, not an edge one.
const RUNS_DIRS = argv.reduce((acc, a, i) => (a === '--runs' ? [...acc, argv[i + 1]] : acc), []);
const RUNS = RUNS_DIRS.length ? RUNS_DIRS : [path.join(here, 'results', 'runs')];
const PLATFORM_FILTER = opt('--only-platform', null);
const BASELINE = opt('--baseline', path.join(here, 'baseline.json'));
// OUTSIDE `results/`, which is gitignored. The raw run records and per-cell logs are
// regenerable measurements and large — ~236K per package, so ~127 MB for a 550-package corpus
// on one platform and ~380 MB across three — but the COLLATED CATALOG is the deliverable and
// belongs in the repo. Defaulting it into the ignored tree would have quietly kept the one
// artefact that matters out of version control.
const OUT = opt('--out', path.join(here, 'catalog-v2.json'));
const PLATFORM = opt('--platform', null);
const OVERRIDES = opt('--overrides', path.join(here, 'overrides'));
const STRICT = argv.includes('--strict');
// Omit the two provenance sections that are DERIVABLE FROM THE RECORDS, for the copy that ships.
//
// MEASURED 2026-08-16 on the 294-package catalog: `packages` — the entire policy nub reads — is 62 KB,
// while `provenance` is 4,405 KB of which `runtimeCells` is 4,055 KB and `resolvedTreeDigests` 349 KB.
// So 98.6% of the shipped file is provenance, it DOUBLED as the corpus grew (2.0 MB -> 4.0 MB) while
// the grants SHRANK, and it grows with every future re-bake.
//
// ⛔ AND NO RUST CODE READS ANY OF IT. `catalog_v2::parse` consumes only `packages`, `env` and
// `baseline` from the root; `runtimeCells` and `resolvedTreeDigests` appear nowhere in `crates/**`.
// `catalog_override.rs` embeds the file with `include_str!`, so every byte is compiled into every nub
// binary regardless.
//
// WHAT THIS KEEPS IS THE AUDIT ANCHOR, NOT A SUMMARY OF IT: `recordsSha256` hashes every record's
// path and bytes, so with the records in hand you can still prove which measurements produced this
// catalog — and `runtimeCells`/`resolvedTreeDigests` are themselves computed from those same records,
// so they add no verifiability the anchor does not already carry. Dropping a derivable projection is
// not dropping evidence. The corpus's own catalog keeps the full block; only the shipped copy is slim.
const SLIM_PROVENANCE = argv.includes('--slim-provenance');
// ── `--prior`: the SHIPPED catalog, as a FLOOR under the two narrowing gates ───────────────────
//
// ⛔ WHY A REGENERATION NEEDS A FLOOR AT ALL, AND WHY IT IS NOT PARANOIA. This generator is a pure
// function of the records it is handed, so a platform the corpus has not RE-measured under the
// current instrument contributes nothing — and contributing nothing reads, everywhere downstream,
// as "needs nothing". MEASURED 2026-09-01 against the shipped 294-package catalog: 0 of 2,270
// win32 records are valid at the epoch the invalidation policy pins (macOS 1430/2293, linux
// 1531/2324), so a regeneration narrows 107 of 131 wide Windows cells on the strength of no
// Windows evidence whatsoever. Under-granting is the ONE direction this project forbids, because
// its symptom is a package that simply fails to install.
//
// So a narrowing is only ever published where the platform actually reported, and where what it
// reported COULD have gone red. Two gates, both armed by this flag, both applying only to the
// NARROWING direction:
//
//   Gate 1 — coverage.       No valid record for this package on this platform ⇒ that platform
//                            keeps the shipped grant. Silence is not evidence.
//   Gate 2 — falsifiability. A valid record whose arms could not have failed is not evidence
//                            either. The rule is `publish-guard.mjs`'s, imported.
//
// ⛔ THE FLOOR IS A UNION, NEVER A PIN, and that is what makes the gates unable to do harm: a
// gated platform is given `max(measured, shipped)`, so arming them can only ever WIDEN a cell
// relative to what the ungated generator would have written. Widening cannot break an install.
//
// ⛔ AND THEY ARE INERT WITHOUT `--prior`, DELIBERATELY. "Narrower" is meaningless without a
// baseline to be narrower THAN; a first-ever collation has none and must not be second-guessed by
// a gate that has nothing to compare against.
const PRIOR_PATH = opt('--prior', null);

// ⛔ REFUSE AN UNRECOGNISED FLAG — THIS SCRIPT BUILDS THE SHIPPED CATALOG. Every option above falls
// back to a default, so a typo'd or wrong-script flag is silently ignored and the default is used
// instead. MEASURED 2026-08-05: invoking this with `--records <dir>` (the flag its sibling
// verify-corpus.mjs takes) read the DEFAULT empty path, printed `records read 0`, wrote a catalog with
// ZERO entries, and EXITED 0. A green run that produced an empty deliverable is the worst possible
// failure for this particular script.
//
// verify-corpus.mjs already refuses unknown flags for exactly this reason — "a gate that tolerates
// unrecognised input cannot be trusted to report on anything" — and this is the same hazard with a
// larger blast radius, so it gets the same treatment rather than a comment warning readers to be
// careful.
{
  const KNOWN = new Set(['--runs', '--only-platform', '--baseline', '--out', '--platform', '--overrides', '--strict',
    '--slim-provenance', '--prior']);
  const unknown = argv.filter(
    (a, i) => a.startsWith('--') && !KNOWN.has(a) && !(i > 0 && KNOWN.has(argv[i - 1])),
  );
  if (unknown.length) {
    console.error(`COLLATE REFUSED: unknown flag(s): ${unknown.join(', ')}`);
    console.error(`  known flags: ${[...KNOWN].join(', ')}`);
    console.error('  Refusing rather than ignoring them: every flag here has a DEFAULT, so an ignored');
    console.error('  one silently collates the wrong tree — and an empty catalog exits 0 and looks fine.');
    process.exit(2);
  }
}

// ⛔ REFUSE A `--prior` THAT IS NOT A CATALOG, rather than reading `undefined` as "no floor". The
// whole value of the flag is that it makes an under-grant impossible, so a silently-empty floor is
// the one failure mode that would leave the gates present and inert — the shape this file already
// pays for elsewhere (`capsKey(dflt) === '{}'`, the `caps()` override comparison).
const PRIOR = PRIOR_PATH ? JSON.parse(fs.readFileSync(PRIOR_PATH, 'utf8')) : null;
if (PRIOR && (!PRIOR.packages || typeof PRIOR.packages !== 'object'
  || !Object.keys(PRIOR.packages).length)) {
  console.error(`COLLATE REFUSED: --prior ${PRIOR_PATH} carries no non-empty \`packages\` object.`);
  console.error('  An empty floor would arm both narrowing gates and let every one of them pass.');
  process.exit(2);
}

// ── read ──────────────────────────────────────────────────────────────────────

const records = [];
const recordInputs = [];
/** Every record under `dir`, at any depth. Records are partitioned
 *  `<platform>/<package>/<version>/results.json`, so this walks rather than lists — and it still
 *  reads a FLAT directory, which keeps older result sets collatable. */
function walk(dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(full));
    // ONLY `results.json`. A version directory holds the record plus every cell's log, and
    // a future artefact dropped beside them must not silently become a record.
    else if (e.name === 'results.json') out.push(full);
  }
  return out;
}

for (const [root, full] of RUNS.flatMap((d) => walk(d).map((f) => [d, f]))) {
  const f = path.relative(root, full);
  try {
    const bytes = fs.readFileSync(full);
    const rec = { file: f, ...JSON.parse(bytes.toString('utf8')) };
    // The platform is the top directory level, but the record's own provenance is the
    // authority — a file moved between directories must not silently change platform.
    if (PLATFORM_FILTER && rec.provenance?.platform !== PLATFORM_FILTER) continue;
    // ⛔ BACKFILL A GRANT THAT WAS NEVER SERIALISED, rather than discarding the record.
    //
    // `grantFor` returned `undefined` for every non-empty state until b5d6898f82 (an `arr[0]` read
    // of an object, left over from the retired array shape), so ~2,500 records across three
    // platforms carry `state` — a human label — and no `grant`. Everything downstream keys on
    // `grant`: `grantKey` bands on it, `capsKey` compares it, `unionGrant` widens off its axes. So
    // without this the whole existing corpus collates into one `null` band and emits a catalog with
    // no capabilities.
    //
    // The reconstruction is EXACT, not a guess. `STATES` is an exhaustive `read x write x network`
    // product and each state's `label` is built deterministically from its cost atoms
    // (`costAtoms.join(' + ')`), so a label names exactly one state, and `grantFor` maps that state
    // to its grant. That is why these records need re-COLLATION and not re-measurement — hours of
    // installs preserved.
    //
    // Only ever fills a MISSING grant; a record that has one is never touched.
    if (!rec.grant && typeof rec.state === 'string' && rec.state !== '(nothing)') {
      const st = STATES.find((s) => s.label === rec.state);
      if (st) {
        rec.grant = grantForState(st);
        rec.grantBackfilled = true;
      } else {
        console.error(`  WARN ${f}: state "${rec.state}" matches no known state — grant not recovered`);
      }
    }
    records.push(rec);
    recordInputs.push({ path: f.split(path.sep).join('/'), bytes });
  } catch (e) { console.error(`  SKIP ${f}: ${e.message}`); }
}

// PROVENANCE IS A GATE, NOT A FOOTNOTE. A results directory silently mixes methodologies when
// records span harness revisions — a filter change once moved nine packages between grants with
// no binary change at all. Collating across two harnesses produces a catalog no single
// experiment ever produced, so the mix is reported and the majority hash named.
const harnessHashes = {};
for (const r of records) {
  const h = `${r.harnessEpoch ?? r.provenance?.harnessEpoch ?? 'unknown'}:`
    + `${r.provenance?.harnessSha256 ?? 'unknown'}`;
  harnessHashes[h] = (harnessHashes[h] ?? 0) + 1;
}
const platforms = new Set(records.map((r) => r.provenance?.platform).filter(Boolean));
const currentInstrument = computeHarnessIdentity();
const invalidationPolicy = loadInvalidationPolicy();
const provenanceFailures = [];
for (const r of records) {
  const validity = recordValidity(r, currentInstrument, invalidationPolicy);
  // ⛔ THE SAME VALIDITY THE STRICT GATE USES, CARRIED ONTO THE RECORD, because Gate 1 below must
  // not invent a second notion of "counts as evidence". It is a private field on the in-memory
  // record only: `recordInputs` holds the raw bytes for the audit hash, and the catalog is built
  // from named fields, so nothing serialises it.
  r.__valid = validity.reusable;
  if (!validity.reusable) provenanceFailures.push(`${r.pkg}@${r.version}: ${validity.reason}`);
  const runtime = r.provenance?.runtime;
  if (!runtime?.node?.sha256 || !runtime?.npm?.version || !runtime?.os?.release
    || !runtime?.runner || !runtime?.environment) {
    provenanceFailures.push(`${r.pkg}@${r.version}: incomplete Node/npm/OS/runner provenance`);
  }
  if (r.verdict === 'MINIMUM') {
    const kinds = new Set((r.resolvedTrees ?? []).flatMap((tree) => tree.kinds ?? []));
    if (!kinds.has('direct') || !kinds.has('npm-observe-resolved')
      || ![...kinds].some((kind) => kind.startsWith('nub-'))) {
      provenanceFailures.push(`${r.pkg}@${r.version}: incomplete direct/reference/Nub resolved-tree provenance`);
    }
  }
}

// ── group by package ──────────────────────────────────────────────────────────

const byPackage = new Map();
const excluded = {
  noVerdict: [], broken: [], harnessError: [], noStatePassed: [], refusedMalicious: [],
  brokenWithoutJailToo: [], brokenInEnvironment: [], artifactGateSuspect: [],
};
// ⛔ WARNED ABOUT, NOT EXCLUDED, AND THE ASYMMETRY WITH `artifactGateSuspect` IS DELIBERATE. That
// bucket is excluded because its grant was never VERIFIED past a shortfall — an unverified NARROW
// grant, the under-granting direction. A truncated descent is the opposite: its grant is WIDE and
// every drop it applied had a verifying arm, so the grant installs. Only its MINIMALITY is unproven,
// which is the over-granting direction and therefore safe to ship. Excluding it would leave the
// package at the base profile — a BROKEN install, and precisely for the slowest packages, since a
// ladder record costs ~3.4x a synth record and so is the one that hits the budget cap.
const unprovenMinimality = [];

for (const r of records) {
  // ⛔ ITS OWN BUCKET. A package that fails IDENTICALLY with the jail off is not evidence about the
  // jail at all — it is a nub PM/linker or packaging bug. Counting it under `broken` inflates the
  // jail's apparent failure rate, which is the number that decides whether the jail can ship.
  // MEASURED: three @pulumi/* records were `node-pre-gyp: not found` from a missing `.bin` shim,
  // reproducing with the jail disabled.
  if (r.verdict === 'BROKEN-WITHOUT-JAIL-TOO') {
    excluded.brokenWithoutJailToo.push(`${r.pkg}@${r.version}`);
    continue;
  }
  if (r.verdict === 'BROKEN-EVEN-WITH-EVERYTHING') { excluded.broken.push(`${r.pkg}@${r.version}`); continue; }
  // ⛔ EVERY `HARNESS-*`, not just `HARNESS-ERROR`. This matched the one spelling, so `HARNESS-CRASH`
  // and `HARNESS-TIMEOUT` — the two the batch driver actually emits — fell through to `noVerdict`.
  // Instrument failures hidden in a generic bucket are the ones most worth surfacing: they mean a
  // package produced NO measurement, so coverage is overstated by exactly that count.
  if (String(r.verdict ?? '').startsWith('HARNESS-')) {
    excluded.harnessError.push(`${r.pkg}@${r.version} [${r.verdict}]`);
    continue;
  }
  // Its OWN bucket for the same reason REFUSED-MALICIOUS has one: this is a DELIBERATE, verified
  // answer — the package fails here and a reference PM fails identically — so reporting it as "no
  // verdict" invites re-investigating packages that are already correctly classified. MEASURED: 51
  // records sat in `noVerdict` on one box and most were this.
  if (r.verdict === 'BROKEN-IN-ENVIRONMENT') {
    excluded.brokenInEnvironment.push(`${r.pkg}@${r.version}`);
    continue;
  }
  // ⛔ `UNDER-PREDICTED` IS macOS'S SPELLING OF THE SAME ANSWER, and both belong in this bucket. The
  // drivers converged on the MEANING — "every rung up to `write:disk` failed, so no state this harness
  // can express installed the package" — while the string stayed split, and `record.mjs` deliberately
  // keeps them as distinct verdicts so existing records keep parsing as what they actually said.
  //
  // Left apart, the macOS half falls through to the catch-all `noVerdict` at the end of this chain,
  // which is the bucket meaning "go investigate". That is precisely the failure this file gives
  // BROKEN-IN-ENVIRONMENT and REFUSED-MALICIOUS their own buckets to avoid: reporting a deliberate,
  // verified answer as an absence invites re-investigating packages that are already classified.
  //
  // MEASURED before changing it: 97 darwin records carry the macOS spelling, 112 the other, and ALL 97
  // have `grant: null` — so this moves reporting granularity and cannot move a catalog entry.
  if (r.verdict === 'NO-STATE-PASSED' || r.verdict === 'UNDER-PREDICTED') {
    excluded.noStatePassed.push(`${r.pkg}@${r.version}`);
    continue;
  }
  // ⛔ EXCLUDED FROM THE CATALOG DESPITE CARRYING A GRANT, AND THAT ASYMMETRY IS DELIBERATE. Every
  // ladder arm exited 0 and fell short by the SAME artifacts at every grant up to `write:"disk"`, so
  // the shortfall is invariant under widening and says nothing about capabilities — but the grant was
  // never VERIFIED past that shortfall and its minimality was never descended. The record keeps it so
  // the package is triageable instead of discarded; the catalog does not take it, because an
  // unverified NARROW grant is the under-granting direction and that is the one that breaks installs.
  if (r.verdict === 'ARTIFACT-GATE-SUSPECT') {
    excluded.artifactGateSuspect.push(`${r.pkg}@${r.version} [${JSON.stringify(r.grant)}]`);
    continue;
  }
  // Its OWN bucket, not `noVerdict`. The OSV screen refusing a MAL-* package is a deliberate
  // answer and the screen working as designed — reporting it as "no verdict" invites someone to
  // go re-investigate a package that is refused on purpose. It is excluded from the catalog
  // either way (a refused package never installs, so no grant is meaningful), but the REPORT
  // should say which of those two things happened.
  if (r.verdict === 'REFUSED-MALICIOUS') { excluded.refusedMalicious.push(`${r.pkg}@${r.version}`); continue; }
  if (r.verdict !== 'MINIMUM') { excluded.noVerdict.push(`${r.pkg}@${r.version}`); continue; }
  // A descent killed at its budget: `record.mjs` marks these `grantSource: "descended-incomplete"` /
  // `minimality: "UNPROVEN"` rather than letting them keep claiming a completed descent. The record
  // is kept and shipped; this is the line that stops the claim being invisible, which is what the
  // `driver-timeout` note alone could never do — nothing consumed it.
  if (r.grantSource === 'descended-incomplete' || (r.notes ?? []).includes('driver-timeout')) {
    unprovenMinimality.push(`${r.pkg}@${r.version} [${JSON.stringify(r.grant)}]`);
  }
  if (!byPackage.has(r.pkg)) byPackage.set(r.pkg, []);
  byPackage.get(r.pkg).push(r);
}

/** A grant's identity for banding: two versions share a band iff their capabilities AND their
 *  declared writes are identical. Key order is normalised so two equal grants never differ by
 *  serialisation alone. */
function grantKey(r) {
  const g = r.grant ?? null;
  const norm = (x) => {
    if (x === null || typeof x !== 'object') return x;
    if (Array.isArray(x)) return x.map(norm);
    return Object.fromEntries(Object.keys(x).sort().map((k) => [k, norm(x[k])]));
  };
  return JSON.stringify({ g: norm(g), w: (r.writePaths ?? []).slice().sort() });
}

/** Semver ordering, enough for catalog banding: numeric release triple, and a prerelease sorts
 *  BELOW its release (1.0.0-rc.1 < 1.0.0) per semver §11. Build metadata is ignored. This is a
 *  comparator, not a range parser -- the catalog's only range form is `<X`, which the Rust side
 *  resolves; here we just need to order measured versions. */
function cmpVer(a, b) {
  const split = (v) => {
    const [core, pre] = String(v).split('+')[0].split('-');
    return [core.split('.').map((n) => parseInt(n, 10) || 0), pre ?? null];
  };
  const [ac, ap] = split(a);
  const [bc, bp] = split(b);
  for (let i = 0; i < 3; i++) if ((ac[i] ?? 0) !== (bc[i] ?? 0)) return (ac[i] ?? 0) - (bc[i] ?? 0);
  if (ap === bp) return 0;
  if (ap === null) return 1;        // release outranks its own prerelease
  if (bp === null) return -1;
  return ap < bp ? -1 : 1;
}

/** Capability identity, ignoring prose. Two grants are the same grant iff this matches. */
function capsKey(g) {
  const norm = (x) => {
    if (x === null || typeof x !== 'object') return x;
    if (Array.isArray(x)) return x.slice().sort().map(norm);
    return Object.fromEntries(Object.keys(x).filter((k) => k !== 'notes').sort()
      .map((k) => [k, norm(x[k])]));
  };
  return JSON.stringify(norm(g ?? {}));
}

/** The capability axes a grant can carry. `notes`/`platforms` are metadata, not capabilities. */
const CAP_AXES = ['read', 'write', 'network', 'writePaths', 'env'];

/** Per-OS overlays for one grant, or `{}` when every platform wants exactly the base.
 *
 *  ⛔ WHY THIS EXISTS. `byVersion` unions grants ACROSS platforms, so a need measured only on
 *  win32 became the answer everywhere. Measured on the shipped catalog: 0 of 453 bands carried an
 *  overlay, and 45 of the 65 whole-disk grants are win32-ONLY by record — 45 packages reading the
 *  whole filesystem on macOS and Linux because Windows needed it. The union is not WRONG (CANON
 *  reconciles by union, and it can never under-grant); it is coarser than the vocabulary allows.
 *
 *  ⛔ THE SAFETY PROPERTY, and it is what makes this landable: the overlay is built so the
 *  EFFECTIVE grant for an OS equals that OS's OWN measured union. Overlays merge per field
 *  (`catalog_v2.rs`: "deliberately UNLIKE the per-OS overlays, which DO merge"), so emitting every
 *  axis that DIFFERS — the value, or `null` where this OS needs the axis ABSENT — resolves to
 *  exactly `osCaps`. That is a shape the parser already accepts, because it came from a record and
 *  went through the same construction as any base. No new grant shape is invented here.
 *
 *  ⛔ A PLATFORM WITH NO RECORD GETS NO OVERLAY, which is the rule that keeps this from
 *  under-granting: it inherits the union, exactly as today. Silence about a platform is not
 *  evidence that it needs less.
 *
 *  ⛔ A REDUNDANT OVERLAY IS REJECTED BY THE PARSER, and a rejected catalog is SILENTLY discarded —
 *  nub prints REJECTED and keeps running on the compiled-in table, so one bad entry invalidates all
 *  338 packages. Emitting only DIFFERING axes is what avoids restating an outer value, and it
 *  disposes of the `write` ⇒ `read` redundancy for free: where an OS needs no read, the axis is
 *  emitted as `null` rather than left standing beneath a wider write.
 */
function osOverlays(coveredVersions, baseCaps, byVersionOs, allPlatforms) {
  const overlays = {};
  for (const os of allPlatforms) {
    // Only the covered versions this OS actually measured. An OS that measured NONE of them says
    // nothing, and silence must not narrow it.
    const mine = coveredVersions
      .map((v) => byVersionOs.get(v)?.get(os))
      .filter((g) => g !== undefined);
    if (!mine.length) continue;
    let osCaps = {};
    for (const g of mine) osCaps = unionGrant(osCaps, g);

    const overlay = {};
    for (const axis of CAP_AXES) {
      if (capsKey(osCaps[axis] ?? null) === capsKey(baseCaps[axis] ?? null)) continue;
      // `null` — not omission — is how the schema REMOVES an axis the outer grant carries.
      overlay[axis] = osCaps[axis] ?? null;
    }
    if (!Object.keys(overlay).length) continue;

    // The base is the union of every platform, so no platform can legitimately want MORE than it.
    // If one does, the union is broken and emitting the overlay would under-grant everyone else.
    //
    // ⛔ TESTED ON THE WHOLE GRANT, NEVER AXIS BY AXIS, because the axes are not independent:
    // `unionGrant` DROPS `read` once `write` widens to `"disk"` (whole-disk already covers every
    // read, and the parser rejects the redundant pair). So a base of `{write:"disk"}` and a platform
    // of `{write:{project},read:{userHome}}` compares as "macos widens read" on a per-axis reading
    // while being a perfectly ordinary NARROWING — the base grants strictly more. An axis-wise
    // assertion here fired on the real corpus for exactly that shape. Unioning the platform's caps
    // INTO the base and checking the base is unchanged asks the subset question directly, and gets
    // the write⇒read implication for free because `unionGrant` applies it.
    if (capsKey(unionGrant({ ...baseCaps }, osCaps)) !== capsKey(baseCaps)) {
      throw new Error(
        `per-OS overlay for ${os} would widen beyond the cross-platform union — the union invariant `
        + 'is broken; refusing to emit an overlay that would under-grant the rest. '
        + `base=${capsKey(baseCaps)} ${os}=${capsKey(osCaps)}`,
      );
    }
    overlays[os === 'windows' ? 'win' : os] = overlay;
  }
  return overlays;
}

/** The catalog names platforms `macos | linux | windows`; provenance records them as
 *  `darwin-arm64`, `linux-x64`, `win32-x64`. Map once, here, so nothing downstream has to
 *  know both vocabularies. Architecture is deliberately dropped: the grant model has no
 *  per-arch axis, and a run on arm64 speaks for the OS. */
function osOf(r) {
  const p = r.provenance?.platform ?? '';
  if (p.startsWith('darwin')) return 'macos';
  if (p.startsWith('linux')) return 'linux';
  if (p.startsWith('win')) return 'windows';
  return null;
}

/** Every platform the gates reason about, in `osOf`'s vocabulary. */
const GATED_PLATFORMS = ['macos', 'linux', 'windows'];

/** `baseline_caps()` from `crates/nub-sandbox/src/catalog_v2.rs`, in the catalog's own grant
 *  vocabulary — what a package with NO entry is granted.
 *
 *  ⛔ TRANSCRIBED FROM THAT FUNCTION AND ITS `BASELINE_WRITE_PATHS`, AND IT MUST STAY IN STEP WITH
 *  THEM. `read: Reach::None` is why there is no `read` key; `write: Reach::Scopes([Deps])` is
 *  `{deps: true}`; `network: true` is the documented concession (90.1% of packages need egress).
 *
 *  ⛔ THE WRITE-PATH LIST IS CACHE ROOTS AND DELIBERATELY CARRIES NO CONFIG ROOT. `.config` and
 *  `Library/Application Support` were REMOVED from it: promotion is nub itself writing into the
 *  user's real home once the scripts finish, so a promoted `.config/git/config` carrying
 *  `core.hooksPath` is code that runs on the next `git` command in any repository — persistence
 *  outliving the jail, which is the one property the jail exists to deny. Do not "complete" this
 *  list with a config directory. */
const BASELINE_CAPS = {
  write: { deps: true },
  network: true,
  writePaths: ['.cache', '.npm', '.electron', 'AppData/Local', 'Library/Caches'],
};

/** What ONE platform is actually granted by a catalog grant: the outer axes with that OS's block
 *  laid over them field by field, `null` REMOVING an axis.
 *
 *  ⛔ MIRRORS `catalog_v2.rs` `Grant::on`, WHICH IS THE ONLY READING THAT MEANS ANYTHING. Reading
 *  the outer fields alone answers about a grant no platform is ever given — and it is exactly how
 *  a `win`-only overlay goes unseen, which is the whole class of defect the floor exists to stop.
 *  The schema spells Windows `win`; `osOf` says `windows`. */
function effectiveFor(grant, os) {
  const key = os === 'windows' ? 'win' : os;
  const out = {};
  for (const axis of CAP_AXES) {
    if (grant?.[axis] !== undefined && grant[axis] !== null) out[axis] = grant[axis];
  }
  const overlay = grant?.[key];
  if (overlay && typeof overlay === 'object') {
    for (const axis of CAP_AXES) {
      if (!(axis in overlay)) continue;
      if (overlay[axis] === null) delete out[axis];
      else out[axis] = overlay[axis];
    }
  }
  return out;
}

// ── build ─────────────────────────────────────────────────────────────────────

const packages = {};
const notes = [];
/** Packages whose `default` was generated from something other than npm's real `latest`. A GATE,
 *  not a note — see the comment at the assignment site. */
const staleDefaults = [];
/** Packages whose records predate the dist-tag being recorded, so latest could not be checked
 *  at all. Distinct from staleDefaults: unknown-and-unchecked, rather than known-and-wrong. */
const missingTag = [];
/** Every narrowing the two gates refused to publish, one row per (package, version, platform).
 *  Reported in full: a floor that applies silently is how a catalog stops being derived without
 *  anyone noticing, which is the same reason every override is reported. */
const prevented = [];
/** Packages the regeneration would have DROPPED outright while `--prior` still carries an entry. */
const carriedForward = [];
/** Every (package, platform, floor) this run CLAIMS to have floored, recorded as the floor is
 *  applied so the check at the end reads the claim rather than re-deriving it and agreeing with
 *  itself. See the gate below the override pass. */
const flooredClaims = [];
/** Packages whose absence from the regenerated catalog IS a measurement — every platform reported,
 *  every report falsifiable, and the answer was "needs nothing". These must survive the
 *  carry-forward pass below, or a real narrowing would be undone by the floor. */
const evidencedDrop = new Set();

/** Merge two grants by UNION — the wider of each axis.
 *
 *  Reconciliation across machines is where this matters. A package that probes for host tooling
 *  takes different code paths on different hosts, so one run measures narrower than another;
 *  `sharp` is the worked example, needing full disk write only on the branch that shells out to
 *  brew. The wider grant covers both branches, and the narrower one BREAKS for every user whose
 *  machine takes the richer path. Over-granting is the failure this project accepts; under-
 *  granting is the one it does not. So: never intersect. */
function unionGrant(a, b) {
  if (!a) return b;
  if (!b) return a;
  const out = { ...a };
  const widest = (x, y) => {
    if (x === 'disk' || y === 'disk') return 'disk';
    if (!x) return y;
    if (!y) return x;
    return { ...x, ...y };
  };
  if (a.write || b.write) out.write = widest(a.write, b.write);
  if (a.read || b.read) out.read = widest(a.read, b.read);
  if (a.network || b.network) out.network = true;
  // A read the widened write now covers is rejected by the parser, so drop it.
  if (out.read && out.write === 'disk') delete out.read;
  else if (out.read && typeof out.read === 'object' && typeof out.write === 'object') {
    const r = { ...out.read };
    for (const k of Object.keys(out.write)) delete r[k];
    if (Object.keys(r).length) out.read = r; else delete out.read;
  }
  const wp = [...new Set([...(a.writePaths ?? []), ...(b.writePaths ?? [])])].sort();
  if (wp.length) out.writePaths = wp.filter((d) => !wp.some((o) => o !== d && d.startsWith(`${o}/`)));
  return out;
}

for (const [pkg, rsRaw] of [...byPackage.entries()].sort()) {
  // RECONCILE FIRST: several machines may have measured the SAME platform and version. Fold
  // those into one record per (platform, version) by UNION before banding, so a host that took
  // a narrower code path cannot erase a grant a richer host proved necessary.
  const folded = new Map();
  for (const r of rsRaw) {
    const key = `${r.provenance?.platform ?? '?'}\u0000${r.version}`;
    const prev = folded.get(key);
    if (!prev) { folded.set(key, r); continue; }
    folded.set(key, {
      ...prev,
      grant: unionGrant(prev.grant, r.grant),
      writePaths: [...new Set([...(prev.writePaths ?? []), ...(r.writePaths ?? [])])].sort(),
      _mergedFrom: (prev._mergedFrom ?? 1) + 1,
    });
  }
  const rs = [...folded.values()];
  for (const r of rs) {
    if (r._mergedFrom) notes.push(`${pkg}@${r.version}: reconciled ${r._mergedFrom} runs by union`);
  }
  const allPlatforms = new Set(rs.map((r) => osOf(r)).filter(Boolean));
  const allVersions = new Set(rs.map((r) => r.version));

  const ordered = [...allVersions].sort(cmpVer);
  // LATEST: the probe's recorded dist-tag when present, else the highest measured version. The
  // mega script always probes `latest` explicitly, so the fallback only serves legacy records --
  // and if it ever picks wrong, `default` is generated from an older version and FUTURE releases
  // are under-granted, which is why the dist-tag is preferred rather than merely nice.
  //
  // ⛔ HOISTED ABOVE THE GATES BECAUSE GATE 3 READS IT. It used to sit immediately above `dflt`,
  // which is AFTER the floor has been applied — so the one fact that says "this regeneration has no
  // evidence at the top of the version line" arrived too late to gate anything with.
  const distTag = rs.map((r) => r.standing?.latestVersion).find(Boolean) ?? null;
  const tagged = distTag && ordered.includes(distTag) ? distTag : null;
  const latest = tagged ?? ordered[ordered.length - 1];

  // ── GATE 1 (coverage) + GATE 2 (falsifiability) + GATE 3 (version coverage) ──
  //
  // Which platforms may be narrowed below the shipped grant at all. Both gates read the RAW
  // records, never the folded ones: folding unions a platform's runs into one grant and drops the
  // rest of each record, so `notes` and `minimality` — the two fields Gate 2 turns on — survive
  // for only one of them.
  //
  // ⛔ GATE 2 AGGREGATES WITH `every`, NOT `some`, AND THAT FOLLOWS FROM THE UNION. A cell's caps
  // are the union of its records, so the WIDEST record sets them; a record that vacuously reported
  // narrow contributes nothing and can hide a capability the union then has no way to recover. One
  // untrustworthy record is therefore enough to make the cell's narrowness unproven, however many
  // sound records sit beside it.
  const priorEntry = PRIOR?.packages?.[pkg] ?? null;
  /** os -> why this platform may not sit below the floor. Empty ⇒ every platform reported with
   *  evidence that could have gone red, at a version line reaching npm's real `latest`, so the
   *  regeneration speaks for itself. */
  const gated = new Map();
  // ⛔ GATE 3 — VERSION COVERAGE, AND IT IS GATE 1 ASKED ALONG THE OTHER AXIS. Gate 1 refuses a
  // narrowing where a PLATFORM did not report; this refuses one where the top of the VERSION LINE
  // did not. When npm's real `latest` was never measured, `default` is generated from an older
  // release and — because `default` is what every current and future version resolves to — the band
  // structure below it is redrawn around that older release. The regeneration therefore has no
  // evidence at all about the range the shipped `default` covered, and silence there is not
  // evidence any more than silence about a platform is.
  //
  // ⛔ MEASURED, AND THIS IS THE HOLE THAT MADE THE `--prior` RE-BAKE NON-MONOTONE. `@apollo/rover`
  // shipped `default` (empty, measured at 0.41.0) plus a `<0.41.0` band granting `write.deps`. With
  // 0.41.0 no longer measured, `latest` falls back to 0.40.0, every band collapses into `default`,
  // and `default`'s `linux: {write: null}` overlay — computed from 0.40.0 ALONE — then applies to
  // the whole version line. Linux lost `write.deps` everywhere below 0.41.0 on the strength of one
  // release's measurement, with both existing gates passing because linux DID report, falsifiably.
  //
  // ⛔ A FLOOR, NOT A REFUSAL, AND THAT IS THE WHOLE POINT OF PUTTING IT HERE. 353 of the corpus's
  // packages carry a stale default, so refusing on one would mean nobody can ever bake — the
  // `staleDefaults` list stays a reported gate for `--strict`, while this turns the same fact into
  // the response the project already uses for absent evidence: keep what shipped.
  //
  // ⛔ TESTED LAST OF THE THREE, SO IT CLAIMS ONLY THE PLATFORMS THE OTHER TWO CLEARED. The floor it
  // applies is identical either way (`floorFor(os)`), so ordering cannot change the emitted catalog
  // — but it decides which REASON the entry's note and the run's report carry, and "no valid record
  // on this platform" is the more specific and more actionable finding. Ordered the other way, gate
  // 1's count fell from 1044 to 575 and gate 2's to zero, which reads as two gates having stopped
  // working.
  const staleDefault = Boolean(distTag && !tagged);
  for (const os of (priorEntry ? GATED_PLATFORMS : [])) {
    const valid = rsRaw.filter((r) => osOf(r) === os && r.__valid);
    if (!valid.length) {
      gated.set(os, 'no valid record on this platform — silence is not evidence');
      continue;
    }
    const blind = valid.filter((r) => !narrowingEvidence(r).evidence);
    if (blind.length) {
      gated.set(os, `${blind.length} of ${valid.length} valid record(s) could not have failed `
        + `(${[...new Set(blind.map((r) => r.version))].sort(cmpVer).join(', ')})`);
      continue;
    }
    if (staleDefault) {
      gated.set(os, `latest ${distTag} was never measured, so \`default\` comes from ${latest} `
        + '— the regeneration has no evidence at the top of the version line');
    }
  }
  /** The floor for one gated platform: the WIDEST grant the shipped catalog gives it anywhere on
   *  the version line — `default` unioned with every band.
   *
   *  ⛔ VERSION-UNIFORM ON PURPOSE, AND THE PER-VERSION ALTERNATIVE LEAKS. Reproducing the shipped
   *  band structure needs a BAND to carry each interval's floor, and a band is emitted only where
   *  the BASE differs from `default` — so a floor that a sibling platform's floor already lifted
   *  the base past is silently dropped, and the gated platform's `default` overlay, computed from
   *  `latest` alone, then applies all the way down. MEASURED: `@pulumi/gcp` lost `write.userHome`
   *  below 0.16.9 on macOS through exactly that hole, while its entry carried a note saying macOS
   *  was floored. Making the band model overlay-aware would fix it and would also start emitting
   *  bands that grant a platform LESS at an old version — a narrowing, against this file's own
   *  "a version needing LESS gets no band at all" rule.
   *
   *  So the floor does not draw a version line the evidence cannot support. A gated platform has no
   *  new information at ANY version; giving it the safest thing ever shipped, everywhere, is what
   *  that actually means. It over-grants the gated platform on older versions, which is the
   *  direction this project accepts.
   *
   *  ⛔ AND WITH NO PRIOR ENTRY THE FLOOR IS `baseline_caps()`, WHICH IS THE SAME RULE AND NOT A
   *  SECOND ONE. The floor is always "what nub granted this package BEFORE this bake". For a
   *  catalogued package that is its shipped entry; for an uncatalogued one it is the baseline, and
   *  the two are one rule because a v2 ENTRY REPLACES `baseline_caps()` RATHER THAN MERGING WITH IT
   *  (`crates/nub-cli/src/pm_engine/build_jail.rs`; `catalog_v2.rs` states it as "an entry: ITS OWN
   *  value / absent: the BASELINE"). So a first-ever entry naming less than the baseline does not
   *  merely fail to widen — it WITHDRAWS egress, the deps write and the whole promotion list from a
   *  package that had them yesterday by virtue of being unknown.
   *
   *  ⛔ MEASURED on the 2026-09-01 regeneration, which is why this is not defensive coding: 165 of
   *  the 166 cells the re-bake narrowed were FIRST entries, across 50 packages, and 72 of them
   *  dropped egress outright — `node-sass`, `zeromq`, `netlify`, `neonctl`, `ffi`, `fibers` among
   *  them. Both existing gates were structurally unable to see it, because both compare against a
   *  prior ENTRY and a new package has none.
   *
   *  ⛔ IT FLOORS AN ENTRY, IT NEVER CREATES ONE. A package measured as needing nothing is still
   *  DROPPED (see `meaningful` below), because absence already resolves to exactly this baseline —
   *  flooring it into existence would add hundreds of entries that grant precisely what their
   *  absence grants. The floor only ever applies to a package that is getting an entry anyway.
   *
   *  ⛔ AND IT STOPS AT THE GENERATOR. Overrides are applied after this loop and are deliberately
   *  NOT floored: `catalog_v2.rs` documents a sub-baseline entry as a supported, intended shape —
   *  "a widely-depended-on package may deliberately be granted LESS than an unknown one, because
   *  the damage if it is compromised is greater" — and a hand-authored override with its mandatory
   *  `rationale` block is the reviewed seam for that decision. A MEASUREMENT is not that decision:
   *  "this host did not happen to need egress" is not "this package should be denied egress". */
  const floorFor = (os) => (priorEntry
    ? [priorEntry.default ?? {}, ...Object.values(priorEntry.versions ?? {})]
      .reduce((caps, grant) => unionGrant(caps, effectiveFor(grant, os)), {})
    : { ...BASELINE_CAPS, writePaths: [...BASELINE_CAPS.writePaths] });

  const bands = new Map();
  for (const r of rs) {
    const k = grantKey(r);
    if (!bands.has(k)) bands.set(k, []);
    bands.get(k).push(r);
  }

  // A package needing NOTHING at every measured version earns no entry at all: the base profile
  // is the default, and an empty grant is rejected by the parser rather than being a spelling of
  // "nothing". This is why most of the corpus is absent from the catalog rather than present
  // with an empty entry.
  const meaningful = [...bands.entries()].filter(([, group]) =>
    group[0].grant || (group[0].writePaths ?? []).length);
  // ⛔ A GATED PLATFORM KEEPS THE ENTRY ALIVE. "Every measured grant is empty" is the ordinary way
  // a package leaves the catalog, and it is correct when every platform reported it — but with one
  // platform unmeasured it is exactly the silent removal the floor exists to stop, and an absent
  // entry runs at the BASE PROFILE, which is the widest under-grant this file can commit.
  //
  // ⛔ AND IT IS SCOPED TO A PACKAGE THAT HAS A SHIPPED ENTRY TO LOSE. The baseline floor below
  // gates NOTHING here on purpose: absence already resolves to exactly `baseline_caps()`, so
  // keeping an uncatalogued "needs nothing" package alive would emit hundreds of entries granting
  // precisely what their absence grants. The floor raises an entry that is being written; it never
  // conjures one.
  if (!meaningful.length && !(priorEntry && gated.size)) { evidencedDrop.add(pkg); continue; }

  // ── `default` + `<` BANDS ────────────────────────────────────────────────────
  //
  // `default` is generated from LATEST, and every band key is a `<` bound. That pairing is what
  // makes coverage total: bands reach DOWNWARD without limit, so every old version -- including
  // the ones too unpopular to probe -- is caught by the lowest band, while `default` covers
  // today's release and every future one. Bands nest by construction, so resolution is
  // NARROWEST-BOUND-WINS with no ordering rule and no key-order dependence.
  //
  // ⛔ NEVER emit a point version as a matcher. The first real catalog emitted `versions: 5.1.1`
  // for bcrypt, which grants 5.1.1 and leaves 5.0.0 on the base profile -- it BREAKS. That is
  // under-granting, the one direction this project rejects everywhere.
  const byVersion = new Map();
  // The SAME folding, kept per OS. `byVersion` unions across platforms and that is what erases the
  // per-OS answer, so the unerased form is retained alongside it for [`osOverlays`]. Built here
  // rather than re-derived later so the two can never disagree about what a platform measured.
  const byVersionOs = new Map();
  for (const [, group] of meaningful) {
    for (const r of group) {
      const cur = byVersion.get(r.version);
      const here = { ...(r.grant ?? {}) };
      if ((r.writePaths ?? []).length) here.writePaths = r.writePaths;
      byVersion.set(r.version, cur ? unionGrant(cur, here) : here);
      const os = osOf(r);
      if (!os) continue;
      if (!byVersionOs.has(r.version)) byVersionOs.set(r.version, new Map());
      const perOs = byVersionOs.get(r.version);
      perOs.set(os, perOs.has(os) ? unionGrant(perOs.get(os), here) : here);
    }
  }
  // A version measured as needing NOTHING is absent from `meaningful` but is still evidence --
  // it bounds a band from above. Seed those as empty so the ordering below sees every version.
  for (const v of allVersions) if (!byVersion.has(v)) byVersion.set(v, {});
  // The same seeding per OS, and it is load-bearing for NARROWING rather than for banding: an OS
  // that measured a version and needed NOTHING is exactly the case an overlay should express (it
  // gets `{}`, so every axis the union carries is emitted as `null` and the OS runs at the base
  // profile). Without this it would look unmeasured and silently inherit the union instead.
  for (const r of rs) {
    const os = osOf(r);
    if (!os) continue;
    if (!byVersionOs.has(r.version)) byVersionOs.set(r.version, new Map());
    const perOs = byVersionOs.get(r.version);
    if (!perOs.has(os)) perOs.set(os, {});
  }

  // ── THE FLOOR ────────────────────────────────────────────────────────────────
  //
  // ⛔ SNAPSHOT THE UNGATED ANSWER FIRST. A platform with no row of its own inherits the BASE, and
  // the loop below mutates the base — so reading it mid-loop attributes a prevented narrowing to
  // whichever platform happens to be gated later, purely by iteration order. The emitted catalog is
  // unaffected (a union is order-independent); the REPORT is not, and a report naming the wrong
  // gate is how the wrong thing gets re-measured.
  //
  // ⛔ WHICH PLATFORMS ARE FLOORED DEPENDS ON WHETHER THERE IS A PRIOR ENTRY, AND THE ASYMMETRY IS
  // THE POINT. A CATALOGUED package is floored only where a gate fired, because a platform that
  // reported falsifiably at a version line reaching npm's `latest` has earned the right to narrow
  // its own shipped grant. An UNCATALOGUED one is floored on EVERY platform unconditionally: the
  // gates all ask "is this narrowing evidenced?", and for a first entry that is the wrong question.
  // However good the measurement, publishing an entry below `baseline_caps()` withdraws capabilities
  // the package held yesterday by being unknown, and no measurement of what a package HAPPENED to
  // need is a decision to take away what it is ALLOWED to need.
  //
  // ⛔ AND FOR AN UNCATALOGUED PACKAGE IT IS CONDITIONED ON THE ENTRY EXISTING WITHOUT IT.
  // `meaningful` is NOT that test: a v2 record carries `grant: {}` for "needs nothing", and `{}` is
  // truthy, so a package every version of which needs nothing has a non-empty `meaningful` and is
  // dropped later, by the empty-entry check at the end of this loop. Flooring before that check
  // pre-empts it — MEASURED: it emitted 301 entries granting exactly `baseline_caps()`, which is
  // byte-for-byte what those packages already get by being absent, nearly doubling the catalog to
  // say nothing. The floor raises an entry that is being written; it never conjures one.
  const emitsEntry = [...byVersion.values()].some((g) => CAP_AXES.some((k) => g[k] !== undefined));
  const floors = new Map(priorEntry
    ? [...gated.keys()].map((os) => [os, floorFor(os)])
    : (emitsEntry ? GATED_PLATFORMS : []).map((os) => [os, floorFor(os)]));
  for (const [os, floor] of floors) {
    if (Object.keys(floor).length) flooredClaims.push({ pkg, os, floor });
  }
  const ungated = new Map();
  for (const v of (floors.size ? byVersion.keys() : [])) {
    ungated.set(v, new Map(GATED_PLATFORMS.map((os) =>
      [os, byVersionOs.get(v)?.get(os) ?? byVersion.get(v) ?? {}])));
  }
  for (const [os, floor] of floors) {
    const why = gated.get(os) ?? 'no prior entry — an uncatalogued package is granted '
      + '`baseline_caps()`, and an entry REPLACES that rather than merging with it';
    if (!Object.keys(floor).length) continue;
    for (const v of [...byVersion.keys()]) {
      const dropped = narrows(floor, ungated.get(v).get(os));
      if (dropped.length) prevented.push({ pkg, version: v, os, dropped, why });
      // ⛔ UNION, NEVER ASSIGN. `max(measured, shipped)` can only widen; pinning the platform TO
      // the shipped value would throw away a measured WIDENING, which is evidence in the safe
      // direction and the one thing a re-measure most reliably produces.
      byVersion.set(v, unionGrant(byVersion.get(v) ?? {}, floor));
      // ⛔ AND INTO THE PLATFORM'S OWN ROW WHENEVER IT HAS ONE AT ALL — including at a version it
      // never measured. `osOverlays` unions a band's covered versions for THIS platform only, so a
      // row missing at one covered version would let that platform's overlay resolve BELOW the
      // floor even though the base carries it. A platform with no row anywhere stays rowless and
      // inherits the base, which is already floored.
      if (allPlatforms.has(os)) {
        if (!byVersionOs.has(v)) byVersionOs.set(v, new Map());
        byVersionOs.get(v).set(os, unionGrant(byVersionOs.get(v).get(os) ?? {}, floor));
      }
    }
  }

  // ⛔ `default` GENERATED FROM A NON-LATEST VERSION IS AN UNDER-GRANT RISK, so it is a GATE and
  // not a note. If the true latest needs MORE than the highest version we measured, every release
  // from that point on silently falls to a grant that is too narrow — the one direction this
  // project rejects. MEASURED on the first real corpus: the highest-measured fallback was wrong
  // for 3 of 8 packages (better-sqlite3 13.0.2 vs 12.6.0, canvas 3.2.3 vs 2.11.2, sharp 0.35.3
  // vs 0.34.4), which is what turned this from a note into a gate.
  if (distTag && !tagged) staleDefaults.push(`${pkg}: latest is ${distTag}, highest measured ${latest}`);
  else if (!distTag) missingTag.push(pkg);

  const dflt = { ...(byVersion.get(latest) ?? {}) };

  // A BAND IS WRITTEN ONLY WHERE AN OLDER VERSION NEEDS *MORE* THAN LATEST. A version needing
  // LESS gets no band at all: it falls to `default` and is harmlessly over-granted, the safe
  // direction. That is also what dissolves the INVERTED case (better-sqlite3 needs network at
  // 12.6.0 and nothing at 9.6.0), which has no clean `<`-band expression.
  //
  // A band's grant is the UNION of every measured grant BELOW its bound, unioned with `default`
  // -- so it covers the unmeasured gaps between probed versions, and can never grant less than
  // `default`. Nothing merges at resolution time, so each band must be complete on its own.
  const bandList = [];
  for (let i = 1; i < ordered.length; i++) {
    const bound = ordered[i];
    let acc = { ...dflt };
    for (let j = 0; j < i; j++) acc = unionGrant(acc, byVersion.get(ordered[j]) ?? {});
    if (capsKey(acc) === capsKey(dflt)) continue;          // needs no more than latest
    bandList.push({ bound, caps: acc, covers: ordered.slice(0, i) });
  }
  // Same grant at two bounds means the narrower is redundant (narrowest wins), so keep the
  // WIDEST bound per distinct grant.
  const widest = new Map();
  for (const b of bandList) widest.set(capsKey(b.caps), b);

  const entry = { default: dflt };
  dflt.notes = `latest measured ${latest}`;
  // NARROW PER OS where the platforms disagree. The base stays the union — so a platform with no
  // record is unaffected — and each platform that measured `latest` gets its own answer back.
  Object.assign(dflt, osOverlays([latest], dflt, byVersionOs, allPlatforms));

  const versions = {};
  for (const b of [...widest.values()].sort((x, y) => cmpVer(y.bound, x.bound))) {
    b.caps.notes = `measured ${b.covers.join(', ')}; covers everything below ${b.bound}`;
    // A band's own covered set, not `latest` — the platforms can disagree differently on old
    // versions than on the current one, and a band resolves on its own with nothing merging in.
    Object.assign(b.caps, osOverlays(b.covers, b.caps, byVersionOs, allPlatforms));
    versions[`<${b.bound}`] = b.caps;
  }
  if (Object.keys(versions).length) entry.versions = versions;

  // A writePaths entry embedding the measured version names a directory that moves on the next
  // release. Under `<` bands that is no longer expressible as a matcher, so it is surfaced as a
  // re-measure note rather than silently pinning the grant to one point.
  const pinned = [...new Set(rs.flatMap((r) => r.writePathsVersionPinned ?? []))];
  if (pinned.length) {
    dflt.notes += `; version-pinned writePaths (${pinned.join(', ')}) — re-measure on a new release`;
    notes.push(`${pkg}: writePaths embed a version (${pinned.join(', ')}) — re-measure each release`);
  }
  // PER-PLATFORM: only when the platforms disagree, else one line covers all three.
  if (allPlatforms.size === 1 && PLATFORM) dflt.platforms = [PLATFORM];

  const unmeasured = [...new Set(rs.flatMap((r) => r.unmeasuredScopesGranted ?? []))];
  if (unmeasured.length) {
    dflt.notes += `; widened for unmeasured scopes (${unmeasured.join(', ')})`;
    notes.push(`${pkg}: widened for ${unmeasured.join(', ')}`);
  }
  // ⛔ THE PRESERVATION IS STATED IN THE ARTEFACT, not only in this run's stdout. A cell that is
  // partly floored rather than wholly derived is exactly the thing a later reader must not mistake
  // for a measurement, and stdout is gone by then.
  if (gated.size) {
    dflt.notes += `; ${[...gated].map(([os, why]) => `${os} floored at the prior catalog (${why})`).join('; ')}`;
  } else if (!priorEntry && floors.size) {
    dflt.notes += '; floored at the uncatalogued baseline (first entry — an entry REPLACES '
      + '`baseline_caps()` rather than merging with it)';
  }
  if (rs.some((r) => r.declaresInstallScript && !r.projectAxisConclusive)) {
    dflt.notes += '; project axis inconclusive (package was not materialized)';
  }

  // A band that grants strictly LESS than `default` is a generator bug by construction -- bands
  // are unioned WITH default above, so this can only fire if that invariant is broken. Assert it
  // rather than shipping a silently narrowed old-version grant.
  for (const [k, v] of Object.entries(versions)) {
    const merged = unionGrant(v, dflt);
    if (capsKey(merged) !== capsKey(v)) {
      throw new Error(`${pkg} band ${k} grants less than default — generator invariant broken`);
    }
  }
  // ⛔ AN ENTRY THAT WIDENS NOTHING IS REJECTED BY NUB, AND A REJECTED CATALOG IS A SILENTLY
  // DISCARDED ONE — `Decision::FellBack` keeps nub running on the compiled-in table and merely
  // prints REJECTED, so ONE such package invalidates the WHOLE catalog while every record beside it
  // is perfectly good. Verbatim: "`default` widens nothing and there are no version bands, so the
  // entry grants exactly the base profile; drop it".
  //
  // ⛔ IT COULD NOT FIRE UNDER v1 AND IT FIRES CONSTANTLY UNDER v2, which is why the gate reached
  // production without it. A v1 "needs nothing" record carries `grant: null` and never becomes a
  // `meaningful` row; a v2 record carries `grant: {}` — an empty grant VERIFIED in the real jail,
  // which is a stronger statement and a legitimately different value. Roughly half the corpus
  // synthesizes the empty grant, so v2 turns a case that never arose into the modal one. MEASURED,
  // run 31102880006: `git-validate@2.2.4` verified at `{}` and took the macOS smoke slice's catalog
  // gate down with it, alongside two sound records.
  //
  // Dropping the package IS the correct encoding, not a workaround: the override REPLACES the
  // compiled-in table rather than merging into it, so an ABSENT package runs at the base profile —
  // exactly what "this package needs nothing" means, and exactly what the `needed nothing` line
  // below has always counted.
  //
  // ⛔ `notes` AND `platforms` ARE NOT CAPABILITIES, and `capsKey` only strips the first. `dflt`
  // always carries a `notes` and carries `platforms` whenever one platform measured it, so testing
  // `capsKey(dflt) === '{}'` would never fire on a real entry — the guard would look present and be
  // inert. Test for the capability axes by name instead.
  const CAPS = ['read', 'write', 'network', 'writePaths', 'env'];
  if (!CAPS.some((k) => dflt[k] !== undefined) && !Object.keys(versions).length) {
    // Nothing was floored and nothing is granted: every platform reported, with evidence that could
    // have failed, that this package needs nothing. That IS the measurement, so the carry-forward
    // pass below must not put the shipped entry back over it.
    if (!(priorEntry && gated.size)) evidencedDrop.add(pkg);
    continue;
  }
  packages[pkg] = entry;
}

// ── carry forward what this collation cannot speak about ──────────────────────
//
// A package the shipped catalog grants and these records say NOTHING about — no `MINIMUM` record on
// any platform, because none was measured, or every one was excluded as BROKEN / HARNESS-* /
// REFUSED-MALICIOUS. Every platform is gated by definition, so the floor IS the whole shipped entry
// and there is no emitted entry to merge it into.
//
// ⛔ THIS IS THE WIDEST UNDER-GRANT THE GENERATOR CAN COMMIT AND IT LOOKS LIKE HOUSEKEEPING. An
// override REPLACES the compiled-in table, so an absent package runs at the BASE PROFILE — the
// package does not get a narrower grant, it gets none, and it simply fails to install. MEASURED on
// the 2026-09-01 regeneration: 86 of the 155 wide-cell removals were a package dropping out
// entirely, not a grant narrowing.
//
// `evidencedDrop` is the carve-out that keeps this from being a freeze: a package every platform
// measured, falsifiably, as needing nothing has EARNED its removal and is not resurrected.
if (PRIOR) {
  for (const [name, entry] of Object.entries(PRIOR.packages)) {
    if (packages[name] || evidencedDrop.has(name)) continue;
    packages[name] = JSON.parse(JSON.stringify(entry));
    carriedForward.push(name);
  }
}

// ── overrides ─────────────────────────────────────────────────────────────────
//
// A hand-authored grant REPLACES the measured one. This is the seam for a package a sweep
// cannot answer — sharp, where the honest move is to read the source rather than infer from a
// run whose result depended on whether a download succeeded.
//
// EVERY override is reported, every run. An override that applies silently is how a catalog
// stops reflecting measurement without anyone noticing, and the whole value of this pipeline is
// that its output is derived rather than asserted.
const applied = [];
const deadWeight = [];
const rejected = [];
for (const f of (fs.existsSync(OVERRIDES) ? fs.readdirSync(OVERRIDES) : []).sort()) {
  if (!f.endsWith('.json')) continue;
  let o;
  try { o = JSON.parse(fs.readFileSync(path.join(OVERRIDES, f), 'utf8')); }
  catch (e) { rejected.push(`${f}: unparseable (${e.message})`); continue; }
  const name = o.package ?? f.replace(/\.json$/, '').replace('+', '/');
  // RATIONALE IS MANDATORY. An override without one is indistinguishable from a guess a year
  // later, and the reader has no measurement to fall back on — that is the point of the file.
  const r = o.rationale ?? {};
  const missing = ['investigator', 'evidence', 'date'].filter((k) => !r[k]);
  if (missing.length) { rejected.push(`${f}: missing rationale.${missing.join(', rationale.')}`); continue; }
  // An override is an ENTRY -- `{default, versions?}` -- the same shape the generator emits, so a
  // human writing one never has to learn a second grammar. The legacy `grants: [...]` array is
  // rejected rather than silently coerced: its first-match-wins semantics do not survive the move
  // to `<` bands, so a quietly-converted override would resolve differently than its author read.
  if (Array.isArray(o.grants)) {
    rejected.push(`${f}: legacy 'grants' array — rewrite as { default, versions? }`);
    continue;
  }
  const ent = o.entry ?? (o.default ? { default: o.default, ...(o.versions ? { versions: o.versions } : {}) } : null);
  if (!ent?.default) { rejected.push(`${f}: no entry.default`); continue; }
  // COMPARE CAPABILITIES, NOT THE WHOLE ENTRY. `notes` always differs — the measured note records
  // what was observed, the override's records why a human wrote it — so comparing serialised
  // entries made this check STRUCTURALLY UNABLE TO FIRE. Verified by a fixture whose override
  // matched the measured result exactly and was still not reported.
  const caps = (e) => JSON.stringify({
    d: capsKey(e?.default ?? {}),
    v: Object.fromEntries(Object.entries(e?.versions ?? {}).sort()
      .map(([k, v]) => [k, capsKey(v)])),
  });
  const before = packages[name] ? caps(packages[name]) : null;
  packages[name] = ent;
  if (before && before === caps(ent)) deadWeight.push(name);
  applied.push({ name, why: r.evidence, by: r.investigator, on: r.date });
}

const baseline = fs.existsSync(BASELINE)
  ? JSON.parse(fs.readFileSync(BASELINE, 'utf8'))
  : { baseline: [], env: [] };

// ⛔ THIS IS A v2 CATALOG: egress is the per-package `network: true` capability, and there is no
// `packageNetwork.full` table here. A v1 table was added at one point to make Windows grant egress;
// it worked, but it papered over a nub bug rather than fixing it — `package_network_allowed()`
// consulted only the v1 catalog, so a v2 override yielded nothing and the net gate fell back to the
// compiled-in table. Fixed in `e3cdc0e7f9` and pinned by
// `crates/nub-sandbox/tests/generated_catalog_round_trip.rs`, which asserts THIS output shape
// reaches the lookup the jail uses.
const recordsHash = crypto.createHash('sha256');
for (const input of recordInputs.sort((a, b) => a.path.localeCompare(b.path))) {
  recordsHash.update(`${Buffer.byteLength(input.path)}:${input.path}:${input.bytes.length}:`);
  recordsHash.update(input.bytes);
}
const runtimeCells = {};
const canonical = (value) => {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonical);
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
};
for (const record of records) {
  const runtime = record.provenance?.runtime;
  const cell = {
    platform: record.provenance?.platform ?? null,
    node: runtime?.node?.version ?? record.provenance?.node ?? null,
    nodeSha256: runtime?.node?.sha256 ?? null,
    npm: runtime?.npm?.version ?? null,
    python: (runtime?.python ?? []).map((tool) => tool.version),
    buildTools: Object.fromEntries(Object.entries(runtime?.buildTools ?? {})
      .map(([name, tool]) => [name, tool?.version ?? null]).sort()),
    runnerImage: runtime?.runner?.imageVersion ?? null,
    nubSha256: record.provenance?.nubBinary?.sha256 ?? null,
    venue: record.provenance?.venue ?? null,
    ciEnvSet: record.provenance?.ciEnvSet ?? null,
    storeLayout: record.provenance?.storeLayout ?? null,
    environmentAxes: runtime?.environment?.values ?? null,
    runtimeSha256: runtime ? crypto.createHash('sha256')
      .update(JSON.stringify(canonical(runtime))).digest('hex') : null,
    overridesSha256: record.provenance?.overrides ? crypto.createHash('sha256')
      .update(JSON.stringify(canonical(record.provenance.overrides))).digest('hex') : null,
  };
  const key = JSON.stringify(cell);
  runtimeCells[key] = (runtimeCells[key] ?? 0) + 1;
}
const catalog = {
  packages,
  baseline: baseline.baseline ?? [],
  env: baseline.env ?? [],
  provenance: {
    schemaVersion: 1,
    // ⛔ THE ONLY FIELD THAT LETS TWO CATALOGS BE ORDERED, and nub now depends on it. A catalog can
    // reach a shipped nub from its data directory as well as compiled in, and without a comparable
    // stamp there is no way to tell an UPDATE from a STALE COPY. The failure is silent and in the wrong
    // direction: a file left by an older nub replaces a newer compiled catalog, every package measured
    // since loses its entry, and each drops to the baseline — no error, installs mostly still working,
    // and the catalog quietly no longer current. nub refuses a candidate that is not STRICTLY newer.
    //
    // ⛔ SECOND-PRECISION UTC WITH A LITERAL `Z`, WHICH IS NOT COSMETIC. nub compares these
    // LEXICOGRAPHICALLY, and that is only sound for a fixed-width, zero-padded, single-timezone
    // spelling — a local-offset or variable-width stamp compares in an order that looks right in a test
    // and is wrong across a DST boundary or a year end. nub's parser REJECTS any other shape, so a
    // change here that drops the `Z` or adds milliseconds makes every catalog fail validation and fall
    // back to the compiled floor.
    generatedAt: `${new Date().toISOString().slice(0, 19)}Z`,
    harnessEpoch: currentInstrument.harnessEpoch,
    harnessSha256: currentInstrument.harnessSha256,
    invalidationPolicySha256: currentInstrument.invalidationPolicySha256,
    recordsSha256: recordsHash.digest('hex'),
    recordCount: records.length,
    sourceHarnesses: Object.fromEntries(Object.entries(harnessHashes).sort()),
    // `provenanceSlim` is stated rather than implied: a reader who finds no `runtimeCells` must be
    // able to tell "omitted deliberately" from "this collator predates them" or "the file was
    // truncated". An absence that carries no explanation is the thing that gets misdiagnosed later.
    ...(SLIM_PROVENANCE ? { provenanceSlim: true } : {
      runtimeCells: Object.entries(runtimeCells).sort(([a], [b]) => a.localeCompare(b))
        .map(([identity, count]) => ({ ...JSON.parse(identity), count })),
      resolvedTreeDigests: [...new Set(records.flatMap((record) =>
        (record.resolvedTrees ?? []).map((tree) => tree.digest)))].sort(),
    }),
  },
};

// ── report ────────────────────────────────────────────────────────────────────

const grantCount = Object.values(packages)
  .reduce((n, e) => n + 1 + Object.keys(e.versions ?? {}).length, 0);
const bandCount = Object.values(packages)
  .reduce((n, e) => n + Object.keys(e.versions ?? {}).length, 0);
console.log(`records read        ${records.length}`);
console.log(`platforms           ${[...platforms].join(', ') || '(none recorded)'}`);
const hh = Object.entries(harnessHashes).sort((a, b) => b[1] - a[1]);
console.log(`harness revisions   ${hh.map(([h, n]) => `${h}:${n}`).join('  ')}`);
// ⛔ DO NOT NAME THE MODAL REVISION AS THE TARGET. This line used to say "re-run the minority under
// <hh[0][0]>" — the most COMMON revision — and modal is the OLDEST era BY CONSTRUCTION: a spec that
// already holds a record is never revisited (search.mjs's resumability rule), so the earliest sweep
// permanently owns the largest share. MEASURED 2026-08-05: the modal revision `81d34faf44f6e376`
// (1782 records) had measured EXCLUSIVELY with nub `666a4aadfe`, the binary predating BOTH disk-tail
// fixes, while `2abf8f2aaa9a8eee` carried 571 records on the branch tip. Following the old advice
// would have migrated CURRENT records onto the stalest configuration — the same staleness that took
// 81% of the win32 disk tail to undo.
//
// The collator cannot know which nub commit is newest (it has no ancestry), so it must not prescribe
// a target at all. It reports the SPAN and the harness->binary pairing; choosing the target needs
// `git merge-base --is-ancestor` against the fixes, which belongs to whoever runs the re-measure.
if (hh.length > 1) {
  if (provenanceFailures.length) {
    console.log(`  ⚠ RECORDS SPAN ${hh.length} HARNESS REVISIONS — this catalog mixes unapproved measurement regimes`);
    console.log('    ⛔ the MODAL revision is NOT the target: it is the oldest era by construction (a spec');
    console.log('       holding a record is never re-measured, so the first sweep keeps the largest share).');
    console.log('       Re-measure the invalid records or add a narrowly scoped, reviewed invalidation transition.');
  } else {
    console.log(`  records span ${hh.length} source harness revisions; every older source is explicitly`);
    console.log('  preserved by the current targeted invalidation policy and is effective in this epoch.');
  }
  const pairing = {};
  for (const r of records) {
    const h = String(r.provenance?.harnessSha256 ?? 'unknown').slice(0, 16);
    const b = String(r.provenance?.nubGitSha ?? 'none').slice(0, 10);
    pairing[h] ??= {};
    pairing[h][b] = (pairing[h][b] ?? 0) + 1;
  }
  for (const [h, n] of hh) {
    const bins = Object.entries(pairing[h] ?? {}).sort((a, b) => b[1] - a[1]);
    console.log(`       ${h}  n=${String(n).padStart(4)}  nub: ${bins.slice(0, 4).map(([b, c]) => `${b}(${c})`).join(' ')}`);
  }
}
console.log(`packages with entry ${Object.keys(packages).length}`);
console.log(`grants emitted      ${grantCount}  (${Object.keys(packages).length} default + ${bandCount} version bands)`);
console.log(`needed nothing      ${byPackage.size - Object.keys(packages).length}`);
if (staleDefaults.length) {
  console.log(`\n⚠ ${staleDefaults.length} PACKAGE(S) HAVE A STALE \`default\` — latest was never measured,`);
  console.log('  so their default grant comes from an older version and a newer release that needs');
  console.log('  MORE is silently under-granted. Probe latest and re-collate before shipping:');
  for (const s of staleDefaults) console.log(`    ${s}`);
}
if (PRIOR) {
  const cells = (rows) => new Set(rows.map((p) => `${p.pkg} ${p.version} ${p.os}`)).size;
  const coverage = prevented.filter((p) => p.why.startsWith('no valid record'));
  const staleTop = prevented.filter((p) => p.why.startsWith('latest '));
  const uncatalogued = prevented.filter((p) => p.why.startsWith('no prior entry'));
  const falsifiability = prevented.filter((p) => !coverage.includes(p) && !staleTop.includes(p)
    && !uncatalogued.includes(p));
  console.log(`\nprior floor         ${PRIOR_PATH}  (${Object.keys(PRIOR.packages).length} packages)`);
  console.log(`  gate 1 — coverage       ${String(cells(coverage)).padStart(4)} narrowing(s) refused`
    + ` across ${new Set(coverage.map((p) => p.pkg)).size} package(s),`
    + ` platforms: ${JSON.stringify(coverage.reduce((m, p) => ({ ...m, [p.os]: (m[p.os] ?? 0) + 1 }), {}))}`);
  console.log(`  gate 2 — falsifiability ${String(cells(falsifiability)).padStart(4)} narrowing(s) refused`
    + ` across ${new Set(falsifiability.map((p) => p.pkg)).size} package(s),`
    + ` platforms: ${JSON.stringify(falsifiability.reduce((m, p) => ({ ...m, [p.os]: (m[p.os] ?? 0) + 1 }), {}))}`);
  console.log(`  gate 3 — version coverage ${String(cells(staleTop)).padStart(3)} narrowing(s) refused`
    + ` across ${new Set(staleTop.map((p) => p.pkg)).size} package(s) whose \`latest\` was never measured`);
  console.log(`  baseline floor (first entry) ${String(cells(uncatalogued)).padStart(4)} narrowing(s) refused`
    + ` across ${new Set(uncatalogued.map((p) => p.pkg)).size} uncatalogued package(s)`);
  console.log(`  packages carried forward whole (no measurement at all)  ${carriedForward.length}`);
  console.log(`  packages dropped on evidence (every platform measured)  ${evidencedDrop.size}`);
  for (const p of prevented.slice(0, 8)) {
    console.log(`    ${p.pkg}@${p.version} ${p.os}: kept ${p.dropped.join(', ')} — ${p.why}`);
  }
  if (prevented.length > 8) console.log(`    … and ${prevented.length - 8} more`);
}
if (missingTag.length) {
  console.log(`\n⚠ ${missingTag.length} package(s) predate dist-tag recording, so latest is UNCHECKED`);
  console.log(`  (assumed = highest measured): ${missingTag.join(', ')}`);
}
if (unprovenMinimality.length) {
  console.log(`\n⚠ ${unprovenMinimality.length} RECORD(S) COME FROM A DESCENT KILLED AT ITS BUDGET —`);
  console.log('  SHIPPED, because the grant installs: every drop that was applied had a verifying arm,');
  console.log('  and dropping the record would leave the package at the base profile (a broken install).');
  console.log('  But its MINIMALITY is unproven: a capability whose arm never ran is still in the grant');
  console.log('  UNTESTED, so these are wider than measurement requires. Re-measure with a larger');
  console.log('  `NUB_CORPUS_PKG_BUDGET` to narrow them:');
  for (const u of unprovenMinimality) console.log(`    ${u}`);
}
for (const [k, v] of Object.entries(excluded)) {
  if (v.length) console.log(`excluded (${k})  ${v.length}: ${v.slice(0, 6).join(', ')}${v.length > 6 ? ' …' : ''}`);
}
for (const n of notes) console.log(`  note: ${n}`);
if (applied.length) {
  console.log(`\noverrides applied   ${applied.length}`);
  for (const a of applied) console.log(`  ${a.name}  — ${a.by}, ${a.on}: ${a.why}`);
}
for (const d of deadWeight) console.log(`  ⚠ ${d}: override MATCHES the measured result — prune it`);
for (const r of rejected) console.log(`  ⛔ REJECTED ${r}`);
const strictFailures = [];
if (provenanceFailures.length) {
  strictFailures.push(`${provenanceFailures.length} record provenance failure(s): `
    + `${provenanceFailures.slice(0, 5).join('; ')}${provenanceFailures.length > 5 ? ' …' : ''}`);
}
if (staleDefaults.length) strictFailures.push(`${staleDefaults.length} package default(s) are not latest`);
if (missingTag.length) strictFailures.push(`${missingTag.length} package(s) have no recorded latest dist-tag`);
if (unprovenMinimality.length) strictFailures.push(`${unprovenMinimality.length} record(s) have unproven minimality`);
if (deadWeight.length) strictFailures.push(`${deadWeight.length} override(s) duplicate measured grants`);
if (rejected.length) strictFailures.push(`${rejected.length} override(s) were rejected`);
if (excluded.harnessError.length || excluded.noVerdict.length || excluded.noStatePassed.length
  || excluded.artifactGateSuspect.length) {
  strictFailures.push('incomplete record verdicts remain: '
    + `harness=${excluded.harnessError.length}, noVerdict=${excluded.noVerdict.length}, `
    + `noState=${excluded.noStatePassed.length}, artifactSuspect=${excluded.artifactGateSuspect.length}`);
}
if (STRICT && strictFailures.length) {
  console.error('\nCOLLATE STRICT FAILED:');
  for (const failure of strictFailures) console.error(`  - ${failure}`);
  console.error(`  refusing to write ${OUT}`);
  process.exit(1);
}

// ── GATE 4: EVERY FLOOR THIS RUN CLAIMED MUST ACTUALLY HOLD IN THE EMITTED CATALOG ────────────
//
// ⛔⛔ IT CHECKS THE FLOORS, NOT "DID ANYTHING NARROW", AND THE DIFFERENCE IS THE WHOLE DESIGN.
// An evidenced narrowing is the POINT of gates 1-3: a platform that reported validly, falsifiably,
// at a version line reaching npm's `latest` is allowed to narrow its own shipped grant, and
// `collate-narrowing-gates.test.mjs` pins that in both directions because "a floor that freezes
// everyone is not a gate". A blanket "no cell may narrow" assertion satisfies every one of those
// preservation tests, freezes the catalog at its current grants forever, and looks correct doing it
// — it was written that way first and refused NINE of this file's own tests, every one of them a
// deliberate, evidenced narrowing.
//
// So the question this asks is narrower and answerable: WHERE A FLOOR WAS APPLIED, DID IT SURVIVE
// INTO THE OUTPUT? That is a claim the run makes about itself, and it is exactly the claim that has
// silently failed before. `floorFor`'s own header documents the shape: `@pulumi/gcp` lost
// `write.userHome` below 0.16.9 on macOS *while its entry carried a note saying macOS was floored*,
// because the floor went into the base and the band model then dropped it. A note asserting a
// preservation that did not happen is worse than no note at all.
//
// ⛔ IT READS THE RECORDED CLAIM RATHER THAN RE-DERIVING THE FLOOR. Re-deriving would recompute
// `floorFor` from the same inputs with the same code, so the check would agree with itself by
// construction and could only ever catch a transcription slip. `flooredClaims` is appended at the
// moment a floor is applied, and this resolves the FINISHED entry the way `catalog_v2.rs` does.
//
// ⛔ ARMED ALWAYS, NOT BEHIND `--strict`, AND THAT IS THE FIX RATHER THAN AN OMISSION. `--strict`
// bundles seven unrelated conditions — record provenance, missing dist-tags, unproven minimality,
// dead-weight overrides, incomplete verdicts — and MEASURED on the 2026-09-01 corpus a `--strict`
// bake fails FIVE of them, 10,953 record provenance failures among them. It is unpassable on any
// real corpus, so routing a must-always-hold invariant through it is the same as not having it.
//
// ⛔ OVERRIDES ARE EXEMPT, AND THAT IS A CAPABILITY RATHER THAN A LOOPHOLE. An override REPLACES the
// generated entry outright, so no floor this loop applied survives it by design. `catalog_v2.rs`
// states a sub-baseline entry is an intended shape — "a widely-depended-on package may deliberately
// be granted LESS than an unknown one, because the damage if it is compromised is greater" — and an
// override file, with its mandatory `rationale.{investigator,evidence,date}`, is the reviewed seam
// for making that call. What this gate forbids is the GENERATOR doing it silently off a measurement.
{
  const overridden = new Set(applied.map((a) => a.name));
  /** `Entry::grant_for` — narrowest applicable `<` bound wins, else `default`. */
  const resolve = (entry, v) => {
    const hit = Object.entries(entry.versions ?? {})
      .map(([range, grant]) => ({ bound: range.replace(/^</, '').trim(), grant }))
      .filter((b) => cmpVer(v, b.bound) < 0)
      .sort((a, b) => cmpVer(a.bound, b.bound))[0];
    return hit ? hit.grant : entry.default;
  };
  // ⛔ THE SUBSET QUESTION IS ASKED WITH `unionGrant`, NOT WITH `narrows`, AND THE DIFFERENCE IS NOT
  // STYLISTIC. `narrows` is a set difference over `capsOf` tokens, in which `write:"disk"` is its own
  // token rather than a superset of `write.deps` — so a cell WIDENING from `{write:{deps,project,
  // userHome}}` to `{write:"disk"}` reports three dropped capabilities. MEASURED: the first draft of
  // this gate refused on exactly five such cells (`gifsicle@7.0.1`, `optipng-bin@9.0.0`,
  // `redis-memory-server@0.17.1`, `@tensorflow/tfjs-backend-wasm`, `react-native-purchases`), every
  // one of them a widening. That is the trap `osOverlays` documents on its own invariant check, and
  // it takes the same way out: union the floor INTO the emitted grant and ask whether the emitted
  // grant changed. `unionGrant` knows `"disk"` swallows every narrow scope, that a write implies the
  // read the parser would reject as redundant, and that a `writePaths` prefix covers everything
  // beneath it, so all three subsumptions come for free and cannot drift from what this file emits.
  const covers = (grant, floor) => capsKey(unionGrant({ ...grant }, { ...floor })) === capsKey(grant);
  const lostAxes = (grant, floor) => {
    const merged = unionGrant({ ...grant }, { ...floor });
    return CAP_AXES.filter((a) => capsKey(merged[a] ?? null) !== capsKey(grant[a] ?? null))
      .map((a) => `${a} (${JSON.stringify(grant[a] ?? null)} < ${JSON.stringify(merged[a])})`);
  };
  const breaches = [];
  for (const { pkg, os, floor } of flooredClaims) {
    if (overridden.has(pkg)) continue;
    const entry = packages[pkg];
    // A floored package ABSENT from the output resolves to `baseline_caps()`, which breaches any
    // claimed floor wider than the baseline — the "package dropped out entirely" under-grant.
    const points = ['0.0.0-0', ...Object.keys(entry?.versions ?? {})
      .map((k) => k.replace(/^</, '').trim())].sort(cmpVer);
    for (const v of points) {
      const eff = entry ? effectiveFor(resolve(entry, v), os) : BASELINE_CAPS;
      if (!covers(eff, floor)) breaches.push({ pkg, os, v, floor, eff, lost: lostAxes(eff, floor) });
    }
  }
  if (breaches.length) {
    console.error(`\nCOLLATE REFUSED: ${breaches.length} cell(s) across `
      + `${new Set(breaches.map((b) => b.pkg)).size} package(s) resolve BELOW a floor this run applied.`);
    console.error('  The entry says the platform was floored and the emitted grant does not carry it,');
    console.error('  so its note claims a preservation that did not happen. Under-granting is the one');
    console.error('  direction this project forbids: its symptom is a package that fails to install.');
    console.error('  Fix the generator — do not hand-edit the output, which would un-derive the catalog.');
    for (const b of breaches.slice(0, 20)) {
      console.error(`    ${b.pkg}@${b.v} ${b.os}: ${b.lost.join(', ')}`);
      console.error(`      floor ${JSON.stringify(b.floor)}  ->  emitted ${JSON.stringify(b.eff)}`);
    }
    if (breaches.length > 20) console.error(`    … and ${breaches.length - 20} more`);
    console.error(`  refusing to write ${OUT}`);
    process.exit(3);
  }
  if (flooredClaims.length) {
    console.log(`  gate 4 — every applied floor holds in the output  (${flooredClaims.length} `
      + `(package, platform) floor(s) re-resolved against the emitted entry)`);
  }
}
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(catalog, null, 2)}\n`);
console.log(`\nwrote ${OUT}`);
