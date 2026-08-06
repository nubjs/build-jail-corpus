// N OBSERVE runs -> one grant, plus the DISAGREEMENT between them.
//
// ⛔ WHY THIS EXISTS. OBSERVE ran exactly once per package for the whole life of this corpus, and a
// single observation of a non-deterministic script MISSES whatever that run did not do. The grant
// then omits the capability and a real user's install breaks — the one direction this system may
// not take. Repeating and UNIONING is over-granting by construction, which is the safe direction.
//
// ⛔ THE UNION IS THE ANSWER; THE DISAGREEMENT IS THE MEASUREMENT. Keeping only the union would
// destroy the evidence for whether the second run was worth its ~2x cost, so every per-run set is
// retained and diffed. Two runs can differ on hundreds of paths that all map to one scope and
// synthesize an IDENTICAL grant — that is harmless. A single path that flips a scope is what breaks
// an install, so the headline is the GRANT-level verdict and the path-level diff is context for it.
//
// ⛔ WHAT A LOW DISAGREEMENT RATE DOES NOT MEAN. Repeats catch VARIANCE, never BIAS. A decoder that
// resolves a relative path against the wrong base produces the same phantom path on every run, and
// a truncation loses the same destinations every time; both survive any number of repeats with a
// perfect agreement score. Known-answer fixtures (`probes/syscall-coverage.c`) are what catch those.
// Read an agreement number as "the observer is CONSISTENT", never as "the observer is CORRECT".
//
//   usage: node observe-union.mjs <observed-1.txt> <observed-2.txt> [...]
//
// Each input is one `observe.mjs` stdout captured with `NUB_V2_DUMP_WRITES=1`. That flag is the
// only complete per-path record observe.mjs emits — the human-readable report prints a COUNT plus
// ten examples per bucket, which cannot be diffed. Reading observe.mjs's own output rather than
// re-deriving from the trace is deliberate: the thing being measured is the grant the DRIVER would
// have published, so it has to come off the driver's own synthesizer, not a second copy of it.
import fs from 'node:fs';

// `WRITE\t<scope>\t<path>` from observe.mjs's NUB_V2_DUMP_WRITES block. Scope is carried rather than
// recomputed: this file must not hold a second copy of the classifier — that duplication is exactly
// what produced the 18-of-26 decoder drift the shared `decode()` was introduced to close.
const DUMP = /^WRITE\t([^\t]*)\t(.*)$/;

// ⛔ ONLY THESE THREE SCOPES REACH THE GRANT. Mirrors observe.mjs's synthesizer exactly; `ownPkg`,
// `jailHome`, `kernelfs` and `outside` are reported there and billed to nothing, so a run-to-run
// difference confined to them CANNOT move a grant and must not be counted as one.
const GRANT_SCOPES = ['deps', 'project', 'userHome'];

export function parseObserved(text) {
  const writes = new Map(); // path -> scope
  let grant = null, sockets = null, next = false;
  for (const line of text.split('\n')) {
    const m = DUMP.exec(line);
    if (m) { writes.set(m[2], m[1]); continue; }
    if (next) { grant = line.trim(); next = false; continue; }
    if (line.includes('SYNTHESIZED GRANT')) { next = true; continue; }
    const s = line.match(/AF_INET sockets:\s*(\d+)/);
    if (s) sockets = Number(s[1]);
  }
  return { writes, grant, sockets };
}

// The synthesizer, restated over a scope SET rather than a bucket map. Same key order as
// observe.mjs, so a union of one run reproduces that run's own grant byte for byte — the property
// that makes the default `NUB_V2_OBSERVE_RUNS=1` a no-op and is asserted in the tests.
//
// ⛔ IT ITERATES `GRANT_SCOPES` RATHER THAN TESTING THREE HARDCODED KEYS, so the list above is
// LOAD-BEARING and a wrong entry in it is caught by a test. A first revision hardcoded the three and
// left `GRANT_SCOPES` decorative: adding `outside` to it changed nothing and every test stayed green
// — a test that cannot fail, which reads as coverage and is not.
export function synthesize(scopes, network) {
  const g = {};
  for (const s of GRANT_SCOPES) if (scopes.has(s)) g.write = { ...(g.write ?? {}), [s]: true };
  if (network) g.network = true;
  return g;
}

export function union(runs) {
  const scopes = new Set(), all = new Map();
  let network = false;
  for (const r of runs) {
    for (const [p, s] of r.writes) { all.set(p, s); scopes.add(s); }
    // A run whose report carried no socket line falls back to its own grant text, so a format change
    // in one of the two places cannot silently zero the network axis.
    if (r.sockets > 0 || /"network":\s*true/.test(r.grant ?? '')) network = true;
  }
  return { grant: synthesize(scopes, network), paths: all };
}

// What run `i` saw that no OTHER run saw, split by whether the scope can reach a grant. The split is
// the whole reason the headline is a grant-level rate: a run-to-run difference confined to
// `outside`/`jailHome`/`ownPkg`/`kernelfs` cannot move a grant, and counting it would inflate the
// rate with churn that breaks nothing. Shared with the report so the printed number and the tested
// number cannot drift.
export function onlyIn(runs, i) {
  const others = runs.filter((_, j) => j !== i);
  const only = [...runs[i].writes].filter(([p]) => !others.some((o) => o.writes.has(p)));
  return { only, decisive: only.filter(([, s]) => GRANT_SCOPES.includes(s)) };
}

// Per-run grants compared as CANONICAL JSON. `JSON.stringify` on the object built by `synthesize`
// is already canonical — one key order, no optional whitespace — because both grants come out of
// the same constructor. Comparing the raw grant TEXT from two observe.mjs runs is equally safe for
// the same reason, and is what lets a run whose text failed to parse (`null`) refuse agreement
// rather than silently support it.
export function grantAgreement(runs) {
  const seen = runs.map((r) => r.grant);
  const distinct = [...new Set(seen)];
  return { agree: distinct.length === 1 && distinct[0] != null, grants: seen, distinct };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const files = process.argv.slice(2);
  if (files.length < 1) { console.error('usage: observe-union.mjs <observed-1.txt> [...]'); process.exit(2); }
  const runs = files.map((f) => parseObserved(fs.readFileSync(f, 'utf8')));

  console.log(`== OBSERVE REPEAT == ${runs.length} run(s)`);
  runs.forEach((r, i) => {
    const byScope = {};
    for (const s of r.writes.values()) byScope[s] = (byScope[s] ?? 0) + 1;
    const shape = Object.entries(byScope).sort().map(([k, v]) => `${k}=${v}`).join(' ');
    console.log(`  run ${i + 1}: writes=${r.writes.size} sockets=${r.sockets ?? '?'} [${shape}]  grant=${r.grant}`);
  });

  // Path-level: what each run saw that no OTHER run saw. Reported per run rather than only pairwise
  // so a three-run comparison stays readable, and split by whether the scope can reach a grant —
  // an `outside`-only difference is noise by construction and saying so keeps it from being read as
  // a near miss.
  if (runs.length > 1) {
    console.log('== PATH-LEVEL DISAGREEMENT ==');
    runs.forEach((_r, i) => {
      const { only, decisive } = onlyIn(runs, i);
      console.log(`  only in run ${i + 1}: ${only.length} paths (${decisive.length} in a grant-bearing scope)`);
      only.slice(0, 12).forEach(([p, s]) => console.log(`      [${s}] ${p}`));
      if (only.length > 12) console.log(`      … and ${only.length - 12} more`);
    });
  }

  const { grant, paths } = union(runs);
  const agr = grantAgreement(runs);
  console.log('== GRANT-LEVEL DISAGREEMENT ==');
  console.log(`  per-run grants: ${JSON.stringify(agr.grants)}`);
  console.log(`  verdict: ${runs.length < 2 ? 'N/A (single run)' : agr.agree ? 'AGREE' : '⛔ DISAGREE'}`);
  console.log(`  union write paths: ${paths.size}`);
  console.log('== UNION GRANT (the safe answer; over-granting by construction) ==');
  console.log('  ' + JSON.stringify(grant));
}
