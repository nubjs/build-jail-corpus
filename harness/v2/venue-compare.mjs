// The venue-portability acceptance test: read N measured cells, compare them, and run both controls.
//
// ⛔ THE DELIVERABLE IS A 2x2, NOT A PAIR, because venue and CI-ness are different axes and
// collapsing them is the mistake VENUE-PORTABILITY.md warns about at length:
//
//                | CI unset                      | CI=1
//   VM           | the real-laptop case          | isolates CI-ness from venue
//   CI runner    | isolates venue from CI-ness   | the real-CI case
//
//   DOWN a column  same package, same CI state, different machine  =>  THE GRANT MUST BE IDENTICAL.
//                  Not identical logs — absolute paths necessarily differ, and a harness producing
//                  identical logs would be one that had flattened a real difference.
//   ACROSS a row   same machine, different CI state  =>  a difference is a REAL FINDING, not a
//                  defect. `CI` disables the global virtual store, relocating every dependency's
//                  materialised directory from the user's cache into the project, so a write can
//                  genuinely change scope. Where the two disagree the catalog takes the UNION.
//
// ⛔ AND THE RESULT MEANS NOTHING WITHOUT BOTH CONTROLS. "The grants matched" is equally consistent
// with a comparison that cannot detect a difference at all, so this refuses to report a verdict
// unless a deliberate perturbation CHANGED the grant.
//
//   POSITIVE (must MATCH)  every cell's archive is RE-DECODED here, on this machine, and must
//                          reproduce the grant its own venue published. That is the R2 claim
//                          stated as a test: the decode is a property of the archive, not of the
//                          reader. Run this on a third machine and it is stronger still.
//   NEGATIVE (must DIFFER) one root is deliberately falsified and the grant must change.
//
// ⛔ THE NEGATIVE CONTROL PERTURBS A ROOT THE SUBJECT ACTUALLY WRITES UNDER, WHICH IS PER-PACKAGE
// AND NOT A FIXED RECIPE. An earlier attempt at this test perturbed a root the subject never
// touched; the grant was unchanged, the control "passed" by being vacuous, and it demonstrated
// nothing. So the root to falsify is CHOSEN from the cell's own observed writes — and if no
// perturbation can change the grant, that is reported as an inadmissible control rather than
// papered over.
//
//   usage: node venue-compare.mjs --cell <label>=<dir> [--cell ...] [--json out.json]
//
//   <dir> is a driver run root holding `observed.json` plus its `cap/` capture directory.
//   <label> is `<venue>/<ci-state>`, e.g. `vm/ci-unset`, `ci/ci-set`.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const HERE = import.meta.dirname;
const args = process.argv.slice(2);
const jsonOut = (() => { const i = args.indexOf('--json'); return i >= 0 ? args[i + 1] : null; })();
const cells = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] !== '--cell') continue;
  const [label, ...rest] = args[i + 1].split('=');
  cells.push({ label, dir: rest.join('=') });
}
if (cells.length < 2) {
  console.error('usage: venue-compare.mjs --cell <venue>/<ci-state>=<run-dir> [--cell ...] [--json f]');
  process.exit(2);
}

const G = (g) => JSON.stringify(g === null || g === undefined ? null : sortDeep(g));
// Two grants that differ only in key order are the same grant. Comparing raw JSON text would report
// a mismatch the catalog does not have, which is the kind of false finding that discredits the run.
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])]));
  }
  return v;
}

// ── Load ────────────────────────────────────────────────────────────────────────────────────────
for (const c of cells) {
  const runDir = fs.existsSync(path.join(c.dir, 'observed.json'))
    ? c.dir
    // The driver mints a `m-<pkg>-<rand>` subdirectory per run, so a caller may reasonably hand us
    // either it or its parent. Resolving one level is a convenience; guessing further is not.
    : fs.readdirSync(c.dir).map((d) => path.join(c.dir, d)).find((d) => fs.existsSync(path.join(d, 'observed.json')));
  if (!runDir) { console.error(`⛔ ${c.label}: no observed.json under ${c.dir}`); process.exit(3); }
  c.runDir = runDir;
  c.observed = JSON.parse(fs.readFileSync(path.join(runDir, 'observed.json'), 'utf8'));
  c.capDir = path.join(runDir, 'cap');
  c.capture = JSON.parse(fs.readFileSync(path.join(c.capDir, 'capture.json'), 'utf8'));
  c.ndjson = path.join(c.capDir, 'events.ndjson');
  const [venue, ci] = c.label.split('/');
  c.venue = venue;
  c.ci = ci;
  c.grant = c.observed.grant;
}

// ── Re-decode a cell HERE, from its archive alone ────────────────────────────────────────────────
//
// ⛔ THIS IS THE POSITIVE CONTROL AND IT IS THE R2 CLAIM ITSELF. Before the 8.3 map became an
// archive artifact, `windows.mjs` and `windows-retain.mjs` gated short-name expansion on
// `meta.host == process.env.COMPUTERNAME`, so this function would have returned one answer on the
// capture host and a different one everywhere else — including here. Any machine may run it now.
//
// `capture.json` may be REWRITTEN with perturbed roots, which is how the negative control works;
// the events and the 8.3 map are untouched, so exactly one variable moves.
function rootPidOf(cell) {
  const pid = cell.capture.run?.rootPid;
  if (typeof pid !== 'number' || !Number.isFinite(pid)) {
    console.error(`⛔ ${cell.label}: capture.json declares no run.rootPid, so this archive cannot be`);
    console.error('   re-classified. Attribution keys on it; defaulting would silently widen the grant.');
    process.exit(3);
  }
  return pid;
}

function reclassify(cell, { roots = null, label = 're-decode' } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'venue-'));
  const cap = path.join(dir, 'capture.json');
  const outJson = path.join(dir, 'observed.json');
  fs.writeFileSync(cap, JSON.stringify(roots ? { ...cell.capture, roots } : cell.capture, null, 2));
  const r = spawnSync(process.execPath, [
    path.join(HERE, 'classify.mjs'), cell.ndjson,
    '--capture', cap,
    // ⛔ NODE'S `process.platform` VALUE, NOT THE `win32-x64` CORPUS PLATFORM ID. `classify.mjs`
    // derives its separator handling, case folding and kernelfs/systemfs predicates from this, so
    // it must say `win32` however the capture spells its platform — which is exactly what lets a
    // Windows archive be decoded correctly on a Linux or macOS machine.
    '--platform', (cell.capture.platform ?? '').startsWith('win32') ? 'win32'
      : (cell.capture.platform ?? '').startsWith('darwin') ? 'darwin' : 'linux',
    // ⛔ FROM THE ARCHIVE, AND FATAL IF ABSENT. Attribution depends on it: without the root pid the
    // traced root's own cmd.exe reads as a lifecycle shell, so npm's registry connections and its
    // profile cache writes enter the grant. That produces a plausible, much wider grant and would
    // make this control fail — or, worse, pass on two archives that were both decoded wrong the
    // same way. Guessing 0 here would be the ambient fallback R2 exists to forbid, one level up.
    '--root-pid', String(rootPidOf(cell)),
    '--json', outJson,
  ], { encoding: 'utf8' });
  const ok = r.status === 0 && fs.existsSync(outJson);
  const report = ok ? JSON.parse(fs.readFileSync(outJson, 'utf8')) : null;
  fs.rmSync(dir, { recursive: true, force: true });
  return { ok, status: r.status, stderr: r.stderr, grant: report?.grant ?? null, report, label };
}

const results = { cells: [], positive: [], negative: [], columns: [], rows: [], verdict: null };
const fail = [];

// ── POSITIVE CONTROL: every archive re-decodes here to the grant its venue published ────────────
console.log('== POSITIVE CONTROL — each archive re-decoded on THIS machine (must MATCH its venue) ==');
console.log(`   decoding host: ${process.platform}-${process.arch}\n`);
for (const c of cells) {
  const re = reclassify(c);
  const match = re.ok && G(re.grant) === G(c.grant);
  results.positive.push({ cell: c.label, published: c.grant, redecoded: re.grant, match });
  console.log(`   ${c.label.padEnd(14)} published ${G(c.grant)}`);
  console.log(`   ${''.padEnd(14)} re-decoded ${G(re.grant)}   ${match ? 'MATCH' : '⛔ DIFFERS'}`);
  if (!match) {
    fail.push(`positive control: ${c.label} re-decoded to a different grant than its venue published`
      + (re.ok ? '' : ` (classify rc=${re.status}: ${re.stderr.trim()})`));
  }
}

// ── NEGATIVE CONTROL: falsify a root the SUBJECT ACTUALLY USES ──────────────────────────────────
//
// The root is picked from the cell's OWN writes: whichever declared root the observed writes were
// bucketed under is the one whose falsification can move them. Perturbing anything else would be
// the vacuous control this file exists to refuse.
console.log('\n== NEGATIVE CONTROL — one falsified root (must DIFFER) ==');
for (const c of cells) {
  const buckets = Object.entries(c.observed.writes ?? {}).filter(([, n]) => n > 0).map(([k]) => k);
  // `deps` is `<project>\node_modules`, derived from `project` rather than declared separately, so
  // both bucket names point at the same root to falsify.
  const rootFor = { deps: 'project', project: 'project', userHome: 'home' };
  const target = buckets.map((b) => rootFor[b]).find(Boolean);
  if (!target) {
    fail.push(`negative control: ${c.label} has no write in a keyed scope, so NO perturbation of a`
      + ` declared root could change its grant — the control is inadmissible, not passing.`
      + ` Observed write buckets: ${JSON.stringify(c.observed.writes)}`);
    console.log(`   ${c.label.padEnd(14)} ⛔ INADMISSIBLE — no write lands in a keyed scope`);
    continue;
  }
  const wrong = { ...c.capture.roots, [target]: `${c.capture.roots[target]}-DELIBERATELY-WRONG` };
  const re = reclassify(c, { roots: wrong, label: `wrong ${target}` });
  const differs = re.ok && G(re.grant) !== G(c.grant);
  results.negative.push({ cell: c.label, perturbed: target, was: c.grant, became: re.grant, differs });
  console.log(`   ${c.label.padEnd(14)} falsified \`${target}\` (the root its ${buckets.join('+')} writes sit under)`);
  console.log(`   ${''.padEnd(14)} ${G(c.grant)} -> ${G(re.grant)}   ${differs ? 'DIFFERS (control has teeth)' : '⛔ UNCHANGED'}`);
  if (!differs) {
    fail.push(`negative control: ${c.label} produced the SAME grant under a falsified \`${target}\` root.`
      + ' The comparison cannot detect a difference, so no match it reports is evidence of anything.');
  }
}

// ── DOWN each column: venue portability ─────────────────────────────────────────────────────────
console.log('\n== VENUE PORTABILITY — down each column, same CI state, different machine (must MATCH) ==');
const ciStates = [...new Set(cells.map((c) => c.ci))].sort();
for (const ci of ciStates) {
  const col = cells.filter((c) => c.ci === ci);
  if (col.length < 2) {
    console.log(`   ${ci.padEnd(10)} only ${col.length} cell (${col.map((c) => c.venue).join(', ') || 'none'}) — NOT COMPARED, and not a pass`);
    results.columns.push({ ci, cells: col.map((c) => c.venue), compared: false });
    continue;
  }
  const grants = col.map((c) => G(c.grant));
  const same = grants.every((g) => g === grants[0]);
  console.log(`   ${ci.padEnd(10)} ${col.map((c) => `${c.venue}=${G(c.grant)}`).join('   ')}   ${same ? 'IDENTICAL' : '⛔ DIVERGED'}`);
  results.columns.push({ ci, cells: col.map((c) => ({ venue: c.venue, grant: c.grant })), compared: true, identical: same });
  if (!same) fail.push(`venue portability: the ${ci} column diverged across venues — ${col.map((c) => `${c.venue} ${G(c.grant)}`).join(' vs ')}`);
}

// ── ACROSS each row: the CI axis ────────────────────────────────────────────────────────────────
//
// ⛔ A DIFFERENCE HERE IS A FINDING, NOT A FAILURE, so it never enters `fail`. `CI` disables the
// global virtual store, which relocates every dependency's materialised directory into the project
// — a write can genuinely change scope. The catalog's answer is the UNION, because over-granting is
// safe and under-granting breaks installs.
console.log('\n== THE CI AXIS — across each row, same machine, CI toggled (a difference is a FINDING) ==');
const venues = [...new Set(cells.map((c) => c.venue))].sort();
for (const venue of venues) {
  const row = cells.filter((c) => c.venue === venue);
  if (row.length < 2) {
    console.log(`   ${venue.padEnd(10)} only ${row.length} cell — NOT COMPARED`);
    results.rows.push({ venue, compared: false });
    continue;
  }
  const grants = row.map((c) => G(c.grant));
  const same = grants.every((g) => g === grants[0]);
  const union = row.reduce((acc, c) => mergeGrant(acc, c.grant), {});
  console.log(`   ${venue.padEnd(10)} ${row.map((c) => `${c.ci}=${G(c.grant)}`).join('   ')}   ${same ? 'same' : 'DIFFER -> catalog takes the UNION'}`);
  if (!same) console.log(`   ${''.padEnd(10)} union ${G(union)}`);
  results.rows.push({ venue, cells: row.map((c) => ({ ci: c.ci, grant: c.grant })), compared: true, same, union });
}

// Union of two grants: a capability present in EITHER is present in the result. `write: "disk"`
// dominates a per-scope write object, since it is strictly wider.
function mergeGrant(a, b) {
  const out = { ...a };
  for (const [k, v] of Object.entries(b ?? {})) {
    if (k === 'write' && typeof out.write === 'object' && typeof v === 'object') {
      out.write = { ...out.write, ...v };
    } else if (k === 'write' && (out.write === 'disk' || v === 'disk')) {
      out.write = 'disk';
    } else if (v === true || out[k] === undefined) {
      out[k] = v;
    }
  }
  return out;
}

for (const c of cells) {
  results.cells.push({
    label: c.label, venue: c.venue, ci: c.ci, grant: c.grant,
    roots: c.capture.roots, host: c.capture.os?.host ?? null,
    observeUser: c.capture.identity?.whoami ?? null,
    shortNameComponents: c.capture.shortNames ? Object.keys(c.capture.shortNames.entries).length : null,
    writes: c.observed.writes ?? null, peers: c.observed.peers ?? null,
  });
}

console.log('\n== VERDICT ==');
if (fail.length) {
  for (const f of fail) console.log(`  ⛔ ${f}`);
  results.verdict = 'FAIL';
} else {
  const comparedColumns = results.columns.filter((c) => c.compared).length;
  if (comparedColumns === 0) {
    console.log('  ⛔ NO COLUMN WAS COMPARED — this run has not tested venue portability at all.');
    results.verdict = 'INCONCLUSIVE';
  } else {
    console.log(`  PASS — ${comparedColumns} column(s) identical across venues, with a positive control that`);
    console.log('  matched and a negative control that DIFFERED on a root the subject actually writes under.');
    results.verdict = 'PASS';
  }
}
if (jsonOut) fs.writeFileSync(jsonOut, `${JSON.stringify(results, null, 2)}\n`);
process.exit(results.verdict === 'PASS' ? 0 : 1);
