// The known-answer assertion. Both directions, and the direction that is usually skipped is the one
// that matters: an adapter which reports a write the fixture never performed causes an OVER-GRANT,
// and nothing downstream can detect it.
//
//   usage: node expect-macos.mjs <events.ndjson> <projDir> <fixHome> <arm:full|skip-home> [--selftest]
//
// ⛔ WHY --selftest EXISTS. "13 assertions passed" is worth nothing on its own. An assertion can be
// green because the adapter is right, or because the assertion CANNOT FAIL — it reads a field that
// is always present, or asserts the absence of something this platform could never produce. The
// Windows adapter's equivalent control is what caught its parser emitting ZERO events from 16470
// while its suite still looked healthy.
//
// So every check here is evaluated a SECOND time against a deliberately corrupted copy of the event
// stream, and is required to go RED. The corruption is per-check and minimal:
//   * a MUST-SEE check has its supporting evidence DELETED  → it must now fail.
//   * a MUST-NOT check has the forbidden event INJECTED     → it must now fail.
// A check that stays green under its own mutation is not testing anything, and --selftest fails.
import fs from 'node:fs';

const args = process.argv.slice(2);
const selftest = args.includes('--selftest');
const [file, proj, home, arm] = args.filter((a) => a !== '--selftest');
const events = fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));

const P = {
  projWrite: `${proj}/project-write.txt`,
  homeWrite: `${home}/home-write.txt`,
  readOnly: `${proj}/read-only-input.txt`,
  deniedFile: `${proj}/denied.txt`,
  nearMiss: `${proj}/nearmiss.txt`,
  untouched: `${proj}/untouched.txt`,
};
const wantHome = arm === 'full';

// The whole assertion set as a PURE function of the event array, so the mutation control can call it
// with a corrupted stream and get a comparable answer. Nothing here may read the filesystem or the
// clock — determinism rule 5 in ../MAPPING.md binds the validator as much as the mapper.
const evaluate = (evs) => {
  const paths = (op) => new Set(evs.filter((e) => e.op === op && e.path).map((e) => e.path));
  const writes = paths('write'), reads = paths('read'), execs = paths('exec');
  const denied = new Set(evs.filter((e) => e.result === 'denied' && e.path).map((e) => e.path));
  const connects = evs.filter((e) => e.op === 'connect');
  return [
    // ── FALSE-NEGATIVE DETECTORS: the adapter must not miss a real access ──
    ['MUST-SEE  project write (a `>` redirect performed BY THE SHELL)', writes.has(P.projWrite)],
    ['MUST-SEE  read of a file the fixture never writes', reads.has(P.readOnly)],
    ['MUST-SEE  exec reached depth 3 (the fixture binary itself)', [...execs].some((p) => p.endsWith('/fixture'))],
    ['MUST-SEE  a TCP connect was reported at all', connects.length > 0],
    ['MUST-SEE  the EACCES open surfaced as result:"denied"', denied.has(P.deniedFile)],

    // ── FALSE-POSITIVE DETECTORS: the adapter must not invent one ──
    ['MUST-NOT  the read-only file reported as a WRITE', !writes.has(P.readOnly)],
    ['MUST-NOT  the successful openat near-miss reported as denied', !denied.has(P.nearMiss)],
    ['MUST-NOT  a file the fixture never touched appears in ANY event', !evs.some((e) => e.path === P.untouched)],
    ['MUST-NOT  any connect event carries a fabricated host/port', !connects.some((e) => 'host' in e || 'port' in e)],

    // ── THE FALSIFICATION CONTROL ──
    // Arm `full` performs the $HOME write; arm `skip-home` provably does not. The SAME assertion is
    // asserted true in one and false in the other, so a green run cannot come from an adapter that
    // reports everything, and equally cannot come from one that reports nothing.
    [`CONTROL   $HOME write ${wantHome ? 'present (arm=full)' : 'ABSENT (arm=skip-home)'}`,
      writes.has(P.homeWrite) === wantHome],

    // Every emitted event must carry a real pid — the contract's whole point is attribution.
    ['SCHEMA    every event carries a numeric pid', evs.every((e) => typeof e.pid === 'number')],
  ];
};

// The per-check mutation, positionally paired with `evaluate`'s checks. The arity assertion below is
// what stops a reordering from silently leaving a check uncontrolled.
const drop = (pred) => (evs) => evs.filter((e) => !pred(e));
const add = (ev) => (evs) => [...evs, { pid: 1, ppid: 0, result: 'ok', ...ev }];
const MUTATIONS = [
  drop((e) => e.op === 'write' && e.path === P.projWrite),
  drop((e) => e.op === 'read' && e.path === P.readOnly),
  drop((e) => e.op === 'exec' && typeof e.path === 'string' && e.path.endsWith('/fixture')),
  drop((e) => e.op === 'connect'),
  drop((e) => e.result === 'denied' && e.path === P.deniedFile),
  add({ op: 'write', path: P.readOnly }),
  add({ op: 'read', path: P.nearMiss, result: 'denied' }),
  add({ op: 'read', path: P.untouched }),
  add({ op: 'connect', host: '203.0.113.1', port: 443 }),
  // The control flips with the arm: delete the home write in `full`, inject one in `skip-home`.
  // Either way the check must stop holding.
  wantHome ? drop((e) => e.op === 'write' && e.path === P.homeWrite) : add({ op: 'write', path: P.homeWrite }),
  (evs) => [...evs, { op: 'read', path: '/etc/hosts', result: 'ok', ppid: 0 }],   // pid deliberately absent
];

const checks = evaluate(events);
let bad = 0;
console.log(`\n=== KNOWN-ANSWER VALIDATION  (arm=${arm}, ${events.length} events) ===`);
for (const [label, ok] of checks) { if (!ok) bad++; console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`); }

const writes = new Set(events.filter((e) => e.op === 'write' && e.path).map((e) => e.path));
const reads = new Set(events.filter((e) => e.op === 'read' && e.path).map((e) => e.path));
const execs = new Set(events.filter((e) => e.op === 'exec' && e.path).map((e) => e.path));
const denied = new Set(events.filter((e) => e.result === 'denied' && e.path).map((e) => e.path));
console.log(`\n  writes(${writes.size}) reads(${reads.size}) execs(${execs.size}) denied(${denied.size}) connects(${events.filter((e) => e.op === 'connect').length})`);
const inRoots = [...writes].filter((p) => p.startsWith(proj) || p.startsWith(home));
console.log(`  writes inside the declared roots: ${JSON.stringify(inRoots.sort(), null, 0)}`);

// ── THE MUTATION CONTROL ──────────────────────────────────────────────────────────────────────
// Mutating an ALREADY-FAILING check proves nothing, so those are reported as SKIP and counted
// against the control rather than quietly passing it.
let selftestBad = 0;
if (selftest) {
  console.log(`\n=== MUTATION CONTROL (arm=${arm}) — every check must go RED when its own evidence is corrupted ===`);
  if (MUTATIONS.length !== checks.length) {
    console.log(`  FAIL  arity: ${checks.length} checks but ${MUTATIONS.length} mutations — a check has no control`);
    selftestBad++;
  }
  for (let i = 0; i < Math.min(checks.length, MUTATIONS.length); i++) {
    const [label, originallyOk] = checks[i];
    if (!originallyOk) { console.log(`  SKIP  ${label}   (already failing; mutation proves nothing)`); selftestBad++; continue; }
    const stillGreen = evaluate(MUTATIONS[i](events))[i][1] !== false;
    if (stillGreen) selftestBad++;
    console.log(`  ${stillGreen ? 'FAIL' : 'RED '}  ${label}${stillGreen ? '   <-- STAYED GREEN UNDER MUTATION: this check cannot fail' : ''}`);
  }
  console.log(selftestBad === 0
    ? `\n  MUTATION CONTROL ${arm}: all ${checks.length} checks demonstrably able to fail`
    : `\n  MUTATION CONTROL ${arm}: ${selftestBad} CHECK(S) WITHOUT A WORKING CONTROL`);
}

console.log(bad === 0 ? `\n  ARM ${arm}: ALL CHECKS PASSED` : `\n  ARM ${arm}: ${bad} CHECK(S) FAILED`);
process.exit(bad === 0 && selftestBad === 0 ? 0 : 1);
