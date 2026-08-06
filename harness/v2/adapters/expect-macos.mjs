// The known-answer assertion. Both directions, and the direction that is usually skipped is the one
// that matters: an adapter which reports a write the fixture never performed causes an OVER-GRANT,
// and nothing downstream can detect it.
//
//   usage: node expect-macos.mjs <events.ndjson> <projDir> <fixHome> <arm:full|skip-home>
import fs from 'node:fs';

const [file, proj, home, arm] = process.argv.slice(2);
const events = fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));

const paths = (op) => new Set(events.filter((e) => e.op === op && e.path).map((e) => e.path));
const writes = paths('write'), reads = paths('read'), execs = paths('exec');
const denied = new Set(events.filter((e) => e.result === 'denied' && e.path).map((e) => e.path));
const connects = events.filter((e) => e.op === 'connect');

const P = {
  projWrite: `${proj}/project-write.txt`,
  homeWrite: `${home}/home-write.txt`,
  readOnly: `${proj}/read-only-input.txt`,
  deniedFile: `${proj}/denied.txt`,
  nearMiss: `${proj}/nearmiss.txt`,
  untouched: `${proj}/untouched.txt`,
};
const wantHome = arm === 'full';

const checks = [
  // ── FALSE-NEGATIVE DETECTORS: the adapter must not miss a real access ──
  ['MUST-SEE  project write (a `>` redirect performed BY THE SHELL)', writes.has(P.projWrite)],
  ['MUST-SEE  read of a file the fixture never writes', reads.has(P.readOnly)],
  ['MUST-SEE  exec reached depth 3 (the fixture binary itself)', [...execs].some((p) => p.endsWith('/fixture'))],
  ['MUST-SEE  a TCP connect was reported at all', connects.length > 0],
  ['MUST-SEE  the EACCES open surfaced as result:"denied"', denied.has(P.deniedFile)],

  // ── FALSE-POSITIVE DETECTORS: the adapter must not invent one ──
  ['MUST-NOT  the read-only file reported as a WRITE', !writes.has(P.readOnly)],
  ['MUST-NOT  the successful openat near-miss reported as denied', !denied.has(P.nearMiss)],
  ['MUST-NOT  a file the fixture never touched appears in ANY event', !events.some((e) => e.path === P.untouched)],
  ['MUST-NOT  any connect event carries a fabricated host/port', !connects.some((e) => 'host' in e || 'port' in e)],

  // ── THE FALSIFICATION CONTROL ──
  // Arm `full` performs the $HOME write; arm `skip-home` provably does not. The SAME assertion is
  // asserted true in one and false in the other, so a green run cannot come from an adapter that
  // reports everything, and equally cannot come from one that reports nothing.
  [`CONTROL   $HOME write ${wantHome ? 'present (arm=full)' : 'ABSENT (arm=skip-home)'}`,
    writes.has(P.homeWrite) === wantHome],
];

// Every emitted event must carry a real pid — the contract's whole point is attribution.
const noPid = events.filter((e) => typeof e.pid !== 'number');
checks.push([`SCHEMA    every event carries a numeric pid (${noPid.length} without)`, noPid.length === 0]);

let bad = 0;
console.log(`\n=== KNOWN-ANSWER VALIDATION  (arm=${arm}, ${events.length} events) ===`);
for (const [label, ok] of checks) { if (!ok) bad++; console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`); }

console.log(`\n  writes(${writes.size}) reads(${reads.size}) execs(${execs.size}) denied(${denied.size}) connects(${connects.length})`);
const inRoots = [...writes].filter((p) => p.startsWith(proj) || p.startsWith(home));
console.log(`  writes inside the declared roots: ${JSON.stringify(inRoots.sort(), null, 0)}`);
console.log(bad === 0 ? `\n  ARM ${arm}: ALL CHECKS PASSED` : `\n  ARM ${arm}: ${bad} CHECK(S) FAILED`);
process.exit(bad === 0 ? 0 : 1);
