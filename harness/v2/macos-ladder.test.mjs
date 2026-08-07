// The macOS bounded ladder, EXECUTED — not grepped for.
//
// ⛔ WHY THIS FILE RUNS SHELL INSTEAD OF PINNING STRINGS. `descent-vocabulary.test.mjs` and
// `descent-contract.test.mjs` are both source-matching guards, and a source-matching guard cannot
// tell a ladder that FIRES from three rung literals sitting in a file next to a `for` loop that is
// never reached. The defect being fixed here was exactly an absence, so a test that would pass on the
// absent code is worth nothing. Every assertion below is made against the driver's real stdout.
//
// ⛔ WHAT IS STUBBED, AND WHY THAT IS STILL A REAL TEST. `verify` is the one thing that cannot run
// here: it needs sudo, dtrace, a nub binary built with `build-jail-catalog-override`, and a live
// npm registry. Everything else — the rung sequence, the rc 0/1/2 branching, the `write:"disk"`
// guard, the descent's variant generation (real `node -e`), the exact sentences `record.mjs` reads —
// is the driver's own code, executed. The stub is the ORACLE, so each case states which arms pass and
// the test reads what the driver concluded from that.
//
// ⛔ AND THE FALSIFICATION CONTROL IS IN THE FILE, NOT IN A COMMIT MESSAGE. `LADDERLESS` deletes the
// `for` loop from the extracted source and re-runs the identical stub; the case at the bottom asserts
// that the ladder findings VANISH. Without it, every case here would keep passing if the ladder were
// removed tomorrow, which is the state this file exists to end.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const DRIVER = fs.readFileSync(path.join(HERE, 'measure-macos.sh'), 'utf8');

// The driver's post-VERIFY tail: the descent function, the DIAGNOSE arm and the ladder. Anchored on
// the section banner rather than a line number so an edit above it cannot silently shift the slice.
const REGION = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => /^# ── 3b\. NARROW/.test(l));
  return start < 0 ? '' : lines.slice(start).join('\n');
})();

const RUNG0 = '{"write":{"deps":true,"project":true,"userHome":true},"network":true}';
const RUNG1 = '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}';
const RUNG2 = '{"write":"disk","network":true}';

test('INSTRUMENT: the region was located and holds the three rungs and the descent', () => {
  assert.ok(REGION.length > 1500, `the 3b banner was not found in measure-macos.sh (got ${REGION.length} chars)`);
  for (const needle of [RUNG0, RUNG1, RUNG2, 'descend () {', 'ladder fallback']) {
    assert.ok(REGION.includes(needle), `the extracted region no longer contains \`${needle}\``);
  }
});

/**
 * Run the extracted region with a stubbed `verify`, and return its stdout.
 *
 * `oracle` is bash injected into the stub: it sees `$1` (grant JSON) and `$2` (arm label) and must
 * `return` 0 SUFFICIENT / 1 INSUFFICIENT / 2 VOID, which is `verify`'s real three-outcome contract.
 * Arm labels are the driver's own: `fb<cksum>` per rung, `nar-no-<capability>` per descent arm,
 * `joint-narrow`, `diag`.
 */
const run = (oracle, { verified = 0, grant = '{"write":{"deps":true}}', source = REGION } = {}) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-ladder-'));
  const script = path.join(root, 'region.sh');
  fs.writeFileSync(script, [
    'set -uo pipefail',
    `ROOT=${JSON.stringify(root)}`,
    'PKG=demo; VER=1.0.0',
    `GRANT='${grant}'`,
    `VERIFIED=${verified}`,
    // The real driver prints this during OBSERVE, well above the extracted region. `record.mjs` gates
    // the whole grant-source rule on seeing it — absence is read as "the check never ran" — so a
    // round trip that omitted it would test the wrong branch of `applyGrantSourceRule`.
    'echo \'  ARM-FALSIFIABILITY {"pkg":"demo","falsifiable":true}\'',
    'verify () {',
    '  local grant="$1" label="$2"',
    oracle,
    '}',
    source,
  ].join('\n'));
  try {
    return execFileSync('bash', [script], { encoding: 'utf8' });
  } catch (e) {
    // The ladder exits 3 on a VOID rung, and that path still has stdout worth asserting on.
    if (e.stdout !== undefined) return e.stdout;
    throw e;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
};

// Rung 0 suffices. Of its four capabilities only `network` turns out to be droppable, so the descent
// lands at N=1 — the case `applyGrantSourceRule` publishes as `descended` off a single real arm.
const RUNG0_PASSES_NETWORK_DROPS = `
  case "$label" in
    fb*) case "$grant" in *'"read":"disk"'*|*'"write":"disk"'*) return 1 ;; *) return 0 ;; esac ;;
    nar-no-network) return 0 ;;
    *) return 1 ;;
  esac
`;

test('⭑ the ladder FIRES when the synthesized grant fails, and says so in record.mjs\'s words', () => {
  const out = run(RUNG0_PASSES_NETWORK_DROPS);
  assert.match(out, /falling back to a bounded ladder/, 'the driver never entered the ladder');
  assert.ok(out.includes(`  => MINIMUM ${RUNG0}   (ladder fallback; synthesized grant was insufficient)`),
    `the ladder verdict line is not the wording record.mjs parses:\n${out}`);
});

test('⭑ a ladder record is a MINIMUM with verifiedBy "ladder", where before it was a dead UNDER-PREDICTED', () => {
  // ⛔ THE ACCEPTANCE CRITERION FOR THE WHOLE CHANGE. `collate.mjs` drops every verdict that is not
  // `MINIMUM`, so the old terminal `UNDER-PREDICTED` produced NO catalog entry and the package fell
  // back to the restrictive base profile at install time — a broken install. `verifiedBy` is what
  // keeps a repaired grant distinguishable from one synthesis got right first time.
  const r = parseDriverLog(run(RUNG0_PASSES_NETWORK_DROPS));
  assert.equal(r.verdict, 'MINIMUM');
  assert.equal(r.verifiedBy, 'ladder');
  assert.ok(r.notes.includes('under-predicted'),
    'the record must still carry the finding that OBSERVE under-predicted, as Linux and Windows do');
});

test('⭑ the winning rung DESCENDS — a bundle is never published un-narrowed', () => {
  // ⛔ THE SECOND HALF OF THE PORT, AND THE ONE THAT PROTECTS THE JAIL\'S CORE PROPERTY. Rung 0 grants
  // deps + project + userHome + network on the strength of ONE arm, and `userHome` is write access to
  // `~/.ssh` and every shell profile — the PERSISTENCE capability. The descent is what says which of
  // the four the package actually needed.
  const r = parseDriverLog(run(RUNG0_PASSES_NETWORK_DROPS));
  assert.deepEqual(r.overPredictedBy, ['no-network'], 'the descent did not run over the ladder rung');
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: { deps: true, project: true, userHome: true } },
    'the published grant still carries `network`, which an arm proved droppable off the RUNG');
});

test('the ladder climbs: rung 0 and rung 1 fail, and the record reports the rung that passed', () => {
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `);
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'MINIMUM');
  assert.deepEqual(r.grant, { write: 'disk', network: true });
});

test('⭑ the write:"disk" rung is NOT descended — Object.keys on a string would fabricate arms', () => {
  // ⛔ `Object.keys("disk")` IS `["0","1","2","3"]`. Handing the top rung to the variant generator
  // would manufacture four `no-write-<digit>` arms, none of which `record.mjs` can parse — so the
  // record would carry `descent-name-unparsed` off a measurement of nothing. It is also the absence
  // of confinement rather than a grant with droppable terms.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 0 ;;
    esac
  `);
  assert.match(out, /no droppable terms, so no descent/);
  assert.doesNotMatch(out, /no-write-0/, 'the string rung was fed to the variant generator');
  const r = parseDriverLog(out);
  assert.deepEqual(r.overPredictedBy, [], 'a descent ran over write:"disk"');
  assert.ok(!r.notes.includes('descent-name-unparsed'));
});

test('⭑ a VOID rung stops the ladder instead of climbing past a grant it never tested', () => {
  // Collapsing VOID into "this rung failed" makes the ladder publish the NEXT rung as the minimum on
  // the strength of no measurement at all.
  const out = run(`
    case "$label" in
      fb*) return 2 ;;
      *) return 1 ;;
    esac
  `);
  assert.match(out, /VOID rung — override did not engage/);
  const r = parseDriverLog(out);
  assert.notEqual(r.verdict, 'MINIMUM', 'a VOID rung must never yield a published minimum');
});

test('⭑ every rung failing is still the terminal UNDER-PREDICTED, with no grant', () => {
  // The honest end of the ladder: nothing this harness can express installs the package, so there is
  // genuinely no measured minimum and `collate.mjs` is right to exclude it. This is the ONLY case in
  // which that verdict should now appear.
  const r = parseDriverLog(run('  return 1'));
  assert.equal(r.verdict, 'UNDER-PREDICTED');
  assert.equal(r.grant, null, 'a verdict with no state that passed must not publish a grant');
});

test('the synth-verified path is untouched: it descends from GRANT, not from a rung', () => {
  // The regression guard for turning the descent into a function. `$GRANT` here, `$g0` inside.
  const out = run(`
    case "$label" in
      nar-no-write-deps) return 0 ;;
      *) return 1 ;;
    esac
  `, { verified: 1, grant: '{"write":{"deps":true},"network":true}' });
  assert.doesNotMatch(out, /bounded ladder/, 'a verified grant must not reach the ladder');
  const r = parseDriverLog(out);
  assert.deepEqual(r.overPredictedBy, ['no-write-deps']);
});

// ── THE FALSIFICATION CONTROL ─────────────────────────────────────────────────────────────────────

// The driver with the ladder's `for` loop excised, everything else identical. This is what the file
// looked like before the port, reconstructed mechanically rather than pasted, so it cannot go stale.
const LADDERLESS = REGION.replace(/\n {2}for g in \\\n[\s\S]*?\n {2}done\n/, '\n');

test('⭑ FALSIFICATION: with the ladder removed, every finding above disappears', () => {
  // ⛔ WITHOUT THIS THE WHOLE FILE IS UNFALSIFIABLE. A passing test is not evidence until it has been
  // seen to fail for the right reason, and the reason here has to be the ladder's absence
  // specifically — not a broken stub, not a mangled extraction.
  assert.notEqual(LADDERLESS, REGION, 'the excision matched nothing, so this control is vacuous');
  assert.ok(!LADDERLESS.includes(RUNG0), 'the rungs survived the excision');
  assert.ok(LADDERLESS.includes('descend () {'), 'the excision removed more than the ladder');

  const out = run(RUNG0_PASSES_NETWORK_DROPS, { source: LADDERLESS });
  assert.doesNotMatch(out, /ladder fallback/, 'the ladderless driver still published a ladder minimum');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'UNDER-PREDICTED', 'this is the dead-end verdict the port exists to eliminate');
  assert.equal(r.grant, null);
  assert.notEqual(r.verifiedBy, 'ladder');
});
