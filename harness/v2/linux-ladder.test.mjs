// The Linux bounded ladder, EXECUTED — not grepped for.
//
// ⛔ WHY THIS FILE RUNS SHELL INSTEAD OF PINNING STRINGS. `descent-vocabulary.test.mjs` covers
// `measure.sh` already, but it is a source-matching guard plus a set of hand-written logs fed to
// `record.mjs` — and neither half can tell a ladder that DESCENDS from three rung literals sitting
// beside a `for` loop that publishes whatever passed. The defect this file was written for was
// exactly that absence: `measure.sh` walked the ladder and then `exit 0`-ed on the winning rung
// verbatim, so a package repaired by rung 0 got `deps` + `project` + `userHome` + `network` in the
// catalog because ONE arm passed. Every assertion below is made against the driver's real stdout.
//
// ⛔ WHAT IS STUBBED, AND WHY THAT IS STILL A REAL TEST. `verify` is the one thing that cannot run
// here: it needs strace, a nub binary built with `build-jail-catalog-override`, and a live npm
// registry. Everything else — the rung sequence, the rc 0/1/2 branching, the `write:"disk"` guard,
// the descent's variant generation (real `node -e`), `diagnose`, the grant-independence predicate
// (real `shortfall-invariance.mjs`), the exact sentences `record.mjs` reads — is the driver's own
// code, executed. The stub is the ORACLE, so each case states which arms pass and the test reads what
// the driver concluded from that.
//
// ⛔ `ARM_LEDGER` IS A SEPARATE INPUT FROM THE ORACLE, AND CONFLATING THEM WOULD BE WRONG. The real
// `verify` records the INSTALL's exit code in the ledger while RETURNING on `rc == 0 && gate == 0`,
// so an arm that installed cleanly and then failed the artifact gate is `rc=0` in the ledger and
// "insufficient" to the caller. That gap is the whole subject of `ARTIFACT-GATE-SUSPECT`. A stub that
// derived one from the other could not express it, so each case states the ledger it wants.
//
// ⛔ AND THE FALSIFICATION CONTROL IS IN THE FILE, NOT IN A COMMIT MESSAGE. `LADDERLESS` deletes the
// `for` loop from the extracted source and re-runs the identical stub; the case at the bottom asserts
// that the ladder findings VANISH. Without it, every case here would keep passing if the ladder were
// removed tomorrow.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const DRIVER = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');

// The driver's post-VERIFY tail: the descent function, the DIAGNOSE arm, the ladder and the
// grant-independence check. Anchored on the section banner rather than a line number so an edit above
// it cannot silently shift the slice.
const REGION = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => /^# ── 3a\. DESCEND/.test(l));
  return start < 0 ? '' : lines.slice(start).join('\n');
})();

const RUNG0 = '{"write":{"deps":true,"project":true,"userHome":true},"network":true}';
const RUNG1 = '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}';
const RUNG2 = '{"write":"disk","network":true}';

test('INSTRUMENT: the region was located and holds the three rungs and the descent', () => {
  assert.ok(REGION.length > 1500, `the 3a banner was not found in measure.sh (got ${REGION.length} chars)`);
  for (const needle of [RUNG0, RUNG1, RUNG2, 'descend () {', 'ladder fallback']) {
    assert.ok(REGION.includes(needle), `the extracted region no longer contains \`${needle}\``);
  }
});

// A four-arm ledger whose shortfall digest CHANGES across arms, so `shortfall-invariance.mjs` refuses
// and the all-rungs-fail path lands on its real terminal verdict rather than on the SUSPECT escape.
// Format is `verify`'s own: `<install rc>:<shortfall digest>:<ok|abs>:<missing count>`.
//
// ⛔ THIS FIXTURE WAS REACHING THE PREDICATE AS ONE ARM AND REFUSING FOR THE WRONG REASON, TWICE OVER,
// and every case here stayed green because they all check only the terminal verdict — which is a
// refusal either way. Found while porting this stage to the other two drivers; both defects are fixed
// and an INSTRUMENT case below pins them.
//
//   1. `JSON.stringify` renders the separators as the two characters `\` `n`, which bash inside
//      double quotes does not interpret, so the predicate saw ONE line and answered `ladder was not
//      fully walked`. The assignment is single-quoted now; a real newline survives that verbatim.
//   2. Every arm was rc=1, and the predicate checks exit codes BEFORE digests, so it answered `an arm
//      exited non-zero` and never looked at the shortfall. rc=0 is what puts the DIGEST clause — the
//      one that does the separating — in the refusing position, and it is the realistic shape besides:
//      an install that exits clean and then fails the artifact gate is why this stage exists at all.
const LEDGER_RESPONSIVE = ['0:aa11:ok:9', '0:bb22:ok:7', '0:cc33:ok:4', '0:dd44:ok:2'].join('\n') + '\n';

/**
 * Run the extracted region with a stubbed `verify`, and return its stdout.
 *
 * `oracle` is bash injected into the stub: it sees `$1` (grant JSON) and `$2` (arm label) and must
 * `return` 0 SUFFICIENT / 1 INSUFFICIENT / 2 VOID, which is `verify`'s real three-outcome contract.
 * Arm labels are the driver's own: `fb<cksum>` per rung, `drop-<variant>` per descent arm,
 * `joint-narrow`, `diag`.
 *
 * ⛔ `HERE` IS `import.meta.dirname`, WHICH IS THE RESOLVED PATH. The driver's own `HERE` is
 * `cd "$(dirname "$0")" && pwd`, i.e. the LOGICAL path — and `shortfall-invariance.mjs`'s
 * main-module guard compares `import.meta.url` (physical) against `pathToFileURL(process.argv[1])`
 * (as given). Handing it a path through a symlink makes it exit 0 printing nothing, which the driver
 * reads as GRANT-INDEPENDENT. That bit this test during development, on macOS, where `/tmp` is a
 * symlink to `/private/tmp`.
 */
const run = (oracle, {
  src = 1, grant = '{"write":{"deps":true}}', source = REGION, ledger = LEDGER_RESPONSIVE,
  here = HERE,
  // ⛔ DEFAULT 0 = "nub CAN install this unjailed", which is what every pre-existing test in this
  // file assumes: their subject is the LADDER, and the jail-off control must not silently change
  // what they assert. Set 1 to drive the other branch.
  unjailedNubRc = 0,
} = {}) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'linux-ladder-'));
  const script = path.join(root, 'region.sh');
  fs.writeFileSync(script, [
    'set -uo pipefail',
    `ROOT=${JSON.stringify(root)}`,
    `HERE=${JSON.stringify(here)}`,
    // Single-quoted, not `JSON.stringify` — see the note on `LEDGER_RESPONSIVE`. No ledger contains
    // a single quote.
    `ARM_LEDGER='${ledger}'`,
    `GRANT='${grant}'`,
    // `verify "$GRANT" "synth"; SRC=$?` sits just above the extracted region, so its result is the
    // region's input: 0 means the synthesized grant verified and the ladder must never be reached.
    `SRC=${src}`,
    // The terminal jail-off control names the package it is asking about; `set -u` makes these
    // mandatory even though the stubbed control ignores them.
    "PKG=demo", "VER=1.0.0",
    // The real driver prints this during OBSERVE, well above the extracted region. `record.mjs` gates
    // the whole grant-source rule on seeing it — absence is read as "the check never ran" — so a
    // round trip that omitted it would test the wrong branch of `applyGrantSourceRule`.
    'echo \'  ARM-FALSIFIABILITY {"pkg":"demo","falsifiable":true}\'',
    // The jail-off control the terminal verdict now consults. Stubbed here for the same reason
    // `verify` is: the real one runs two `nub` installs, which no unit test can afford.
    `unjailed_nub_ok () { return ${unjailedNubRc}; }`,
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
    drop-no-network) return 0 ;;
    *) return 1 ;;
  esac
`;

test('⭑ the ladder FIRES when the synthesized grant fails, and says so in record.mjs\'s words', () => {
  const out = run(RUNG0_PASSES_NETWORK_DROPS);
  assert.match(out, /falling back to a bounded ladder/, 'the driver never entered the ladder');
  assert.ok(out.includes(`  => MINIMUM ${RUNG0}   (ladder fallback; synthesized grant was insufficient)`),
    `the ladder verdict line is not the wording record.mjs parses:\n${out}`);
});

test('⭑ THE ACCEPTANCE CRITERION: the winning rung DESCENDS, so a bundle is never published whole', () => {
  // ⛔ WHAT THIS PROTECTS. Rung 0 grants deps + project + userHome + network on the strength of ONE
  // arm, and `userHome` is write access to `~/.ssh` and every shell profile — the PERSISTENCE
  // capability. Before this, `measure.sh` printed the rung and exited, so the catalog got all four.
  // The descent can only narrow to a grant that still VERIFIES in the same real jail, so widening and
  // then narrowing cannot under-grant.
  const r = parseDriverLog(run(RUNG0_PASSES_NETWORK_DROPS));
  assert.equal(r.verdict, 'MINIMUM');
  assert.equal(r.verifiedBy, 'ladder');
  assert.deepEqual(r.overPredictedBy, ['no-network'], 'the descent did not run over the ladder rung');
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: { deps: true, project: true, userHome: true } },
    'the published grant still carries `network`, which an arm proved droppable off the RUNG');
  assert.ok(r.notes.includes('under-predicted'),
    'the record must still carry the finding that OBSERVE under-predicted');
});

test('the ladder climbs: rungs 0 and 1 fail, and the record reports the rung that passed', () => {
  const r = parseDriverLog(run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `));
  assert.equal(r.verdict, 'MINIMUM');
  assert.deepEqual(r.grant, { write: 'disk', network: true });
});

test('⭑ the write:"disk" rung is NOT descended — Object.keys on a string would fabricate arms', () => {
  // ⛔ `Object.keys("disk")` IS `["0","1","2","3"]`. Handing the top rung to the variant generator
  // would manufacture four `no-write-<digit>` arms, none of which `record.mjs` can parse — so the
  // record would carry `descent-name-unparsed` off a measurement of nothing, and that note forces the
  // WHOLE record back to the wide grant. It is also the absence of confinement rather than a grant
  // with droppable terms.
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

test('⭑ `read` DROPS on the one rung that carries it — the .env axis is questioned, not assumed', () => {
  // ⛔ WHAT THIS BUYS, AND WHY IT IS NOT HOUSEKEEPING. Rung 1 is the only grant in this driver that
  // carries a `read` key, and `read:"disk"` is the capability under which a project's `.env` files
  // become readable. Until the descent enumerated it, every rung-1 record published that grant
  // unquestioned. The arm below is what makes the drop a MEASUREMENT: `record.mjs` only ever keeps a
  // drop whose arm VERIFIED, so a `read` that disappears here is one the install provably did not need.
  //
  // ⛔ THIS TEST REPLACED ONE THAT PINNED THE OPPOSITE, and that is the intended lifecycle rather than
  // a regression. `read` was skipped for as long as `applyGrantSourceRule` had no `no-read` case —
  // a droppable `read` landed in `unparsedNames` and forced the WHOLE record back to the wide grant,
  // discarding the write/network narrowings that did parse. `366936ce3` added the case; the two POSIX
  // drivers were taught the name together, so no driver can be the odd one out.
  //
  // The oracle: only rung 1 passes (rung 0 has no `read`), and of its five terms only `read` drops.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"read":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      drop-no-read) return 0 ;;
      *) return 1 ;;
    esac
  `);
  assert.match(out, /drop-no-read|'no-read'/, 'no `read` variant was generated off the rung that carries one');
  const r = parseDriverLog(out);
  assert.deepEqual(r.overPredictedBy, ['no-read'], 'the descent did not put `read` to the question');
  assert.ok(!r.notes.includes('descent-name-unparsed'),
    'an unparseable variant name reached record.mjs, which discards every narrowing on the record');
  assert.equal(r.grantSource, 'descended');
  // ⛔ ASSERTED ON THE VALUE, NOT ON `overPredictedBy`. A driver that emits the name while the recorder
  // fails to recompute would satisfy every assertion above and still publish `read:"disk"` — which is
  // precisely the shape of the defect the unparsed-name guard exists for.
  assert.deepEqual(r.grant, { write: { deps: true, project: true, userHome: true }, network: true },
    'the published grant still carries `read`, which an arm proved droppable off the RUNG');
});

test('⭑ NEGATIVE CONTROL: a grant with no `read` key emits no `no-read` arm', () => {
  // ⛔ WITHOUT THIS, "the driver enumerates `read`" IS SATISFIED BY EMITTING THE VARIANT
  // UNCONDITIONALLY — which would spend a full jail run per package measuring the removal of a key
  // that was never there, and hand `record.mjs` a name for a capability the grant does not hold.
  // Synthesis never produces a `read` key at all, so this is the common case, not the corner.
  const out = run('  return 1', { src: 0, grant: '{"write":{"deps":true},"network":true}' });
  assert.doesNotMatch(out, /no-read/, 'a `read` arm was generated for a grant that has no `read` key');
  assert.match(out, /drop-no-network|'no-network'/, 'the descent did not run at all, so this control proves nothing');
});

test('⭑ N>=2 off a RUNG still keeps the wide grant until the joint arm verifies it', () => {
  // Leave-one-out proves each capability drops ON ITS OWN and nothing proves they drop TOGETHER. The
  // rung path must not become the one place that inference gets published as a measurement.
  const oracle = (joint) => `
    case "$label" in
      fb*) case "$grant" in *'"read":"disk"'*|*'"write":"disk"'*) return 1 ;; *) return 0 ;; esac ;;
      drop-no-network|drop-no-write-userHome) return 0 ;;
      joint-narrow) return ${joint} ;;
      *) return 1 ;;
    esac
  `;
  const failed = parseDriverLog(run(oracle(1)));
  assert.deepEqual(failed.overPredictedBy, ['no-network', 'no-write-userHome']);
  assert.equal(failed.grantSource, 'synthesized', 'N>=2 narrowed with no verified joint arm');
  assert.deepEqual(failed.grant, { write: { deps: true, project: true, userHome: true }, network: true },
    'the wide RUNG must be kept when the joint drop was never measured');

  const verified = parseDriverLog(run(oracle(0)));
  assert.equal(verified.grantSource, 'descended');
  assert.deepEqual(verified.grant, { write: { deps: true, project: true } },
    'a verified joint arm is a measurement and must be published');
});

test('⭑ the descent keeps THREE outcomes on the ladder path — a VOID arm is not necessity', () => {
  // ⛔ THE COLLAPSE THIS GUARDS. `verify` returns 2 when the override did not engage, so NOTHING was
  // measured. Reading that as "the capability is necessary" manufactures evidence in the direction
  // that HIDES over-prediction, and `=> MINIMAL` would then be printed having proven nothing.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"read":"disk"'*|*'"write":"disk"'*) return 1 ;; *) return 0 ;; esac ;;
      drop-no-network) return 2 ;;
      *) return 1 ;;
    esac
  `);
  assert.match(out, /INCONCLUSIVE for 'no-network'/);
  assert.doesNotMatch(out, /=> MINIMAL/, 'an unmeasured capability was reported as proving minimality');
  const r = parseDriverLog(out);
  assert.equal(r.minimality, 'UNPROVEN');
  assert.ok(r.notes.includes('descent-inconclusive'));
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

test('INSTRUMENT: the ledger reaches the predicate as FOUR arms, and refuses on the DIGEST clause', () => {
  // ⛔ THE CONTROL FOR THE TWO DEFECTS DESCRIBED ON `LEDGER_RESPONSIVE`. Without it this file's
  // negative control is satisfiable by a fixture the predicate never parses: it refuses, the terminal
  // verdict appears, and nothing distinguishes "the shortfall responded" from "the fixture was
  // mangled". Asserting the CLAUSE is what makes the refusal attributable.
  const out = run('  return 1');
  assert.doesNotMatch(out, /not fully walked/, 'the ledger arrived truncated to a single arm');
  assert.doesNotMatch(out, /an arm exited non-zero/,
    'the exit-code clause refused first, so the varying shortfall was never examined');
  assert.match(out, /NOT-GRANT-INDEPENDENT the shortfall CHANGED across arms/);
});

test('every rung failing is NO-STATE-PASSED **when nub can install the package unjailed**', () => {
  // The honest end of the Linux ladder: nothing this harness can express installs the package, and
  // the shortfall responded to the grant, so the grant-independence escape does not apply either.
  // ⛔ THE UNJAILED CLAUSE IS LOAD-BEARING, NOT DECORATION — see the sibling test below.
  const out = run('  return 1', { unjailedNubRc: 0 });
  assert.match(out, /=> NO-STATE-PASSED even at write:disk/);
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'a shortfall that responded to the grant was classified as grant-independent');
  assert.doesNotMatch(out, /OVER-PREDICTED|=> MINIMAL/, 'a descent ran with no rung to descend from');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'NO-STATE-PASSED');
  assert.equal(r.grant, null, 'a verdict with no state that passed must not publish a grant');
});

test('⭑ every rung failing is BROKEN-UNJAILED-NUB when nub cannot install it unjailed either', () => {
  // ⛔ THE DISTINCTION THE OLD CONTROL COULD NOT MAKE. The jail-off control at the top of the driver
  // keys on OBSERVE's rc, and OBSERVE runs `npm rebuild` — a DIFFERENT PROGRAM from the `nub install`
  // every verify arm runs. So a package npm installs fine but nub cannot install even unjailed used
  // to climb the whole ladder and be filed NO-STATE-PASSED, reading as "the jail blocks this" about
  // a defect the jail had no part in. Measured on `@progress/kendo-licensing@0.1.2`.
  const out = run('  return 1', { unjailedNubRc: 1 });
  assert.match(out, /=> BROKEN-UNJAILED-NUB/);
  assert.doesNotMatch(out, /=> NO-STATE-PASSED/,
    'a nub install defect must not also claim the jail-capability verdict');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'BROKEN-UNJAILED-NUB');
  assert.equal(r.grant, null, 'a verdict with no state that passed must not publish a grant');
});

test('the synth-verified path is untouched: it descends from GRANT and still says "synthesized"', () => {
  // The regression guard for turning the descent into a function. `$GRANT` at the call site, `$g0`
  // inside — and the provenance word is what a human auditing a `write.userHome` entry reads.
  const out = run(`
    case "$label" in
      drop-no-write-deps) return 0 ;;
      *) return 1 ;;
    esac
  `, { src: 0, grant: '{"write":{"deps":true},"network":true}' });
  assert.doesNotMatch(out, /bounded ladder/, 'a verified grant must not reach the ladder');
  assert.match(out, /\(synthesized \{"write":\{"deps":true\},"network":true\};/,
    'the summary line no longer names the grant it descended from as synthesized');
  const r = parseDriverLog(out);
  assert.equal(r.verifiedBy, 'synth');
  assert.deepEqual(r.overPredictedBy, ['no-write-deps']);
  assert.deepEqual(r.grant, { network: true });
});

// ── THE GRANT-INDEPENDENCE STAGE REFUSES A PREDICATE THAT NEVER RAN ───────────────────────────────
//
// ⛔ THE SHAPE OF THE DEFECT. `ARTIFACT-GATE-SUSPECT` is the one verdict that publishes a grant with no
// leave-one-out descent behind it, and the branch that emits it tested `$IRC` alone. An exit code of 0
// is not evidence the predicate ran: `shortfall-invariance.mjs`'s main-module guard compares
// `import.meta.url` (physical) against `pathToFileURL(process.argv[1])` (as given), and `HERE` in the
// driver is the LOGICAL path — so on any checkout reached through a symlink the CLI block never
// executes and the script exits 0 having printed nothing. MEASURED by invoking it both ways: through
// the real path a `1:aa:ok:9` ledger prints `NOT-ESTABLISHED an arm exited non-zero` and exits 1;
// through a symlinked directory the identical invocation prints nothing and exits 0.
//
// ⛔ THE STUB IS THE PREDICATE, NOT THE ORACLE, WHICH IS WHY BOTH CASES BELOW EXIST. Only the silent
// one can distinguish the guard from no guard; the printing one proves the refusal is caused by the
// EMPTY output rather than by the stubbing itself. `$HERE` is used exactly once in the extracted
// region — this call — so overriding it swaps the predicate and nothing else.
const withPredicate = (body, fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'linux-inv-'));
  fs.writeFileSync(path.join(dir, 'shortfall-invariance.mjs'), body);
  try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};

test('⭑ a predicate that exits 0 printing NOTHING is refused, not read as grant-independence', () => {
  const out = withPredicate('process.exit(0);\n', (dir) => run('  return 1', { here: dir }));
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'the driver published its only un-descended grant off a predicate that never ran');
  assert.doesNotMatch(out, /the SAME -artifact/, 'the verdict rendered an empty artifact count');
  const r = parseDriverLog(out);
  // ⛔ `HARNESS-ERROR` SPECIFICALLY, BECAUSE `claim-slice.mjs` RETURNS THAT ROW TO `pending`. Any other
  // verdict closes the queue row, which would bake an instrument failure into the corpus as a result —
  // and a re-run off a checkout with no symlink in its path would have answered the question.
  assert.equal(r.verdict, 'HARNESS-ERROR',
    'an instrument failure must reopen the queue row, not close it with a measurement it never made');
});

test('⭑ CONTROL: a predicate that PRINTS still yields ARTIFACT-GATE-SUSPECT, with its real count', () => {
  // Without this, a guard that refused unconditionally would satisfy the case above while destroying
  // the verdict the stage exists to produce — the shape of a harness that refuses everything.
  const out = withPredicate('console.log("GRANT-INDEPENDENT 7 aa");\nprocess.exit(0);\n',
    (dir) => run('  return 1', { here: dir }));
  assert.doesNotMatch(out, /HARNESS-ERROR/, 'a predicate that printed was refused as if it had not run');
  assert.match(out, /the SAME 7-artifact shortfall/, 'the count is not read out of the predicate\'s stdout');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'ARTIFACT-GATE-SUSPECT');
});

// ── THE FALSIFICATION CONTROL ─────────────────────────────────────────────────────────────────────

// The driver with the ladder's `for` loop excised, everything else identical. This is what the file
// looked like before the descent was wired in — reconstructed mechanically rather than pasted, so it
// cannot go stale.
const LADDERLESS = REGION.replace(/\nfor g in \\\n[\s\S]*?\ndone\n/, '\n');

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
  assert.notEqual(r.verifiedBy, 'ladder');
  assert.equal(r.grant, null);
});
