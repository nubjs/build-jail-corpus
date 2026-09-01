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
// The verdict vocabulary comes from the module that owns it, so a rename cannot leave this suite
// asserting a spelling no driver produces.
import { VERDICT, classify } from './unjailed-nub.mjs';

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
  // ⛔ WHOSE FAULT the failure is. `unjailedNubRc: 1` alone says only "nub cannot install it";
  // whether that is a NUB defect or a broken package turns on npm, so both branches need driving.
  npmRc = 0,
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
    //
    // ⛔ THE STUB EMULATES THE MODULE'S CONTRACT, WHICH IS NOT ITS OLD rc. The control moved into
    // `unjailed-nub.mjs`, which PRINTS its own verdict for every case it can settle alone and exits 3
    // for the single case needing npm. So `unjailedNubRc: 0` means "the module already printed
    // NO-STATE-PASSED", not "the driver will print it" — and getting that backwards is a silently
    // green test, because the driver would print nothing and the log would carry no verdict at all.
    //
    // The token is taken from the module rather than written as a literal, so renaming a verdict
    // cannot leave this stub asserting a spelling nothing produces.
    // The stub's output is built from the module's own `classify`, so it reproduces the real
    // wording by construction rather than by hand. The `jail-off control:` line is the evidence the
    // control actually RAN, which is asserted separately from the verdict it produced.
    `unjailed_nub_ok () { ${unjailedNubRc === 0
      ? `echo '  jail-off control: ${classify({ nub: { rc: 0, engaged: true } }).why}'; `
        + `echo '  => ${VERDICT.noStatePassed} even at write:disk — investigate; do not widen the catalog blindly'; `
      : ''}return ${unjailedNubRc === 0 ? 0 : 3}; }`,
    // Shadows the real `npm_ok` defined inside the branch; a function defined later wins in bash,
    // so this is set via an env the branch's definition cannot see. Stub `npm` itself instead.
    `npm () { return ${npmRc}; }`,
    // The extracted terminal control now screens the safely-resolved npm tree. This suite's subject
    // is the ladder, so the screen is stubbed clean just as both installers are.
    'security_screen_tree () { :; }',
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

// ── THE TERMINAL RUNG'S DESCENT ───────────────────────────────────────────────────────────────────
//
// ⛔⛔ THESE REPLACED A CASE THAT PINNED THE OPPOSITE, and that is the intended lifecycle rather than a
// regression — the same shape as the `read` rung below, which was also once pinned as deliberately
// skipped. The old case asserted `no droppable terms, so no descent` on `{"write":"disk","network":
// true}`. Its reason was sound and its scope was not: `Object.keys("disk")` really is
// `["0","1","2","3"]`, so the old inline generator really would have fabricated four unparseable
// arms — but the rung is a BUNDLE like every other, and refusing the whole descent threw away its
// SECOND term along with the first.
//
// MEASURED on the committed corpus 2026-09-01: all 75 `write:"disk"` records carry
// `overPredictedBy: []` and `minimality: null`, and all 75 carry `network: true`. The widest grants
// in the corpus were the only ones no arm had ever questioned.
//
// `descent-terms.mjs` now decides what the rung can be asked: no write term (every narrower reach the
// catalog can spell is a `Scopes` value — i.e. rungs 0 and 1, which this ladder already ran and which
// already failed), and `no-network` on the platforms whose backend still enforces that axis once the
// fs axis is relaxed. Linux is one: `linux.rs`'s `sandboxing = confine_fs || policy.net.enforce || …`,
// and the seccomp net filter is independent of the Landlock ruleset `write:"disk"` relaxes.

test('⭑ RED-GREEN: the write:"disk" rung IS descended, and narrows to {"write":"disk"}', () => {
  // The oracle: only the terminal rung passes, and its one descent arm passes too.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      drop-no-network) return 0 ;;
      *) return 1 ;;
    esac
  `);
  assert.match(out, /OVER-PREDICTED/, 'no descent arm ran on the terminal rung');
  const r = parseDriverLog(out);
  assert.deepEqual(r.overPredictedBy, ['no-network'],
    'the terminal rung published without any arm trying to drop its network capability');
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: 'disk' },
    'the published grant still carries `network` — the whole-filesystem record did not narrow');
});

test('⭑ the fabrication the old guard existed to prevent still does not happen', () => {
  // The old exemption's reason, kept as a live assertion rather than as a comment. A regenerated
  // `Object.keys(g.write)` over the string would put `no-write-0` here, and `record.mjs` would file
  // `descent-name-unparsed` off a measurement of four states that mean nothing — forcing the WHOLE
  // record back to the wide grant, network narrowing included.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 0 ;;
    esac
  `);
  for (const n of [0, 1, 2, 3]) {
    assert.doesNotMatch(out, new RegExp(`no-write-${n}`), 'the string rung was fed to Object.keys');
  }
  assert.doesNotMatch(out, /no-write-disk/, 'a name that parses and recomputes nothing was emitted');
  const r = parseDriverLog(out);
  assert.ok(!r.notes.includes('descent-name-unparsed'));
});

test('⭑ CONTROL: a NECESSARY network capability keeps the wide grant and reports MINIMAL', () => {
  // Without this, a descent that narrowed unconditionally would satisfy the acceptance case above
  // while under-granting every record it touched. Same rung, failing arm.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `);
  const r = parseDriverLog(out);
  assert.equal(r.minimality, 'MINIMAL');
  assert.deepEqual(r.overPredictedBy, []);
  assert.deepEqual(r.grant, { write: 'disk', network: true }, 'a failing arm must not narrow anything');
});

test('⭑ FALSIFICATION: restore the old guard and the terminal-rung finding disappears', () => {
  // ⛔ THE EXCISION CONTROL FOR THIS CHANGE SPECIFICALLY. `LADDERLESS` below proves the ladder is
  // load-bearing; it says nothing about whether the TOP rung descends, because the old driver walked
  // the same ladder and simply skipped the descent there. This restores that skip and re-runs the
  // identical oracle, so the only variable is the guard.
  const guarded = REGION.replace(/^(\s*)descend "\$g" ladder$/m,
    '$1case "$g" in *\'"write":"disk"\'*) : ;; *) descend "$g" ladder ;; esac');
  assert.notEqual(guarded, REGION, 'the excision matched nothing, so this control is vacuous');

  const oracle = `
    case "$label" in
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      drop-no-network) return 0 ;;
      *) return 1 ;;
    esac
  `;
  const withGuard = parseDriverLog(run(oracle, { source: guarded }));
  assert.deepEqual(withGuard.overPredictedBy, [],
    'the restored guard still descended — this control is not measuring the guard');
  assert.deepEqual(withGuard.grant, { write: 'disk', network: true });
  // And the live driver, same oracle, narrows. Both halves in one case so neither can rot alone.
  assert.deepEqual(parseDriverLog(run(oracle)).grant, { write: 'disk' });
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
  const out = run('  return 1', { unjailedNubRc: 1, npmRc: 0 });
  assert.match(out, /=> BROKEN-UNJAILED-NUB/);
  assert.doesNotMatch(out, /=> NO-STATE-PASSED/,
    'a nub install defect must not also claim the jail-capability verdict');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'BROKEN-UNJAILED-NUB');
  assert.equal(r.grant, null, 'a verdict with no state that passed must not publish a grant');
});

test('⭑ nub failing unjailed is BROKEN-WITHOUT-JAIL-TOO when npm cannot install it either', () => {
  // ⛔ THE OVER-CLAIM THIS PREVENTS, caught on the stage's FIRST live record.
  // `@aws-amplify/cli@2.0.0` came back BROKEN-UNJAILED-NUB — true about nub, and misleading,
  // because plain `npm install` fails too (gyp rejects Python 3.12). Naming nub as the culprit for
  // a package NOTHING installs sends the next reader chasing a bug that is not there.
  const out = run('  return 1', { unjailedNubRc: 1, npmRc: 1 });
  // The `=>` line now carries the shared verdict TOKEN and the reason sits on the line above it, so
  // three drivers cannot drift on the spelling `record.mjs` matches while each keeps its own context.
  // Both halves are asserted: the token because the parser needs it, the reason because a verdict
  // naming no culprit is what sent readers chasing a nub bug that was not there.
  assert.match(out, new RegExp(`=> ${VERDICT.brokenWithoutJailToo}`));
  assert.match(out, /jail-off control: neither nub nor npm installs this unjailed/);
  assert.doesNotMatch(out, /=> BROKEN-UNJAILED-NUB/,
    'a package npm cannot install either must not be filed as a nub defect');
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
// EMPTY output rather than by the stubbing itself.
//
// ⛔ `$HERE` IS NO LONGER USED ONLY ONCE IN THE REGION, AND THIS COMMENT USED TO SAY IT WAS. The
// wide-but-confined probe resolves `confined-wide.mjs` through it too, so a bare override would swap
// the predicate AND break the probe's marker — which `record.mjs` reads as "not established", i.e. it
// would quietly change what these two cases exercise while they stayed green. The real module is
// linked in beside the stub so the override still swaps THE PREDICATE AND NOTHING ELSE, which is the
// property both cases rest on.
const withPredicate = (body, fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'linux-inv-'));
  fs.writeFileSync(path.join(dir, 'shortfall-invariance.mjs'), body);
  fs.symlinkSync(path.join(HERE, 'confined-wide.mjs'), path.join(dir, 'confined-wide.mjs'));
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

// ── THE WIDE-BUT-CONFINED PROBE ───────────────────────────────────────────────────────────────────
//
// ⛔ WHAT THESE CASES PROTECT. The ladder's terminal rung is not a wider sandbox — it is NO sandbox
// (`relax_fs_to_full_disk` clears `entries`, sets `default_effect = Allow` and puts tmp back to
// Shared; `linux_landlock.rs` then emits one `/` `FullDisk` rule). So a package that passes only there
// may need a wide write scope or may be failing for a confinement-compatibility reason no path grant
// can fix, and every `write:"disk"` record in this corpus came from that rung. The probe is the state
// BETWEEN the two: the last confined rung's grant, widened by a catalog `baseline` that leaves
// `default_effect` at `Deny`.
//
// ⛔ THE PROBE MUST NEVER CHANGE WHAT IS PUBLISHED, and that is the load-bearing assertion here rather
// than the marker. Its widening rides a GLOBAL baseline, which the shipped per-package vocabulary
// cannot express, so publishing a grant it passed at would ship an entry narrower than the package was
// measured to need — the under-granting direction. `the probe adds a measurement and changes no
// verdict` is what pins that.

const CW_MARKER = /CONFINED-WIDE \{/;

test('⭑ the probe runs BETWEEN the last confined rung and the unconfined one', () => {
  // Every confined rung fails; only `write:"disk"` passes. That is the exact population — 75 records
  // today — whose grant this probe exists to explain.
  const out = run(`
    case "$label" in
      cw) return 1 ;;
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `);
  const cwAt = out.search(CW_MARKER);
  assert.ok(cwAt > -1, `the probe never ran:\n${out}`);
  // ORDER, not merely presence: a probe that ran AFTER the terminal rung would be reporting on a
  // question the ladder had already answered, and would cost an install on every package instead of
  // only the ones in doubt.
  const diskRung = out.indexOf('=> MINIMUM {"write":"disk"');
  assert.ok(diskRung > -1, 'the terminal rung did not publish, so the ordering claim is vacuous');
  assert.ok(cwAt < diskRung, 'the probe ran after the terminal rung rather than before it');
});

test('⭑ the probe does NOT run when a confined rung already passed', () => {
  // ⛔ THE COST CONTROL. The probe is a full install. Running it when rung 0 already answered the
  // question would add one to every laddered package for no measurement at all — and would also
  // record a `confinedWide` on packages whose grant was never in question.
  //
  // ⛔⛔ THE POSITIVE CONTROL IS IN THIS TEST, NOT IN A SIBLING, AND THAT IS WHY IT IS HERE. An
  // ABSENCE assertion passes when the feature is deleted — measured: with the probe call excised from
  // the driver, the four other cases below go red and this one stayed GREEN, which is exactly the
  // shape of a test that reads as coverage and is not. Asserting that the marker DOES appear on the
  // laddering oracle, in the same case, is what makes the absence half mean something.
  const laddered = run(`
    case "$label" in
      cw) return 1 ;;
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `);
  assert.match(laddered, CW_MARKER, 'the probe never fires at all, so the absence below proves nothing');

  const out = run(RUNG0_PASSES_NETWORK_DROPS);
  assert.doesNotMatch(out, CW_MARKER, 'the probe ran even though a confined rung had already passed');
  assert.equal(parseDriverLog(out).confinedWide, null,
    'a record whose confined rung passed must carry no probe result at all');
});

test('⭑ THE ACCEPTANCE CRITERION: the probe adds a measurement and changes NO verdict', () => {
  // ⛔ THIS IS THE FAIL-CLOSED ASSERTION. Whatever the probe answers, the published grant is still
  // whatever the ladder concluded — here the terminal rung. A future edit that let a passing probe
  // publish its own grant would ship an entry NARROWER than the package was measured to need, because
  // the catalog cannot carry the baseline the probe passed under. Both polarities are driven, since a
  // rule that fired on only one of them would look correct from the other.
  const oracle = (cw) => `
    case "$label" in
      cw) return ${cw} ;;
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `;
  const passed = parseDriverLog(run(oracle(0)));
  const failed = parseDriverLog(run(oracle(1)));
  assert.equal(passed.confinedWide.result, 'pass');
  assert.equal(failed.confinedWide.result, 'fail');
  for (const r of [passed, failed]) {
    assert.equal(r.verdict, 'MINIMUM');
    assert.deepEqual(r.grant, { write: 'disk', network: true },
      'the probe moved the published grant — it is a diagnosis, never a licence to narrow');
    assert.equal(r.verifiedBy, 'ladder');
  }
});

test('⭑ a VOID probe arm is recorded as VOID, never as a failure', () => {
  // ⛔ COLLAPSING VOID INTO `fail` WOULD PUBLISH "THIS PACKAGE CANNOT RUN CONFINED" OFF AN ARM THAT
  // NEVER RAN THE EXPERIMENT. A VOID arm measured the COMPILED-IN catalog, so it says nothing about a
  // wide confined grant. Same three-outcome contract the rungs themselves keep.
  const r = parseDriverLog(run(`
    case "$label" in
      cw) return 2 ;;
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `));
  assert.equal(r.confinedWide.result, 'void');
  assert.notEqual(r.confinedWide.result, 'fail');
  // A VOID PROBE MUST NOT STOP THE LADDER. A void RUNG does (the ladder cannot climb past a grant it
  // never tested), but the probe publishes nothing, so abandoning the run over it would discard a
  // record the ladder was still able to produce.
  assert.equal(r.verdict, 'MINIMUM', 'a void probe aborted a run the ladder could still complete');
});

test('⭑ FALSIFICATION: with the probe excised, the confined-wide finding disappears', () => {
  // ⛔ WITHOUT THIS EVERY CASE ABOVE IS UNFALSIFIABLE. Excised mechanically from the same region the
  // other cases run, so it cannot go stale — and asserted to have actually matched, because a
  // no-op replacement would make this control pass while proving nothing.
  const PROBELESS = REGION.replace(/\n *case "\$g" in \*'"write":"disk"'\*\) confined_wide_probe ;; esac\n/, '\n');
  assert.notEqual(PROBELESS, REGION, 'the excision matched nothing, so this control is vacuous');
  assert.ok(PROBELESS.includes('confined_wide_probe () {'), 'the excision removed more than the call');
  assert.ok(PROBELESS.includes(RUNG2), 'the excision took the terminal rung with it');

  const out = run(`
    case "$label" in
      cw) return 0 ;;
      fb*) case "$grant" in *'"write":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      *) return 1 ;;
    esac
  `, { source: PROBELESS });
  assert.doesNotMatch(out, CW_MARKER, 'the probeless driver still emitted a confined-wide marker');
  assert.equal(parseDriverLog(out).confinedWide, null);
  // The ladder itself is untouched by the excision, which is what makes the control specific to the
  // probe rather than to a mangled region.
  assert.deepEqual(parseDriverLog(out).grant, { write: 'disk', network: true });
});
