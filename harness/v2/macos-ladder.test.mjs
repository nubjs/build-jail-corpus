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
//
// ⛔ `ARM_LEDGER` IS A SEPARATE INPUT FROM THE ORACLE, AND CONFLATING THEM WOULD BE WRONG. The real
// `verify` records the INSTALL's exit code in the ledger while RETURNING on `rc == 0 && gate == 0`,
// so an arm that installed cleanly and then failed the artifact gate is `rc=0` in the ledger and
// "insufficient" to the caller. That gap is the whole subject of `ARTIFACT-GATE-SUSPECT`. A stub that
// derived one from the other could not express it, so each case states the ledger it wants.
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

// A four-arm ledger whose shortfall digest CHANGES across arms, so `shortfall-invariance.mjs` refuses
// and the all-rungs-fail path lands on its real terminal verdict rather than on the SUSPECT escape.
// Format is `verify`'s own: `<install rc>:<shortfall digest>:<ok|abs>:<missing count>`.
//
// ⛔ EVERY ARM IS rc=0 DELIBERATELY, SO THE DIGEST CLAUSE IS WHAT REFUSES. The predicate checks exit
// codes BEFORE digests, so an rc=1 ledger is turned away by `an arm exited non-zero` and the varying
// shortfall is never examined — a negative control that never reaches the clause it is controlling
// for. This is the `mozjpeg@6.0.1` shape the predicate's own comment names: rc=0 on every arm, held
// out only because the shortfall MOVED. rc=0 with a shortfall is also the realistic shape here — an
// install that exits clean and then fails the artifact gate is the whole reason this stage exists.
const LEDGER_RESPONSIVE = ['0:aa11:ok:9', '0:bb22:ok:7', '0:cc33:ok:4', '0:dd44:ok:2'].join('\n') + '\n';

/**
 * Run the extracted region with a stubbed `verify`, and return its stdout.
 *
 * `oracle` is bash injected into the stub: it sees `$1` (grant JSON) and `$2` (arm label) and must
 * `return` 0 SUFFICIENT / 1 INSUFFICIENT / 2 VOID, which is `verify`'s real three-outcome contract.
 * Arm labels are the driver's own: `fb<cksum>` per rung, `nar-no-<capability>` per descent arm,
 * `joint-narrow`, `diag`.
 *
 * ⛔ `HERE` IS `import.meta.dirname`, WHICH IS THE RESOLVED PATH. The driver's own `HERE` is
 * `cd "$(dirname "$0")" && pwd`, i.e. the LOGICAL path — and `shortfall-invariance.mjs`'s
 * main-module guard compares its own URL against the resolved URL of the invoked script. Handing it a
 * path through a symlink makes it exit 0 printing nothing, which an unguarded driver would read as
 * GRANT-INDEPENDENT. macOS is where that bites, `/tmp` being a symlink to `/private/tmp`.
 */
const run = (oracle, {
  verified = 0, grant = '{"write":{"deps":true}}', source = REGION, ledger = LEDGER_RESPONSIVE,
  here = HERE,
} = {}) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-ladder-'));
  const script = path.join(root, 'region.sh');
  fs.writeFileSync(script, [
    'set -uo pipefail',
    `ROOT=${JSON.stringify(root)}`,
    `HERE=${JSON.stringify(here)}`,
    // ⛔ SINGLE QUOTES, NOT `JSON.stringify`, AND THE DIFFERENCE IS THE WHOLE LEDGER. `JSON.stringify`
    // renders the separators as the two characters `\` `n`, which bash inside double quotes does not
    // interpret — so the predicate receives ONE arm and refuses on `ladder was not fully walked`
    // rather than on the clause the case is about. Every assertion that only checked the terminal
    // verdict still passed, which is exactly how it went unnoticed. Bash single quotes carry a real
    // newline verbatim; no ledger contains a single quote.
    `ARM_LEDGER='${ledger}'`,
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

test('⭑ `read` DROPS on the one rung that carries it — the .env axis is questioned, not assumed', () => {
  // ⛔ WHAT THIS BUYS, AND WHY IT IS NOT HOUSEKEEPING. Rung 1 is the only grant in this driver that
  // carries a `read` key, and `read:"disk"` is the capability under which a project's `.env` files
  // become readable. Until the descent enumerated it, every rung-1 record published that grant
  // unquestioned. The arm below is what makes the drop a MEASUREMENT: `record.mjs` only ever keeps a
  // drop whose arm VERIFIED, so a `read` that disappears here is one the install provably did not need.
  //
  // ⛔ THE POINT OF HAVING IT ON BOTH POSIX DRIVERS. `measure.sh` and this file were taught `no-read`
  // in one change, because a Linux-only edit is exactly the cross-driver asymmetry that let macOS
  // ship without a ladder at all. Its Linux twin is `linux-ladder.test.mjs`, same oracle shape.
  //
  // The oracle: only rung 1 passes (rung 0 has no `read`), and of its five terms only `read` drops.
  const out = run(`
    case "$label" in
      fb*) case "$grant" in *'"read":"disk"'*) return 0 ;; *) return 1 ;; esac ;;
      nar-no-read) return 0 ;;
      *) return 1 ;;
    esac
  `);
  assert.match(out, /'no-read'/, 'no `read` variant was generated off the rung that carries one');
  const r = parseDriverLog(out);
  assert.deepEqual(r.overPredictedBy, ['no-read'], 'the descent did not put `read` to the question');
  assert.ok(!r.notes.includes('descent-name-unparsed'),
    'an unparseable variant name reached record.mjs, which discards every narrowing on the record');
  assert.equal(r.grantSource, 'descended');
  // ⛔ ASSERTED ON THE VALUE, NOT ON `overPredictedBy`. A driver that emits the name while the recorder
  // fails to recompute would satisfy every assertion above and still publish `read:"disk"`.
  assert.deepEqual(r.grant, { write: { deps: true, project: true, userHome: true }, network: true },
    'the published grant still carries `read`, which an arm proved droppable off the RUNG');
});

test('⭑ NEGATIVE CONTROL: a grant with no `read` key emits no `no-read` arm', () => {
  // ⛔ WITHOUT THIS, "the driver enumerates `read`" IS SATISFIED BY EMITTING THE VARIANT
  // UNCONDITIONALLY — which would spend a full jail run per package measuring the removal of a key
  // that was never there. Synthesis never produces a `read` key, so this is the common case.
  const out = run('  return 1', { verified: 1, grant: '{"write":{"deps":true},"network":true}' });
  assert.doesNotMatch(out, /no-read/, 'a `read` arm was generated for a grant that has no `read` key');
  assert.match(out, /'no-network'/, 'the descent did not run at all, so this control proves nothing');
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
  // genuinely no measured minimum and `collate.mjs` is right to exclude it. The default ledger is the
  // RESPONSIVE one — the shortfall moved as the grant widened — so this is also the negative control
  // for the grant-independence stage below: the escape must not fire on a shortfall that responded.
  const out = run('  return 1');
  assert.match(out, /NOT-GRANT-INDEPENDENT the shortfall CHANGED across arms/,
    'the stage did not run, or did not say why it refused');
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'a shortfall that responded to the grant was classified as grant-independent');
  const r = parseDriverLog(out);
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

// ── THE GRANT-INDEPENDENCE STAGE ──────────────────────────────────────────────────────────────────
//
// ⛔ WHAT THE PORT BUYS, MEASURED. `@arbitrum/sdk@3.0.0-beta.0` re-measured on darwin ran all three
// rungs and returned `rc=0 artifacts=816/1117 missing=301 shortfall=0d0532fa4785` at rung 0, at rung 1
// and at `write:"disk"` — the same digest at the widest grant that exists — and this driver recorded
// `UNDER-PREDICTED`, while Linux had already recorded the same package `ARTIFACT-GATE-SUSPECT` from a
// different tracer. Not a broken-install risk (`collate.mjs:187` excludes both verdicts) but a TRIAGE
// gap: without the stage darwin cannot tell "needs a wider grant" from "no grant will ever help",
// which is the distinction that sends someone to widen a catalog entry no widening can fix.

// A four-arm ledger whose digest is INVARIANT across every rung — the shape that earns the verdict.
const LEDGER_INVARIANT = ['0:ab12cd:ok:301', '0:ab12cd:ok:301', '0:ab12cd:ok:301', '0:ab12cd:ok:301']
  .join('\n') + '\n';

test('INSTRUMENT: the ledger reaches the predicate as FOUR arms, not as one escaped line', () => {
  // ⛔ THE FAILURE THIS PINS ALREADY HAPPENED. Passing the ledger through `JSON.stringify` into a
  // double-quoted bash assignment delivers the separators as literal backslash-n, so the predicate
  // sees ONE arm and refuses with `ladder was not fully walked` — a refusal, so every case that only
  // checked the terminal verdict stayed green while testing a clause it did not mean to test. Both
  // ledgers are asserted, because a fixture is only a control if it reaches the instrument intact.
  for (const [name, ledger] of [['responsive', LEDGER_RESPONSIVE], ['invariant', LEDGER_INVARIANT]]) {
    const out = run('  return 1', { ledger });
    // ⛔ THE POSITIVE HALF FIRST. Both assertions below are `doesNotMatch`, which a driver with NO
    // stage at all satisfies vacuously — so the stage has to be shown to have RUN before its absence
    // of complaints means anything.
    assert.match(out, /ARTIFACT-GATE-SUSPECT|NOT-GRANT-INDEPENDENT/,
      `the stage never ran on the ${name} ledger, so this control proves nothing`);
    assert.doesNotMatch(out, /not fully walked/,
      `the ${name} ledger arrived truncated, so its case tests the arm-count clause and nothing else`);
  }
});

test('⭑ a shortfall invariant to the top rung is ARTIFACT-GATE-SUSPECT, not a capability finding', () => {
  const out = run('  return 1', { ledger: LEDGER_INVARIANT });
  assert.match(out, /=> ARTIFACT-GATE-SUSPECT \{"write":\{"deps":true\}\}/,
    'the stage did not fire, or did not publish the SYNTHESIZED grant');
  assert.match(out, /the SAME 301-artifact shortfall/,
    'the count is not read out of the predicate\'s stdout');
  // ⛔ ASSERTED ON THE RECORD, NOT ONLY ON THE TEXT. `record.mjs` walks the log line by line and the
  // LAST matching `=>` wins, so a driver that printed BOTH verdicts would satisfy the match above
  // while filing every one of these packages as `UNDER-PREDICTED` exactly as before the port.
  assert.doesNotMatch(out, /=> UNDER-PREDICTED/,
    'the terminal verdict was printed alongside the SUSPECT one, which overwrites it in the record');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'ARTIFACT-GATE-SUSPECT');
  assert.deepEqual(r.grant, { write: { deps: true } });
  assert.ok(r.notes.includes('artifact-shortfall-grant-independent'));
  // ⛔ THE GRANT IS A CANDIDATE, NOT A MEASUREMENT, AND THE RECORD HAS TO SAY SO. This is the only
  // path in the driver that publishes a grant with no leave-one-out descent behind it.
  assert.equal(r.verifiedBy, null, 'a grant no arm verified was recorded as verified');
  assert.equal(r.minimality, null, 'minimality was claimed for a grant that was never descended');
});

test('⭑ an ABSENT package is refused even though its shortfall never moves', () => {
  // ⛔ THE SAFETY CLAUSE, EXERCISED THROUGH THE DRIVER RATHER THAN ONLY THE PREDICATE'S UNIT TEST.
  // `<package absent>` on every arm is "invariant" only in the sense that nothing happened four
  // times; blessing it would publish a narrow grant off a run in which the package never installed —
  // an under-grant of unknown size, the one direction that breaks a real install.
  const absent = ['0:ff99:abs:1', '0:ff99:abs:1', '0:ff99:abs:1', '0:ff99:abs:1'].join('\n') + '\n';
  const out = run('  return 1', { ledger: absent });
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/, 'a package that never installed was blessed');
  assert.match(out, /NOT-GRANT-INDEPENDENT the package was ABSENT/);
  assert.equal(parseDriverLog(out).verdict, 'UNDER-PREDICTED');
});

// ⛔ THE STUB IS THE PREDICATE, NOT THE ORACLE, WHICH IS WHY BOTH CASES BELOW EXIST. Only the silent
// one can distinguish the guard from no guard; the printing one proves the refusal is caused by the
// EMPTY output rather than by the stubbing itself. `$HERE` is used exactly once in the extracted
// region — this call — so overriding it swaps the predicate and nothing else.
const withPredicate = (body, fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-inv-'));
  fs.writeFileSync(path.join(dir, 'shortfall-invariance.mjs'), body);
  try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};

test('⭑ a predicate that exits 0 printing NOTHING is refused, not read as grant-independence', () => {
  // ⛔ THE GUARD `measure.sh` GAINED IN `14d77b078`, CARRIED ACROSS RATHER THAN LEFT AS A LINUX-ONLY
  // REPAIR. An exit code of 0 is not evidence the predicate ran: the main-module guard compares the
  // module's own URL against the resolved URL of the invoked script, while the driver's `HERE` is the
  // LOGICAL path — so a checkout reached through a symlink makes the CLI block never execute and the
  // script exit 0 having printed nothing. macOS is where that bites first: `/tmp` is a symlink to
  // `/private/tmp`. Unguarded, the driver renders `the SAME -artifact shortfall` and exits 0.
  const out = withPredicate('process.exit(0);\n',
    (dir) => run('  return 1', { here: dir, ledger: LEDGER_INVARIANT }));
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'the driver published its only un-descended grant off a predicate that never ran');
  assert.doesNotMatch(out, /the SAME -artifact/, 'the verdict rendered an empty artifact count');
  const r = parseDriverLog(out);
  // ⛔ `HARNESS-ERROR` SPECIFICALLY, BECAUSE `claim-slice.mjs` RETURNS THAT ROW TO `pending`. Any
  // other verdict closes the queue row, which would bake an instrument failure into the corpus as a
  // result — and a re-run off a checkout with no symlink in its path would have answered the question.
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
  assert.equal(parseDriverLog(out).verdict, 'ARTIFACT-GATE-SUSPECT');
});

test('⭑ the SUSPECT path still reaches `### DONE`, which is where `synthesized` survives', () => {
  // ⛔ macOS DIFFERS FROM LINUX HERE ON PURPOSE. `measure.sh` `exit 0`s on this verdict and has no
  // trailing line; this driver restates the synthesized grant on `### DONE`, and `record.mjs:191`
  // reads it — the only place it survives a run whose earlier `SYNTHESIZED GRANT` line was not
  // captured. An `exit 0` copied over from Linux would drop that field silently.
  const out = run('  return 1', { ledger: LEDGER_INVARIANT });
  assert.match(out, /### DONE demo@1\.0\.0\s+synthesized=\{"write":\{"deps":true\}\}/,
    'the SUSPECT path exits before the DONE line');
});

// ── THE LEDGER APPEND, DRIVEN WITH ARM STATES AND FED TO THE REAL PREDICATE ───────────────────────
//
// ⛔ THE OTHER HALF OF THE STAGE, AND IT LIVES INSIDE `verify`, WHICH CANNOT RUN HERE. So the append
// block is lifted out and driven with the gate lines an arm would have produced. Without this the
// cases above would all pass on a driver that never appended anything — they inject the ledger.
const APPEND = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => /# ── Ledger for the grant-INDEPENDENCE test/.test(l));
  if (start < 0) return '';
  const end = lines.findIndex((l, i) => i > start && l === '  esac');
  return end < 0 ? '' : lines.slice(start, end + 1).join('\n');
})();

/** Run the driver's own append block once per arm, and return the ledger lines it built. */
const buildLedger = (arms) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-led-'));
  const script = path.join(root, 'append.sh');
  fs.writeFileSync(script, [
    'set -uo pipefail',
    'ARM_LEDGER=""',
    // `local` is only legal inside a function, which is where the block really lives.
    'append () {',
    '  local rc="$1" label="$2" gate="$3"',
    APPEND,
    '}',
    ...arms.map(({ rc, label, gate }) => `append ${rc} ${label} ${JSON.stringify(gate)}`),
    'printf %s "$ARM_LEDGER"',
  ].join('\n'));
  try {
    return execFileSync('bash', [script], { encoding: 'utf8' }).split('\n').filter(Boolean);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
};

test('INSTRUMENT: the append block was extracted and is the real one', () => {
  assert.ok(APPEND.includes('ARM_LEDGER="$ARM_LEDGER'),
    'the ledger append was not extracted, so every case using it is vacuous');
  assert.ok(APPEND.includes('diag|at-grant|at-catalog'), 'the extraction lost the exclusion list');
});

test('⭑ the append block reads the gate line, in the field order the predicate parses', () => {
  // ⛔ THE FIELD ORDER IS A CROSS-DRIVER CONTRACT, NOT A LOCAL CHOICE. `classify` splits on `:` and
  // reads rc, digest, state, count positionally, so a macOS-shaped ordering would be parsed as
  // something else entirely and answered with confidence.
  const led = buildLedger([
    { rc: 0, label: 'synth', gate: 'artifacts=816/1117 missing=301 shortfall=0d0532fa4785' },
    { rc: 1, label: 'fb1', gate: 'artifacts=ABSENT/1117 missing=1 shortfall=ff00ff00' },
    // A gate that could not run at all: no digest to read, so `?` — which can never equal another
    // arm's digest, so an unreadable arm only ever REFUSES the claim.
    { rc: 3, label: 'fb2', gate: 'no artifact reference' },
    // DIRECT mode and the dtrace re-run of the SAME grant must not appear at all.
    { rc: 0, label: 'at-grant', gate: 'artifacts=1/1 missing=0 shortfall=none' },
    { rc: 0, label: 'diag', gate: 'artifacts=1/1 missing=0 shortfall=none' },
  ]);
  assert.deepEqual(led, ['0:0d0532fa4785:ok:301', '1:ff00ff00:abs:1', '3:?:ok:?'],
    'the ledger shape drifted, or a non-widening arm leaked into it');
});

test('⭑ END TO END: gate lines -> the real append block -> the real predicate -> the verdict', () => {
  // ⛔ THE ROUND TRIP IS THE POINT. Each half could be individually right and still disagree about
  // what a ledger line means; only feeding one into the other proves they do not. The four arms below
  // are the `@arbitrum/sdk@3.0.0-beta.0` shape measured on darwin — `rc=0 artifacts=816/1117
  // missing=301 shortfall=0d0532fa4785` at every rung up to `write:"disk"`.
  const gate = 'artifacts=816/1117 missing=301 shortfall=0d0532fa4785';
  const arms = ['synth', 'fb0', 'fb1', 'fb2'].map((label) => ({ rc: 0, label, gate }));
  const ledger = buildLedger(arms).join('\n') + '\n';
  const out = run('  return 1', { ledger });
  assert.match(out, /the SAME 301-artifact shortfall/);
  assert.equal(parseDriverLog(out).verdict, 'ARTIFACT-GATE-SUSPECT');

  // And the same path with ONE arm's shortfall moved must not be. A single changed digest is the
  // whole difference between a toolchain artefact and a capability gap.
  const moved = arms.map((a, i) => (i === 2
    ? { ...a, gate: 'artifacts=816/1117 missing=301 shortfall=deadbeefcafe' } : a));
  const out2 = run('  return 1', { ledger: buildLedger(moved).join('\n') + '\n' });
  assert.doesNotMatch(out2, /ARTIFACT-GATE-SUSPECT/);
  assert.equal(parseDriverLog(out2).verdict, 'UNDER-PREDICTED');
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
