// The Windows ladder's grant-INDEPENDENCE stage, EXECUTED — not grepped for.
//
// ⛔ WHY THIS FILE EXISTS AT ALL. A cross-driver TOKEN test fires only on TOTAL absence of a string,
// so reverting one driver's emission leaves it green whenever the token survives anywhere else in the
// file — measured in this effort, on this repo. `descent-contract.test.mjs` and
// `descent-vocabulary.test.mjs` are both source-matching guards over `measure-windows.mjs` and cannot
// tell a stage that FIRES from one sitting in the file above a `console.log` that overwrites it. Every
// assertion below is made against the driver's real stdout, produced by its own code.
//
// ⛔ WHAT IS STUBBED, AND WHY THAT IS STILL A REAL TEST. `verify` is the one thing that cannot run
// here: it needs a real Windows host, a nub binary built with `build-jail-catalog-override`, ETW
// capture and a live registry. Everything else — the rung sequence, the void/timeout branching, the
// `write:"disk"` descent guard, the real `shortfall-invariance.mjs`, and the exact sentences
// `record.mjs` reads — is the driver's own source, executed on this host. The stub is the ORACLE, so
// each case states which arms pass and the test reads what the driver concluded from that.
//
// ⛔ THE LEDGER IS A SEPARATE INPUT FROM THE ORACLE, AND CONFLATING THEM WOULD BE WRONG. The real
// `verify` records the INSTALL's exit code while RETURNING `ok` on `rc === 0 && missing.length === 0`,
// so an arm that installed cleanly and then failed the artifact gate is `rc=0` in the ledger and
// "insufficient" to the caller. That gap is the whole subject of `ARTIFACT-GATE-SUSPECT`. A stub that
// derived one from the other could not express it — so the LEDGER-APPEND block is extracted and
// executed separately, against arm states this file states outright, and its output is then fed to
// the real predicate. That round trip is what makes the two halves one test rather than two mocks.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const DRIVER = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');

// The driver's post-VERIFY tail: the ladder and the grant-independence stage. Anchored on the section
// banner rather than a line number so an edit above it cannot silently shift the slice.
const REGION = (() => {
  const lines = DRIVER.split('\n');
  const start = lines.findIndex((l) => /^\/\/ ── 4\. FALL BACK/.test(l));
  return start < 0 ? '' : lines.slice(start).join('\n');
})();

// The ledger append, lifted out of `verify` so it can be driven with arm states instead of a real
// jailed install. It is the driver's own three lines, not a paraphrase.
const APPEND = /\n(\s*if \(label !== 'at-grant'\) \{\n[\s\S]*?\n\s*\}\n)/.exec(DRIVER)?.[1] ?? '';

// ⛔ THE DRIVER'S OWN SPELLING, WHICH IS A JS OBJECT LITERAL AND NOT JSON. The two POSIX drivers hold
// their rungs as JSON strings; matching this file against those would find nothing and report the
// region as mis-extracted — or, worse, be relaxed until it matched something.
const RUNG0 = '{ write: { deps: true, project: true, userHome: true }, network: true }';
const RUNG2 = "{ write: 'disk', network: true }";

test('INSTRUMENT: both regions were located and hold the code under test', () => {
  assert.ok(REGION.length > 1500, `the banner-4 slice was not found (got ${REGION.length} chars)`);
  for (const needle of [RUNG0, RUNG2, 'shortfall-invariance.mjs', 'ARTIFACT-GATE-SUSPECT',
    'NO-STATE-PASSED']) {
    assert.ok(REGION.includes(needle), `the extracted region no longer contains \`${needle}\``);
  }
  assert.ok(APPEND.includes('ARM_LEDGER.push('),
    'the ledger-append block was not extracted, so every case using it is vacuous');
});

// A four-arm ledger whose digest is INVARIANT across every rung — the shape that earns the verdict.
const LEDGER_INVARIANT = ['0:ab12cd:ok:301', '0:ab12cd:ok:301', '0:ab12cd:ok:301', '0:ab12cd:ok:301'];
// ⛔ EVERY ARM rc=0 DELIBERATELY, SO THE DIGEST CLAUSE IS WHAT REFUSES. The predicate checks exit
// codes BEFORE digests, so an rc=1 ledger is turned away by `an arm exited non-zero` and the varying
// shortfall is never examined — a negative control that never reaches the clause it controls for.
const LEDGER_RESPONSIVE = ['0:aa11:ok:9', '0:bb22:ok:7', '0:cc33:ok:4', '0:dd44:ok:2'];

/**
 * Run the extracted ladder+stage with a stubbed `verify`, and return its stdout.
 *
 * `oracle` is a JS expression evaluating to `(grant, label) => <verify result>`, which is the
 * driver's own contract: `{ ok }` SUFFICIENT, `{ void: true }` the override never engaged,
 * `{ timedOut: true, stage }` the deadline fired. Arm labels are the driver's own: `fb<i>` per rung,
 * `nar-<name>` per descent arm, `joint-narrow`.
 *
 * ⛔ `here` SWAPS THE PREDICATE AND NOTHING ELSE — `HERE` is used exactly once in this region, on the
 * `shortfall-invariance.mjs` spawn.
 */
const runRegion = (oracle, {
  grant = '{"write":{"deps":true}}', source = REGION, ledger = LEDGER_RESPONSIVE, here = HERE,
} = {}) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-inv-'));
  const script = path.join(dir, 'region.mjs');
  fs.writeFileSync(script, [
    "import { spawnSync } from 'node:child_process';",
    "import path from 'node:path';",
    'const NODE = process.execPath;',
    `const HERE = ${JSON.stringify(here)};`,
    // The driver's own `run`, copied because it is defined far above the extracted slice. Keeping it
    // byte-identical matters: `input` is how the ledger reaches the predicate's stdin.
    'const run = (exe, args, opts = {}) =>',
    "  spawnSync(exe, args, { encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, ...opts });",
    'const argv = [];',
    `const GRANT = ${grant};`,
    `const ARM_LEDGER = ${JSON.stringify(ledger)};`,
    'const descend = (g, provenance) => console.log(`  DESCEND[${provenance}] ${JSON.stringify(g)}`);',
    `const verify = ${oracle};`,
    source,
  ].join('\n'));
  try {
    return execFileSync(process.execPath, [script], { encoding: 'utf8' });
  } catch (e) {
    // HARNESS-ERROR exits 1 and a VOID rung exits 3; both paths have stdout worth asserting on.
    if (e.stdout !== undefined) return e.stdout;
    throw e;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

const ALL_FAIL = '(g, label) => ({ ok: false })';

// ── THE STAGE ─────────────────────────────────────────────────────────────────────────────────────

test('⭑ a shortfall invariant to the top rung is ARTIFACT-GATE-SUSPECT, not a capability finding', () => {
  // ⛔ THE TRIAGE GAP THIS CLOSES. `collate.mjs:187` excludes both `NO-STATE-PASSED` and
  // `ARTIFACT-GATE-SUSPECT` from the catalog, so this is not a broken-install risk — it is the
  // difference between "needs a wider grant" and "no grant will ever help", which is the distinction
  // that sends someone to widen a catalog entry that no widening can fix.
  const out = runRegion(ALL_FAIL, { ledger: LEDGER_INVARIANT });
  assert.match(out, /=> ARTIFACT-GATE-SUSPECT \{"write":\{"deps":true\}\}/,
    'the stage did not fire, or did not publish the SYNTHESIZED grant');
  assert.match(out, /the SAME 301-artifact shortfall/,
    "the count is not read out of the predicate's stdout");
  // ⛔ ASSERTED ON THE RECORD, NOT ONLY ON THE TEXT. `record.mjs` walks the log line by line and the
  // LAST matching `=>` wins, so a driver that printed BOTH verdicts would satisfy the match above
  // while filing every one of these packages as `NO-STATE-PASSED` exactly as before the port.
  assert.doesNotMatch(out, /=> NO-STATE-PASSED/,
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

test('⭑ NEGATIVE CONTROL: a shortfall that VARIES across arms is not grant-independent', () => {
  // ⛔ WITHOUT THIS, "the driver classifies grant-independence" IS SATISFIED BY CLASSIFYING
  // EVERYTHING — and the failure would be silent and in the under-granting direction, because a
  // SUSPECT record publishes an undescended grant.
  const out = runRegion(ALL_FAIL, { ledger: LEDGER_RESPONSIVE });
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'a shortfall that responded to the grant was classified as grant-independent');
  assert.match(out, /NOT-GRANT-INDEPENDENT the shortfall CHANGED across arms/,
    'the stage did not run, or refused on a clause other than the digest one');
  assert.equal(parseDriverLog(out).verdict, 'NO-STATE-PASSED');
});

test('⭑ an ABSENT package is refused even though its shortfall never moves', () => {
  // ⛔ THE SAFETY CLAUSE, EXERCISED THROUGH THE DRIVER. `<package absent>` on every arm is "invariant"
  // only in the sense that nothing happened four times; blessing it would publish a narrow grant off a
  // run in which the package never installed — an under-grant of unknown size, and under-granting is
  // the one direction that breaks a real install.
  const out = runRegion(ALL_FAIL, { ledger: ['0:ff99:abs:1', '0:ff99:abs:1', '0:ff99:abs:1', '0:ff99:abs:1'] });
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/, 'a package that never installed was blessed');
  assert.match(out, /NOT-GRANT-INDEPENDENT the package was ABSENT/);
  assert.equal(parseDriverLog(out).verdict, 'NO-STATE-PASSED');
});

// ⛔ THE STUB IS THE PREDICATE, NOT THE ORACLE, WHICH IS WHY BOTH CASES BELOW EXIST. Only the silent
// one can distinguish the guard from no guard; the printing one proves the refusal is caused by the
// EMPTY output rather than by the stubbing itself.
const withPredicate = (body, fn) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-pred-'));
  fs.writeFileSync(path.join(dir, 'shortfall-invariance.mjs'), body);
  try { return fn(dir); } finally { fs.rmSync(dir, { recursive: true, force: true }); }
};

test('⭑ a predicate that exits 0 printing NOTHING is refused, not read as grant-independence', () => {
  // ⛔ THE GUARD `measure.sh` GAINED IN `14d77b078`, CARRIED ACROSS RATHER THAN LEFT A LINUX-ONLY
  // REPAIR. An exit code of 0 is not evidence the predicate ran: its main-module guard compares the
  // module's own URL against the resolved URL of the invoked script, and a mismatch skips the entire
  // CLI block while exiting 0. Windows is the platform that guard was written FOR — the string form it
  // replaced could never match a backslash argv — so an unguarded driver here would render
  // `the SAME -artifact shortfall` and publish it.
  const out = withPredicate('process.exit(0);\n',
    (dir) => runRegion(ALL_FAIL, { here: dir, ledger: LEDGER_INVARIANT }));
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/,
    'the driver published its only un-descended grant off a predicate that never ran');
  assert.doesNotMatch(out, /the SAME -artifact/, 'the verdict rendered an empty artifact count');
  // ⛔ `HARNESS-ERROR` SPECIFICALLY, BECAUSE `claim-slice.mjs` RETURNS THAT ROW TO `pending`. Any
  // other verdict closes the queue row, baking an instrument failure into the corpus as a result.
  assert.equal(parseDriverLog(out).verdict, 'HARNESS-ERROR',
    'an instrument failure must reopen the queue row, not close it with a measurement it never made');
});

test('⭑ CONTROL: a predicate that PRINTS still yields ARTIFACT-GATE-SUSPECT, with its real count', () => {
  // Without this, a guard that refused unconditionally would satisfy the case above while destroying
  // the verdict the stage exists to produce — the shape of a harness that refuses everything.
  const out = withPredicate('console.log("GRANT-INDEPENDENT 7 aa");\nprocess.exit(0);\n',
    (dir) => runRegion(ALL_FAIL, { here: dir }));
  assert.doesNotMatch(out, /HARNESS-ERROR/, 'a predicate that printed was refused as if it had not run');
  assert.match(out, /the SAME 7-artifact shortfall/, "the count is not read out of the predicate's stdout");
  assert.equal(parseDriverLog(out).verdict, 'ARTIFACT-GATE-SUSPECT');
});

test('a rung that PASSES never reaches the stage — the ladder still owns the ordinary repair', () => {
  // The stage is a last resort, not a shortcut. A ladder that repaired the grant must publish a
  // MINIMUM and descend, exactly as before the port, whatever the ledger says.
  const out = runRegion("(g, label) => ({ ok: /\"read\":\"disk\"|\"write\":\"disk\"/.test(JSON.stringify(g)) === false })",
    { ledger: LEDGER_INVARIANT });
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT|NOT-GRANT-INDEPENDENT/,
    'the stage ran even though a rung passed');
  assert.match(out, /DESCEND\[ladder\]/, 'the winning rung was published un-narrowed');
  const r = parseDriverLog(out);
  assert.equal(r.verdict, 'MINIMUM');
  assert.equal(r.verifiedBy, 'ladder');
});

test('⭑ a VOID rung aborts before the stage — nothing was measured, so nothing is classified', () => {
  // ⛔ A VOID ARM MEASURED NOTHING, and its ledger line would be indistinguishable from a real one.
  // The abort is what keeps grant-independence a statement about measurements.
  const out = runRegion('(g, label) => ({ ok: false, void: true })', { ledger: LEDGER_INVARIANT });
  assert.match(out, /=> VOID rung 0/);
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT|NOT-GRANT-INDEPENDENT/,
    'a run in which the override never engaged was handed to the invariance predicate');
});

// ── `shortfall=` ON THE VERIFY LINE, WHERE `falsify.mjs` CAN ACTUALLY READ IT ─────────────────────

test('⭑ the new VERIFY field sits where falsify.mjs captures it, not merely somewhere on the line', () => {
  // ⛔ THE POSITION IS LOAD-BEARING AND THE FAILURE IS SILENT. `falsify.mjs` parses the win32
  // `VERIFY[at-grant]` line with `missing=(\d+)(?:\s+shortfall=(\S+))?`, so the optional group only
  // matches when `shortfall=` IMMEDIATELY follows `missing=N`. Placed after `(tree …)` instead, the
  // trailing `[^\n]*` swallows it, the capture is null, and the line still parses — so `OVERRIDDEN`
  // and `REJECTED` are read correctly and NOTHING goes red. That is the same silent-null shape the
  // comment above that regex was written about: a win32 case declaring `mustDetect: ['gate']` was once
  // unsatisfiable for a purely PARSING reason, and the optionality exists to keep the capture-group
  // numbering stable for POSIX rather than to make the field's position free.
  //
  // The regex is READ OUT OF `falsify.mjs`, never retyped — a retyped copy tests the copy.
  const src = fs.readFileSync(path.join(HERE, 'falsify.mjs'), 'utf8');
  const literal = /\/VERIFY\\\[at-grant\\\][^\n]*\/(?=,)/.exec(src)?.[0];
  assert.ok(literal, 'the VERIFY[at-grant] pattern was not found in falsify.mjs; this scan is broken');
  // eslint-disable-next-line no-eval
  const re = eval(literal);

  // The driver's own emission, located in its source and rendered with concrete values, so a change
  // to the template is a change to what is asserted here.
  const template = DRIVER.split('\n').find((l) => l.includes('VERIFY[${label}] rc='));
  assert.ok(template?.includes('missing=${missing.length} shortfall=${shortfall}'),
    `\`shortfall=\` must immediately follow \`missing=\` on the VERIFY line, or falsify.mjs reads null:\n${template}`);
  const emitted = '  VERIFY[at-grant] rc=0 artifacts=6/12 missing=6 shortfall=abc123def456'
    + ' (tree 100/200) OVERRIDDEN=2 REJECTED=0 grant={"network":true}';
  assert.deepEqual(re.exec(emitted)?.slice(1),
    ['0', '6', '12', '6', 'abc123def456', '2', '0'],
    'the emitted line does not fill the captures falsify.mjs depends on');

  // ⛔ THE NEGATIVE CONTROL IS THE WHOLE TEST. Without it "the field parses" is satisfied by a regex
  // that would parse it anywhere, and the misplacement this guards against would sail through.
  const misplaced = emitted.replace(' shortfall=abc123def456', '')
    .replace('(tree 100/200)', '(tree 100/200) shortfall=abc123def456');
  const m = re.exec(misplaced);
  assert.equal(m?.[5], undefined, 'the control does not reproduce the misplacement it controls for');
  assert.equal(m?.[6], '2', 'the misplaced line still parses OVERRIDDEN — which is why it goes unnoticed');

  // And a driver that emits no `shortfall=` at all must still fill every older capture, or adding the
  // field to one driver would break the parse for the two that have not been changed.
  assert.deepEqual(re.exec(emitted.replace(' shortfall=abc123def456', ''))?.slice(1),
    ['0', '6', '12', '6', undefined, '2', '0']);
});

// ── THE LEDGER APPEND, DRIVEN WITH ARM STATES AND FED TO THE REAL PREDICATE ───────────────────────

/** Run the driver's own append block once per arm state, and return the ledger it built. */
const buildLedger = (arms) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'win-led-'));
  const script = path.join(dir, 'append.mjs');
  fs.writeFileSync(script, [
    'const ARM_LEDGER = [];',
    `for (const { rc, shortfall, got, missing, label } of ${JSON.stringify(arms)}) {`,
    APPEND,
    '}',
    'console.log(JSON.stringify(ARM_LEDGER));',
  ].join('\n'));
  try {
    return JSON.parse(execFileSync(process.execPath, [script], { encoding: 'utf8' }));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

test('⭑ the append block emits the field order the predicate parses, and excludes DIRECT mode', () => {
  // ⛔ THE FIELD ORDER IS A CROSS-DRIVER CONTRACT, NOT A LOCAL CHOICE. `classify` splits on `:` and
  // reads rc, digest, state, count positionally, so a Windows-shaped ordering would be parsed as
  // something else entirely and answered with confidence.
  const led = buildLedger([
    { rc: 0, shortfall: 'ab12cd', got: true, missing: [1, 2, 3], label: 'synth' },
    { rc: 1, shortfall: 'none', got: null, missing: [1], label: 'fb0' },
    { rc: 0, shortfall: 'zz', got: true, missing: [], label: 'at-grant' },
  ]);
  assert.deepEqual(led, ['0:ab12cd:ok:3', '1:none:abs:1'],
    'the ledger shape drifted, or DIRECT mode leaked an arm into it');
});

test('⭑ END TO END: arm states -> the real append block -> the real predicate -> the verdict', () => {
  // ⛔ THE ROUND TRIP IS THE POINT. Each half above could be individually right and still disagree
  // about what a ledger line means; only feeding one into the other proves they do not. Four arms
  // that each exited 0 and each fell short by the SAME files — the `@arbitrum/sdk@3.0.0-beta.0` shape
  // measured on darwin (`rc=0 artifacts=816/1117 missing=301 shortfall=0d0532fa4785` at every rung up
  // to `write:"disk"`) — must come out the far end as SUSPECT.
  const invariant = ['synth', 'fb0', 'fb1', 'fb2'].map((label) => (
    { rc: 0, shortfall: '0d0532fa4785', got: true, missing: Array(301).fill('x'), label }));
  const out = runRegion(ALL_FAIL, { ledger: buildLedger(invariant) });
  assert.match(out, /the SAME 301-artifact shortfall/);
  assert.equal(parseDriverLog(out).verdict, 'ARTIFACT-GATE-SUSPECT');

  // And the same path with ONE arm's shortfall moved must not be. A single changed digest is the
  // whole difference between a toolchain artefact and a capability gap.
  const moved = invariant.map((a, i) => (i === 2 ? { ...a, shortfall: 'deadbeef' } : a));
  const out2 = runRegion(ALL_FAIL, { ledger: buildLedger(moved) });
  assert.doesNotMatch(out2, /ARTIFACT-GATE-SUSPECT/);
  assert.equal(parseDriverLog(out2).verdict, 'NO-STATE-PASSED');
});

// ── THE FALSIFICATION CONTROL ─────────────────────────────────────────────────────────────────────

// The region with the grant-independence stage excised, everything else identical. This is what the
// driver looked like before the port, reconstructed mechanically rather than pasted, so it cannot go
// stale.
// Line-based rather than a regex over the whole slice: the stage is several sibling `if` blocks, so a
// non-greedy `[\s\S]*?` up to a closing brace stops at the FIRST one and leaves the verdict-emitting
// block standing — an excision that looks like it worked and removes nothing that matters.
const STAGELESS = (() => {
  const lines = REGION.split('\n');
  const start = lines.findIndex((l) => /^\/\/ ── 5\. BEFORE DECLARING/.test(l));
  // ⛔ CUT UP TO THE TERMINAL VERDICT'S OWN `console.log`, NOT TO THE LAST STAGE STATEMENT. The
  // comment between them explains why the two verdicts are mutually exclusive and NAMES the token, so
  // an excision that stopped earlier would leave `ARTIFACT-GATE-SUSPECT` in the slice and this
  // control's absence assertion would fail on prose. That is the same "a token test fires only on
  // TOTAL absence" trap this whole file exists to avoid, met from the other side.
  const end = lines.findIndex((l) => l.includes("=> NO-STATE-PASSED even at write:disk"));
  return start < 0 || end < start ? REGION : [...lines.slice(0, start), ...lines.slice(end)].join('\n');
})();

test('⭑ FALSIFICATION: with the stage removed, every finding above disappears', () => {
  // ⛔ WITHOUT THIS THE WHOLE FILE IS UNFALSIFIABLE. A passing test is not evidence until it has been
  // seen to fail for the right reason, and the reason here has to be the stage's absence
  // specifically — not a broken stub, not a mangled extraction.
  assert.notEqual(STAGELESS, REGION, 'the excision matched nothing, so this control is vacuous');
  assert.ok(!STAGELESS.includes('ARTIFACT-GATE-SUSPECT'), 'the stage survived the excision');
  assert.ok(!STAGELESS.includes('shortfall-invariance.mjs'), 'the predicate spawn survived the excision');
  assert.ok(STAGELESS.includes(RUNG0), 'the excision removed the ladder as well as the stage');
  assert.ok(STAGELESS.includes('NO-STATE-PASSED'),
    'the excision took the terminal verdict too, so the control tests an empty region');

  const out = runRegion(ALL_FAIL, { source: STAGELESS, ledger: LEDGER_INVARIANT });
  assert.doesNotMatch(out, /ARTIFACT-GATE-SUSPECT/, 'the stageless driver still classified');
  assert.equal(parseDriverLog(out).verdict, 'NO-STATE-PASSED',
    'this is the dead-end verdict the port exists to distinguish from a real capability gap');
});
