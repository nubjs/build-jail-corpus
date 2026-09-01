// The promotion probe: the paired arm that makes a `writePaths` narrowing falsifiable.
//
// ⛔ THE FIXTURE IS THE REAL BLOCKED CASE, NOT AN INVENTED ONE. `@clerk/shared@2.9.2` sits in this
// repo three times — `{"writePaths":["Library/Preferences/clerk"]}` on darwin,
// `{"write":{"userHome":true}}` on linux and win32 — and the darwin record is `minimality: MINIMAL`
// with `arms-unfalsifiable`, i.e. a whole-home-to-one-directory narrowing the guard withholds because
// nothing in the run could have gone red. Every assertion below is about that transition.
//
//   node --test harness/v2/promotion-probe.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import {
  PROMOTION_PROBE_MARKER, VERDICT, licensedCaps, observeHome, probeArms, probePlan, scoreProbe,
  verdictLines,
} from './promotion-probe.mjs';
import { PROMOTION_TERM, descentTerms, narrow } from './descent-terms.mjs';
import { decide, narrowingEvidence } from './publish-guard.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLERK = { writePaths: ['Library/Preferences/clerk'] };
const ENTRY = 'Library/Preferences/clerk';

// ── THE VOCABULARY ────────────────────────────────────────────────────────────────────────────────

test('`no-writePaths` is a drop this vocabulary can APPLY but never a leave-one-out TERM', () => {
  // Applying it is the whole point — the arm has to run a genuinely narrowed grant.
  assert.deepEqual(narrow({ ...CLERK, network: true }, [PROMOTION_TERM]), { network: true });
  // ⛔ AND IT MUST NOT BE IN `terms`. A name there is one whose GREEN arm narrows the grant, and a
  // green `no-writePaths` install arm is green for every package on earth — the artefact is lost one
  // install LATER, which no arm here can see. Putting it in `terms` would narrow every `writePaths`
  // record to nothing on a vacuous pass.
  assert.deepEqual(descentTerms({ ...CLERK, network: true }, 'linux').terms, ['no-network']);
  assert.deepEqual(descentTerms(CLERK, 'linux').terms, []);
});

test('applying `no-writePaths` to a grant that declares none THROWS rather than no-opping', () => {
  // ⛔ THE NO-OP IS THE DANGEROUS OUTCOME. A silent `delete g.writePaths` on `{network:true}` returns
  // the UNNARROWED grant, so the pair would compare an arm against itself and read the entry present
  // in both — a verdict reached by measuring nothing.
  assert.throws(() => narrow({ network: true }, [PROMOTION_TERM]), /would be a no-op/);
  assert.throws(() => probeArms({ network: true }, narrow), /would be a no-op/);
});

test('`no-writePaths` does not match the `no-write-<scope>` regex, so a stray one FAILS CLOSED', () => {
  // ⛔ IF A FUTURE DRIVER ROUTED IT INTO `overPredictedBy`, `record.mjs` must keep the WIDE grant.
  // Its recomputation loop matches `/^no-write-(.+)$/`; this name has no hyphen after `write`, so it
  // lands in `unparsedNames`, which keeps the synthesized value and says the recomputation failed.
  // That is fail-closed by an accident of spelling, and pinning it is what stops it being an accident.
  assert.equal(/^no-write-(.+)$/.exec(PROMOTION_TERM), null);
  const r = parseDriverLog([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"writePaths":["Library/Preferences/clerk"],"network":true}',
    `     ⛔ OVER-PREDICTED — the strictly narrower {"network":true} also verifies; '${PROMOTION_TERM}' was not needed`,
  ].join('\n'));
  assert.equal(r.grantSource, 'synthesized');
  assert.ok(r.notes.includes('descent-name-unparsed'));
  assert.deepEqual(r.grant, { writePaths: [ENTRY], network: true }, 'the WIDE grant is kept');
});

// ── THE PLAN ──────────────────────────────────────────────────────────────────────────────────────

test('the probe declines a grant that already writes the real home, and says which case', () => {
  // ⛔ BOTH WRITE SHAPES. `write` is a map of scopes OR the string `"disk"`, and a `typeof === object`
  // test drops the string form on the floor — the same shape `publish-guard.mjs`'s `scopeTokens`
  // carries a scar for. Either way the control arm's PRESENT would be unattributable: the script
  // could have written the real home directly and the promotion moved nothing.
  for (const w of [{ userHome: true }, 'disk']) {
    const plan = probePlan({ write: w, ...CLERK });
    assert.equal(plan.supported, false, JSON.stringify(w));
    assert.equal(plan.reason, 'home-write-granted', JSON.stringify(w));
    assert.deepEqual(plan.skipped, [ENTRY], 'the declined entries are still named');
  }
  assert.equal(probePlan({ write: { deps: true }, ...CLERK }).supported, true,
    'a write scope that is NOT the real home leaves the probe answerable');
  assert.equal(probePlan({ network: true }).reason, 'no-declaration');
});

test('every declared entry is probed, the baseline prefixes included', () => {
  // ⛔ THE PREMISE THAT WOULD HAVE EXCLUDED `.cache` IS FALSE HERE, AND `measure.sh` STILL SAYS
  // OTHERWISE. An UNCATALOGUED package promotes `baseline_caps().write_paths` — `.cache`, `.npm`,
  // `.electron`, `AppData/Local`, `Library/Caches` — so a drop arm that reached the jail with the
  // package ABSENT could not go red on any of them. But `dep-scaffold.mjs::buildCatalog` writes
  // `packages[target] = {default: grant}` UNCONDITIONALLY, and `catalog_v2.rs` now accepts an empty
  // entry ("AN ENTRY THAT GRANTS NOTHING IS THE TIGHTEST GRANT THERE IS"), so the drop arm always
  // carries an explicit entry with empty `write_paths` and promotion returns before its loop.
  // Skipping these would be a hardcoded claim about a Rust constant standing in for the measurement
  // the pair already makes.
  assert.deepEqual(probePlan({ writePaths: ['.cache/puppeteer'] }).entries, ['.cache/puppeteer']);
});

// ── THE GATE ──────────────────────────────────────────────────────────────────────────────────────

test('PROVEN needs the control PRESENT *and* the drop ABSENT — neither alone', () => {
  const plan = probePlan(CLERK);
  const score = (control, drop) => scoreProbe(plan, { control: { [ENTRY]: control }, drop: { [ENTRY]: drop } });
  assert.equal(score(true, false).verdict, VERDICT.PROVEN);
  // ⛔ THE CONTROL IS THE ARM THAT CATCHES THE UNDER-GRANT. A `writePaths` grant claims the script's
  // home writes FOLLOWED `$HOME`; if the derivation got that wrong the write named the real home by
  // absolute path, the control arm (which grants no real-home write) is refused, and nothing lands.
  assert.equal(score(false, false).verdict, VERDICT.UNPROVEN_CONTROL);
  // ⛔ AND A GREEN DROP ARM IS NOT EVIDENCE OF ANYTHING — it says the pair could not have failed.
  assert.equal(score(true, true).verdict, VERDICT.UNPROVEN_DROP);
  assert.equal(score(false, true).verdict, VERDICT.UNPROVEN_CONTROL);
});

test('a MISSING observation is VOID, never a red drop arm', () => {
  // ⛔ THE MISTAKE THIS FORBIDS MANUFACTURES THE VERY EVIDENCE THE MODULE EXISTS TO DEMAND. An arm
  // whose home directory the driver never created looks exactly like a drop arm that correctly
  // discarded everything, and collapsing the two publishes a narrowing off an arm that never ran.
  const plan = probePlan(CLERK);
  assert.equal(scoreProbe(plan, { control: { [ENTRY]: true }, drop: {} }).verdict, VERDICT.VOID);
  assert.equal(scoreProbe(plan, { control: {}, drop: { [ENTRY]: false } }).verdict, VERDICT.VOID);
  assert.equal(scoreProbe(plan, {}).verdict, VERDICT.VOID);
});

test('the gate reads a REAL directory tree, and a missing home is null rather than absent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promo-'));
  try {
    fs.mkdirSync(path.join(dir, 'control', ...ENTRY.split('/')), { recursive: true });
    fs.mkdirSync(path.join(dir, 'drop'), { recursive: true });
    assert.deepEqual(observeHome(path.join(dir, 'control'), [ENTRY], { fs, path }), { [ENTRY]: true });
    assert.deepEqual(observeHome(path.join(dir, 'drop'), [ENTRY], { fs, path }), { [ENTRY]: false });
    assert.equal(observeHome(path.join(dir, 'never-created'), [ENTRY], { fs, path }), null);
    // ⛔ SEPARATOR-TERMINATED, NEVER A PREFIX MATCH: a sibling whose name merely STARTS with the
    // entry is a different directory, and reading it as the entry is a green that could not fail.
    fs.mkdirSync(path.join(dir, 'sib', 'Library', 'Preferences', 'clerk-backup'), { recursive: true });
    assert.deepEqual(observeHome(path.join(dir, 'sib'), [ENTRY], { fs, path }), { [ENTRY]: false });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── THE MARKER, AND THE ROUND TRIP INTO `results.json` ────────────────────────────────────────────

test('⭑ the marker round-trips all the way into the emitted record, not merely into the parser', () => {
  // ⛔ THIS IS THE TEST `confinedWide` DID NOT HAVE, AND THE OMISSION COST A WHOLE PROBE. That field
  // was parsed into `out` and then dropped by the CLI's explicit whitelist, so the one arm
  // adjudicating the write axis of a `write:"disk"` record left NO trace in any record — every
  // parse-level assertion passing the entire time. `publish-guard.mjs` reads records and never logs,
  // so this field's whole value is that it reaches the file.
  const plan = probePlan(CLERK);
  const scored = scoreProbe(plan, { control: { [ENTRY]: true }, drop: { [ENTRY]: false } });
  const lines = verdictLines('darwin', CLERK, plan, scored);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promo-rec-'));
  try {
    const log = path.join(dir, 'driver.out');
    fs.writeFileSync(log, ['  ARM-FALSIFIABILITY {"reasons":[]}',
      `  => VERIFIED ${JSON.stringify(CLERK)}`, ...lines].join('\n'));
    const parsed = parseDriverLog(fs.readFileSync(log, 'utf8'));
    assert.equal(parsed.promotionProbe.verdict, VERDICT.PROVEN, 'the parser read it');

    const outRoot = path.join(dir, 'out');
    execFileSync(process.execPath, [path.join(HERE, 'record.mjs'),
      '--log', log, '--pkg', 'p', '--version', '1.0.0', '--out', outRoot, '--rc', '0'],
    { encoding: 'utf8' });
    const found = fs.globSync(path.join(outRoot, '**', 'results.json'));
    assert.equal(found.length, 1, `exactly one record should be written, got ${found.length}`);
    const rec = JSON.parse(fs.readFileSync(found[0], 'utf8'));
    assert.equal(rec.promotionProbe?.verdict, VERDICT.PROVEN,
      'the probe ran, printed, parsed — and must also be IN the file the guard reads');
    assert.deepEqual(rec.promotionProbe.entries, [{ entry: ENTRY, control: true, drop: false }]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('FAIL CLOSED: an unreadable marker leaves the field null and notes it', () => {
  for (const bad of [`  ${PROMOTION_PROBE_MARKER} {not json}`, `  ${PROMOTION_PROBE_MARKER} {}`]) {
    const r = parseDriverLog(bad);
    assert.equal(r.promotionProbe, null, `\`${bad}\` produced a verdict`);
    assert.ok(r.notes.includes('promotion-probe-unparsable'), `\`${bad}\` was dropped silently`);
  }
  // Absent is not unparsable: every record predating the probe has no marker, and noting those would
  // flood `notes` with a non-finding.
  const none = parseDriverLog('  => VERIFIED {"network":true}');
  assert.equal(none.promotionProbe, null);
  assert.ok(!none.notes.includes('promotion-probe-unparsable'));
});

test('a declined probe still PRINTS, because a silent skip is the state this replaces', () => {
  const plan = probePlan({ network: true });
  const out = verdictLines('linux', { network: true }, plan, scoreProbe(plan, {})).join('\n');
  assert.match(out, /PROMOTION PROBE UNSUPPORTED/);
  assert.match(out, new RegExp(`${PROMOTION_PROBE_MARKER} \\{`));
  assert.equal(parseDriverLog(out).promotionProbe.verdict, VERDICT.UNSUPPORTED);
});

// ── WHAT IT LICENSES, AND WHAT IT MUST NOT ────────────────────────────────────────────────────────

const rec = (probe, over = {}) => ({
  verdict: 'MINIMUM',
  grant: CLERK,
  minimality: 'MINIMAL',
  overPredictedBy: [],
  notes: ['arms-unfalsifiable'],
  descentRedArm: false,
  provenance: { platform: 'win32-x64' },
  promotionProbe: probe,
  ...over,
});
const proven = { platform: 'win32', verdict: VERDICT.PROVEN, reason: 'x', entries: [{ entry: ENTRY, control: true, drop: false }], skipped: [] };

test('⭑ @clerk/shared: whole-home → one directory PUBLISHES on a red arm and WITHHOLDS on a green one', () => {
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true } }, notes: [] };
  // Today, with no probe at all: withheld, which is the gap.
  assert.equal(decide(prior, rec(null)).publish, false);
  // A RED drop arm — the declaration is what carried the artefact into the real home.
  const red = decide(prior, rec(proven));
  assert.equal(red.publish, true);
  assert.match(red.reason, /PROMOTION PROBE that went red/);
  // ⛔⛔ AND A GREEN DROP ARM MUST NOT PUBLISH. This is the direction the whole design turns on: an
  // arm that passed could not have failed, so reading it as a licence would be the waiver this
  // replaces, wearing an arm's clothes.
  const green = { ...proven, verdict: VERDICT.UNPROVEN_DROP, entries: [{ entry: ENTRY, control: true, drop: true }] };
  assert.equal(decide(prior, rec(green)).publish, false);
  // A control that produced nothing is the derivation being wrong, and must not publish either.
  const noCtl = { ...proven, verdict: VERDICT.UNPROVEN_CONTROL, entries: [{ entry: ENTRY, control: false, drop: false }] };
  assert.equal(decide(prior, rec(noCtl)).publish, false);
});

test('the verdict WORD is not trusted — the guard re-derives it from the rows', () => {
  // A half-updated driver emitting `PROVEN` beside rows that say otherwise must not get through.
  const forged = { ...proven, entries: [{ entry: ENTRY, control: true, drop: true }] };
  assert.equal(narrowingEvidence(rec(forged), ['write.userHome']).evidence, false);
  assert.equal(narrowingEvidence(rec({ ...proven, entries: [] }), ['write.userHome']).evidence, false);
});

test('the licence is ONE capability, so a narrowing that also drops another still withholds', () => {
  // ⛔ THE PAIR SPEAKS TO THE HOME AXIS AND NOTHING ELSE. It shows the artefact travelled through the
  // promotion under a grant with no real-home write; it says nothing about egress, so a record that
  // also drops `network` gets no licence from it. Same `every`-over-dropped-capabilities shape
  // `record.mjs` uses for the denial witness.
  assert.deepEqual([...licensedCaps(scoreProbe(probePlan(CLERK),
    { control: { [ENTRY]: true }, drop: { [ENTRY]: false } }))], ['write.userHome']);
  const prior = { verdict: 'MINIMUM', grant: { write: { userHome: true }, network: true }, notes: [] };
  assert.equal(decide(prior, rec(proven)).publish, false, 'network was dropped too, unproven');
});

test('the licence covers the read the home write IMPLIES, and no independently-authored one', () => {
  // ⛔ WHY THE LICENCE NAMES TWO TOKENS FOR ONE CAPABILITY. `write` implies read at its own scope and
  // the parser REJECTS a grant that spells the implied half out, so `capsOf` materialises
  // `read.userHome` rather than reading it off the text — and every promotion narrowing therefore
  // drops BOTH. A licence naming only the authored half would fail `every` on a token no author ever
  // wrote, and would withhold every record this term exists to publish.
  const implied = { verdict: 'MINIMUM', grant: { write: { userHome: true } }, notes: [] };
  assert.equal(decide(implied, rec(proven)).publish, true);
  // ⛔ AND IT IS STILL ONE CAPABILITY, WHICH IS THE HALF THAT COULD HAVE GONE WRONG. `read.project` is
  // AUTHORED — `write.userHome` does not imply it — so a narrowing that also gives it up is asking
  // the probe about a scope it never touched, and gets no licence.
  const authored = {
    verdict: 'MINIMUM',
    grant: { write: { userHome: true }, read: { project: true } },
    notes: [],
  };
  assert.equal(decide(authored, rec(proven)).publish, false, 'an authored read is not implied');
});

test('a PROVEN probe on a record that ALREADY holds the home write licenses nothing', () => {
  // The precondition `probePlan` enforces, re-derived at the guard: a record whose grant carries
  // `write.userHome` beside a PROVEN probe is an instrument disagreement, and the safe reading is
  // that the probe proves nothing.
  //
  // ⛔ `minimality` IS `OVER-PREDICTED` HERE ON PURPOSE, AND WITHOUT THAT THIS TEST CANNOT FAIL. With
  // `MINIMAL` and a non-empty capability set the record already has evidence under `hasRedArm`'s
  // second clause — every arm went red — so the assertion would pass for a reason that has nothing to
  // do with the promotion term. Isolating a term means removing the ones that would carry it anyway.
  for (const w of [{ userHome: true }, 'disk']) {
    const r = rec(proven, { grant: { write: w, ...CLERK }, minimality: 'OVER-PREDICTED' });
    assert.equal(narrowingEvidence(r, ['write.userHome']).evidence, false, JSON.stringify(w));
    // The positive control for this test's own instrument: the SAME record without the real-home
    // write in its grant does get the licence, so the `false` above is the precondition firing.
    assert.equal(narrowingEvidence(rec(proven, { minimality: 'OVER-PREDICTED' }), ['write.userHome']).evidence,
      true, 'the control case must be licensed, or the assertion above proves nothing');
  }
});

test('an unscoped caller cannot reach the promotion term at all', () => {
  // ⛔ `collate.mjs` GATES A PLATFORM AND HAS NO DROP SET TO HAND OVER, so it cannot ask the scoped
  // question — and not being able to ask it means no licence, which keeps that consumer exactly as
  // strict as it was before this term existed.
  assert.equal(narrowingEvidence(rec(proven)).evidence, false);
  assert.equal(narrowingEvidence(rec(proven), []).evidence, false);
});

// ── ALL THREE DRIVERS ─────────────────────────────────────────────────────────────────────────────

test('⭑ all three drivers run the probe, on BOTH the synthesized and the ladder path', () => {
  // ⛔ A CHANGE ONE DRIVER DOES NOT GET READS AS A REAL PLATFORM FINDING. The marker's absence on one
  // platform is indistinguishable in the corpus from "the pair could not be proven there", so the
  // delegation is pinned rather than trusted — the same reason `descent-vocabulary.test.mjs` pins the
  // descent's.
  for (const [driver, calls] of [
    ['measure.sh', /promotion_probe "\$GRANT"/],
    ['measure-macos.sh', /promotion_probe "\$GRANT"/],
    ['measure-windows.mjs', /promotionProbe\(GRANT\)/],
  ]) {
    const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
    assert.match(src, calls, `${driver} does not run the probe on the synthesized path`);
    assert.match(src, /promotion.?[Pp]robe\(?\s*"?\$?g\)?/, `${driver} does not run it on the ladder path`);
    assert.match(src, /promotion-probe\.mjs|promotion-probe'/, `${driver} does not use the shared module`);
  }
});

test('⭑ each probe arm gets its OWN real home, in every driver', () => {
  // ⛔ WITHOUT THIS THE DROP ARM COULD NOT GO RED. Promotion only ever ADDS
  // (`promote_declared_path` renames where the destination is absent), so a control arm promoting
  // into a shared `$HOME` leaves the directory sitting there for the drop arm to find — a green that
  // could not have been red, produced by the instrument built to rule one out.
  const sh = ['measure.sh', 'measure-macos.sh'].map((f) => fs.readFileSync(path.join(HERE, f), 'utf8'));
  for (const src of sh) {
    assert.match(src, /promo-control-home/);
    assert.match(src, /promo-drop-home/);
    // ⛔ AND THE CACHE MUST NOT MOVE WITH IT. `sandbox_homes` falls back to `$HOME/.cache` only when
    // `XDG_CACHE_HOME` is unset, so repointing HOME alone drags the persistent private jail home
    // along and the arm runs cold — a failure that reads exactly like a denial.
    assert.match(src, /XDG_CACHE_HOME/);
  }
  const win = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  assert.match(win, /promo-\$\{label\}-home/);
  // `sandbox_homes` reads HOME first and USERPROFILE only as a fallback, so a Windows driver setting
  // one of them leaves nub promoting into the ambient profile on a box that has the other.
  assert.match(win, /env\.HOME = realHome; env\.USERPROFILE = realHome;/);
});
