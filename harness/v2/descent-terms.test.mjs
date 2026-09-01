// THE TERMINAL RUNG IS DESCENDABLE, AND THE THREE WAYS THAT COULD GO WRONG ARE EACH PINNED HERE.
//
// ⛔ WHAT THIS FILE IS GUARDING. Until `descent-terms.mjs`, all three ladders refused to descend
// `{"write":"disk","network":true}` — "no droppable terms, so no descent" — and the refusal was worth
// exactly what it cost: MEASURED on the committed corpus 2026-09-01, all 75 `write:"disk"` records
// carry `overPredictedBy: []`, `minimality: null` and `grantSource: "synthesized"`. Every one is a
// whole-filesystem grant no arm has ever tried to disprove. All 75 also carry `network: true`.
//
// The refusal's stated reason was real, and case 1 below REPRODUCES it rather than trusting the
// comment: `Object.keys("disk")` really is `["0","1","2","3"]`, so the old inline generator really
// would have fabricated four `no-write-<digit>` arms. What was wrong was the SCOPE — the rung is a
// bundle, and refusing the whole descent threw away its second term along with its first.
//
// Three failure directions, each with a control that can actually fire:
//
//   FABRICATION   the generator invents arm names out of a string. Case 1 shows the hazard is real;
//                 cases 2-4 show this module refuses it, by throwing rather than by omission.
//   VACUOUS PASS  an arm that could not have gone red is scored as evidence. That is what a win32
//                 `no-network` arm would be, and cases 7-8 pin the UNSUPPORTED answer instead.
//   SILENT NO-OP  a name that PARSES and recomputes nothing, so the record publishes
//                 `grantSource: "descended"` beside the wide grant. Cases 5-6 and 12-13.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  ATOMIC_WRITE_REACH, NET_ENFORCED_AT_FULL_DISK, descentTerms, narrow, variants, verdictLines,
} from './descent-terms.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const TERMINAL = { write: 'disk', network: true };
const RUNG0 = { write: { deps: true, project: true, userHome: true }, network: true };
const RUNG1 = { write: { deps: true, project: true, userHome: true }, read: 'disk', network: true };

// ── 1. THE POSITIVE CONTROL FOR THE HAZARD ────────────────────────────────────────────────────────

test('INSTRUMENT: the fabrication this module prevents is REAL, not a story in a comment', () => {
  // ⛔ THE ONE CASE THAT MAKES EVERY OTHER CASE HERE MEAN SOMETHING. The old generator, verbatim, run
  // against the terminal rung. If this ever stops producing digit-named arms the hazard has changed
  // shape and the refusals below are guarding nothing.
  const legacy = (g) => {
    const out = [];
    if (g.network) out.push('no-network');
    for (const k of Object.keys(g.write ?? {})) out.push(`no-write-${k}`);
    if (g.read) out.push('no-read');
    return out;
  };
  assert.deepEqual(legacy(TERMINAL),
    ['no-network', 'no-write-0', 'no-write-1', 'no-write-2', 'no-write-3'],
    'Object.keys over a string no longer fabricates arms — re-derive what this module must refuse');
  // And the fabricated names PARSE in the recorder, which is why omitting them is not enough.
  assert.match('no-write-0', /^no-write-(.+)$/);
});

// ── 2. THE GENERATOR ──────────────────────────────────────────────────────────────────────────────

test('⭑ the terminal rung yields the one term that IS droppable, and no write term at all', () => {
  for (const platform of ['linux', 'darwin']) {
    assert.deepEqual(descentTerms(TERMINAL, platform).terms, ['no-network'],
      `${platform} must descend the terminal rung's network axis — it is the only publishable term`);
  }
});

test('⭑ RED-GREEN: no digit-named or `no-write-disk` arm is produced for a string reach', () => {
  // The acceptance criterion for case 1's hazard. Asserted on the VALUE, not on `terms.length`: a
  // generator that emitted `['no-network','no-write-disk']` would satisfy a length check and would
  // recompute to nothing in `record.mjs`.
  for (const platform of ['linux', 'darwin', 'win32']) {
    for (const t of descentTerms(TERMINAL, platform).terms) {
      assert.doesNotMatch(t, /^no-write-/, `${platform} produced \`${t}\` from a string write reach`);
    }
  }
});

test('the ordinary rungs are unchanged — this module is not a behaviour change below the top', () => {
  assert.deepEqual(descentTerms(RUNG0, 'linux').terms,
    ['no-network', 'no-write-deps', 'no-write-project', 'no-write-userHome']);
  assert.deepEqual(descentTerms(RUNG1, 'linux').terms,
    ['no-network', 'no-write-deps', 'no-write-project', 'no-write-userHome', 'no-read']);
  // The same on win32: the platform rule is scoped to the terminal rung, not to the platform.
  assert.deepEqual(descentTerms(RUNG0, 'win32').terms, descentTerms(RUNG0, 'linux').terms,
    'win32 lost a term on a CONFINED rung — the net-axis rule leaked past `write:"disk"`');
});

test('⭑ an unrecognised write shape THROWS rather than yielding a guessed arm list', () => {
  // Refusing is the whole contract: a generator that returns `[]` for a shape it does not understand
  // is indistinguishable from one that understood it and found nothing droppable.
  assert.throws(() => descentTerms({ write: 'everything', network: true }, 'linux'),
    /neither a map of scopes nor/);
  assert.throws(() => descentTerms({ write: 7 }, 'linux'), /neither a map of scopes nor/);
  assert.throws(() => descentTerms(null, 'linux'), /is not a grant/);
  // CONTROL: the one string it DOES accept still works, or the assertions above pass for free.
  assert.deepEqual(descentTerms({ write: ATOMIC_WRITE_REACH }, 'linux').terms, []);
});

// ── 3. THE APPLIER ────────────────────────────────────────────────────────────────────────────────

test('⭑ RED-GREEN: `narrow` REFUSES a drop that would be a silent no-op', () => {
  // ⛔ THE DEFECT IN ONE LINE: `delete "disk"["disk"]` evaluates to `true` and changes nothing, and
  // `Object.keys("disk").length` is 4 so the collapse never fires either. An applier built that way
  // returns the UNNARROWED grant, the arm passes trivially, and the pass is recorded as proof the
  // capability was droppable. Demonstrated first so the refusal below is not taken on trust.
  const silent = JSON.parse(JSON.stringify(TERMINAL));
  delete silent.write[ATOMIC_WRITE_REACH];
  assert.deepEqual(silent, TERMINAL, 'the no-op is no longer a no-op — re-derive what `narrow` guards');

  assert.throws(() => narrow(TERMINAL, ['no-write-disk']), /cannot be applied/);
  assert.throws(() => narrow(RUNG0, ['no-write-nosuchscope']), /cannot be applied/);
  assert.throws(() => narrow(RUNG0, ['network']), /not a drop name this vocabulary defines/);
});

test('CONTROL: `narrow` still applies every real drop, including the collapse', () => {
  // Without this, a `narrow` that threw on everything would satisfy the case above.
  assert.deepEqual(narrow(TERMINAL, ['no-network']), { write: 'disk' });
  assert.deepEqual(narrow(RUNG1, ['no-read']), RUNG0);
  assert.deepEqual(narrow({ write: { deps: true }, network: true }, ['no-write-deps']), { network: true },
    'an emptied `write` must be removed, not left as `{}`');
  assert.deepEqual(variants(TERMINAL, 'linux'), [['no-network', { write: 'disk' }]]);
});

// ── 4. THE PLATFORM RULE ──────────────────────────────────────────────────────────────────────────

test('⭑ win32 gets NO term at the terminal rung, because its net axis is gone there', () => {
  // ⛔ NOT CAUTION — `windows.rs`'s own branch. `if policy.build_jail && !confine_fs` returns
  // `plain_command` with `Degradation::full()` and pushes `net` onto `lost`: "egress is an
  // AppContainer CAPABILITY here (`internetClient`), so declining the token declines the net axis
  // with it." A `no-network` arm there cannot go red for a network reason, so its green would narrow
  // the catalog to "no network needed" for a package that used the network freely — a vacuous pass
  // converted into an under-grant.
  const { terms, skipped } = descentTerms(TERMINAL, 'win32');
  assert.deepEqual(terms, []);
  assert.deepEqual(skipped.map((s) => `${s.axis}:${s.reason}`),
    ['network:net-axis-lost-at-full-disk', 'write:reach-atomic']);
  assert.ok(!NET_ENFORCED_AT_FULL_DISK.has('win32'));
});

test('⭑ CONTROL: the POSIX backends keep the axis, so they are NOT marked unsupported', () => {
  // The negative half. A rule that marked every platform unsupported would satisfy the case above
  // while deleting the only descent this change buys.
  for (const platform of ['linux', 'darwin']) {
    assert.ok(NET_ENFORCED_AT_FULL_DISK.has(platform));
    assert.deepEqual(descentTerms(TERMINAL, platform).skipped.map((s) => s.axis), ['write'],
      `${platform} skipped an axis it can measure`);
  }
});

// ── 5. THE VERDICT SENTENCES ──────────────────────────────────────────────────────────────────────

test('⭑ RED-GREEN: a wide grant with no droppable term must NOT print the "empty grant" sentence', () => {
  // ⛔ `record.mjs` MATCHES `/grant is already empty/` AND SETS `minimality: 'MINIMAL'`. Printing that
  // sentence for `{"write":"disk","network":true}` publishes the widest grant in the corpus as PROVEN
  // MINIMAL off a descent that ran zero arms — strictly worse than the refusal it replaced.
  const lines = verdictLines(TERMINAL, 'win32').join('\n');
  assert.doesNotMatch(lines, /grant is already empty/);
  assert.doesNotMatch(lines, /=>\s*MINIMAL\b/);
  assert.match(lines, /=> DESCENT UNSUPPORTED/);
  assert.match(lines, /MINIMALITY IS UNPROVEN/);
  assert.match(lines, /DESCENT-UNSUPPORTED \{/, 'the machine-readable payload is missing');
  assert.match(lines, /CONFINED-WIDE probe/, 'the write axis must name the arm that DOES adjudicate it');
});

test('CONTROL: a genuinely empty grant still prints the sentence record.mjs reads as MINIMAL', () => {
  const lines = verdictLines({}, 'linux').join('\n');
  assert.match(lines, /grant is already empty/);
  assert.equal(parseDriverLog(`  => MINIMUM {}   (observed, then verified)\n${lines}`).minimality, 'MINIMAL');
});

test('a grant WITH terms prints no verdict line — the arms speak instead', () => {
  assert.deepEqual(verdictLines(TERMINAL, 'linux'), []);
  assert.deepEqual(verdictLines(RUNG0, 'linux'), []);
});

// ── 6. THROUGH THE REAL RECORDER ──────────────────────────────────────────────────────────────────

const drv = (lines) => parseDriverLog(lines.join('\n'));
// ⛔ BOTH OBSERVE PRODUCTS `record.mjs` GATES ON, because a fixture missing either tests a branch it
// did not mean to. The falsifiability line's absence reads as "the check never ran"; the `== NETWORK`
// census's absence makes the network term FAIL CLOSED and refuse every `no-network` drop. All three
// classifiers print the census unconditionally, so a real log always carries it — and ZERO peers is
// the shape that leaves the descent vocabulary, which is this file's subject, the only variable.
const FALSIFIABLE = ['  ARM-FALSIFIABILITY {"reasons":[]}',
  '  == NETWORK ==', '    distinct peers: 0', '  == REFUSALS ==', '    distinct: 0'].join('\n');

test('⭑ RED-GREEN: a Linux terminal-rung record NARROWS to {"write":"disk"}', () => {
  // The whole point of the change, asserted on the published VALUE. Before it, this record could not
  // exist: the ladder printed "no droppable terms, so no descent" and `overPredictedBy` stayed empty.
  const r = drv([
    FALSIFIABLE,
    '  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)',
    '  => OVER-PREDICTED by: no-network  (ladder-rung {"write":"disk","network":true}; each named capability drops on its own)',
  ]);
  assert.equal(r.minimality, 'OVER-PREDICTED');
  assert.deepEqual(r.overPredictedBy, ['no-network']);
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { write: 'disk' },
    'the published grant still carries `network`, which an arm proved droppable — the descent was a no-op');
});

test('⭑ RED-GREEN: `no-write-disk` keeps the WIDE grant instead of no-opping into "descended"', () => {
  // ⛔ THE BACKSTOP FOR A FOURTH DRIVER. `descent-terms.mjs` never emits this name, but the recorder
  // must not reward it: `/^no-write-(.+)$/` matches, and the old body then ran `delete
  // descended.write["disk"]` on a STRING — no-op, no collapse, `descendedGrant === grant`, published
  // as `grantSource: "descended"`. That is the exact shape `descent-vocabulary.test.mjs` exists to
  // catch, arriving through a name that happens to match the regex.
  const r = drv([
    FALSIFIABLE,
    '  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)',
    '  => OVER-PREDICTED by: no-write-disk  (ladder-rung {"write":"disk","network":true}; each named capability drops on its own)',
  ]);
  assert.equal(r.grantSource, 'synthesized',
    'a drop that recomputes nothing was published as a descended grant');
  assert.deepEqual(r.grant, { write: 'disk', network: true }, 'the wide grant must be kept');
  assert.ok(r.notes.includes('descent-name-unparsed'),
    'the failed recomputation must be queryable in the record, not just in prose');
  assert.match(r.grantSourceReason, /cannot parse/);
});

test('CONTROL: a real `no-write-<scope>` on an OBJECT write still narrows', () => {
  // Without this, a guard that rejected every `no-write-*` name would satisfy the case above and
  // silently disable the descent's largest term on every confined rung.
  const r = drv([
    FALSIFIABLE,
    '  => MINIMUM {"write":{"userHome":true},"network":true}   (observed, then verified)',
    "     ⛔ OVER-PREDICTED — the strictly narrower {\"network\":true} also verifies; 'no-write-userHome' was not needed",
  ]);
  assert.equal(r.grantSource, 'descended');
  assert.deepEqual(r.grant, { network: true });
});

test('⭑ RED-GREEN: DESCENT UNSUPPORTED records UNPROVEN and its per-axis reason', () => {
  const r = drv([
    FALSIFIABLE,
    '  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)',
    ...verdictLines(TERMINAL, 'win32'),
  ]);
  assert.equal(r.minimality, 'UNPROVEN',
    'a descent that could ask nothing must not read as a proven minimum');
  assert.equal(r.descentUnsupported.platform, 'win32');
  assert.deepEqual(r.descentUnsupported.skipped.map((s) => s.reason),
    ['net-axis-lost-at-full-disk', 'reach-atomic']);
  assert.deepEqual(r.grant, { write: 'disk', network: true }, 'nothing may narrow off an untested axis');
});

test('the UNSUPPORTED marker FAILS CLOSED on a payload it cannot read', () => {
  const r = drv([
    '  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)',
    '  DESCENT-UNSUPPORTED {"platform":"win32","skipped":[]}',
  ]);
  assert.equal(r.descentUnsupported, null, 'an empty skip list is not a reason');
  assert.ok(r.notes.includes('descent-unsupported-marker-unparsable'));
});

// ── 7. THE HALF-WIRED FIELDS REACH THE RECORD ─────────────────────────────────────────────────────

test('⭑ RED-GREEN: `confinedWide` and `descentUnsupported` survive into results.json', () => {
  // ⛔ `rec` IS AN EXPLICIT WHITELIST, so a field added to the parser and not to it is computed on
  // every run and thrown away. `confinedWide` shipped in exactly that state: the wide-but-confined
  // probe ran, printed its marker, was parsed into a field — and vanished, so the one arm that
  // adjudicates the WRITE axis of a `write:"disk"` record left no trace in the corpus at all. Only an
  // end-to-end run of the CLI can see this; every parse-level assertion passed throughout.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'descent-terms-'));
  const log = path.join(dir, 'd.txt');
  fs.writeFileSync(log, [
    '  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)',
    '  CONFINED-WIDE {"result":"pass","platform":"win32","interpretation":"bounded","paths":["C:/Windows/Temp"]}',
    ...verdictLines(TERMINAL, 'win32'),
    '',
  ].join('\n'));
  const r = spawnSync(process.execPath, [path.join(HERE, 'record.mjs'), '--log', log,
    '--pkg', 'p', '--version', '1.0.0', '--out', dir, '--platform', 'win32-x64'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const rec = JSON.parse(fs.readFileSync(path.join(r.stdout.trim(), 'results.json'), 'utf8'));
  fs.rmSync(dir, { recursive: true, force: true });

  assert.equal(rec.confinedWide?.result, 'pass',
    'the wide-but-confined probe was parsed and then dropped from the emitted record');
  assert.equal(rec.confinedWide?.interpretation, 'bounded');
  assert.equal(rec.descentUnsupported?.platform, 'win32');
  assert.equal(rec.minimality, 'UNPROVEN');
});

// ── 8. THE DRIVERS ACTUALLY DELEGATE ──────────────────────────────────────────────────────────────

test('⭑ DRIFT GUARD: all three drivers reach this module, and none rebuilds the vocabulary', () => {
  // ⛔ THE ASSERTION THAT KEEPS THE THREE IN STEP. `descent-vocabulary.test.mjs` used to pin the
  // literal `out.push("no-network")` inside `measure.sh`, which only worked while each driver carried
  // its own copy. Delegation is the stronger property: a driver that stops calling this module cannot
  // be spelling the vocabulary right by accident.
  const DRIVERS = { linux: 'measure.sh', macos: 'measure-macos.sh', windows: 'measure-windows.mjs' };
  for (const [platform, file] of Object.entries(DRIVERS)) {
    const src = fs.readFileSync(path.join(HERE, file), 'utf8');
    assert.match(src, /descent-terms\.mjs/, `${file} no longer reaches the descent vocabulary module`);
    assert.doesNotMatch(src, /Object\.keys\(g0?\.write/,
      `${file} builds write arm names itself again — on a string reach that fabricates digit arms`);
  }
});

test('⭑ DRIFT GUARD: no driver still refuses the terminal rung outright', () => {
  // The excision this change performed, pinned so it cannot come back quietly. The old guard was a
  // `case` on the rung's shape plus the sentence below; either one returning is the regression.
  for (const file of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, file), 'utf8');
    assert.doesNotMatch(src.split('\n').filter((l) => !/^\s*(#|\/\/)/.test(l)).join('\n'),
      /no droppable terms, so no descent/,
      `${file} still refuses to descend write:"disk"`);
  }
  assert.doesNotMatch(fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8'),
    /if \(g\.write !== 'disk'\) descend/, 'the win32 ladder guard is back');
});
