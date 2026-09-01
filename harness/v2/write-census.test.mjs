// The REAL-home write census, and the withhold-only term it drives in `applyGrantSourceRule`.
//
// ⛔ WHAT THIS GUARDS IS AN UNDER-GRANT — the one direction this project forbids. `artifact-gate.mjs`
// only ever walks the package's OWN directory, so a home write is by construction outside everything
// it can see; a browser downloader therefore passes its `no-write-userHome` drop arm with the browser
// missing. `redArmLicenses` cannot close it: a red SIBLING arm proves the jail → denial → rc chain
// fires SOMEWHERE, never that it fires on the home write.
//
//   node --test harness/v2/write-census.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  CENSUS_CLEAR, CENSUS_REFUSE, CENSUS_UNKNOWN, homeDropVerdict, homeWriteCensus, homeWrites,
} from './write-census.mjs';
import { homeWrites as reExported } from './stale-adjudication.mjs';
import { parseDriverLog } from './record.mjs';
import { TOOL_CACHE_LEAVES, toolCacheRw } from './tool-cache-leaves.mjs';

const HERE = import.meta.dirname;

// ── the fixture ───────────────────────────────────────────────────────────────────────────────────
//
// A one-capability descent that drops `no-write-userHome` off a `{write:{project,userHome},network}`
// synthesis — the shape of every record this term exists for. Two licences are offered separately so
// each can be shown to be insufficient on its own: `redArm` is the `arms-unfalsifiable` + red-sibling
// shape the committed corpus is full of, and the default is an ordinarily falsifiable record that
// needs no licence at all.
const LOG = ({ writes = ['    jailTmp       3'], redArm = false, witness = null, census = true } = {}) => [
  `  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":3,"reasons":${redArm ? '["gate-vacuous"]' : '[]'},"declaresInstallWork":true}`,
  ...(redArm ? ['  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:'] : []),
  ...(census ? ['  == WRITES ==', ...writes] : []),
  '  == READS ==',
  '    deps          1',
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  '    {"write":{"project":true,"userHome":true},"network":true}',
  '  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true},"network":true}',
  '  => MINIMUM {"write":{"project":true,"userHome":true},"network":true}   (observed, then verified)',
  ...(redArm ? [
    '  VERIFY[nar-no-network] rc=1 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true,"userHome":true}}',
    "     'no-network' is NECESSARY — dropping it fails to verify",
  ] : []),
  ...(witness ? [`  DENIAL-WITNESS {"cap":"no-write-userHome","verdict":"${witness}"}`] : []),
  '  VERIFY[nar-no-write-userHome] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant={"write":{"project":true},"network":true}',
  '  => OVER-PREDICTED by: no-write-userHome  (synthesized {"write":{"project":true,"userHome":true},"network":true}; each named capability drops on its own)',
].join('\n');

const home = (g) => !!g?.write && (typeof g.write === 'string' || !!g.write.userHome);

// ── the census reader ─────────────────────────────────────────────────────────────────────────────

test('CONTROL: the reader answers the two cases whose real values are known independently', () => {
  // Both counts are read off the committed corpus: `@playwright/browser-chromium@1.61.1` (win32,
  // bare header) 629 and `playwright-chromium@1.9.2` (linux, long header) 1185. A reader that got
  // either of these wrong would make every conclusion below unfounded.
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n    jailTmp       8\n  == READS =='), 629);
  assert.equal(homeWrites([
    '  == WRITES the script actually performed ==',
    // ⛔ A SUFFIXED SIBLING ROW, WHICH IS WHAT THE DARWIN CLASSIFIER REALLY EMITS. `BASE_COVERED` is
    // `ownPkg jailHome jailTmp toolsRw` — `userHome` is not in it and never carries the note, so this
    // pins that a suffixed NEIGHBOUR does not derail the block rather than a suffix on the row read.
    '    jailHome      1  (base profile already grants this — NOT billed)',
    '    userHome   1185',
    '  == READS ==',
  ]), 1185);
});

test('⭑ a WRITES block with no `userHome` row is ZERO; an absent block is UNKNOWN', () => {
  // ⛔ THE DISTINCTION IS THE WHOLE GATE. The drivers omit a bucket with no members, so a block
  // without the row is a script that never touched the real home — the SAFE case, and the one a
  // "no row means unknown" reading would fence off.
  assert.equal(homeWrites('  == WRITES ==\n    systemfs      1\n    jailTmp    1070\n  == READS =='), 0);
  assert.equal(homeWrites('  => MINIMUM {}\n'), null);
});

test('a raw log and an already-split line array read identically, including a win32 CRLF log', () => {
  // `record.mjs` holds `lines` (echoed output already dropped); `stale-adjudication.mjs` holds the
  // archived string. Both must reach the same number or the two callers are reading different logs.
  const raw = '  == WRITES ==\r\n    userHome    629\r\n  == READS ==\r\n    userHome  40000\r\n';
  assert.equal(homeWrites(raw), 629);
  assert.equal(homeWrites(raw.split('\n')), 629, 'record.mjs splits on \\n alone, so rows keep a trailing \\r');
});

test('the census stops at the next section, so READS cannot be billed as WRITES', () => {
  // Every driver prints a `userHome` row under READS too, routinely two orders of magnitude larger.
  assert.equal(homeWrites('  == WRITES ==\n    jailTmp 3\n  == READS ==\n    userHome    661\n'), 0);
});

// ── the classifier ────────────────────────────────────────────────────────────────────────────────

test('⭑ only positive evidence clears a home drop, and there are exactly two kinds of it', () => {
  const withHome = '  == WRITES ==\n    userHome    629\n  == READS ==';
  assert.equal(homeDropVerdict({ log: withHome, witness: null }).verdict, CENSUS_REFUSE);
  assert.equal(homeDropVerdict({ log: withHome, witness: 'CLEAN' }).verdict, CENSUS_CLEAR);
  // Everything that is not the word CLEAN is "not established" and clears nothing.
  for (const w of ['WITNESSED', 'VOID', 'UNSUPPORTED', undefined]) {
    assert.equal(homeDropVerdict({ log: withHome, witness: w }).verdict, CENSUS_REFUSE, `witness ${w} cleared a home drop`);
  }
  assert.equal(homeDropVerdict({ log: '  == WRITES ==\n    jailTmp 3\n  == READS ==', witness: null }).verdict, CENSUS_CLEAR);
  assert.equal(homeDropVerdict({ log: '  => MINIMUM {}', witness: null }).verdict, CENSUS_UNKNOWN);
});

// ── the term inside `applyGrantSourceRule` ────────────────────────────────────────────────────────

test('⭑ a positive real-home census WITHHOLDS the narrowing a red sibling arm would have licensed', () => {
  // ⛔ THE MEASURED CASE. `playwright-chromium@1.9.2` (linux) attributed 1185 real-home writes and
  // still dropped `write.userHome`; `@playwright/browser-chromium@1.61.1` (win32) 629. Both carry a
  // red sibling arm on `network`, which is what `redArmLicenses` reads as a positive control — and
  // it is a control for the EXIT CODE, not for the home write the artifact gate never looks at.
  const r = parseDriverLog(LOG({ writes: ['    userHome   1185'], redArm: true }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.equal(home(r.grant), true, 'the grant lost the home the script demonstrably wrote to');
  assert.match(r.grantSourceReason, /attributed 1185 write\(s\) to the REAL home/);
  assert.ok(r.notes.includes('home-write-attributed'), 'the withholding must be queryable in the record, not just in prose');
  // The narrowing it refused is still recorded, so the delta is auditable rather than invisible.
  assert.equal(home(r.descendedGrant), false);
});

test('⭑ the same shape without `arms-unfalsifiable` is withheld too — the term is not a falsifiability rider', () => {
  // An ordinarily falsifiable record needs no licence at all and reaches `n === 1` directly, so a
  // term written into the falsifiability branch would miss it entirely.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'] }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.ok(r.notes.includes('home-write-attributed'));
});

test('⛔ RED CONTROL: a census attributing NO real-home write still narrows', () => {
  // Without this the assertions above could be produced by a term that refuses every home drop, which
  // would make the whole descent inert on this capability.
  for (const redArm of [true, false]) {
    const r = parseDriverLog(LOG({ redArm }));
    assert.equal(r.grantSource, 'descended', `redArm=${redArm}: ${r.grantSourceReason}`);
    assert.equal(home(r.grant), false);
    assert.ok(!r.notes.includes('home-write-attributed'));
  }
});

test('⛔ RED CONTROL: a CLEAN denial witness narrows over a positive census', () => {
  // The witness scores the DROP ARM's own jailed trace, so it outranks the observe arm's count.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'], witness: 'CLEAN' }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.equal(home(r.grant), false);
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('⭑ WITHHOLD-ONLY: a record the chain already kept wide keeps its own, better reason', () => {
  // ⛔ THE TERM IS AN OVERRIDE ON `source === 'descended'`, NOT A BRANCH IN THE CHAIN, and this is
  // what that buys. A two-capability leave-one-out record already reaches the wider grant for a more
  // complete reason — nothing proves the two drop TOGETHER — and as a branch this term fired first
  // and replaced that sentence on records whose grant does not change at all.
  const log = LOG({ writes: ['    userHome    629'] })
    .replace('=> OVER-PREDICTED by: no-write-userHome ', '=> OVER-PREDICTED by: no-network no-write-userHome ');
  const r = parseDriverLog(log);
  assert.deepEqual(r.overPredictedBy, ['no-network', 'no-write-userHome']);
  assert.equal(r.grantSource, 'synthesized');
  assert.match(r.grantSourceReason, /leave-one-out/);
  assert.ok(!r.notes.includes('home-write-attributed'), 'the census overrode a withholding it did not cause');
});

test('⭑ WITNESSED keeps outranking this term, and owns the reason when both apply', () => {
  // ⛔ A WITNESSED refusal is direct evidence the script ASKED and the jail REFUSED — strictly
  // stronger than a count of what it wrote unjailed. Reordering these two branches would replace the
  // better finding with the weaker one in the record.
  const r = parseDriverLog(LOG({ writes: ['    userHome    629'], witness: 'WITNESSED' }));
  assert.equal(r.grantSource, 'synthesized');
  assert.ok(r.notes.includes('denial-witnessed'), r.grantSourceReason);
  assert.ok(!r.notes.includes('home-write-attributed'));
  assert.match(r.grantSourceReason, /ATTEMPTED a write inside no-write-userHome/);
});

test('⭑ an absent census does NOT fire the term, which is the documented policy and not an oversight', () => {
  // ⛔ THE CENSUS IS AN OBSERVE PRODUCT, and this file's settled policy for an absent OBSERVE product
  // is `observedCounts`': absence vetoes nothing, so every existing record keeps the behaviour it was
  // measured under. The absence case is covered elsewhere instead — by the driver-parity assertion
  // below at authoring time, and by `stale-adjudication.mjs`'s G3 for an archived log.
  const r = parseDriverLog(LOG({ census: false }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('⭑ the term is keyed on the GRANT, not on the arm name', () => {
  // A descent can name `no-write-userHome` over a grant that never carried the home — deleting it is
  // then a no-op and there is nothing to withhold. Keying on `overPredictedBy` would withhold a
  // narrowing that does not touch the home at all.
  const log = LOG({ writes: ['    userHome    629'] })
    .replace(/\{"write":\{"project":true,"userHome":true\},"network":true\}/g, '{"write":{"project":true},"network":true}');
  const r = parseDriverLog(log);
  assert.equal(home(r.synthesized), false, 'the fixture must present a grant without the home');
  assert.ok(!r.notes.includes('home-write-attributed'));
});

test('an ECHOED census line cannot open a block, so echoed output cannot forge an acquittal', () => {
  // ⛔ THE DEFENCE IS THE HEADER REGEX, NOT THE ECHO FILTER, and saying so is the point of this test:
  // `^\s*==` cannot get past the `|`, so the census is safe on the raw log too. An UNPREFIXED second
  // block DOES win, which is the honest limit — the census is printed by the OBSERVE classifier and
  // a later descent arm's package output is the only thing that could sit after it.
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n    | == WRITES ==\n    |     jailTmp 1\n  == READS =='), 629);
  assert.equal(homeWrites('  == WRITES ==\n    userHome    629\n  == WRITES ==\n    jailTmp 1\n  == READS =='), 0);
});

// ── ONE implementation, two readers ───────────────────────────────────────────────────────────────

test('⭑ `stale-adjudication.mjs` re-exports this census rather than carrying a second copy', () => {
  // ⛔ THE DEFECT CLASS THIS PROJECT HAS PAID FOR FIVE TIMES: a soundness guard wired into one reader
  // and not the other. Identity, not equivalence — two functions that agree today are exactly the
  // pair that drifts.
  assert.equal(reExported, homeWrites);
});

test('⭑ neither reader defines a census of its own', () => {
  // Scans CODE, not prose: both files legitimately discuss `== WRITES` in their comments, and a raw
  // line scan would flag the documentation of the rule as a violation of it.
  const code = (f) => fs.readFileSync(path.join(HERE, f), 'utf8').split('\n')
    .filter((l) => !/^(\/\/|\*|\/\*)/.test(l.trimStart())).join('\n');
  const CENSUS_REGEX = /==\\s\*?WRITES|\[A-Za-z\]\[A-Za-z0-9\]\*/;
  assert.match(code('write-census.mjs'), CENSUS_REGEX, 'CONTROL: the scan cannot see the census it is looking for');
  for (const f of ['record.mjs', 'stale-adjudication.mjs']) {
    assert.doesNotMatch(code(f), CENSUS_REGEX, `${f} carries its own copy of the census parser`);
  }
});

test('⭑ all three classifiers emit a census header this module matches', () => {
  // ⛔ THIS IS WHAT BACKS THE DECISION TO LET AN ABSENT CENSUS PASS. The term is scoped to a POSITIVE
  // count, so a driver that stopped printing the block would silently disarm it in `record.mjs`.
  // Asserted at authoring time instead, the same shape `three-driver-parity.test.mjs` uses: a fourth
  // driver, or a reworded header, fails here rather than in a record nobody re-reads.
  for (const f of ['observe.mjs', 'observe-macos.mjs', 'classify.mjs']) {
    const emitted = fs.readFileSync(path.join(HERE, f), 'utf8')
      .split('\n').filter((l) => /console\.log\('== WRITES/.test(l));
    assert.equal(emitted.length, 1, `${f} does not print exactly one == WRITES header`);
    const header = /console\.log\('([^']+)'\)/.exec(emitted[0])[1];
    assert.equal(homeWrites(`${header}\n    userHome    7\n  == READS ==`), 7,
                 `${f} prints a header this module's reader does not recognise: ${header}`);
  }
});

// ── the FREE-DIRECTORY subtraction ────────────────────────────────────────────────────────────────
//
// ⛔ THE DEFECT THESE COVER, AND IT IS AN OVER-REFUSAL RATHER THAN THE UNDER-GRANT ABOVE. The
// three-leaf tool-cache carve-out landed in the POSIX classifiers on 2026-08-31 (`0492dce58`);
// before it they carved out `npm-prefix` alone, so an `electron-cache` write — into a directory nub
// creates, redirects the package at, and `push_rw_path`s read-write — was billed to `userHome`. An
// archived `driver.out` is frozen at the classifier that wrote it, so no forward fix reaches those
// records and the gate must read the paths rather than the count.
//
// MEASURED over the committed archive, split on that commit: 72 pre-era records (28 darwin, 44
// linux) carry a positive `userHome` census whose EVERY listed path is a tool-cache leaf, against 0
// post-era; and 20 post-era records carry a `toolsRw` bucket against 0 pre-era. A clean cut in both
// directions, which is what makes this an era effect rather than a live classifier bug.

/** A POSIX driver log with a ROOTS echo, a `userHome` census and the feasibility listing behind it.
 *  Indentation is the drivers' real indentation — the feasibility block is closed by INDENT, not by
 *  the next `==` header, because what follows it in a real log is `EVICT[…]` at the outer level. */
const POSIX_LOG = ({
  home = '/Users/runner',
  toolsDir = '/Users/runner/.cache/nub/pm/tools',
  userHome = 3,
  outside = 0,
  paths = [
    '.cache/nub/pm/tools/electron-cache',
    '.cache/nub/pm/tools/electron-cache/4b092cc6/electron-v33.4.11-darwin-arm64.zip',
    '.cache/nub/pm/tools/electron-cache/4b092cc6',
  ],
  count = null,
  more = 0,
  feasibility = true,
} = {}) => [
  '  == ROOTS (from capture.json — R2: no ambient reads) ==',
  `    project       ${home}/v2m-xARqly/Observe`,
  `    home          ${home}`,
  `    jailHome      ${home}/v2m-xARqly/jailhome`,
  `    globalStore   ${home}/.cache/nub/pm/store   [declared, not keyed on]`,
  `    toolsDir      ${toolsDir === null ? '(null)' : toolsDir}`,
  `    npmPrefix     ${toolsDir === null ? '(null)' : `${toolsDir}/npm-prefix`}`,
  '  == WRITES the script actually performed ==',
  '    jailTmp       4  (base profile already grants this — NOT billed)',
  `    userHome  ${String(userHome).padStart(5)}`,
  ...(outside ? [`    outside   ${String(outside).padStart(5)}`] : []),
  '  == READS ==',
  '    deps          1',
  ...(feasibility ? [
    '  == writePaths FEASIBILITY (distinct writes outside project/deps) ==',
    `    count: ${count ?? paths.length + more}`,
    ...paths.map((p) => `        ${p}`),
    ...(more ? [`      … and ${more} more`] : []),
  ] : []),
  '  EVICT[synth] 52 store entries removed, 3 spared as nub tooling, 301 in store',
].join('\n');

test('⭑ CONTROL: the two archived shapes whose answers were checked by hand first', () => {
  // ⛔ BOTH READ OFF THE COMMITTED CORPUS BEFORE THIS CODE EXISTED, which is what makes them a
  // control rather than a restatement of the implementation. `electron@33.4.11` (darwin) attributed
  // 3 real-home writes and its feasibility block lists exactly three `electron-cache` paths;
  // `@mui+x-telemetry@9.10.0` (linux) attributed 2 and lists `.config/mui-x{,/config.json}`.
  const free = homeWriteCensus(POSIX_LOG());
  assert.deepEqual({ total: free.total, free: free.free, billable: free.billable, basis: free.basis },
                   { total: 3, free: 3, billable: 0, basis: 'paths' });

  const real = homeWriteCensus(POSIX_LOG({
    home: '/home/runner',
    toolsDir: '/home/runner/.cache/nub/pm/tools',
    userHome: 2,
    paths: ['.config/mui-x', '.config/mui-x/config.json'],
  }));
  assert.deepEqual({ total: real.total, free: real.free, billable: real.billable, basis: real.basis },
                   { total: 2, free: 0, billable: 2, basis: 'paths' });
});

test('⭑ a census whose every path is a tool-cache leaf CLEARS the drop, and says which leaves', () => {
  const v = homeDropVerdict({ log: POSIX_LOG(), witness: null });
  assert.equal(v.verdict, CENSUS_CLEAR, v.reason);
  assert.equal(v.homeWrites, 3, 'the RAW row stays raw — a reader must find the same number in driver.out');
  assert.equal(v.billableHomeWrites, 0);
  assert.match(v.reason, /places all 3 of them inside nub's tool-cache read-write leaves/);
  // ⛔ A DISTINCT SENTENCE FROM "attributed no write to the REAL home". Collapsing the two would hide
  // the only fact a reviewer needs to re-check the subtraction.
  assert.doesNotMatch(v.reason, /attributed no write/);
});

test('⛔ RED CONTROL: one non-tool path among the free ones is enough to REFUSE', () => {
  // Without this the clear above could be produced by a rule that subtracts every listed path.
  const v = homeDropVerdict({
    log: POSIX_LOG({
      userHome: 4,
      paths: [
        '.cache/nub/pm/tools/electron-cache',
        '.cache/nub/pm/tools/electron-cache/zip',
        '.cache/nub/pm/tools/ms-playwright',
        '.ssh/authorized_keys',
      ],
    }),
    witness: null,
  });
  assert.equal(v.verdict, CENSUS_REFUSE, v.reason);
  assert.equal(v.billableHomeWrites, 1);
  assert.match(v.reason, /3 of them inside nub's tool-cache leaves and 1 not/);
});

test('⛔ RED CONTROL: `tools` ITSELF is not a leaf, and neither is a sibling under it', () => {
  // ⛔ SECURITY BOUNDARY, NOT TIDINESS. `tools` also holds the node-gyp bootstraps nub executes on
  // every later install, so a subtraction spanning the directory would clear a package that
  // overwrote one — persistence, dressed as a build need.
  for (const p of ['.cache/nub/pm/tools', '.cache/nub/pm/tools/node-gyp/bin/node-gyp.js',
                   '.cache/nub/pm/tools/electron-cache-evil']) {
    const c = homeWriteCensus(POSIX_LOG({ userHome: 1, paths: [p] }));
    assert.equal(c.billable, 1, `${p} was subtracted as if it were a granted leaf`);
  }
  // CONTROL: the leaf itself and a file inside it DO subtract, or the loop above proves nothing.
  for (const p of ['.cache/nub/pm/tools/electron-cache', '.cache/nub/pm/tools/npm-prefix/bin/x']) {
    assert.equal(homeWriteCensus(POSIX_LOG({ userHome: 1, paths: [p] })).billable, 0, p);
  }
});

test('⭑ every condition on the subtraction fails CLOSED, back to the raw count', () => {
  // ⛔ EACH CASE IS A WAY THE SUBTRACTION COULD BE WRONG, and the safe answer to every one of them is
  // the number the gate used before this code existed. Subtracting a write the package needed is an
  // UNDER-GRANT; failing to subtract a free one costs a narrowing and nothing else.
  //
  // ⛔ EACH CASE ALSO PINS THE REASON, NOT ONLY THE VERDICT, AND THAT IS NOT DECORATION — a mutation
  // test is what put it there. The conditions overlap: on an honest log a truncated listing also
  // fails the relative/absolute split, so DELETING the truncation check leaves the verdict correct
  // and only the reason wrong. Asserting the verdict alone let that mutation live.
  const cases = {
    'no feasibility block at all (every win32 record)': [POSIX_LOG({ feasibility: false }), /lists no `writePaths FEASIBILITY`/],
    'the listing is truncated past the printer\'s 40-entry cap': [POSIX_LOG({ userHome: 303, more: 300 }), /TRUNCATED \(3 shown of 303\)/],
    'the listing does not reconcile with the userHome row': [POSIX_LOG({ userHome: 9 }), /3 home-relative, 0 absolute.*userHome 9 \+ outside 0/],
    'an `outside` row the listing does not account for': [POSIX_LOG({ outside: 2 }), /3 home-relative, 0 absolute.*userHome 3 \+ outside 2/],
    'the tool cache is not under the declared home': [POSIX_LOG({ toolsDir: '/opt/nub/pm/tools' }), /does not sit under the declared home/],
    'no toolsDir root is echoed at all': [POSIX_LOG({ toolsDir: null }), /echoes no `home`\/`toolsDir` root pair/],
  };
  for (const [why, [log, reason]] of Object.entries(cases)) {
    const c = homeWriteCensus(log);
    assert.equal(c.basis, 'count-only', `${why}: the subtraction ran anyway`);
    assert.equal(c.billable, c.total, `${why}: a write was subtracted on evidence that does not hold`);
    assert.equal(homeDropVerdict({ log, witness: null }).verdict, CENSUS_REFUSE, why);
    assert.match(c.why ?? '', reason, `${why}: the recorded reason names a different condition`);
  }
});

test('⛔ a win32-shaped absolute path in the listing FAILS the split rather than reading as relative', () => {
  // The printer relativizes an entry exactly when it is under `home`, so the non-absolute entries
  // must number `userHome` and the absolute ones `outside`. `classify.mjs` prints no listing today;
  // this is what stops one appearing later and being read one bucket wrong.
  const c = homeWriteCensus(POSIX_LOG({ userHome: 2, outside: 1, paths: ['.config/x', '/tmp/y', 'C:\\Users\\r\\z'] }));
  assert.equal(c.basis, 'count-only');
  assert.equal(c.billable, 2);
});

test('⛔ an `outside` write that DOES reconcile is not mistaken for a free home write', () => {
  // outside 1 + userHome 1, listing of 2 with one absolute: the split reconciles, so the subtraction
  // runs — and it must consider only the home-relative entry.
  const c = homeWriteCensus(POSIX_LOG({
    userHome: 1, outside: 1, paths: ['.cache/nub/pm/tools/electron-cache/z', '/tmp/hsperfdata_runner'],
  }));
  assert.deepEqual({ basis: c.basis, total: c.total, free: c.free, billable: c.billable },
                   { basis: 'paths', total: 1, free: 1, billable: 0 });
});

test('⭑ END TO END: the record narrows on a tool-cache-only census and is withheld on a real one', () => {
  // ⛔ THROUGH `parseDriverLog`, not through the classifier alone: the term lives in
  // `applyGrantSourceRule`, and a subtraction that never reaches it changes no record.
  const descent = LOG({ writes: ['    userHome      3'] });
  const roots = POSIX_LOG().split('\n').slice(0, 7).join('\n');
  const feas = POSIX_LOG().split('\n').slice(-6, -1).join('\n');   // the header, `count:` and 3 paths

  const freeRec = parseDriverLog([roots, descent, feas].join('\n'));
  assert.equal(freeRec.grantSource, 'descended', freeRec.grantSourceReason);
  assert.equal(home(freeRec.grant), false, 'a home the script never needed was kept anyway');
  assert.ok(!freeRec.notes.includes('home-write-attributed'));

  const realFeas = feas.replace(/\.cache\/nub\/pm\/tools\/electron-cache/g, '.config/mui-x');
  const realRec = parseDriverLog([roots, descent, realFeas].join('\n'));
  assert.equal(realRec.grantSource, 'synthesized', realRec.grantSourceReason);
  assert.equal(home(realRec.grant), true, 'the grant lost the home the script demonstrably wrote to');
  assert.ok(realRec.notes.includes('home-write-attributed'));
});

// ── ONE list of leaves, three readers ─────────────────────────────────────────────────────────────

test('⭑ the leaf list is shared, and neither classifier carries a literal copy of it', () => {
  // ⛔ THE DEFECT CLASS, IN ITS ORIGINAL FORM. The list grew from one leaf to three on 2026-08-31 and
  // both copies had to be edited together. They were — but a third reader arrived later, and two
  // array literals plus a third would have been the fifth recurrence of the guard-in-one-driver bug
  // `three-driver-parity.test.mjs` exists for.
  const code = (f) => fs.readFileSync(path.join(HERE, f), 'utf8').split('\n')
    .filter((l) => !/^(\/\/|\*|\/\*)/.test(l.trimStart())).join('\n');
  const LITERAL = /\[\s*'npm-prefix'\s*,/;
  assert.match(code('tool-cache-leaves.mjs'), /'npm-prefix', 'ms-playwright', 'electron-cache'/,
               'CONTROL: the scan cannot see the list it is looking for');
  for (const f of ['observe.mjs', 'observe-macos.mjs', 'write-census.mjs']) {
    assert.doesNotMatch(code(f), LITERAL, `${f} carries its own copy of the tool-cache leaf list`);
  }
});

test('⭑ the hoist is a NO-OP: `toolCacheRw` reproduces the expression both classifiers carried', () => {
  // ⛔ THIS IS WHAT SAYS THE CHANGE DOES NOT MOVE A MEASUREMENT. The old expression is copied here
  // verbatim; over every root pair the committed captures actually declare, the two agree. Run
  // against all 5,742 committed `capture.json` files at authoring time: 0 differences, and
  // `toolsDir` is null in 0 of them while `npmPrefix` is null in 1,688 (every win32 capture).
  const OLD = (toolsDir, npmPrefix) => [
    ...(toolsDir ? ['npm-prefix', 'ms-playwright', 'electron-cache'].map((l) => `${toolsDir}/${l}`) : []),
    ...(npmPrefix ? [npmPrefix] : []),
  ];
  const venues = [
    ['/Users/runner/.cache/nub/pm/tools', '/Users/runner/.cache/nub/pm/tools/npm-prefix'],  // darwin
    ['/home/runner/.cache/nub/pm/tools', '/home/runner/.cache/nub/pm/tools/npm-prefix'],    // linux
    ['C:\\Users\\runneradmin\\AppData\\Local\\nub\\pm\\tools', null],                       // win32
    [null, null], [null, '/x/npm-prefix'],                                                  // the latent branches
  ];
  for (const [toolsDir, npmPrefix] of venues) {
    assert.deepEqual(toolCacheRw({ toolsDir, npmPrefix }), OLD(toolsDir, npmPrefix), `${toolsDir} / ${npmPrefix}`);
  }
  // CONTROL: the comparison can fail, or the loop above is vacuous.
  assert.notDeepEqual(toolCacheRw({ toolsDir: '/x' }), OLD('/y', null));
});

test('⭑ the leaves are exactly the three `preset.rs` push_rw_paths, in one place', () => {
  assert.deepEqual(TOOL_CACHE_LEAVES, ['npm-prefix', 'ms-playwright', 'electron-cache']);
});
