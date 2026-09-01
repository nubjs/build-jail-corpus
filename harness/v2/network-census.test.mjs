// The attributed NETWORK census, and the withhold-only term it drives in `applyGrantSourceRule`.
//
// ⛔ WHAT THIS GUARDS IS AN UNDER-GRANT — the one direction this project forbids. `artifact-gate.mjs`
// walks the package's own directory and counts what is there, so it cannot tell a fetch that NEVER
// HAPPENED from one a WARM CACHE made unnecessary: both leave every artefact present and `rc=0`. The
// per-arm store eviction does not close it either — it clears `pm/store`, while nub redirects a
// confined script's downloads at `pm/tools/{electron-cache,ms-playwright}` and grants those leaves
// unconditionally, so they outlive every arm.
//
//   node --test harness/v2/network-census.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  NET_CLEAR, NET_REFUSE, NET_UNKNOWN, networkDropVerdict, networkPeers,
} from './network-census.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;

// ── the fixture ───────────────────────────────────────────────────────────────────────────────────
//
// A ONE-capability descent dropping `no-network` off a `{write:{project},network}` synthesis — the
// shape of every record this term exists for. `write` deliberately carries no `userHome`, so the
// sibling home-write term cannot fire and every outcome below is attributable to this one.
const LOG = ({
  net = ['    AF_INET connects: 2   distinct peers: 2',
    '        185.199.108.133:443', '        172.182.252.133:443'],
  census = true, witness = null, drop = 'no-network',
  synth = '{"write":{"project":true},"network":true}',
  narrowed = '{"write":{"project":true}}',
} = {}) => [
  '  ARM-FALSIFIABILITY {"manifestFiles":8,"filesTheScriptProduced":3,"reasons":[],"declaresInstallWork":true}',
  '  == WRITES ==',
  '    jailTmp       3',
  '  == READS ==',
  '    deps          1',
  ...(census ? ['  == NETWORK ==', ...net] : []),
  '  == REFUSALS (errno EPERM/EACCES/EROFS only; ENOENT is a miss, not a denial) ==',
  '    distinct: 0',
  '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
  `    ${synth}`,
  `  VERIFY[synth] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant=${synth}`,
  `  => MINIMUM ${synth}   (observed, then verified)`,
  ...(witness ? [`  DENIAL-WITNESS {"cap":"${drop}","verdict":"${witness}"}`] : []),
  `  VERIFY[nar-${drop}] rc=0 artifacts=8/8 missing=0 shortfall=none (tree 10/10) OVERRIDDEN=2 REJECTED=0 grant=${narrowed}`,
  `  => OVER-PREDICTED by: ${drop}  (synthesized ${synth}; each named capability drops on its own)`,
].join('\n');

// ── the census reader ─────────────────────────────────────────────────────────────────────────────

test('CONTROL: the reader answers three real corpus lines whose values are known independently', () => {
  // One per platform, copied from committed logs and checked by eye first. A reader that got any of
  // these wrong would make every conclusion below unfounded — and the darwin/linux pair is the whole
  // point, because they share no leading token.
  assert.equal(networkPeers('  == NETWORK ==\n    AF_INET connects: 2   distinct peers: 2\n  == REFUSALS =='), 2,
    'darwin: `AF_INET connects:` — electron-chromedriver@33.4.9');
  assert.equal(networkPeers('  == NETWORK ==\n    AF_INET sockets: 0   distinct peers: 0\n  == REFUSALS =='), 0,
    'linux: `AF_INET sockets:` — @antv/g-base@0.1.0-beta.1');
  assert.equal(networkPeers('  == NETWORK ==\n    distinct peers: 0\n  == REFUSALS =='), 0,
    'win32: the bare row — @apollo/protobufjs@1.2.7');
});

test('⭑ the reader keys on `distinct peers`, the ONLY spelling common to all three platforms', () => {
  // ⛔ `AF_INET connects:` IS DARWIN-ONLY. MEASURED over the 6,887 committed records: 1,912 logs
  // carry it and every one is darwin, while `distinct peers:` appears on 1,912 darwin + 2,059 linux
  // + 1,688 win32. Keying on the leading token returns 181 records where the true answer is 951 — a
  // 5.2x undercount that reads as a clean single-platform finding. This test is what makes that
  // mistake fail here instead of in a conclusion.
  for (const row of ['    AF_INET connects: 3   distinct peers: 3',
    '    AF_INET sockets: 0   distinct peers: 3',
    '    distinct peers: 3',
    // The live linux classifier's newer form, which no committed log carries yet: the ATTRIBUTED
    // count first, the whole-tree count after. The reader must take the first.
    '    AF_INET sockets: 1   distinct peers: 3  /  whole traced tree 9']) {
    assert.equal(networkPeers(`  == NETWORK ==\n${row}\n  == REFUSALS ==`), 3, row);
  }
});

test('⭑ the PEER count is read, never the socket count', () => {
  // ⛔ THE TWO ARE POPULATED FROM DIFFERENT EVENTS AND THEY DISAGREE. MEASURED: 510 of the 2,059
  // committed linux logs print an attributed `AF_INET sockets: 0` beside a positive peer count,
  // against 0 of 1,912 darwin. Reading the socket field would score a run that reached two hosts as
  // having reached none — a false CLEAR, in the under-grant direction.
  assert.equal(networkPeers('  == NETWORK ==\n    AF_INET sockets: 0   distinct peers: 2\n  == REFUSALS =='), 2);
});

test('⭑ an ABSENT block is null, and so is a PRESENT block with no peers row', () => {
  // ⛔ THE SECOND HALF IS WHERE THIS DIFFERS FROM THE WRITE CENSUS, DELIBERATELY. There a missing
  // bucket inside a present block means "no members", because the drivers omit an empty bucket. Here
  // the row is the only thing the block carries, so its absence means the block was not understood —
  // and guessing zero would be a false CLEAR.
  assert.equal(networkPeers('  => MINIMUM {}\n'), null);
  assert.equal(networkPeers('  == NETWORK ==\n    (tracer unavailable)\n  == REFUSALS =='), null);
});

test('a raw log, a line array, and a win32 CRLF log all read identically', () => {
  const rows = ['  == NETWORK ==', '    distinct peers: 4', '  == REFUSALS =='];
  assert.equal(networkPeers(rows.join('\n')), 4);
  assert.equal(networkPeers(rows), 4);
  assert.equal(networkPeers(rows.join('\r\n')), 4);
});

test('the block is closed by the next section, so a later arm cannot reopen it', () => {
  // A descent arm's own echoed output sits behind `    | `, which `^\s*==` cannot get past.
  assert.equal(networkPeers([
    '  == NETWORK ==', '    distinct peers: 2', '  == REFUSALS ==', '    | == NETWORK ==',
    '    |     distinct peers: 0',
  ]), 2);
});

// ── the verdict ───────────────────────────────────────────────────────────────────────────────────

test('⭑ a POSITIVE peer count with no CLEAN witness REFUSES the drop', () => {
  const v = networkDropVerdict({ log: '  == NETWORK ==\n    distinct peers: 2\n  == REFUSALS ==', witness: null });
  assert.equal(v.verdict, NET_REFUSE);
  assert.equal(v.peers, 2);
  assert.match(v.reason, /WARM CACHE/);
});

test('⛔ RED CONTROL: a census that ran and found NO peer clears the drop', () => {
  // The one thing that licenses a narrowing on this axis without a witness, and the reason the term
  // is not simply "always refuse a network drop".
  const v = networkDropVerdict({ log: '  == NETWORK ==\n    distinct peers: 0\n  == REFUSALS ==', witness: null });
  assert.equal(v.verdict, NET_CLEAR);
});

test('⛔ RED CONTROL: a CLEAN denial witness clears a POSITIVE peer count', () => {
  // A live jailed trace of the DROP ARM outranks a count taken on the observe arm: it is a statement
  // about the run whose greenness is in question.
  const v = networkDropVerdict({ log: '  == NETWORK ==\n    distinct peers: 9\n  == REFUSALS ==', witness: 'CLEAN' });
  assert.equal(v.verdict, NET_CLEAR);
});

test('⭑ only CLEAN clears — WITNESSED, VOID, UNSUPPORTED and absent license nothing', () => {
  for (const witness of ['WITNESSED', 'VOID', 'UNSUPPORTED', null, undefined]) {
    const v = networkDropVerdict({ log: '  == NETWORK ==\n    distinct peers: 1\n  == REFUSALS ==', witness });
    assert.equal(v.verdict, NET_REFUSE, `witness=${witness} must not license the drop`);
  }
});

test('⭑ an absent census is UNKNOWN, never CLEAR', () => {
  const v = networkDropVerdict({ log: '  => MINIMUM {}', witness: null });
  assert.equal(v.verdict, NET_UNKNOWN);
  assert.equal(v.peers, null);
});

test('⭑ a CLEAN witness outranks an ABSENT census, not only a positive one', () => {
  // ⛔ ORDER MATTERS ONLY FOR A FAIL-CLOSED CALLER, WHICH IS WHY THE WRITE CENSUS GETS AWAY WITH THE
  // OPPOSITE ORDER. There `CENSUS_UNKNOWN` is let through, so a null census never reached the witness
  // branch and never needed to. Here UNKNOWN REFUSES — so testing the census first would throw away a
  // live jailed trace of the drop arm, which is strictly stronger evidence than any observe-arm count.
  const v = networkDropVerdict({ log: '  => MINIMUM {}', witness: 'CLEAN' });
  assert.equal(v.verdict, NET_CLEAR);
  assert.equal(v.peers, null);
  assert.match(v.reason, /DENIAL-WITNESS CLEAN/);
});

// ── the term in `record.mjs` ──────────────────────────────────────────────────────────────────────

test('⭑ a descent that drops `network` over a positive peer count keeps the WIDER grant', () => {
  const r = parseDriverLog(LOG());
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.equal(r.grant.network, true, 'the withheld record must keep the network the descent removed');
  assert.ok(r.notes.includes('network-attributed'), `notes were ${JSON.stringify(r.notes)}`);
  assert.match(r.grantSourceReason, /attributed 2 network peer\(s\)/);
});

test('⛔ RED CONTROL: the same descent with a ZERO peer count still narrows', () => {
  // Without this the test above proves only that the term fires, not that it discriminates — a term
  // that refused every network drop would pass it and be worthless.
  const r = parseDriverLog(LOG({ net: ['    AF_INET connects: 0   distinct peers: 0'] }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.equal(r.grant.network, undefined);
});

test('⛔ RED CONTROL: a CLEAN denial witness on the dropped capability still narrows', () => {
  const r = parseDriverLog(LOG({ witness: 'CLEAN' }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.equal(r.grant.network, undefined);
});

test('⭑ FAILS CLOSED: a descent that drops `network` with NO census is refused', () => {
  // ⛔ WHERE THIS DEPARTS FROM THE HOME-WRITE TERM, WHICH LETS AN ABSENT CENSUS THROUGH. 1,228
  // committed records carry no `== NETWORK` block at all; reading "the question was never asked" as
  // "the answer was no" is exactly the under-grant this term exists to stop. It costs nothing today —
  // MEASURED, all 212 records that actually drop `network` carry a census, so this arm refuses none
  // of them and is here for the log that stops printing one.
  const r = parseDriverLog(LOG({ census: false }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.equal(r.grant.network, true);
  assert.ok(r.notes.includes('network-census-absent'), `notes were ${JSON.stringify(r.notes)}`);
  assert.match(r.grantSourceReason, /carries no `== NETWORK` census/);
});

test('⛔ RED CONTROL: a descent that drops something ELSE is untouched', () => {
  const r = parseDriverLog(LOG({
    drop: 'no-write-project',
    synth: '{"write":{"project":true},"network":true}',
    narrowed: '{"network":true}',
  }));
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.deepEqual(r.grant, { network: true });
});

test('⛔ RED CONTROL: naming `no-network` over a grant that never had it withholds nothing', () => {
  // ⛔ THE QUESTION IS ASKED OF THE TWO GRANTS, NOT OF `overPredictedBy`, AND THIS IS THE ONLY TEST
  // THAT CAN TELL THE TWO APART. MEASURED over the committed corpus: 559 records name `no-network`
  // and only 212 actually lose the capability — a ladder rung names the arm over a grant that never
  // carried network, where deleting it is a no-op. A term keyed on the arm NAME would refuse those
  // 347 records for a narrowing that happened on some other axis entirely.
  const synth = '{"write":{"project":true}}';
  const r = parseDriverLog(LOG({ synth, narrowed: synth }));
  assert.deepEqual(r.overPredictedBy, ['no-network'], 'CONTROL: the arm really is named in the record');
  assert.equal(r.grantSource, 'descended', r.grantSourceReason);
  assert.equal(r.notes.includes('network-attributed'), false, `notes were ${JSON.stringify(r.notes)}`);
});

test('⭑ a NON-BOOLEAN network grant is still a network grant', () => {
  // ⛔ ASKED FOR TRUTHINESS, NOT FOR `=== true`, AND THE WRITE AXIS SHOWS WHY. `write` is already the
  // bare string `"disk"` on the terminal ladder rung, and `record.mjs` carries a scar where a
  // `no-write-*` name against that string form recomputed a no-op and published it as `descended`.
  // MEASURED, `grant.network` is only ever `true` (2,767) or absent (4,120) across the 6,887
  // committed records — so this pins the shape a future reach could take before it can make the
  // largest possible drop read as no drop at all.
  const r = parseDriverLog(LOG({ synth: '{"write":{"project":true},"network":"egress"}' }));
  assert.equal(r.grantSource, 'synthesized', r.grantSourceReason);
  assert.equal(r.grant.network, 'egress');
});

test('⭑ the term is WITHHOLD-ONLY: it can never turn a wide record into a narrow one', () => {
  // The asymmetry the whole file rests on. Over every shape the fixture can take, the patched grant
  // is either the descended one or the strictly wider synthesized one — never anything else.
  for (const o of [{}, { census: false }, { witness: 'CLEAN' }, { witness: 'WITNESSED' },
    { net: ['    distinct peers: 0'] }, { net: ['    distinct peers: 7'] }]) {
    const r = parseDriverLog(LOG(o));
    const wide = JSON.stringify({ write: { project: true }, network: true });
    const narrow = JSON.stringify({ write: { project: true } });
    assert.ok([wide, narrow].includes(JSON.stringify(r.grant)),
      `${JSON.stringify(o)} produced a third grant: ${JSON.stringify(r.grant)}`);
  }
});

// ── authoring-time guards ─────────────────────────────────────────────────────────────────────────

test('⭑ all three classifiers emit a census header and a peers row this module matches', () => {
  // ⛔ THE TERM FAILS CLOSED, so a driver that stopped printing the block would not silently disarm
  // it — it would refuse every network drop instead. That is the safe direction but a bad one to
  // discover from a corpus, so the fourth driver, or a reworded header, fails HERE.
  for (const f of ['observe.mjs', 'observe-macos.mjs', 'classify.mjs']) {
    const src = fs.readFileSync(path.join(HERE, f), 'utf8').split('\n');
    const header = src.filter((l) => /console\.log\('== NETWORK/.test(l));
    assert.equal(header.length, 1, `${f} does not print exactly one == NETWORK header`);
    const row = src.filter((l) => /console\.log\(`.*distinct peers:/.test(l));
    assert.equal(row.length, 1, `${f} does not print exactly one peers row`);
    // Render the template with a known count and read it back through the real parser.
    const rendered = /console\.log\(`([^`]+)`\)/.exec(row[0])[1].replace(/\$\{[^}]+\}/g, '5');
    assert.equal(networkPeers(`== NETWORK ==\n  ${rendered}\n== REFUSALS ==`), 5,
      `${f} prints a peers row this module's reader does not recognise: ${rendered}`);
  }
});

test('⭑ the census is a LEAF — it imports nothing, so it cannot close a cycle', () => {
  // ⛔ `stale-adjudication.mjs` imports `parseDriverLog` from `record.mjs`, and `record.mjs` imports
  // this file. An import back up would close a cycle, and a cycle here does NOT throw: these are
  // `const` exports, so the importer silently receives `undefined` and the guard is disarmed with no
  // error anywhere. Same rule, same reason, as `write-census.mjs` and `tool-cache-leaves.mjs`.
  const src = fs.readFileSync(path.join(HERE, 'network-census.mjs'), 'utf8');
  assert.doesNotMatch(src, /^\s*import\s/m, 'network-census.mjs must import nothing');
});

test('⭑ `record.mjs` carries no second copy of the census parser', () => {
  // Scans CODE, not prose: `record.mjs` legitimately discusses the census at length in the comment
  // on the term, and a raw line scan would flag the documentation of the rule as a violation of it.
  const code = fs.readFileSync(path.join(HERE, 'record.mjs'), 'utf8').split('\n')
    .filter((l) => !/^(\/\/|\*|\/\*)/.test(l.trimStart())).join('\n');
  assert.doesNotMatch(code, /distinct peers/, 'record.mjs parses the peers row itself');
});
