// Screen the QUEUE against OSV before any runner fetches anything, and take flagged rows out of
// circulation permanently.
//
// ⛔ WHY THIS EXISTS ALONGSIDE THE IN-RUN SCREEN, WHICH IS NOT REDUNDANT WITH IT.
//
// `search.mjs` already screens the whole INSTALLED TREE after an `--ignore-scripts` discovery
// install and before a single script executes, which is what keeps malicious CODE from running.
// That screen is the load-bearing one and this does not replace it: only the resolved tree reveals a
// compromised TRANSITIVE dependency, and the tree is not known until resolution.
//
// What this adds is earlier and narrower: a package OSV already flags by NAME AND VERSION should
// never be fetched onto a machine at all, and with 6,750 queue rows about to be installed on GitHub
// runners, "fetched but not executed" is a worse default than "never requested". It also stops the
// corpus spending a runner slot on a row whose only possible outcome is a refusal.
//
// FAILS CLOSED, like the in-run screen. A pre-screen that silently passes when it could not reach
// OSV would hand the queue a clean bill of health it never earned — and an all-clear from an
// instrument that was never shown to alarm is worth nothing, which is why `--self-test` exists.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);

const KNOWN = new Set(['--queue', '--self-test', '--dry-run']);
const unknown = argv.filter((a, i) => a.startsWith('--') && !KNOWN.has(a)
  && !(i > 0 && KNOWN.has(argv[i - 1])));
if (unknown.length) {
  console.error(`PRESCREEN REFUSED: unknown flag(s): ${unknown.join(', ')}`);
  console.error(`  known flags: ${[...KNOWN].join(', ')}`);
  process.exit(2);
}

const QUEUE = opt('--queue', path.join(here, '..', 'queue.ndjson'));
const DRY = argv.includes('--dry-run');

/** Batch-query OSV. Chunked at 500 because `querybatch` caps a request at ~1000 and returns SHORT
 *  rather than erroring — the per-chunk length check is what turns that into a refusal instead of a
 *  silent partial screen. Body goes over stdin: a large batch is hundreds of KB and argv has its own
 *  ceiling. */
function osvMalicious(specs) {
  const queries = specs.map((sp) => {
    const at = sp.lastIndexOf('@');
    const name = at > 0 ? sp.slice(0, at) : sp;
    const version = at > 0 ? sp.slice(at + 1) : undefined;
    return version
      ? { package: { name, ecosystem: 'npm' }, version }
      : { package: { name, ecosystem: 'npm' } };
  });
  const CHUNK = 500;
  const results = [];
  for (let i = 0; i < queries.length; i += CHUNK) {
    const slice = queries.slice(i, i + CHUNK);
    const r = spawnSync('curl', ['-sS', '--max-time', '120', '-X', 'POST',
      'https://api.osv.dev/v1/querybatch', '-H', 'Content-Type: application/json',
      '--data-binary', '@-'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, input: JSON.stringify({ queries: slice }) });
    if (r.status !== 0) {
      throw new Error(`OSV pre-screen FAILED (curl ${r.status}): ${(r.stderr || '').slice(0, 200)}`);
    }
    let parsed;
    try { parsed = JSON.parse(r.stdout); } catch (e) {
      throw new Error(`OSV pre-screen FAILED to parse: ${e.message}`);
    }
    const got = parsed.results ?? [];
    if (got.length !== slice.length) {
      throw new Error(`OSV pre-screen returned ${got.length} results for ${slice.length} queries `
        + `(chunk ${i / CHUNK} of ${Math.ceil(queries.length / CHUNK)}) — refusing a partial screen`);
    }
    results.push(...got);
  }
  const flagged = new Map();
  results.forEach((res, i) => {
    const ids = (res.vulns ?? []).map((v) => v.id ?? '').filter((id) => id.startsWith('MAL-'));
    if (ids.length) flagged.set(specs[i], ids);
  });
  return flagged;
}

/** Build the distinct spec list, REFUSING any row that does not carry the keys this screen reads.
 *
 *  ⛔ THIS IS THE FAIL-OPEN THIS SCREEN IS MOST EXPOSED TO, and it was live: a row keyed `package`
 *  instead of `pkg` yields the string `undefined@<version>`, OSV answers "no advisory" for a package
 *  that does not exist, and the screen prints `PRESCREEN: ok` having queried nothing at all. Every
 *  other refusal here is loud; this one is silent and lands on the safe-looking side.
 *
 *  So an unreadable row is a REFUSAL, never a skip and never a coerced string. The error names the
 *  keys the row DOES carry, because the whole failure mode is a near-miss key.
 *
 *  Note what is deliberately NOT checked: that the distinct-spec count equals the row count. The
 *  queue holds each package-version once per OS, so N < rows is the normal, correct shape — a
 *  count-equality guard would fire on every real queue. */
function specsFromRows(rows) {
  const bad = [];
  for (const [i, r] of rows.entries()) {
    const ok = (v) => typeof v === 'string' && v.length > 0;
    if (!ok(r?.pkg) || !ok(r?.version)) bad.push(`  row ${i}: keys [${Object.keys(r ?? {}).join(', ')}]`);
  }
  if (bad.length) {
    throw new Error(`${bad.length} of ${rows.length} queue row(s) lack a usable \`pkg\`/\`version\` — `
      + `refusing, because such a row screens as \`undefined@<version>\` and passes vacuously:\n`
      + `${bad.slice(0, 5).join('\n')}${bad.length > 5 ? `\n  … and ${bad.length - 5} more` : ''}`);
  }
  return [...new Set(rows.map((r) => `${r.pkg}@${r.version}`))];
}

// ⛔ PROVE THE INSTRUMENT CAN ALARM BEFORE BELIEVING ITS ALL-CLEAR. @ctrl/tinycolor@4.1.2 is a real
// Shai-Hulud compromise carrying MAL-2025-47141. If this stops firing, OSV's schema or the MAL-
// prefix convention has moved and every "clean" verdict below is meaningless.
if (argv.includes('--self-test')) {
  const known = '@ctrl/tinycolor@4.1.2';
  const clean = 'lodash@4.17.21';
  const got = osvMalicious([known, clean]);
  const alarmed = got.has(known);
  const quiet = !got.has(clean);
  console.log(`  ${known.padEnd(26)} -> ${alarmed ? `FLAGGED ${got.get(known).join(',')}` : 'NOT FLAGGED'}`);
  console.log(`  ${clean.padEnd(26)} -> ${quiet ? 'clean' : `FLAGGED ${got.get(clean).join(',')}`}`);

  // ⛔ SECOND CONTROL: THE KNOWN POSITIVE, BURIED MID-BATCH AT FULL CHUNK SIZE.
  //
  // The small-batch test above proves the screen can alarm. It does NOT prove the screen still
  // alarms at the size it actually runs at, nor that a hit is attributed to the RIGHT package.
  // Results come back as a positional array, so a chunk boundary or a silent truncation misaligns
  // every index after it — and a misaligned hit does not look like an error, it looks like a
  // DIFFERENT package being flagged. That is worse than a miss: it would pull an innocent package
  // out of the corpus while leaving the malicious one in.
  //
  // The per-chunk length check already refuses a SHORT batch. This covers the other half: right
  // length, wrong order.
  const CHUNK_SIZE = 500;
  const padded = Array.from({ length: CHUNK_SIZE }, (_, i) => `nub-osv-control-filler-${i}@1.0.0`);
  const at = Math.floor(CHUNK_SIZE / 2);
  padded[at] = known;
  const bulk = osvMalicious(padded);
  const foundInBulk = bulk.has(known);
  const noFalsePositives = [...bulk.keys()].every((k) => k === known);
  console.log(`  ${known} at index ${at} of a ${CHUNK_SIZE}-query batch -> ${foundInBulk ? 'FOUND' : 'LOST'}`);
  console.log(`  filler packages flagged: ${[...bulk.keys()].filter((k) => k !== known).length} (want 0)`);

  // ⛔ THIRD CONTROL: THE SHAPE GUARD REFUSES A WRONG-KEY ROW.
  //
  // The two controls above prove the screen can alarm on a package it was ASKED about. This one
  // proves it cannot be talked out of asking. A wrong-key queue passed vacuously for a full day
  // while reporting `ok`, so the guard against it is worth no more than its own proof that it fires.
  let rejectsWrongKey = false;
  try { specsFromRows([{ package: '@ctrl/tinycolor', version: '4.1.2' }]); } catch { rejectsWrongKey = true; }
  let acceptsRightKey = false;
  try {
    acceptsRightKey = specsFromRows([{ pkg: 'lodash', version: '4.17.21' }])[0] === 'lodash@4.17.21';
  } catch { /* stays false */ }
  console.log(`  wrong-key row (\`package\`) -> ${rejectsWrongKey ? 'REFUSED' : 'ACCEPTED — fails open!'}`);
  console.log(`  right-key row (\`pkg\`)     -> ${acceptsRightKey ? 'accepted, spec correct' : 'MISREAD'}`);

  if (alarmed && quiet && foundInBulk && noFalsePositives && rejectsWrongKey && acceptsRightKey) {
    console.log('SELF-TEST: ok — the screen alarms on a known-malicious version, stays quiet on a clean one, '
      + 'still finds the positive at the correct index in a full-size batch, and refuses a queue row it '
      + 'cannot read rather than screening it vacuously');
    process.exit(0);
  }
  console.error('SELF-TEST FAILED: the screen cannot be trusted to alarm, so its all-clears are worthless.');
  if (!foundInBulk) console.error('  the positive was LOST in a full-size batch — results are truncated or misaligned.');
  if (!noFalsePositives) console.error('  a filler package was flagged — results are misaligned, so hits name the WRONG package.');
  if (!rejectsWrongKey) console.error('  a wrong-key row was ACCEPTED — such a queue screens as undefined@<v> and passes vacuously.');
  if (!acceptsRightKey) console.error('  a well-formed row was misread — the guard is rejecting valid queues.');
  process.exit(1);
}

const rows = fs.readFileSync(QUEUE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
// One query per DISTINCT package-version; the queue holds each one once per OS.
let specs;
try {
  specs = specsFromRows(rows);
} catch (e) {
  console.error(`PRESCREEN REFUSED: ${e.message}`);
  process.exit(2);
}
console.error(`screening ${specs.length} distinct package-version(s) from ${rows.length} queue row(s)`);

const flagged = osvMalicious(specs);
if (flagged.size === 0) {
  console.log(`PRESCREEN: ok — no MAL-* advisory covers any of the ${specs.length} package-versions in the queue`);
  process.exit(0);
}

let marked = 0;
for (const r of rows) {
  const ids = flagged.get(`${r.pkg}@${r.version}`);
  if (!ids) continue;
  // Terminal, and deliberately NOT `pending`: a flagged row must never be claimable again, and
  // `--reclaim-stale` must never resurrect it.
  r.status = 'refused-malicious';
  r.maliciousAdvisories = ids;
  delete r.run;
  delete r.claimedAt;
  marked++;
}

console.error(`\nFLAGGED ${flagged.size} package-version(s), covering ${marked} queue row(s):`);
for (const [spec, ids] of flagged) console.error(`  ${spec}  ${ids.join(', ')}`);

if (DRY) { console.error('\n--dry-run: queue NOT modified'); process.exit(0); }
fs.writeFileSync(QUEUE, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
console.error(`\nqueue updated: ${marked} row(s) marked refused-malicious and removed from circulation`);
