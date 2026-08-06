// KNOWN-ANSWER FIXTURE, assertion half: hold the normalized event stream against ground truth the
// fixture CONTROLS, and report what the tracer lost.
//
// ⛔ THIS ASSERTS AGAINST THE ADAPTER'S OUTPUT, NOT AGAINST THE CLASSIFIER'S. The question is whether
// CAPTURE is complete; attribution and scope assignment are downstream of that and cannot repair it.
// The known Windows defect (allTreePeers 0 on a package with real egress) was a capture defect that
// every parser-level assertion in the repo passed straight over.
//
// ⛔ AND IT ASSERTS A COUNT, NOT JUST PRESENCE. A presence check cannot see a tracer that drops 30%
// of events -- N uniquely-named storm files can. That is the assertion the macOS lane never had, and
// its absence is why a 100%-loss defect lived in that adapter for its whole life.
//
//   usage: node kaf-assert.mjs <events.ndjson> <kaf-expect.json> <capture-dir> [--json out.json]
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const jsonOut = (() => { const i = args.indexOf('--json'); return i >= 0 ? args[i + 1] : null; })();
const [evPath, expectPath, capDir] = args.filter((a) => !a.startsWith('--') && a !== jsonOut);
if (!evPath || !expectPath || !capDir) {
  console.error('usage: kaf-assert.mjs <events.ndjson> <kaf-expect.json> <capture-dir> [--json out]');
  process.exit(2);
}

const meta = JSON.parse(fs.readFileSync(path.join(capDir, 'meta.json'), 'utf8'));
const exp = JSON.parse(fs.readFileSync(expectPath, 'utf8'));
const events = fs.readFileSync(evPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

// Windows is case-insensitive and the kernel emits a directory both with and without its trailing
// separator. Fold both here, exactly as classify.mjs rule 1 does, so a spelling difference is never
// mistaken for a missing event.
const norm = (p) => {
  let s = String(p).replace(/\//g, '\\');
  if (s.length > 3 && s.endsWith('\\')) s = s.slice(0, -1);
  return s.toLowerCase();
};

const writes = new Set(), reads = new Set(), denied = new Set();
for (const e of events) {
  if (!e.path || e.op === 'exec' || e.op === 'connect') continue;
  const p = norm(e.path);
  if (e.result === 'denied') { denied.add(`${e.op} ${p}`); continue; }
  (e.op === 'write' ? writes : reads).add(p);
}

const results = [];
const add = (id, pass, detail) => { results.push({ id, pass, detail }); };

// ── the named shapes ──────────────────────────────────────────────────────────────────────────
// A `write` expectation is satisfied ONLY by a write. Seeing the path as a read instead is the
// under-report that matters, so it is called out by name rather than folded into a bare FAIL.
const byShape = new Map();
for (const e of exp.expect) {
  const p = norm(e.path);
  const sawWrite = writes.has(p), sawRead = reads.has(p);
  const ok = e.op === 'write' ? sawWrite : (sawRead && !sawWrite);
  const how = e.op === 'write'
    ? (sawWrite ? 'reported as write' : sawRead ? '⛔ REPORTED AS READ ONLY -- the write was LOST' : '⛔ ABSENT ENTIRELY')
    : (sawWrite ? '⛔ a read was reported as a WRITE (over-report)' : sawRead ? 'reported as read' : '⛔ ABSENT ENTIRELY');
  const rec = { shape: e.shape, expected: e.op, path: e.path, ok, how };
  (byShape.get(e.shape) ?? byShape.set(e.shape, []).get(e.shape)).push(rec);
}

// ── the storm count: the assertion that catches partial loss ──────────────────────────────────
const stormSeen = exp.stormPaths.filter((p) => writes.has(norm(p)));
const stormMissing = exp.stormPaths.filter((p) => !writes.has(norm(p)));
add('COUNT', stormSeen.length === exp.storm,
  `${stormSeen.length}/${exp.storm} storm writes reported (${stormMissing.length} missing)`);

// ── the decoy: absence must be a statement about the tracer ───────────────────────────────────
const decoyHits = [...writes, ...reads].filter((p) => p.includes('never-touched'));
add('DECOY', decoyHits.length === 0, `${decoyHits.length} hits on the never-touched decoy`);

// ── the alternate data stream: reported, never gated ──────────────────────────────────────────
const adsHits = [...writes, ...reads].filter((p) => p.includes('kaf-ads-host') && p.includes(':kafstream'));
const adsHostHits = [...writes].filter((p) => p.includes('kaf-ads-host'));

// ── capture integrity ─────────────────────────────────────────────────────────────────────────
add('LOSS', meta.eventsLost === 0, `eventsLost=${meta.eventsLost} eventsTotal=${meta.eventsTotal}`);

// ── report ────────────────────────────────────────────────────────────────────────────────────
console.log(`capture: user ${meta.whoami} elevated ${meta.elevated} exit ${meta.exitCode} ` +
  `events ${meta.eventsTotal} LOST ${meta.eventsLost}`);
console.log(`stream:  ${events.length} normalized events  (${writes.size} distinct writes, ${reads.size} distinct reads)\n`);

console.log('== SHAPE COVERAGE — what the tracer reported, against ground truth it did not choose ==');
let shapeFail = 0;
for (const [shape, recs] of byShape) {
  for (const r of recs) {
    if (!r.ok) shapeFail++;
    console.log(`  [${r.ok ? 'PASS' : 'FAIL'}] ${shape.padEnd(9)} expect ${r.expected.padEnd(5)} ${r.how}`);
    if (!r.ok) console.log(`           ${r.path}`);
  }
}

console.log('\n== INTEGRITY ==');
for (const r of results) console.log(`  [${r.pass ? 'PASS' : 'FAIL'}] ${r.id.padEnd(6)} ${r.detail}`);
console.log(`\n== ALTERNATE DATA STREAM (reported, not gated) ==`);
console.log(`  stream path seen: ${adsHits.length ? adsHits.join(', ') : 'NO'}`);
console.log(`  host file seen as a write: ${adsHostHits.length ? 'yes' : 'no'}`);

if (stormMissing.length) {
  console.log(`\n== STORM MISSES (first 10 of ${stormMissing.length}) ==`);
  stormMissing.slice(0, 10).forEach((p) => console.log(`      ${p}`));
}

const failed = shapeFail + results.filter((r) => !r.pass).length;
const report = {
  eventsTotal: meta.eventsTotal, eventsLost: meta.eventsLost,
  normalized: events.length, distinctWrites: writes.size, distinctReads: reads.size,
  stormExpected: exp.storm, stormSeen: stormSeen.length, stormMissing: stormMissing.length,
  decoyHits: decoyHits.length, adsSeen: adsHits.length > 0,
  shapes: [...byShape].map(([shape, recs]) => ({ shape, recs })),
  integrity: results, failed,
};
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2));

console.log(`\n${failed === 0 ? 'KAF PASSED' : `KAF FAILED (${failed})`}`);
// ⛔ EXIT 0 REGARDLESS. This is a VIABILITY PROBE: a failing shape is the FINDING, not an error, and
// a non-zero exit would stop the workflow before the real-package measurements that follow.
process.exit(0);
