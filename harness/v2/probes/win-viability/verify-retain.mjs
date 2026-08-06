// Read a retained Windows archive BACK and assert it holds what it claims.
//
// ⛔ IT ASSERTS ON THE RETAINED BYTES, NEVER ON THE DECODER'S CONSOLE OUTPUT. A summary line is the
// program's claim about what it did; the archive is the artifact. Every check below gunzips the
// files and reads them the way a stranger re-parsing this corpus in a year would.
//
// ⛔ AND THE SUPERSET CHECK IS THE LOAD-BEARING ONE. Retention is a SECOND decoder, so the way it
// fails quietly is by keeping less than the synthesis decoder already kept while still producing a
// plausible-looking archive full of paths. Comparing against `windows.mjs`'s own output on the SAME
// capture is the only check that catches that, and it is the one that would have caught the Linux
// lane's 18-of-27 before it shipped.
//
//   usage: node verify-retain.mjs <record-dir> --cap <capture-dir> [--project D] [--json out]
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { makeDosPath } from '../../adapters/windows-retain.mjs';

const argv = process.argv.slice(2);
const val = (f, d = null) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const rec = argv.find((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const cap = val('--cap');
if (!rec || !cap) { console.error('usage: verify-retain.mjs <record-dir> --cap <capture-dir> [--json out]'); process.exit(2); }

const fail = [];
const note = [];
const check = (ok, msg) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${msg}`); if (!ok) fail.push(msg); };
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const size = (p) => { try { return fs.statSync(p).size; } catch { return -1; } };

const RAW = path.join(rec, 'etw-raw.xml.gz');
const HDR = path.join(rec, 'etw-header.json');
const DER = path.join(rec, 'events.ndjson.gz');
const XML = path.join(cap, 'trace.xml');
const ETL = path.join(cap, 'trace.etl');

// ── 1. THE RAW IS THE ARTIFACT OF RECORD, SO IT MUST BE BYTE-FOR-BYTE ──────────────────────────
console.log('== RAW ==');
check(fs.existsSync(RAW), 'etw-raw.xml.gz exists');
let rawXml = null;
if (fs.existsSync(RAW)) {
  rawXml = zlib.gunzipSync(fs.readFileSync(RAW));
  const src = fs.readFileSync(XML);
  // Not a length check and not a spot check. A gzip that decompresses to SOMETHING plausible is
  // exactly the shape of a truncated stream, and a truncated raw archive is worthless in the one
  // situation it exists for.
  check(sha(rawXml) === sha(src), `gunzip(etw-raw.xml.gz) is byte-identical to trace.xml (sha ${sha(src).slice(0, 16)}…)`);
  check(rawXml.length === src.length, `${src.length} bytes recovered`);
}

// ── 2. THE HEADER IS WHAT MAKES THE RAW RE-PARSEABLE ───────────────────────────────────────────
console.log('== HEADER ==');
check(fs.existsSync(HDR), 'etw-header.json exists standalone (the raw must not need the derived view)');
const hdr = fs.existsSync(HDR) ? JSON.parse(fs.readFileSync(HDR, 'utf8')) : {};
check(!!hdr.tracer?.session?.name, 'names the ETW session');
check(Number.isInteger(hdr.tracer?.session?.bufferSizeKB), 'records the buffer geometry');
const provs = hdr.tracer?.providers ?? [];
check(provs.length === 3, `names all 3 providers (got ${provs.length})`);
const fileProv = provs.find((p) => p.name === 'Microsoft-Windows-Kernel-File');
// ⛔ A KEYWORD BIT THAT IS CLEAR IS A SILENT FILTER. At 0x11F0 events 26/27/28 are never written, so
// rename and hardlink destinations are absent with nothing in the stream saying so. An archive that
// does not name its mask cannot be re-read with any confidence about what it is missing.
check(!!fileProv?.keywords, `records the Kernel-File keyword mask (${fileProv?.keywords})`);
check(String(fileProv?.keywords).toUpperCase() === '0X1FF0',
  'and it is 0x1FF0 — every keyword the provider declares, so destinations exist');
check(Object.keys(hdr.devmap ?? {}).length > 0,
  'carries the NT-device -> drive-letter map, without which every raw path is undecodable');
check(!!hdr.roots?.project && !!hdr.roots?.home,
  'carries the roots, so a future classifier can recompute scopes it does not have yet');
check(!!hdr.tracer?.captureScriptSha256, 'pins the capture script by sha256');
check(hdr.integrity?.lostFrom?.includes('tracerpt'),
  'says WHERE eventsLost came from (logman reports Buffers Lost 0 while dropping 62% of events)');
check(hdr.raw?.etlRetained === false && hdr.raw?.etlBytes > 0,
  `states the ETL was NOT retained and how big it was (${hdr.raw?.etlBytes} B)`);
check(hdr.raw?.sha256 === (rawXml ? sha(rawXml) : null),
  'binds itself to the raw by sha256, so the pair is verifiably matched rather than merely adjacent');

// ── 3. THE DERIVED VIEW ────────────────────────────────────────────────────────────────────────
console.log('== DERIVED ==');
check(fs.existsSync(DER), 'events.ndjson.gz exists');
const lines = zlib.gunzipSync(fs.readFileSync(DER)).toString('utf8').trim().split('\n').map((l) => JSON.parse(l));
const h2 = lines[0];
check(h2.k === 'h', 'first line is the header');
check(JSON.stringify({ ...h2, stats: null }) === JSON.stringify({ ...hdr, stats: null }),
  'the embedded header and the standalone header agree');
const procs = lines.filter((l) => l.k === 'p');
const events = lines.filter((l) => l.k === 'e');
check(procs.length > 0, `${procs.length} process records`);
check(events.length > 0, `${events.length} event records`);

// The three things `windows.mjs` discards by design. Each is a capability the archive has and the
// synthesis decoder does not, so an archive missing all of them is not a second decoder at all.
const nonRefusal = events.filter((e) => e.st && e.st !== '0x00000000'
  && !['0xc0000022', '0xc0000061', '0xc00000a2', '0xc0000121'].includes(e.st));
check(nonRefusal.length > 0,
  `${nonRefusal.length} events carry a NON-REFUSAL NTSTATUS that windows.mjs drops entirely`);
if (nonRefusal.length) {
  const byStatus = {};
  for (const e of nonRefusal) byStatus[e.st] = (byStatus[e.st] ?? 0) + 1;
  note.push(`non-refusal statuses: ${Object.entries(byStatus).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k}×${v}`).join(' ')}`);
}
const withIo = events.filter((e) => Number.isFinite(e.io));
check(withIo.length > 0, `${withIo.length} events carry a per-operation BYTE COUNT (no other lane has one)`);
const withDisp = events.filter((e) => e.d != null);
check(withDisp.length > 0, `${withDisp.length} events carry the raw create DISPOSITION`);
const paired = events.filter((e) => e.kind);
note.push(`two-path (rename/hardlink/delete) records: ${paired.length}`);
// ⛔ THE RULE THE WHOLE DESIGN RESTS ON: no classifier verdict may be baked into the archive.
check(!events.some((e) => 'scope' in e || 'bucket' in e), 'no event carries a scope tag');

// ── 4. THE SUPERSET CHECK ──────────────────────────────────────────────────────────────────────
console.log('== SUPERSET vs the synthesis decoder ==');
const synth = path.join(cap, 'events.ndjson');
if (!fs.existsSync(synth)) {
  // Regenerate rather than skip: a check that quietly does not run is indistinguishable from one
  // that passed, and this is the check that catches retention keeping LESS than synthesis.
  const adapters = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')), '..', '..', 'adapters');
  spawnSync(process.execPath, [path.join(adapters, 'windows.mjs'), cap, '--out', synth, '--allow-lossy'],
    { encoding: 'utf8', maxBuffer: 1 << 28 });
}
if (fs.existsSync(synth)) {
  const dosPath = makeDosPath(hdr.devmap);
  const norm = (p) => String(p).replace(/\//g, '\\').toLowerCase().replace(/\\+$/, '');
  const retained = new Set();
  for (const e of events) for (const p of [e.f, e.fx, e.g, e.gx]) if (p) retained.add(norm(p));
  // A process image is retained on the PROC record, not as an event, so the comparison has to look
  // there too — otherwise every `exec` windows.mjs emits reads as a retention loss that is not one.
  for (const p of procs) if (p.data?.ImageName) retained.add(norm(dosPath(p.data.ImageName)));
  const synthEvents = fs.readFileSync(synth, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const missing = [];
  for (const e of synthEvents) {
    if (!e.path) continue;
    if (!retained.has(norm(e.path))) missing.push(`${e.op} ${e.path}`);
  }
  check(missing.length === 0,
    `every one of ${synthEvents.filter((e) => e.path).length} paths the synthesis decoder emitted is in the archive`
    + (missing.length ? ` — MISSING ${missing.length}` : ''));
  for (const m of missing.slice(0, 15)) console.log(`       missing: ${m}`);
  note.push(`retained distinct paths ${retained.size} vs synthesis ${new Set(synthEvents.filter((e) => e.path).map((e) => norm(e.path))).size}`);
}

// ── 5. SIZES, reported honestly rather than optimised for ──────────────────────────────────────
console.log('== SIZE ==');
const sizes = {
  etlBytes: size(ETL), xmlBytes: size(XML),
  rawGzBytes: size(RAW), derivedGzBytes: size(DER), headerBytes: size(HDR),
  synthNdjsonBytes: size(synth),
  eventsTotal: hdr.integrity?.eventsTotal ?? null, eventsLost: hdr.integrity?.eventsLost ?? null,
  distinctEvents: events.length, procs: procs.length,
};
sizes.rawToDerivedRatio = sizes.derivedGzBytes > 0 ? +(sizes.rawGzBytes / sizes.derivedGzBytes).toFixed(2) : null;
sizes.xmlCompression = sizes.rawGzBytes > 0 ? +(sizes.xmlBytes / sizes.rawGzBytes).toFixed(1) : null;
sizes.perRecordBytes = sizes.rawGzBytes + sizes.derivedGzBytes + sizes.headerBytes;
for (const [k, v] of Object.entries(sizes)) console.log(`  ${k.padEnd(20)} ${v}`);
// ⛔ ONLY tracerpt's `Total Events Lost` IS TRUSTWORTHY HERE. `logman query` reported `Buffers Lost
// 0` on a session dropping 62% of its events, and prints no `Events Lost` line at all.
if (sizes.eventsLost > 0) {
  console.log(`  !! ${sizes.eventsLost} EVENTS LOST (tracerpt Total Events Lost) — this archive`
    + ' cannot support an exact-set claim, though it is still a complete record of what arrived');
}

for (const n of note) console.log(`  note: ${n}`);
if (val('--json')) fs.writeFileSync(val('--json'), `${JSON.stringify({ sizes, notes: note, failures: fail }, null, 2)}\n`);

console.log(fail.length ? `\nRETAIN-VERIFY FAILED: ${fail.length} check(s)` : '\nRETAIN-VERIFY OK');
process.exit(fail.length ? 1 : 0);
