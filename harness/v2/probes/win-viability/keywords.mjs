// Decode the ETW keyword mask `windows.ps1` enables against the provider's OWN manifest, and say
// which of the event IDs the parser switches on can actually be delivered under it.
//
// ⛔ THIS EXISTS BECAUSE A KEYWORD MASK IS A SILENT FILTER. `logman update trace -p <provider> <mask>`
// succeeds whatever the mask is: an event whose keyword bit is clear is simply never written, with no
// error anywhere. So a parser can carry a correct handler for event 16 forever and never see one, and
// the resulting trace looks healthy -- `EventsLost 0`, thousands of events, a plausible path set.
// The undercount direction is an UNDER-GRANT, which is the direction that breaks installs.
//
// Input is `wevtutil gp <provider> /ge:true` text, which lists every keyword with its value and
// every event with the keyword mask it is published under. Nothing here is guessed from a name.
//
// ⛔ TWO FORMAT FACTS, BOTH MEASURED AFTER A FIRST VERSION OF THIS PARSER READ ZERO OF EACH:
//   1. `mask:` is BARE HEX with no `0x` prefix -- `mask: 1000` is 0x1000, not decimal 1000.
//      Reading it as decimal is silent and produces a plausible-looking wrong answer.
//   2. `wevtutil gp` WITHOUT `/ge:true` emits no `events:` block at all. The `tasks:` block is
//      still there and gives id -> name, so the ids are recoverable, but the per-event keyword
//      mapping -- the thing that actually decides delivery -- is not.
//
//   usage: node keywords.mjs <wevtutil-dump.txt> <mask-hex> [--events 12,15,16,...]
import fs from 'node:fs';

const [dumpPath, maskHex] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const evArg = (() => { const i = process.argv.indexOf('--events'); return i >= 0 ? process.argv[i + 1] : ''; })();
if (!dumpPath || !maskHex) { console.error('usage: keywords.mjs <dump.txt> <mask-hex> [--events a,b,c]'); process.exit(2); }

const text = fs.readFileSync(dumpPath, 'utf8');
const MASK = BigInt(maskHex);
// A `mask:`/`keywords:` value in this dump is bare hex. Normalise both spellings so a future dump
// that DOES carry `0x` is read the same way rather than becoming a second silent failure mode.
const hex = (s) => BigInt(/^0x/i.test(s) ? s : `0x${s}`);

// `wevtutil gp` emits an indentation-structured listing. Two blocks matter and they are parsed
// independently rather than with one clever regex, because their shapes differ:
//
//   keywords:
//     keyword:
//       name: KERNEL_FILE_KEYWORD_FILENAME
//       mask: 0x10
//   events:
//     event:
//       value: 12
//       ...
//       keywords: 0x80
// Each block is parsed by splitting on its own record separator (`  keyword:`, `  task:`,
// `  event:`) rather than by slicing the file on block headers. A header slice was the first
// version and it is brittle in exactly the way that produces a confident empty answer.
const recs = (label) => text.split(new RegExp(`^\\s*${label}:\\s*$`, 'm')).slice(1);

const keywords = [];
for (const chunk of recs('keyword')) {
  const n = /\bname:\s*(\S+)/.exec(chunk);
  const m = /\bmask:\s*([0-9a-fA-Fx]+)/.exec(chunk);
  if (n && m) keywords.push({ name: n[1], mask: hex(m[1]) });
}

// `tasks:` gives id -> name and is present even without `/ge:true`. It does NOT give the keyword
// mapping, so on its own it can say what an id IS but never whether it can be delivered.
const tasks = new Map();
for (const chunk of recs('task')) {
  const n = /\bname:\s*(\S+)/.exec(chunk);
  const v = /\bvalue:\s*(\d+)/.exec(chunk);
  if (n && v) tasks.set(+v[1], n[1]);
}

// `events:` is only present with `/ge:true`. Each record carries `value:` and `keywords:`.
const events = [];
for (const chunk of recs('event')) {
  const v = /\bvalue:\s*(\d+)/.exec(chunk);
  const k = /\bkeywords:\s*([0-9a-fA-Fx]+)/.exec(chunk);
  const t = /\btemplate:\s*(\S+)/.exec(chunk);
  if (v) events.push({ id: +v[1], keywords: k ? hex(k[1]) : null, template: t?.[1] ?? '' });
}

console.log(`== PROVIDER MANIFEST ==  keywords ${keywords.length}   tasks ${tasks.size}   events ${events.length}`);
if (keywords.length === 0) {
  console.log('!! NO KEYWORDS PARSED -- the instrument is broken, not the provider. Read the raw dump.');
  process.exit(1);
}
if (events.length === 0) {
  console.log('!! NO EVENTS BLOCK -- re-run `wevtutil gp <provider> /ge:true`. Delivery cannot be');
  console.log('   decided from tasks alone, so the per-event table below will be INCONCLUSIVE.');
}

console.log(`\n== MASK ${maskHex} DECODED ==`);
for (const k of keywords.sort((a, b) => (a.mask < b.mask ? -1 : 1))) {
  const on = (MASK & k.mask) !== 0n;
  console.log(`  ${on ? 'ON ' : 'off'}  0x${k.mask.toString(16).padStart(4, '0')}  ${k.name}`);
}
const unaccounted = MASK & ~keywords.reduce((a, k) => a | k.mask, 0n);
if (unaccounted !== 0n) console.log(`  !! 0x${unaccounted.toString(16)} of the mask matches NO declared keyword`);

// The decisive table: for each event the parser handles, can it be delivered under this mask?
// An event is delivered when ANY of its keyword bits is enabled (ETW ORs the mask), and an event
// published with keyword 0 is delivered unconditionally.
const want = evArg ? evArg.split(',').map(Number) : [];
if (want.length) {
  console.log(`\n== EVENTS THE PARSER SWITCHES ON, UNDER ${maskHex} ==`);
  let dead = 0, unknown = 0;
  for (const id of want) {
    const name = tasks.get(id) ?? '?';
    const e = events.find((x) => x.id === id);
    if (!e) { unknown++; console.log(`  ????????   ${String(id).padStart(3)}  ${name.padEnd(18)} no event record (need /ge:true)`); continue; }
    const kw = e.keywords ?? 0n;
    const delivered = kw === 0n || (MASK & kw) !== 0n;
    if (!delivered) dead++;
    console.log(`  ${delivered ? 'DELIVERED' : '⛔ NEVER  '}  ${String(id).padStart(3)}  ${name.padEnd(18)} keywords=0x${kw.toString(16)}  ${e.template}`);
  }
  console.log(`\n  ⇒ ${dead} of ${want.length} handled event IDs can NEVER be delivered under ${maskHex}` +
    (unknown ? `, and ${unknown} are UNDECIDED (no event record).` : '.'));
}
