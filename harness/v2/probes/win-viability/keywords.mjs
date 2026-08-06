// Decode the ETW keyword mask `windows.ps1` enables against the provider's OWN manifest, and say
// which of the event IDs the parser switches on can actually be delivered under it.
//
// ⛔ THIS EXISTS BECAUSE A KEYWORD MASK IS A SILENT FILTER. `logman update trace -p <provider> <mask>`
// succeeds whatever the mask is: an event whose keyword bit is clear is simply never written, with no
// error anywhere. So a parser can carry a correct handler for event 16 forever and never see one, and
// the resulting trace looks healthy -- `EventsLost 0`, thousands of events, a plausible path set.
// The undercount direction is an UNDER-GRANT, which is the direction that breaks installs.
//
// Input is `wevtutil gp <provider>` text, which lists every keyword with its value and every event
// with the keyword mask it is published under. Nothing here is guessed from a name.
//
//   usage: node keywords.mjs <wevtutil-dump.txt> <mask-hex> [--events 12,15,16,...]
import fs from 'node:fs';

const [dumpPath, maskHex] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const evArg = (() => { const i = process.argv.indexOf('--events'); return i >= 0 ? process.argv[i + 1] : ''; })();
if (!dumpPath || !maskHex) { console.error('usage: keywords.mjs <dump.txt> <mask-hex> [--events a,b,c]'); process.exit(2); }

const text = fs.readFileSync(dumpPath, 'utf8');
const MASK = BigInt(maskHex);

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
const keywords = [];
{
  const re = /name:\s*(\S+)[\s\S]*?mask:\s*(0x[0-9a-fA-F]+)/g;
  // Scope to the keywords block so an event's `name:`/`mask:` pair cannot be mistaken for one.
  const start = text.indexOf('keywords:');
  const end = text.indexOf('\n  events:', start >= 0 ? start : 0);
  const block = text.slice(start >= 0 ? start : 0, end > 0 ? end : text.length);
  let m;
  while ((m = re.exec(block))) keywords.push({ name: m[1], mask: BigInt(m[2]) });
}

// Events: `value: N` ... `keywords: 0xNN` within one event record. Split on the record boundary so a
// missing `keywords:` line cannot silently borrow the next event's.
const events = [];
for (const chunk of text.split(/^\s*event:\s*$/m).slice(1)) {
  const v = /\bvalue:\s*(\d+)/.exec(chunk);
  const k = /\bkeywords:\s*(0x[0-9a-fA-F]+)/.exec(chunk);
  const o = /\bopcode:\s*(\S+)/.exec(chunk);
  const t = /\btemplate:\s*(\S+)/.exec(chunk);
  if (v) events.push({ id: +v[1], keywords: k ? BigInt(k[1]) : null, opcode: o?.[1] ?? '', template: t?.[1] ?? '' });
}

console.log(`== PROVIDER MANIFEST ==  keywords parsed: ${keywords.length}   events parsed: ${events.length}`);
if (keywords.length === 0 || events.length === 0) {
  console.log('!! PARSE FOUND NOTHING -- the instrument is broken, not the provider. Read the raw dump.');
  process.exit(1);
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
  let dead = 0;
  for (const id of want) {
    const e = events.find((x) => x.id === id);
    if (!e) { console.log(`  ??  ${String(id).padStart(3)}  NOT DECLARED BY THIS PROVIDER`); continue; }
    const kw = e.keywords ?? 0n;
    const delivered = kw === 0n || (MASK & kw) !== 0n;
    if (!delivered) dead++;
    console.log(`  ${delivered ? 'DELIVERED' : '⛔ NEVER  '}  ${String(id).padStart(3)}  keywords=0x${kw.toString(16)}  ${e.opcode} ${e.template}`);
  }
  console.log(`\n  ⇒ ${dead} of ${want.length} handled event IDs can NEVER be delivered under ${maskHex}.`);
}
