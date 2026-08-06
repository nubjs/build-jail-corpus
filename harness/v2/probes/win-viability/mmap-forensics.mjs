// WHAT DOES THE TRACE ACTUALLY CONTAIN ABOUT A MEMORY-MAPPED WRITE?
//
// The known-answer fixture maps `kaf-mmap.bin`, stores 4096 bytes into the view, flushes and
// disposes -- and the normalized stream reports no write to it, at either keyword mask. That is an
// UNDER-GRANT and it needs a name, so this walks the raw trace for every event that mentions the
// file, directly or through a FileObject the file was opened on, and prints them whole.
//
// ⛔ THE POINT IS TO SEPARATE THREE VERY DIFFERENT ANSWERS, which the normalized stream cannot:
//   (a) the write IS in the trace and the decoder drops it -- e.g. a Write event attributed to the
//       memory manager's system thread, which `inSubtree` correctly refuses. FIXABLE HERE.
//   (b) the Create carries something that marks the mapping as writable, so the open could be
//       classified a write instead of a read. FIXABLE HERE, at a cost in width.
//   (c) nothing in this provider observes it at all -- the CPU stores into a mapped view and the
//       memory manager flushes those pages on its own schedule, with no WriteFile to see. NOT
//       FIXABLE HERE, and then the honest deliverable is a NAMED GAP rather than silence.
//
//   usage: node mmap-forensics.mjs <trace.xml> <substring> [--max N]
import fs from 'node:fs';
import readline from 'node:readline';

const [xmlPath, needleRaw] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const maxIdx = process.argv.indexOf('--max');
const MAX = maxIdx >= 0 ? Number(process.argv[maxIdx + 1]) : 60;
if (!xmlPath || !needleRaw) { console.error('usage: mmap-forensics.mjs <trace.xml> <substring> [--max N]'); process.exit(2); }
const needle = needleRaw.toLowerCase();

const rl = readline.createInterface({ input: fs.createReadStream(xmlPath), crlfDelay: Infinity });
let block = null;
const objects = new Set();                              // FileObjects the named file was opened on
// ⛔ FileKey IS TRACKED SEPARATELY, AND OMITTING IT MADE THIS TOOL LIE. `windows.mjs` resolves a
// handle op as FileObject first and FileKey second, so an event that carries only a FileKey -- a
// flush issued against a SECTION rather than the original handle, for instance -- is resolved by
// the decoder and was invisible here. That produced the exact false negative this file exists to
// avoid: a memory-mapped write present in the normalized stream while this tool reported the file
// appeared in one NameCreate and nothing else.
const keys = new Set();                                 // FileKeys the named file resolves through
const hits = [];
const byId = new Map();
let total = 0;

// Two passes in one: a Create naming the file registers its FileObject, and any later event on that
// FileObject is a hit even though the path never appears in its payload. That ordering is why this
// cannot be done with grep.
for await (const line of rl) {
  if (line.includes('<Event ')) { block = [line]; continue; }
  if (block === null) continue;
  block.push(line);
  if (!line.includes('</Event>')) continue;
  const xml = block.join('\n');
  block = null;
  total++;

  const id = +(/<EventID[^>]*>(\d+)<\/EventID>/.exec(xml)?.[1] ?? -1);
  const data = {};
  for (const m of xml.matchAll(/<Data Name="([^"]+)">([^<]*)<\/Data>/g)) data[m[1]] = m[2].trim();

  const named = Object.values(data).some((v) => String(v).toLowerCase().includes(needle));
  if (named && data.FileObject) objects.add(data.FileObject);
  if (named && data.FileKey) keys.add(data.FileKey);
  const viaObject = data.FileObject && objects.has(data.FileObject);
  const viaKey = data.FileKey && keys.has(data.FileKey);
  if (!named && !viaObject && !viaKey) continue;

  byId.set(id, (byId.get(id) ?? 0) + 1);
  if (hits.length < MAX) {
    const ex = /ProcessID="(\d+)" ThreadID="(\d+)"/.exec(xml);
    const how = named ? 'BY-NAME  ' : viaObject ? 'BY-OBJECT' : 'BY-KEY   ';
    hits.push(`  id=${String(id).padStart(3)} pid=${ex?.[1] ?? '?'} tid=${ex?.[2] ?? '?'} ${how} ${JSON.stringify(data)}`);
  }
}

console.log(`== ${total} trace events scanned for "${needleRaw}" ==`);
console.log(`   FileObjects the name was seen on: ${[...objects].join(', ') || '(none)'}`);
console.log(`   FileKeys   the name was seen on: ${[...keys].join(', ') || '(none)'}`);
console.log(`   matching events by EventID: ${JSON.stringify(Object.fromEntries([...byId].sort((a, b) => a[0] - b[0])))}`);
console.log(`\n== first ${hits.length} matching events, whole ==`);
hits.forEach((h) => console.log(h));
if (!byId.size) console.log('  !! NOTHING MATCHED -- either the fixture did not run or the name never reached the trace.');
