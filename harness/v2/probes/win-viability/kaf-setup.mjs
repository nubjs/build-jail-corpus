// KNOWN-ANSWER FIXTURE, setup half. Runs BEFORE the trace starts.
//
// ⛔ THE PRE-SEEDING IS WHAT MAKES EACH SHAPE DECISIVE, and doing it inside the trace would quietly
// destroy the whole fixture. The question "does a write through a FILE_OPEN handle get reported?"
// can only be asked of a file that ALREADY EXISTS -- if the child creates it first, that create is
// an OVERWRITE_IF disposition, the adapter reports the path as written for that reason alone, and
// the assertion passes while measuring nothing. Same for append, truncate, rename, delete, hardlink,
// copy and setattr: every one needs an existing input, and every one is a different mechanism.
//
//   usage: node kaf-setup.mjs <fixture-root>
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.argv[2];
if (!ROOT) { console.error('usage: kaf-setup.mjs <fixture-root>'); process.exit(2); }

fs.rmSync(ROOT, { recursive: true, force: true });
const D = (...p) => path.join(ROOT, ...p);
fs.mkdirSync(D('work'), { recursive: true });
fs.mkdirSync(D('storm'), { recursive: true });

const seed = (name, fill, size = 4096) => {
  const p = D('work', name);
  fs.writeFileSync(p, Buffer.alloc(size, fill));
  return p;
};

seed('kaf-openrw.bin', 2);
seed('kaf-append.bin', 4, 64);
seed('kaf-truncate.bin', 6, 8192);
seed('kaf-rename-SOURCE.bin', 7, 256);
seed('kaf-delete.bin', 8, 256);
seed('kaf-link-SOURCE.bin', 9, 256);
seed('kaf-copy-SOURCE.bin', 10);
seed('kaf-setattr.bin', 11, 64);
seed('kaf-readonly-INPUT.bin', 12, 1024);
seed('kaf-mmap.bin', 13, 65536);
seed('kaf-ads-HOST.bin', 14, 256);
// The decoy exists so that "absent from the trace" is a statement about the TRACER rather than
// about the filesystem. A path that was never created could not appear whatever the tracer did.
seed('kaf-NEVER-TOUCHED.bin', 0xff, 256);
fs.mkdirSync(D('work', 'kaf-rmdir-DIR'));

console.log(`KAF setup complete at ${ROOT}`);
