// KNOWN-ANSWER FIXTURE, child half: perform an EXACT, counted set of filesystem operations whose
// ground truth is decided HERE rather than inferred from the trace. Runs inside the ETW session.
//
// ⛔ THE POINT IS THE GROUND TRUTH, NOT THE COVERAGE. A trace that looks healthy proves nothing: the
// macOS lane lost 100% of rename DESTINATIONS for the whole life of that adapter while its decoder
// printed confident grants, because nothing downstream ever asserted a count it controlled. Every
// operation here targets its OWN uniquely-named path, its inputs were seeded by `kaf-setup.mjs`
// BEFORE the trace, and the expectation file this emits names each path and what it must come back
// as. An assertion that cannot fail is not an assertion.
//
// Each shape separates a DIFFERENT capture mechanism:
//
//   create        FILE_OVERWRITE_IF disposition -- the easy case the adapter certainly gets
//   openrw        pre-existing file, FILE_OPEN disposition, written through the handle. DECISIVE:
//                 if the WRITE keyword is not enabled the Create says `read` and the write VANISHES
//   append        FILE_OPEN_IF disposition -- intent visible in the disposition alone
//   truncate      FILE_OPEN + SetInformation(EndOfFile), no data written
//   rename        BOTH ends must appear. The DESTINATION only arrives on a RenamePath event
//   delete        SetDelete / DeletePath
//   hardlink      SetLinkPath
//   copyfile      libuv's CopyFileExW; destination should be an ordinary Create
//   mkdir/rmdir   the directory namespace
//   setattr       SetInformation via utimes, no data written
//   readonly      a plain read -- the control that must NEVER be reported as a write
//   storm         N uniquely-named creates -- the COUNT assertion that catches partial loss
//
//   usage: node kaf-child.mjs <fixture-root> <storm-count> <grandchild.ps1>
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = process.argv[2];
const STORM = Number(process.argv[3] ?? '500');
const GRAND = process.argv[4];
if (!ROOT) { console.error('usage: kaf-child.mjs <fixture-root> <storm-count> [grandchild.ps1]'); process.exit(2); }

const D = (...p) => path.join(ROOT, ...p);
const expect = [];
let shape = '';
const W = (p) => expect.push({ path: p, op: 'write', shape });
const R = (p) => expect.push({ path: p, op: 'read', shape });

// ── create ────────────────────────────────────────────────────────────────────────────────────
shape = 'create';
const pCreate = D('work', 'kaf-create.bin');
fs.writeFileSync(pCreate, Buffer.alloc(4096, 1));
W(pCreate);

// ── openrw — THE DECISIVE SHAPE ───────────────────────────────────────────────────────────────
// `r+` is O_RDWR with no O_CREAT/O_TRUNC, which libuv turns into CreateFileW(OPEN_EXISTING) =>
// NtCreateFile disposition FILE_OPEN(1) => the adapter's `read` branch. Only a Write event can
// rescue it, and the Write event is keyword-gated.
shape = 'openrw';
const pOpenRw = D('work', 'kaf-openrw.bin');
const fd = fs.openSync(pOpenRw, 'r+');
fs.writeSync(fd, Buffer.alloc(4096, 3), 0, 4096, 0);
fs.fsyncSync(fd);
fs.closeSync(fd);
W(pOpenRw);

// ── append ────────────────────────────────────────────────────────────────────────────────────
shape = 'append';
const pAppend = D('work', 'kaf-append.bin');
fs.appendFileSync(pAppend, Buffer.alloc(64, 5));
W(pAppend);

// ── truncate ──────────────────────────────────────────────────────────────────────────────────
shape = 'truncate';
const pTrunc = D('work', 'kaf-truncate.bin');
fs.truncateSync(pTrunc, 128);
W(pTrunc);

// ── rename — BOTH ends. The destination is what the macOS lane lost entirely. ─────────────────
shape = 'rename';
const pRenSrc = D('work', 'kaf-rename-SOURCE.bin');
const pRenDst = D('work', 'kaf-rename-DEST.bin');
fs.renameSync(pRenSrc, pRenDst);
W(pRenSrc);
W(pRenDst);

// ── delete ────────────────────────────────────────────────────────────────────────────────────
shape = 'delete';
const pDel = D('work', 'kaf-delete.bin');
fs.unlinkSync(pDel);
W(pDel);

// ── hardlink ──────────────────────────────────────────────────────────────────────────────────
shape = 'hardlink';
const pLinkSrc = D('work', 'kaf-link-SOURCE.bin');
const pLinkDst = D('work', 'kaf-link-DEST.bin');
let hardlinkOk = true;
try { fs.linkSync(pLinkSrc, pLinkDst); } catch (e) { hardlinkOk = false; console.log(`SKIP hardlink: ${e.code}`); }
if (hardlinkOk) W(pLinkDst);

// ── copyfile ──────────────────────────────────────────────────────────────────────────────────
shape = 'copyfile';
const pCopySrc = D('work', 'kaf-copy-SOURCE.bin');
const pCopyDst = D('work', 'kaf-copy-DEST.bin');
fs.copyFileSync(pCopySrc, pCopyDst);
W(pCopyDst);
R(pCopySrc);

// ── mkdir / rmdir ─────────────────────────────────────────────────────────────────────────────
shape = 'mkdir';
const pMkdir = D('work', 'kaf-mkdir-DIR');
fs.mkdirSync(pMkdir);
W(pMkdir);
shape = 'rmdir';
const pRmdir = D('work', 'kaf-rmdir-DIR');
fs.rmdirSync(pRmdir);
W(pRmdir);

// ── setattr ───────────────────────────────────────────────────────────────────────────────────
shape = 'setattr';
const pAttr = D('work', 'kaf-setattr.bin');
fs.utimesSync(pAttr, new Date(), new Date());
W(pAttr);

// ── readonly — the control ────────────────────────────────────────────────────────────────────
shape = 'readonly';
const pRead = D('work', 'kaf-readonly-INPUT.bin');
fs.readFileSync(pRead);
R(pRead);

// ── storm — the exact-count assertion ─────────────────────────────────────────────────────────
// ⛔ THIS IS THE ONE THAT CATCHES SILENT PARTIAL LOSS. Every other shape is a presence check, and a
// presence check cannot see a tracer that drops 30% of events. N distinct known names can.
shape = 'storm';
const stormPaths = [];
for (let i = 0; i < STORM; i++) {
  const p = D('storm', `kaf-storm-${String(i).padStart(5, '0')}.bin`);
  fs.writeFileSync(p, Buffer.alloc(512, i & 0xff));
  stormPaths.push(p);
}

// ── grandchild: mmap + ADS, and a second process level for attribution ────────────────────────
// Node cannot memory-map a file, and an alternate data stream needs a spelling Node's fs API will
// not produce. Both are real write mechanisms a package could use, and both are invisible to the
// ordinary Write path, so they get their own process.
let grandOk = false, mmapOk = false;
if (GRAND) {
  const g = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', GRAND, ROOT],
    { encoding: 'utf8' });
  grandOk = g.status === 0;
  // ⛔ THE EXIT CODE IS NOT THE ANSWER, AND BELIEVING IT COST THIS FIXTURE ITS mmap ROW ENTIRELY.
  // The grandchild sets `$ErrorActionPreference = 'Continue'` and catches its own exception, so it
  // exits 0 whether the mapping worked or threw. For the whole life of this fixture the mapping
  // THREW -- PowerShell marshals `$null` for a String parameter as the empty string, which
  // `MemoryMappedFile.CreateFromFile` rejects -- and the probe reported the resulting absence as a
  // TRACER blind spot, through two separate investigations, because nothing read this console.
  // An expectation that can never be satisfied is not an assertion, it is a standing false finding.
  mmapOk = /MMAP ok/.test(g.stdout ?? '');
  console.log(`grandchild rc=${g.status} mmapOk=${mmapOk}\n${(g.stdout ?? '').trim()}\n${(g.stderr ?? '').trim()}`);
}
if (grandOk) {
  // Expected only when the grandchild verified the bytes actually landed in the file.
  if (mmapOk) { shape = 'mmap'; W(D('work', 'kaf-mmap.bin')); }
  else console.log('SKIP mmap: the grandchild did not confirm a memory-mapped write, so requiring one would measure the fixture rather than the tracer');
  // The ADS is deliberately NOT asserted as a required write: the kernel names a stream as
  // `<file>:<stream>:$DATA`, and whether that reaches the normalized stream at all is one of the
  // things being measured. It is reported, never gated.
}

fs.writeFileSync(D('kaf-expect.json'), JSON.stringify({
  root: ROOT,
  storm: STORM,
  stormPaths,
  decoy: D('work', 'kaf-NEVER-TOUCHED.bin'),
  adsHost: D('work', 'kaf-ads-HOST.bin'),
  grandchildRan: grandOk,
  expect,
}, null, 2));

console.log(`KAF child done: ${expect.length} named expectations + ${STORM} storm files`);
