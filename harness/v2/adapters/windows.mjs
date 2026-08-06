// Windows god-mode observation adapter, parse half: an ETW trace in, the normalized event stream
// out. Pair this with windows.ps1, which produced the capture directory.
//
// THE ADAPTER IS THIN ON PURPOSE. It emits op/path/host/port/result/pid/ppid and nothing else. No
// scope assignment, no grant lattice, no sentinels -- all of that lives in the shared classifier so
// three platforms cannot drift apart. A thing this adapter cannot express, it omits.
//
//   usage: node windows.mjs <capture-dir> [--out FILE] [--summary] [--allow-lossy]
//                           [--resolve-shortnames | --shortnames F | --no-longpath]
//          <capture-dir>/meta.json  + <capture-dir>/trace.xml   (both written by windows.ps1)
//
// `--resolve-shortnames` is the CAPTURE-HOST pass: it resolves 8.3 names against the live
// filesystem and writes `<capture-dir>/shortnames.json`, which every later decode reads instead.
// Without it (or an existing map) expansion is OFF — deterministically, on every machine.
//
// Prefer --out to a shell redirect. Windows PowerShell's `>` writes UTF-16LE with a BOM, so
// `node windows.mjs ... > events.ndjson` produces a file that PowerShell reads back happily and
// JSON.parse rejects on the first byte.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {
  SHORT_COMPONENT, SHORT_NAMES_FILE, UNMAPPED, componentResolver, shortNameMode, writeShortNames,
} from './windows-shortnames.mjs';

const args = process.argv.slice(2);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };
const outIdx = args.indexOf('--out');
const outFile = outIdx >= 0 ? args[outIdx + 1] : null;
const dumpIdx = args.indexOf('--dump-dest');
const dumpDest = dumpIdx >= 0 ? Number(args[dumpIdx + 1] ?? '5') : 0;
// ⛔ EVERY VALUE-TAKING FLAG MUST BE LISTED HERE OR ITS VALUE BECOMES THE CAPTURE DIRECTORY. The
// positional is found by "the first arg that is not a flag and not a flag's value", so a new
// `--shortnames F` whose `F` is not excluded silently makes `F` the capture dir and the adapter
// then fails on a missing `meta.json` — a confusing error a long way from its cause.
const VALUE_FLAGS = new Set(['--out', '--dump-dest', '--shortnames']);
const dir = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && VALUE_FLAGS.has(args[i - 1]))).find(Boolean);
const wantSummary = args.includes('--summary');
const allowLossy = args.includes('--allow-lossy');
const noLongPath = args.includes('--no-longpath');
if (!dir) { console.error('usage: windows.mjs <capture-dir> [--out FILE] [--summary] [--allow-lossy] [--no-longpath] [--resolve-shortnames] [--shortnames F] [--dump-dest N]'); process.exit(2); }

const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));

// A trace that dropped events cannot support "no more than this", which is half of what the
// validator asserts. Fail rather than quietly answer a weaker question.
if (meta.eventsLost > 0 && !allowLossy) {
  console.error(`windows.mjs: trace lost ${meta.eventsLost} events; re-capture with bigger buffers, or pass --allow-lossy to read it anyway`);
  process.exit(3);
}

// ---------------------------------------------------------------------------------------------
// NT path -> DOS path. Kernel-File reports \Device\HarddiskVolume3\Users\nub\x, never C:\Users\nub\x.
// The map came from QueryDosDevice at capture time, so this is DECODING a different namespace, not
// normalizing a spelling: case folding, symlink resolution and .. collapsing stay downstream in the
// one shared normalizer. A device with no mapping is passed through verbatim -- a named pipe or a
// UNC share is a real touch, and the classifier's "maps to no scope" rule is the right place to
// decide about it, not a guess here.
// ---------------------------------------------------------------------------------------------
const devices = Object.entries(meta.devmap).sort((a, b) => b[0].length - a[0].length);
function dosPath(nt) {
  if (!nt) return null;
  // `\??\C:\x` is the object manager's DosDevices spelling of `C:\x` -- the same file, not a
  // different namespace. The destination-path events (26/27/28) can hand back either spelling
  // depending on how the caller built the target name, and leaving `\??\` on the front sends the
  // path straight into the classifier's `kernelfs` bucket, where a real write is reported as
  // filesystem metadata and never reaches a grant.
  if (nt.startsWith('\\??\\')) nt = nt.slice(4);
  for (const [dev, letter] of devices) {
    if (nt === dev) return letter + '\\';
    if (nt.startsWith(dev + '\\')) return letter + nt.slice(dev.length);
  }
  return nt;
}

// ---------------------------------------------------------------------------------------------
// 8.3 SHORT NAMES. NTFS keeps a second, legacy spelling for a name that does not fit 8.3, and the
// kernel reports whichever spelling the CALLER used. On a GitHub runner `%TEMP%` is literally
// `C:\Users\RUNNER~1\AppData\Local\Temp`, so a package resolving temp through the environment
// produces short-spelled paths while one resolving it through the profile produces long ones.
//
// ⛔ THAT IS A SCOPE DEFECT, NOT A COSMETIC ONE, AND IT UNDER-GRANTS. The classifier assigns scope
// by longest-prefix against roots it is handed, and `c:\users\runner~1\...` does not start with
// `c:\users\runneradmin\`, so it falls to `outside` -- reported, never granted. Measured on the one
// real package the viability probe traced (hugo-extended@0.141.0): 543 paths, 1 write and 542
// reads, every one of them genuinely under the user profile and every one classified `outside`.
//
// ⛔ DIRECTION MATTERS: short -> long, never long -> short. Expanding needs the name to still
// exist, which is false for a deleted temp file; contracting would need us to invent a short name.
// So this walks the path LEFT TO RIGHT and expands each component independently against a parent
// that is already long. Scope is decided by the PREFIX, and directories outlive the files inside
// them, so a deleted leaf still lands in the right scope -- only its own spelling stays ambiguous.
//
// WHEN EXPANSION FAILS the short spelling is KEPT VERBATIM and COUNTED (`stats.shortUnexpanded`,
// printed with the other stats). Keeping both spellings over-counts distinct paths, which is the
// safe direction; guessing a long name would be an invented fact.
//
// TWO GUARDS, both of which have a way to be wrong that this refuses to take:
//   * a resolved component is only accepted when it is still a CHILD of the same parent. Otherwise
//     `realpath` followed a junction and we would be rewriting the path to a different location.
//   * the resolution happens ONCE, on the capture host, and is ARCHIVED — see
//     `windows-shortnames.mjs`. This used to be gated on `meta.host == process.env.COMPUTERNAME`,
//     which made the decoder's OUTPUT depend on the machine it DECODED on: the same archive read on
//     the capture VM and on a runner produced two different views, and comparing two archives is
//     exactly what the venue-portability acceptance test does. (VENUE-PORTABILITY R2.)
// ---------------------------------------------------------------------------------------------
const shortNames = shortNameMode({ dir, args, val });
// `--no-longpath` still wins, and is now the ONLY caller-supplied way to turn expansion off; every
// other mode is decided by what the archive carries.
const longPathOn = !noLongPath && shortNames.mode !== 'off';
const resolveComponent = longPathOn ? componentResolver(shortNames) : null;

function expandShortPath(p) {
  if (!longPathOn || !p.includes('~') || !/^[A-Za-z]:\\/.test(p)) return p;
  const parts = p.split('\\');
  let cur = parts[0];                                   // the drive, e.g. `C:`
  let changed = false, failed = false, unmapped = false;
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    if (!seg) continue;
    if (!SHORT_COMPONENT.test(seg)) { cur = `${cur}\\${seg}`; continue; }
    const long = resolveComponent(cur, seg);
    // ⛔ THREE OUTCOMES, NOT TWO. `null` is the map SAYING there is no long name (the capture host
    // looked and the name was gone) — an answer. `UNMAPPED` is the map not covering this component
    // at all, i.e. an incomplete archive. Both keep the short spelling, but only the second means
    // the archive is missing something, so they are counted apart rather than merged into "failed".
    if (long === UNMAPPED) { unmapped = true; cur = `${cur}\\${seg}`; continue; }
    if (long === null) { failed = true; cur = `${cur}\\${seg}`; continue; }
    if (long !== seg) changed = true;
    cur = `${cur}\\${long}`;
  }
  if (failed) stats.shortUnexpanded++;
  if (unmapped) stats.shortUnmapped++;
  if (changed) stats.shortExpanded++;
  // Put back a trailing separator the component walk dropped. The kernel emits a directory both
  // with and without one, and folding those two spellings is the shared normalizer's job (rule 1),
  // not this adapter's -- doing it here would be a second, invisible normalization that only fires
  // on paths that happened to contain a short name.
  if (changed && p.endsWith('\\') && !cur.endsWith('\\')) cur += '\\';
  return changed ? cur : p;
}

// ---------------------------------------------------------------------------------------------
// Kernel-File event IDs, and the read/write split.
//
// ⛔ WRITE INTENT IS IN THE CREATE DISPOSITION, which Windows packs into the TOP BYTE of
// CreateOptions. FILE_OPEN is the only non-mutating one; supersede/create/open-if/overwrite all
// mean the caller was prepared to change the file. Verified against the fixture: the project write
// arrived as disposition 5 (OVERWRITE_IF) and the read-only input as disposition 1 (OPEN).
//
// Disposition alone is NOT sufficient. A caller may FILE_OPEN an existing file and write to it, so
// the Write event is also treated as a write and its path resolved through the handle maps. The two
// together are the write predicate; either alone under-reports.
// ---------------------------------------------------------------------------------------------
const EV = {
  NAME_CREATE: 10, NAME_DELETE: 11, CREATE: 12, CLEANUP: 13, CLOSE: 14, READ: 15, WRITE: 16,
  SET_INFORMATION: 17, SET_DELETE: 18, RENAME: 19, DIR_ENUM: 20, QUERY_INFORMATION: 22,
  OPERATION_END: 24, DELETE_PATH: 26, RENAME_PATH: 27, SET_LINK_PATH: 28, CREATE_NEW_FILE: 30,
};
const FILE_OPEN = 1;                                    // the one disposition that is read-only
const MUTATORS = new Set([EV.SET_INFORMATION, EV.SET_DELETE, EV.RENAME]);

// ---------------------------------------------------------------------------------------------
// ⛔ THE DESTINATION EVENTS, AND WHY THEY NEED THEIR OWN PATH RESOLUTION.
//
// 26/27/28 are the ONLY events in this provider that carry a path the handle tables cannot supply:
// a rename's NEW name, a hard link's NEW name, a delete's resolved name. Every other handle op
// resolves through `nameByObject.get(FileObject)`, and for a RenamePath that FileObject is still
// the SOURCE -- so the ordinary lookup order returns the source, the source was already emitted by
// the Rename (19) event, the dedup set swallows it, and the destination is ABSENT with nothing in
// the stream saying so. Measured on the known-answer fixture: rename DEST and hardlink DEST absent
// at BOTH masks, i.e. widening the keyword mask alone changed nothing.
//
// So for these three the PAYLOAD path wins and the handle tables are only a fallback. The field
// name is read from a candidate list rather than hardcoded because `wevtutil gp /ge:true` publishes
// no templates for this provider -- `--dump-dest N` prints the raw payload of the first N of these
// events so the list can be checked against a real trace instead of against memory.
//
// A destination may also arrive RELATIVE (a bare leaf name, when the caller set RootDirectory on
// the rename information). A leaf is joined to the SOURCE's directory, which is the only directory
// it can mean; anything else is left alone.
// ---------------------------------------------------------------------------------------------
const DEST_PATH_EVENTS = new Set([EV.DELETE_PATH, EV.RENAME_PATH, EV.SET_LINK_PATH]);
// Keyed on the EVENT, never on InfoClass: one RenamePath in the fixture trace carried
// FileRenameInformation (10) and another FileRenameInformationEx (65), and a delete arrives as 64.
const DEST_KIND = { [EV.RENAME_PATH]: 'rename', [EV.SET_LINK_PATH]: 'hardlink', [EV.DELETE_PATH]: 'delete' };
const DEST_PATH_FIELDS = ['FilePath', 'FileName', 'NewPath', 'TargetName', 'Path'];
const isAbsoluteish = (s) => /^\\/.test(s) || /^[A-Za-z]:[\\/]/.test(s);

function destPathOf(data, sourceName) {
  let raw = null;
  for (const f of DEST_PATH_FIELDS) {
    const v = data[f];
    if (v) { raw = v; break; }
  }
  if (!raw) return null;
  if (isAbsoluteish(raw)) return raw;
  if (!sourceName) return null;                         // a bare leaf with nothing to anchor it
  const cut = sourceName.lastIndexOf('\\');
  return cut > 0 ? `${sourceName.slice(0, cut)}\\${raw}` : null;
}

// ⛔ ONLY A GENUINE REFUSAL IS A REFUSAL. The Windows near-miss is not a string that also matches
// something innocent -- it is the temptation to call every non-zero NTSTATUS a denial. A probe for
// a file that is not there returns STATUS_OBJECT_NAME_NOT_FOUND, which means the operation did not
// happen, not that it was forbidden; those are OMITTED, mirroring the Linux extractor skipping
// `= -1`. Only these four say "you were not allowed".
const REFUSAL_STATUS = new Map([
  [0xc0000022, 'STATUS_ACCESS_DENIED'],
  [0xc0000061, 'STATUS_PRIVILEGE_NOT_HELD'],
  [0xc00000a2, 'STATUS_MEDIA_WRITE_PROTECTED'],
  [0xc0000121, 'STATUS_CANNOT_DELETE'],
]);
const ntSuccess = (s) => (s & 0x80000000) === 0;        // severity 0 or 1; matches NT_SUCCESS()

// Kernel-Network. Only OUTBOUND initiations are connects; data-sent/received on an established
// socket says nothing a connect has not already said, and an inbound accept is not an egress need.
const NET_CONNECT = new Set([12, 28, 42, 58]);          // TCPv4 / TCPv6 / UDPv4 / UDPv6 initiation

// ---------------------------------------------------------------------------------------------
// State.
// ---------------------------------------------------------------------------------------------
const ROOT = meta.rootPid;
const parentOf = new Map([[ROOT, meta.launcherPid]]);
const subtree = new Map();                              // memoizes only POSITIVE ancestry
const tidToPid = new Map();                             // learned free from every event header
const nameByObject = new Map();                         // FileObject -> NT path (from Create)
const nameByKey = new Map();                            // FileKey    -> NT path (from NameCreate)
const pendingIrp = new Map();                           // Irp -> a Create awaiting its status
// ⛔ A SEPARATE MAP, AND LIST-VALUED, FOR A MEASURED REASON. A rename emits Rename (19) and
// RenamePath (27) under ONE Irp, and `pendingIrp` is single-valued and last-writer-wins -- so
// putting the destination in it would EVICT the source and trade one missing end of the rename for
// the other. (Visible in the probe: `orphan creates` went 8 -> 23 the moment the widened mask let
// 26/27/28 into that map.) Keeping the destination events in their own list-valued map leaves the
// existing Create/Read/Write pairing byte-for-byte as it was, which is what keeps the fourteen
// shapes that pass today passing.
const pendingDest = new Map();                          // Irp -> [destination ops awaiting status]
const emitted = new Set();                              // the contract has no timestamp, so two
                                                        // identical tuples are indistinguishable
const stats = {
  events: 0, emitted: 0, unresolvedHandle: 0, orphanCreate: 0, reattributedByThread: 0,
  skippedFailed: 0, denied: 0, destResolved: 0, destUnresolved: 0, destUnmatched: 0,
  shortExpanded: 0, shortUnexpanded: 0, shortUnmapped: 0,
};
const destSamples = [];                                 // raw payloads for --dump-dest

// Only POSITIVE results are memoized. A negative is provisional -- the ProcessStart that supplies
// the missing link may not have been read yet -- and caching it is what silently drops a whole
// grandchild's worth of events.
function inSubtree(pid) {
  if (subtree.get(pid)) return true;
  const chain = [];
  const seen = new Set();
  let cur = pid;
  while (cur !== undefined && !seen.has(cur)) {
    seen.add(cur);
    if (cur === ROOT || subtree.get(cur) === true) {
      for (const p of chain) subtree.set(p, true);
      subtree.set(pid, true);
      return true;
    }
    chain.push(cur);
    cur = parentOf.get(cur);
  }
  return false;
}

const out = [];
function emit(ev) {
  const key = JSON.stringify(ev);
  if (emitted.has(key)) return;
  emitted.add(key);
  stats.emitted++;
  out.push(ev);
}

// `pair` is `{ kind, other }` for a TWO-PATH operation -- see the `path2` note below. Everything
// else passes it undefined and the emitted shape is byte-identical to what it always was.
function emitFile(op, ntPath, pid, result, pair) {
  const p = dosPath(ntPath);
  // Omit rather than guess: an unnamed handle, or a process whose parent we never saw, cannot fill
  // the contract's fields honestly.
  if (!p || p === '\\FI_UNKNOWN') return;
  const ppid = parentOf.get(pid);
  if (ppid === undefined) return;
  // ONE FILE, ONE SPELLING -- see expandShortPath. This is the last point before the contract, so
  // everything downstream (classifier, retained log, validator) sees the canonical form.
  const ev = { op, path: expandShortPath(p), result, pid, ppid };
  // ---------------------------------------------------------------------------------------------
  // ⛔ `path2` -- A TWO-PATH OP BILLS BOTH ENDS, AND THE PAIRING IS A FACT THE KERNEL GAVE US.
  //
  // A hard link is the sharp case: it creates a SECOND NAME for existing content, so afterwards two
  // live paths reach the same bytes. Emitting the two names as two unrelated single-path records
  // loses which link went with which target the moment two operations interleave -- and a link whose
  // target is unknown is not merely an under-grant, it is a path the model cannot reason about.
  //
  // The SetLinkPath event carries both ends in ONE record: the FileObject resolves to the source
  // through the handle tables, and the payload carries the new name. Splitting that apart at the
  // contract boundary would be discarding it on the way out. The Linux retained log already keeps
  // both ends as `f`/`g` for exactly this reason.
  //
  // ADDITIVE AND IGNORED BY EVERYTHING THAT EXISTS. `classify.mjs` reads op/path/result/pid and
  // `validate-windows.mjs` keys its exact-set on `op|path|result|role`, so neither sees this field.
  // The primary `path` stays the DESTINATION, which is the end that needs the grant.
  // ---------------------------------------------------------------------------------------------
  if (pair?.other) {
    const o = dosPath(pair.other);
    if (o && o !== '\\FI_UNKNOWN') {
      const oe = expandShortPath(o);
      if (oe !== ev.path) { ev.path2 = oe; ev.kind = pair.kind; }
    }
  }
  emit(ev);
}

// ---------------------------------------------------------------------------------------------
// The stream. Split on event boundaries rather than reading the file whole: a real install trace
// runs to hundreds of megabytes of XML and readFileSync would hit V8's string cap.
// ---------------------------------------------------------------------------------------------
const rl = readline.createInterface({ input: fs.createReadStream(path.join(dir, 'trace.xml')), crlfDelay: Infinity });
let block = null;

for await (const line of rl) {
  if (line.includes('<Event ')) { block = [line]; continue; }
  if (block === null) continue;
  block.push(line);
  if (!line.includes('</Event>')) continue;

  const xml = block.join('\n');
  block = null;
  stats.events++;

  const idm = /<EventID[^>]*>(\d+)<\/EventID>/.exec(xml);
  const pm = /<Provider Name="([^"]+)"/.exec(xml);
  if (!idm || !pm) continue;
  const id = +idm[1];
  const provider = pm[1];

  const ex = /ProcessID="(\d+)" ThreadID="(\d+)"/.exec(xml);
  let pid = ex ? +ex[1] : -1;
  const tid = ex ? +ex[2] : -1;

  const data = {};
  for (const m of xml.matchAll(/<Data Name="([^"]+)">([^<]*)<\/Data>/g)) data[m[1]] = m[2].trim();

  // ⛔ ETW EVENTS ARE PER-THREAD. The header PID is right for a synchronous request, but I/O the
  // filesystem completes on a system worker thread carries the System process in the header while
  // IssuingThreadId still names the requester. Every event header is a free (tid -> pid) fact, so
  // the map costs nothing; use it to put deferred work back on the process that asked for it.
  if (pid > 0 && tid > 0) tidToPid.set(tid, pid);
  const issuing = data.IssuingThreadId ? +data.IssuingThreadId : null;
  if (issuing && issuing !== tid && tidToPid.has(issuing)) {
    const real = tidToPid.get(issuing);
    if (real !== pid) { pid = real; stats.reattributedByThread++; }
  }

  if (provider === 'Microsoft-Windows-Kernel-Process') {
    if (id === 1) {                                     // ProcessStart
      const child = +data.ProcessID, par = +data.ParentProcessID;
      parentOf.set(child, par);
      if (inSubtree(child)) {
        const image = dosPath(data.ImageName);
        if (image) emit({ op: 'exec', path: image, result: 'ok', pid: child, ppid: par });
      }
    } else if (id === 2) {                              // ProcessStop -- retire the PID so reuse
      tidToPid.forEach((v, k) => { if (v === +data.ProcessID) tidToPid.delete(k); });
    }
    continue;
  }

  if (provider === 'Microsoft-Windows-Kernel-Network') {
    // The header PID is 0 on the receive path (a DPC, not the owning process). The PID field in
    // the payload is the authoritative one for this provider.
    const npid = data.PID ? +data.PID : pid;
    if (!NET_CONNECT.has(id) || !inSubtree(npid)) continue;
    const ppid = parentOf.get(npid);
    if (ppid === undefined || !data.daddr) continue;
    emit({ op: 'connect', host: data.daddr, port: +data.dport, result: 'ok', pid: npid, ppid });
    continue;
  }

  if (provider !== 'Microsoft-Windows-Kernel-File') continue;

  // The name tables. NameCreate is the kernel's filename rundown, emitted by System -- it is a
  // (FileKey -> name) FACT, never an access, and treating it as one would report a read of every
  // file merely enumerated in a directory listing.
  if (id === EV.NAME_CREATE) { if (data.FileKey && data.FileName) nameByKey.set(data.FileKey, data.FileName); continue; }
  if (id === EV.NAME_DELETE) { if (data.FileKey) nameByKey.delete(data.FileKey); continue; }

  if (id === EV.CREATE || id === EV.CREATE_NEW_FILE) {
    if (data.FileObject && data.FileName) nameByObject.set(data.FileObject, data.FileName);
    if (!inSubtree(pid) || !data.FileName || !data.Irp) continue;
    const disposition = (parseInt(data.CreateOptions, 16) >>> 24) & 0xff;
    // ⛔ Irp POINTERS ARE REUSED, back to back. In the fixture the read, the missing-file probe and
    // the ACL-denied write all carried the SAME Irp value. So the pairing is nearest-in-time and
    // consuming; a global Irp map would attach the wrong status to the wrong open. A Create whose
    // Irp is still pending never got its OperationEnd, and without a status the result field cannot
    // be filled -- drop it rather than guess.
    if (pendingIrp.has(data.Irp)) stats.orphanCreate++;
    pendingIrp.set(data.Irp, { op: disposition === FILE_OPEN ? 'read' : 'write', name: data.FileName, pid });
    continue;
  }

  if (id === EV.OPERATION_END) {
    const pend = pendingIrp.get(data.Irp);
    const dests = pendingDest.get(data.Irp);
    if (!pend && !dests) continue;
    pendingIrp.delete(data.Irp);
    pendingDest.delete(data.Irp);
    const status = parseInt(data.Status, 16) >>> 0;
    const settle = (o) => {
      if (ntSuccess(status)) { emitFile(o.op, o.name, o.pid, 'ok', o.pair); return; }
      if (REFUSAL_STATUS.has(status)) { stats.denied++; emitFile(o.op, o.name, o.pid, 'denied', o.pair); return; }
      stats.skippedFailed++;                            // failed for a reason that is not a refusal
    };
    if (pend) settle(pend);
    if (dests) for (const d of dests) settle(d);
    continue;
  }

  if (id === EV.CLOSE) { if (data.FileObject) nameByObject.delete(data.FileObject); continue; }

  // ── DESTINATION PATHS. Handled before the handle-based branch because the payload path, not the
  // FileObject, is the authoritative one here -- see DEST_PATH_EVENTS above.
  if (DEST_PATH_EVENTS.has(id)) {
    if (destSamples.length < dumpDest) destSamples.push({ id, pid, data });
    if (!inSubtree(pid)) continue;
    const source = nameByObject.get(data.FileObject) ?? nameByKey.get(data.FileKey) ?? null;
    const dest = destPathOf(data, source);
    // Fall back to the handle tables so a DeletePath with no payload path still reports SOMETHING
    // -- for a delete the source IS the answer, and for a rename it is a duplicate the emit-set
    // swallows. Never worse than today.
    const name = dest ?? source;
    if (!name) { stats.destUnresolved++; continue; }
    if (dest) stats.destResolved++;
    const op = { op: 'write', name, pid, pair: { kind: DEST_KIND[id], other: source } };
    if (!data.Irp) { emitFile(op.op, op.name, op.pid, 'ok', op.pair); continue; }
    const list = pendingDest.get(data.Irp);
    if (list) list.push(op); else pendingDest.set(data.Irp, [op]);
    continue;
  }

  // Handle-based operations: the path is not in the payload, so it comes from the tables the
  // Create and NameCreate events built. These carry an Irp as well, so they go through the SAME
  // status gate as a Create rather than being assumed successful -- otherwise a read refused on an
  // already-open handle is reported as `ok`, which is the one direction that must never happen.
  if (id === EV.READ || id === EV.WRITE || MUTATORS.has(id)) {
    if (!inSubtree(pid)) continue;
    const name = nameByObject.get(data.FileObject) ?? nameByKey.get(data.FileKey) ?? data.FileName;
    if (!name) { stats.unresolvedHandle++; continue; }
    const op = id === EV.READ ? 'read' : 'write';
    if (!data.Irp) { emitFile(op, name, pid, 'ok'); continue; }
    if (pendingIrp.has(data.Irp)) stats.orphanCreate++;
    pendingIrp.set(data.Irp, { op, name, pid });
  }
}

// A destination whose OperationEnd never arrived (it followed the stop, or the two were emitted in
// the other order) is emitted as `ok` rather than dropped. A Create in that position is dropped
// because guessing its status could invent a read; here the operation is a WRITE either way, and
// over-reporting a write is the direction that cannot break an install. The count is printed.
for (const list of pendingDest.values()) {
  for (const d of list) { stats.destUnmatched++; emitFile(d.op, d.name, d.pid, 'ok', d.pair); }
}
pendingDest.clear();

// The raw payload of the destination events, so the field-name candidate list in DEST_PATH_FIELDS
// is checked against a real trace rather than against anyone's recollection of the manifest.
if (dumpDest) {
  console.error(`\n== --dump-dest: first ${destSamples.length} of events 26/27/28 ==`);
  for (const s of destSamples) {
    console.error(`  id=${s.id} pid=${s.pid} ${JSON.stringify(s.data)}`);
  }
  console.error('');
}

// ⛔ THE RESOLVED MAP IS PERSISTED HERE, AFTER THE WHOLE STREAM HAS BEEN WALKED, so it covers every
// 8.3 component this trace actually contains rather than whatever a partial pass happened to reach.
// This is the ONLY moment the map can be built: it needs the trace (to know which names to ask
// about) and the live capture host (to answer). Writing it is what turns a perishable, host-local
// fact into an archived one — every later decode, on any machine, reads this file and touches no
// filesystem. `windows-retain.mjs` picks it up from the same capture directory with no extra wiring.
if (shortNames.mode === 'resolve') {
  const f = val('--shortnames') ?? path.join(dir, SHORT_NAMES_FILE);
  const written = writeShortNames(f, shortNames.record, meta);
  console.error(`windows.mjs: wrote ${path.basename(f)} — ${Object.keys(written.entries).length} 8.3 components resolved on ${written.host}`);
}

// ---------------------------------------------------------------------------------------------
// Output. NDJSON is the contract; --summary is an eyeball view shaped like the Linux extractor's.
// ---------------------------------------------------------------------------------------------
if (!wantSummary) {
  const ndjson = out.map((e) => JSON.stringify(e)).join('\n') + (out.length ? '\n' : '');
  if (outFile) fs.writeFileSync(outFile, ndjson, 'utf8');
  else process.stdout.write(ndjson);
  console.error(`windows.mjs: ${stats.events} trace events -> ${stats.emitted} normalized events ` +
    `(denied ${stats.denied}, failed-not-refused ${stats.skippedFailed}, unresolved handles ` +
    `${stats.unresolvedHandle}, thread-reattributed ${stats.reattributedByThread}, orphan creates ${stats.orphanCreate})`);
  console.error(`windows.mjs: destination paths ${stats.destResolved} resolved from payload, ` +
    `${stats.destUnresolved} unresolvable, ${stats.destUnmatched} emitted without an OperationEnd` +
    `  |  8.3 names ${stats.shortExpanded} paths expanded, ${stats.shortUnexpanded} kept short` +
    `, ${stats.shortUnmapped} not covered by the archived map` +
    `  [${shortNames.mode}: ${shortNames.reason}]`);
  // ⛔ AN INCOMPLETE MAP IS A DIFFERENT FAILURE FROM NO MAP, AND IT IS THE ONE THAT LOOKS FINE. A
  // path the map does not cover keeps its short spelling and falls to the `outside` scope, which is
  // reported and never granted — an under-grant. Naming it here is what stops it reading as an
  // ordinary "kept short".
  if (stats.shortUnmapped > 0) {
    console.error(`windows.mjs: !! ${stats.shortUnmapped} paths contained an 8.3 component the archived map does not cover;`
      + ' this archive\'s map is INCOMPLETE and those paths keep the short spelling. Re-run the'
      + ' capture-host resolution pass (--resolve-shortnames) against the original capture directory.');
  }
  if (meta.fileMask && meta.fileMask.toUpperCase() !== '0X1FF0') {
    console.error(`windows.mjs: !! this capture used Kernel-File mask ${meta.fileMask}, not 0x1FF0 -- events 26/27/28` +
      ' were never written, so RENAME and HARDLINK DESTINATIONS ARE MISSING from this stream.');
  } else if (!meta.fileMask) {
    console.error('windows.mjs: !! meta.json names no fileMask -- this capture predates the 0x1FF0 widening, so' +
      ' rename and hardlink destinations are missing and nothing in the stream marks their absence.');
  }
} else {
  const w = new Set(), r = new Set(), d = new Set(), h = new Set(), x = new Set();
  for (const e of out) {
    if (e.op === 'connect') { h.add(`${e.host}:${e.port}`); continue; }
    if (e.op === 'exec') { x.add(e.path); continue; }
    if (e.result === 'denied') d.add(`${e.op} ${e.path}`);
    else (e.op === 'write' ? w : r).add(e.path);
  }
  const show = (label, s, n = 40) => {
    console.log(`== ${label} ==`);
    console.log(`  distinct: ${s.size}`);
    [...s].slice(0, n).forEach((v) => console.log(`      ${v}`));
    if (s.size > n) console.log(`      ... ${s.size - n} more`);
  };
  console.log(`== CAPTURE ==\n  user ${meta.whoami}  elevated ${meta.elevated}  rootPid ${meta.rootPid}  ` +
    `exit ${meta.exitCode}  events ${meta.eventsTotal}  lost ${meta.eventsLost}`);
  console.log(`  privileges removed before the run: ${JSON.stringify(meta.privDropped)}`);
  show('PROCESSES EXECUTED', x);
  show('WRITES', w);
  show('READS', r, 15);
  show('NETWORK PEERS', h);
  show('REFUSALS (STATUS_ACCESS_DENIED and friends only)', d);
}
