// Windows god-mode observation adapter, parse half: an ETW trace in, the normalized event stream
// out. Pair this with windows.ps1, which produced the capture directory.
//
// THE ADAPTER IS THIN ON PURPOSE. It emits op/path/host/port/result/pid/ppid and nothing else. No
// scope assignment, no grant lattice, no sentinels -- all of that lives in the shared classifier so
// three platforms cannot drift apart. A thing this adapter cannot express, it omits.
//
//   usage: node windows.mjs <capture-dir> [--out FILE] [--summary] [--allow-lossy]
//          <capture-dir>/meta.json  + <capture-dir>/trace.xml   (both written by windows.ps1)
//
// Prefer --out to a shell redirect. Windows PowerShell's `>` writes UTF-16LE with a BOM, so
// `node windows.mjs ... > events.ndjson` produces a file that PowerShell reads back happily and
// JSON.parse rejects on the first byte.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

const args = process.argv.slice(2);
const outIdx = args.indexOf('--out');
const outFile = outIdx >= 0 ? args[outIdx + 1] : null;
const dir = args.filter((a, i) => !a.startsWith('--') && i !== outIdx + 1).find(Boolean);
const wantSummary = args.includes('--summary');
const allowLossy = args.includes('--allow-lossy');
if (!dir) { console.error('usage: windows.mjs <capture-dir> [--out FILE] [--summary] [--allow-lossy]'); process.exit(2); }

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
  for (const [dev, letter] of devices) {
    if (nt === dev) return letter + '\\';
    if (nt.startsWith(dev + '\\')) return letter + nt.slice(dev.length);
  }
  return nt;
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
const MUTATORS = new Set([EV.SET_INFORMATION, EV.SET_DELETE, EV.RENAME, EV.DELETE_PATH, EV.RENAME_PATH, EV.SET_LINK_PATH]);

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
const emitted = new Set();                              // the contract has no timestamp, so two
                                                        // identical tuples are indistinguishable
const stats = {
  events: 0, emitted: 0, unresolvedHandle: 0, orphanCreate: 0, reattributedByThread: 0,
  skippedFailed: 0, denied: 0,
};

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

function emitFile(op, ntPath, pid, result) {
  const p = dosPath(ntPath);
  // Omit rather than guess: an unnamed handle, or a process whose parent we never saw, cannot fill
  // the contract's fields honestly.
  if (!p || p === '\\FI_UNKNOWN') return;
  const ppid = parentOf.get(pid);
  if (ppid === undefined) return;
  emit({ op, path: p, result, pid, ppid });
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
    if (!pend) continue;
    pendingIrp.delete(data.Irp);
    const status = parseInt(data.Status, 16) >>> 0;
    if (ntSuccess(status)) { emitFile(pend.op, pend.name, pend.pid, 'ok'); continue; }
    if (REFUSAL_STATUS.has(status)) { stats.denied++; emitFile(pend.op, pend.name, pend.pid, 'denied'); continue; }
    stats.skippedFailed++;                              // failed for a reason that is not a refusal
    continue;
  }

  if (id === EV.CLOSE) { if (data.FileObject) nameByObject.delete(data.FileObject); continue; }

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
