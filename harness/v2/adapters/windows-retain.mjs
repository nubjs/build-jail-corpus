// Windows RETENTION adapter: an ETW capture directory in, a re-parseable archive out.
//
// WHY THIS EXISTS SEPARATELY FROM `windows.mjs`. windows.mjs is the SYNTHESIS decoder — it feeds
// classify.mjs, which produces the grant a VERIFY arm is measured against, and it is "thin on
// purpose": op/path/result/pid/ppid and nothing else. That is the wrong shape for RETENTION, whose
// whole point is that a grant model we have not designed yet can be re-derived from what we kept.
// So this file is a SECOND, INDEPENDENT decode of the same capture whose output no arm reads.
// Retention must not be able to move a verdict, and the cheapest way to guarantee that is for the
// verdict to be computed first, by a different decoder, from state this file never touches. Same
// argument, same placement and the same non-fatal failure mode as the Linux lane's `linux.mjs`.
//
// ── THE ARTIFACT OF RECORD IS THE RAW ETW OUTPUT, NOT THIS FILE'S OPINION OF IT ─────────────────
//
// Two artifacts land per record, and their standing is NOT equal:
//
//   etw-raw.xml.gz     THE ARTIFACT OF RECORD. tracerpt's XML, gzipped byte-for-byte, nothing
//                      added, nothing dropped, nothing normalized. Every event the session
//                      delivered, including the ones this file's derived view filters out and the
//                      ones no decoder here has ever looked at.
//   events.ndjson.gz   A CONVENIENCE VIEW, regenerable from the raw at any time. Queryable, shaped
//                      after the Linux retained log so one reader handles both. It is NOT a
//                      contract and it must never constrain what the raw keeps.
//
// ⛔ THE DERIVED VIEW IS ALLOWED TO BE LOSSY; THE RAW IS NOT. Where this file dedups, aggregates or
// filters below, the loss is bounded by "re-gunzip the raw and parse it again". Where a platform
// canonicalizes onto one cross-OS wire format, that loss is PERMANENT — which is the thing this
// design exists to refuse. Measured precedent, both of which a raw archive would have made a
// re-parse rather than a re-measure: the Linux decoder retained 18 of 27 known writes before it was
// fixed, and the macOS dtrace adapter lost 100% of its rename destinations for its entire life.
//
// ⛔ AND IT MAY NOT BAKE IN TODAY'S ANSWERS. No scope tags, no grant lattice, no "outside" bucket:
// those are the current classifier's opinion, and a log carrying only the opinion forces a
// RE-MEASURE to adopt a scope that did not exist when the corpus was measured. The header carries
// the ROOTS and the DEVICE MAP instead, which is what lets any future classifier recompute them.
//
// ── WHAT ETW GIVES US THAT NO OTHER PLATFORM'S SCHEMA CAN EXPRESS ───────────────────────────────
//
// Recorded here on purpose, and deliberately NOT trimmed to the intersection of the three lanes:
//
//   * THE FULL NTSTATUS, on every operation, success or failure. windows.mjs keeps four refusal
//     codes and DROPS everything else (`stats.skippedFailed`) — correct for a grant, and the reason
//     a probe for a file that is not there vanishes. Retention keeps the raw 32-bit status, so
//     STATUS_SHARING_VIOLATION and STATUS_DELETE_PENDING — which have no POSIX errno at all —
//     survive, and so does the far more useful "what did this package LOOK for and not find".
//   * THE CREATE DISPOSITION AND OPTIONS, raw. Windows open semantics are not `O_*`:
//     FILE_SHARE_DELETE, FILE_DELETE_ON_CLOSE and FILE_FLAG_BACKUP_SEMANTICS have no POSIX
//     spelling, and the last one is load-bearing on this harness (see windows.ps1's privilege drop).
//   * THE INFOCLASS on a SetInformation. windows.mjs lumps every mutator into `write`; the InfoClass
//     is what separates a rename from a delete from a timestamp touch from an EOF truncation.
//   * PER-OPERATION I/O SIZE AND OFFSET. `linux.mjs` states plainly that per-operation history is
//     NOT recoverable there — `-e trace=file` never subscribes to `write` — so writes are inferred
//     from an open's flags. ETW delivers the byte count of every read and write.
//   * IRP CORRELATION. Request and completion are separate events joined by an Irp pointer, so an
//     operation's outcome is a fact rather than an assumption. strace's unfinished/resumed pair is
//     the nearest analogue and the Linux adapter joins and discards it.
//   * TWO ON-DISK SPELLINGS FOR ONE FILE. NTFS 8.3 short names have no POSIX analogue; see `fx`.
//   * THE NT DEVICE NAMESPACE plus the QueryDosDevice map. `\Device\HarddiskVolume3\...` is a
//     different namespace from `C:\...`, not a different spelling, and the map is a per-boot fact
//     that only exists at capture time.
//   * KERNEL OBJECT IDENTITY (FileObject / FileKey) — the kernel's own handle-to-name binding.
//   * DEFERRED-I/O ATTRIBUTION. `IssuingThreadId` names the requester when the filesystem completes
//     work on a system worker thread, so an operation can be billed to the process that asked for
//     it rather than to System.
//   * ALTERNATE DATA STREAMS, which arrive as `file:stream:$DATA` — a path shape POSIX cannot form.
//
//   usage: node adapters/windows-retain.mjs <capture-dir> --raw-out FILE.gz --out FILE.ndjson.gz
//                                           [--project D] [--home D] [--jail-home D]
//                                           [--pkg N] [--version V] [--no-longpath] [--summary]
//
// `--out` / `--raw-out` ending in `.gz` are gzipped. Prefer it, and never name either `*.log`: the
// repo's `.gitignore` carries a bare `*.log`, so a file named that is dropped SILENTLY at `git add`
// while looking perfectly present on the runner's disk.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { pathToFileURL, fileURLToPath } from 'node:url';

export const RETAIN_SCHEMA = 1;

// ── The Kernel-File event table ─────────────────────────────────────────────────────────────────
//
// ⛔ NAMED, NOT FILTERED. windows.mjs subscribes to the seven events a grant needs; this table
// exists so every event the provider emits gets a READABLE name in the derived view rather than
// being dropped for not being interesting to today's model. An id with no entry is retained under
// its number — an unnamed event is still an event, and the mask may widen again.
const FILE_EVENT = {
  10: 'NameCreate', 11: 'NameDelete', 12: 'Create', 13: 'Cleanup', 14: 'Close', 15: 'Read',
  16: 'Write', 17: 'SetInformation', 18: 'SetDelete', 19: 'Rename', 20: 'DirEnum',
  21: 'Flush', 22: 'QueryInformation', 23: 'FSControl', 24: 'OperationEnd', 25: 'DirNotify',
  26: 'DeletePath', 27: 'RenamePath', 28: 'SetLinkPath', 29: 'Rename29', 30: 'CreateNewFile',
  31: 'SetSecurity', 32: 'QuerySecurity', 33: 'SetEA', 34: 'QueryEA',
};
const EV = {
  NAME_CREATE: 10, NAME_DELETE: 11, CREATE: 12, CLEANUP: 13, CLOSE: 14, READ: 15, WRITE: 16,
  SET_INFORMATION: 17, SET_DELETE: 18, RENAME: 19, DIR_ENUM: 20, QUERY_INFORMATION: 22,
  OPERATION_END: 24, DELETE_PATH: 26, RENAME_PATH: 27, SET_LINK_PATH: 28, CREATE_NEW_FILE: 30,
};

// Events whose path lives in the PAYLOAD rather than behind a handle. The same three windows.mjs
// calls out: for a RenamePath the FileObject still names the SOURCE, so the ordinary handle lookup
// returns the source and the destination is lost with nothing in the stream saying so.
const DEST_PATH_EVENTS = new Set([EV.DELETE_PATH, EV.RENAME_PATH, EV.SET_LINK_PATH]);
const DEST_KIND = { [EV.RENAME_PATH]: 'rename', [EV.SET_LINK_PATH]: 'hardlink', [EV.DELETE_PATH]: 'delete' };
const DEST_PATH_FIELDS = ['FilePath', 'FileName', 'NewPath', 'TargetName', 'Path'];
// Handle-based operations: the path is not in the payload, it comes from the tables Create and
// NameCreate built. Retention keeps the read-only ones too — a directory enumeration and a
// metadata query are things the package DID, and a future model may need them.
const HANDLE_OPS = new Set([EV.READ, EV.WRITE, EV.SET_INFORMATION, EV.SET_DELETE, EV.RENAME,
  EV.DIR_ENUM, EV.QUERY_INFORMATION, EV.CLEANUP]);

// FILE_OPEN is the one disposition that promises not to modify. Kept as a NUMBER on the event
// rather than folded into a read/write boolean — the boolean is today's model, the number is what
// the kernel said.
const FILE_OPEN = 1;

// Only OUTBOUND initiations are connects, but retention keeps every Kernel-Network event and marks
// which ones today's model would call a connect. Data-sent on an established socket says nothing a
// connect has not, until the day someone asks about egress VOLUME.
const NET_CONNECT = new Set([12, 28, 42, 58]);

const isAbsoluteish = (s) => /^\\/.test(s) || /^[A-Za-z]:[\\/]/.test(s);

// ────────────────────────────────────────────────────────────────────────────────────────────────

export function makeDosPath(devmap) {
  // Longest device first: `\Device\HarddiskVolume1` must not shadow `\Device\HarddiskVolume10`.
  const devices = Object.entries(devmap ?? {}).sort((a, b) => b[0].length - a[0].length);
  return function dosPath(nt) {
    if (!nt) return null;
    // `\??\C:\x` is the object manager's DosDevices spelling of `C:\x` — the same file in a
    // different namespace prefix, not a different file. The destination events can hand back
    // either spelling depending on how the caller built the target name.
    if (nt.startsWith('\\??\\')) nt = nt.slice(4);
    for (const [dev, letter] of devices) {
      if (nt === dev) return letter + '\\';
      if (nt.startsWith(dev + '\\')) return letter + nt.slice(dev.length);
    }
    // A device with no mapping is passed through VERBATIM. A named pipe or a UNC share is a real
    // touch, and inventing a drive letter for it would be a fabricated fact.
    return nt;
  };
}

// ── 8.3 SHORT NAMES, and why retention keeps BOTH spellings ─────────────────────────────────────
//
// NTFS keeps a second legacy spelling for a name that does not fit 8.3, and the kernel reports
// whichever spelling the CALLER used. On a GitHub runner `%TEMP%` is literally
// `C:\Users\RUNNER~1\AppData\Local\Temp`, so the same directory arrives under two names.
//
// ⛔ THE EXPANSION IS PERISHABLE AND THE RAW SPELLING IS PERMANENT, SO THE LOG CARRIES BOTH.
// Expanding needs the name to STILL EXIST on the SAME HOST — false for a deleted temp file, false
// for anyone re-reading this archive later, and false on every other machine. So it can only ever
// be done here, at capture time, and never during the re-parse this whole archive exists to enable.
// But an expansion is also a GUESS the moment either precondition slips. Recording `f` as the
// kernel's own spelling and `fx` as the expansion keeps the honest fact and the perishable one
// separable: a re-parse that distrusts `fx` can ignore it, and one that needs a long name has it.
// windows.mjs by contrast REPLACES the path, because a classifier needs exactly one spelling.
const SHORT_COMPONENT = /^[^\\/.]{1,8}~\d+(\.[^\\/.]{1,3})?$/;

export function makeExpander(enabled, stats) {
  const cache = new Map();
  const expandComponent = (parent, comp) => {
    const key = `${parent}\\${comp}`.toLowerCase();
    if (cache.has(key)) return cache.get(key);
    let out = null;
    try {
      const real = fs.realpathSync.native(`${parent}\\${comp}`);
      const leaf = path.win32.basename(real);
      // Accept ONLY a same-parent rename. A junction or symlink resolves elsewhere, and rewriting
      // the path to its target would silently move the operation to a different location.
      if (leaf && path.win32.dirname(real).toLowerCase() === parent.toLowerCase()) out = leaf;
    } catch { /* gone, or unreachable: there is no long name to be had */ }
    cache.set(key, out);
    return out;
  };
  return function expand(p) {
    if (!enabled || !p || !p.includes('~') || !/^[A-Za-z]:\\/.test(p)) return null;
    const parts = p.split('\\');
    let cur = parts[0];
    let changed = false, failed = false;
    for (let i = 1; i < parts.length; i++) {
      const seg = parts[i];
      if (!seg) continue;
      if (!SHORT_COMPONENT.test(seg)) { cur = `${cur}\\${seg}`; continue; }
      const long = expandComponent(cur, seg);
      if (long === null) { failed = true; cur = `${cur}\\${seg}`; continue; }
      if (long !== seg) changed = true;
      cur = `${cur}\\${long}`;
    }
    if (failed) stats.shortUnexpanded++;
    if (!changed) return null;
    stats.shortExpanded++;
    // Put back a trailing separator the component walk dropped; the kernel emits a directory both
    // with and without one and folding those is a downstream normalizer's job, not this file's.
    if (p.endsWith('\\') && !cur.endsWith('\\')) cur += '\\';
    return cur;
  };
}

// ── The decoder ─────────────────────────────────────────────────────────────────────────────────
//
// ⛔ STREAMED, NOT `readFileSync`. A real install trace runs to hundreds of megabytes of XML and
// would blow V8's string cap. `decodeLines` takes an async line iterator so the CLI can stream a
// file and the tests can pass an array — the tests then exercise the SAME code path, which is the
// only way a known-answer fixture proves anything about the real thing.
export async function decodeLines(lines, opts = {}) {
  const meta = opts.meta ?? {};
  const dosPath = makeDosPath(meta.devmap);
  const stats = {
    xmlEvents: 0, kept: 0, distinct: 0, byProvider: {}, unknownFileEvent: {},
    unresolvedHandle: 0, unsettled: 0, reattributedByThread: 0, outOfSubtree: 0,
    destResolved: 0, destUnresolved: 0, shortExpanded: 0, shortUnexpanded: 0,
  };
  const expand = makeExpander(opts.expandShort === true, stats);

  const ROOT = meta.rootPid;
  const parentOf = new Map(meta.rootPid != null ? [[meta.rootPid, meta.launcherPid ?? null]] : []);
  const subtree = new Map();
  const tidToPid = new Map();
  const nameByObject = new Map();     // FileObject -> NT path (from Create)
  const nameByKey = new Map();        // FileKey    -> NT path (from NameCreate)
  const procs = new Map();            // pid -> the full ProcessStart payload, verbatim
  const pendingIrp = new Map();       // Irp -> the single request awaiting its OperationEnd
  const pendingDest = new Map();      // Irp -> [destination requests awaiting the same status]
  const events = new Map();           // dedup key -> event with a repeat count

  // Only POSITIVE ancestry is memoized. A negative is provisional — the ProcessStart supplying the
  // missing link may not have been read yet — and caching it silently drops a whole grandchild's
  // worth of events.
  const inSubtree = (pid) => {
    if (ROOT == null) return true;
    if (subtree.get(pid)) return true;
    const chain = [];
    const seen = new Set();
    let cur = pid;
    while (cur !== undefined && cur !== null && !seen.has(cur)) {
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
  };

  // ⛔ DEDUP + AGGREGATE, AND THE LOSS IS BOUNDED BY THE RAW ARCHIVE. A real install emits hundreds
  // of thousands of Read events against the same handful of files; one line each would make the
  // derived view larger than the raw XML it is a convenience for. So identical (pid, event, path,
  // status, disposition) tuples collapse to one line with a count, and the two things a count
  // cannot carry — total bytes moved and the time span — are ACCUMULATED rather than dropped.
  // Per-operation ordering and offsets are the price, and they are in `etw-raw.xml.gz`.
  const emit = (e, io) => {
    const key = `${e.p}\u0000${e.o}\u0000${e.f ?? ''}\u0000${e.g ?? ''}\u0000${e.st ?? ''}`
      + `\u0000${e.d ?? ''}\u0000${e.ic ?? ''}`;
    const prior = events.get(key);
    if (prior) {
      prior.n++;
      if (io != null) prior.io = (prior.io ?? 0) + io;
      if (e.ts && (!prior.ts2 || e.ts > prior.ts2)) prior.ts2 = e.ts;
      return;
    }
    e.n = 1;
    if (io != null) e.io = io;
    events.set(key, e);
    stats.distinct++;
  };

  const record = (o) => {
    stats.kept++;
    const dos = dosPath(o.name);
    if (!dos || dos === '\\FI_UNKNOWN') { stats.unresolvedHandle++; return; }
    const e = {
      k: 'e', p: o.pid, o: o.op, s: o.ev, f: dos,
      st: o.status === null || o.status === undefined ? null : `0x${o.status.toString(16).padStart(8, '0')}`,
    };
    if (o.status === undefined) { e.st = null; e.uns = 1; stats.unsettled++; }
    const fx = expand(dos);
    if (fx) e.fx = fx;
    if (o.other) {
      const od = dosPath(o.other);
      if (od && od !== dos) {
        e.g = od;
        const gx = expand(od);
        if (gx) e.gx = gx;
        if (o.kind) e.kind = o.kind;
      }
    }
    if (o.disposition != null) e.d = o.disposition;
    if (o.createOptions) e.co = o.createOptions;
    if (o.shareAccess) e.sa = o.shareAccess;
    if (o.infoClass != null && o.infoClass !== '') e.ic = o.infoClass;
    if (o.tid) e.t = o.tid;
    if (o.ts) e.ts = o.ts;
    if (o.fileAttributes) e.fa = o.fileAttributes;
    emit(e, o.io);
  };

  const settle = (o, status) => record({ ...o, status });

  // Split on event boundaries rather than reading the file whole. A `<Event ...>...</Event>` that
  // arrives on ONE line is handled too: tracerpt wraps, but the tests feed literal lines and a
  // reader that only worked on wrapped input would make every fixture a different code path from
  // the real thing.
  let block = null;
  for await (const line of lines) {
    if (line.includes('<Event ')) block = [line];
    else if (block !== null) block.push(line);
    else continue;
    if (!line.includes('</Event>')) continue;

    const xml = block.join('\n');
    block = null;
    stats.xmlEvents++;

    const idm = /<EventID[^>]*>(\d+)<\/EventID>/.exec(xml);
    const pm = /<Provider Name="([^"]+)"/.exec(xml);
    if (!idm || !pm) continue;
    const id = +idm[1];
    const provider = pm[1];
    stats.byProvider[provider] = (stats.byProvider[provider] ?? 0) + 1;

    const ex = /ProcessID="(\d+)" ThreadID="(\d+)"/.exec(xml);
    let pid = ex ? +ex[1] : -1;
    const tid = ex ? +ex[2] : -1;
    const ts = /<TimeCreated SystemTime="([^"]+)"/.exec(xml)?.[1] ?? null;

    const data = {};
    for (const m of xml.matchAll(/<Data Name="([^"]+)">([^<]*)<\/Data>/g)) data[m[1]] = m[2].trim();

    // ETW events are PER-THREAD. The header PID is right for a synchronous request, but I/O the
    // filesystem completes on a system worker thread carries the System process in the header while
    // IssuingThreadId still names the requester. Every event header is a free (tid -> pid) fact.
    if (pid > 0 && tid > 0) tidToPid.set(tid, pid);
    const issuing = data.IssuingThreadId ? +data.IssuingThreadId : null;
    if (issuing && issuing !== tid && tidToPid.has(issuing)) {
      const real = tidToPid.get(issuing);
      if (real !== pid) { pid = real; stats.reattributedByThread++; }
    }

    if (provider === 'Microsoft-Windows-Kernel-Process') {
      if (id === 1) {
        const child = +data.ProcessID, par = +data.ParentProcessID;
        parentOf.set(child, par);
        // ⛔ THE WHOLE PAYLOAD, VERBATIM. Process events number in the dozens, so keeping every
        // field the provider publishes costs nothing and settles the "does this build carry
        // CommandLine / PackageFullName / the elevation type" question by EVIDENCE at re-parse
        // time rather than by anyone's recollection of the manifest today.
        if (inSubtree(child)) {
          procs.set(child, { k: 'p', pid: child, ppid: par, ts, life: 1, data });
        }
      } else if (id === 2) {
        tidToPid.forEach((v, kk) => { if (v === +data.ProcessID) tidToPid.delete(kk); });
        const p = procs.get(+data.ProcessID);
        if (p) { p.endTs = ts; if (data.ExitStatus != null) p.exit = data.ExitStatus; }
      }
      continue;
    }

    if (provider === 'Microsoft-Windows-Kernel-Network') {
      // The header PID is 0 on the receive path (a DPC, not the owning process); the payload PID is
      // the authoritative one for this provider.
      const npid = data.PID ? +data.PID : pid;
      if (!inSubtree(npid)) { stats.outOfSubtree++; continue; }
      const e = {
        k: 'e', p: npid, o: 'net', s: `net${id}`,
        h: data.daddr ?? null, pt: data.dport ? +data.dport : null,
        sh: data.saddr ?? null, spt: data.sport ? +data.sport : null,
        conn: NET_CONNECT.has(id) ? 1 : 0, st: null,
      };
      if (ts) e.ts = ts;
      emit(e, data.size ? +data.size : null);
      stats.kept++;
      continue;
    }

    if (provider !== 'Microsoft-Windows-Kernel-File') continue;
    if (!FILE_EVENT[id]) stats.unknownFileEvent[id] = (stats.unknownFileEvent[id] ?? 0) + 1;
    const evName = FILE_EVENT[id] ?? `File${id}`;

    // The name tables. NameCreate is the kernel's filename rundown emitted by System — a
    // (FileKey -> name) FACT, never an access. Treating it as one would report a read of every file
    // merely enumerated in a directory listing.
    if (id === EV.NAME_CREATE) { if (data.FileKey && data.FileName) nameByKey.set(data.FileKey, data.FileName); continue; }
    if (id === EV.NAME_DELETE) { if (data.FileKey) nameByKey.delete(data.FileKey); continue; }

    if (id === EV.CREATE || id === EV.CREATE_NEW_FILE) {
      if (data.FileObject && data.FileName) nameByObject.set(data.FileObject, data.FileName);
      if (!inSubtree(pid)) { stats.outOfSubtree++; continue; }
      if (!data.FileName) continue;
      const co = parseInt(data.CreateOptions, 16);
      const disposition = Number.isNaN(co) ? null : (co >>> 24) & 0xff;
      const req = {
        op: disposition === FILE_OPEN ? 'open-r' : 'open-w', ev: evName, name: data.FileName,
        pid, tid, ts, disposition, createOptions: data.CreateOptions ?? null,
        shareAccess: data.ShareAccess ?? null, fileAttributes: data.FileAttributes ?? null,
      };
      // ⛔ Irp POINTERS ARE REUSED BACK TO BACK, so the pairing is nearest-in-time and consuming; a
      // global Irp map attaches the wrong status to the wrong open. Unlike windows.mjs, a request
      // that is EVICTED by a later one is still RECORDED — with its status marked unknown. Dropping
      // it is right for a grant (a status you had to guess could invent a read) and wrong for
      // retention, where the operation demonstrably happened and only its outcome is missing.
      const displaced = pendingIrp.get(data.Irp);
      if (displaced) record({ ...displaced, status: undefined });
      pendingIrp.set(data.Irp, req);
      continue;
    }

    if (id === EV.OPERATION_END) {
      const pend = pendingIrp.get(data.Irp);
      const dests = pendingDest.get(data.Irp);
      if (!pend && !dests) continue;
      pendingIrp.delete(data.Irp);
      pendingDest.delete(data.Irp);
      const status = parseInt(data.Status, 16) >>> 0;
      // ⛔ EVERY STATUS IS KEPT, NOT JUST THE FOUR REFUSALS. This is the single biggest difference
      // from the synthesis decoder and the main reason a re-parse can answer questions today's
      // grant model cannot ask — "what did this package probe for and fail to find" is a
      // STATUS_OBJECT_NAME_NOT_FOUND, which windows.mjs discards by design.
      if (pend) settle(pend, status);
      if (dests) for (const d of dests) settle(d, status);
      continue;
    }

    if (id === EV.CLOSE) { if (data.FileObject) nameByObject.delete(data.FileObject); continue; }

    // DESTINATION PATHS, handled before the handle branch because the payload path — not the
    // FileObject — is the authoritative one here.
    if (DEST_PATH_EVENTS.has(id)) {
      if (!inSubtree(pid)) { stats.outOfSubtree++; continue; }
      const source = nameByObject.get(data.FileObject) ?? nameByKey.get(data.FileKey) ?? null;
      let dest = null;
      for (const f of DEST_PATH_FIELDS) { if (data[f]) { dest = data[f]; break; } }
      // A destination may arrive RELATIVE — a bare leaf, when the caller set RootDirectory on the
      // rename information. A leaf can only mean the SOURCE's directory; anything else is left
      // alone rather than anchored to a guess.
      if (dest && !isAbsoluteish(dest)) {
        const cut = source ? source.lastIndexOf('\\') : -1;
        dest = cut > 0 ? `${source.slice(0, cut)}\\${dest}` : null;
      }
      const name = dest ?? source;
      if (!name) { stats.destUnresolved++; continue; }
      if (dest) stats.destResolved++;
      // ⛔ BOTH ENDS ON ONE RECORD. A hard link creates a SECOND NAME for existing content, so
      // afterwards two live paths reach the same bytes; emitting the two names as unrelated records
      // loses which link went with which target the moment two operations interleave. The Linux
      // retained log keeps both ends as `f`/`g` for the same reason.
      const req = { op: 'dest', ev: evName, name, other: source, kind: DEST_KIND[id], pid, tid, ts,
        infoClass: data.InfoClass ?? null };
      if (!data.Irp) { record({ ...req, status: null }); continue; }
      const list = pendingDest.get(data.Irp);
      if (list) list.push(req); else pendingDest.set(data.Irp, [req]);
      continue;
    }

    if (HANDLE_OPS.has(id)) {
      if (!inSubtree(pid)) { stats.outOfSubtree++; continue; }
      const name = nameByObject.get(data.FileObject) ?? nameByKey.get(data.FileKey) ?? data.FileName;
      if (!name) { stats.unresolvedHandle++; continue; }
      const op = id === EV.READ ? 'read' : id === EV.WRITE ? 'write'
        : id === EV.DIR_ENUM ? 'direnum' : id === EV.QUERY_INFORMATION ? 'query'
        : id === EV.CLEANUP ? 'cleanup' : 'setinfo';
      // The byte count of THIS operation — the field ETW gives that no other lane has at all. It is
      // absent on the events that move no bytes, which is why it is conditional rather than 0.
      const io = data.IOSize != null && data.IOSize !== '' ? Number(data.IOSize) : NaN;
      const req = { op, ev: evName, name, pid, tid, ts, infoClass: data.InfoClass ?? null,
        io: Number.isFinite(io) ? io : undefined };
      if (!data.Irp) { record({ ...req, status: null }); continue; }
      const displaced = pendingIrp.get(data.Irp);
      if (displaced) record({ ...displaced, status: undefined });
      pendingIrp.set(data.Irp, req);
    }
  }

  // Anything still pending never got its OperationEnd — the trace stopped first, or the two events
  // were emitted in the other order. RECORDED with an unknown status and COUNTED, never dropped:
  // the operation happened, and only its outcome is missing.
  for (const req of pendingIrp.values()) record({ ...req, status: undefined });
  for (const list of pendingDest.values()) for (const d of list) record({ ...d, status: undefined });

  return { procs: [...procs.values()].sort((a, b) => a.pid - b.pid), events: [...events.values()], stats };
}

export function serialize(decoded, header) {
  const out = [JSON.stringify({ k: 'h', v: RETAIN_SCHEMA, ...header, stats: decoded.stats })];
  for (const p of decoded.procs) out.push(JSON.stringify(p));
  // Sorted by path then pid: adjacent lines share long prefixes, which is most of why this
  // compresses as well as it does.
  const evs = decoded.events.slice().sort((a, b) =>
    (a.f ?? a.h ?? '').localeCompare(b.f ?? b.h ?? '') || a.p - b.p || a.o.localeCompare(b.o));
  for (const e of evs) out.push(JSON.stringify(e));
  return out.join('\n') + '\n';
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const sizeOf = (p) => { try { return fs.statSync(p).size; } catch { return -1; } };

// ── The re-parse header ─────────────────────────────────────────────────────────────────────────
//
// ⛔ WITHOUT THIS THE ARCHIVE IS A PILE OF STRINGS. Every path in the stream is machine-specific
// (`C:\Users\RUNNER~1\...`) and every path in the RAW is in a namespace (`\Device\HarddiskVolume3`)
// that only the capture-time device map decodes. A reader a year from now needs, and gets:
//
//   roots      what counted as project / home / temp, so a future classifier can recompute scopes
//   devmap     the NT-device -> drive-letter map, which is a per-boot fact queried from the kernel
//   session    buffer geometry and mode — a lossy trace cannot support "no more than this"
//   providers  the exact keyword mask per provider. A keyword bit that is CLEAR is a SILENT filter:
//              at 0x11F0 events 26/27/28 are never written, so rename and hardlink destinations are
//              absent with nothing in the stream saying so. An archive that does not name its mask
//              cannot be re-read with any confidence about what it is missing.
//   tracer     the literal capture and convert invocations, plus a sha256 of the capture SCRIPT, so
//              the exact source that produced this trace can be recovered from git even if the
//              recorded summary here is later found to be incomplete.
//   integrity  eventsLost, and WHERE the number came from. ⛔ Only tracerpt's `Total Events Lost`
//              is trustworthy: `logman query` reported `Buffers Lost 0` on a session that was
//              dropping 62% of its events, and prints no `Events Lost` line at all.
export function buildHeader({ meta, capDir, opts, rawFile, rawBytes, rawGzBytes, rawSha, xmlPath, etlPath }) {
  const scriptPath = path.join(path.dirname(fileURLToPath(import.meta.url)), 'windows.ps1');
  let captureScriptSha = null;
  try { captureScriptSha = sha256(fs.readFileSync(scriptPath)); } catch { /* re-parsed off-host */ }
  const providers = meta.providers ?? (meta.fileMask
    // A capture from before windows.ps1 recorded the whole provider list still names its file mask,
    // which is the one that decides whether destinations exist. Reconstruct what is knowable and
    // leave the rest null rather than asserting the current defaults over an older trace.
    ? [{ name: 'Microsoft-Windows-Kernel-File', keywords: meta.fileMask, level: null, exit: meta.fileMaskExit ?? null }]
    : null);
  return {
    platform: `win32-${process.arch}`,
    pkg: opts.pkg ?? null,
    version: opts.version ?? null,
    at: new Date().toISOString(),
    tracer: {
      kind: 'etw',
      capture: 'harness/v2/adapters/windows.ps1',
      captureScriptSha256: captureScriptSha,
      captureSchema: meta.schema ?? null,
      convert: 'tracerpt <etl> -o <xml> -of XML -summary <sum> -lr -y',
      tracerptExit: meta.tracerptExit ?? null,
      session: meta.session ?? null,
      providers,
    },
    os: { version: meta.os ?? null, host: meta.host ?? null, arch: process.arch },
    identity: {
      whoami: meta.whoami ?? null, sid: meta.sid ?? null,
      elevated: meta.elevated ?? null, privDropped: meta.privDropped ?? null,
    },
    run: {
      command: meta.command ?? null, workDir: meta.workDir ?? null,
      rootPid: meta.rootPid ?? null, launcherPid: meta.launcherPid ?? null,
      exitCode: meta.exitCode ?? null,
      startedUtc: meta.startedUtc ?? null, endedUtc: meta.endedUtc ?? null,
    },
    integrity: {
      eventsTotal: meta.eventsTotal ?? null,
      eventsLost: meta.eventsLost ?? null,
      lostFrom: "tracerpt summary 'Total Events Lost'",
    },
    roots: {
      project: opts.project ?? meta.workDir ?? null,
      home: opts.home ?? meta.userProfile ?? null,
      jailHome: opts.jailHome ?? null,
      temp: meta.temp ?? null,
      ownPkg: opts.pkg && (opts.project ?? meta.workDir)
        ? `${opts.project ?? meta.workDir}\\node_modules\\${opts.pkg.replace(/\//g, '\\')}` : null,
    },
    devmap: meta.devmap ?? null,
    raw: {
      file: rawFile, bytes: rawBytes, gzBytes: rawGzBytes, sha256: rawSha,
      of: path.basename(xmlPath),
      // ⛔ THE ETL IS NOT RETAINED, AND THE ARCHIVE SAYS SO RATHER THAN LEAVING IT AMBIGUOUS. The
      // binary ETL is the most raw form there is, but re-parsing it needs `tracerpt` on a Windows
      // host, which defeats the point of an archive anyone can re-read; the XML is what tracerpt
      // produces from it with `-lr` (keep events whose payload does not match the schema) and it
      // decodes off-Windows with any XML reader. Its size and digest are recorded so a future
      // reader knows exactly what was declined and can compare against a fresh capture.
      etlBytes: sizeOf(etlPath), etlRetained: false,
    },
    derived: {
      file: 'events.ndjson.gz',
      // The one place the derived view's losses are stated. Every item here is recoverable from the
      // raw; nothing here is recoverable from the derived view alone, so a reader who needs one
      // knows to go back to `etw-raw.xml.gz`.
      filter: `subtree of rootPid ${meta.rootPid ?? '?'} (out-of-subtree events are in the raw only)`,
      dedup: 'identical (pid, op, path, path2, status, disposition, infoClass) tuples collapse to '
        + 'one line with a count `n`; `io` sums bytes across them and `ts`/`ts2` bracket the span. '
        + 'Per-operation ordering and file offsets are in the raw only.',
      shortNames: opts.expandShort
        ? '`f` is the kernel spelling; `fx` is an 8.3 expansion done on the capture host'
        : '8.3 expansion OFF — `f` is the kernel spelling and no `fx` is present',
    },
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────────────────────────
//
// ⛔ `pathToFileURL`, NOT `file://${process.argv[1]}`. On Windows argv[1] is `C:\path\x.mjs` while
// import.meta.url is `file:///C:/path/x.mjs`, so the string form NEVER matches and the CLI silently
// does nothing at all — on the one platform this file exists for. `linux.mjs` uses the string form
// and is correct there and only there.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const val = (f, d = null) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
  const flags = new Set(['--out', '--raw-out', '--header-out', '--project', '--home',
    '--jail-home', '--pkg', '--version']);
  const dir = args.find((a, i) => !a.startsWith('--') && !(i > 0 && flags.has(args[i - 1])));
  if (!dir) {
    console.error('usage: windows-retain.mjs <capture-dir> --raw-out F.gz --out F.ndjson.gz'
      + ' [--header-out F.json] [--project D] [--home D] [--jail-home D] [--pkg N] [--version V]');
    process.exit(2);
  }

  const metaPath = path.join(dir, 'meta.json');
  if (!fs.existsSync(metaPath)) { console.error(`windows-retain.mjs: no meta.json in ${dir}`); process.exit(2); }
  const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
  const xmlPath = path.join(dir, 'trace.xml');
  const etlPath = path.join(dir, 'trace.etl');
  if (!fs.existsSync(xmlPath)) { console.error(`windows-retain.mjs: no trace.xml in ${dir}`); process.exit(2); }

  // ⛔ THE RAW GOES FIRST, BEFORE ANY DECODING CAN FAIL. The archive's whole value is that a broken
  // decoder becomes a re-parse; writing the raw only after a successful decode would make the raw
  // hostage to exactly the bug it is insurance against.
  const rawOut = val('--raw-out');
  let rawBytes = -1, rawGzBytes = -1, rawSha = null;
  if (rawOut) {
    rawBytes = sizeOf(xmlPath);
    const gzip = zlib.createGzip({ level: 9 });
    const hash = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
      const rs = fs.createReadStream(xmlPath);
      rs.on('data', (b) => hash.update(b));
      const ws = fs.createWriteStream(rawOut);
      rs.on('error', reject); gzip.on('error', reject); ws.on('error', reject);
      ws.on('finish', resolve);
      rs.pipe(gzip).pipe(ws);
    });
    rawSha = hash.digest('hex');
    rawGzBytes = sizeOf(rawOut);
    console.log(`  RAW       ${path.basename(rawOut)}  ${rawBytes} B xml -> ${rawGzBytes} B gz`
      + ` (${(rawBytes / Math.max(rawGzBytes, 1)).toFixed(1)}x)  sha256 ${rawSha.slice(0, 16)}…`);
  }

  // Expansion is only meaningful on the capture host: `RUNNER~1` names whatever THAT machine had.
  // Re-decoding an archived trace elsewhere gets the short spelling back, honestly, rather than a
  // confident wrong long name.
  const sameHost = (meta.host ?? '').toLowerCase() === (process.env.COMPUTERNAME ?? '').toLowerCase();
  const expandShort = !args.includes('--no-longpath') && process.platform === 'win32' && sameHost && !!meta.host;

  const opts = {
    meta, expandShort,
    project: val('--project'), home: val('--home'), jailHome: val('--jail-home'),
    pkg: val('--pkg'), version: val('--version'),
  };
  const rl = readline.createInterface({ input: fs.createReadStream(xmlPath), crlfDelay: Infinity });
  const decoded = await decodeLines(rl, opts);

  const header = buildHeader({ meta, capDir: dir, opts, rawFile: rawOut ? path.basename(rawOut) : null,
    rawBytes, rawGzBytes, rawSha, xmlPath, etlPath });

  // ⛔ THE HEADER IS WRITTEN TWICE, ON PURPOSE. It is the first line of the derived stream so a
  // reader of that one file needs nothing else — and it is ALSO a standalone `etw-header.json`,
  // because the raw archive is the artifact of record and must be re-parseable on its own. Without
  // the standalone copy, re-parsing `etw-raw.xml.gz` would require the derived view to still exist,
  // which makes the convenience file load-bearing and inverts the whole design. It carries the
  // raw's sha256, so the pair is verifiably matched rather than merely adjacent. ~2 KB.
  const headerOut = val('--header-out');
  if (headerOut) {
    fs.writeFileSync(headerOut, `${JSON.stringify({ k: 'h', v: RETAIN_SCHEMA, ...header, stats: decoded.stats }, null, 2)}\n`);
    console.log(`  HEADER    ${path.basename(headerOut)} (${sizeOf(headerOut)} bytes)`);
  }

  const text = serialize(decoded, header);
  const out = val('--out');
  if (out) {
    fs.writeFileSync(out, out.endsWith('.gz') ? zlib.gzipSync(Buffer.from(text), { level: 9 }) : text);
  } else if (!args.includes('--summary')) {
    process.stdout.write(text);
  }

  const s = decoded.stats;
  console.log(`  DERIVED   ${decoded.events.length} distinct from ${s.kept} kept ops`
    + ` (${s.xmlEvents} xml events, ${s.outOfSubtree} out of subtree)`);
  console.log(`  PROCS     ${decoded.procs.length}   thread-reattributed ${s.reattributedByThread}`);
  if (s.unsettled) console.log(`  ⛔ ${s.unsettled} operations with NO OperationEnd — kept, status marked unknown`);
  if (s.unresolvedHandle) console.log(`  ⛔ ${s.unresolvedHandle} handle ops whose path no table could supply`);
  if (s.destUnresolved) console.log(`  ⛔ ${s.destUnresolved} destination events with no resolvable path`);
  if (expandShort) console.log(`  8.3       ${s.shortExpanded} expanded, ${s.shortUnexpanded} kept short`);
  const unknown = Object.entries(s.unknownFileEvent);
  if (unknown.length) console.log(`  unnamed Kernel-File events: ${unknown.map(([k, v]) => `${k}×${v}`).join(' ')}`);
  if (out) console.log(`  wrote ${path.basename(out)} (${sizeOf(out)} bytes)`);
  if (meta.eventsLost > 0) {
    console.log(`  ⛔ ${meta.eventsLost} EVENTS LOST — this archive cannot support an exact-set claim`);
  }
}
