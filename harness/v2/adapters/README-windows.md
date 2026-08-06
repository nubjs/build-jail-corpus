# Windows adapter

Observation on Windows is a system-wide ETW session plus a PID-subtree filter. The adapter is two halves — `windows.ps1` captures and converts, `windows.mjs` emits the normalized event stream — and it holds to the same contract as the Linux extractor: op, path or host/port, result, pid, ppid, and nothing else.

```powershell
# capture: runs the command under trace, leaves trace.xml + meta.json in the out-dir
powershell -NoProfile -ExecutionPolicy Bypass -File windows.ps1 `
  -OutDir C:\obs\run1 -Command "npm install dprint@0.19.2" -WorkDir C:\obs\proj

# parse: ETW XML -> newline-delimited events
node windows.mjs C:\obs\run1 --out C:\obs\run1\events.ndjson
node windows.mjs C:\obs\run1 --summary        # eyeball view, shaped like observe.mjs

# validate against the known-answer fixture, both directions
node validate-windows.mjs C:\obs\run1\events.ndjson C:\obs\run1 --selftest
```

Use `--out` rather than a shell redirect. Windows PowerShell writes UTF-16LE with a BOM for `>`, which PowerShell reads back happily and `JSON.parse` rejects on the first byte.

## Mechanism, and why

| candidate | verdict |
| --- | --- |
| **ETW via `logman` + `tracerpt`** | **Chosen.** Already on the box, no install, no driver, no download. Manifest providers decode to named fields, so parsing is field access rather than column guessing. Measured 0 events lost on both traces. |
| Process Monitor CSV | Rejected. Needs a Sysinternals download and a kernel driver, and its CSV is a rendered view — write intent arrives as English in a `Detail` column rather than as the disposition integer. |
| A custom ETW consumer | Rejected for a prototype. It is the right answer if `tracerpt` becomes the bottleneck, but it needs the TraceEvent NuGet package and buys nothing yet. |

Three providers, and each is load-bearing:

| provider | keywords | what it supplies |
| --- | --- | --- |
| `Microsoft-Windows-Kernel-File` | `0x1FF0` | Create with the path and disposition, OperationEnd with the NTSTATUS, Read/Write on handles, and — see [Destination paths](#destination-paths) — the destination of a rename, hard link or delete |
| `Microsoft-Windows-Kernel-Network` | `0x30` | TCP and UDP connection attempts with `PID`, `daddr`, `dport` |
| `Microsoft-Windows-Kernel-Process` | `0x10` | ProcessStart with `ParentProcessID` — the only way to follow grandchildren |

The session runs sequential, not circular. A circular buffer silently overwrites the start of the trace, which is where a postinstall's first writes are.

## Read-open versus write-open

Write intent is in the create disposition, which Windows packs into the top byte of `CreateOptions`. Only `FILE_OPEN` is non-mutating.

```
disposition = (CreateOptions >>> 24) & 0xFF

0 SUPERSEDE  2 CREATE  3 OPEN_IF  4 OVERWRITE  5 OVERWRITE_IF   -> write
1 OPEN                                                          -> read
```

Disposition alone under-reports, because a caller may `FILE_OPEN` an existing file and then write to it. So the `Write` event counts as a write too, with its path resolved through the FileObject and FileKey tables that Create and NameCreate build. The mutators `SetInformation`, `SetDelete` and `Rename` are writes as well, and so are `DeletePath`, `RenamePath` and `SetLinkPath` — which resolve their path differently, for the reason below.

## Destination paths

Events 26, 27 and 28 — `DeletePath`, `RenamePath`, `SetLinkPath` — are the only events in this provider that carry a path the handle tables cannot supply: a rename's new name, a hard link's new name, a delete's resolved name. Two independent defects hid all of them, and each masked the other, so the fix had to move both halves together.

**The keyword mask never delivered them.** The session enabled `0x11F0`, whose own comment named nine keywords when it carried six. Decoded on a real runner ([31116467283](https://github.com/nubjs/build-jail-corpus/actions/runs/31116467283)) against the provider's `wevtutil gp Microsoft-Windows-Kernel-File /ge:true` manifest, `WRITE` (`0x200`), `DELETE_PATH` (`0x400`) and `RENAME_SETLINK_PATH` (`0x800`) were clear. A keyword mask is a silent filter — `logman update trace` exits 0 whatever the mask is, and an event whose keyword bit is clear is simply never written — so the parser carried correct handlers for three events that could never fire while the trace looked healthy. `WRITE`'s absence turned out not to matter, because event 16 is published under `WRITE|FILEIO` and `FILEIO` was on; the other two are published under `0x400`/`0x800` alone. The mask is now `0x1FF0`, which is every keyword the provider declares.

**And the decoder preferred the source.** A handle op resolved its path as `nameByObject.get(FileObject) ?? nameByKey.get(FileKey) ?? data.FileName`, and on a `RenamePath` that `FileObject` still names the source. So the source won, the source had already been emitted by the `Rename` event, the dedup set swallowed it, and the destination was absent with nothing in the stream saying so. Measured on the known-answer fixture at both masks: rename destination and hard-link destination absent entirely, identically. Widening the mask alone changed nothing.

For those three events the payload path now wins and the handle tables are a fallback. Measured across both arms of [31118563399](https://github.com/nubjs/build-jail-corpus/actions/runs/31118563399):

| capture mask | decoder | rename destination | hard-link destination | storm | decoy | events lost |
| --- | --- | --- | --- | --- | --- | --- |
| `0x11F0` | shipped | absent | absent | 500/500 | 0 | 0 |
| `0x11F0` | fixed | absent | absent | 500/500 | 0 | 0 |
| `0x1FF0` | shipped | absent | absent | 500/500 | 0 | 0 |
| `0x1FF0` | fixed | **present** | **present** | 500/500 | 0 | 0 |

Three details the fix depends on:

- **`Rename` and `RenamePath` share one Irp**, and the pending-status map is single-valued and last-writer-wins — so routing the destination through it evicts the source and trades one end of the rename for the other. Visible as the orphan-create count going 6 to 25 the moment the widened mask puts events 26/27/28 into that map, and back to 8 once they get their own list-valued one. `harness/v2/adapters/windows.test.mjs` pins it; it is the one case a mutation of that map turns red.
- **The provider publishes no templates**, so the destination field name is read from a candidate list rather than hardcoded. Measured on a real trace it is `FilePath`, and every destination arrived as an absolute NT device path — the relative-leaf branch is defensive and unexercised. Run `windows.mjs <capture-dir> --dump-dest N` to print the raw payload of the first N of these events.
- **`SetLinkPath` needs both ends kept together.** A hard link creates a second name for existing content, so afterwards two live paths reach the same bytes. Both names already reach the stream — the old one as a read from the open that made the link, the new one as a write — but as two unrelated records nothing says which link went with which target, and two interleaved link operations lose the correspondence outright. The event carries both ends at once (`FileObject` resolves to the source, the payload carries the new name), so the destination record keeps the other end as `path2` with a `kind` of `rename`, `hardlink` or `delete`. A delete carries no `path2`, because both ends are the same file.

`path2` and `kind` are additive: `classify.mjs` reads `op`/`path`/`result`/`pid` and `validate-windows.mjs` keys its exact-set on `op|path|result|role`, so neither sees them. The primary `path` stays the destination, which is the end that needs the grant. The Linux retained log bills both ends of a two-path op the same way, as `f`/`g`.

### What this looked like on a real package

Not a fixture artifact. `hugo-extended@0.141.0` writes through node's compile cache, which is an atomic write: a temp file, then a rename into place. Every compile-cache write the harness recorded, before and after, on the same package:

```
BEFORE  write  …\node-compile-cache\…\b9b9bb80.1lvASz     (spelled C:\Users\RUNNER~1\…)
        write  …\node-compile-cache\…\b9b9bb80.1lvASz     (spelled C:\Users\runneradmin\…)

AFTER   write  …\node-compile-cache\…\39e31735.c1peEI
        write  …\node-compile-cache\…\39e31735            path2 …\39e31735.c1peEI  kind rename
```

Both defects in four lines. Before, the harness recorded one temp file **twice** — the same path under two spellings — and never saw `b9b9bb80`, the only name that still exists when the install finishes. After, each file appears once, and the name that persists is recorded along with where it came from.

A capture whose `meta.json` records a mask other than `0x1FF0`, or records none at all, is called out on stderr at decode time. A stream captured before this change has no destinations in it and the events themselves cannot say so, so the meta has to.

This is the same defect class the macOS dtrace adapter carried — 100% of rename destinations lost, for the life of that adapter — reached independently on a different platform by a different mechanism.

## 8.3 short names

NTFS keeps a legacy 8.3 spelling for a name that does not fit, and the kernel reports whichever spelling the caller used. On a GitHub runner `%TEMP%` is literally `C:\Users\RUNNER~1\AppData\Local\Temp` while `%USERPROFILE%` is `C:\Users\runneradmin`, so one directory arrives under two names in one trace.

That is a scope defect, not a cosmetic one, and it under-grants. The classifier assigns scope by longest-prefix against the roots it is handed, and `c:\users\runner~1\...` does not start with `c:\users\runneradmin\`, so a real write under the user profile lands in `outside` — reported, never granted. Measured on the one real package the viability probe traced (`hugo-extended@0.141.0`): 543 paths, 1 write and 542 reads, every one genuinely under the profile and every one classified `outside`.

The adapter expands short to long, never the reverse — contracting would mean inventing a short name, and expanding needs the name to still exist, which is false for a deleted temp file. It walks the path left to right and expands each component against a parent that is already long, so a deleted leaf still lands in the right scope; only its own spelling stays ambiguous. Two guards:

- A resolved component is accepted only when it is still a child of the same parent. Otherwise `realpath` followed a junction, and taking that answer would rewrite the path to a different location.
- Expansion is skipped entirely when the capture came from another host, because `RUNNER~1` names whatever that machine happens to have. Re-decoding an archived trace elsewhere gets the short spelling back rather than a confident wrong long name. `--no-longpath` forces the same.

When expansion fails the short spelling is kept verbatim and counted in the stderr stats. That over-counts distinct paths, which is the safe direction; guessing a long name would be an invented fact.

The known-answer check is `probes/win-viability/shortname-kaf.mjs`: it writes one file through `%TEMP%`, records the long spelling from `realpathSync.native` as ground truth, and asserts the stream reports the long one and only the long one. On [31118563399](https://github.com/nubjs/build-jail-corpus/actions/runs/31118563399) it passes with the fix and fails on the shipped decoder, which emits the same file under both spellings. Over the fixture run, 30 paths expanded and 0 were kept short. The check reports SKIP rather than a pass when `%TEMP%` on the runner carries no 8.3 component, because an assertion with nothing to expand measures nothing.

Only four NTSTATUS values are refusals: `STATUS_ACCESS_DENIED`, `STATUS_PRIVILEGE_NOT_HELD`, `STATUS_MEDIA_WRITE_PROTECTED`, `STATUS_CANNOT_DELETE`. The Windows near-miss is not a string collision like `AT_EACCESS` — it is the temptation to call every non-zero status a denial. A probe for a file that is not there returns `STATUS_OBJECT_NAME_NOT_FOUND`, which means the operation did not happen; those are omitted, matching the Linux extractor skipping `= -1`. On the fixture trace 379 operations failed for a reason that was not a refusal and exactly one was a refusal.

## Elevation

The capture needs an elevated token — ETW kernel providers are administrator-only — and `windows.ps1` asserts both that it has one and that it is not running as SYSTEM.

Elevation also perturbs the measurement, so the adapter removes the perturbation rather than caveating it. Every Node file open sets `FILE_FLAG_BACKUP_SEMANTICS` — libuv's `fs__open` sets it unconditionally, right before `CreateFileW`, so that opening a directory works — and combined with the `SeBackupPrivilege` an elevated token carries, that bypasses the DACL outright. Measured on `nub-win3`, one variable changed:

| token | Node write into a directory with an explicit Deny ACE |
| --- | --- |
| as launched (`SeBackupPrivilege` Enabled) | **succeeded** |
| after `AdjustTokenPrivileges` removes Backup, Restore and TakeOwnership | **refused, EPERM** |

That is not cosmetic. A package that probes a location, is refused, and falls back elsewhere would be observed taking the probe and never the fallback — a grant both wider than needed and missing the need that is real. So `windows.ps1` removes the three privileges before spawning the target and records the result in `meta.json`. ETW is gated on administrator group membership rather than on these, and `logman` create and stop still exit 0 afterwards.

## Validation

The fixture is a three-level process tree — `cmd.exe` → `node.exe` → `powershell.exe` — doing one project write, one userprofile write from the grandchild, one read it never writes, one TCP connect to a pinned peer, and one write into an ACL-denied directory. Two decoys never appear in any correct answer: a file the fixture never touches, and a probe for a file that does not exist.

The exact-set assertion is scoped to `C:\obs\fx`, a namespace the fixture fully controls, so "no more" is checkable rather than aspirational. Captured on `nub-win3` as `nub-win3\nub`:

```
capture: user NUB-WIN3\nub  elevated true  exit 0  events 16470  lost 0
tree:    root 2008 -> child 5432 -> grandchild 2992
stream:  454 normalized events

  [PASS] + P1  project write is reported
  [PASS] + P2  userprofile write is reported, attributed to the GRANDCHILD
  [PASS] + P3  the read-only input is reported as a READ
  [PASS] + P4  the pinned TCP connect is reported, attributed to the GRANDCHILD
  [PASS] + P5  the ACL-denied write is reported as DENIED
  [PASS] + P6  the exec chain is three levels deep (cmd -> node -> powershell)
  [PASS] + P7  the PowerShell Invoke-WebRequest peer is reported (the dprint shape)
  [PASS] - N1  the never-touched decoy appears nowhere
  [PASS] - N2  the missing-file probe is NOT reported (failed != refused)
  [PASS] - N3  the read-only input is never reported as a WRITE
  [PASS] - N4  no connect to a peer the fixture never contacted
  [PASS] - N5  the ACL-denied write is the ONLY refusal
  [PASS] = E1  inside the fixture namespace the emitted set is EXACTLY the expected one

self-test: each positive assertion must FAIL once its evidence is deleted
  [PASS] P1 went red with 1 event(s) removed
  ... P2 through P7 likewise

VALIDATION PASSED
```

The self-test is the part that matters. It deletes each positive assertion's evidence and requires the assertion to go red, because an assertion that stays green without its evidence is measuring nothing. The first version of the parser emitted **zero** events from 16470 — it memoized a negative subtree answer and cached away the seeded root — and the known-answer fixture is what caught it. A version of this note written before that run would have claimed the adapter worked.

## The dprint case

The postinstall of `dprint@0.19.2` is `node ./install.js`, which spawns `powershell.exe` to run `install.ps1`, which does `Invoke-WebRequest` against GitHub releases. A Node-level shim sits at the `install.js` process and cannot see any of it — in an earlier proxy-versus-real-block differential this showed 0 requests at the proxy but 5 files lost under a real block.

The adapter sees the whole thing. Real output, `npm install dprint@0.19.2` on `nub-win3`, 104453 trace events to 2496 normalized events with 0 lost:

```
{"op":"exec","path":"C:\\Windows\\System32\\cmd.exe","result":"ok","pid":2180,"ppid":1160}
{"op":"exec","path":"C:\\Program Files\\nodejs\\node.exe","result":"ok","pid":4020,"ppid":2180}
{"op":"exec","path":"C:\\Windows\\System32\\cmd.exe","result":"ok","pid":1704,"ppid":4020}
{"op":"exec","path":"C:\\Program Files\\nodejs\\node.exe","result":"ok","pid":4056,"ppid":1704}
{"op":"exec","path":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","result":"ok","pid":3196,"ppid":4056}
{"op":"exec","path":"C:\\Program Files\\nodejs\\node.exe","result":"ok","pid":5996,"ppid":3196}

{"op":"connect","host":"104.16.8.34","port":443,"result":"ok","pid":4020,"ppid":2180}
{"op":"connect","host":"140.82.114.3","port":443,"result":"ok","pid":3196,"ppid":4056}
{"op":"connect","host":"185.199.110.133","port":443,"result":"ok","pid":3196,"ppid":4056}

{"op":"read","path":"C:\\obs\\dprint\\node_modules\\dprint\\install.ps1","result":"ok","pid":3196,"ppid":4056}
{"op":"write","path":"C:\\obs\\dprint\\node_modules\\dprint\\dprint.zip","result":"ok","pid":3196,"ppid":4056}
```

The PowerShell process is five levels below the traced root, and both GitHub peers and the `dprint.zip` write are attributed to it. Following grandchildren is not optional here: an adapter watching the direct child, or even the child and grandchild, reports nothing about the download at all.

## What it cannot see

- **Work a Windows service performs on the package's behalf.** The subtree filter is the whole attribution model, so anything a service does lands outside it and is dropped. Observed directly: the fixture's DNS lookup appears as UDP:53 from the `dnscache` service, not from the process that asked. The consequence to plan for is that a postinstall using BITS (`Start-BitsTransfer`) would show no network at all, since the transfer runs in the service. Same shape for MSI actions and any COM server that does the work out-of-process.
- **Hostnames.** Peers are IP addresses only. Adding `Microsoft-Windows-DNS-Client` would plausibly recover query names in the caller's context; that is untested here, and the event contract has no field for it today.
- **The registry.** The contract has no registry op, so `Microsoft-Windows-Kernel-Registry` is not enabled.
- **Accesses that only an unprivileged user would be refused.** Removing the three DACL-bypass privileges closes the biggest hole, but the target still runs at high integrity with Administrators in its token, so a path writable only to administrators is still writable. Running the target under a medium-integrity restricted token is the real fix and is feasible — ETW needs the privilege in the tracing process, not in the target.
- **Anything the kernel could not name.** Handles that resolve to no path, and `\FI_UNKNOWN`, are omitted rather than guessed. Measured: 3 unresolved handles on the fixture trace, 2 on the dprint trace.
- **Creates whose OperationEnd never arrived.** Without a status the result field cannot be filled honestly, so they are dropped and counted — 6 on the fixture trace, 11 on the dprint trace.
- **Deferred-I/O reattribution is unexercised.** The adapter learns a thread-to-process map free from every event header and uses it to put filesystem work completed on a system worker thread back on the requester. The counter read 0 on both traces, so the mechanism is implemented but not validated.

Two things the adapter deliberately leaves to the shared normalizer, per determinism rule 1: case folding, and the fact that the kernel emits both `C:\obs\fx` and `C:\obs\fx\` for the same directory. It does decode NT device paths to drive letters, using a `QueryDosDevice` map captured at run time and recorded in `meta.json` — that is a different namespace rather than a different spelling, and a device with no mapping is passed through verbatim so the classifier's "maps to no scope" rule can decide about it.

One more thing the classifier will need to know about: NTFS metadata writes to `C:\$Mft` and `C:\$LogFile` are attributed into the subtree, because the filesystem writes them in the requesting thread's context. They are the Windows analogue of the Linux `/proc`, `/sys` and `/dev` bucket, and rounding them up into a write grant would be exactly the mistake determinism rule 3 forbids.

## Cost

| | fixture | `npm install dprint@0.19.2` |
| --- | --- | --- |
| trace events | 16470 | 104453 |
| events lost | 0 | 0 |
| `trace.xml` | 20 MB | 133 MB |
| normalized events | 454 | 2496 |
| parse time | under 1 s | 2.2 s |

Sizing note: `trace.xml` runs about 1.3 KB per trace event, so budget roughly 1.3 GB of scratch per million events. `windows.mjs` streams the file rather than reading it whole, so the ceiling is disk, not V8's string cap. Check free space before a sweep — `nub-win3` had 95.6 GB free for these runs.
