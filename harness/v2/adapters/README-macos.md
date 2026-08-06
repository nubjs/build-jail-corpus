# macOS adapter

```sh
# observe: run a command under trace, emit the normalized EVENT stream
sudo node macos.mjs --out events.ndjson --diag diag.json -- npm install --foreground-scripts <pkg>

# harvest ground truth about what the instruments actually print
sudo ./recon-macos.sh /tmp/recon

# validate against the known-answer fixture, both directions, with the mutation control
sudo NODE="$(command -v node)" ./validate-macos.sh
```

## Mechanism, and why

| candidate | verdict |
| --- | --- |
| **`eslogger` + `fs_usage`, both as root** | **Chosen.** Both ship with macOS, need no install, no driver, no download, and no custom entitlement. Neither satisfies the contract alone, so the adapter runs both. |
| `DYLD_INSERT_LIBRARIES` | Rejected. SIP strips the variable when exec'ing `/bin/sh`, and npm lifecycle scripts always go through `sh -c`, so the interposer never loads where it matters. |
| `dtrace` | Rejected. Refuses on a SIP-enabled Mac: `system integrity protection is on`. |
| `ktrace` | Rejected. Root-only and undocumented, and `fs_usage` is the supported front end to the same kdebug data. |
| `sandbox-exec` with `(with report)` | Rejected. Parses on macOS 26 but writes nothing, and what it emits is a deduplicated PROFILE with no pid, ppid, or result — it describes a policy, not a trace. |
| Endpoint Security client of our own | Rejected. Needs an Apple-approved entitlement plus root. `eslogger` already is one, Apple-signed, carrying `com.apple.developer.endpoint-security.client`. |

The split between the two is forced by what each structurally cannot see:

| source | supplies | cannot see |
| --- | --- | --- |
| `eslogger` | full path, real pid AND ppid, open flags, exec, fork. The only macOS source carrying a pid, so every attributed event comes from here. | TCP connects (ES has no such event — `uipc_connect` is UNIX-domain only) and refusals (NOTIFY events fire on operations that were allowed). |
| `fs_usage` | refusals as a numeric errno, and AF_INET socket/connect. | Any pid. It prints `command.threadid` and nothing else. |

## ⛔ The process-group trap

**`eslogger` suppresses events for every process in its own process group, and node's `spawn` puts it in yours.** From `eslogger(1)`, verbatim:

> To avoid feedback loops when filtering output using shell pipelines, `eslogger` automatically suppresses events for all processes that are part of its process group.

Started the obvious way, the tracer therefore suppresses the adapter, the traced command, and every descendant — precisely the processes the adapter exists to observe. The fix is one flag, `detached: true`, which makes node call `setsid(2)`.

This is the most dangerous shape a defect can take here, because **there is no error**. `eslogger` stays alive, exits cleanly, writes an empty stderr, and reports everything else on the machine, so the log looks healthy and voluminous. Measured on a macos-14 runner before the flag, the top executables across 6682 records were:

```
mdworker_shared=3291  mds=2763  mds_stores=400  xpcproxy=96  cfprefsd=63  launchd=40
```

System daemons only — not one `node`, `sh`, `sudo`, or `fixture`. The pid subtree resolved to **0 pids out of 8341 records**, so every file event was filtered out and the run emitted a single unattributed `connect`. A package that wrote to disk and one that touched nothing produce the same answer.

Two plausible explanations were ruled out by measurement first, and each had a fix attached that would have been wasted work:

| hypothesis | what killed it |
| --- | --- |
| The tracer's final buffer was lost to `SIGKILL` | Its record window brackets the command — first record `06:17:14.0`, last `06:17:20.7`, command `06:17:18.1` to `06:17:19.5`. Waiting for a clean exit at teardown *lowered* the record count. |
| The tracer died or never subscribed | Clean exit, empty stderr, and it kept emitting for other processes throughout. |

The diagnostic that answers this in one run rather than one CI cycle each is now recorded unconditionally: the eslogger time window against the command's own start and end, `seed_presence` (a seed appearing as neither a parent nor a child means nothing anchored the closure), and the per-executable histogram. Together they separate *tracer died* from *tracer truncated* from *tracer suppressed us*, which otherwise have identical symptoms.

**Do not merge the tracers' stderr into their data streams.** The parser skips every line that does not start with `{` without counting it, so a merged stderr destroys the one artifact that explains a failure. Each tracer writes stderr to its own file and the tail is surfaced in the diagnostics.

## Read-open versus write-open

Write intent is in the open flags. By the time bytes move, the fd hides the path, so an open that never writes still establishes the need and an open that does write is invisible if you only watch `write(2)`.

**ES `fflag` is the kernel's FFLAGS, not the userspace `O_*` flags.** They are off by one in the access-mode bits, because the kernel stores `oflags + 1`:

```
userspace  O_RDONLY=0  O_WRONLY=1  O_RDWR=2
kernel     FREAD  =1   FWRITE  =2  FREAD|FWRITE=3
```

So the userspace value for `O_WRONLY` (`0x0001`) is the kernel's value for `FREAD`. Testing `fflag & 0x0001` — the obvious port of the Linux predicate — classifies **every read as a write**, silently, and over-grants every package in the corpus. Measured on the runner: a read-only open of a `results.json` reported `fflag=32769` (`0x8001` = `O_EVTONLY|FREAD`), which that predicate calls a write. The correct mask is `FWRITE|APPEND|CREAT|TRUNC`. The mutators `create`, `unlink`, `rename`, `link` and `truncate` each name a write need on their own.

## Refusals

`fs_usage` prints errno **numerically** as `[%3d]` and never emits the symbolic name. Porting Linux's `grep EACCES` therefore matches nothing and reports a clean run for every package — a silent false negative, the one direction that under-grants. Linux's trap is an over-count from `AT_EACCESS`; the macOS mirror image is worse.

Only `1 EPERM`, `13 EACCES` and `30 EROFS` count. Three impostors sit in the same bracketed column and all three were found in real trace data:

| impostor | example | discriminator |
| --- | --- | --- |
| An `openat` directory fd | `renameat [4]/F365749A20...` | Printed `[%d]` unpadded and followed by `/` — it is a path prefix, not a column. The errno form is exactly three characters wide. |
| A dirfd that *is* three wide | `openat [ 13]/...` from a process holding 13 fds | Same `/` test. Filtering on "is the number a refusal errno?" alone is not enough. |
| A process exit status | `exit [  1]` from a `cat` that exited 1 after its open was refused | Calls that take no path can never express a filesystem refusal. It sits next to the genuine EACCES it followed, so it reads as corroboration. |

## Path truncation runs the opposite way from the guess

`fs_usage` **keeps the tail and drops the head.** It does not trim the tail. A head-trimmed path is no longer absolute, so it silently stops matching any declared root — and one that still looks plausible would match the wrong one.

Measured from the length ladder in `recon-macos.sh`:

- Longest path printed complete: **154 characters.** Shortest printed form already truncated: **144** (real length 154, leading 10 characters gone, no ellipsis).
- Total line width is fixed at roughly **242 columns** (about 254 for the wider `WrData` form), so the budget left for the path **depends on the call** — a long syscall name eats into it. The boundary is a **144–162 band**, not one number.
- `-w` raises the budget to `MAX_WIDE_MODE_COLS` minus overhead. It does not remove the limit.

The check is therefore structural rather than a length threshold: an absolute path that does not start with `/` was truncated, and is dropped and counted rather than emitted. A second signal is independent of width — the **kernel** pads a VFS_LOOKUP record with `>` when there is more path beyond the component it resolved, observed live as `/System/Volumes/Data/private/var/root/Library>>>>>>>>>>>`. That string is a valid-looking absolute path, so the first test does not catch it.

`eslogger` states truncation explicitly per path as a sibling `path_truncated` boolean, so that side needs no heuristic.

## Attribution, and the instrument observing itself

`fs_usage` carries no pid. The trailing column is `command.threadid` — measured directly: `mds` appears as `.13927`, `.13966`, `.13964` and `.9871` while ES reports it as the single pid 103. So `fs_usage` events are attributed by command NAME, and only when that name is unambiguous inside the subtree; anything else is dropped and counted rather than assigned a guessed pid.

`fs_usage` also **excludes processes named `sh` and `zsh` by default**, which is exactly the shell performing a `>` redirect. Those writes come from `eslogger` instead, and the fixture performs its project write as a shell redirect specifically so a regression here fails loudly.

The pid subtree is a transitive closure over three edge sources with unrelated failure modes, because one that depends on `eslogger` alone cannot survive a tracer that drops or stops:

| source | covers |
| --- | --- |
| per-record `(pid, ppid)` pairs | any process that generated an event |
| ES `fork` events | a process that never opens anything — including a pure fork with no exec, which is what a shell does before a builtin redirect |
| a `ps` sampler at 50ms | anything the tracer missed entirely |

**The sampler must not observe itself.** It is a child of the adapter, so its own subtree satisfies the closure and every `/bin/ps` and `/bin/sleep` it spawns lands in the event stream with each one's dyld and libsystem reads. Measured at **102–130 pids per run**. It cannot fabricate a write, so no grant widens, but it inflates the read set and buries the package's real activity. Excluded by ancestry, and the excluded count is recorded so the noise stays measurable.

The adapter's own sentinel files are the same shape and are **not yet excluded** — a worklist run attributed 80 unmapped writes to `/private/tmp/macos-adapter-*/sentinel-*`.

## Privilege, and whether SIP matters

The **tracer** runs as root; the **target** is dropped to the invoking user with `sudo -u`. That ordering is load-bearing rather than tidy: root bypasses mode bits entirely, so the fixture's mode-000 refusal check is meaningless under it. The Windows adapter has to actively remove `SeBackupPrivilege` to avoid the same class of perturbation; here the privilege boundary already sits in the right place, and the EACCES assertion is the positive control proving it.

**Both instruments are gated by root, not by SIP.** Measured unprivileged on two hosts running the *same* macOS 26.5.2, differing only in SIP:

| host | SIP | `eslogger` | `fs_usage` | `dtrace` (control) |
| --- | --- | --- | --- | --- |
| SIP-enabled Mac | enabled | `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`, "need to be superuser" | "must be run as root" | **"system integrity protection is on"**, plus needs privileges |
| `macos-26` runner | disabled | identical | identical | needs privileges — **no SIP line** |

`dtrace` is the positive control and it fires exactly as required: the SIP diagnostic appears when SIP is on and is absent when it is off, on the same OS version. So the probe genuinely discriminates SIP state, and against that working discriminator the two instruments the adapter depends on demand only privilege.

**The boundary, stated plainly: this is measured at client creation. Whether the full event stream is delivered under root with SIP enabled is UNTESTED** — every GitHub macOS runner image reports SIP disabled (`macos-14` 14.8.7, `macos-15` 15.7.7, `macos-26` 26.5.2), and no SIP-enabled host with passwordless root was available. Do not re-derive the mechanism survey above from these runners either: it was measured on a SIP-enabled Mac, and a mechanism that works on a SIP-disabled runner is a SIP-off fact, not a refutation.

## Validation

The fixture is a four-level process tree — `run-fixture.sh` → `sh` → `sh` → a C binary — performing one project write as a shell redirect from depth 1, and from depth 3 a `$HOME` write, a read of a file it never writes, a TCP connect to a pinned loopback listener, a mode-000 refusal, and a successful `openat` near-miss. The C binary is deliberate: an interpreter makes thousands of incidental syscalls and "exactly this set" stops being assertable.

Two arms, and the second is the reason to believe the first. `full` performs all five behaviours; `skip-home` provably omits the `$HOME` write, and the same assertion must invert. An adapter that passes both arms identically is reporting from imagination.

**A pass without a mutation control does not count.** `--selftest` re-evaluates every check against a deliberately corrupted copy of the event stream — evidence deleted for a MUST-SEE, the forbidden event injected for a MUST-NOT — and requires each to go red. A check that stays green is reported as `STAYED GREEN UNDER MUTATION: this check cannot fail`; a check that was already failing is counted **against** the control rather than passed, since mutating it proves nothing. Current state: **11 checks per arm, 22 of 22 passing, 22 of 22 mutation controls red**, on macOS 14.8.7, 15.7.7 and 26.5.2.

The gate is the workflow's `Verdict` step. Every other step carries `continue-on-error: true`, so a green step badge on the validate step alone means nothing.

## What it cannot see

- **The peer of a connect.** `fs_usage` formats connect as FMT_FD — fd and errno, never the sockaddr — and ES has no TCP event at all. Connect events are emitted without `host`/`port` rather than with an invented peer, and the gap is reported in the diagnostics. The Windows adapter gets `daddr`/`dport` from the kernel network provider; there is no macOS equivalent.
- **DNS.** The fixture's listener is loopback, so name resolution is never exercised.
- **Anything below a dropped ES record.** The bracket control makes that loud rather than silent: both sentinel bursts must appear in the captured log or the run is declared vacuous. One worklist package aborted on exactly this (`pre=true post=false`) instead of under-reporting.
