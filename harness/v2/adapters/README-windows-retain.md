# Windows retention — what a record keeps, and why

Linux and macOS records retain a decoded event stream. Windows retained **nothing** until this change: `measure.sh` carries the Linux hook, `measure-windows.mjs` has never used `measure.sh`, and `run-batch-v2.mjs`'s `process.platform === 'linux'` gate was excluding a platform that had no path to the mechanism anyway. Every path a package touched was discarded at the end of every Windows run this corpus has ever done, which is why a harness fix has always meant re-measuring.

## Three files per record, and they are not peers

| File | Standing | What it is |
| --- | --- | --- |
| `etw-raw.xml.gz` | **The artifact of record** | `tracerpt`'s XML, gzipped byte-for-byte. Every event the session delivered, including the ones the derived view filters out and the ones no decoder has ever looked at. |
| `etw-header.json` | Required to read the raw | Session and buffer geometry, every provider's keyword mask, the `QueryDosDevice` device map, the roots, the OS build, the tracer invocation, a sha256 of the capture script, and a sha256 binding it to the raw. |
| `events.ndjson.gz` | A convenience, regenerable | A queryable view shaped after the Linux retained log, so one reader handles both. **Not a contract.** It must never constrain what the raw keeps. |

The derived view is allowed to be lossy; the raw is not. Where the decoder dedups, aggregates or filters, the loss is bounded by "gunzip the raw and parse it again". A single canonical cross-OS wire format would make those losses permanent, which is the thing this design exists to refuse. The precedent is measured, twice: the Linux decoder retained 18 of 27 known writes before it was fixed, and the macOS dtrace adapter lost 100% of its rename destinations for its entire life. Under raw retention both are re-parses.

`windows-retain.mjs` is a **second, independent decoder**. It runs after synthesis and feeds nothing back, so retention structurally cannot move a verdict — same placement and the same non-fatal failure mode as the Linux lane's `linux.mjs`. A failure loses an archive; it must never lose a measurement.

## What the archive keeps that `windows.mjs` discards

`windows.mjs` is the synthesis decoder and is thin on purpose. The things it drops are the reason this file exists:

- **The full NTSTATUS on every operation.** It keeps four refusal codes and drops the rest, so a probe for a file that is not there (`STATUS_OBJECT_NAME_NOT_FOUND`) leaves no trace. "What did this package look for and fail to find" is exactly the question a future grant model asks.
- **Per-operation I/O byte counts**, the raw **create disposition** and **share access**, the **`SetInformation` InfoClass**, and read-only operations a write grant ignores.
- **Both spellings of an 8.3 path** — `f` is the kernel's spelling, `fx` the expansion. The expansion is perishable (it needs the file to still exist on the same host) so it can only be done at capture time and never during a re-parse; keeping both separates the permanent fact from the perishable one.

No scope tags anywhere. A log carrying `scope:"outside"` forces a re-measure to adopt a scope that did not exist when the corpus was measured; a log carrying the raw path plus the roots makes the same change a re-parse.

## What the archive structurally cannot answer

Written into `etw-header.json` under `limits` rather than left to be rediscovered, because an archive that does not state its limits gets read as if it had none. Each was measured on a real `windows-latest` runner:

- **`Create` carries no `DesiredAccess`.** The Linux soundness argument — an fd is only writable if it was opened with write flags, and the open is retained with them — **does not transfer**. `d`/`open-r`/`open-w` here is the CreateDisposition, a statement about what the caller was prepared to do to the contents, not the access requested. A `FILE_OPEN` handle can still be written through. Treat every `Create` as write-capable; writes are evidenced by event 16.
- **No rundown session**, so the FileObject/FileKey name tables hold nothing for a file already open when the session started. Those handle ops are unnameable rather than missing, and `stats.unresolvedHandle` is the size of the gap.
- **A hardlink destination is carried only by event 28 at keyword `0x800`.** NTFS emits no `NameCreate` for a second name on an existing FileKey, so below `0x1FF0` it is unrecoverable by re-parse rather than merely unrelated. A rename destination by contrast also appears as its own `NameCreate`, so a narrow mask costs only the source-to-destination relation. This is the sharpest reason the capture mask must be recorded.

Two decoding traps, both measured twice by independent agents: events 26/27/28 name their path field **`FilePath`** while every other Kernel-File event uses `FileName` (a decoder ending in `?? data.FileName` reads the wrong path on exactly the three events carrying a destination), and event 27 renders its `RenderingInfo/Task` as **`NameDelete`**, so events must be keyed on the numeric `EventID`.

## Sizes — UNMEASURED

Raw-gz and derived-gz per package are **not yet measured**. Producing them needs one real ETW capture, and `windows-latest` runners were saturated for the whole window this was built in — five attempts, four of which never got a runner at all. They are not gating anything: the retention code is what unblocks future work, and the Linux (~2.1 gz bytes per trace line, ~233 MB per platform) and macOS (1.72x archive-to-derived, ~237 MB per platform) figures already bound the storage question.

Whoever runs the first real Windows package gets them for free. The exact command:

```powershell
gh workflow run win-etw-retain.yml --ref harness/win-etw-retain -f package=hugo-extended@0.141.0
```

The `VERIFY the archive` step prints the `SIZE` block — `xmlBytes`, `rawGzBytes`, `derivedGzBytes`, `headerBytes`, `rawToDerivedRatio`, `xmlCompression`, `perRecordBytes` — and `verify-retain.mjs --json` writes them machine-readably.

## Reading a Windows CI result

⛔ **A Windows job that never got a runner reports as a failed measurement.** Under runner starvation the job is cancelled after ~15 minutes with `runner_name` empty and **zero steps executed**; the run then reports `conclusion=failure` with no artifacts. That is indistinguishable at a glance from a probe that ran and failed, and it is not one — nothing executed.

```sh
gh api /repos/nubjs/build-jail-corpus/actions/runs/<id>/jobs \
  --jq '.jobs[]|{conclusion,runner_name,steps:(.steps|length)}'
```

The workflow is **dispatch-only**, deliberately. Its name is registered on the default branch so both triggers would fire; Windows runners are the scarce resource here and an automatic run on every commit spends a slot a higher-priority probe needs.
