# From god-mode logs to a grant, deterministically, on three operating systems

The observe-first pipeline is only as trustworthy as this step. Three platforms produce three
unrelated log formats, and one grant vocabulary has to come out the other end. Written naively
that is three parsers that drift apart, disagree silently, and are individually unfalsifiable —
the same shape as every defect this effort has paid for.

## The architecture: thin adapters, one classifier

Nothing platform-specific may touch grant logic. Each OS gets an ADAPTER whose only job is to emit
a normalized event stream; a single CLASSIFIER turns that stream into a grant.

```
strace -f        ─┐
fs_usage / ES     ├─►  ADAPTER  ─►  EVENT[]  ─►  NORMALIZE  ─►  CLASSIFY  ─►  GRANT
ETW / Procmon    ─┘   (per-OS)      (shared)     (shared)       (shared)
```

**EVENT** is the entire contract, and it is deliberately tiny:

```jsonc
{
  "op":    "read" | "write" | "connect" | "exec",
  "path":  "/abs/path",        // op != connect
  "host":  "1.2.3.4", "port": 443,   // op == connect
  "result":"ok" | "denied",
  "pid": 1234, "ppid": 1200
}
```

An adapter that cannot express something emits nothing rather than guessing. Everything
interesting — scope assignment, the grant lattice, the sentinels — lives downstream, written once.

### What each adapter owns

| OS | source | the one hard part |
| --- | --- | --- |
| Linux | `strace -f -e trace=file,network` | `-f` is mandatory; write intent is in the OPEN FLAGS, not a later `write()` |
| macOS | `fs_usage -w -f filesys,network` (root), or an Endpoint Security client | `fs_usage` truncates long paths — the adapter must widen or fail loudly, never silently trim |
| Windows | ETW file+TCP providers, or Procmon CSV | events are per-thread; the adapter resolves to a PID subtree before emitting |

## The five determinism rules

Everything below exists because a violation of it has already produced a wrong answer here.

**1. NORMALIZE BEFORE CLASSIFYING, IDENTICALLY ON ALL THREE.** Resolve symlinks, collapse `..`
and `.`, apply the platform's case-folding (Windows and macOS fold, Linux does not) — then
classify. `Path` equality normalizes `.` away and `parent()` trims a trailing `.`, so paths that
look distinct compare equal; that must happen in ONE place, not in three adapters.

**2. SCOPE IS ASSIGNED BY LONGEST-PREFIX AGAINST DECLARED ROOTS, NEVER BY PATTERN-MATCHING A
STRING.** The roots — project, the materialized package dir, the store, the throwaway home, the
real home — are passed IN, measured from the fixture, never inferred from the path text. A rule
like "contains `/node_modules/`" is not deterministic: it depends on where the fixture happened to
live. Order the roots longest-first and take the first match, so nested roots (the package dir
inside the project) resolve the same way every time.

**3. A PATH THAT MAPS TO NO SCOPE IS AN ERROR, NOT A `"disk"`.** The single most dangerous
rounding available is "unclassifiable, therefore grant everything". Unmapped paths are REPORTED
and the record carries them; a human or a rule decides. `dotnet-2.0.0@1.4.4` is the case in point:
its blocker is `/proc/self/stat`, which belongs to no write scope and is not a write at all.
Rounding it up to `write:"disk"` is precisely the mistake the corpus has been making.

**4. ONLY A GENUINE REFUSAL IS A REFUSAL.** On Linux only `= -1 EACCES|EPERM|EROFS` — a bare
`grep EACCES` also matches the FLAG name `AT_EACCESS` in ordinary successful `faccessat` calls
(measured: naive 26, real 11). Each adapter states its own refusal predicate and is tested on a
fixture containing a near-miss.

**5. THE MAPPING IS A PURE FUNCTION AND IS TESTED AS ONE.** Same event stream in, same grant out,
on every platform and every run. No clock, no cwd, no environment, no host lookups. Golden
fixtures live beside it: a recorded event stream and the grant it must produce, one per
interesting shape (deps-only writer, home-cache writer, network downloader, `/proc` reader,
writes-outside-everything).

## ⛔ THE LADDER IS THE TEST SUITE FOR THIS MAPPING

This is why v1 is not being deleted, and it is the strongest argument for keeping it.

The build jail is used to build its own catalog: the VERIFY arm runs the synthesized grant in the
real, unprivileged jail and compares artifacts against the unjailed control. So every package is
an end-to-end test of the mapper —

- **synthesized grant verifies** → the mapping was right for this package;
- **synthesized grant fails, ladder finds a wider one** → the mapping UNDER-PREDICTED, and the
  DELTA between the two names exactly what the mapper missed;
- **ladder finds a NARROWER grant than synthesis** → the mapping OVER-PREDICTED: the trace saw a
  touch the package does not actually need (a probe, a failed fallback path).

That third case is the one a pure observation pipeline cannot detect on its own, and it is why the
ladder must stay. **Track the under- and over-prediction rate as a first-class metric of the
harness itself.** A mapper with a low, well-understood miss rate is trustworthy; one whose miss
rate is unknown is not, however elegant its parser.

Confidence in the mapping is therefore not asserted — it is MEASURED, package by package, by the
mechanism we already have.
