# build-jail-corpus

Measures, for every npm package that runs an install script, the **minimum OS capability its
lifecycle scripts actually need** — across macOS, Linux and Windows — and keeps every run record so a
result can be re-read, re-checked and audited later.

That measured data becomes the catalog nub's **build jail** enforces. The jail confines dependency
install scripts by default; the catalog is what tells it which packages legitimately need to write to
disk or reach the network, so the jail can stop a Shai-Hulud-style supply-chain attack while breaking
as close to zero real packages as possible.

**No catalog entry ⇒ no capability. The defence is package identity.**

---

## Operating it

The corpus advances in **slices**. A run claims ~100 rows from the queue, measures them, commits the
records and the updated queue in one commit, then dispatches itself again.

```sh
# start (or restart) a platform. It self-chains until that OS's rows are drained.
gh workflow run corpus-queue-runner.yml \
  -f os=linux -f slice=100 -f nub_sha=<nubjs/nub commit> -f chain=true

# a small non-chaining probe — use this after any harness change, before letting it chain
gh workflow run corpus-queue-runner.yml \
  -f os=windows -f slice=10 -f nub_sha=<sha> -f chain=false

# where coverage stands
node harness/claim-slice.mjs --status

# return rows stranded by a run that died mid-slice
node harness/claim-slice.mjs --reclaim-stale 360
```

`nub_sha` is an explicit `nubjs/nub` commit, never a branch: every record's provenance names the nub
it measured, and an old corpus stays reproducible.

## The queue is the spec

`queue.ndjson` holds one row per `(package, version, os)` — 6,750 rows for 2,250 package-versions
across three operating systems. Coverage is then checkable by reading ONE artifact rather than
reconciling CI history. That matters: the previous approach lost track badly enough that 175 packages
were measured twice on two machines while 349 sat unmeasured.

| status | meaning |
|---|---|
| `pending` | nobody has taken it |
| `claimed` | a run took it; carries the run id and a timestamp |
| `done` | measured; the record is committed alongside, with its verdict |

A run that dies mid-slice leaves its rows `claimed` **with its run id** — attributable and
recoverable via `--reclaim-stale`, never silently lost or double-run. Reclaim happens at the START of
every slice, or the queue would drain to a floor of permanently-stuck rows and report itself
incomplete with nothing pending.

## Reading the results

| verdict | meaning |
|---|---|
| `MINIMUM` | measured — the grant recorded is the minimum that reproduces the control |
| `BROKEN-IN-ENVIRONMENT` | fails here AND a reference PM fails identically — the environment, not nub |
| `BROKEN-WITHOUT-JAIL-TOO` | fails identically with the jail off, so confinement is **not** implicated — either a nub PM/linker problem *or* a package that cannot run on this host at all |
| `BROKEN-EVEN-WITH-EVERYTHING` | the jail IS implicated: fails jailed, succeeds unjailed, reference PMs succeed |
| `HARNESS-FLAKE` | npm 6's cacache race under contention — re-run serially; not a measurement |
| `REFUSED-MALICIOUS` | the OSV screen refused something in the tree; `maliciousAdvisories` names what |
| `HARNESS-*` | instrument failure — **not** a measurement, and re-run automatically |

```sh
node harness/collate.mjs --runs records --out catalog-v2.json   # records -> catalog
node harness/verify-corpus.mjs --records records                # does it carry what it measured?
```

⛔ **`BROKEN-WITHOUT-JAIL-TOO` is not a failure rate for nub.** The classifier asks the jail-off cell
first and short-circuits, so the bucket collects everything that fails with confinement off — and in
practice that is dominated by packages no tool can install on the host. Measured on a 100-package
Linux slice: 19 landed there, and at least 15 were environmental — old C++ against a modern V8, dead
download CDNs, a Windows-only package on Linux, `primordials is not defined` on too-new Node, and
packages whose own `postinstall` invokes a binary they never depend on (npm exits 127 on those too).
Reading the per-cell log per package is the only way to split them, which is why the artifact matters
more than the verdict.

## Keeping the corpus honest

Three things go stale in different ways, and each has its own tool. None of them runs automatically —
they are deliberate operations, because each one throws work away.

```sh
# After landing a nub fix: drop failure verdicts that fix may already have cured, so they re-run.
# Takes the BINARY, not a version string — the binary is the comparison.
node harness/purge-stale-verdicts.mjs --nub /path/to/nub --dry-run

# Before a sweep, and periodically while one drains: refuse to hand a runner a known-malicious
# package at all. Prove the screen can alarm before believing its all-clear.
node harness/prescreen-queue.mjs --self-test
node harness/prescreen-queue.mjs --dry-run

# When a run measured a slice and then lost it: the Actions log holds the complete records.
gh run view <id> -R nubjs/build-jail-corpus --log > /tmp/run.log
node harness/salvage-from-log.mjs --log /tmp/run.log --dry-run
```

**Why a failure verdict goes stale but a `MINIMUM` does not.** `search.mjs` skips any package that
already has a record, which is what makes the corpus resumable. A measured floor does not move
because an unrelated nub bug was fixed — but a *failure* often IS that bug, so leaving it in place
re-reports a defect that no longer exists. Nothing else catches this: `--stale-harness` keys on a hash
of the harness, so a nub-side fix invalidates nothing at all. Measured: 19 `BROKEN-WITHOUT-JAIL-TOO`
verdicts were committed hours after the fix for them had already landed.

---

## ⛔ The failure mode this system is built against

**A green run that produces nothing.** Six defects shipped in this harness while its measurement layer
was correct throughout — each produced records that parsed, collated and reported success, and a
catalog with ZERO capabilities. None was caught by a test, because every test asserted the
hand-maintained compiled-in table; nothing compared GENERATOR output against a CONSUMER.

`verify-corpus.mjs` closes that, and runs BEFORE every commit. It asserts substance, not validity:

- a `MINIMUM` record with a non-empty state must carry a structured `grant`
- a catalog with packages must carry capabilities
- a package measured as needing egress must still say so after collation
- `.store` bookkeeping directories must never appear as package names
- `--expect <n>`: if rows were claimed and NOTHING was produced, fail

That last one exists because the very first live macOS slice claimed 100 rows, hit
`timeout: command not found` (it is GNU coreutils; macOS does not ship it), had the refusal swallowed
by `|| true`, and committed a slice of zero records while reporting success.

### Traps that have already cost real time

- **`timeout` is not on macOS.** `run-batch.sh` resolves `timeout` → `gtimeout` →
  `harness/portable-timeout.sh` (a Perl shim, verified against GNU `timeout` including exit 124,
  which is read as `HARNESS-TIMEOUT`).
- **Two catalog parsers exist.** `catalog_v2::parse` takes `packages[<name>].default.network` — what
  this harness emits, and what `catalog_override` tries FIRST. `catalog::parse` is v1 and wants
  `networkHosts`/`packageGrants`. Asserting a v2 document against the v1 parser fails with
  `` `networkHosts` must be an array ``, which reads as a generator defect and is not one.
- **A correlation is not the variable.** A 6× scoped-vs-unscoped skew in Windows failures pointed hard
  at the name lookup. Splitting on BOTH variables killed it: scoped packages needing no network failed
  0% of the time. Scope merely correlates with needing egress.
- **`ci-watch.ts` defaults to a 45-minute timeout.** Pass `--timeout 360` for corpus-sized work, or
  the watcher reports TIMEOUT while the run is perfectly healthy.

### If records ever stop carrying grants

They are recoverable without re-measuring. Each record stores `state` (a label) and `cost`; `STATES`
is an exhaustive `read × write × network` product and each label is built deterministically from its
cost atoms, so a label names exactly one state and `grantForState` (in `states.mjs` — one definition,
two callers) reconstructs the grant exactly. `collate.mjs` backfills automatically. Measured: that
recovered a pre-fix corpus from 0 to 63 packages with real capabilities on macOS, and 93 and 97 on two
Linux hosts.
