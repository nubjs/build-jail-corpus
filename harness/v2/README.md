# Harness v2 — observe first, verify second

v1 searched. v2 observes, then checks. The ladder is not deleted; it is demoted from *discovery* to *fallback*, which is the job it is actually good at.

## Why v1 is shaped the way it is, and why that shape was forced

v1's only signal is **pass/fail of a jailed run**. Given that, an ascending-cost walk over 55 states is close to optimal: the first passing state is the true minimum by construction, and greedy descent was rejected because a cheaper state passing does not imply every cheaper state fails.

But a blind oracle is expensive and it answers the wrong question. The walk tells you **how WIDE a grant must be**. It never tells you **WHAT the script touched**. Every "why does this package need `userHome`?" has had to be reconstructed afterwards by hand, and three separate record fields that *sound* like they answer it — `pathsBlockedWithoutGrant`, `pathsBlockedByPrefix`, `pathsRestoredOverRunnerUp` — do not. The first two are both `controlOnly(control, floor)`, a delta against the ZERO-grant cell describing a *successful* install; the third was retired outright because it is dominated by downstream consequence.

Cost, measured: ~13 min/package, 160-minute slices, and a cell walk that is mostly tail.

## The change: the harness may use root, the jail may not

These are two systems with opposite constraints, and conflating them is what kept the ladder load-bearing.

| | generation (this harness) | the shipped build jail |
| --- | --- | --- |
| runs on | our boxes, our CI | a stranger's laptop |
| privilege | **root / ptrace / eBPF / ETW is fine** | **unprivileged, always** |
| assumes | the script is well-behaved | the script is hostile |
| job | interrogate what it needs | enforce the narrowest grant |

Nothing the harness uses has to be available to the jail. That single permission means we can stop inferring needs from which rung happens to pass and simply **watch**.

## The v2 pipeline

1. **OBSERVE** — install the package **unjailed**, under full tracing (`strace -f -e trace=file,network` on Linux). Extract every path opened for write, every path read, every AF_INET socket and peer, and every genuine refusal.
2. **SYNTHESIZE** — map the observed paths onto the catalog's scopes (`deps` / `project` / `userHome`) and emit the narrowest grant covering them, plus any `writePaths` the run earns. Anything that maps to no scope — a write outside project and home, a `/proc` read — is surfaced explicitly rather than rounded up into `"disk"`.

   ⛔ **`writePaths` is not a narrower spelling of `write:{userHome}`, and reading it as one ships an under-grant.** nub's `persist_declared_home_writes` grants nothing: after the scripts finish it renames `private_jail_home/<rel>` into `real_home/<rel>` for each declared entry. So it can only move something that already landed in the throwaway home — the classifier's `jailHome` bucket, and only that bucket. A `userHome` write named the real home by absolute path, is REFUSED in the jail, and has nothing of its own in the private home to promote; the scope stays and `write-paths.mjs` says so in the log. The derivation, its collapse rule, its toolchain denylist and its scatter refusal all live in `harness/v2/write-paths.mjs`.
3. **VERIFY** — run that grant in the real unprivileged jail and compare artifacts against the unjailed control. This is the arm that can fail, and it is the only one whose result goes in the catalog.
4. **FALL BACK** — only if VERIFY fails, walk the ladder **upward from the synthesized grant**, not from zero. The search space is a handful of states, not 55.

Discovery is now O(1) runs; the ladder is a bounded repair step.

## `--at-grant` — a second mode, for a different question

```sh
measure.sh <pkg> <version> [nub-binary]                        # the pipeline above: what is the MINIMUM?
measure.sh <pkg> <version> [nub-binary] --at-grant '<json>'    # does it install under EXACTLY this grant?
```

The pipeline answers *"what is the minimum this package needs?"*. To ask instead *"does this package install under exactly this grant?"* — its own v1 record, say — **the ladder is not merely expensive, it is WRONG**, and the reason is worth internalising:

> MEASURED on `electron-prebuilt@0.31.2`: OBSERVE logged **2417 events with `malformed: 0`** and reported `attributedPeers: 0, allTreePeers: 0, peers: []`, for a package whose v1 record says `network: true` — the ETW adapter missed the egress entirely. Synthesis therefore under-predicts, the fallback ladder repairs it by climbing, and the `=> MINIMUM` line then conflates *what the package needs* with *what OBSERVE failed to see plus what the ladder recovered*. Read as a comparison against the v1 record, that reads as **"v1 UNDER-GRANTED"**.
>
> ⛔ **AN EARLIER REVISION OF THIS PARAGRAPH JUSTIFIED IT WITH "every ladder rung on Windows carries `network:true`", AND THAT IS FALSE.** `states.mjs` has 54 states of which **22 carry no network at all**, including `{"read":[],"write":["userHome"],"network":false}` at cost 7 — strictly cheaper than the same grant with network at cost 10. Since the walk is ascending-cost and the first passing state is the minimum by construction, `electron-prebuilt` **was tested at the network-free rung, failed there, and only passed with network**. ⇒ v1 MEASURED that egress; it is not a rung artifact.
>
> That correction *strengthens* the case rather than weakening it. v1 measured the need, and the Windows adapter's own validator (`adapters/validate-windows.mjs`, assertions **P4**/**P7** with negative control **N4**) proves ETW capture works for both a raw `TcpClient.Connect` and an `Invoke-WebRequest`. Two independent instruments say the egress is real and observable, and OBSERVE still reported none of it.

⇒ **A tracer blind spot presents as a defect in the thing being measured.** `--at-grant` removes that path: no synthesis, so nothing OBSERVE missed can enter the verdict. One arm, ~4× cheaper.

OBSERVE still runs, and must — the artifact gate needs its file manifest as the reference for "did this arm produce what an unjailed install produces". Only OBSERVE's *network* attribution is in question; its file output is unaffected.

| exit | verdict | meaning |
| --- | --- | --- |
| 0 | `SUFFICIENT` | installed, artifacts matched OBSERVE |
| 1 | `INSUFFICIENT` | needs MORE than this grant ⇒ if the grant came from a v1 record, that record UNDER-GRANTS |
| 3 | `VOID` | the override did not engage — **measured nothing, and is NEITHER outcome** |

⛔ **The vocabulary is deliberately not the ladder's.** Reporting `MINIMUM` here would invite exactly the conflation above: "the minimum came out wider than expected" is not "the record under-grants". And VOID stays its own verdict — collapsing it into `INSUFFICIENT` is the bug the ladder carried at three separate decision points before it was fixed.

**Verification status, stated honestly:** all four `verify` return codes were driven through the decision block with a stub and dispatch correctly (0→SUFFICIENT, 1→INSUFFICIENT, **2→VOID**, 3→INSUFFICIENT); the malformed-grant guard rejects a non-object; both modes parse; `bash -n` clean under stock bash 3.2. ⛔ **It has NOT been run end-to-end against a real package by its author** — `measure.sh` needs `strace`, so it cannot run on macOS. First real use should read its output sceptically and report anything surprising.

## How much each adapter is actually trusted — measured, and it is UNEVEN

Three operating systems means three tracers and three parsers (strace, dtrace, ETW). That is fine by design — the OSes share no observation mechanism, so a common implementation was never available. What matters is knowing how much each one has earned. Stated honestly, because the weakest link is where a wrong grant enters the catalog:

| | tracer | store eviction | parser unit tests | end-to-end evidence |
| --- | --- | --- | --- | --- |
| **linux** ✅ RUNNING | `strace -f` | root + transitive, nub tooling spared | **7** (`observe.test.mjs`) | converged 5/5 MINIMAL, 0 under- and 0 over-prediction; plus 24 packages at `--at-grant`, 19 measurable, 0 under-grants |
| **macos** ✅ RUNNING | dtrace (`macos-observe.d`) | root + transitive, nub tooling spared | **11** (`observe-macos.test.mjs`) | `@apollo/rover@0.2.1` reproduces the Linux control in both directions on `macos-15`; nothing at corpus scale yet |
| **windows** ⛔ **DISABLED** | ETW (`windows.ps1`) | root + transitive, nub tooling spared — **active but UNPROVEN** | **0** | `validate-windows.mjs` — both-directions, with `--selftest` |
| *shared* | — | — | **8** (`artifact-gate.test.mjs`) | the golden cases |

⛔ **THE WINDOWS LANE IS HARD-DISABLED, AND IT IS NOW THE ONLY ONE.** `measure-windows.mjs` exits 3 immediately and carries the full reasoning and a lift procedure above its guard. Its transitive sweep **is** ported and measured active (run 31107020153: `EVICT   30 store entries removed, 5 spared as nub tooling` per arm) — it stays disabled because that eviction is **unproven in the direction that matters**, blocked by the read denial below. macOS carried the same guard for the same reason; it was lifted once the eviction was ported and the control ran on a real runner (below).

⛔ **A WINDOWS ARM CURRENTLY FAILS AT EVERY GRANT, ON A READ OF THE PACKAGE'S OWN ENTRY POINT.** Verbatim, from four `@apollo/rover@0.2.1` arms spanning `{"network":true}` to `{"write":{"deps":true},"network":true}`:

```
Error: EPERM: operation not permitted, open
'C:\jail\...\verify-at-grant\node_modules\.store\@apollo+rover@0.2.1\node_modules\@apollo\rover\install.js'
```

`@pulumi/datadog@0.18.9` dies the same way on `...\.store\grpc@1.24.2\...\node-pre-gyp\bin\node-pre-gyp`. No rung on the ladder widens a read of the package's own store entry, so every rung returns the same verdict — which means **no arm can pass, so no arm can FALSELY pass**, and the teeth control (the same arm under a deliberately root-only eviction, which must falsely pass) came back INSUFFICIENT alongside the real one. Two eviction modes agreeing when neither can succeed is evidence of nothing. Fixing that read denial is the prerequisite for the Windows proof, and the probe that runs it is `.github/workflows/win-evict-probe.yml`.

The store eviction is not housekeeping — it is what makes two arms independent. A package still materialized in the machine-global virtual store is **relinked, not reinstalled**, so its lifecycle script never runs; the arm then **passes at whatever grant is under test, including one narrower than the package needs**. That is an **under-grant**, and under-granting breaks real users' installs while over-granting only wastes capability. `measure.sh` records the measured case, three runs on one binary differing only in what was evicted:

```
evict rover only              {"network":true}             rc=0  bin/ EMPTY   -> false PASS
evict rover + binary-install  {"network":true}             rc=1  bin/ absent  -> correct FAIL
evict rover + binary-install  {"write":{"deps":true},...}  rc=0  bin/ rover,README.md,LICENSE
```

⇒ **Root-only eviction is precisely the arm that falsely passed**, so Windows' narrower scope makes it rarer, not safer. macOS evicted nothing at all and mitigated with a per-arm `NUB_CACHE_DIR`; that is the wrong remedy on both counts, because `aube_store::dirs::cache_dir()` and `side_effects_cache_root()` (= `virtual_store_dir()/../side-effects-v1`) both land beside the store under the XDG cache and neither moves with `NUB_CACHE_DIR`, which governs the resolver primer cache alone. The macOS driver now carries the same closure sweep as Linux, the same `side-effects-cache=false` opt-out, and the same artifact-manifest gate.

⛔⛔ **AND ON A HOSTED RUNNER THE EVICTION MAY NEVER FIRE AT ALL, WHICH IS NOT THE REASSURANCE IT SOUNDS LIKE.** Under `is_ci()` nub can resolve the linker to a **project-local** `node_modules/.store` inside each arm directory rather than the machine-global store (`install_report.rs` `layout_row`; an explicit `enableGlobalVirtualStore` is the one thing resolved before it). Then there is no global store to evict, the sweep skips in silence, and arms come out independent by accident. MEASURED on Windows in run 31106248877: four arms, `linker isolated (global virtual store auto-disabled in CI)` in every log, **zero `EVICT` lines**, and root-only and transitive eviction giving identical verdicts. Every v2 `driver.out` in the corpus shows the same shape — 3 of 3 carry a `CLOSURE` line and 0 of 3 an `EVICT` line. Two consequences, in opposite directions:

- The replay hazard is **not live on those runners**, so existing rows are not under-granted by *this* mechanism.
- The corpus is measuring a **layout real users do not get**: outside CI the machine-global store is the default, and the rover case is exactly a write through a link into a *sibling's* store entry, which the project-local layout relocates. Whether a grant measured under one layout transfers to the other is **UNVERIFIED** and worth settling before the next full sweep.

A probe of any eviction code therefore has to check that it fired, or it measures nothing while looking healthy — which is how the first Windows attempt at this proof passed its own preconditions and proved nothing.

⛔⛔ **macOS IS NOT IN THAT STATE, AND THE REASON IS `sudo`, NOT THE PLATFORM — SO IT IS A KNOB THE WINDOWS LANE CAN REACH TOO.** `is_ci()` is `std::env::var_os("CI").is_some()` and nothing more (`aube-util/src/env.rs`). The macOS driver launches every arm as `sudo -u "$RUNUSER" -H env "PATH=$PATH" …`, and sudo's `env_reset` drops `CI`/`GITHUB_ACTIONS` while `env` re-adds only `PATH` — so **nub inside an arm does not know it is in CI, the auto-disable never fires, and the arm uses the machine-global store**. The Windows driver spawns nub with the CI environment intact, which is why it saw zero `EVICT` lines. Measured both directions on `macos-15`:

| | store before | store after | `node_modules/<pkg>` resolves to |
| --- | --- | --- | --- |
| driver arm (`sudo -u … env PATH=…`) | absent — `EVICT[synth] no store … yet (first arm on this box)` | **50 entries**, `EVICT` then removing 30 per descent arm | machine-global `/Users/runner/.cache/nub/pm/store` |
| plain `nub install` in the job shell, `CI` intact ([31109041194](https://github.com/nubjs/build-jail-corpus/actions/runs/31109041194)) | 50 | **50 — unchanged** | `/private/tmp/lay/node_modules/.store/@apollo+rover@0.2.1/…` |

The store not existing before the first arm and holding 50 entries after it is what makes this a measurement rather than an inference: the arms populated it. ⇒ **The macOS lane measures the layout real users get; the Windows lane does not.** The lift rests on that plus the control pair, `@apollo/rover@0.2.1`, three arms:

```
VERIFY[synth]             {"write":{"deps":true},"network":true}  rc=0  artifacts=6/6  -> VERIFIED
VERIFY[nar-no-network]    {"write":{"deps":true}}                 rc=1                 -> necessary
VERIFY[nar-no-write-deps] {"network":true}                        rc=1                 -> necessary
```

The same fixture passes at `write.deps` and fails without it, so the failure is attributable to the missing capability rather than to the platform. That is the documented Linux pair, reproduced.

⛔ **But the FAILING control did not reproduce, and it is recorded rather than smoothed over.** Re-running the same fixture on the same warm store with the eviction AND the memo opt-out both neutered — i.e. the pre-fix driver — still returned `rc=1` at `{"network":true}` ([31108595308](https://github.com/nubjs/build-jail-corpus/actions/runs/31108595308)); the arms re-ran the lifecycle script anyway. ⇒ **macOS has not been shown to produce the false pass Linux measured on this package.** The eviction's necessity there rests on the shared mechanism — identical store path, identical relink behaviour — and on the Linux measurement, not on a macOS reproduction. It is a strict tightening either way, so it does not gate the lift; it does mean the macOS lane's freedom from replay is less proven than Linux's.

⛔ **Any darwin-arm64 record written before the guard, or any win32 record, is suspect in the UNSAFE direction** — re-measure it rather than trusting it. Linux rows written before `67c01911` skew **wide** instead (the node-gyp collision failed arms spuriously), which is safe for users but inflates the headline `write:"disk"` metric.

The unit suites are worth their cost because they cover the *same* semantic hazards independently on Linux and macOS — a symlink into the real user home, `rename` billing **both** ends, a failed call not counting as a need, an unattributed run yielding `UNKNOWN` rather than an empty grant. Two parsers agreeing on those, written separately, is most of the cross-parser confidence there is. The artifact gate's suite carries the one assertion nobody may relax: **`.npmrc` is not excused by the packaging-metadata exclusion.**

⛔ **Windows has no parser unit suite, and `validate-windows.mjs` does not substitute for one** — it needs a real Windows host plus a PowerShell-built fixture at `C:\obs\fx`, so it runs nowhere else. What it *does* cover it covers well: every deliberate action must be PRESENT, every decoy ABSENT, the emitted set EXACT inside the namespace the fixture controls, and `--selftest` deletes each positive assertion's evidence and requires it to FAIL.

⛔⛔ **But note precisely what that validator can and cannot catch, because the known Windows defect slipped past it.** OBSERVE reported `allTreePeers: 0` on a package whose egress two other instruments say is real. `allTreePeers` is the **pre-attribution** count, so zero means no network events reached the parser at all ⇒ **the defect is in CAPTURE, not parsing, and a parser unit test would not have caught it either.** The validator asserts egress (**P4** a raw `TcpClient.Connect` with no DNS and no TLS; **P7** an `Invoke-WebRequest`) and passes — so whatever that package does differs in shape from both, and that shape is unidentified. ⇒ **The gap to close on Windows is capture-side coverage in `windows.ps1`, not more parsing tests.**

## Running it at corpus scale — the v2 lane

`.github/workflows/corpus-v2-runner.yml` is the queue-driven lane, one job per OS per slice. Its architecture is `corpus-queue-runner.yml`'s and deliberately so: the claim is pushed before any measuring starts (so parallel runners can never hold the same row), records are add-only and unique per `(platform, package, version)`, and a slice resumes past whatever it already measured.

| | v1 lane | v2 lane |
| --- | --- | --- |
| workflow | `corpus-queue-runner.yml` | `corpus-v2-runner.yml` |
| index | `queue.ndjson` | `queue-v2.ndjson` |
| records | `records/runs/` | `records-v2/runs/` |
| publisher | `harness/publish-record.sh` | `harness/v2/publish-record-v2.sh` |
| batch driver | `harness/run-batch.sh` → `search.mjs` | `harness/v2/run-batch-v2.mjs` → the platform driver |
| chains by default | yes | **no** |

⛔ **The two lanes share no file, and that is the guarantee rather than a convention.** `publish-record-v2.sh` refuses any path that is not `records-v2/*`, so there is no path expressible in the v2 lane that names a v1 record. Each record additionally carries `harnessVersion: 2`, which is what survives being collated or copied out of that tree. The v1 corpus is not gold-standard data but it is kept for historical reference, and nothing here can overwrite it.

⛔ **`chain` defaults to FALSE, inverting the v1 runner's default.** A full-corpus v2 re-measure is a large compute commitment and a separate decision; a lane that self-dispatches by default takes that decision by accident, one hop at a time, and the tell arrives hours later as a drained queue.

### The drivers print; `record.mjs` is what makes a record

None of the three drivers writes a file — they were built to be read by a human on a probe branch, so every v2 result so far has lived in a workflow log that expires. `record.mjs` parses a driver's terminal vocabulary into a record shaped like a v1 one, which is what lets `collate.mjs --runs records-v2/runs` and `claim-slice.mjs --reconcile --records records-v2` read it with no changes.

The vocabularies differ, and one pair is a false friend. The POSIX drivers print `=> VERIFIED <grant>` where the Windows driver prints `=> MINIMUM <grant> (observed, then verified)` for the **same** outcome — and all three print `=> MINIMUM <grant> (ladder fallback)` for a materially different one, where OBSERVE under-predicted and the ladder repaired it. Keying on the word `MINIMUM` alone merges the arm that proves synthesis works with the arm that proves it failed, so the record carries `verifiedBy: synth | ladder`.

macOS was the last driver without a ladder, and the cost was an absent catalog entry rather than a wide one: `collate.mjs` drops every non-`MINIMUM` verdict, so each terminal `UNDER-PREDICTED` left its package with no entry and therefore on the restrictive base profile at install time — a broken install, in the one direction this project forbids. Measured at the time of the port: 5 of 64 darwin-arm64 records, against zero records on any platform carrying `verifiedBy: ladder`. All three drivers now walk the same three rungs, and the winning rung **descends** — a rung is a bundle (rung 0 alone grants `deps` + `project` + `userHome`), so publishing one un-narrowed would hand out three capabilities because one arm passed. That second half arrived one lane at a time, Windows then macOS then Linux, and Linux was the last: it had walked a ladder since it was written and published whichever rung passed verbatim. `linux-ladder.test.mjs`, `macos-ladder.test.mjs` and `windows-invariance.test.mjs` execute their driver's post-`VERIFY` region against a stubbed `verify` oracle, because a source-matching guard cannot tell a rung that descends from three rung literals sitting beside a loop that publishes them.

### Before declaring nothing passed: did the shortfall ever respond to the grant?

A ladder that fails at every rung has two indistinguishable causes, and only one of them is about capabilities. **A shortfall that is IDENTICAL at every grant up to `write:"disk"` cannot have been caused by a denied write, read or socket** — the top rung is the widest state the harness can express, so there is no narrower grant for the shortfall to be evidence about. It says something about the arm's toolchain instead. `shortfall-invariance.mjs` is the predicate: it reads the SEQUENCE of gate verdicts (`rc:shortfall-digest:ok|abs:missing-count`, one line per grant-widening arm) and nothing in it can make an arm pass that did not.

**All three drivers run this stage, and for a while only Linux did.** The cost of that asymmetry was measured on `@arbitrum/sdk@3.0.0-beta.0`: darwin walked all three rungs and got `rc=0 artifacts=816/1117 missing=301 shortfall=0d0532fa4785` at every one of them, `write:"disk"` included, and recorded `UNDER-PREDICTED` — while Linux, from a different tracer, had already recorded the same package `ARTIFACT-GATE-SUSPECT`. `collate.mjs:187` excludes both verdicts from the catalog, so this was never a broken-install risk; it was a **triage** gap, and the distinction it erases — *needs a wider grant* versus *no grant will ever help* — is the one that manufactures false under-grant findings.

⛔ **The verdict is `SUSPECT`, not `VERIFIED`.** Grant-independence proves the shortfall is not a capability gap; it does not prove the install was good. It is the only path that publishes a grant with no leave-one-out descent behind it, so `verifiedBy` stays null, no `minimality` is claimed, and the grant is a candidate for triage rather than a measurement.

⛔ **An exit code alone does not say the predicate RAN.** Its CLI prints on every path it takes, so empty stdout means it never executed — and the failure that produces that (a main-module guard defeated by a symlinked or backslash-spelled path) exits 0. All three drivers therefore refuse on empty output with `HARNESS-ERROR`, which `claim-slice.mjs` returns to `pending` instead of closing, rather than publishing a verdict off no evidence.

| driver says | record verdict | grant |
| --- | --- | --- |
| `=> VERIFIED <g>` / `=> MINIMUM <g> (observed, then verified)` | `MINIMUM`, `verifiedBy: synth` | `<g>` |
| `=> MINIMUM <g> (ladder fallback)` | `MINIMUM`, `verifiedBy: ladder` | `<g>` |
| `=> UNDER-PREDICTED` (macOS, once every rung has failed and the shortfall responded) | `UNDER-PREDICTED` | none — nothing was verified |
| `=> ARTIFACT-GATE-SUSPECT <g>` (all three, once every rung has failed) | `ARTIFACT-GATE-SUSPECT`, `verifiedBy: null` | `<g>`, the SYNTHESIZED one — a CANDIDATE, never descended |
| `=> BROKEN-WITHOUT-JAIL-TOO`, `=> NO-STATE-PASSED`, `=> VOID` | the same word | none |
| nothing at all | `HARNESS-ERROR` / `HARNESS-TIMEOUT` | none |

⛔ **Silence is not an empty grant.** A driver killed by a deadline, or dying before its first `=>`, measured NOTHING; emitting `{}` would record "this package needs no capabilities", an under-grant manufactured out of an instrument failure. It gets a `HARNESS-*` verdict instead, which `claim-slice.mjs` refuses to close a queue row on, so a later fix can still reach the package.

⛔ **The recorded grant is the one whose arm passed, never the narrowest variant that also passed.** Leave-one-out proves each capability droppable *individually*, never jointly, so adopting the narrowest observed variant would under-grant the moment a package has two capabilities. Over-prediction is recorded beside the grant, as `minimality` and `overPredictedBy`.

`record.test.mjs` runs the parser against fixtures captured verbatim from `macos-v2-measure` run 31088841052, rather than reconstructed from the drivers' own `echo` statements — a reconstructed fixture agrees with a parser that is wrong in exactly the way the reconstruction was.

### The retained event log — `events.ndjson.gz` (Linux and macOS live; Windows pending)

Until now nothing about WHAT a package touched survived a run. `measure.sh` writes the full strace to `$OBS/trace.txt` inside a `mktemp -d` it deletes on exit, and the publisher copies only `driver.out` plus the extracted verdict. So a record answers "which grant" and never "which paths" — and every harness fix has meant RE-MEASURING the corpus (28–121 runner-hours per platform; v1 was ~495) rather than re-parsing it. `adapters/linux.mjs` closes that: it decodes the trace a second time, independently of synthesis, and writes a normalized event stream into the record dir.

⛔ **It stores raw paths and the ROOTS, never scope tags.** A scope tag is derived data that bakes in today's classifier. We were adding a `tmp` scope while writing this; a log carrying only `scope:"outside"` would have forced a re-measure to gain it, where a raw path plus the roots makes it a re-parse. Same argument one level up for attribution: the process table carries `ppid`/`exe`/`cwd`/`life` so a changed attribution RULE is also a re-parse.

| field | why it cannot be dropped |
| --- | --- |
| `o` op class + `s` raw syscall | the class is this file's opinion; the syscall name is not |
| `f`, `g` | a two-path op bills BOTH ends — the macOS lane lost 100% of its rename destinations and nobody noticed |
| `r` errno, `fl` open flags | a failed access is not a need, and write INTENT lives only in the flags |
| `n` repeat count | makes dedup lossless rather than merely small |
| header `roots` | every path is machine-specific (`/home/runner/v2-hNdvB5/…`); without these the stream is a pile of strings |

⛔ **`events.ndjson.gz`, never `events.log`.** The repo's `.gitignore` carries a bare `*.log`, so a file named that is dropped silently at `git add` while looking present on the runner's disk — the same trap `record.mjs` documents for `driver.out`. Verified both ways with `git check-ignore`.

**Cost, measured on four packages, then extrapolated over the 45 existing linux records' actual trace-line distribution:** 2.1 gzipped bytes per trace line; median record 22 KB, mean 101 KB, **~233 MB per platform and ~700 MB for a 2,250-package three-platform corpus**. Deduplication on `(pid, syscall, path, path2, result, flags)` is what makes that affordable — 216,512 calls collapse to 80,329 events on `lmdb-store@2.0.0-alpha2` — and it is lossless for a capability model because `n` keeps the frequency.

⛔ **Nothing is filtered, and dropping `ENOENT` is NOT the free win it looks like.** It buys 1.3–1.75× after dedup, and the argument for it ("the file does not exist, so no grant would change the outcome") holds only on the MEASURING machine. MEASURED on `lmdb-store@2.0.0-alpha2`: 21,142 of its ENOENT probes are outside project and home, and they are the C++ **include search path** — `/usr/include/c++/12/bits/…`, `/usr/local/include/…`. On a box with a different gcc layout those same probes HIT. A future model that wants "grant the read the compiler searched for" is derivable only from the ENOENT set, so filtering it is the under-grant direction. Refusals (`EACCES`/`EPERM`/`EROFS`) are kept for the obvious reason: they are the signal that a grant is missing.

#### ⛔ The RAW tracer output is the archive; the normalized stream is a derived cache

Maintainer directive, and it corrects the retention design one layer up from the scope tags. A normalized event stream bakes in **today's DECODER** exactly the way a scope tag bakes in today's classifier — and we have two measured instances where that would already have cost us:

- the macOS dtrace adapter lost **100% of rename destinations** for its entire existence, silently;
- the Linux decoder retained **18 of 27** known writes against a C fixture where its rewrite retains 26 of 26.

Every normalized log written in either era would have carried those holes forward, permanently and invisibly. With the raw kept, a decoder bug is a **re-parse**; without it, a re-measure at best.

⇒ **Per-OS raw formats with per-OS parsers is the shape.** Do NOT canonicalize onto one wire format — a mandatory shared schema is itself a canonicalization, and it would force each lane to trim to the intersection of what all three tracers can express. A field only one tracer exposes is a reason to capture it.

| file in the record dir | role |
| --- | --- |
| `trace.txt.gz` | **the archive.** Byte-exact tracer output. If only one file survives, this one. |
| `capture.json` | what makes the archive re-parseable — exact invocation, a **sha256 of the D script** plus the subscription list it implies, OS/kernel, roots |
| `events.ndjson.gz` | derived, queryable, regenerable from the two above |

⛔ **`capture.json` is not optional metadata.** A trace with no `linkat` records means "`linkat` never fired" under today's adapter and "`linkat` was not subscribed" under this morning's, and *nothing in the byte stream distinguishes them*. The adapter is versioned by content hash rather than by a number someone has to remember to bump.

**Measured on `@apollo/rover@0.2.1`**, with the adapter subscribing everything dtrace exposes — 13,217 trace lines, 12,644 calls, 6,076 distinct events:

| artifact | raw | gzip -9 |
| --- | --- | --- |
| `trace.txt` — **the archive** | 1,904,148 | **69,929** |
| `events.ndjson` — derived | 999,295 | 40,567 |
| `driver.out` — all that is published today | 4,216 | — |

Archive-to-derived is **1.72×**, at the low end of the 2–2.8× the Linux lane measured. At 2,250 packages: **~150 MiB per platform archive-only, ~237 MiB for both.** Dropping `ENOENT` would take the derived log from 40,567 to 30,829 gzipped bytes (24%) and 6,076 events to 4,226 — refused, because a failed lookup names a fallback path the script probed for, and 82% of these are the read-side probes that a future read-scope model would be derived from.

⛔ **Both files are committed as fixtures** (`fixtures/macos-apollo-rover-0.2.1.{trace.txt,events.ndjson}.gz`) so the pair is demonstrable rather than described: regenerate the second from the first and diff it.

#### The macOS half — `adapters/macos-eventlog.mjs`

Same schema, same file name in the record dir, same no-scope-tags rule; the differences are the ones dtrace forces, and each is additive so a shared reader that filters on `k` is unaffected.

- **`k:"x"` — the tracer loss ledger.** dtrace aborts a whole clause on a `copyin` fault, so the event is never emitted, and until the adapter grew a `dtrace:::ERROR` clause it happened in total silence — dtrace complains on its own stderr, which the driver captures into a file nothing downstream reads. That is how a 32-bit-truncated `self->np2` lost **100% of rename destinations, every run, for as long as that adapter existed**. A dropped event is a path never seen and therefore a capability never granted, so WHERE the stream has holes belongs in the stream. strace has no analogue, which is why the Linux log has no such record.
- **`dfd` beside `u`.** The Linux adapter maintains an fd→path table and resolves `*at` dirfds itself; the macOS one does not yet, so it keeps the raw dirfd value — enough for a table added later to resolve what this tracer could not. MEASURED on `@apollo/rover@0.2.1`: **14 relative paths under a real dirfd in a single run**, every one of which the decoder previously resolved against the cwd and turned into a path no process ever touched.
- **`r` uses Darwin's errno numbering.** The numbers genuinely diverge — 35 is `EAGAIN` here and `ENOTEMPTY`-adjacent nonsense under Linux's table — so the mapping to a symbol happens where the number is still known, and a shared reader only ever sees the symbol.

⛔ **The `*at` family was unsubscribed and that was an under-grant.** MEASURED on macOS 15.7.7 arm64 (run 31116027627), over a workload of the shell utilities and node `fs` calls a lifecycle script really issues: **46 of 86 path-mutating syscalls were invisible**. The number splits, and only one half is fixable by subscribing — 9 are path-taking (`unlinkat`, `setattrlistat`, `linkat`, `clonefileat`, `fchmodat`), while 37 are fd-taking (`fchmod` 22, `ftruncate` 8, `fchown` 4, `fsetattrlist` 3) and name no path for any tracer without an fd→path table. `probes/at-family-fixture.sh` is the known-answer guard: its denominator is a `syscall:::entry` census taken in the same run rather than assumed from its own C source, the pre-fix adapter must capture zero, and the fixed one must capture exactly the number of times each syscall fired. First green run: 10 ops × 64 calls, pre 0, post exact, 64/64 rename pairs matched, 0 phantom paths.

⛔ **Five Darwin syscalls have NO dtrace probe on this kernel at all** — `renamex_np`, `utimensat`, `clonefile`, `lchmod`, `futimens` — proven by compiling each name alone, which is the only safe way to ask (a name the kernel does not publish makes dtrace refuse to run the *whole* script). They are unreachable from the `syscall` provider rather than merely unsubscribed, so a `syscall:::entry` census cannot even count them. `renamex_np` and `utimensat` are the two that matter; closing them needs Endpoint Security, whose `rename` event fires for the VFS operation whichever syscall entered it.

**Cost, measured on `@apollo/rover@0.2.1`** — 3,442 trace lines, 2,869 calls collapsing to 2,716 distinct events:

| artifact | bytes |
| --- | --- |
| `trace.txt`, the dtrace source | 504,592 |
| `events.ndjson` | 483,429 |
| **`events.ndjson.gz`** | **23,623** (20.5×) |
| `driver.out`, all that is published today | 3,675 |

That is **8.7 gzipped bytes per distinct event**, against the Linux fixture's 6.21 — the gap is Darwin's longer paths (`/opt/homebrew/Cellar/node@22/…`) plus the `dfd`/`u` fields, and the two agreeing to within a factor of 1.4 is the cross-check that neither is mis-sized. Extrapolated at this package's size, ~51 MiB gzipped per platform for 2,250 packages; ⛔ treat that as ONE package rather than a median — its 541 renames are node's V8 compile cache and dedup only pays 1.05× here against 2.7× on Linux's `lmdb-store`.

Dropping `ENOENT` — 705 of 2,716 events — buys **15% of the gzipped size** (23,623 → 20,029 B). Refused, for the reason the Linux lane refused it: a failed lookup names a fallback path the script probed for, and on a machine where it exists the same script reads it.

#### The claim, executed rather than asserted — `eventlog-query.mjs`

The argument for retention is that a scope set which did not exist at measurement time is still derivable. `harness/v2/eventlog-query.mjs` is that argument as a command: it reads any platform's log with the same code and classifies from raw paths plus the header's roots, including a **`tmp` scope that is in no shipped classifier**.

```
$ node harness/v2/eventlog-query.mjs harness/v2/fixtures/*.events.ndjson.gz
linux-arm64   hugo-extended            {"jailHome":4,"ownPkg":8,"tmp":9}
darwin-arm64  @apollo/rover            {"systemfs":7,"tmp":1625,"userHome":2,"deps":6,"project":2}
```

Those 1,625 macOS temp writes were `outside` under the classifier that measured them; naming them took a re-parse of a committed log and no runner at all. `--script-only` applies the attribution the process table records, and `--paths <scope>` dumps the distinct paths — which is the corpus-wide question ("what do all the outside-writes look like?") that could not be asked before.

⛔ **Analysis only.** Nothing here feeds grant synthesis, the driver, or the catalog. The moment a retained log can move a verdict, the verdict stops being an independent second opinion on the trace.

### One thing v2 broke that v1 could not

⛔ **Roughly half the corpus synthesizes the empty grant, and `collate.mjs` used to emit an entry for it.** nub rejects an entry that widens nothing — and a rejected catalog is a *silently discarded* one, since `Decision::FellBack` keeps nub running on the compiled-in table and merely prints `REJECTED`. So one such package invalidated the whole catalog while every record beside it was sound. It could not arise under v1, whose needs-nothing records carry `grant: null` and never become a meaningful row; a v2 record carries a *verified* `{}`, which is a stronger statement and a legitimately different value. Measured on the first macOS smoke slice: `git-validate@2.2.4` took the catalog gate down alongside two good records. The collator now omits the package, which is the correct encoding — the override replaces the compiled-in table rather than merging into it, so an absent package runs at the base profile.

## What v2 does NOT change

- The catalog schema and the grant vocabulary are unchanged.
- The verification arm is still the real jail, unprivileged, on the real binary. A synthesized grant is a hypothesis until that arm passes.
- Over-granting stays safe and under-granting stays the only unacceptable direction. When OBSERVE and VERIFY disagree, VERIFY wins and the grant widens.

## Gotchas already paid for

- **`grep EACCES` is wrong.** It matches the flag name `AT_EACCESS` in ordinary successful `faccessat` calls. Only `= -1 EACCES` is a refusal. Measured on a real trace: naive 26, real 11.
- **Write intent lives in the OPEN FLAGS**, not in a later `write()` — by then the fd hides the path. `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`, plus the path-taking mutators (`mkdir`, `unlink`, `rename`, `link`, `symlink`, `truncate`).
- **`-f` is not optional.** Lifecycle scripts fork, and the interesting syscall is routinely three processes down: `dotnet-2.0.0@1.4.4`'s whole story is one `openat("/proc/self/stat")` in a bundled yarn, a grandchild of the postinstall.
- **A trace of a jailed run answers a different question.** OBSERVE must run UNJAILED or you are measuring the jail, not the package.
