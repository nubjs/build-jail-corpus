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
2. **SYNTHESIZE** — map the observed paths onto the catalog's scopes (`deps` / `project` / `userHome`) and emit the narrowest grant covering them. Anything that maps to no scope — a write outside project and home, a `/proc` read — is surfaced explicitly rather than rounded up into `"disk"`.
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
| **macos** ✅ RUNNING | dtrace (`macos-observe.d`) | root + transitive, nub tooling spared | **9** (`observe-macos.test.mjs`) | `@apollo/rover@0.2.1` reproduces the Linux control in both directions on `macos-15`; nothing at corpus scale yet |
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

The vocabularies differ, and one pair is a false friend. The POSIX drivers print `=> VERIFIED <grant>` where the Windows driver prints `=> MINIMUM <grant> (observed, then verified)` for the **same** outcome — and `=> MINIMUM <grant> (ladder fallback)` for a materially different one, where OBSERVE under-predicted and the ladder repaired it. Keying on the word `MINIMUM` alone merges the arm that proves synthesis works with the arm that proves it failed, so the record carries `verifiedBy: synth | ladder`.

| driver says | record verdict | grant |
| --- | --- | --- |
| `=> VERIFIED <g>` / `=> MINIMUM <g> (observed, then verified)` | `MINIMUM`, `verifiedBy: synth` | `<g>` |
| `=> MINIMUM <g> (ladder fallback)` | `MINIMUM`, `verifiedBy: ladder` | `<g>` |
| `=> UNDER-PREDICTED` (macOS, which has no ladder) | `UNDER-PREDICTED` | none — nothing was verified |
| `=> BROKEN-WITHOUT-JAIL-TOO`, `=> NO-STATE-PASSED`, `=> VOID` | the same word | none |
| nothing at all | `HARNESS-ERROR` / `HARNESS-TIMEOUT` | none |

⛔ **Silence is not an empty grant.** A driver killed by a deadline, or dying before its first `=>`, measured NOTHING; emitting `{}` would record "this package needs no capabilities", an under-grant manufactured out of an instrument failure. It gets a `HARNESS-*` verdict instead, which `claim-slice.mjs` refuses to close a queue row on, so a later fix can still reach the package.

⛔ **The recorded grant is the one whose arm passed, never the narrowest variant that also passed.** Leave-one-out proves each capability droppable *individually*, never jointly, so adopting the narrowest observed variant would under-grant the moment a package has two capabilities. Over-prediction is recorded beside the grant, as `minimality` and `overPredictedBy`.

`record.test.mjs` runs the parser against fixtures captured verbatim from `macos-v2-measure` run 31088841052, rather than reconstructed from the drivers' own `echo` statements — a reconstructed fixture agrees with a parser that is wrong in exactly the way the reconstruction was.

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
