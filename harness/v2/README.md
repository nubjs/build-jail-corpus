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

> Every ladder rung on Windows carries `network:true`. MEASURED on `electron-prebuilt@0.31.2`: OBSERVE logged **2417 events with `malformed: 0`** and reported `attributedPeers: 0, peers: []`, for a package whose v1 record says `network: true` — the ETW adapter missed the egress entirely. That package fails at its synthesized grant, climbs to a rung that necessarily includes network, lands WIDER than its v1 record, and the `=> MINIMUM` line then reads as **"v1 UNDER-GRANTED"**.

⇒ **A tracer blind spot presents as a defect in the thing being measured.** `--at-grant` removes that path: no synthesis, so nothing OBSERVE missed can enter the verdict. One arm, ~4× cheaper.

OBSERVE still runs, and must — the artifact gate needs its file manifest as the reference for "did this arm produce what an unjailed install produces". Only OBSERVE's *network* attribution is in question; its file output is unaffected.

| exit | verdict | meaning |
| --- | --- | --- |
| 0 | `SUFFICIENT` | installed, artifacts matched OBSERVE |
| 1 | `INSUFFICIENT` | needs MORE than this grant ⇒ if the grant came from a v1 record, that record UNDER-GRANTS |
| 3 | `VOID` | the override did not engage — **measured nothing, and is NEITHER outcome** |

⛔ **The vocabulary is deliberately not the ladder's.** Reporting `MINIMUM` here would invite exactly the conflation above: "the minimum came out wider than expected" is not "the record under-grants". And VOID stays its own verdict — collapsing it into `INSUFFICIENT` is the bug the ladder carried at three separate decision points before it was fixed.

**Verification status, stated honestly:** all four `verify` return codes were driven through the decision block with a stub and dispatch correctly (0→SUFFICIENT, 1→INSUFFICIENT, **2→VOID**, 3→INSUFFICIENT); the malformed-grant guard rejects a non-object; both modes parse; `bash -n` clean under stock bash 3.2. ⛔ **It has NOT been run end-to-end against a real package by its author** — `measure.sh` needs `strace`, so it cannot run on macOS. First real use should read its output sceptically and report anything surprising.

## What v2 does NOT change

- The catalog schema and the grant vocabulary are unchanged.
- The verification arm is still the real jail, unprivileged, on the real binary. A synthesized grant is a hypothesis until that arm passes.
- Over-granting stays safe and under-granting stays the only unacceptable direction. When OBSERVE and VERIFY disagree, VERIFY wins and the grant widens.

## Gotchas already paid for

- **`grep EACCES` is wrong.** It matches the flag name `AT_EACCESS` in ordinary successful `faccessat` calls. Only `= -1 EACCES` is a refusal. Measured on a real trace: naive 26, real 11.
- **Write intent lives in the OPEN FLAGS**, not in a later `write()` — by then the fd hides the path. `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`, plus the path-taking mutators (`mkdir`, `unlink`, `rename`, `link`, `symlink`, `truncate`).
- **`-f` is not optional.** Lifecycle scripts fork, and the interesting syscall is routinely three processes down: `dotnet-2.0.0@1.4.4`'s whole story is one `openat("/proc/self/stat")` in a bundled yarn, a grandchild of the postinstall.
- **A trace of a jailed run answers a different question.** OBSERVE must run UNJAILED or you are measuring the jail, not the package.
