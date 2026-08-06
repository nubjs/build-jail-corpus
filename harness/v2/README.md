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

## What v2 does NOT change

- The catalog schema and the grant vocabulary are unchanged.
- The verification arm is still the real jail, unprivileged, on the real binary. A synthesized grant is a hypothesis until that arm passes.
- Over-granting stays safe and under-granting stays the only unacceptable direction. When OBSERVE and VERIFY disagree, VERIFY wins and the grant widens.

## Gotchas already paid for

- **`grep EACCES` is wrong.** It matches the flag name `AT_EACCESS` in ordinary successful `faccessat` calls. Only `= -1 EACCES` is a refusal. Measured on a real trace: naive 26, real 11.
- **Write intent lives in the OPEN FLAGS**, not in a later `write()` — by then the fd hides the path. `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND`, plus the path-taking mutators (`mkdir`, `unlink`, `rename`, `link`, `symlink`, `truncate`).
- **`-f` is not optional.** Lifecycle scripts fork, and the interesting syscall is routinely three processes down: `dotnet-2.0.0@1.4.4`'s whole story is one `openat("/proc/self/stat")` in a bundled yarn, a grandchild of the postinstall.
- **A trace of a jailed run answers a different question.** OBSERVE must run UNJAILED or you are measuring the jail, not the package.
