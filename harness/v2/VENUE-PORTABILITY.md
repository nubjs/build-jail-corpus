# Venue portability — one record, any machine

A record measured on a cloud VM and a record measured on a CI runner must be **the same record**. Today they are not, and the reason is not that the venues differ — it is that a record does not carry enough about its own environment for the classifier to be venue-independent, and does not carry enough about its venue for a difference to be attributable.

Both venues are permanent. A VM is closer to a typical developer machine — a real user's Node is often under `~/.nvm`, i.e. inside `$HOME` — and `nub install` genuinely runs in CI too. So the goal is never to make one venue imitate the other. It is a record that depends on neither.

## What a record carries today

Measured on the tree at `2256f78`:

| | today | gap |
| --- | --- | --- |
| `capture.json` `roots` | `{project, home}` | the classifier also keys on the store, the interpreter and the jail home, and takes those from ambient state |
| `results.json` provenance | `platform, harness, nubGitSha, nubVersion, corpusGitSha, node, at` | nothing names the venue, the store layout, or where the interpreter lives |

The second gap is the sharper one: two records produced on different venues are **indistinguishable in the record**, so a divergence between them cannot be attributed without going back to the run.

## ⛔ What the harness must NOT normalise

The requirements below make a record portable. Read alone they invite exactly the wrong fix: making the venues *agree* by flattening the ways they differ. **The build jail runs in CI and on real laptops both.** A harness override that hides a CI-only behaviour produces a catalog that under-grants for every CI user — and under-granting breaks installs, which is the one direction this project forbids.

The temptation is concrete and it is one line of shell. Setting `CI=1` on the VM, or unsetting it on a runner, would make the two venues match immediately. It would also silently pick one store layout and leave the other unmeasured, because `is_ci()` is `std::env::var_os("CI").is_some()` and `install_report.rs` returns the isolated layout when it is set. Install scripts read `CI` too, and many change what they download or whether they build from source on the strength of it.

So the rule is:

> **The harness may normalise its own apparatus. It may not normalise the environment under test.**

Apparatus is the measuring instrument — the tracer, the fixture directory names, the catalog override that pins the grant for an arm, log verbosity that only affects our own output. Environment is anything an install script or nub itself can observe and change behaviour on: `CI`, `GITHUB_ACTIONS`, `NODE_ENV`, TTY-ness, the store layout, `PATH`, cache warmth, the interpreter's location.

Where an environment axis genuinely changes what a package needs, **the catalog takes the UNION of the capabilities across both states.** Over-granting is safe; under-granting breaks installs. A CI-only capability is not an edge case to be excluded — it is a capability a real user hits on every push.

Two consequences worth stating separately, because each has been reached for here:

- **Equal-length arm roots (R4) are apparatus, and legitimate**, because path length changes only where files land, never what the script decides to do. Contrast a throwaway `$HOME`, which is environment: it removes cache warmth that a real machine has, so it over-predicts — a safe direction, but a real one, and it must be recorded rather than assumed harmless.
- **A record must be able to say what was normalised.** See R6.

## The requirements

### R1 — `capture.json.roots` declares every root the classifier keys on

Add to the existing `project` and `home`: `jailHome`, `globalStore`, `projectStore`, `interpreter`, `toolsDir`, `temp`. Each an absolute path as it existed at capture time, or an explicit `null` where the platform genuinely has no such root — never omitted, because an absent key and an inapplicable root read the same downstream.

### R2 — the classifier reads roots ONLY from `capture.json`

No ambient environment reads, no hardcoded `~/.cache/nub` patterns, no deriving a root from the path being classified. **A root the classifier needs and `capture.json` does not declare is a hard error, not a fallback.** A fallback is precisely what makes a venue difference silent: it produces a plausible answer on the machine that happens to match and a wrong one everywhere else.

This is already proven workable — a macOS archive was re-decoded with roots taken from `capture.json` alone and reproduced the published output byte-for-byte, with a wrong-root negative control producing a different view.

### R3 — provenance records the venue and the layout

Add `venue` (`"vm"` | `"ci"` | `"local"`), `ciEnvSet` (bool), `storeLayout` (`"isolated"` | `"hoisted"`), `interpreterPath`, and `interpreterInsideHome` (bool).

`ciEnvSet` and `storeLayout` are separate fields on purpose and neither implies the other. `is_ci()` is `std::env::var_os("CI").is_some()`, and `install_report.rs` returns the isolated layout when it is set — so CI genuinely measures a different store layout. That difference is **real and must be preserved, not normalised away**; recording it is what turns it from a confound into a covered axis.

### R4 — the artifact gate does not compare sizes of toolchain-generated build files

⛔ **This requirement REPLACES "arm roots are equal length", which measurement killed.** The original acceptance test — byte-identical `config.gypi` and `*.o.d` between OBSERVE and a passing arm — is not reachable, and the reason is not path length:

- `config.gypi` differs **structurally**. It is node-gyp's dump of WHO INVOKED IT: `npm rebuild` injects npm's whole config surface (~14 keys the jailed arm has no analogue for, plus `user_agent: npm/10.9.3` vs `nub/0.6.0`). No root length adds or removes a key.
- `*.target.mk` differs because `nodedir` differs in **kind** (downloaded headers vs the Node installation) and because the include path reflects **hoisted vs isolated layout** — which is environment this document forbids normalising.

The earlier stated mechanism was wrong in DIRECTION and is retracted: the jailed home is LONGER (58 chars vs 28) and its file is still SMALLER. What survives is only the narrow measured claim that size tracks embedded path length — true, and not what is happening between these two arms.

⇒ **These files are toolchain-invocation records, not build output the package produced**, so comparing their sizes across two different package managers asks a question the artifact cannot answer. Exclude them from the SIZE comparison. Keep, for every file including these: **absent**, and **empty against a non-empty reference** — neither of which a different generator or layout can produce, and both of which are the download-blocked shape the gate exists to catch.

**The size comparison still applies to everything else, and above all to the linked output.** A truncated `build/Release/*.node` must still fail. Prove that with a test, or the exclusion has widened the gate further than it was justified to.

Retire the `.d` size exemption into this rule rather than keeping two: one mechanism-justified rule, not an extension allowlist.

### R5 — bytecode caches are dropped, symmetrically

`__pycache__/` and `*.pyc` writes are not billed, in both OBSERVE and VERIFY. Two grounds, and it needs both:

1. Measured: 10 of 10 `mkdir __pycache__` refused `EACCES` inside the provisioned node-gyp store entry, install still `rc=0`. A capability whose absence does not change the outcome is not a needed capability.
2. CPython falls back to compiling in memory when it cannot write bytecode. That is a language-level guarantee, which is what makes generalising from one measurement sound here where it would not be for an arbitrary refused write.

⛔ **This does not generalise to "writes the preset already covers".** The compiled policy is a pure allowlist with the deny floor stripped, so grants union — a read-only preset rule does not veto a read-write scope rule on the same path. `Scope::Deps` grants read-write per *declared* dependency resolved through the store, so it reaches the provisioned node-gyp for any package that declares it, and `Scope::UserHome` can cover the interpreter closure whenever the interpreter sits under `$HOME`. Dropping that broader class would discard writes a scope could have satisfied, which is an under-grant. Anything beyond bytecode needs its own refused-and-`rc=0` measurement with a control.

### R7 — OBSERVE runs with FULL USER PERMISSIONS, and asserts it

The traced script must run as an ordinary user with the permissions a real developer has — not root, and not a restricted service account. Assert it at the top of the run and fail loudly rather than measuring under a reduced token.

**Why this is load-bearing rather than tidy.** If OBSERVE is LESS privileged than a real user, a script that tries its primary path, is refused, and falls back gets measured on the fallback — and a real user with the permission takes the primary path and needs a capability we never saw. That is an under-grant, the one direction this project forbids, and it is invisible in the record.

The converse error is safe: a more-privileged OBSERVE measures a path a real user cannot take, which over-grants. So the requirement is an ordinary user, and erring toward more privilege is the tolerable side.

⛔ Do not confuse this with the TRACER's privilege. The tracer may need root (`strace`, `dtrace`, ETW) — that is measuring apparatus. The traced PROCESS is the environment under test and runs as a user.

This also settles a question raised against the Linux tracer: an `EACCES` in an unjailed OBSERVE run is a capability **no grant could supply**, because the jail can only restrict what the OS already permits and never elevate. Under R7 a refusal therefore carries no capability information, and a tracer that cannot observe refused opens loses nothing *in OBSERVE*. Refusals remain the whole signal when tracing a JAILED run to explain a failure.

### R6 — provenance declares what the harness overrode

An `overrides` object listing every environment variable the harness set, unset or redirected for the run, with its value. Normalisation that is recorded is a covered axis; normalisation that is invisible is a silent bet that it did not matter.

This is what makes the previous section enforceable rather than aspirational. A reviewer reading a record can see whether `CI` was touched, and a future reader can tell whether a grant was measured under a warm cache or a throwaway home.

## The acceptance test

Requirements R1–R6 are means. This is the deliverable, and it is a 2×2 rather than a pair, because venue and CI-ness are different axes and collapsing them is the mistake the section above warns about:

| | `CI` unset | `CI=1` |
| --- | --- | --- |
| **VM** | the real-laptop case | isolates CI-ness from venue |
| **CI runner** | isolates venue from CI-ness | the real-CI case |

Two readings come out of it, and they answer different questions:

- **Venue portability** — compare down each column. Same package, same `CI` state, different machine ⇒ **the grant must be IDENTICAL.** Not identical logs; absolute paths necessarily differ, and a harness producing identical logs would be one that had flattened a real difference. The grant is what has to agree.
- **The CI axis** — compare across each row. A difference here is a real finding, not a defect: it is a capability real CI users need. Where the two states disagree, **the catalog takes the union**, and the record says which state produced which half.

**Two controls, and the result means nothing without them:**

- **A positive control that must MATCH** — a package whose grant is already stable, agreeing down a column. Shows the pipeline runs to completion on both machines.
- **A negative control that must DIFFER** — one deliberate perturbation, such as a wrong root fed to the classifier, whose grant is expected to change. Without it, "the grants matched" is equally consistent with a comparison that can never detect a difference at all.

Report as a table: package, venue, `CI` state, grant, and whether the expectation was match or differ. **A run that reports only matches has not been shown able to find a mismatch.**

## Platform status

| platform | VM | CI | note |
| --- | --- | --- | --- |
| linux-x64 | available | available | both halves runnable |
| win32-x64 | available | available | run measurements through the SSH session itself, which is an ordinary user; a scheduled task runs as SYSTEM and silently changes the answer |
| darwin-arm64 | **none** | available | no macOS VM exists. The local Mac cannot run the OBSERVE tracer, which needs root. macOS therefore satisfies R1–R3 by construction and verifies the CI half only; its VM half is honestly open, not quietly skipped |
