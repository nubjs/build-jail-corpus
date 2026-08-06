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

### R4 — arm roots are equal length

Two identical successful installs differing only in `$HOME` length moved `config.gypi` by 175 B and `*.target.mk` by 490 B. Generated build files embed absolute paths, so their sizes measure path length, not capability, and an artifact gate comparing sizes across arms reads that as a shortfall.

The constraint covers **the home the toolchain embeds** — `config.gypi`'s `nodedir` — not only the fixture directory names. Once it holds, the `.d` size exemption in the artifact gate should be reverted rather than extended: the cause is removed, so the symptom needs no excuse.

Acceptance: `config.gypi` and `*.o.d` byte-identical between the OBSERVE tree and a passing arm.

### R5 — bytecode caches are dropped, symmetrically

`__pycache__/` and `*.pyc` writes are not billed, in both OBSERVE and VERIFY. Two grounds, and it needs both:

1. Measured: 10 of 10 `mkdir __pycache__` refused `EACCES` inside the provisioned node-gyp store entry, install still `rc=0`. A capability whose absence does not change the outcome is not a needed capability.
2. CPython falls back to compiling in memory when it cannot write bytecode. That is a language-level guarantee, which is what makes generalising from one measurement sound here where it would not be for an arbitrary refused write.

⛔ **This does not generalise to "writes the preset already covers".** The compiled policy is a pure allowlist with the deny floor stripped, so grants union — a read-only preset rule does not veto a read-write scope rule on the same path. `Scope::Deps` grants read-write per *declared* dependency resolved through the store, so it reaches the provisioned node-gyp for any package that declares it, and `Scope::UserHome` can cover the interpreter closure whenever the interpreter sits under `$HOME`. Dropping that broader class would discard writes a scope could have satisfied, which is an under-grant. Anything beyond bytecode needs its own refused-and-`rc=0` measurement with a control.

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
