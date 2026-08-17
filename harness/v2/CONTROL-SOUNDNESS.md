# Which records rest on a control that was unsound when they were made

Read this before quoting a failure rate out of `records-v2/`, and before bumping the harness epoch.

The jail-off control decides whether a ladder of failures is a jail finding at all. It was fixed across all three drivers in the `unjailed-nub.mjs` series; the records written **before** that are a different matter, and this file says exactly which and why. The whole point is that an unsound control does not produce an error — it produces agreement, which reads as confidence.

## The two unsound controls, and which direction each errs

**macOS ran its control as `root`.** That driver measures under `sudo` and deliberately re-drops every `verify()` arm to the invoking user; the control was a byte-for-byte copy of the Linux one, which has no such need, so it inherited a plain spawn. Root succeeds where the user cannot, so the control was biased toward `rc=0` — the branch that concludes "the jail IS the difference".

**No driver asserted that its own off-switch engaged.** All three wrote `nub.jsonc` and trusted it. v1 shipped that exact shape for months: its fixture set a key whose every reader had already been deleted, so every "jail off" cell ran **jailed** and every failing package was filed as not-the-jail. Re-measuring the affected records with a working switch flipped 2 of the first 5 to real jail defects the broken control had buried.

**The error direction is not symmetric, and it decides what needs re-measuring:**

| verdict | rests on the control | root bias runs | re-measure? |
| --- | --- | --- | --- |
| `NO-STATE-PASSED` / `UNDER-PREDICTED` | **succeeding** (`rc=0`) | toward success, so toward THIS verdict | **yes** — ~209 records |
| `BROKEN-UNJAILED-NUB` / `BROKEN-WITHOUT-JAIL-TOO` | **failing** | toward success, i.e. AGAINST these | no — a control that failed *as root* is stronger evidence of real failure |

That asymmetry is why a re-measure should be targeted. Invalidating the `BROKEN-*` buckets would re-measure ~1,498 packages for no gain.

Counts at the time of writing, each recomputed from the records and the shipped catalog rather than quoted:

- **97 darwin records** carry `UNDER-PREDICTED` (the macOS spelling of the succeeded-control verdict) and **112** carry `NO-STATE-PASSED`. All 97 of the former are darwin, as expected.
- The catalog holds **34 whole-disk grants across 30 packages**, and **23 of those 30 packages are win32-only** — win32 asked for the whole disk where no POSIX platform did. Regenerate with `node corpus/win32-disk-worklist.mjs --catalog <path>`.

⛔ **`measure-windows.mjs`'s header says "45 of the 62 `write:"disk"` grants" — that figure is STALE against the shipped catalog, which has 34.** It is quoted in several places and it was nearly repeated here. The point it makes still stands and is worth keeping: Windows matters out of proportion to its share, because the widest capability the jail hands out is disproportionately decided on the one platform whose control could least prove it was measuring the jail's absence. Use the recomputed numbers above, and prefer the script to any number written down.

## Do not bump the harness epoch casually

`record-validity.mjs` walks epoch transitions, and a **targeted** transition requires an exact `toHarnessSha256` that a non-invalidated record must land on and that must equal the CURRENT instrument identity.

That digest is **computed from harness content** — `instrument.json` stores only `harnessEpoch`, `inputs` and `excludePrefixes`, never the digest. So the moment the harness changes again, a transition's hardcoded target stops matching and **every** record falls to `transition target does not match current instrument`. One stale hex string mass-invalidates the corpus, silently.

Consequences:

- The epoch bump belongs to a moment when the harness is **final**, not mid-series.
- Harness edits that do NOT bump the epoch invalidate nothing. That is why the corpus still trusts records measured under the old controls — the fix alone did not reclassify them.
- `scopeMatches` supports `platforms` / `packages` / `verdicts`, ANDed, so the targeted scope above is directly expressible.

## An exit code cannot justify a narrowing, and neither can the artifact gate alone

`verify()`'s sufficiency test is `rc == 0 && grc == 0` — exit code AND artifact gate — so the normal path is not exit-code-only. Two residuals survive it:

1. **The `grc == 3` branch gates on `rc` alone** (`measure.sh`), the no-artifact-reference case. Already documented in that file; noted here because it is easy to forget when reading a grant.
2. **A source-build fallback defeats both checks, and nothing covers this.** Measured directly: with `network` stripped from `gifsicle@4.0.1`'s grant, run with a fresh `HOME` and `NUB_CACHE_DIR` so no promoted cache could satisfy the fetch, the install returned **rc=0** — and the log shows `⚠ gifsicle pre-build test failed` then `✔ gifsicle built successfully`. The download WAS denied; the package compiled from source instead. Same artifacts either way, so `rc` and the gate both pass while the capability need differs: network versus a C toolchain that is not always present.

So a narrowing that removes `network` from a package with a build fallback trades one dependency for another silently, and can break on a machine without a compiler while every measurement said it was fine. `corpus/win32-disk-worklist.mjs` therefore emits a **re-measure worklist** rather than narrowing anything itself.

**Verifying enforcement needs a probe with no fallback path.** Three attempts each picked a target that could not answer the question: `esbuild` ships its binary in a platform package so its postinstall never fetches; `gifsicle` under a warm cache was satisfied by an earlier run's promoted `.cache`; `gifsicle` clean has the source-build fallback above.
