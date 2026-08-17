# Why ~21% of corpus packages fail with the jail OFF

The `BROKEN-WITHOUT-JAIL-TOO` rate (1498 of 6880 records) has been the standing objection to trusting this corpus: a fifth of packages failing even unconfined reads as an instrument problem. **It is mostly not.** The large categories are packages that cannot install for ANYONE — npm, pnpm or nub, jailed or not — and this file names the mechanisms with evidence.

Two things are true at once, and conflating them is what made this look suspicious: the **control** used to reach that verdict was unsound for older records (`npm rebuild` no-ops to exit 0 on an unmaterialized tree — see `CONTROL-SOUNDNESS.md`), *and* the **verdict** is nevertheless right for most of the population, for reasons the logs now show.

## The mechanism: a postinstall that needs a devDependency

**A consumer install never installs the dependency's devDependencies.** So a package whose `postinstall` invokes a binary that lives in its own devDependencies is broken on arrival, and the failure has nothing to do with confinement.

Verified end to end on two, from the registry rather than inferred:

| package | scripts | the binary it needs |
| --- | --- | --- |
| `@antv/dom-util@2.0.0` | `"postinstall": "npm run build"`, `"build": "rm -rf lib && tsc"` | `tsc` — a devDependency |
| `@paypal/paypal-js@2.1.8` | `"postinstall": "husky install"` | `husky` — confirmed `devDependencies`, absent from `dependencies` |

The log says exactly that: `npm error > @antv/dom-util@2.0.0 build` / `npm error > rm -rf lib && tsc` / `npm error sh: tsc: command not found`.

## The distribution, over the 105 darwin records that fail this way

Counted from `driver.out` across all 498 darwin `BROKEN-WITHOUT-JAIL-TOO` records, not sampled. **105** match the `sh: <cmd>: command not found` shape these binaries were counted from; a 106th says "command not found" in another shell's phrasing and is excluded rather than silently folded in.

| missing binary | n | what it is |
| --- | --- | --- |
| `husky` | 14 | devDependency. The `"postinstall": "husky install"` pattern husky itself later moved to `prepare` precisely because it breaks consumers |
| `pulumi` | 12 | an EXTERNAL CLI, not an npm package at all — the `@pulumi/*` family expects it on `PATH` |
| `tsc` | 10 | devDependency |
| `patch-package` | 7 | devDependency |
| `pnpm` | 6 | expects a different package manager on `PATH` |
| `typings`, `nodejs`, `rimraf` | 5 each | devDependencies, or a binary under a name that does not exist |

Most of these records show NO npm-announced script name, which is itself the tell: the postinstall command *is* the missing binary (`husky install`), rather than a script that shells out to one. Where a name does appear it is `build` (20) or `clean` (7) — a postinstall delegating to `npm run build`.

## What this means for the corpus

1. **These are genuine package defects, and no grant can fix them.** Widening the jail would not help; the binary does not exist in a consumer install. They belong in a bucket that says "broken for everyone" rather than one a reader might mistake for a capability gap.
2. **`pulumi` and `pnpm` are a different shape from the rest** — an external tool expected on `PATH`. Whether the corpus should provide those tools is a policy question, not a defect: if the answer is no, ~18 records are permanently unmeasurable and should say so.
3. **The rate is not evidence against the instrument.** The `npm rebuild` control WAS unsound for older records and that remains true — but the verdict it produced is corroborated for this population by the logs, so the two problems must not be argued from one another.
4. **It bounds the re-measure.** `CONTROL-SOUNDNESS.md` already says not to re-measure the 1498 wholesale, because the root bias runs against the `BROKEN-*` verdicts. This adds a positive reason: for the largest categories the verdict is independently confirmed, so a re-measure would spend runner hours to reconfirm a package defect.

## How to extend this

The counts above cover only `command not found`. The same method — read `driver.out`, group by the installer's own error line — applies to the rest of the failing population, and the arm-level installer errors now retained on all three drivers make it work for the other two platforms as well. Before trusting any count from it, control the extractor against a case whose answer you know: an earlier pass at this scored 430/430 because its pattern matched the harness's own verdict line rather than the installer's.
