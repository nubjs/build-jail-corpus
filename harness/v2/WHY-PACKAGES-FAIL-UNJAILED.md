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

## The second large category: old native addons, built against a Node their author never saw

61 of the 498 darwin records are native addons whose `make` failed. Digging past the wrappers matters here — `gyp ERR! not ok` is the outer shell and `` `make` failed with exit code `` is the next one; neither is a cause. The compiler's own first error is: `too many errors emitted, stopping now` (26), a header it cannot find (5), a call to a function ISO C99 removed (1), and 29 with no compiler line surfaced.

⛔ **Every one of the 61 ran `node -v v22.23.1`, and not one mentions an era pin.** The harness pins an era Node precisely so this population builds against the Node it was published for — but the pin **fails open silently**: if no era version resolves, or if the requested version is not present on the box, `ERA_PATH` becomes the ambient `$PATH` and nothing is recorded. So these failures were filed against the package while the cause may be the toolchain.

That is now fixed at the source rather than argued about: both POSIX drivers declare `ERA-NODE PINNED <v>` or `NOT-PINNED (<why>)` into `driver.out`, with the two negative branches distinguished — a lookup gap and an unprovisioned box are fixed in different places. **Until records carry that line, treat any native-addon failure in this corpus as unattributed between the package and the toolchain.**

Other causes gyp itself names, from the same pass: 15 `Failed to execute <node> <runner>` (old node-gyp against a modern Node), 3 HTTP 403/404 fetching a prebuilt — and `@pdftron/pdfnet-node`'s 403 is a license-gated download, which no grant can fix.

## What this means for the corpus

1. **These are genuine package defects, and no grant can fix them.** Widening the jail would not help; the binary does not exist in a consumer install. They belong in a bucket that says "broken for everyone" rather than one a reader might mistake for a capability gap.
2. **`pulumi` and `pnpm` are a different shape from the rest** — an external tool expected on `PATH`. Whether the corpus should provide those tools is a policy question, not a defect: if the answer is no, ~18 records are permanently unmeasurable and should say so.
3. **The rate is not evidence against the instrument.** The `npm rebuild` control WAS unsound for older records and that remains true — but the verdict it produced is corroborated for this population by the logs, so the two problems must not be argued from one another.
4. **It bounds the re-measure.** `CONTROL-SOUNDNESS.md` already says not to re-measure the 1498 wholesale, because the root bias runs against the `BROKEN-*` verdicts. This adds a positive reason: for the largest categories the verdict is independently confirmed, so a re-measure would spend runner hours to reconfirm a package defect.

## How to extend this

The counts above cover only `command not found`. The same method — read `driver.out`, group by the installer's own error line — applies to the rest of the failing population, and the arm-level installer errors now retained on all three drivers make it work for the other two platforms as well. Before trusting any count from it, control the extractor against a case whose answer you know: an earlier pass at this scored 430/430 because its pattern matched the harness's own verdict line rather than the installer's.
