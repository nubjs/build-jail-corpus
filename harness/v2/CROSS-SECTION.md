# The cross-section — the same ~100 packages on every platform

`VENUE-PORTABILITY.md` sets the completion bar as ~100 packages per platform, **the same ~100 on all three**, stratified rather than ranked. This document is the selection method; [`cross-section.json`](cross-section.json) is the list `run-batch-v2.mjs` consumes.

**The list is committed, not regenerated.** A regenerated sample is a different sample, and a per-platform difference is only attributable to the platform if the sample is identical. Re-deriving it from a live registry would silently re-cut the strata as packages publish new versions.

## What it is for, and what it is not

The question is *does a grant differ by platform, and why* — not *what does the average npm package need*. So the sample is built to **contain the shapes that could differ**, and it deliberately over-represents rare ones. It is **not** a random sample of npm and no frequency claim should be read off it. Where a rate matters, it has to come from the population census below, not from the 120.

⛔ **Not ranked by downloads.** A popularity ranking is dominated by one or two shapes — 1,289 of 2,087 measurable install scripts in the corpus population are a plain `node <script>` postinstall — and would leave every interesting behaviour unmeasured. Popularity is a tie-breaker *within* a stratum, never the selection.

## The population it was drawn from

| | |
| --- | --- |
| v1 corpus records | 6,648 across three platforms |
| distinct `pkg@version` | 2,263 |
| declaring an install script, non-malicious | 2,087 |
| of those, `MINIMUM` (measurable) | 1,633 |

Install-script text was harvested from the registry for **all 680 distinct package names**, and every stratum below is classified from **the actual script body**, not from the package name.

⛔ **The harvest is validated, because its failure mode is silent.** The first attempt requested `application/vnd.npm.install-v1+json` — the abbreviated packument, which **omits `scripts` entirely**. Every one of 552 specs classified as `no-hook`, plausibly and wrongly. The harvester now asserts two scripts whose text is known by hand (`ttf2woff2@1.2.3` → `(node-gyp rebuild > builderror.log) || (exit 0)`, `kerberos@7.0.0` → `prebuild-install --runtime napi || node-gyp rebuild`) and refuses to report counts unless both are recovered.

## Population shape — the denominators the sample is drawn against

Measured over the 2,087 script-declaring specs:

| shape | in population | in cross-section |
| --- | --- | --- |
| plain `node <script>` postinstall | 1,289 | 10 |
| v1 minimum was `(nothing)` | 782 | 10 |
| known-hard families | 352 | 12 |
| shell compound (`&&`, `\|\|`, `;`) | 240 | — (subsumed) |
| prebuilt download | 155 | 10 |
| native `node-gyp` build | 69 | 10 |
| v1 minimum needed 2+ capabilities | 69 | — (see N≥2 below) |
| `X \|\| node-gyp rebuild` fallback | 31 | 10 |
| shell script (`./x.sh`, `sh x.sh`) | 12 (6 measurable) | 6 |
| **shell redirect (`>`)** | **11** | **11 — all of them** |

**The two rarest strata are taken whole.** There are only 11 measurable packages in the entire corpus population whose install script contains a `>` redirect, and 6 whose script invokes a shell script. Sampling those would have produced zero or one.

## Strata, and why each earns a slot

- **`existing-corpus` (45)** — every package with a v2 record. Making the list a superset means the 45 linux-x64 and 3 darwin-arm64 records get re-measured in a run that was happening anyway, and the old-vs-new diff shows exactly what the recent harness fixes bought.
- **`pre-descent-over-predicted` (5)** — the `PRE-DESCENT.json` set, whose published grant is wider than their own arms measured. They are the records that most need re-measuring.
- **`native-gyp` (10)** — a real compile. The platform axis that produced the sharpest divergence so far.
- **`prebuilt-download` (10)** and **`fallback-shape` (10)** — `X || node-gyp rebuild` is the shape that produced a genuine per-platform split: `kerberos@7.0.0` is `{}` on macOS, where the runner's toolchain makes the fallback succeed, and `{"network":true}` on Linux, where it does not. Ten more of that shape is how we learn whether that split is typical or a one-off.
- **`pure-js-postinstall` (10)** — the modal shape, and the control for the relative-path guard: a `node` script resolving with `__dirname` writes absolute paths and does not trip it.
- **`shell-redirect` (11, all)** — the shape that *does* trip it. On macOS a lifecycle script's cwd is unobservable (posix_spawn `addchdir_np`; dtrace's `cwd` yields a basename; `fbt::chdir*:entry` matches nothing), so a relative write cannot be placed and the grant is widened. **Whether that widening is rare or routine is currently an n=3 anecdote** — 3 of 3 darwin packages trip the guard, but only 1 of 3 widens a grant. These 11 are what turn it into a quotable mechanism or kill it.
- **`shell-script` (6, all measurable)** — an install script that hands control to a `.sh` file, where the harness sees the shell and not the work.
- **`known-hard` (12)** — electron, playwright, cypress, puppeteer, hugo, ffmpeg, the drivers. Re-confirmed rather than assumed stable.
- **`needs-nothing` (10)** — the modal answer, and the case v2 could not express until recently. A stratum of packages whose correct grant is `{}` is how an over-granting regression gets caught.
- **`n>=2-candidate` (10)** — see below.
- **win32 strata (9)** — `win32-structurally-refused` (3: `handbrake-js@8.0.2`, `hugo-extended@0.153.5`, `java@0.18.0` — the only `BROKEN-EVEN-WITH-EVERYTHING` set in the corpus), `win32-no-state-passed` (2), `win32-write-disk` (2), `win32-8.3-shortpath-candidate` (2).

## N≥2 is a recorded property, NOT a selection requirement

`measure.sh`'s JOINT-NARROW arm needs a package whose synthesis over-predicts by **two or more** capabilities. **Nothing in this list was chosen to manufacture one, and the joint arm gates nothing.**

The rate is known: an enumeration of all 45 v2 records found 6 candidates with ≥2 capabilities, 5 ruled out with a named reason each, leaving 1 live — **roughly 2% of packages**. A stratified hundred contains a couple at that rate on its own, so no stratum slot was sacrificed and no package was added that did not otherwise belong. If the arm never fires on the existing 45, the honest report is that N≥2 does not occur there, and the first live firing comes out of the cross-section naturally.

Already ruled out, recorded in `cross-section.json` so nobody re-derives them: `@pulumi/kubernetes@0.14.0` (`BROKEN-WITHOUT-JAIL-TOO`), `@pulumi/gcp@0.16.9` (re-measures `{}` at N=0, arms `gate-vacuous`), `@apollo/rover@0.4.8` (`MINIMAL`, nothing droppable), `@notarize/qlc-cli@0.4.0` (N=1 — the single arm *is* the joint case), `@playwright/browser-chromium@1.61.1` (synth arm `rc=1`, so no descent runs). **The live one is `playwright-chromium@0.17.0`.**

⛔ **One trap worth recording, because the tempting proxy is backwards.** "v1 needed 2+ capabilities" selects the wrong packages: a genuinely multi-capability minimum has *nothing* droppable, so N=0. N≥2 needs the opposite — a package that **touches** several capabilities during OBSERVE and needs **none**. The 10 `n>=2-candidate` entries are selected that way (v1 minimum `(nothing)`, install script demonstrably downloads: `re2@1.26.1`, `lzma-native@4.0.6`, `duckdb@1.4.4`, `@discordjs/opus@0.10.0`, `farmhash@2.1.0`), but they earn their slots as downloaders regardless of what N turns out to be.

**The arm itself is proven working** — it fired on `ttf2woff2@1.2.3` (darwin-arm64) and verified `{}` across 3 capabilities. ⛔ But `ttf2woff2` is **not** a Linux subject: N=3 on macOS only because the cwd guard widens its synthesis, N=0 on Linux which bills its one write as free `ownPkg`. Both platforms end at `{}` — they agree.

## ⭑ `playwright-chromium@0.17.0` — the persistent-leaf stress case

In the list for a reason independent of N≥2. Its documented false `OVER-PREDICTED` came from an `ms-playwright` replay, so it stresses the persistent-leaf purge harder than anything else in the corpus; `FALSIFICATION.md:75` names it the most valuable case to add.

## ⛔ Comparing three platforms' logs: triage by ARTIFACT, never by error string

The cross-section exists to compare platforms, and **the same denial does not produce the same words on every platform.** Measured: an AppContainer read refusal surfaces as `EPERM … open` on a CI runner and as

```
Error [ERR_MODULE_NOT_FOUND]: Cannot find module 'C:\jailv\…\@apollo\rover\install.js'
```

on `nub-win3` — the file present on disk the whole time, confirmed by `fsutil hardlink list`. Node's ESM resolver converts the refusal into "cannot find module".

⇒ **Triaging by grepping for `EPERM` scores a reproducing venue as non-reproducing**, and that mistake has already produced one retracted "the VM cannot reproduce it" claim. The driver's `missingArtifacts` gate is immune because it compares the artifact manifest rather than the error text. **Any cross-platform comparison built on this list must key on artifacts, not on log strings.**

## ⛔ Three path encodings for the same package, and they differ

A scoped package is spelled three ways across the surfaces this list touches:

| surface | spelling |
| --- | --- |
| npm / this list | `@scarf/scarf@1.4.0` |
| virtual store entry | `@scarf+scarf@1.4.0-<hash>` |
| side-effects cache | `@scarf__scarf@1.4.0` — **double underscore** |

Measured. **Any code that slugs a package name for one surface and reuses another's spelling silently no-ops on every scoped package** — which is 43 of the 120 entries here, counted. That has already shipped once in this project.

## ⛔ Hash the artifact; do not trust the path

Four separate incidents in one day of *a path resolving to something other than what the caller believed*: a shared mutable `CARGO_TARGET_DIR` overwriting a control binary at the path it kept using, `nub-ci.exe`, a CI cache `restore-keys` prefix fallback that would have served a 14-hour-old binary, and an abbreviated packument silently omitting `scripts` from this document's own harvest. `certutil -hashfile` settled the first; a known-answer control settled the last. **If a run built from this list resolves a path to a binary, a cache or a record, hash it.**

**Practical caveat for `nub-win3`:** three early arms with a binary confirmed pre-fix passed `rc=0` at the wide grant before the CAS at `%LOCALAPPDATA%\nub\store\v1` was wiped, and the same binary fails once it is wiped and repopulated. Two hypotheses were tested and refuted; it is open. **Wipe the CAS before a jail A/B on that box, or a pre-fix binary can look fixed.**

## Malicious-package exclusion

Every candidate was OSV-screened, and **the screen's own self-test was run first**, so a clean result rests on an instrument shown to alarm on `@ctrl/tinycolor@4.1.2`. Result: **120 distinct package-versions screened, none covered by a `MAL-*` advisory.**

Excluded outright, by **package name rather than by version** — a package with any known-malicious release does not earn a cross-section slot: `@azure-devops/mcp`, `apollo-server`, `webdev-toolkit`, `@google/clasp`. (The corpus's five `REFUSED-MALICIOUS` records are `@azure-devops/mcp@0.1.0`, `apollo-server@0.1.5`, `webdev-toolkit@1.13.3`, `webdev-toolkit@2.4.3`, `@google/clasp@1.0.7`.)

⛔ **`prescreen-queue.mjs` reads `pkg`, not `package`, and fails OPEN on the wrong key.** A queue file using `package` produces `undefined@<version>` for every row and reports `PRESCREEN: ok` having screened nothing — while the file's own header states it fails closed. The count line is the only tell: *"screening N distinct package-version(s)"* where N is the number of distinct **versions**, not packages. Check that N equals the row count before believing a clean result.

## What could not be filled, stated plainly

- **Windows 8.3 short paths — NOT filled by evidence.** The temp redirect moved that axis out of `iedriver@4.0.0` and the recorded short-name map is now empty on both runner cells. Nothing in the corpus population can be *mechanically* selected for hitting 8.3, because the trigger is a path property of the runner, not of the package. The two entries tagged `win32-8.3-shortpath-candidate` (`iedriver@4.0.0`, `@sitespeed.io/edgedriver@100.0.1185-29`) are **the historical subject and its nearest sibling, offered as candidates rather than as a filled stratum.** If neither produces a non-empty map, the honest conclusion is that the mechanism has 6 unit tests and no live subject, and it should be either exercised with a synthetic fixture or retired.
- **`shell-script` is 6, not 12.** Only 6 of the 12 shell-script packages in the population have a `MINIMUM` verdict; the rest are `BROKEN-WITHOUT-JAIL-TOO` and would burn a slot to re-confirm a broken install.
- **No stratum for a package that needs `write:"disk"`.** The v1 corpus records 96 win32 packages at a `write.disk` state, but that is a v1 ladder rung, not a v2 grant, and v2 has never produced one. Two are included as `win32-write-disk` to find out whether the state survives v2 at all.

⛔ **This list makes no claim that a venue cannot reproduce a jail denial.** An earlier draft carried one; it was retracted. `nub-win3` **does** reproduce the store-entry behaviour — interleaved, one variable, same package and grant: pre-fix `rc=1` hardlinked, integration `rc=0` copy, twice each, agreeing with two real-runner runs. The apparent non-reproduction was the error-string triage described above, not the venue.

## Count

**120 packages.** Above the ~100 bar because the mandatory superset (45 existing records + 5 PRE-DESCENT) overlaps the shape strata only partially. Trimming to exactly 100 would have meant dropping either existing-corpus continuity or a rare stratum, and both are worth more than the round number.

## Changelog

- 2026-08-06 — Initial selection. Population 2,087 script-declaring specs across 680 package names; scripts harvested from the registry and classified from the script body; OSV-screened after a self-test.
