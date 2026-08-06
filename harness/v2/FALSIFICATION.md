# The falsification control

Everything else in this harness is a check that passes. This is the one whose job is to show the harness can still return the wrong-answer verdict at all.

Run it before a sweep:

```sh
node harness/v2/falsify.mjs --nub <nub-with-the-override-feature> --json /tmp/falsify.json
```

`run-batch-v2.mjs` runs it automatically on Linux before it starts measuring, and refuses to start the batch unless it passes — on `FAIL` and on `INCONCLUSIVE` alike, because both mean the slice would measure nothing worth keeping. `--no-falsify` skips it. The full six-arm run took **55 seconds** on the corpus VM, against a slice budget of roughly 13 minutes per package, so the pre-flight does not use `--quick`.

| exit | meaning |
| --- | --- |
| 0 | every deliberately-narrowed grant was detected, and every correct grant installed |
| 1 | **the harness accepted a grant known to be insufficient**, or a known-minimal grant stopped installing |
| 2 | inconclusive — the venue could not put the question (VOID arm, registry down, timeout) |

## Result, linux-x64, 2026-08-06

**The harness detects an under-grant on both capability axes.** `nub v0.7.1` built with `--features nub-cli/build-jail-catalog-override`, driver at `main`, on the corpus VM. Six arms, `falsify: PASS`, exit 0.

| case | arm | grant | verdict | install rc | artifact gate | refusal | detectors |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `@apollo/rover@0.4.8` | wrong-cold | `{"network":true}` | INSUFFICIENT | 1 | `6/6 missing=0` | seen | `rc` |
| | right | `{"write":{"deps":true},"network":true}` | SUFFICIENT | 0 | `6/6 missing=0` | — | — |
| | wrong-warm | `{"network":true}` | INSUFFICIENT | 1 | `6/6 missing=0` | seen | `rc` |
| `hugo-extended@0.141.0` | wrong-cold | `{}` | INSUFFICIENT | 1 | `9/12 missing=3` | seen | `rc`+`gate` |
| | right | `{"network":true}` | SUFFICIENT | 0 | `12/12 missing=0` | — | — |
| | wrong-warm | `{}` | INSUFFICIENT | 1 | `9/12 missing=3` | seen | `rc`+`gate` |

The refusals, quoted from the arms' own logs:

```
EACCES: permission denied, mkdir '<store>/binary-install@0.1.1-cb634da28dfef7ed/node_modules/binary-install/bin'
```
```
EAI_AGAIN / ENETUNREACH / ECONNREFUSED on https://github.com/gohugoio/hugo/releases/download/v0.141.0/hugo_extended_0.141.0_linux-amd64.tar.gz
```

**And the oracle was shown going red in the same session.** Against a driver mutated by one line (`local rc=$?; rc=0`), `falsify: FAIL`: `@apollo/rover`'s wrong arm was reported `SUFFICIENT` and raised the P0 line, while `hugo-extended`'s stayed `INSUFFICIENT` via the gate and failed instead on `detector 'rc' did not fire`. Both mechanisms, as designed.

## Why

Over-granting is safe. Under-granting breaks a stranger's install. So the only harness failure that matters is one where a too-narrow grant comes back sufficient — and by construction that failure is silent. It does not crash, it does not warn, and it raises the agreement rate rather than lowering it.

`measure.sh` already carries a long list of assertions guarding routes to exactly that failure: the override engaged, the jail was stated explicitly, the arm root has a unique name, the store was evicted, `running build scripts` appears in a log. Every one of them was written after it had already produced a wrong record. What none of them do is demonstrate, end to end on a real package, that the assembled pipeline still says no when the answer is no.

Three separate checks in this project turned out to be structurally incapable of failing:

- an arm passed that should have failed, because a warm cache satisfied a download the jailed run was supposed to be denied — the record then called a needed capability unnecessary;
- a package's artifact gate could never go red, because the package ships its build output prebuilt, so the gate's reference set was just the tarball contents, and the script ended `|| (exit 0)`;
- a guard asserting that a directory name contained an uppercase letter matched a lowercase name, because bash 3.2 under `en_US.UTF-8` range-collates `*[A-Z]*`.

All three share one shape: a predicate nobody had watched go red for the right reason.

## What it does

Per case, three real end-to-end driver runs. Not a unit test of a predicate — the three failures above all hid in the seams between jail, install, artifact gate and exit code, and a predicate test steps over exactly those seams.

Each run is one `measure.sh … --at-grant '<json>'` invocation. `--at-grant` is the right primitive for the same reason its own header gives: it runs one arm at a stated grant with no synthesis and no ladder, so nothing OBSERVE missed and nothing the ladder recovered can enter the verdict.

| arm | grant | must report |
| --- | --- | --- |
| `wrong-cold` | the recorded minimum **minus one capability**, run first | `INSUFFICIENT` |
| `right` | the recorded minimum | `SUFFICIENT` |
| `wrong-warm` | the same narrowed grant again, after `right` has filled every cache | `INSUFFICIENT` |

**How literally "one variable" holds, and where it does not.** For `@apollo/rover` the three arms differ in the grant JSON and nothing else. For `hugo-extended` the narrowed grant is `{}`, and `measure.sh` cannot express an empty grant as a catalog entry — nub rejects an entry that widens nothing — so it writes a sentinel entry for an unrelated package name instead. That arm therefore also differs in *which package the catalog names*. The difference is forced by the driver and is stated here rather than papered over; the rover case exists partly so that at least one case varies the grant and strictly nothing else.

Two further limits worth naming. The control is **point-in-time**: it says the binary and driver detected a wrong grant at the moment the batch started, not that they still do at package 80 — the mid-batch binary rebuild recorded below would not be caught, and `run-batch-v2.mjs` reads `nub --version` once before the loop, so every record written after such a swap would claim the pre-swap version. Closing that needs the batch to hash the binary at pre-flight and re-check it per package; it is not done. And the write axis rests on a single package because `@apollo/rover@0.4.8` is the only write-axis `MINIMAL` record in the linux corpus; a second one should be added as soon as one exists.

**The passing control is not ceremony.** Without it, `wrong-cold` failing proves nothing: a broken venue, an unreachable registry, or a nub binary built without `build-jail-catalog-override` fails every arm, and "the wrong grant failed" then reads as a working oracle while the harness is dead. That is not hypothetical — it happened during this file's own bring-up, below.

**`wrong-warm` tests the warm-state trap instead of avoiding it — but note what these two cases actually put it through.** Neither package writes into the persistent redirect leaves (`tools/ms-playwright`, `tools/electron-cache`) or leans on `jail-home`, so what `wrong-warm` genuinely exercises here is the store eviction, including the transitive-dependency eviction that `@apollo/rover` needs. A case that downloads into one of the persistent leaves — a Playwright or Electron package — would stress it harder and is the most valuable case to add next.

⛔ **`wrong-warm` cannot cover replay via nub's side-effects cache, and no choice of package would change that.** Every arm writes `side-effects-cache=false` into its own `.npmrc` (`measure.sh`, in `verify()`), so no arm can populate that cache at all — the warm state `wrong-warm` builds up never contains a side-effects entry. MEASURED on `msgpackr-extract@3.0.4`: two installs sharing one cache produce `side-effects-cache: saved` then `restored` **without** that `.npmrc`, and neither line plus no entry on disk **with** it. So this control's green says the store-eviction and persistent-leaf paths held; it says nothing about the side-effects path, which is closed by a setting rather than by eviction and is asserted separately by the `REPLAY CONFIRMED` check in `verify()`. Worth stating because the obvious reading — "the warm arm covers replay" — is the one that would let a regression there pass unnoticed.

For the mechanism itself: `measure.sh` evicts a great deal per arm: the store entries for the package and its whole observed closure, the side-effects memo, `jail-home/<pkg>-*`, and the `ms-playwright` / `electron-cache` redirect leaves. Every one of those evictions was added after a warm artifact had already masked a denial. Ordering `wrong-cold` first gives it the coldest venue available; running the identical grant again after `right` has downloaded the binary, materialised the store and filled the private home asks whether any surviving warm state can satisfy the operation the grant forbids. A `wrong-warm` that passes where `wrong-cold` failed is not a flake — it is the arm-independence guarantee failing, the same defect that produced a false `OVER-PREDICTED` on `playwright-chromium@0.17.0`.

## A negative verdict is not enough

A wrong arm that comes back `INSUFFICIENT` has told you the driver said no. It has not told you the driver said no *for the right reason*, and a no for the wrong reason is how the corpus acquires a spuriously wide grant.

So each case names the OS-level refusal its removed capability must produce, and the arm's own `i.log`/`a.log` must carry it:

Each `refusal` is a **conjunction** — a failure KIND and the SUBJECT it must have failed on — because a bare errno is evidence that something failed, not that the grant was enforced:

| removed | failure kind | subject |
| --- | --- | --- |
| `write.deps` | `EACCES` | `binary-install` — the sibling package whose `bin/` the script must create |
| `network` | `EAI_AGAIN` / `ENETUNREACH` / `ECONNREFUSED` / `EHOSTUNREACH` | `github.com` — the host the script fetches its release from |

The subject term is not decoration. nub's own **registry** fetch runs outside the jail, so without it a transient `ECONNREFUSED` from anywhere in the install would satisfy the network case and report a clean detection of a denial that never happened.

That is the positive control: proof the fatal operation was *attempted and denied*, rather than skipped because something upstream had already satisfied it. An arm that fails with no matching refusal is reported as a failure of this control, not as a detection.

**And the control arm must be clean of it.** A refusal pattern is only ever *required* on a wrong arm, so a pattern loose enough to match anything would satisfy every wrong arm and be read nowhere else — leaving the oracle green while proving nothing. The `right` arm installs successfully under the full grant, so the same pattern must be *absent* there, and the run fails if it is not.

## And the script has to have run at all

Separately from *why* an arm failed, every arm — wrong and right alike — must show that the lifecycle script executed. A replayed arm materialises from the store without spawning the script, and on a wrong-grant arm that is indistinguishable from a detection.

Each case therefore carries a `ranEvidence` regex matching output only that package's own script can produce, in either shape:

| case | evidence |
| --- | --- |
| `@apollo/rover@0.4.8` | `Downloading release from …` when the write is permitted, the `binary-install/index.js` require-stack when it is not |
| `hugo-extended@0.141.0` | `✔ Hugo installed successfully!` or `✖ Hugo installation failed. :(` |

**And there is a negative control on the control.** A `ranEvidence` regex loose enough to match ordinary install chatter would be a check that cannot fail — this file's own defect, one level up. So the regex must also be *silent* on `observe/fetch.log`, which is an `npm install --ignore-scripts` of the same package in the same run: an install where the script provably did not execute. Validated in both directions on five real arm logs before being wired in.

### And the arm has to have been independent

`measure.sh` prints how many store entries it evicted before each arm — the mechanism that makes two arms independent. Nothing was reading that number. Its first revision used a slug that matched nothing for **scoped** packages (`@babel/core` became `-babel-core`), so it removed zero entries for a large share of the corpus while looking healthy, and `@apollo/rover` is scoped. The `right` and `wrong-warm` arms now fail if the eviction removed nothing. `wrong-cold` is exempt: it runs first, and an empty store there is exactly what a cold venue should look like.

### Why the ran-evidence control replaced the driver's own replay check

`measure.sh` warns `REPLAY SUSPECTED` when no arm log matches `running build scripts for`. That predicate is satisfiable only by packages on nub's **default-trust** list, where the script runs during `install` and nub logs `WARN defaultTrust: running build scripts for <pkg>`. For every other package `install` logs `WARN ignored build scripts for N package(s)` and the script runs later under `approve-builds --all`, which prints neither line.

Measured on both sides in a single run:

| package | on default-trust? | `running build scripts for` | driver verdict | reality |
| --- | --- | --- | --- | --- |
| `@apollo/rover@0.4.8` | yes | present | quiet | script ran |
| `hugo-extended@0.141.0` | no | absent | `⛔ REPLAY SUSPECTED` | script ran — `✔ Hugo installed successfully!`, 12/12 artifacts |

**10 of the 45 committed `records-v2/runs/linux-x64/*/*/driver.out` files carry the warning.** This is the failure mode the surrounding comment in `measure.sh` warns about in its own words — "a warning that fires on arms that genuinely ran trains its reader to skip it, so a REAL replay sails through".

`falsify.mjs` neither fails on it nor trusts it: it prints it, and answers the question directly with `ranEvidence`. Fixing the driver's predicate is `measure.sh`'s to make.

## The detectors are not interchangeable

Measured, and it is why one case would not have been enough:

| case | grant | install rc | artifact gate | caught by |
| --- | --- | --- | --- | --- |
| `@apollo/rover@0.4.8` | `{"network":true}` | 1 | `artifacts=6/6 missing=0` — **passes** | rc only |
| `hugo-extended@0.141.0` | `{}` | 1 | `artifacts=9/12 missing=3` | rc **and** the gate |

`@apollo/rover`'s postinstall writes into a sibling package (`node_modules/binary-install/bin`), and `artifact-gate.mjs` is scoped to the measured package's own directory by deliberate design. So the gate passes that arm 6/6, and the only thing between a narrowed grant and a `SUFFICIENT` verdict is the install exit code.

If a future change made the driver tolerant of a non-zero rc, `hugo-extended` would still be caught by the gate and the regression would go unnoticed. Each case therefore declares the detectors that *must* fire, and the observed set is printed on every arm so a change in the detection story is visible even when it does not fail the run.

**`artifacts=ABSENT` does not count as the gate firing.** The gate reports `ABSENT` with `missing=1 <package absent>` when the package directory is not in the arm tree at all — which is what a wholesale install failure looks like, and is the same event that made `rc` non-zero. Counting it would give a case asking for two independent detectors one signal counted twice, and it would never notice that the per-file manifest had stopped discriminating. The gate has genuinely fired only when the package is present and some of its own files are missing or short.

## Proving the oracle can fail

An oracle that has never gone red is the thing it exists to catch.

```sh
bash harness/v2/falsify-selftest.sh <nub-binary>
```

That script writes a deliberately broken copy of `measure.sh` beside the real one, runs `falsify.mjs --driver` against it, asserts the run goes red for both of its two mechanisms, and deletes the copy. It exits 1 if `falsify.mjs` passed a driver that cannot detect a wrong grant.

The mutation models the real `|| (exit 0)` failure — one line in `verify()`, so nothing else about the driver moves:

```sh
local rc=$?; rc=0   # SABOTAGE: the install exit code never reaches the driver
```

The copy must live beside `measure.sh`, because the driver resolves `artifact-gate.mjs` relative to its own directory; a copy under `/tmp` would fail the gate for a reason that has nothing to do with the mutation, and the self-test would pass for the wrong reason.

Under that mutation the two cases fail for two different reasons, which is the point of carrying both:

- `@apollo/rover` — the gate already passes this arm, so with rc suppressed the driver reports `SUFFICIENT` for a grant the package cannot install under. The oracle raises the P0 line.
- `hugo-extended` — the gate still catches it, so the verdict stays `INSUFFICIENT`; the oracle fails it instead on `detector 'rc' did not fire`, naming the detector that was lost.

## Why these two packages

They were not picked only for their axes. Measured from their own arm logs, the pair also spans the two ways nub runs a lifecycle script, which is a different variable and one the corpus depends on:

| case | axis | nub's script path |
| --- | --- | --- |
| `@apollo/rover@0.4.8` | `write.deps` | **default-trust** — the script runs during `install`, logged as `WARN defaultTrust: running build scripts for …` |
| `hugo-extended@0.141.0` | `network` | **untrusted** — `install` logs `WARN ignored build scripts` and the script runs later under `approve-builds --all` |

The untrusted path is the majority of the corpus, so a case table made only of default-trust packages would leave it unexercised. That is also why `hugo-extended` is kept even though its committed record carries `notes: ["replay-suspected"]` and the clean alternatives (`kerberos@7.0.0`, `sharp@0.32.6`, `saucectl@0.132.0`) are marginally faster: that note is the false alarm described above, and it is a *consequence* of the very path this case exists to cover.

## Adding a case

A case is only as good as the record it cites. Read `sufficient` off a committed `records-v2/runs/<platform>/<slug>/<version>/results.json` with `verdict: MINIMUM` **and** `minimality: MINIMAL` — MINIMAL is the descent having tested each capability's removal individually and found it necessary, so `insufficient` is the corpus's own answer with one term deleted rather than a guess. Then pick a `refusal` regex anchored on something specific to that package, so it cannot be satisfied by an unrelated denial elsewhere in the tree.

Cheap and fast beats thorough here: this runs before every batch, so a case that costs ten minutes will get skipped.

## Bring-up record

The control caught a real venue defect the first time it ran end to end, which is the best evidence available that it is not decorative.

On `nub-corpus-linux`, four manual arms passed at 22:1x UTC on 2026-08-06. Twenty minutes later the identical invocation returned `VOID` on every arm. The shared `~/nub/target/release/nub` had been rebuilt at 22:39:30 UTC without `--features nub-cli/build-jail-catalog-override`, so nub refused `NUB_BUILD_JAIL_CATALOG` outright:

```
Error: NUB_BUILD_JAIL_CATALOG is set, but this binary was not built with the
`build-jail-catalog-override` feature, so it cannot honour it.
```

That refusal goes to the arm's `i.log`; the driver sees only `OVERRIDDEN=0` and reports `VOID` with no cause, so the run reads as a harness defect until someone opens the arm log.

`measure.sh` has since grown its own pre-flight for this exact cause — it exercises the binary before OBSERVE and aborts `rc=3` — so that is now the primary detector and `falsify.mjs` matching the string is a backstop for the case where a binary passes the pre-flight and still fails per-arm. Worth recording how the pre-flight arrived, because it is the same lesson: its first revision grepped the binary for the feature *name*, which appears only in the error text a **featureless** build prints, so it refused every correct binary and admitted every broken one. Measured on three binaries side by side. A capability has to be asked of the artifact by exercising it, never inferred from something that merely correlates with it.

Two things follow, and both are in the code:

- **VOID is `INCONCLUSIVE`, not `FAIL`.** Reporting a featureless binary as "the harness cannot detect under-granting" would burn the alarm this file exists to raise. Both still exit non-zero — an unanswered falsification control is never a green light.
- **A batch must not point at a binary a sibling can rebuild under it.** Build the measuring binary into its own `CARGO_TARGET_DIR` and pin the path.

## The two platform oracles, assessed

Both were named in an earlier survey as cheap ways to get tracer-independent ground truth. Neither is worth building yet, and the reasons differ.

**⛔ Everything in this section is INFERRED from documented semantics, not MEASURED.** Neither oracle was built or run; what follows is why building them was not the next move, not a result. The one MEASURED input is the `unparsed: 0` figure quoted for the Linux tracer, read off the `EVENTLOG-STATS` line of the runs above. (`malformed` is a *Windows* `classify.mjs` field and does not appear in the Linux stats line — do not conflate them.)

**Linux overlayfs upperdir — no.** Mounting the fixture on an overlay and reading `upperdir` afterwards does give a list of files written without consulting any tracer. But it cross-checks the instrument that is already strongest: on Linux the tracer is `strace`, a direct syscall record that names the call *and* the errno, and it reported `unparsed: 0` on both packages measured here (6,585 distinct events from 15,276 calls on `hugo-extended`). Overlayfs is also a coarser instrument than the thing it would audit — copy-up fires on any open-for-write and on metadata-only changes, so `upperdir` over-reports, which is the safe direction and therefore useless for catching an over-prediction. Worse, it is not free of side effects: it changes the filesystem the jail is enforcing against, adding a second variable to an arm whose whole value is that it varies one. And the writes that matter are spread across the project, the machine-global store, `jail-home` and the private temp, so it would take several mounts or an overlay on `/`.

**Windows USN change journal — not yet, and not for the defect that motivated it.** Windows is where the tracer is demonstrably weak: `measure.sh` records that ETW reported `attributedPeers: 0` for `electron-prebuilt@0.31.2`, a package whose egress two independent instruments confirm. But the USN journal records *file* changes. It would not have caught that defect, because that defect is on the network axis.

It is also unattributable on its own terms. `USN_RECORD_V3` carries `FileReferenceNumber`, `ParentFileReferenceNumber`, `Usn`, `TimeStamp`, `Reason`, `SourceInfo`, `SecurityId`, `FileAttributes` and `FileName` — and [no process identifier of any kind](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v3). `SecurityId` is the file's, not the writer's. `SourceInfo` is opt-in: a process tags its *own* writes by calling `FSCTL_MARK_HANDLE`, which a lifecycle script will not be doing. So tying a change to the script rather than to npm, to nub, or to the OS indexer means correlating by path and time window — the same shape of inference that already merged two unrelated Windows bugs in this project. `Reason` flags also accumulate until the handle closes, so the record you read is a summary of everything that happened to that file, not a sequence of operations.

**What to build instead.** Port this falsification control to Windows. `measure-windows.mjs` has no `--at-grant` equivalent yet; adding one and giving `falsify.mjs` a Windows case table would put a *direct* check on the platform whose tracer is known to under-report — for less work than either oracle, and answering the question that actually matters (does the Windows driver reject a wrong grant?) rather than a proxy for it.
