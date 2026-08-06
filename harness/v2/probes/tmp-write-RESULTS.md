# Does a jailed write to the temp dir need a grant?

Findings from `tmp-write-fixture.sh` and the `--at-grant` arms in `.github/workflows/tmp-redirect-probe.yml`. Linux (`ubuntu-latest`) only — the answer is backend-specific and macOS/Windows are not covered here.

## The question

`observe.mjs` buckets a write that falls under no catalog-expressible scope as `outside` and prints `⛔ N writes OUTSIDE project/home`. Ten of the 45 `linux-x64` v2 records carry that flag, and every path the records enumerate is under `/tmp`. OBSERVE is the UNJAILED arm, so its `os.tmpdir()` is the real shared `/tmp`. The proposal was that the jail redirects those writes into already-granted space, making the `outside` classification an artifact and any grant it produced pure over-granting.

## Answer: it depends on HOW the script names the temp dir, and the split is real

| target | unjailed | jailed at `{}` |
| --- | --- | --- |
| `os.tmpdir()/…` | ALLOW | **ALLOW** |
| literal `/tmp/…` | ALLOW | **DENY (EACCES)** |
| `<real $HOME>/…` (negative control) | ALLOW | DENY (EACCES) |
| `/var/tmp/…` (negative control) | ALLOW | DENY (EACCES) |

Reproduced on two independent runners ([31115255290](https://github.com/nubjs/build-jail-corpus/actions/runs/31115255290), [31115609171](https://github.com/nubjs/build-jail-corpus/actions/runs/31115609171)), each with `OVERRIDDEN=2 REJECTED=0` and a fresh per-run temp dir name. Inside the jail the fixture reported `os.tmpdir() = /tmp/nub-tmp-<random>` and `TMPDIR=/tmp/nub-tmp-<random>`.

Both negative controls were refused in the same arm in which the `os.tmpdir()` write succeeded, so the jail was demonstrably enforcing while that row passed. The unjailed arm passes all four, so a jailed denial cannot be the fixture failing for an ordinary reason.

## Why: the build jail on Linux is Landlock, and Landlock cannot rebind a path

`backend/linux.rs` is explicit — *"THE BUILD JAIL'S ONLY MECHANISM. There is no bubblewrap arm below this for a build-jail policy… Landlock or nothing."* Bubblewrap needs a user namespace, which is not universally available unprivileged.

That decides the whole result. `linux.rs`'s `TmpMode::Private` arm — `setup.arg("--bind").arg(dir).arg("/tmp")` with `insert_tmp_env(…, "/tmp")` — is the **bubblewrap** path and is unreachable for a build-jail policy. `linux_landlock.rs` says what actually happens: *"`TmpMode::Private` gives the jail a per-run scratch dir, which bubblewrap bound over `/tmp`. There is no mount namespace to rebind here, so the child gets the host path granted directly and `TMPDIR` pointed at it."*

So the grant is on `/tmp/nub-tmp-<random>`, not on `/tmp`. A path that follows `TMPDIR` lands inside the grant; a hardcoded `/tmp/foo` names the ungranted parent and is refused.

⛔ Reading the bubblewrap backend and concluding the two spellings are equivalent is the mistake this probe exists to prevent. The source supports that reading, and it describes a code path the build jail never takes.

## The corpus split: all ten flagged records follow `TMPDIR`

Every `/tmp` write in the ten `outside`-flagged `linux-x64` records is constructed from `os.tmpdir()`, not hardcoded — traced to the line that builds the path:

| record | temp path built by | verdict |
| --- | --- | --- |
| `playwright-chromium@0.17.0` | `playwright-core@0.17.0` `lib/install/browserFetcher.js:98` — `path.join(os.tmpdir(), …)` | `os.tmpdir()` |
| `@playwright/browser-chromium@1.61.1` | `playwright-core@1.61.1` `lib/coreBundle.js:27750` — `mkdtemp(path.join(os.tmpdir(), "playwright-download-"))` | `os.tmpdir()` |
| `sharp@0.32.6` | `install/libvips.js:185` — `path.join(os.tmpdir(), \`${process.pid}-${tarFilename}\`)` | `os.tmpdir()` |
| `electron-prebuilt@0.28.3` | `electron-download` `index.js:48` — `path.join(os.tmpdir(), 'electron-tmp-download-' + pid + '-' + Date.now())` | `os.tmpdir()` |
| `hugo-extended@0.141.0` | `careful-downloader` → `tempy` → `temp-dir` — `await fs.realpath(os.tmpdir())` | `os.tmpdir()` |
| `lmdb-store@2.0.0-alpha2` | `node-gyp` `lib/install.js:206` — `mkdtemp(path.join(os.tmpdir(), 'node-gyp-tmp-'))` | `os.tmpdir()` |
| `windows-foreground-love@0.6.1` | same `node-gyp` line | `os.tmpdir()` |
| `agent-browser@0.27.0` | Node itself — `lib/internal/modules/helpers.js:483`, `join(lazyTmpdir(), 'node-compile-cache')` | `os.tmpdir()` |
| `@pulumi/gcp@0.16.9` | the Go `pulumi` CLI (`install-pulumi-plugin.js` shells out); Go's `os.TempDir()` honours `$TMPDIR` | INFERRED — Go source not read |
| `@pulumi/kubernetes@0.14.0` | same | INFERRED — Go source not read |

The two `INFERRED` rows have independent empirical backing: both records' `drop-writeuserHome` descent arm passed at `{"network":true}` with no write scope, so their `/tmp` write cost no grant whichever way the Go binary builds it.

⛔ A path starting `/tmp/` in a record is NOT evidence of either spelling. OBSERVE runs with `TMPDIR` unset, where `os.tmpdir()` **is** `/tmp`, so both spellings print identically. Only the source says which.

## What this means for the ten records: nothing narrows

The proposal was that ~10/45 records are over-granted because of this. They are not — the classification never reaches the grant, and the records mostly already sit at a no-write grant.

`observe.mjs` synthesizes from `w.deps` / `w.project` / `w.userHome` only. `w.outside` is printed as a warning and never enters the grant (determinism rule 3: *"a path that maps to no scope is REPORTED, never rounded up"*). So an `outside` write cannot by itself cause a ladder climb; only a failed VERIFY can.

| record | recorded grant | over-granted because of `/tmp`? |
| --- | --- | --- |
| `agent-browser@0.27.0` | `{}` | no — already empty |
| `electron-prebuilt@0.28.3` | `{"network":true}` | no — MINIMAL, no write scope |
| `hugo-extended@0.141.0` | `{"network":true}` | no — MINIMAL, no write scope |
| `sharp@0.32.6` | `{"network":true}` | no — MINIMAL, no write scope |
| `@pulumi/gcp@0.16.9` | `{"write":{"userHome":true},"network":true}` | no — descent shows `{"network":true}` sufficient |
| `@pulumi/kubernetes@0.14.0` | `{"write":{"userHome":true},"network":true}` | no — same |
| `lmdb-store@2.0.0-alpha2` | NO-STATE-PASSED | no — an artifact shortfall, not a denial |
| `windows-foreground-love@0.6.1` | NO-STATE-PASSED | no — same |
| `playwright-chromium@0.17.0` | `{"write":{deps,project,userHome},"network":true}` | no — see below |
| `@playwright/browser-chromium@1.61.1` | `{"write":{deps,project,userHome},"network":true}` | no — see below |

Four of these packages pass a real jailed arm with NO write scope at all while writing to `os.tmpdir()`, which is the corpus's own confirmation of the mechanism.

## The two wide records are wide for a different reason

Only 2 of 45 records landed on the ladder's wide rung, and both are playwright. `--at-grant` arms on [31115609171](https://github.com/nubjs/build-jail-corpus/actions/runs/31115609171), every one with `OVERRIDDEN=2 REJECTED=0`:

| package | grant | verdict |
| --- | --- | --- |
| `playwright-chromium@0.17.0` | `{"network":true}` | INSUFFICIENT — reproduces the record |
| `playwright-chromium@0.17.0` | `{"read":"disk","network":true}` | INSUFFICIENT |
| `playwright-chromium@0.17.0` | `{"write":{"deps":true},"network":true}` | INSUFFICIENT |
| `hugo-extended@0.141.0` | `{"network":true}` | SUFFICIENT |

Four more arms on [31115847389](https://github.com/nubjs/build-jail-corpus/actions/runs/31115847389) pin the scope exactly:

| grant | verdict |
| --- | --- |
| `{"write":{"project":true},"network":true}` | INSUFFICIENT |
| `{"write":{"deps":true,"project":true},"network":true}` | INSUFFICIENT |
| `{"write":{"userHome":true},"network":true}` | **SUFFICIENT** |
| `{"write":{"deps":true,"userHome":true},"network":true}` | SUFFICIENT |

⇒ `playwright-chromium@0.17.0`'s minimum is `{"write":{"userHome":true},"network":true}`. `userHome` is necessary and sufficient; `deps` and `project` in the recorded grant are both unearned. **The record narrows from three write scopes to one** — and not because of anything to do with temp.

The refused paths the record's DIAGNOSE named (`/proc/self/maps`, `/proc/version_signature`, `/proc/self/cgroup`) were a red herring, exactly as `measure.sh`'s own DIAGNOSE comment warns: the passing arm widens no reads at all.

⛔ Do NOT read the `read:"disk"` arm as evidence about `/proc`. `disk_minus_secrets_read_allows` walks `/`'s children and `is_unrepresentable_grant` skips `RESERVED_KERNEL_TREES` — `/proc`, `/sys`, `/dev` are deliberately excluded, with eight specific files granted by `linux_landlock`'s `PROC_READ_PATHS` instead. So that arm never widened `/proc` and could not have tested the kernel-fs floor. The `userHome` arm is what settles it.

`observe.mjs` billed all 650 `ms-playwright` writes as `jailHome` — *"base profile already grants this — NOT billed"* — on the strength of them following `$HOME` in the traced arm. In the real jail they need `write.userHome`, so that assumption does not hold for this package. That is the under-prediction the record's `⛔ OBSERVE UNDER-PREDICTED` line was pointing at, and it has nothing to do with `/tmp`.

⛔ The ladder is what makes this expensive, and it is a separate defect from anything about temp. The v2 fallback's FIRST rung is already `{"write":{deps,project,userHome},"network":true}` — there is no `project`-alone or `userHome`-alone rung — so any synth failure, whatever its cause, publishes the widest write grant.

## What is NOT established

- **macOS and Windows.** macOS `TmpMode::Private` denies `/private/tmp` and the confstr scratch and grants back only the per-run dir, with `TMPDIR`/`TMP`/`TEMP` repointed — so the same split is expected, but it is unmeasured here. Windows takes the SHARED tmp (`preset.rs` spells `Private` as unavailable there), so neither row transfers.
- **Whether any real package hardcodes `/tmp`.** None of the ten do. The refused row is a live hazard the fixture demonstrates, not one the corpus has yet hit.
- **WHY `playwright-chromium@0.17.0` needs `write.userHome`.** The scope is measured; the code path that leaves the jail's private `$HOME` is not traced.
- **`@playwright/browser-chromium@1.61.1`.** Not re-measured. Its record shows `⛔ REPLAY SUSPECTED` on the arm that PASSED, so its recorded wide grant is not trustworthy in either direction.
- **`@pulumi/*` arm quality.** `install-pulumi-plugin.js` calls `process.exit(0)` on every path including a missing `pulumi` binary, and the plugin's own output lands under `$HOME` rather than in the package, so the artifact gate may not see whether the script did anything. Both records' descent arms should be read with that in mind.
