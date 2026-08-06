# win-tmp — where a jailed child's scratch actually lives on Windows, and whether that place holds still

## The question

On Linux and macOS the build jail makes a private per-run temp directory, grants it read+write, and repoints the child's `TMPDIR` at it. A script that calls `os.tmpdir()` therefore writes into already-granted space and needs no grant, while a script that hardcodes `/tmp` gets `EACCES`.

Windows does none of that. `compiler/preset.rs` inserts `fs["$tmp"]="rw"` only under `#[cfg(not(windows))]`, and `backend/mod.rs`'s `make_private_tmp` returns `None` unless the mode is `TmpMode::Private` — so the Windows jail creates no private temp and repoints nothing. Whatever scratch a jailed script gets comes from the OS's own handling of an AppContainer's temp.

That leaves one property to establish before a `temp` grant can even be written down: **is the resulting location stable, and stable across what?** Across two runs of one package, across two packages in one session, across machines. If it moves on any of those axes, a grant cannot name it as a fixed path.

## What the harness measures

`probe-tmp.cjs` is the fixture. It runs identically jailed and unjailed and emits one JSON record between assembled sentinels: `os.tmpdir()`, the `TEMP`/`TMP`/`USERPROFILE`/`LOCALAPPDATA` family and the full env key list, what `fs.mkdtempSync` created and where `realpathSync.native` says it is, a write plus read-back inside it, hardcoded writes to `C:\Windows\Temp` and `C:\Temp`, a bounded hunt for its own marker under `%LOCALAPPDATA%\Packages`, and a negative control.

**Every path it probes arrives on `argv`.** The whole question is what the jailed child's environment says, so a fixture that derived its own targets from `%USERPROFILE%` would probe a different target in each arm — and the negative control, which only means anything when both arms aim at the same file, would be aiming at two. The environment is data here, reported and never consumed.

## The two arms, and why both

| | Arm A — `drive.mjs` | Arm B — `drive-lifecycle.mjs` |
| --- | --- | --- |
| How the jail is reached | `nub run --sandbox build-jail` | `nub install` + `nub approve-builds --all`, real lifecycle interposition |
| Policy | `build_jail_surface` with no `package_dir`, no `private_home` | the same surface through `compile_build_jail` |
| Environment | the strip-all floor | the **scrubbed lifecycle env** |
| Answers | repeatability across runs and across cwd identities | what a real `postinstall` sees, and the per-package axis |

Arm A cannot answer the environment question, because only the lifecycle path replaces the strip-all floor with the scrubbed lifecycle env. Reporting arm A's env dump as a `postinstall`'s would be answering a different question in the right format.

**Neither arm can rely on the jailed child reading a file, so both deliver the fixture as source.** Arm A passes it to `node -e` on the command line: with no `package_dir` the fs allowlist is the OS minimal-root closure plus the dependency-tree reads, and the checkout is not in it, so a jailed `node <path>` would die on a read refusal that reads exactly like a temp finding and is not one. Arm B hit the same wall from the other side — measured twice, a confined `postinstall` could not read the fixture out of its **own package directory** (`EPERM … open '…\.store\<pkg>@file+<hash>\node_modules\<pkg>\probe-tmp.mjs'`), and forcing `enableGlobalVirtualStore` did not move it — so it ships the fixture as a gzip+base64 blob on the postinstall command line with a one-line `eval` bootstrap. gzip is what makes it fit: cmd.exe truncates at 8191 characters, plain base64 of the fixture is ~10.1 kB, gzip+base64 is ~4.5 kB. That is also why the fixture is CommonJS — `node -e` evaluates source as CJS, and the bootstrap has no way to pass `--input-type=module`.

### The smoke gate, and why it exists

Arm A settles which spelling of `nub run --sandbox <shape> <cmd> [args]` reaches `run_sandboxed` **once**, with three spawns of a payload that contains no fixture, before running a single arm.

The first run of this probe tried the spellings inside every arm instead. Three spellings × five arms, each spawn burning its full timeout because the jail produced nothing, is 45 minutes of wall clock — and `spawnSync`'s deadline kills the direct child only, so each attempt left a jailed grandchild behind. Run 31119799480's runner lost communication with the server at exactly that mark, and GitHub returned no log and no artifact for it. Settling the spelling up front reports a total failure in three minutes instead of making it indistinguishable from a slow run.

Two related hardenings came out of a dry run against a stand-in `nub`:

- **The frame sentinels are assembled at runtime, never written whole.** The fixture travels to arm A as a command-line argument, so any path that echoes the command line would reproduce a literal sentinel pair — and a driver scanning for it would extract the fixture's own source and report it as a result.
- **A frame that does not parse is not a record.** Returning a `{parseError}` object made it truthy, and the gate counted a garbage arm as one that had produced evidence.

Arm B installs **two** local tarball packages in one `nub install`. Two packages in one session against one host state is the per-package axis; two separate installs would not be. Tarballs rather than directory deps because a `file:` directory is a link, and a linked dependency's lifecycle script is not the spawn under test.

## The gates

Neither arm's rows are evidence unless its gate passes, and each driver exits non-zero and says so when one fails.

- **The negative control.** Both arms write a file into the real user profile from inside the jail. It must succeed unjailed and fail jailed. A permissive misconfiguration otherwise reports an unconfined `node`'s temp paths with a clean exit code, and nothing else in the output would tell you.
- **Arm B additionally proves the script ran and was confined.** `running build scripts for` must appear in the install or approve log — nub replays a cached side-effect tree without spawning anything, and a replayed arm is indistinguishable from a real one by exit code. And `running without the build sandbox` must *not* appear: `confines()` announces an unconfined lifecycle spawn, and if it stood aside every path below is a property of an ordinary `node`.

Reading the user profile is *not* part of the control. The Windows jail leaves it readable by design (`backend/windows.rs`, the `TRAVERSE_MASK` note), so a successful read there is expected and is reported separately.

## Running it

Windows only, and CI is the only Windows path — `.github/workflows/win-tmp-resolution.yml`, branch-scoped on `probe/win-tmp-resolution`, no PR needed. The workflow builds `nub` once from `nubjs/nub`'s `sandbox/integration`, caches it by commit, and runs each arm in **its own job**. That is not cosmetic: when both arms shared a runner and the runner died, arm B was lost to a failure that had nothing to do with arm B. Separate jobs also give the cross-**machine** axis for free — two jobs are two fresh runner VMs, which is the closest reachable stand-in for "after a reboot" since a hosted runner cannot be rebooted and resumed.

Each arm step carries its own `timeout-minutes`. A hung step then gets killed by the runner, which survives to upload its artifact, rather than being starved until it drops off the network.

```
node harness/v2/probes/win-tmp/drive.mjs           --nub C:\nubbin\nub.exe --root C:\jail\wintmpA --out C:\jail\wintmpA\out
node harness/v2/probes/win-tmp/drive-lifecycle.mjs --nub C:\nubbin\nub.exe --root C:\jail\wintmpB --out C:\jail\wintmpB\out
```

This probe touches no grant and publishes no record. `measure-windows.mjs` and its `NUB_V2_WINDOWS_EVICTION_VERIFIED` guard are not involved.
