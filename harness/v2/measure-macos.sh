#!/usr/bin/env bash
# Harness v2 driver, macOS lane: OBSERVE -> SYNTHESIZE -> VERIFY -> NARROW -> DIAGNOSE.
#
# The sibling of measure.sh. Two structural differences, both forced by the platform:
#
#   1. The tracer is dtrace, scoped by PROCESS ANCESTRY (`progenyof($target)`) rather than by
#      strace's `-f`. dtrace needs uid 0, so the traced command is dropped back to the invoking
#      user with `sudo -u` inside the wrapper — otherwise npm would run as root and every
#      `userHome` write would land in /var/root and be misclassified as `outside`.
#
#   2. NARROWING replaces the corpus record as the over-prediction measure. A v1 corpus record is
#      the output of a blind pass/fail ladder: it can say a grant was insufficient, never what was
#      missing, and it carries every harness defect that was live when it was taken. So it is not
#      an oracle and this driver does not consult it. Instead, once a synthesized grant VERIFIES,
#      each capability is dropped in turn and re-verified. A narrower grant that also passes is
#      over-prediction, measured directly rather than inferred from a comparison.
#
#   usage: measure-macos.sh <pkg> <version> [nub-binary]
set -uo pipefail
PKG="${1:?usage: measure-macos.sh <pkg> <version> [nub] [--at-grant <json>|--at-catalog <file>]}"
VER="${2:?usage: measure-macos.sh <pkg> <version> [nub] [--at-grant <json>|--at-catalog <file>]}"
# ⛔ `[nub-binary]` IS OPTIONAL AND A FLAG TAKES ITS SLOT, so a `$3` beginning with `-` is a FLAG,
# not a path. Ported deliberately: `measure.sh` took `${3:-}` blindly once, which made the documented
# form `<pkg> <ver> --at-grant '<json>'` exec `--at-grant install` — every arm rc=127
# `--at-grant: command not found`, reported as `⛔ VOID`. Honest verdict, unusable flag.
case "${3:-}" in
  ''|-*) NUB="" ;;
  *) NUB="$3" ;;
esac
# ⛔ DIRECT MODE. Two flags, two DIFFERENT questions, and neither is the measurement this driver
# normally makes. `--at-grant` asks "does this package install under EXACTLY this grant?" and builds
# its own one-package catalog, so it can only ever test a catalog of this driver's construction.
# `--at-catalog` runs the identical arm against a catalog FILE — `collate.mjs`'s real output, with
# version bands, baseline, env and absent-package entries that `--at-grant` cannot express. That
# round trip has never been checked on darwin: everything this pipeline has produced so far is the
# harness reading its own output back, and `--at-catalog` is the first thing that would catch a
# grant the collator encodes in a shape nub's parser reads differently.
#
# Both still run the FULL OBSERVE phase first, because the artifact gate compares the arm against
# OBSERVE's manifest — a direct arm with no reference cannot tell "installed correctly" from
# "installed nothing".
AT_GRANT=""
AT_CATALOG=""
for i in "$@"; do
  case "${PREV_ARG:-}" in
    --at-grant) AT_GRANT="$i" ;;
    --at-catalog) AT_CATALOG="$i" ;;
  esac
  PREV_ARG="$i"
done
[ -n "$AT_GRANT" ] && case "$AT_GRANT" in
  '{'*'}') : ;;
  *) echo "⛔ --at-grant needs a JSON object, got: $AT_GRANT" >&2; exit 2 ;;
esac
[ -n "$AT_GRANT" ] && [ -n "$AT_CATALOG" ] && {
  echo "⛔ --at-grant and --at-catalog ask two different questions; pass one" >&2; exit 2; }
[ -n "$AT_CATALOG" ] && { [ -s "$AT_CATALOG" ] || {
  echo "⛔ --at-catalog needs a non-empty catalog FILE, got: $AT_CATALOG" >&2; exit 2; }; }
# Absolute, because every arm runs with its cwd inside the fixture.
[ -n "$AT_CATALOG" ] &&
  AT_CATALOG="$(cd "$(dirname "$AT_CATALOG")" && pwd)/$(basename "$AT_CATALOG")"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNUSER="${SUDO_USER:-$(id -un)}"
NPM_BIN="$(command -v npm)"
# nub's global virtual store, resolved the way the ARM will resolve it rather than the way this
# driver would. The driver runs as root (dtrace needs uid 0) while every arm is dropped back with
# `sudo -u -H`, whose env_reset drops XDG_CACHE_HOME — so an arm always lands on the invoking user's
# `~/.cache/nub/pm/{store,tools}`: `aube_store::dirs::cache_dir()` has no macOS `~/Library/Caches`
# branch, and nub's embedder pins `cache_namespace: "nub/pm"` + `virtual_store_subdir: "store"`
# (`identity.rs`). Hence the paths are byte-identical to the Linux driver's; only the ANCHOR differs.
# ⛔ ANCHORING ON THE DRIVER'S OWN `$HOME` WOULD RESOLVE TO /var/root UNDER sudo AND EVICT NOTHING,
# SILENTLY — the same shape as the scoped-slug bug `measure.sh` records, and just as invisible.
USER_HOME="$(dscl . -read "/Users/$RUNUSER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
USER_HOME="${USER_HOME:-/Users/$RUNUSER}"
STORE="$USER_HOME/.cache/nub/pm/store"
TOOLS="$USER_HOME/.cache/nub/pm/tools"
# ⛔ DERIVED ONCE, HERE, AND PASSED DOWN — never re-derived inside the classifier (PORTABILITY R2).
# The shell driver is apparatus and may read the environment; the classifier may not, because it is
# the thing that would silently produce a venue-specific answer.
GLOBAL_STORE="$STORE"
# The interpreter INSTALL ROOT, not the binary: `<root>/bin/node` resolved through any symlink, then
# up two. That is the tree node-gyp's bundled `gyp/pylib` lives in, and whether it sits inside
# `$HOME` is exactly the venue difference that made one package synthesize two different grants on
# Linux. macOS has no `readlink -f`, so the resolution is done with node itself.
INTERPRETER="$(node -e 'const fs=require("fs"),p=require("path");let n=process.argv[1];try{n=fs.realpathSync(n)}catch{};console.log(p.dirname(p.dirname(n)))' "$(command -v node)" 2>/dev/null)"

# ⛔ R7 — THE TRACED SCRIPT RUNS AS AN ORDINARY USER, ASSERTED RATHER THAN INTENDED. The TRACER needs
# uid 0 (dtrace does), which is apparatus; the traced PROCESS is the environment under test and must
# have the permissions a real developer has. A LESS privileged OBSERVE measures a script's FALLBACK
# path while a real user takes the primary one — a capability we never see, which is an under-grant
# and invisible in the record. Erring toward MORE privilege is the safe side, so this asserts only
# that the run user is a real non-root account.
#
# `sudo -u "$RUNUSER" -H` is what gives the traced process that identity, and `-H` sets HOME to the
# REAL home of that user from the directory service — verified: `USER_HOME` above is read with
# `dscl . -read NFSHomeDirectory` and is `/Users/runner` on CI, matching what the traced npm saw in
# every record so far. The jail-home redirect below then overrides it for the CHILD only, exactly as
# nub does — `sandbox_homes` reads nub's OWN `HOME`, not the one it hands the script.
RUNUID="$(id -u "$RUNUSER" 2>/dev/null || echo -1)"
if [ "$RUNUID" = "-1" ]; then
  echo "  ⛔ R7 VIOLATION: run user '$RUNUSER' does not resolve to a uid. Refusing to measure."; exit 1
fi
if [ "$RUNUID" = "0" ]; then
  echo "  ⛔ R7 VIOLATION: the traced script would run as ROOT. A root OBSERVE takes paths no real"
  echo "     user can, and the tracer's own privilege is not the script's. Refusing to measure."; exit 1
fi

# ⛔ THE OBSERVE ARM MUST REPRODUCE THE JAIL'S ENVIRONMENT, AND UNTIL NOW THIS DRIVER REPRODUCED NONE
# OF IT. `measure.sh` rewrites five variables here; this rewrote zero, so the traced script saw the
# REAL $HOME and $TMPDIR. That was not a cosmetic gap — MEASURED on kerberos@7.0.0, run 31128743486:
# OBSERVE downloaded the prebuilt binary into the real `~/.npm/_prebuilds`, EVICT clears only the nub
# store and never `~/.npm`, so every later arm started with that tarball already cached. The
# `nar-no-network` arm therefore PASSED and the record claimed `network` was unnecessary — while the
# same arm on Linux FAILS with `missing: build/Release/kerberos.node`. A false pass in the
# under-grant direction, caused entirely by the missing redirect.
#
# ⛔ EACH REWRITE CORRESPONDS TO SOMETHING THE JAIL ACTUALLY DOES TO A CONFINED SCRIPT — none is here
# to make two numbers agree. Ported verbatim from measure.sh:145-172, which carries the derivations:
#   HOME                     private_home_dir / jail_private_home, RW-granted by push_rw_path
#   TMPDIR                   make_private_tmp, TmpMode::Private
#   NODE_COMPAT=1            build_jail.rs:140, unconditional
#   PLAYWRIGHT_BROWSERS_PATH redirect_playwright_browsers, unconditional for every jailed spawn
#   ELECTRON_CACHE / electron_config_cache   redirect_electron_cache, likewise
#   npm_config_prefix        redirect_npm_prefix, likewise

# ⛔ NOT UNDER /tmp — that path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all.
ROOT="$(mktemp -d "$HOME/v2m-XXXXXX")" || exit 1
# ⛔ THESE LIVE HERE, AFTER `$ROOT`, AND NOT BESIDE THE OTHER ROOT DERIVATIONS ABOVE. The jail home is
# a subdirectory of the per-run fixture, so it cannot be computed before the fixture exists — placing
# it with `INTERPRETER` and `GLOBAL_STORE` cost a whole macOS run to `line 86: ROOT: unbound variable`
# under `set -u`, which clobbered two good published records with HARNESS-ERROR.
JAIL_HOME="$ROOT/jailhome"; mkdir -p "$JAIL_HOME"
# ⛔ `${TMPDIR%/}`, NOT `$TMPDIR`. macOS sets TMPDIR WITH a trailing slash
# (`/var/folders/<..>/T/`), so the naive form yields a root containing `T//nub-tmp-obsXXXXXX` while
# every path the kernel reports carries a single slash — and `p.startsWith(root)` is then false for
# every file in the driver's own private temp. MEASURED on cpu-features@0.0.10: 3,345 writes into
# $JAIL_TMP were bucketed `outside` instead of free `jailTmp`, so the record warned about thousands
# of writes "OUTSIDE project/home" that were in a directory this driver created. It did not inflate
# the grant — `outside` bills nothing — but it made the temp root dead on this platform.
JAIL_TMP="$(mktemp -d "${TMPDIR:-/tmp}"/nub-tmp-obsXXXXXX)" || exit 1
JAIL_TMP="$(cd "$JAIL_TMP" && pwd -P)"
chown -R "$RUNUSER" "$JAIL_HOME" "$JAIL_TMP" 2>/dev/null
# The driver runs under sudo (dtrace needs uid 0) but every measured process is dropped back to the
# invoking user — so the tree they write into must be theirs, or npm fails on its own fixture and
# the run reports a package problem that is really a harness problem.
chown -R "$RUNUSER" "$ROOT" 2>/dev/null
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)   nub=${NUB:-<none>}"

# ── 0a. THE CI-DETECTION SCRUB ─────────────────────────────────────────────────────────────────
# Shared with `measure.sh`; `measure-windows.mjs` carries the same key list in JS and
# `ci-env-scrub.test.mjs` asserts all three agree. Full reasoning is in the sourced file. The short
# version: a package that branches on `CI` runs LESS code on a runner, so a CI-measured record omits
# capabilities a developer hits — an under-grant. `NUB_CORPUS_CI_ENV=inherit` keeps the axis
# measurable rather than normalising it away.
# shellcheck source=harness/v2/ci-env-scrub.sh
. "$HERE/ci-env-scrub.sh"

# ── 0b. fbt PREFLIGHT — a timeboxed probe, folded in rather than given its own runner. ─────────
#
# The open question it answers: can an `fbt` probe observe the cwd change that posix_spawn's
# in-kernel `addchdir_np` performs? If it can, cwd becomes OBSERVED (R2's actual demand) and the cwd
# guard becomes a backstop instead of the mechanism. If it cannot, the guard is the answer.
#
# ⛔ IT MUST NEVER FAIL THE JOB. This is a question, not a gate — a measurement must not be lost to a
# probe. Every command is `|| true` and the whole block is advisory output only.
#
# ⛔ AND IT IS NOT ANSWERABLE FROM DOCUMENTATION. Apple's man page says default SIP forbids D
# programs "access to kernel address values or kernel memory contents", which reads like a refusal —
# but the shipped `cwd` inline in /usr/lib/dtrace/darwin.d dereferences curproc->p_fd.fd_cdir->v_name,
# which IS kernel memory, and this adapter runs fine on this box. So the restriction is demonstrably
# not total and only a live probe settles it.
echo "  --- fbt preflight (advisory; never fails the run) ---"
echo "     csrutil: $(csrutil status 2>&1 | head -1 || true)"
echo "     fbt probes visible: $(dtrace -l -P fbt 2>/dev/null | wc -l | tr -d ' ' || echo 0)"
echo "     fbt enable attempt: $(dtrace -n 'fbt:::entry { exit(0); }' -c /usr/bin/true 2>&1 | head -2 | tr '\n' ' ' || true)"
echo "     cwd builtin value:  $(dtrace -q -n 'syscall::open:entry /pid == $target/ { printf("%s", cwd); exit(0); }' -c /usr/bin/true 2>&1 | head -1 || true)"
# ⛔ THE ONE QUESTION LEFT, AND EITHER ANSWER RETIRES IT. SIP is off on these runners and ~93k fbt
# probes are visible, so fbt is AVAILABLE — what is unknown is whether a probe on the kernel's
# internal chdir routine fires for the posix_spawn + addchdir_np path. If it does, the lifecycle
# script's cwd becomes OBSERVABLE and the cwd guard drops from mechanism to backstop. If it does not,
# the guard IS the answer and this loop closes.
#
# ⛔ WILDCARD, NOT A GUESSED SYMBOL NAME. `chdir_internal` is the likely XNU routine but the name is
# not a stable ABI and guessing one produces a silent zero that reads exactly like "does not fire".
# Listing what actually matches is the difference between a measurement and an assumption.
echo "     fbt chdir symbols:  $(dtrace -l -n 'fbt::chdir*:entry' 2>/dev/null | tail -n +2 | awk '{print $3}' | sort -u | tr '\n' ' ' || true)"
# The probe target: a node process that spawns a child with an explicit `cwd`, which is exactly the
# libuv addchdir_np path npm uses for a lifecycle script. Written to a file because `dtrace -c`
# word-splits its argument and execs directly — there is no shell, so a quoted -e script cannot work.
FBTJS="$ROOT/fbt-spawn-probe.js"
mkdir -p "$(dirname "$FBTJS")" 2>/dev/null || true
printf '%s\n' "require('child_process').spawnSync(process.execPath,['-e','0'],{cwd:'/tmp'});" > "$FBTJS" 2>/dev/null || true
echo "     fbt fires on spawn-with-cwd: $(dtrace -q -n 'fbt::chdir*:entry /progenyof($target)/ { @[probefunc] = count(); }' -c "$(command -v node) $FBTJS" 2>&1 | tr '\n' ' ' | sed 's/  */ /g' | head -c 300 || true)"
echo "  --- end fbt preflight ---"

# ── 1. OBSERVE ─────────────────────────────────────────────────────────────────────────────────
# ⛔ THE CAPITAL `O` IS LOAD-BEARING AND MUST NOT BE "TIDIED" TO LOWERCASE. dtrace's `cwd` built-in
# yields a BASENAME, not a path (`/usr/lib/dtrace/darwin.d:339` — Apple's own comment says they want
# `vn_getpath()` and cannot have it because it takes `namecache_rw_lock`), so the decoder's
# staleness detector can only ever compare basenames. A lowercase `observe` COLLIDES with the real
# npm package of that name, and a colliding basename makes a wrong resolution look verified — an
# error in the under-grant direction, which is the one this project forbids. npm has refused
# uppercase in package names since 2017, so a basename carrying one cannot be a package directory:
# the collision becomes unrepresentable rather than merely unlikely. Asserted, not just intended.
OBS="$ROOT/Observe"; mkdir -p "$OBS"; cd "$OBS" || exit 1
# ⛔ `[[:upper:]]`, NEVER `[A-Z]` — THE OBVIOUS SPELLING MAKES THIS ASSERTION VACUOUS ON THE EXACT
# SHELL THIS FILE RUNS UNDER. bash 3.2 (macOS /bin/bash) does RANGE COLLATION under a UTF-8 locale, so
# `[A-Z]` matches lowercase. MEASURED on this Mac, single-variable across both axes:
#     bash 3.2.57  LC_ALL=C            [A-Z] correct     [[:upper:]] correct
#     bash 3.2.57  LC_ALL=en_US.UTF-8  [A-Z] MATCHES     [[:upper:]] correct   <- the guard never fires
#     bash 5.2.12  either              [A-Z] correct     [[:upper:]] correct
# GitHub macOS runners set LANG=en_US.UTF-8, which is precisely the failing cell.
case "$(basename "$OBS")" in
  *[[:upper:]]*) ;;
  *) echo "  ⛔ observation dir '$(basename "$OBS")' carries no uppercase letter, so its basename"
     echo "     could collide with an npm package name and make a stale-cwd resolution read as"
     echo "     verified. Refusing rather than measuring something that cannot be checked."; exit 1 ;;
esac
printf '{"name":"o","version":"1.0.0","private":true}\n' > package.json
# ⛔ THE FETCH IS NOT TRACED AND THAT IS THE WHOLE POINT. Tracing `npm install` traces NPM: its
# registry TLS and its `~/.npm/_cacache` writes land in the same event stream as the lifecycle
# script's. MEASURED on Linux: that made EVERY package synthesize `network:true` + `write:userHome`
# regardless of behaviour. Fetch with `--ignore-scripts` outside the trace; trace `npm rebuild`,
# which runs the lifecycle scripts and nothing else.
npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER" > "$OBS/fetch.log" 2>&1
if [ $? -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed; nothing to measure)"; exit 0
fi
# ⛔ CHOWN AFTER THE FETCH, NOT ONLY BEFORE IT. The chown at $ROOT creation predates this fetch, and
# the fetch runs as ROOT (the driver is under sudo for dtrace) — so every file npm just wrote is
# root-owned, and the traced `npm rebuild`, which is dropped back to $RUNUSER, then dies on
# `EACCES: permission denied, mkdir .../node_modules`. MEASURED on run 31086358188: that is what
# @nuxt/components and codeceptjs reported once the dtrace -c defect stopped masking it.
chown -R "$RUNUSER" "$ROOT" 2>/dev/null

# dtrace's `-c` word-splits its argument and execs it directly — there is no shell, so the command
# cannot carry a redirect and cannot report its own exit status. A wrapper file supplies both.
# ⛔ THE WRAPPER MUST NOT BE `sh -c`. The decoder identifies the lifecycle script as the only
# `sh -c` in the subtree (npm execs one per script); a `-c` wrapper here would be indistinguishable
# from it and would attribute the ENTIRE npm subtree to the package.
# ⛔ THE REWRITES GO AFTER `sudo`, NOT BEFORE IT. sudo's env_reset discards the caller's environment,
# so a variable set on the driver side never reaches the traced npm; `env` runs as the target user
# and its assignments are what the child actually sees. `-H` still sets HOME first — the `env`
# assignment overrides it, which is the same one-way redirect nub applies to a confined script.
# ⛔ ASSERT WHAT THE CHILD SEES, NOT WHAT THE DRIVER UNSET. `ci-env-scrub.sh` does a plain `unset` in
# THIS shell, which is sufficient on Linux because strace runs the target directly in the driver's
# environment. It is NOT sufficient reasoning here: this driver reaches the traced npm through
# `sudo -u <user> -H env …`, and sudo's env_reset builds a FRESH environment from its own env_keep
# list rather than inheriting ours. So whether the child ever saw `CI` is a property of sudo's
# configuration, not of the scrub — and the two produce an identical-looking record.
#
# Dumping the child's real environment under the IDENTICAL sudo/env chain is the only thing that
# distinguishes them. Runs before the traced command, outside the trace, so it costs the measurement
# nothing.
cat > "$OBS/childenv.sh" <<WRAP
sudo -u "$RUNUSER" -H env "PATH=\$PATH" \
  "HOME=$JAIL_HOME" "TMPDIR=$JAIL_TMP" "NODE_COMPAT=1" \
  "PLAYWRIGHT_BROWSERS_PATH=$TOOLS/ms-playwright" \
  "ELECTRON_CACHE=$TOOLS/electron-cache" \
  "electron_config_cache=$TOOLS/electron-cache" \
  "npm_config_prefix=$TOOLS/npm-prefix" \
  /usr/bin/env > "$OBS/child-env.txt" 2>&1
WRAP
bash "$OBS/childenv.sh" 2>/dev/null || true
# ⛔ THE GUARD CHECKS ITSELF FIRST, BECAUSE ITS FAILURE MODE IS A SILENT "CLEAN". Every part of this
# is a false-negative risk: a malformed alternation makes grep error out and print nothing, which
# reads exactly like "no CI variable reached the child". That is the same vacuous-guard shape as the
# `[A-Z]` assertion, and it is invisible unless the pattern is run against a line that MUST match.
#
# (The scare that produced this: the pattern appeared broken until I noticed I had been testing it in
# zsh, which does not word-split unquoted expansions, while this driver is bash, which does. The
# spelling was fine; my instrument was in the wrong shell. A self-check is immune to both.)
CI_PAT="$(printf '%s\n' $CI_KEYS | paste -sd'|' -)"
if ! printf 'CI=1\n' | grep -qE "^($CI_PAT)=" 2>/dev/null; then
  echo "  ⛔ VENUE-CI-CHILD SELF-CHECK FAILED — the leak pattern does not match a known-positive"
  echo "     line, so a 'clean' result below would prove nothing. Treat CI scrubbing as UNVERIFIED."
elif printf 'PRECIRCLECI=1\nMY_CI_THING=1\n' | grep -qE "^($CI_PAT)=" 2>/dev/null; then
  echo "  ⛔ VENUE-CI-CHILD SELF-CHECK FAILED — the pattern matches a NON-CI variable, so a leak"
  echo "     report below would be noise. Treat CI scrubbing as UNVERIFIED."
fi
CI_IN_CHILD="$(grep -oE "^($CI_PAT)=" "$OBS/child-env.txt" 2>/dev/null | tr -d '=' | tr '\n' ' ' || true)"
if [ -n "${CI_IN_CHILD// /}" ]; then
  echo "  ⛔ VENUE-CI-CHILD LEAKED:$CI_IN_CHILD — the traced script SEES CI detection despite the scrub"
else
  echo "  VENUE-CI-CHILD clean (no CI-detection variable reaches the traced script)"
fi

cat > "$OBS/run.sh" <<WRAP
cd "$OBS"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" \
  "HOME=$JAIL_HOME" \
  "TMPDIR=$JAIL_TMP" \
  "NODE_COMPAT=1" \
  "PYTHONDONTWRITEBYTECODE=1" \
  "PLAYWRIGHT_BROWSERS_PATH=$TOOLS/ms-playwright" \
  "ELECTRON_CACHE=$TOOLS/electron-cache" \
  "electron_config_cache=$TOOLS/electron-cache" \
  "npm_config_prefix=$TOOLS/npm-prefix" \
  "$NPM_BIN" rebuild --no-audit --no-fund "$PKG" > "$OBS/npm.log" 2>&1
echo \$? > "$OBS/rc"
WRAP

PRE=$(find -L "$OBS" -type f ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
# ⛔ TAKEN BEFORE THE TRACE, WHICH IS THE ONLY MOMENT IT EXISTS. The fetch above ran with
# --ignore-scripts, so the package dir right now is exactly what the tarball shipped. After the
# lifecycle script runs that state is unrecoverable, and it is what decides whether the artifact gate
# could ever have failed for this package.
node "$HERE/arm-falsifiability.mjs" --snapshot "$OBS" --pkg "$PKG" --ver "$VER" \
  --out "$OBS/pre-manifest.json" 2>/dev/null || true
# `-x` and an unconditional dump of both the wrapper and dtrace's own stderr: the first run of this
# driver produced a live tracer, a clean dtrace exit, and NO npm.log at all — i.e. the `-c` child
# exited without executing its body, which is invisible unless the wrapper narrates itself.
#
# ⛔ /bin/bash, NEVER /bin/sh. macOS's /bin/sh is a 101 KB STUB that immediately RE-EXECS the real
# 1.29 MB /bin/bash, and `dtrace -c` does not survive its target re-execing: the grip dtrace took on
# the process it spawned is invalidated, dtrace tears down, and the child dies without running its
# body. MEASURED by probes/dtrace-c-matrix.sh — `/bin/sh` 0/8 sentinels, `/bin/bash` 1/1 with the
# full exec tree including the inner `sudo`. The tell in the trace is an `EXEC` record at the
# TARGET's own pid whose execname is `bash`; /bin/bash produces no such record.
#
# Single-variable: an UNSIGNED copy of /bin/sh fails identically, so this is the re-exec and not a
# code-signature or SIP restriction; `-x` and the inner `sudo` were each independently exonerated.
# Not `sh -c`/`bash -c` either — the decoder identifies the lifecycle script as the only `-c` shell
# in the subtree, so the wrapper stays a FILE argument.
dtrace -q -s "$HERE/adapters/macos-observe.d" -o "$OBS/trace.txt" \
       -c "/bin/bash -x $OBS/run.sh" > "$OBS/dtrace.log" 2>&1
DT_RC=$?
echo "  --- wrapper (run.sh) ---"; sed 's/^/     /' "$OBS/run.sh"
echo "  --- dtrace stderr + wrapper trace ---"; sed 's/^/     /' "$OBS/dtrace.log" | head -30
OBS_RC=$(cat "$OBS/rc" 2>/dev/null || echo 99)
OBS_FILES=$(find -L "$OBS" -type f ! -name 'trace.txt' ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
TRACE_LINES=$(wc -l < "$OBS/trace.txt" 2>/dev/null | tr -d ' ')
echo "  OBSERVE   rc=$OBS_RC dtrace_rc=$DT_RC files=$OBS_FILES (pre=$PRE) trace=$TRACE_LINES lines"
# ⛔ A tracer that never attached produces an empty file and a synthesized `{}` that reads as a
# confident "needs nothing". Fail loudly instead.
if ! grep -q 'DTRACE-LIVE' "$OBS/trace.txt" 2>/dev/null; then
  echo "  ⛔ DTRACE NEVER STARTED — see dtrace.log; the run below is NOT a measurement"
  sed 's/^/     /' "$OBS/dtrace.log" | head -20
  exit 1
fi
if [ "$OBS_RC" -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed rc=$OBS_RC; nothing to measure)"
  tail -20 "$OBS/npm.log" | sed 's/^/     /'
  exit 0
fi

# The dependency closure npm actually installed to run this lifecycle script, read off the OBSERVE
# arm's own hoisted `node_modules` — MEASURED rather than guessed. Consumed by the per-arm store
# eviction in `verify()`; see the long note there for why evicting `$PKG` alone leaves a live replay
# path through a transitive dependency's entry.
CLOSURE=$(node -e '
  const fs = require("fs"), path = require("path");
  const nm = process.argv[1], out = [];
  let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { process.exit(0); }
  for (const e of ents) {
    if (!e.isDirectory() || e.name.startsWith(".")) continue;
    if (e.name.startsWith("@")) {
      for (const s of fs.readdirSync(path.join(nm, e.name))) out.push(e.name + "/" + s);
    } else out.push(e.name);
  }
  console.log(out.join("\n"));
' "$OBS/node_modules" 2>/dev/null)
echo "  CLOSURE   $(printf '%s\n' $CLOSURE | grep -c . ) packages evicted per arm   store=$STORE"

# ── 1b. RETAIN THE RAW TRACE — THE ARTIFACT OF RECORD ──────────────────────────────────────────
#
# ⛔ THE RAW TRACER OUTPUT IS THE ARCHIVE. THE NORMALIZED STREAM BELOW IT IS A DERIVED CACHE.
# Maintainer directive, and it corrects a mistake one layer up from the scope tags: a normalized
# event stream bakes in TODAY'S DECODER exactly as a scope tag bakes in today's classifier. Two
# measured proofs that this is not theoretical —
#
#   * this adapter lost 100% of rename DESTINATIONS for its entire existence, silently. Every
#     normalized log written in that era would have carried the hole forward, permanently.
#   * the Linux decoder retained 18 of 27 known writes against a C fixture where the rewritten one
#     retains 26 of 26. Nine losses, invisible, and unrecoverable without the raw.
#
# With the raw kept, a decoder bug is a RE-PARSE. Without it, it is a re-measure — or, worse, a hole
# nobody can see. So if only one of these two files can be committed, THIS is the one that survives.
#
# ⛔ AND A RAW TRACE WITHOUT ITS CAPTURE PARAMETERS IS WORTH FAR LESS THAN IT LOOKS. A future
# re-parse has to know WHAT WAS SUBSCRIBED — a trace with no `linkat` records means "linkat never
# fired" under today's adapter and "linkat was not subscribed" under the one from this morning, and
# nothing in the byte stream distinguishes them. `capture.json` records the exact invocation, a hash
# of the D script that produced it, the kernel it ran on, and the roots every path is relative to.
CAPTURE="$OBS/capture.json"
node -e '
  const fs = require("fs"), crypto = require("crypto");
  const [dscript, trace, obs, home, pkg, ver, sw, kern, argvline, globalStore, toolsDir,
         interpreter, jailHome, jailTmp] = process.argv.slice(1);
  const src = fs.readFileSync(dscript);
  const st = (p) => { try { return fs.statSync(p).size; } catch { return null; } };
  console.log(JSON.stringify({
    v: 1,
    kind: "capture",
    platform: `darwin-${process.arch}`,
    pkg, version: ver,
    tracer: "dtrace",
    // The exact invocation, verbatim. A paraphrase is the thing that goes stale.
    invocation: argvline,
    // ⛔ THE HASH IS WHAT MAKES "what was subscribed?" ANSWERABLE. The adapter is versioned by its
    // CONTENT, not by a number someone has to remember to bump, and the subscription list is
    // recorded beside it so the question can be answered without the file in hand.
    adapter: { path: "harness/v2/adapters/macos-observe.d", sha256: crypto.createHash("sha256").update(src).digest("hex"), bytes: src.length },
    subscribes: [...new Set((src.toString().match(/syscall::[a-z_0-9]+:entry/g) ?? []).map((s) => s.slice(9, -6)))].sort(),
    os: { product: sw, kernel: kern },
    // Every path in the trace is machine-specific. Without these a future parser has a pile of
    // strings — the same reason the normalized log carries them.
    //
    // ⛔ EVERY ROOT THE CLASSIFIER KEYS ON IS DECLARED HERE AND NOWHERE ELSE (PORTABILITY R1).
    // `observe-macos.mjs` reads these and REFUSES TO RUN if one is missing, so this object is the
    // single definition of what a path means. An absent key is fatal there; `null` is a legitimate
    // answer meaning this platform has no such root. Never omit a key to express "not applicable".
    //
    // ⛔ FOUR OF THESE ARE HONESTLY `null` AND THE NULLS ARE A FINDING, NOT AN OVERSIGHT. Unlike
    // `measure.sh`, this driver does NOT reproduce the jail environment for the traced run: the
    // wrapper is `sudo -u <user> -H`, so the script sees the REAL `$HOME`, the real `$TMPDIR`, no
    // `npm_config_prefix` redirect and no private tmp. So there is no jailHome, no jail temp and no
    // npm-prefix root to declare, and a write Linux buckets as free `jailHome` buckets here as
    // billable `userHome`. Declaring `null` makes that asymmetry visible in every record instead of
    // leaving it to be rediscovered from a grant that differs by platform for no stated reason.
    // Closing it changes what is measured, so it needs its own evidence rather than riding along.
    //
    // `cwd` is `null` on principle, not by omission: it is per-process, macOS cannot observe it
    // (posix_spawn addchdir_np) and this driver cannot truthfully declare it, because npm chooses
    // it. The cwd guard in the classifier is what handles the resulting unresolvable paths.
    roots: { project: obs, home, jailHome, temp: jailTmp, npmPrefix: `${toolsDir}/npm-prefix`,
             toolsDir, globalStore, projectStore: `${obs}/node_modules/.store`,
             interpreter, ownPkg: `${obs}/node_modules/${pkg}`, cwd: null },
    // ⛔ THE OBSERVE/VERIFY PARITY CONTRACT, RECORDED. These rewrites are what make the traced run
    // reproduce the environment the real jail creates; a script reading os.tmpdir() writes to a
    // DIFFERENT path without them. When this set changes, a trace taken under the old set is not
    // comparable with one taken under the new, and only a recorded set makes that detectable.
    // PYTHONDONTWRITEBYTECODE joined the set when nub began setting it on every confined script
    // (BUILD_JAIL_BASELINE_ENV in compiler/preset.rs). The OBSERVE arm runs UNJAILED under npm, so
    // the nub baseline env does not reach it — the harness must set it, or OBSERVE sees bytecode
    // writes the jailed arm never attempts. The two are not redundant; they cover opposite sides of
    // the same seam.
    observeEnv: { HOME: jailHome, TMPDIR: jailTmp, NODE_COMPAT: "1", PYTHONDONTWRITEBYTECODE: "1",
                  PLAYWRIGHT_BROWSERS_PATH: `${toolsDir}/ms-playwright`,
                  ELECTRON_CACHE: `${toolsDir}/electron-cache`,
                  electron_config_cache: `${toolsDir}/electron-cache`,
                  npm_config_prefix: `${toolsDir}/npm-prefix` },
    // ⛔ THE PACKAGE DIRECTORY AS IT EXISTS AFTER OBSERVE, EMBEDDED SO THE ARCHIVE STAYS
    // SELF-SUFFICIENT. The cwd guard resolves a relative write against the package dir and then
    // CONFIRMS the resolution against this list — a write to `buildcheck.gypi` is placed only if
    // `buildcheck.gypi` is actually there afterwards. Kept IN the capture rather than as a side file
    // because a re-parse months later has the archive and nothing else; a manifest that lived only
    // on the runner would make the guard permanently unresolvable on every retained trace.
    pkgManifest: (() => {
      const root = obs + "/node_modules/" + pkg, out = [];
      const walk = (d, rel) => { let e; try { e = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const x of e) { if (x.name === "node_modules") continue;
          const p = d + "/" + x.name, r = rel ? rel + "/" + x.name : x.name;
          let t; try { t = fs.statSync(p); } catch { continue; }
          if (t.isDirectory()) { out.push(r); walk(p, r); } else out.push(r); } };
      walk(root, ""); return out;
    })(),
    rawBytes: st(trace),
    at: new Date().toISOString(),
  }, null, 2));
' "$HERE/adapters/macos-observe.d" "$OBS/trace.txt" "$OBS" "$USER_HOME" "$PKG" "$VER" \
  "$(sw_vers -productVersion 2>/dev/null)" "$(uname -a 2>/dev/null)" \
  "dtrace -q -s adapters/macos-observe.d -o trace.txt -c '/bin/bash -x run.sh'" \
  "$GLOBAL_STORE" "$TOOLS" "$INTERPRETER" "$JAIL_HOME" "$JAIL_TMP" \
  > "$CAPTURE" 2>/dev/null
gzip -9 -c "$OBS/trace.txt" > "$OBS/trace.txt.gz" 2>/dev/null
if [ -s "$OBS/trace.txt.gz" ] && [ -s "$CAPTURE" ]; then
  echo "  RAWLOG-FILE $OBS/trace.txt.gz"
  echo "  RAWLOG-CAPTURE $CAPTURE"
  echo "  RAWLOG-BYTES raw=$(wc -c < "$OBS/trace.txt" | tr -d ' ') gz=$(wc -c < "$OBS/trace.txt.gz" | tr -d ' ')"
  echo "  VENUE-INTERPRETER $INTERPRETER"
  # ⛔ EVERY VARIABLE THIS DRIVER SET, UNSET OR REDIRECTED (PORTABILITY R6) — and `CI` is listed with
  # its INHERITED value precisely because the one override that would invalidate the whole venue/CI
  # acceptance test is touching it. Recording it unchanged is the claim a reader can check.
  # ⛔ The harness normalises its own APPARATUS, never the environment under test. `CI`,
  # `GITHUB_ACTIONS` and `NODE_ENV` are passed through verbatim, because an install script reads them
  # and changes what it downloads or whether it builds from source; flattening them would produce a
  # catalog that under-grants every CI user.
  # ⛔ `unset` IS NOT EMPTY AND THE ENTRY THERE IS A MEASURED FINDING. sudo env_reset discards the
  # caller environment, so before this driver set TMPDIR the traced npm had NONE — and node's
  # os.tmpdir() falls back to the SHARED /tmp when TMPDIR is unset. MEASURED on hugo-extended: its
  # downloader wrote to /private/tmp/<hex> rather than the per-user /var/folders/... a real developer
  # gets. So the old wrapper was not merely "not redirecting temp", it was moving the script to a
  # different temp root than any user has. Recorded because a reader comparing an old archive with a
  # new one needs to know the temp root changed and why.
  echo "  VENUE-OVERRIDES $(node -e '
    const e = process.env;
    const jh = process.argv[1], jt = process.argv[2], tools = process.argv[3];
    process.stdout.write(JSON.stringify({
      set: { PATH: "inherited-and-forwarded", HOME: jh, TMPDIR: jt, NODE_COMPAT: "1",
             PYTHONDONTWRITEBYTECODE: "1",
             PLAYWRIGHT_BROWSERS_PATH: tools + "/ms-playwright",
             ELECTRON_CACHE: tools + "/electron-cache",
             electron_config_cache: tools + "/electron-cache",
             npm_config_prefix: tools + "/npm-prefix" },
      // The CI-detection scrub is a NORMALISATION and is declared (R6): it changes which code a
      // package runs, so it matters by construction.
      unset: ["(sudo env_reset discards the caller environment; every var above is re-set after it)"]
        .concat(process.argv[4] ? process.argv[4].trim().split(/\s+/) : []),
      // ⛔ WHAT THE VENUE HAD, captured BEFORE the scrub. Reading `process.env` here would report
      // what the driver left behind, so a real CI run would file `CI: null` — claiming the venue was
      // not CI precisely because we removed the proof.
      passedThrough: Object.fromEntries([["CI", null], ["GITHUB_ACTIONS", null],
        ["NODE_ENV", e.NODE_ENV ?? null],
        ...process.argv[5].split("\n").filter(Boolean).map((kv) => {
          const i = kv.indexOf("="); return [kv.slice(0, i), kv.slice(i + 1)];
        })]),
    }));
  ' "$JAIL_HOME" "$JAIL_TMP" "$TOOLS" "$CI_SCRUBBED" "$CI_INHERITED" 2>/dev/null)"
  echo "  VENUE-OBSERVE-USER $RUNUSER uid=$RUNUID (R7: ordinary non-root user, asserted)"
  # ⛔ FLAG, NEVER FAIL — the package is still measurable; what a flag says is that a GREEN ARM
  # CARRIES NO EVIDENCE for it. `|| true` is deliberate: a detector fault must never cost a record.
  node "$HERE/arm-falsifiability.mjs" --obs "$OBS" --pre "$OBS/pre-manifest.json" \
    --pkg "$PKG" --ver "$VER" 2>/dev/null | sed 's/^/  /' || true
else
  # ⛔ THIS USED TO BE NON-FATAL AND IT NO LONGER IS — noted here so the change is not rediscovered
  # from a confusing failure downstream. Retention was additive while roots arrived as arguments;
  # under R2 capture.json is the ONLY source of roots, so a missing capture means the classifier
  # cannot run and the driver exits SYNTHESIZE FAILED. That is the correct outcome: it is an
  # INSTRUMENT failure, and record.mjs turns it into HARNESS-ERROR, which returns the queue row to
  # pending rather than baking a rootless guess into the corpus as if it were a measurement.
  echo "  ⛔ RAW TRACE NOT RETAINED — the archive artifact is missing for this record"
  echo "     ⛔ AND THIS IS NOW FATAL: capture.json is the only source of classification roots."
fi

# ── 1c. THE DERIVED EVENT LOG ──────────────────────────────────────────────────────────────────
#
# ⛔ DERIVED, AND REGENERABLE FROM `trace.txt.gz` ABOVE. This is the file anyone will actually query
# — greppable, one JSON object per event, paths already resolved — but it is a CACHE, not the
# archive. If it disagrees with the raw trace, the raw trace is right; if a decoder bug is found,
# this file is rebuilt rather than re-measured. That ordering is the whole reason the raw is kept.
#
# ⛔ WHAT IS RETAINED IS STILL THE RAW EVENT, NOT ITS CLASSIFICATION. A path tagged with today's
# scope would bake in today's classifier and would need a re-measure the moment the scope set
# changes — which it is changing right now, with `tmp`. So even the derived view carries the
# syscall, its arguments, its errno and the process identity, and no scope at all.
#
# ⛔ AND IT IS NOT REQUIRED TO MATCH ANY OTHER PLATFORM. Trimming each adapter to the intersection
# of what all three can express is itself a canonicalization, and it would force this lane to drop
# whatever dtrace exposes that strace and ETW do not. Per-OS formats with per-OS parsers is the
# settled shape; `fixtures/schema-contract.test.mjs` checks the derived views for ACCIDENTAL drift
# and is advisory — where conformance would cost fidelity, fidelity wins.
#
# ⛔ TWO PUBLISH PATHS EXIST AND THIS HONOURS BOTH, DELIBERATELY. The Linux lane writes STRAIGHT into
# the record dir from `NUB_V2_EVENTS_OUT`, which `run-batch-v2.mjs` sets (and currently sets only for
# linux); this lane also prints `EVENTLOG-FILE`, which `record.mjs` copies from. The env path is
# cheaper when the batch runner is driving; the stdout path is the only one that works when the
# driver is run STANDALONE, which is how every probe branch and every manual re-measure invokes it.
# Honouring the variable here means the day that gate widens to darwin, nothing has to change.
EVENTS="$OBS/events.ndjson"
node "$HERE/adapters/macos-eventlog.mjs" "$OBS/trace.txt" --out "$EVENTS" \
     --pkg "$PKG" --version "$VER" --project "$OBS" --home "$USER_HOME" \
     > "$OBS/eventlog-stats.json" 2>&1
EV_RC=$?
if [ "$EV_RC" -eq 0 ] && [ -n "${NUB_V2_EVENTS_OUT:-}" ] && [ -s "$EVENTS.gz" ]; then
  cp "$EVENTS.gz" "$NUB_V2_EVENTS_OUT" 2>/dev/null
fi
if [ "$EV_RC" -eq 0 ] && [ -s "$EVENTS.gz" ]; then
  # The record writer copies this file into the record dir. A path on stdout is the contract
  # because the three drivers already communicate with `record.mjs` through their stdout alone.
  echo "  EVENTLOG-FILE $EVENTS.gz"
  # ⛔ RE-SERIALISED BY A JSON PARSER, NOT FLATTENED WITH `tr -d '\n '`. The stats block is pretty-
  # printed, and the record contract needs it on ONE line — but stripping every space also strips
  # the ones INSIDE any string value, so the first spelling of this line was a corrupter waiting for
  # a stats field to contain a path with a space in it. `record.mjs` would then log
  # `eventlog-stats-unparsable` and the evidence census would be silently absent from the record.
  echo "  EVENTLOG-STATS $(node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))))' "$OBS/eventlog-stats.json" 2>/dev/null)"
else
  # ⛔ NOT FATAL, BUT NEVER SILENT. Retention is additive to the measurement; losing it must not
  # cost a measured package. Saying so is what stops a corpus quietly reverting to verdict-only.
  echo "  ⛔ EVENTLOG NOT WRITTEN (rc=$EV_RC) — this record will carry a verdict and no evidence"
  sed 's/^/     /' "$OBS/eventlog-stats.json" 2>/dev/null | head -5
fi

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
# ⛔ `$PKG` IS LOAD-BEARING, NOT DECORATION. Without it the decoder has no `ownPkg` bucket and bills
# every write into the package's OWN directory as `write.deps` — a capability the base profile
# already grants. `measure.sh:194` passes it for the same reason.
node "$HERE/observe-macos.mjs" "$OBS/trace.txt" --capture "$CAPTURE" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }
# ⛔ AN EMPTY GRANT IS A REAL ANSWER; AN UNATTRIBUTED RUN IS NOT. The decoder emits this token
# instead of `{}` when the subtree filter matched nothing, precisely so the two cannot be confused.
if [ "$GRANT" = "UNKNOWN-ATTRIBUTION-FAILED" ]; then
  echo "  => UNKNOWN (attribution failed — the lifecycle shell was never identified, so there is no"
  echo "     measurement here. This is NOT a package that needs nothing.)"
  exit 0
fi

if [ -z "$NUB" ] || [ ! -x "$NUB" ]; then
  echo "  => OBSERVE-ONLY: $GRANT"
  echo "  ⛔ VERIFY NOT RUN — no feature-enabled nub binary was supplied. This is a HYPOTHESIS,"
  echo "     not a measurement: NUB_BUILD_JAIL_CATALOG is inert without"
  echo "     --features nub-cli/build-jail-catalog-override, so a run without it would have"
  echo "     silently measured the compiled-in catalog instead of this grant."
  exit 0
fi

# ── 3. VERIFY — the real, UNPRIVILEGED jail. Runs as the invoking user, never root. ────────────
verify () {
  local grant="$1" label="$2" tracer="${3:-}"
  local v="$ROOT/verify-$label"; mkdir -p "$v"; chown -R "$RUNUSER" "$v" 2>/dev/null
  # A unique root package name per arm: nub's side-effects memo replays a lifecycle outcome keyed
  # on package identity, and a replayed arm is indistinguishable from a real one by exit code.
  local name="v$(echo "$label" | tr -dc 'a-z0-9')$RANDOM"
  printf '{"name":"%s","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$name" "$PKG" "$VER" > "$v/package.json"
  # ⛔ STATE THE JAIL EXPLICITLY RATHER THAN INHERITING IT. An arm that silently ran UNCONFINED
  # passes every time and reports the synthesized grant as sufficient — it inflates the agreement
  # rate rather than breaking anything, which is what makes it the most dangerous false green here.
  printf '{"install":{"buildJail":true}}\n' > "$v/nub.jsonc"
  # THREE REPLAY PATHS, THREE GUARDS, AND NO ONE OF THEM SUBSUMES ANOTHER (`measure.sh` proved the
  # last point directly: with the memo dropped in every arm, the only variable being whether a
  # transitive store entry was evicted, `@apollo/rover@0.2.1` went rc=0 with an EMPTY `bin/` to rc=1
  # with `bin/` absent):
  #
  #   unique root name      — nub memoises a lifecycle outcome keyed on package identity
  #   side-effects-cache=no — the memo says "this script already ran, skip it"
  #   store eviction        — the store says "this package is already materialised, relink it"
  local cache="$v/nubcache"; rm -rf "$cache"
  # ⛔ A PER-ARM `NUB_CACHE_DIR` DROPS NEITHER THE MEMO NOR THE STORE, AND AN EARLIER REVISION OF
  # THIS FILE SAID IT DROPPED BOTH. `NUB_CACHE_DIR` governs the resolver PRIMER cache
  # (`pm_engine/mod.rs`, `config_env("CACHE_DIR")`); the store comes from `aube_store::dirs::
  # cache_dir()`, and the memo from `side_effects_cache_root()` = `virtual_store_dir()/../
  # side-effects-v1`, i.e. BOTH live beside the store under the XDG cache and neither moves with it.
  # So the memo needs its own opt-out, read by `aube_settings::resolved::side_effects_cache`.
  printf 'side-effects-cache=false\n' > "$v/.npmrc"
  # ⛔ AN EMPTY GRANT CANNOT BE EXPRESSED AS `{"<pkg>":{"default":{}}}` — the parser REJECTS an empty
  # default block, which would make the arm VOID and read as "the grant did not work" rather than
  # "the package needs nothing". The override REPLACES the compiled-in table rather than merging
  # into it, so OMITTING the package makes it run at the base profile, which IS the empty grant. A
  # throwaway sentinel entry keeps the file non-empty so the override still engages and the
  # OVERRIDDEN>=1 / REJECTED==0 assertion below stays meaningful. Ported from measure.sh; the
  # Windows lane took husky@4.3.8 from write:"disk" to a verified {} on exactly this construction.
  # ⛔ UNDER `--at-catalog` NONE OF THE CONSTRUCTION BELOW APPLIES — THE FILE IS THE HYPOTHESIS.
  # Copied VERBATIM, sentinel or no sentinel, because the question that mode asks is whether the
  # catalog AS COLLATED installs the package. Rewriting it here to be likelier to engage would
  # answer about a catalog nobody ships, and a collated catalog that fails to engage leaves the arm
  # VOID — which is the honest reading of "this file would not have worked".
  if [ -n "${AT_CATALOG:-}" ]; then
    cp "$AT_CATALOG" "$v/cat.json" || return 1
  else
  node -e '
    const fs=require("fs");const [r,p,g]=process.argv.slice(1);
    const grant=JSON.parse(g);
    const cat = Object.keys(grant).length
      ? {packages:{[p]:{default:grant}}}
      : {packages:{"__v2_empty_grant_sentinel__":{default:{network:true}}}};
    fs.writeFileSync(r+"/cat.json",JSON.stringify(cat));
  ' "$v" "$PKG" "$grant" || return 1
  fi
  # ⛔⛔ EVICT THIS PACKAGE **AND ITS CLOSURE** FROM THE MACHINE-GLOBAL STORE. Ported from
  # `measure.sh`, whose comments carry the measurements; the load-bearing ones, restated because
  # this lane was hard-disabled for lacking exactly this:
  #
  #   * A relinked package runs NO lifecycle script, so the arm PASSES at whatever grant is under
  #     test — including one NARROWER than the package needs. That is an under-grant, the one
  #     unacceptable direction, and it presents with every precondition green.
  #   * `$PKG` ALONE IS NOT ENOUGH. `@apollo/rover@0.2.1`'s postinstall writes into a SIBLING
  #     package's directory (`binary-install/bin/`), which the jail refuses because
  #     `store_entry_write_root` grants the package's OWN entry only. Leaving `binary-install`
  #     populated by a prior arm let a `{"network":true}` arm relink it and pass.
  #   * TARGETED, NOT `rm -rf` ON THE STORE. It is machine-global and a sibling agent may be
  #     measuring on the same box. Anchor `<slug>@` with `/`→`+` — the store's own naming
  #     (`@babel+core@7.29.7-<hash>`); a `tr '/@' '--'` slug matched zero scoped packages, silently.
  #   * SPARE THE ENTRIES nub'S OWN TOOLING LINKS THROUGH (67c01911). nub bootstraps node-gyp into
  #     `<cache>/nub/pm/tools/` against this same store, and `semver`/`tar`/`which`/`graceful-fs`
  #     are ordinary members of a native package's closure — evicting by name leaves a dangling
  #     symlink and `gyp ERR! Cannot find module 'semver'`, which reads as INSUFFICIENT and inflates
  #     the grant. Resolve the sparing set by FOLLOWING SYMLINKS, never by matching the link dir's
  #     name: it is `.store` on one binary and `.nub` on another, so a name match stops matching
  #     silently. Sparing cannot manufacture a false pass — nub's tool closure is pure-JS library
  #     code that declares no lifecycle script, so no arm can leave build output in a spared entry.
  #
  # Cost: each arm re-materializes the closure. That is the price of independent arms.
  if [ -d "$STORE" ]; then
    printf '%s\n' "$PKG" $CLOSURE | sort -u | node -e '
      const fs=require("fs"), path=require("path");
      const [store, tools] = process.argv.slice(1);
      // Every store entry any nub tool project links through, at whatever depth and under whatever
      // name that project gives its virtual-store dir.
      const keep = new Set();
      const walk = (dir, depth) => {
        if (depth > 6) return;
        let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          const p = path.join(dir, e.name);
          if (e.isSymbolicLink()) {
            let t; try { t = path.resolve(dir, fs.readlinkSync(p)); } catch { continue; }
            const rel = path.relative(store, t);
            if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) keep.add(rel.split(path.sep)[0]);
          } else if (e.isDirectory()) walk(p, depth + 1);
        }
      };
      walk(tools, 0);
      const prefixes = [...new Set(fs.readFileSync(0, "utf8").split("\n").filter(Boolean)
        .map(n => n.replace(/\//g, "+") + "@"))];
      let removed = 0, spared = 0;
      let entries; try { entries = fs.readdirSync(store); } catch { entries = []; }
      for (const e of entries) {
        if (!prefixes.some(n => e.startsWith(n))) continue;
        if (keep.has(e)) { spared++; continue; }
        fs.rmSync(path.join(store, e), { recursive: true, force: true });
        removed++;
      }
      console.log(`  EVICT[${process.argv[3]}] ${removed} store entries removed, ${spared} spared as nub tooling, ${entries.length} in store`);
    ' "$STORE" "$TOOLS" "$label" ||
      echo "  ⛔ EVICTION FAILED — this arm may REPLAY a prior arm's build and UNDER-report"
  else
    echo "  EVICT[$label] no store at $STORE yet (first arm on this box)"
  fi
  if [ -n "$tracer" ]; then
    ( cd "$v" && export NUB_CACHE_DIR="$cache" NUB_BUILD_JAIL_CATALOG="$v/cat.json"
      cat > "$v/jail.sh" <<JW
cd "$v"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" NUB_CACHE_DIR="$cache" NUB_BUILD_JAIL_CATALOG="$v/cat.json" \
  "$NUB" install > "$v/i.log" 2>&1
echo \$? > "$v/rc"
JW
      dtrace -q -s "$HERE/adapters/macos-observe.d" -o "$v/trace.txt" \
             -c "/bin/bash -x $v/jail.sh" > "$v/dtrace.log" 2>&1 )   # /bin/sh re-execs; see OBSERVE
    local rc; rc=$(cat "$v/rc" 2>/dev/null || echo 99)
  else
    # ⛔ THE JAILED RUN MUST NOT BE ROOT. This driver is invoked under sudo because dtrace needs
    # uid 0, and a build jail evaluated as root is not the jail that ships — root defeats several
    # of its own confinement primitives, so an arm left at uid 0 would pass for a reason that has
    # nothing to do with the grant.
    chown -R "$RUNUSER" "$v" 2>/dev/null
    sudo -u "$RUNUSER" -H env "PATH=$PATH" NUB_CACHE_DIR="$cache" \
      NUB_BUILD_JAIL_CATALOG="$v/cat.json" sh -c "cd '$v' && '$NUB' install > '$v/i.log' 2>&1; \
      '$NUB' approve-builds --all > '$v/a.log' 2>&1"
    local rc=$?
  fi
  # The replay signature: `materialized` with no install line. Reported, not fatal — a package with
  # no lifecycle script legitimately shows neither.
  if grep -qE '^\s*materialized ' "$v/i.log" 2>/dev/null && ! grep -qE 'installed [0-9]+ package' "$v/i.log" 2>/dev/null; then
    echo "     ⛔ REPLAY SUSPECTED — 'materialized' with no install line; the script may not have run"
  fi
  # ⛔ A malformed override WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  # assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  local ovr rej files
  ovr=$(cat "$v"/*.log 2>/dev/null | grep -c 'catalog OVERRIDDEN')
  rej=$(cat "$v"/*.log 2>/dev/null | grep -c 'REJECTED')
  # ⛔ `-L` IS LOAD-BEARING. nub's global virtual store makes every node_modules entry a SYMLINK,
  # so a bare `find -type f` counts ~30 files where the npm control counted 456, and the artifact
  # gate below then fails an arm that installed perfectly.
  files=$(find -L "$v" -type f ! -name '*.log' ! -name 'cat.json' ! -name 'trace.txt' ! -path '*/nubcache/*' 2>/dev/null | wc -l | tr -d ' ')
  # ⛔⛔ `files >= OBS_FILES` WAS THE GATE HERE AND IT IS NOT A SUCCESS GATE. `find -L` follows the
  # isolated layout's symlinks into the machine-global store, so the number is dominated by the
  # dependency closure and is nearly insensitive to whether THIS package's script produced anything
  # — and the eviction above only makes an arm ATTEMPT the work, so it needs a gate that can see
  # whether the work landed. MEASURED on `@apollo/rover@0.2.1` (Linux): an arm that produced NONE of
  # the package's three artifacts counted 704 files against a 718-file reference. The per-file
  # ARTIFACT MANIFEST is the gate in `measure.sh` and on Windows; the three drivers now agree on what
  # "the arm succeeded" means. `files/OBS_FILES` stays PRINTED for continuity with existing logs.
  # ⛔ OBSERVED FROM THE ARM TREE, NEVER INFERRED FROM `CI`. Deriving the layout from the env var
  # would encode the very rule this field exists to let us CHECK, and would then agree with itself
  # forever. R3 names this the sharp axis, and `record.mjs` reads the marker; without it every darwin
  # record carries storeLayout null. It also matters for `ownPkg`: `store_entry_write_root` is gated
  # on the package dir's parent being a store, i.e. the ISOLATED layout — under a hoisted arm that
  # drop would be an under-grant, and a null field cannot tell you which regime ran.
  if [ -z "${STORE_LAYOUT_REPORTED:-}" ]; then
    if [ -d "$v/node_modules/.store" ] || [ -L "$v/node_modules/$PKG" ]; then
      echo "  VENUE-STORE-LAYOUT isolated"
    else
      echo "  VENUE-STORE-LAYOUT hoisted"
    fi
    STORE_LAYOUT_REPORTED=1
  fi
  local gate grc
  gate=$(node "$HERE/artifact-gate.mjs" --obs "$OBS" --arm "$v" --pkg "$PKG" --ver "$VER" 2>&1); grc=$?
  echo "  VERIFY[$label] rc=$rc $(printf '%s' "$gate" | head -1) (tree $files/$OBS_FILES) OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  printf '%s\n' "$gate" | tail -n +2 | sed 's/^/     /'
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "     ⛔ override did not engage — arm is VOID"; return 2; }
  # rc 3 = OBSERVE produced no files for this package at all, so the manifest can gate on nothing.
  # Fall back to the exit code rather than passing an ungated arm off as measured.
  if [ "$grc" -eq 3 ]; then
    echo "     NOTE no artifact reference for $PKG — gating on rc alone"
    [ "$rc" -eq 0 ]; return $?
  fi
  # Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  # failure mode. Both must hold.
  [ "$rc" -eq 0 ] && [ "$grc" -eq 0 ]
}

# ── 3-DIRECT. ONE ARM AT A NAMED GRANT, THEN STOP. ────────────────────────────────────────────
#
# ⛔ THE EXIT CODES ARE THE CONTRACT. `falsify.mjs` and `e2e.mjs` both branch on them, and the three
# outcomes are genuinely different things. Collapsing VOID into INSUFFICIENT would turn "the override
# never engaged, nothing was measured" into a fabricated capability finding about a package.
#   0  SUFFICIENT    installed, and its artifacts matched OBSERVE
#   1  INSUFFICIENT  the package needs MORE than this grant
#   3  VOID          the override did not engage; NOTHING was measured
#
# ⛔ THIS BLOCK IS THE FEATURE. An earlier commit shipped the flag PARSING without it: `--at-grant`
# validated, then fell through to the ordinary ladder and measured the SYNTHESIZED grant instead of
# the caller's, exiting 0 in every case so 1 and 3 were unreachable. It passed `bash -n`, the smoke
# probe, and six tests — because every one of those stops at a validation gate, and a `grep` for the
# flag name matches the parser. Nothing short of RUNNING the driver and looking for the line below
# could have caught it.
if [ -n "$AT_GRANT" ] || [ -n "$AT_CATALOG" ]; then
  if [ -n "$AT_CATALOG" ]; then
    echo "  ── DIRECT: does $PKG@$VER install under the catalog at $AT_CATALOG ?"
    verify "(catalog $AT_CATALOG)" "at-catalog"; ARC=$?
  else
    echo "  ── DIRECT: does $PKG@$VER install under EXACTLY $AT_GRANT ?"
    verify "$AT_GRANT" "at-grant"; ARC=$?
  fi
  AT_SUBJECT="${AT_CATALOG:-$AT_GRANT}"
  case "$ARC" in
    0) echo "  => SUFFICIENT $AT_SUBJECT   (installed, artifacts matched OBSERVE)"; exit 0 ;;
    2) echo "  => ⛔ VOID — the override did not engage; NOTHING was measured."
       echo "     Not a result. Do NOT record it, and do NOT read it as insufficient."; exit 3 ;;
    *) echo "  => INSUFFICIENT $AT_SUBJECT   (the package needs MORE than this grant)"
       echo "     ⇒ If this grant came from a v1 record, that record UNDER-GRANTS — the direction"
       echo "        that breaks a real install. Worth a mechanism before it is acted on."; exit 1 ;;
  esac
fi

VERIFIED=0
# ⛔ VOID IS NOT INSUFFICIENT ON THE LADDER EITHER. `verify` returns 2 when the catalog override
# never engaged, and a bare `if verify …` reads that as false — so a run that measured NOTHING was
# reported `=> UNDER-PREDICTED … This is the correctness finding`, which is a capability claim about
# the package. `measure.sh` guards this explicitly and this driver did not.
verify "$GRANT" "synth"; SRC=$?
if [ "$SRC" -eq 2 ]; then
  echo "  => ⛔ VOID — the override did not engage on the verdict arm; NOTHING was measured."
  echo "     Not a result. Do NOT read the absence of a verdict as a wide grant."
  exit 3
fi
if [ "$SRC" -eq 0 ]; then
  VERIFIED=1
  echo "  => VERIFIED $GRANT"
else
  echo "  => UNDER-PREDICTED — the synthesized grant did NOT verify. This is the correctness"
  echo "     finding: OBSERVE saw a run that the jail then refused on some axis it did not cover."
fi

# ── 3b. NARROW — the direct over-prediction measure. ───────────────────────────────────────────
#
# Only meaningful once a grant has verified: dropping a capability from a grant that already fails
# tells you nothing. Each variant removes exactly ONE capability, so a passing variant names the
# capability the synthesis did not need. Single-variable by construction.
if [ "$VERIFIED" -eq 1 ]; then
  # ⛔ NO `mapfile` AND NO ARRAYS HERE. macOS ships bash 3.2 at /bin/bash, where `mapfile` does not
  # exist and `${arr[@]}` on an empty array is an unbound-variable error under `set -u`. A plain
  # file plus a read loop works on both.
  node -e '
    const g = JSON.parse(process.argv[1]); const out = [];
    if (g.network) { const c = JSON.parse(JSON.stringify(g)); delete c.network; out.push(["no-network", c]); }
    for (const k of Object.keys(g.write ?? {})) {
      const c = JSON.parse(JSON.stringify(g)); delete c.write[k];
      if (!Object.keys(c.write).length) delete c.write;
      out.push(["no-write-" + k, c]);
    }
    for (const [n, c] of out) console.log(n + "\t" + JSON.stringify(c));
  ' "$GRANT" > "$ROOT/variants.tsv" 2>/dev/null
  if [ ! -s "$ROOT/variants.tsv" ]; then
    echo "  NARROW    no capability to drop — the grant is already empty; over-prediction is 0 by construction"
  fi
  while IFS=$'\t' read -r nm gg; do
    [ -n "${nm:-}" ] || continue
    # An empty variant used to be UNTESTABLE here, because the parser rejects an empty `default`
    # block and the arm came back VOID. `verify` now expresses it the way measure.sh does — omit the
    # package so it runs at the base profile — so the fully-narrowed variant is a real arm, and a
    # package that needs nothing is measurable rather than skipped.
    if verify "$gg" "nar-$nm"; then
      echo "     ⛔ OVER-PREDICTED — the strictly narrower $gg also verifies; '$nm' was not needed"
      ANY_OVER=1
      echo "$nm" >> "$ROOT/dropped.txt"
    else
      echo "     narrowing '$nm' fails ⇒ that capability IS necessary"
    fi
  done < "$ROOT/variants.tsv"
  # ⛔ WITHOUT THIS LINE A FULLY-MINIMAL RECORD CANNOT SAY SO. `record.mjs` sets `minimality` from
  # `=> MINIMAL` or "grant is already empty"; this driver emitted neither when every narrowing FAILED,
  # so the strongest possible descent result — every capability independently proven necessary — was
  # recorded as `minimality: null`, indistinguishable from a descent that never ran. MEASURED on
  # hugo-extended@0.141.0: its sole narrowing failed with a real shortfall and the record still came
  # back null. measure.sh has always printed this; the macOS port dropped it.
  if [ -s "$ROOT/variants.tsv" ] && [ -z "${ANY_OVER:-}" ]; then
    echo "  => MINIMAL — every capability in $GRANT is independently necessary"
  fi
  # ⛔ THE JOINT ARM. The descent is LEAVE-ONE-OUT, so N droppable capabilities give N arms proving
  # each drops ON ITS OWN and nothing proving they drop TOGETHER. The joint grant is strictly
  # narrower than any arm that ran, so publishing it off the individual results would be an inference
  # dressed as a measurement — in the under-grant direction. One extra arm converts it into a real
  # one, and only when there is something to convert: N<2 needs no joint arm because the single
  # leave-one-out arm IS the joint case.
  DROPPED=$(grep -c . "$ROOT/dropped.txt" 2>/dev/null || echo 0)
  if [ "$DROPPED" -ge 2 ]; then
    JOINT=$(node -e '
      const g = JSON.parse(process.argv[1]);
      for (const n of process.argv[2].split(/\s+/).filter(Boolean)) {
        if (n === "no-network") delete g.network;
        const w = /^no-write-(.+)$/.exec(n);
        if (w && g.write) { delete g.write[w[1]]; if (!Object.keys(g.write).length) delete g.write; }
      }
      console.log(JSON.stringify(g));
    ' "$GRANT" "$(tr '\n' ' ' < "$ROOT/dropped.txt")" 2>/dev/null)
    if [ -n "${JOINT:-}" ]; then
      if verify "$JOINT" "joint-narrow"; then
        echo "  => JOINT-NARROW VERIFIED $JOINT — all $DROPPED capabilities drop TOGETHER, measured"
      else
        echo "  => JOINT-NARROW FAILED $JOINT — each capability drops alone but not together;"
        echo "     the record keeps the wider synthesized grant, which is the honest answer"
      fi
    fi
  fi
fi

# ── 3c. DIAGNOSE — run the FAILING grant JAILED, under dtrace, and name the refusal. ───────────
#
# The open question this answers for macOS: Seatbelt denies at the MAC layer, so the syscall still
# returns to userspace with an errno — which is where dtrace reads it. If that holds, the macOS
# lane gets the same closing tool the Linux lane has. If Seatbelt kills the process before the
# return probe fires, it does not, and that is worth knowing precisely.
if [ "$VERIFIED" -eq 0 ]; then
  echo "  DIAGNOSE  re-running the failing grant JAILED, under dtrace"
  verify "$GRANT" "diag" "dtrace" > /dev/null 2>&1
  D="$ROOT/verify-diag/trace.txt"
  if [ ! -s "$D" ]; then
    echo "     ⛔ no diagnose trace produced — dtrace could not observe the jailed run"
  else
    echo "     trace lines: $(wc -l < "$D" | tr -d ' ')"
    # errno 1 EPERM / 13 EACCES / 30 EROFS. ⛔ NOT errno 2 (ENOENT): a jail that hides a path
    # reports it missing, and so does an ordinary probe for a file that was never there — counting
    # ENOENT would bury the real refusals under thousands of module-resolution misses.
    echo "     refused paths under the failing grant (count, path):"
    grep -E '^(OPEN|PATHOP)\|' "$D" | awk -F'|' '$0 ~ /errno=(1|13|30)\|/ {print $NF}' \
      | sort | uniq -c | sort -rn | head -15 | sed 's/^/       /'
    echo "     ⇒ TREAT THIS AS A CANDIDATE SET, NOT AN ANSWER. On Linux the last refusal before a"
    echo "       fatal exit was a trailing red herring once already; settle it with a"
    echo "       single-variable arm per path plus a negative control granting all the others."
  fi
fi

echo "### DONE $PKG@$VER  synthesized=$GRANT verified=$VERIFIED"
