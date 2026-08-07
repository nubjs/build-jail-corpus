#!/usr/bin/env bash
# Harness v2 driver: OBSERVE -> SYNTHESIZE -> VERIFY -> (fall back to the ladder).
#
# See README.md for why. The short version: v1's only signal was pass/fail of a jailed run, so it
# had to SEARCH 55 states to find the minimum, and could never say WHAT a package touched. The
# generation harness may run as root, so it does not have to guess — it watches, then checks.
#
#   usage: measure.sh <pkg> <version> [nub-binary]
#          measure.sh <pkg> <version> [nub-binary] --at-grant '<json>'
#          measure.sh <pkg> <version> [nub-binary] --at-catalog <catalog.json>
#
# ⛔ `--at-grant` ANSWERS A DIFFERENT AND SHARPER QUESTION, AND IT EXISTS BECAUSE THE LADDER
# ANSWERS IT UNSOUNDLY. The default mode asks "what is the minimum this package needs?" — OBSERVE,
# synthesize, verify, then walk. To ask instead "does this package install under EXACTLY this
# grant?" (e.g. its own v1 record), the ladder is not merely expensive, it is WRONG:
#
#   MEASURED on `electron-prebuilt@0.31.2`: OBSERVE logged 2417 events with `malformed: 0` and
#   reported `attributedPeers: 0, allTreePeers: 0, peers: []` for a package whose v1 record says
#   `network: true` — the ETW adapter missed the egress entirely. Synthesis under-predicts, the
#   fallback ladder repairs it by climbing, and `=> MINIMUM` then conflates what the package NEEDS
#   with what OBSERVE failed to SEE plus what the ladder recovered. Compared against the v1 record,
#   that reads as "v1 UNDER-GRANTED" when the defect is v2's own tracer.
#
#   ⛔ AN EARLIER REVISION OF THIS COMMENT JUSTIFIED THE ABOVE WITH "every ladder rung on Windows
#   carries network:true". THAT IS FALSE, and it is recorded here because a confidently wrong
#   rationale outlives the correct conclusion it was attached to. `states.mjs` holds 54 states of
#   which 22 carry NO network, including {"write":["userHome"],"network":false} at cost 7 —
#   strictly cheaper than the same grant with network at cost 10. The walk is ascending-cost and
#   the first passing state is the minimum by construction, so `electron-prebuilt` WAS tested at
#   the network-free rung, failed there, and only passed with network. v1 MEASURED that egress.
#
#   That correction strengthens the case. Two independent instruments say the egress is real and
#   observable — v1's walk, and this adapter's own validator (`adapters/validate-windows.mjs`
#   assertions P4/P7, with negative control N4) proving ETW capture works for a raw
#   TcpClient.Connect AND an Invoke-WebRequest — and OBSERVE still reported none of it.
#
# ⇒ A TRACER BLIND SPOT PRESENTS AS A DEFECT IN THE THING BEING MEASURED. `--at-grant` removes
# that path entirely: no synthesis, so nothing OBSERVE missed can enter the verdict. It runs ONE
# arm and reports pass/fail against the artifact gate, which is the direct answer.
#
# OBSERVE still runs, and must: the artifact gate needs its file manifest as the reference for
# "did this arm produce what an unjailed install produces". Only OBSERVE's NETWORK attribution is
# in question here; its file output is unaffected. Cost is still ~4x lower than the full walk.
set -uo pipefail
PKG="${1:?usage: measure.sh <pkg> <version> [nub] [--at-grant <json>]}"
VER="${2:?usage: measure.sh <pkg> <version> [nub] [--at-grant <json>]}"
# ⛔ `[nub-binary]` IS OPTIONAL AND `--at-grant` TAKES ITS SLOT, so a `$3` beginning with `-` is a
# FLAG, not a path. `${3:-<default>}` took it blindly, which made the documented form
# `measure.sh <pkg> <ver> --at-grant '<json>'` exec `--at-grant install` — every arm came back
# rc=127 `--at-grant: command not found`, reported as `⛔ VOID — the override did not engage`.
# The verdict is honest, so this never corrupted a record; it just made `--at-grant` unusable
# without also naming the binary.
case "${3:-}" in
  ''|-*) NUB="$HOME/nub/target/fast/nub" ;;
  *) NUB="$3" ;;
esac
AT_GRANT=""
# ⛔ `--at-catalog <file>` IS DIRECT MODE AGAINST A CATALOG NOBODY SYNTHESIZED HERE. `--at-grant`
# asks "does this install under exactly this grant?" and builds the one-package catalog ITSELF, so it
# can only ever test a catalog of this driver's own construction. The catalog nub actually SHIPS is
# `collate.mjs`'s output — version bands, `baseline`, `env`, an ABSENT package where the grant is
# empty, a hand-authored override where one exists — and none of that shape is reachable through
# `--at-grant`. This flag runs the identical arm against that FILE instead, so the collated catalog
# meets the same store eviction, memo drop, replay guard, override assertion and artifact gate as
# every measured arm. `e2e.mjs` is the caller.
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
# Absolute, resolved NOW: this script `cd`s into its own fixture roots, so a relative path handed in
# from the caller's cwd would later be read against a directory that did not exist when it was named.
[ -n "$AT_CATALOG" ] &&
  AT_CATALOG="$(cd "$(dirname "$AT_CATALOG")" && pwd)/$(basename "$AT_CATALOG")"
HERE="$(cd "$(dirname "$0")" && pwd)"
# One `rc:shortfall-digest:ok|abs` line per grant-widening arm, appended by `verify()`. Read once, at
# the foot of the ladder, to decide whether a shortfall responded to widening.
ARM_LEDGER=""

# ⛔ NOT UNDER /tmp. That path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all — it already produced one wrong all-clear.
ROOT="$(mktemp -d "$HOME/v2-XXXXXX")" || exit 1
# ⛔ THIS DOES NOT ISOLATE THE STORE, AND AN EARLIER COMMENT HERE CLAIMED IT DID. `NUB_CACHE_DIR`
# governs the RESOLVER PRIMER CACHE only; the global virtual store comes from a different function
# (see the long note in `verify()`). It is kept because a per-run primer cache is still worth
# having, but the thing that makes two arms independent is the per-arm STORE EVICTION below.
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)"

# ── 0a. THE CI-DETECTION SCRUB ─────────────────────────────────────────────────────────────────
# Shared with `measure-macos.sh`; `measure-windows.mjs` carries the same key list in JS and
# `ci-env-scrub.test.mjs` asserts all three agree. The full reasoning lives in the sourced file.
# shellcheck source=harness/v2/ci-env-scrub.sh
. "$HERE/ci-env-scrub.sh"

# ── 0. R7 — OBSERVE RUNS WITH FULL USER PERMISSIONS, AND ASSERTS IT ────────────────────────────
#
# ⛔ THIS IS FATAL, AND IT IS FATAL BECAUSE THE FAILURE IT PREVENTS IS INVISIBLE IN THE RECORD.
# If OBSERVE is LESS privileged than a real developer, a script that tries its primary path, is
# refused, and falls back gets measured ON THE FALLBACK. A real user with the permission takes the
# primary path and needs a capability we never saw — an UNDER-GRANT, the one direction this project
# forbids, and one that looks exactly like a clean measurement. A warning would be read past.
#
# ⛔ DO NOT CONFUSE THIS WITH THE TRACER'S PRIVILEGE. `strace` is measuring APPARATUS and may need
# whatever it needs; the traced PROCESS is the environment under test and runs as an ordinary user.
# On Linux the two coincide (ptracing your own child needs no privilege), so this checks the one
# identity that runs both.
#
# ⛔ THE CONVERSE ERROR IS NOT SAFE HERE, WHICH IS WHY ROOT IS REFUSED RATHER THAN TOLERATED. The
# spec calls extra privilege "the tolerable side" because it over-grants, and over-granting is safe
# — but root is not simply "more privileged". npm DE-ESCALATES to the owning uid when it runs as
# root, so the lifecycle script executes as a different user than the one measured, and root also
# bypasses the permission checks a real user hits, so a write that would be REFUSED for a developer
# silently succeeds. That is a behaviour change in both directions, not a superset.
assert_real_user() {
  local fail=0 probe
  if [ "$(id -u)" -eq 0 ]; then
    echo "⛔ R7: OBSERVE must not run as root — uid 0, user $(id -un)." >&2
    echo "   npm de-escalates to the owning uid under root, so the traced script runs as a" >&2
    echo "   different user than the one measured, and root bypasses refusals a developer hits." >&2
    fail=1
  fi
  # A restricted service account characteristically has no usable home. Every OBSERVE arm redirects
  # HOME into the fixture, but this is the REAL home the redirect is derived from, and `$ROOT` — the
  # whole run — is created inside it.
  if [ ! -d "$HOME" ] || [ ! -w "$HOME" ]; then
    echo "⛔ R7: the real HOME ($HOME) is missing or not writable — this is not an ordinary user." >&2
    fail=1
  fi
  # ⛔ EXECUTABILITY IS CHECKED, NOT ASSUMED, AND IT IS THE CHECK MOST LIKELY TO EARN ITS KEEP. A
  # `noexec` mount is the textbook R7 failure: it does not stop a script running, it makes a script
  # that downloads and runs a prebuilt binary fall back to BUILDING FROM SOURCE — which needs a
  # completely different capability set. Both the run root and the OS temp root are probed, because
  # node-gyp unpacks and executes out of the temp root while the fixture lives under the run root.
  for d in "$ROOT" "${TMPDIR:-/tmp}"; do
    probe="$d/.r7-exec-probe.$$"
    printf '#!/bin/sh\necho R7OK\n' > "$probe" 2>/dev/null
    chmod +x "$probe" 2>/dev/null
    if [ "$("$probe" 2>/dev/null)" != "R7OK" ]; then
      echo "⛔ R7: cannot create and execute a file under $d — a build that stages a binary there" >&2
      echo "   would fall back to compiling from source, and the fallback is what we would measure." >&2
      fail=1
    fi
    rm -f "$probe" 2>/dev/null
  done
  [ "$fail" -eq 0 ] || { echo "⛔ R7 FAILED — refusing to measure under reduced permissions." >&2; exit 3; }
}
assert_real_user
# ⛔ `VENUE-OBSERVE-USER` IS THE SHARED R7 MARKER AND LINUX USES IT RATHER THAN A SECOND SPELLING.
# `measure-windows.mjs` emits this name and `record.mjs` already parses it into `observeUser`; a
# Linux-only marker would have been parsed by nothing, so the assertion would have been invisible in
# a record on exactly the platform that measures most of the corpus. R7 is a claim about the run, so
# it belongs in the record and not only in this log — a reader can then CHECK the claim instead of
# trusting that the assertion existed in whatever driver revision ran.
#
# The capability bounding set and `NoNewPrivs` ride along RECORDED rather than asserted. Each is a
# signature of a restricted container, but neither changes what an unprivileged install script can
# do, so failing on them would manufacture false failures for no measurement benefit. Recording makes
# it an axis a reviewer can check (R6) instead of a silent assumption.
# (No apostrophes in this block: it lives inside a single-quoted `node -e` script.)
echo "  VENUE-OBSERVE-USER $(node -e '
  const fs = require("fs");
  let status = "";
  try { status = fs.readFileSync("/proc/self/status", "utf8"); } catch { status = ""; }
  const field = (k) => (new RegExp("^" + k + ":\\s*(\\S+)", "m").exec(status) || [])[1] ?? null;
  process.stdout.write(JSON.stringify({
    uid: process.getuid(), user: process.argv[1], umask: process.argv[2],
    capBnd: field("CapBnd"), noNewPrivs: field("NoNewPrivs"),
  }));
' "$(id -un)" "$(umask)" 2>/dev/null)"

# ⛔ WHICH BINARY, NOT WHICH COMMIT — `nubGitSha` PROVABLY CANNOT ANSWER THIS. Two binaries built
# from the SAME commit behave differently when their feature sets differ, and that is not
# hypothetical: MEASURED 2026-08-06, a `--release` build of the right commit missing only
# `build-jail-catalog-override` VOIDed four measurement cells, while provenance recorded a `nubGitSha`
# identical to the working binary's. A record has to be able to say what it was measured WITH.
#
# ⛔ ONE DETECTION FEEDS ALL THREE CONSUMERS — the R5 symmetry report, the override preflight, and
# this marker. They were briefly three separate greps of the same file, which is the shape that lets
# them drift into disagreeing about the same binary.
#
# The content hash is the identity that survives a shared mutable path. Lanes sharing
# `~/nub/target/<profile>/nub` can swap the artifact MID-BATCH — a preflight that passed twenty
# minutes ago proves nothing about the arm running now — so the hash is what lets a reader tell a
# batch measured against one binary from a batch measured against two.
NUB_HAS_OVERRIDE=false; NUB_HAS_BYTECODE_ENV=false
if [ -f "$NUB" ]; then
  # ⛔⛔ THE OVERRIDE CHECK IS BEHAVIOURAL, AND A STRING SEARCH FOR THE FEATURE NAME IS EXACTLY
  # INVERTED. Rust does not embed feature names in a binary. The literal
  # `build-jail-catalog-override` appears in ONE place: the error text a nub built WITHOUT the
  # feature prints when it refuses `NUB_BUILD_JAIL_CATALOG`. So the grep matches the BROKEN binary
  # and misses the WORKING one — MEASURED on both binaries side by side:
  #
  #   target/release/nub  (no feature)   grep=1   NUB_BUILD_JAIL_CATALOG=… --version -> rc=1 "Error: … not built with"
  #   target/fast/nub     (feature on)   grep=0   NUB_BUILD_JAIL_CATALOG=… --version -> rc=0 "catalog OVERRIDDEN from …"
  #
  # A grep-based preflight would therefore have refused every correct binary and admitted every
  # broken one — strictly worse than no check. This is the whole reason a capability is asked of the
  # ARTIFACT by exercising it, rather than inferred from something that merely correlates with it.
  NUB_PROBE_CAT="$(mktemp "${TMPDIR:-/tmp}/nub-probe-cat-XXXXXX.json")"
  printf '{"packages":{"__override_probe__":{"default":{"network":true}}}}' > "$NUB_PROBE_CAT"
  if NUB_BUILD_JAIL_CATALOG="$NUB_PROBE_CAT" "$NUB" --version >/dev/null 2>&1; then
    NUB_HAS_OVERRIDE=true
  fi
  rm -f "$NUB_PROBE_CAT"
  # The bytecode env name IS a genuine string constant (`BUILD_JAIL_BASELINE_ENV` in preset.rs), so a
  # content search answers this one honestly. Positively controlled against a binary carrying the
  # commit (match) and negatively against one predating it (no match).
  grep -qa PYTHONDONTWRITEBYTECODE "$NUB" 2>/dev/null && NUB_HAS_BYTECODE_ENV=true
  echo "  VENUE-NUB-BINARY $(node -e '
    const fs = require("fs"), crypto = require("crypto");
    let sha = null, bytes = null;
    try { const b = fs.readFileSync(process.argv[1]);
          sha = crypto.createHash("sha256").update(b).digest("hex"); bytes = b.length; } catch {}
    process.stdout.write(JSON.stringify({
      path: process.argv[1], sha256: sha, bytes,
      features: { buildJailCatalogOverride: process.argv[2] === "true",
                  pythonDontWriteBytecodeEnv: process.argv[3] === "true" },
    }));
  ' "$NUB" "$NUB_HAS_OVERRIDE" "$NUB_HAS_BYTECODE_ENV" 2>/dev/null)"
fi

# ⛔ R5 IS A SYMMETRY CLAIM, SO THE HALF THIS DRIVER DOES NOT CONTROL IS CHECKED RATHER THAN ASSUMED.
# The OBSERVE arm gets `PYTHONDONTWRITEBYTECODE=1` from the env block below; the VERIFY arm gets it
# from NUB, via `BUILD_JAIL_BASELINE_ENV` in `compiler/preset.rs`. A nub predating that commit
# silently breaks the symmetry — OBSERVE stops seeing bytecode writes while the jailed arm still
# attempts and is refused them.
#
# Reported, not fatal, and the direction is why: CPython falls back to compiling in memory, so the
# refusal cannot change an arm's outcome, and failing here would block every measurement whenever a
# nub build lags the harness.
if [ -f "$NUB" ] && [ "$NUB_HAS_BYTECODE_ENV" != true ]; then
  echo "  ⛔ R5 ASYMMETRY — $NUB does not carry PYTHONDONTWRITEBYTECODE; OBSERVE suppresses Python"
  echo "     bytecode and the jailed arm does not, so the two arms differ in more than enforcement"
fi
# ⛔ THE OVERRIDE FEATURE IS CHECKED BEFORE ANY WORK, NOT AFTER — AND `nubGitSha` CANNOT SUBSTITUTE.
# A nub built without `build-jail-catalog-override` refuses `NUB_BUILD_JAIL_CATALOG`, so every arm
# reports `OVERRIDDEN=0` and the run ends `⛔ VOID`. The verdict is honest and nothing is
# mis-recorded, but it costs a full OBSERVE plus a jail arm to discover, and a batch pointed at such
# a binary produces zero usable records while looking busy.
#
# MEASURED, 2026-08-06: a `--release` build of the RIGHT commit, missing only this feature, took four
# 2x2 cells to VOID. Two binaries from one commit behaved differently, so the commit sha in
# `provenance` could not have told them apart — which is why this keys on the ARTIFACT and why a
# feature list belongs beside `nubGitSha` in the record.
#
# ⛔ The detection above is BEHAVIOURAL for a reason recorded there: the first version of this
# preflight grepped the binary for the feature NAME and was exactly inverted, because that string
# lives only in the refusal message a FEATURELESS build prints.
#
# ⛔ Fatal, unlike the R5 check above, and the asymmetry is deliberate: an R5 mismatch cannot change
# an arm's outcome, whereas this one makes every arm meaningless.
if [ -f "$NUB" ] && [ "$NUB_HAS_OVERRIDE" != true ]; then
  echo "⛔ $NUB was not built with \`build-jail-catalog-override\`; every arm would report" >&2
  echo "   OVERRIDDEN=0 and the run would end VOID. Rebuild with:" >&2
  echo "   cargo build -p nub-cli --profile fast --features nub-cli/build-jail-catalog-override" >&2
  exit 3
fi

# ── 1. OBSERVE — unjailed, traced. This is the DISCOVERY step and it needs no jail at all. ─────
OBS="$ROOT/observe"; mkdir -p "$OBS"; cd "$OBS" || exit 1
printf '{"name":"o","version":"1.0.0"}\n' > package.json
# ⛔ THE FETCH IS NOT TRACED, AND THAT IS THE WHOLE POINT. Tracing `npm install` traces NPM —
# its registry TLS connections and its `~/.npm/_cacache` writes land in the same event stream as
# the lifecycle script's, so EVERY package synthesizes `network:true` + `write:userHome` no matter
# what its script does. MEASURED: that is over-prediction on 100% of packages and it makes the
# per-path question (can `writePaths` replace `write:"disk"`?) unanswerable. So: fetch and unpack
# with `--ignore-scripts` OUTSIDE the trace, then trace `npm rebuild`, which runs the lifecycle
# scripts and nothing else.
npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER" > "$OBS/fetch.log" 2>&1
FETCH_RC=$?
if [ "$FETCH_RC" -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed; nothing to measure)"; exit 0
fi
PRE_FILES=$(find "$OBS" -type f ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
# ⛔ TAKEN BEFORE THE TRACE, WHICH IS THE ONLY MOMENT IT EXISTS. The fetch above ran with
# `--ignore-scripts`, so the package dir right now is exactly what the tarball shipped. After the
# lifecycle script runs that state is unrecoverable, and it is what decides whether the artifact gate
# could ever have failed for this package.
#
# ⛔ THIS DRIVER RAN WITHOUT THE DETECTOR FOR THE WHOLE LIFE OF THE DESCENT, AND THAT WAS NOT A
# COSMETIC GAP. `record.mjs:301` gates the entire grant-source rule on seeing an `ARM-FALSIFIABILITY`
# line — absence is read as "the check never ran", which is correct and deliberate — and it is tested
# BEFORE the `n===1` and `jointVerified` branches. So a driver that never emits the line is pinned to
# `grantSource: "synthesized"` no matter what its descent measures. MEASURED: 0 of 45 committed
# linux-x64 records carry the line, against 3 of the darwin ones, and the Linux descent has therefore
# never narrowed a single record. macOS (`measure-macos.sh:219,403`) and Windows
# (`measure-windows.mjs:356,461`) have both called it since it landed.
node "$HERE/arm-falsifiability.mjs" --snapshot "$OBS" --pkg "$PKG" --ver "$VER" \
  --out "$OBS/pre-manifest.json" 2>/dev/null || true
# ⛔ OBSERVE WITH THE SAME `HOME` THE JAIL WILL GIVE THE SCRIPT, OR EVERY npm-CACHE WRITE IS BILLED
# AS A CAPABILITY THE PACKAGE DOES NOT NEED. The jail redirects `HOME`/`USERPROFILE` to a per-package
# private home (`preset.rs` `private_home_dir`, RW-granted by the base profile), so inside the jail
# `$HOME/.npm/_cacache/...` lands in already-granted space. Observing under the AMBIENT `$HOME` put
# those same writes under the real home and synthesized `write:{userHome}` — measured on
# `vanilla-cookieconsent@3.0.0-rc.9`, 51 of its 52 writes were npm's own cache.
#
# ⛔ THE REDIRECT IS THE POINT, AND A `$HOME`-PREFIX EXCLUSION WOULD NOT DO. Filtering the paths
# afterwards would silently swallow a script that hardcodes a real-home path — an UNDER-prediction,
# the one direction that breaks installs. Redirecting instead makes `jailHome` a MEASUREMENT of
# which writes actually follow `$HOME`: a hardcoded path still lands in `userHome` and still earns
# the grant.
JAIL_HOME="$ROOT/jailhome"; mkdir -p "$JAIL_HOME"
# ⛔ `HOME` IS ONE OF SEVERAL VARIABLES THE JAIL REWRITES, AND OBSERVING WITH ONLY THAT ONE MOVED
# MEASURES A RUN THAT NEVER HAPPENS. The governing rule for this arm is that OBSERVE and VERIFY may
# differ in EXACTLY ONE VARIABLE — enforcement — so every env rewrite `compile_build_jail` and
# `pm_engine/build_jail.rs` apply to the confined child is reproduced here. Each entry below names
# the nub-side line that puts it in the jailed child's environment; the entry and that line move
# together, and a divergence is not cosmetic — it changes WHICH PATHS the same script writes, which
# is the whole input to synthesis.
#
#   TMPDIR                  `backend/linux.rs::apply_landlock` sets it to the fresh per-run private
#                           dir it also grants rw. Without it here `os.tmpdir()` is the shared
#                           `/tmp`, which classifies `outside` and is billed to no scope at all —
#                           MEASURED on `playwright-chromium@0.17.0`, whose download staged through
#                           `/tmp/playwright-download-chromium-linux-764964.zip` and produced the
#                           driver's "1 writes OUTSIDE project/home" warning for that reason alone.
#                           ⛔ TMPDIR ONLY, deliberately: the Landlock arm sets that one name, while
#                           `insert_tmp_env`'s TMPDIR/TMP/TEMP triple is the BUBBLEWRAP arm's, and
#                           the build jail runs on Landlock. Setting all three here would observe an
#                           environment the shipped jail does not produce.
#   NODE_COMPAT=1           `build_jail.rs:140`, unconditional — a dependency's script runs on
#                           vanilla Node under the jail.
#   PYTHONDONTWRITEBYTECODE=1  `compiler/preset.rs`'s `BUILD_JAIL_BASELINE_ENV`, applied in
#                           `compile_build_jail` — the sole build_jail construction path, so every
#                           CONFINED script gets it and an unconfined one does not.
#                           ⛔ THIS IS PARITY, NOT NORMALISATION, AND THE DISTINCTION IS THE WHOLE
#                           RULE THIS DRIVER OBEYS. The harness may normalise its own APPARATUS and
#                           may not normalise the ENVIRONMENT UNDER TEST — but nub itself now sets
#                           this variable for the jailed child, so NOT setting it here would be the
#                           divergence: OBSERVE would trace a run that differs from the jailed run in
#                           two variables (enforcement AND bytecode) when the contract allows exactly
#                           one. See R5.
#   PLAYWRIGHT_BROWSERS_PATH `redirect_playwright_browsers`, unconditional for EVERY jailed spawn.
#   electron_config_cache / ELECTRON_CACHE   `redirect_electron_cache`, likewise.
#   npm_config_prefix        `redirect_npm_prefix`, likewise.
#
# ⛔ THE FOUR REDIRECT TARGETS DO NOT ALL LAND IN THE SAME PLACE, AND TREATING THEM ALIKE WOULD
# MANUFACTURE A GRANT. `$cache/nub/pm/tools` is granted READ-ONLY, but
# `grant_build_jail_dependency_reads` then `push_rw_path`s the single leaf
# `$cache/nub/pm/tools/npm-prefix` — because a prefix is a directory npm CREATES, and an unwritable
# one was measured refusing `iedriver@4.0.0` outright. So `ms-playwright` and `electron-cache` are
# refused writes that genuinely need `userHome`, while `npm-prefix` is free; the classifier is told
# about the leaf below so the free one is not billed.
#
# ⛔ THE REDIRECT TARGETS ARE NOT INSIDE THE JAIL'S WRITABLE SET, AND THAT IS THE POINT RATHER THAN
# A BUG TO ROUTE AROUND. All four point under `$cache/nub/pm/tools`, which `preset.rs`'s
# `NUB_PM_CACHE_PATTERNS` grants READ-ONLY (`grant_build_jail_dependency_reads` → `push_read_path`).
# On Linux `$cache` is `${XDG_CACHE_HOME:-$HOME/.cache}` — under the REAL user home — so a package
# that writes its cache there needs `write.userHome` and nothing narrower covers it. Observing
# without the redirect sent the same write to `$JAIL_HOME/.cache/...`, which the base profile already
# owns, so it was billed as FREE and the synthesized grant omitted the scope the jailed run then
# required. MEASURED on `playwright-chromium@0.17.0`: 650 of 651 writes landed under `jailHome`,
# synthesis emitted `{"network":true}`, and the jailed arm died on `mkdir … = -1 EACCES`.
#
# `$HOME` here is the REAL home — the redirect is applied to the CHILD's env only, exactly as nub
# does it: `sandbox_homes` reads nub's OWN `HOME`, not the one it hands the script.
JAIL_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
JAIL_TOOLS="$JAIL_CACHE/nub/pm/tools"
# ⛔ DERIVED ONCE, HERE, AND PASSED DOWN — never re-derived inside the classifier (PORTABILITY R2).
# The shell driver is apparatus and may read the environment; the classifier may not, because it is
# the thing that would silently produce a venue-specific answer. `store` is the embedder's
# `virtual_store_subdir` (`pm_engine/identity.rs`), joined onto aube's cache dir.
GLOBAL_STORE="$JAIL_CACHE/nub/pm/store"
# The interpreter INSTALL ROOT, not the binary: `<root>/bin/node` resolved through any symlink, then
# up two. This is the tree node-gyp's bundled `gyp/pylib` lives in, and whether it sits inside `$HOME`
# is exactly the venue difference that made the same package synthesize two different grants.
INTERPRETER="$(cd "$(dirname "$(dirname "$(readlink -f "$(command -v node)")")")" 2>/dev/null && pwd)"
# Under the OS temp root, matching `make_private_tmp`'s `tempfile` under `std::env::temp_dir()`, so
# the path SHAPE a script sees is the jail's too.
JAIL_TMP="$(mktemp -d "${TMPDIR:-/tmp}/nub-tmp-obsXXXXXX")" || exit 1
# `-f` is mandatory: the interesting syscall is routinely a grandchild of the postinstall.
HOME="$JAIL_HOME" TMPDIR="$JAIL_TMP" NODE_COMPAT=1 PYTHONDONTWRITEBYTECODE=1 \
  PLAYWRIGHT_BROWSERS_PATH="$JAIL_TOOLS/ms-playwright" \
  electron_config_cache="$JAIL_TOOLS/electron-cache" \
  ELECTRON_CACHE="$JAIL_TOOLS/electron-cache" \
  npm_config_prefix="$JAIL_TOOLS/npm-prefix" \
  strace -f -e trace=file,network,process -o "$OBS/trace.txt" \
  npm rebuild --no-audit --no-fund "$PKG" > "$OBS/npm.log" 2>&1
OBS_RC=$?
OBS_FILES=$(find "$OBS" -type f ! -name 'trace.txt' ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
echo "  OBSERVE   rc=$OBS_RC files=$OBS_FILES trace=$(wc -l < "$OBS/trace.txt" | tr -d ' ') lines"
if [ "$OBS_RC" -ne 0 ]; then
  # An unjailed failure means the package is broken HERE — a jailed result would be meaningless.
  # v1 calls this BROKEN-WITHOUT-JAIL-TOO and it is a real verdict, not an error.
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed; nothing to measure)"
  exit 0
fi

# The dependency closure npm actually installed to run this lifecycle script, read off the OBSERVE
# arm's own hoisted `node_modules`. Consumed by the per-arm store eviction in `verify()` — see the
# long note there for why evicting `$PKG` alone leaves a live replay path.
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
echo "  CLOSURE   $(printf '%s\n' $CLOSURE | grep -c . ) packages evicted per arm"

# ⛔ FLAG, NEVER FAIL — the package is still measurable; what a flag says is that a GREEN ARM CARRIES
# NO EVIDENCE for it. `|| true` is deliberate: a detector fault must never cost a record. Placed here,
# after the OBSERVE arm is known to have succeeded, because the post-manifest it diffs against only
# means anything once the lifecycle script has actually run.
node "$HERE/arm-falsifiability.mjs" --obs "$OBS" --pre "$OBS/pre-manifest.json" \
  --pkg "$PKG" --ver "$VER" 2>/dev/null | sed 's/^/  /' || true

# ── 1b. RETAIN THE RAW TRACE — THE ARTIFACT OF RECORD ──────────────────────────────────────────
#
# ⛔ THE RAW `strace` OUTPUT IS THE ARCHIVE. THE NORMALIZED STREAM AT 2b IS A DERIVED CACHE. Ported
# from `measure-macos.sh`, which had it first; the reasoning is the maintainer's and it corrects a
# mistake one layer out from retaining scope tags — a normalized event stream bakes in TODAY'S
# DECODER exactly as a scope tag bakes in today's classifier. Neither loss is hypothetical:
#
#   * this lane's decoder split 287 of 363 clone edges across `<unfinished ...>` and never matched
#     them, losing each child's inherited cwd and FABRICATING 70 paths no process touched.
#   * the macOS adapter lost 100% of rename DESTINATIONS, silently, for its entire existence.
#
# Both were decoder losses, so both are INVISIBLE in a derived view by construction. With the raw
# kept, that class of bug is a re-parse; without it, a re-measure — or a hole nobody can see. So if
# only one of the two files can survive, THIS is the one.
#
# ⛔ IT RUNS BEFORE SYNTHESIS, AND THAT ORDERING IS DELIBERATE AND DIFFERENT FROM 2b's. `gzip` and a
# metadata dump cannot feed anything back into a grant, so the "compute the verdict first" argument
# that governs 2b does not apply here — while the case where the archive is worth MOST is exactly
# the one where synthesis fails and `exit 1` runs, taking `$ROOT` with it. Retaining after synthesis
# would discard the trace precisely when it is needed.
#
# ⛔ A RAW TRACE WITHOUT ITS CAPTURE PARAMETERS IS WORTH FAR LESS THAN IT LOOKS. A trace with no
# `linkat` records means "linkat never fired" under one filter and "linkat was never SUBSCRIBED"
# under another, and nothing in the byte stream tells them apart. On Linux the subscription is the
# `-e trace=` class expression, whose MEMBERSHIP is defined by the strace build — so the filter and
# the strace version are recorded together, because neither answers the question alone.
CAPTURE="$OBS/capture.json"
node -e '
  const fs = require("fs"), crypto = require("crypto");
  const [trace, obs, home, jailHome, jailTmp, tools, pkg, ver, straceV, kern, distro, here,
         globalStore, interpreter] = process.argv.slice(1);
  const sha = (p) => { try { const b = fs.readFileSync(p); return { path: "harness/v2/" + p.slice(here.length + 1), sha256: crypto.createHash("sha256").update(b).digest("hex"), bytes: b.length }; } catch { return null; } };
  const st = (p) => { try { return fs.statSync(p).size; } catch { return null; } };
  const lines = () => { try { return fs.readFileSync(trace, "utf8").split("\n").length - 1; } catch { return null; } };
  console.log(JSON.stringify({
    v: 1,
    kind: "capture",
    platform: `linux-${process.arch}`,
    pkg, version: ver,
    tracer: "strace",
    // The exact invocation, verbatim. A paraphrase is the thing that goes stale.
    invocation: "strace -f -e trace=file,network,process -o trace.txt npm rebuild --no-audit --no-fund <pkg>",
    // ⛔ THE CLASS EXPRESSION *AND* THE VERSION. `file` is not a fixed list — which syscalls it
    // expands to is a property of the strace binary, so recording one without the other leaves
    // "was `linkat` subscribed?" unanswerable, which is the whole point of this file.
    subscribes: { traceFilter: "file,network,process", followForks: true, straceVersion: straceV },
    // Hashed by CONTENT, not by a version number someone must remember to bump. `observe.mjs`
    // produced the GRANT in this record; `adapters/linux.mjs` produced the derived view at 2b. A
    // re-parse needs to know which revision of each answered, and they move independently.
    decoders: { synthesizer: sha(`${here}/observe.mjs`), derived: sha(`${here}/adapters/linux.mjs`) },
    os: { kernel: kern, distro },
    // ⛔ EVERY PATH IN THE TRACE IS MACHINE-SPECIFIC. Without these a future classifier cannot tell
    // a project write from a home write and the archive is a pile of strings. These are exactly the
    // arguments `observe.mjs` and `adapters/linux.mjs` take, and they must stay in step with them.
    // ⛔ EVERY ROOT THE CLASSIFIER KEYS ON IS DECLARED HERE AND NOWHERE ELSE (PORTABILITY R1).
    // `observe.mjs` reads these and REFUSES TO RUN if one is missing, so this object is the single
    // definition of what a path means. An absent key is fatal there; `null` is a legitimate answer
    // meaning this platform has no such root. Never omit a key to express "not applicable".
    //
    // globalStore / projectStore / interpreter are declared but not yet keyed on (see the note in
    // observe.mjs). They are recorded NOW because a root that has to be re-derived later is a root
    // that gets re-derived from AMBIENT state, which is the exact failure R2 exists to prevent.
    roots: { project: obs, home, jailHome, temp: jailTmp, toolsDir: tools,
             npmPrefix: `${tools}/npm-prefix`, ownPkg: `${obs}/node_modules/${pkg}`,
             globalStore, projectStore: `${obs}/node_modules/.store`, interpreter },
    // ⛔ THE OBSERVE/VERIFY PARITY CONTRACT, RECORDED. These rewrites are what make the traced
    // run reproduce the environment the real jail creates; a script reading `os.tmpdir()` writes to
    // a DIFFERENT path without them. When that set changes, a trace taken under the old set is not
    // comparable to one taken under the new, and this is the only place that would say so.
    // `PYTHONDONTWRITEBYTECODE` joined the set when nub began setting it on every confined script
    // (`BUILD_JAIL_BASELINE_ENV`); a trace taken before that is not comparable to one taken after.
    observeEnv: { HOME: jailHome, TMPDIR: jailTmp, NODE_COMPAT: "1", PYTHONDONTWRITEBYTECODE: "1",
                  PLAYWRIGHT_BROWSERS_PATH: `${tools}/ms-playwright`,
                  ELECTRON_CACHE: `${tools}/electron-cache`,
                  electron_config_cache: `${tools}/electron-cache`,
                  npm_config_prefix: `${tools}/npm-prefix` },
    // ⛔ `rawLines` COUNTS NEWLINE-TERMINATED LINES while the decoder `stats.lines` counts the
    // split, so the two differ by exactly 1 on a well-formed trace. Both are correct under their
    // own names; noted here so the difference is not chased as a loss.
    // (No apostrophes in this block: it lives inside a single-quoted `node -e` script.)
    rawBytes: st(trace), rawLines: lines(),
    at: new Date().toISOString(),
  }, null, 2));
' "$OBS/trace.txt" "$OBS" "$HOME" "$JAIL_HOME" "$JAIL_TMP" "$JAIL_TOOLS" "$PKG" "$VER" \
  "$(strace -V 2>/dev/null | head -1)" "$(uname -a 2>/dev/null)" \
  "$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown)" "$HERE" \
  "$GLOBAL_STORE" "$INTERPRETER" \
  > "$CAPTURE" 2>/dev/null
gzip -9 -c "$OBS/trace.txt" > "$OBS/trace.txt.gz" 2>/dev/null
if [ -s "$OBS/trace.txt.gz" ] && [ -s "$CAPTURE" ]; then
  # `record.mjs` copies by PATH off these two stdout lines, and its handling is platform-agnostic —
  # printing them is the entire adoption cost of retention for a driver.
  echo "  RAWLOG-FILE $OBS/trace.txt.gz"
  echo "  RAWLOG-CAPTURE $CAPTURE"
  echo "  RAWLOG-BYTES raw=$(wc -c < "$OBS/trace.txt" | tr -d ' ') gz=$(wc -c < "$OBS/trace.txt.gz" | tr -d ' ')"
else
  # ⛔ NOT FATAL, BUT NEVER SILENT. Retention is additive to the measurement, so losing it must not
  # cost a measured package — but a record that carries a verdict and no evidence is the exact state
  # this machinery exists to end, and `record.mjs` turns this line into a `rawlog-missing` note.
  echo "  ⛔ RAW TRACE NOT RETAINED — the archive artifact is missing for this record"
fi

# ⛔ VENUE PROVENANCE IS EMITTED UNCONDITIONALLY, OUTSIDE THE RETENTION BLOCK ABOVE, AND THE NESTING
# IS NOT COSMETIC. These two markers describe the RUN — which interpreter it used, and what this
# driver did to the environment (PORTABILITY R3 + R6). The block above describes the ARCHIVE. They
# are independent facts, and coupling them meant a `gzip` failure or a zero-byte `capture.json`
# silently stripped `interpreterPath`, `interpreterInsideHome` and the WHOLE `overrides` object from
# a record whose measurement was otherwise perfect. A record that cannot say whether `CI` was touched
# is exactly the un-attributable record R6 exists to end — and it would have failed CLOSED-looking,
# with `overrides: null` reading as "nothing was overridden" rather than as "we lost the answer".
echo "  VENUE-INTERPRETER $INTERPRETER"
# ⛔ EVERY VARIABLE THIS DRIVER SET, UNSET OR REDIRECTED (PORTABILITY R6) — and `CI` is listed with
# its INHERITED value precisely because the one override that would invalidate the whole
# venue/CI acceptance test is touching it. Recording it unchanged is the claim a reader can check.
# ⛔ The harness normalises its own APPARATUS, never the environment under test: `CI`,
# `GITHUB_ACTIONS` and `NODE_ENV` are passed through verbatim, because an install script reads them
# and changes what it downloads or whether it builds from source. Flattening them would produce a
# catalog that under-grants every CI user.
echo "  VENUE-OVERRIDES $(node -e '
  const e = process.env;
  process.stdout.write(JSON.stringify({
    set: { HOME: process.argv[1], TMPDIR: process.argv[2], NODE_COMPAT: "1",
           PLAYWRIGHT_BROWSERS_PATH: process.argv[3] + "/ms-playwright",
           ELECTRON_CACHE: process.argv[3] + "/electron-cache",
           electron_config_cache: process.argv[3] + "/electron-cache",
           npm_config_prefix: process.argv[3] + "/npm-prefix",
           PYTHONDONTWRITEBYTECODE: "1",
           NUB_CACHE_DIR: process.argv[4] },
    // ⛔ THE CI-DETECTION SCRUB IS A NORMALISATION, SO IT IS DECLARED (R6). Normalisation that is
    // recorded is a covered axis; normalisation that is invisible is a silent bet it did not matter
    // — and this one changes which code a package runs, so it matters by construction.
    unset: process.argv[5] ? process.argv[5].trim().split(/\s+/) : [],
    // ⛔ WHAT THE VENUE ACTUALLY HAD, captured BEFORE the scrub. Reading `process.env` here would
    // report what this driver left behind and a real CI run would file `CI: null`, which is exactly
    // backwards: the record would claim the venue was not CI precisely because we removed the proof.
    passedThrough: Object.fromEntries([["CI", null], ["GITHUB_ACTIONS", null], ["NODE_ENV", e.NODE_ENV ?? null],
      ...process.argv[6].split("\n").filter(Boolean).map((kv) => {
        const i = kv.indexOf("="); return [kv.slice(0, i), kv.slice(i + 1)];
      })]),
  }));
' "$JAIL_HOME" "$JAIL_TMP" "$JAIL_TOOLS" "$NUB_CACHE_DIR" "$CI_SCRUBBED" "$CI_INHERITED" 2>/dev/null)"

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
# ⛔ ROOTS ARE NOT PASSED AS ARGUMENTS ANY MORE — the classifier takes them from `capture.json` and
# from nothing else (PORTABILITY R2). Two positional lists that had to stay in step were themselves a
# drift hazard: `measure.sh` and `capture.json` could disagree about what a path meant, and the
# capture is the artifact a re-parse actually has. One source, and 1b above already wrote it.
node "$HERE/observe.mjs" "$OBS/trace.txt" --capture "$CAPTURE" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }

# ── 2b. THE DERIVED EVENT LOG ──────────────────────────────────────────────────────────────────
#
# ⛔ DERIVED, AND REGENERABLE FROM `trace.txt.gz` AT 1b. This is the file anyone will actually query
# — greppable, one JSON object per event, paths already resolved — but it is a CACHE, not the
# archive. If it disagrees with the raw trace, the raw trace is right; a decoder bug rebuilds this
# file rather than re-measuring the package. That ordering is the whole reason 1b exists.
#
# ⛔ WHAT IS RETAINED IS THE RAW EVENT, NOT ITS CLASSIFICATION — the syscall, its arguments, its
# errno and the process identity, and no scope tag. A scope would bake in today's classifier and
# force a re-measure the moment the scope set changes, which is exactly what `tmp` is doing now.
#
# ⛔ IT RUNS AFTER SYNTHESIS AND FEEDS NOTHING BACK. `observe.mjs` above has already produced the
# grant; this is a second, INDEPENDENT decode whose output no arm reads. Retention must not be able
# to move a verdict, and the cheapest way to guarantee that is for the verdict to be computed first
# and by a different decoder. A failure here is deliberately non-fatal for the same reason. (1b is
# ordered the other way round, for the reason stated there.)
#
# ⛔ TWO PUBLISH PATHS, AND THIS HONOURS BOTH — the shape `measure-macos.sh` settled on. The batch
# runner sets `NUB_V2_EVENTS_OUT` to a path inside the record dir; the stdout marker is the only one
# that works when this driver is run STANDALONE, which is how every probe branch and every manual
# re-measure invokes it. Writing into `$OBS` first and copying makes the marker path the primary, so
# a standalone run retains as much as a batched one — previously it retained NOTHING.
EVENTS="$OBS/events.ndjson.gz"
node "$HERE/adapters/linux.mjs" "$OBS/trace.txt" \
  --project "$OBS" --home "$HOME" --jail-home "$JAIL_HOME" --jail-tmp "$JAIL_TMP" \
  --pkg "$PKG" --version "$VER" --out "$EVENTS" --stats-json "$OBS/eventlog-stats.json" 2>&1 | sed 's/^/  /'
if [ -s "$EVENTS" ]; then
  [ -n "${NUB_V2_EVENTS_OUT:-}" ] && cp "$EVENTS" "$NUB_V2_EVENTS_OUT" 2>/dev/null
  echo "  EVENTLOG-FILE $EVENTS"
  # ⛔ RE-SERIALISED BY A JSON PARSER, NOT FLATTENED WITH `tr -d '\n '`. The record contract needs
  # this on ONE line, but stripping every space also strips the ones INSIDE a string value — and
  # these stats carry a PATH. `record.mjs` would then note `eventlog-stats-unparsable` and the
  # evidence census would be silently absent from the record.
  [ -s "$OBS/eventlog-stats.json" ] && echo "  EVENTLOG-STATS $(node -e 'process.stdout.write(JSON.stringify(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))))' "$OBS/eventlog-stats.json" 2>/dev/null)"
else
  echo "  ⛔ EVENTLOG NOT WRITTEN — this record will carry a verdict and no queryable evidence"
fi

# ── 3. VERIFY — the real, UNPRIVILEGED jail. The only arm whose result may enter the catalog. ──
verify () {
  local grant="$1" label="$2" tracer="${3:-}"
  local v="$ROOT/verify-$label"; mkdir -p "$v/pkg"
  # A unique package name per arm: nub's side-effects cache memoises a lifecycle outcome keyed on
  # package identity, so a reused name REPLAYS the previous arm's result with every precondition
  # still green. Measured — the most dangerous failure shape here, because nothing looks wrong.
  local name="v$(basename "$v" | tr -dc 'a-z0-9')"
  printf '{"name":"%s","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$name" "$PKG" "$VER" > "$v/package.json"
  # ⛔ STATE THE JAIL EXPLICITLY RATHER THAN INHERITING A DEFAULT. A VERIFY arm that silently ran
  # UNCONFINED passes every time and reports the synthesized grant as sufficient — the single most
  # dangerous false green available here, because it inflates the agreement rate rather than
  # breaking anything. The catalog override engaging is NOT evidence the jail engaged.
  printf '{"install":{"buildJail":true}}\n' > "$v/nub.jsonc"
  # ⛔ THE THIRD REPLAY GUARD, AND IT IS NOT REDUNDANT WITH THE OTHER TWO — MEASURED, NOT ASSUMED.
  # v1 used this and the v2 drivers never inherited it (`harness/search.mjs`: "a warm cache replays a
  # prior build and the lifecycle script NEVER SPAWNS, which reads exactly like a jail denial").
  # The engine really reads it: `aube_settings::resolved::side_effects_cache`, consulted in
  # `vendor/aube/crates/aube/src/commands/rebuild.rs` and the `install/finalize.rs` path.
  #
  # THE THREE GUARDS CLOSE THREE DIFFERENT REPLAY PATHS, and dropping any one reopens its own:
  #   unique root name      — nub memoises a lifecycle outcome keyed on package identity
  #   side-effects-cache=no — the memo says "this script already ran, skip it"
  #   store eviction        — the store says "this package is already materialised, relink it"
  #
  # Tested directly on `@apollo/rover@0.2.1` with this line PRESENT in every arm and the only
  # variable being whether the transitive dependency's store entry was evicted:
  #
  #   evict binary-install=no    {"network":true}   rc=0   bin/ POPULATED  -> false PASS survives
  #   evict binary-install=yes   {"network":true}   rc=1   bin/ empty      -> correct FAIL
  #
  # So the config line does NOT subsume the eviction. Keep both.
  printf 'side-effects-cache=false\n' > "$v/.npmrc"
  # ⛔⛔ A UNIQUE NAME IS NOT ENOUGH, AND NEITHER IS DROPPING THE MEMO. THIS ARM EVICTS THE STORE.
  #
  # The memo keys on the DEPENDENCY's identity, which is identical across arms by construction, so
  # the unique ROOT name above does not separate them. Dropping `pm/side-effects-v1` was the fix for
  # that — and it is INSUFFICIENT, proven on the Windows driver, which carries both mitigations and
  # replayed anyway: three runs of the same binary and package gave rc=1 with a real refusal once,
  # then rc=0 twice, and diffing the install logs showed the later runs printed only
  # `materialized …` / `installed 1 package in 2.4s` where the first had downloaded 84 packages and
  # run the script. **The lifecycle script never executed.** The surviving replay source is the
  # GLOBAL VIRTUAL STORE — a package already materialized there is relinked, not reinstalled, so its
  # scripts do not run again.
  #
  # ⛔ AND EVERY PRECONDITION STAYED GREEN THROUGHOUT — override engaged, jail stated, unique name,
  # fixture outside temp. That is what makes this the most dangerous failure shape in the harness:
  # it does not break, it silently measures nothing.
  #
  # ⛔⛔ A PER-ARM `NUB_CACHE_DIR` DOES **NOT** CLOSE THIS, AND AN EARLIER REVISION OF THIS FILE
  # CLAIMED IT DID. That is worse than no fix, because it looks like protection. `NUB_CACHE_DIR`
  # governs the RESOLVER PRIMER CACHE only — `pm_engine/mod.rs` says so where it maps
  # `config_env("CACHE_DIR")`, and the store comes from a DIFFERENT function,
  # `aube_store::dirs::cache_dir()` joined with the embedder's `virtual_store_subdir`
  # (`vite_compat.rs:248`). MEASURED on Windows: with a fresh cache dir per arm, the arm's cache
  # ended the run with ZERO files while the old store still served the package.
  #
  # So evict the package from the STORE instead. The positive control that settles it: before
  # eviction the install log holds only `materialized …` (1.2s); after eviction it holds the
  # package's OWN script output — both binary downloads, the extractions, `Success!` (5.8s). The
  # script's stdout appears only in the evicted arm.
  #
  # ⛔ TARGETED, NOT `rm -rf` ON THE WHOLE STORE. The store is MACHINE-GLOBAL and a sibling agent
  # may be measuring on the same box; wiping it would silently corrupt their run. Match the
  # package's own entries only.
  #
  # Cost: each arm re-materializes this package from scratch. That is the price of independent arms.
  # Both, not either: the memo drop is NECESSARY and never SUFFICIENT, so keeping it costs nothing
  # and removing it would reintroduce a second replay path behind the one being fixed here.
  # ⛔ THIS LINE HAS NEVER REMOVED ANYTHING AND IS KEPT ONLY SO THE CLAIM DIES HERE RATHER THAN BEING
  # REDISCOVERED. `NUB_CACHE_DIR` does not relocate the side-effects cache — measured; the real purge
  # is the `SE-PURGE` below, at the XDG path with the cache's own `__` encoding. Harmless either way,
  # because `side-effects-cache=false` above is what actually closes this path.
  rm -rf "$NUB_CACHE_DIR/pm/side-effects-v1" 2>/dev/null
  # ⛔ THE SLUG MUST MATCH THE STORE'S OWN NAMING, AND THE FIRST REVISION OF THIS EVICTION DID NOT
  # — so it silently NO-OPPED FOR EVERY SCOPED PACKAGE, leaving open exactly the replay it was
  # added to close. The store names each directory `<name, with `/` as `+`>@<version>-<hash>`, e.g.
  # `@babel+core@7.29.7-ee0b878d8515d4c9`. `tr '/@' '--'` turned `@babel/core` into `-babel-core`,
  # which matches nothing. MEASURED on the Linux box against a populated 802-entry store: the old
  # pattern found 0 entries for `@babel/core` while that package was demonstrably present in it;
  # the pattern below found 1. Scoped packages are a large share of the corpus, so this was not an
  # edge case — and it fails silently, which is the shape this whole comment block exists to warn
  # about.
  #
  # Anchoring on `<slug>@` instead of wrapping in `*…*` also keeps the eviction TARGETED, as the
  # note above requires: the store is machine-global and a sibling agent may be measuring on the
  # same box, so a bare `*yorkie*` would take out an unrelated `yorkie-foo` alongside it.
  # ⛔⛔ AND EVICTING `$PKG` ALONE IS STILL NOT ENOUGH — THE REPLAY ALSO ARRIVES THROUGH A
  # TRANSITIVE DEPENDENCY'S STORE ENTRY, AND WHEN IT DOES IT MANUFACTURES A FALSE **OVER**-PREDICTION.
  #
  # MEASURED on `@apollo/rover@0.2.1`. Its postinstall writes into a SIBLING package's directory —
  # `node_modules/binary-install/bin/{rover,README.md,LICENSE}`, not its own — because it delegates to
  # the `binary-install` package. In the jail that path resolves through a SYMLINK out of rover's own
  # store entry into `binary-install@0.1.1-<hash>`'s entry, which `preset.rs`'s
  # `store_entry_write_root` deliberately does NOT grant (it grants the package's own entry root
  # only). So the write is genuinely refused and `write.deps` is genuinely NECESSARY.
  #
  # Evicting `@apollo+rover@*` alone left `binary-install@*` populated by the PREVIOUS arm, so the
  # descent arm relinked an already-built dependency, never attempted the write, and passed. Two arms
  # with the same binary, differing only in what was evicted:
  #
  #   evict rover only          {"network":true}                       rc=0   bin/ EMPTY  -> false PASS
  #   evict rover + binary-install  {"network":true}                   rc=1   bin/ absent -> correct FAIL
  #   evict rover + binary-install  {"write":{"deps":true},...}        rc=0   bin/ rover,README.md,LICENSE
  #
  # ⛔ THE DIRECTION MATTERS. A replay in the VERDICT arm inflates agreement; a replay in a DESCENT
  # arm reports a capability as droppable that is not — an UNDER-prediction, the one direction that
  # breaks installs. So the descent is only as honest as this eviction is complete.
  #
  # The closure comes from the OBSERVE arm's own hoisted `node_modules`, i.e. it is MEASURED rather
  # than guessed: exactly the packages npm needed to run this lifecycle script.
  #
  # ⛔ COST, weighed and accepted. The store is machine-global, so this reaches further than the
  # single-entry eviction it replaces and a sibling agent measuring a package that SHARES one of
  # these dependencies pays a re-materialization. That is strictly better than the alternative it
  # replaces, which was a silent false verdict. Still targeted — exact `<slug>@*` names from this
  # package's own closure, never a wildcard sweep of the store.
  #
  # ⛔⛔ AND THE STORE IS SHARED WITH nub'S OWN TOOLING, SO A NAME-WILDCARD EVICTION AMPUTATES THE
  # TOOL THE PACKAGE IS ABOUT TO BUILD WITH. nub bootstraps `node-gyp` lazily into its own project
  # under `<cache>/nub/pm/tools/node-gyp/<bucket>/`, and that project links against THE SAME global
  # store — measured, `node-gyp@12.4.0-<hash>/node_modules/semver -> ../../semver@7.8.5-<hash>/…`.
  # `semver`, `tar`, `which`, `graceful-fs` are ordinary members of a native package's own closure,
  # so evicting `<name>@*` deletes the entry nub's node-gyp resolves through and leaves a DANGLING
  # symlink behind it.
  #
  # MEASURED on `@pulumi/datadog@0.18.9` against the pre-fix harness: every rung of the ladder
  # failed, `=> NO-STATE-PASSED even at write:disk`, with `gyp ERR! stack Error: Cannot find module
  # 'semver'` in the arm logs — require stack rooted at
  # `<store>/node-gyp@12.4.0-6386ab3e4584a36d/node_modules/node-gyp/lib/process-release.js` — and
  # ZERO `= -1 EACCES/EPERM` in either arm. Not a jail refusal at all. The direction is the bad one
  # for the corpus but the SAFE one for users, which is what makes it hard to notice: a harness
  # failure reads as INSUFFICIENT, the ladder climbs, and the package lands WIDER than it needs.
  #
  # ⛔ nub's own fast path cannot self-heal from this. `node_gyp_bootstrap::ensure_cached` returns
  # early on `node_modules/.bin/node-gyp` merely EXISTING, and that shim is untouched by the
  # eviction — so nub reports the tool as ready on every subsequent arm while `require` is broken.
  # Repairing it takes deleting the whole tool dir (verified: `rm -rf <cache>/nub/pm/tools/node-gyp`
  # then `nub __node-gyp-bootstrap <dir>` restored all ten links).
  #
  # ⇒ SKIP THE ENTRIES nub'S OWN TOOL PROJECTS RESOLVE THROUGH. They are read off the tool projects'
  # virtual-store link dirs, which are FLAT and hold the tool's COMPLETE closure (20 entries for
  # node-gyp v12), so no graph walk is needed — but the dir's NAME is not stable (`.store` on the
  # binary that populated this box in the morning, `.nub` on the one that re-bootstrapped it an hour
  # later), so this resolves every symlink under `tools/` and keeps whatever lands in the store
  # rather than matching a name that would silently stop matching.
  #
  # ⛔ WHY SKIPPING CANNOT MANUFACTURE THE FALSE PASS THIS EVICTION EXISTS TO PREVENT. A protected
  # entry could mask a refusal only if it carried build output from a prior arm — and nub's tool
  # closure is pure-JS library code that never builds anything. MEASURED by reading the
  # `package.json` of all 20 entries the node-gyp v12 tool project resolves through (`semver`, `tar`,
  # `nopt`, `which`, `minipass`, …): ZERO declare `preinstall`, `install` or `postinstall`, so no arm
  # can write a build artifact into one. The overlap is narrow besides — an entry is protected only
  # at the exact `<name>@<version>-<hash>` nub's tooling pinned, so a package resolving any other
  # version of the same name is still evicted. On `@pulumi/datadog@0.18.9`, 2 of its 188 closure
  # names hit a protected entry and 193 entries were still removed.
  #
  # Rejected alternatives, both measured rather than reasoned about:
  #   per-arm store isolation — `XDG_CACHE_HOME` DOES relocate the store (unlike `NUB_CACHE_DIR`,
  #     see above), so it is available; it is refused because it re-downloads the whole closure per
  #     arm and re-bootstraps node-gyp from the registry inside every arm, turning a registry blip
  #     into the same false INSUFFICIENT this fix removes.
  #   re-bootstrap after eviction — works (the repair above is exactly it), but it pays a registry
  #     install per arm and the bootstrap failure path is a WARNING, not an error, so a flaky fetch
  #     would again land as a package-under-test failure.
  local store="${XDG_CACHE_HOME:-$HOME/.cache}/nub/pm/store"
  if [ -d "$store" ]; then
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
      // `<slug>@` anchoring, not `*<slug>*` — same targeting the note above records as measured.
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
      console.log(`  EVICT     ${removed} store entries removed, ${spared} spared as nub tooling`);
    ' "$store" "${XDG_CACHE_HOME:-$HOME/.cache}/nub/pm/tools" ||
      echo "  ⛔ EVICTION FAILED — this arm may REPLAY a prior arm's build and UNDER-report"
  fi
  # ⛔⛔ THE FOURTH REPLAY PATH, AND THE STORE EVICTION ABOVE CANNOT REACH IT. Two directories the
  # jail hands the script are PERSISTENT ACROSS ARMS by design and live OUTSIDE `pm/store`:
  #
  #   $cache/nub/jail-home/<pkg>-<hash>     `private_home_dir` — "PERSISTENT across runs, which is
  #                                         the one divergence from `$tmp`… re-installing the same
  #                                         package skips a ~250 MB Cypress re-download".
  #   $cache/nub/pm/tools/{ms-playwright,electron-cache}
  #                                         the redirect targets `redirect_playwright_browsers` and
  #                                         `redirect_electron_cache` stamp for every jailed spawn.
  #
  # A downloader that finds its artifact already there does not open a socket, so a LATER arm can
  # pass on a grant that would have failed cold. MEASURED on `playwright-chromium@0.17.0` (run
  # 31121368708, records at 8e0a868c): the synth arm at `{"write":{"userHome":true},"network":true}`
  # downloaded chromium into `tools/ms-playwright/chromium-764964`, and the `drop-network` descent
  # arm that followed exited 0 with all 6 artifacts — reported as
  # `⛔ OVER-PREDICTED: dropping 'network' STILL VERIFIES`. Its own OBSERVE arm had just recorded
  # 4 AF_INET sockets and a 142.250.73.91:443 peer, so the package plainly does fetch.
  #
  # ⛔ THE DIRECTION IS THE BAD ONE, which is why this is worth the re-download it costs. A replay in
  # a DESCENT arm reports a capability as droppable that is not — an UNDER-prediction, and this
  # harness may not take that direction. The same shape the `binary-install` note above records.
  #
  # ⛔ THE LEAVES, NEVER `tools` ITSELF. `tools` also holds the node-gyp nub bootstraps for itself and
  # links into the global store; wiping it strands the only node-gyp a confined native build can
  # reach, which is the exact failure the elaborate "spared as nub tooling" logic above exists to
  # prevent. Naming the two redirect leaves keeps this away from it entirely.
  local jailcache="${XDG_CACHE_HOME:-$HOME/.cache}/nub"
  rm -rf "$jailcache/pm/tools/ms-playwright" "$jailcache/pm/tools/electron-cache" 2>/dev/null
  # The private home is keyed on a hash of the package dir, which differs per arm root, so match the
  # readable basename prefix rather than trying to recompute nub's hash.
  rm -rf "$jailcache"/jail-home/"$(basename "$PKG")"-* 2>/dev/null
  # ⛔ REPAIRING A DEAD GUARD — NOT CLOSING A LIVE HOLE, AND THE DISTINCTION IS RECORDED BECAUSE THE
  # AUTHOR OF THIS LINE FIRST GOT IT WRONG IN THE ALARMING DIRECTION. The `rm -rf` above at the
  # `$NUB_CACHE_DIR` path has never removed anything: `side_effects_cache_root` is
  # `virtual_store_dir().parent()/side-effects-v1` (`install/side_effects_cache.rs:267`), a SIBLING of
  # `pm/store`, and `NUB_CACHE_DIR` does not relocate it. MEASURED under this driver's exact env — the
  # entry lands at `~/.cache/nub/pm/side-effects-v1/…` and NOTHING appears under `$ROOT/nubcache`.
  #
  # ⛔ THE PATH IS ALREADY CLOSED BY `side-effects-cache=false` IN EVERY ARM'S `.npmrc` (above), SO
  # THIS IS DEFENCE IN DEPTH AND NOTHING MORE. Measured both ways on the same package and box:
  #
  #   two installs sharing a cache, NO `.npmrc`     -> `saved` then `restored`   (a real replay)
  #   the same two installs WITH the arm's `.npmrc` -> no `saved`, no `restored`, no entry on disk
  #
  # The first configuration is not one this harness ever runs in. It is recorded because it is the
  # red half of the replay assertion below — the only way that check has ever been shown able to fire.
  #
  # Keeping the purge anyway costs one `rm` and removes the reader's need to trust that a setting is
  # honoured; deleting it would leave the surrounding comment describing a guard that is not there.
  # ⛔⛔ `__`, NOT `+`, AND NOT THE RAW NAME — A THIRD ENCODING, MEASURED RATHER THAN ASSUMED. The
  # store spells a scoped package `@scarf+scarf@1.4.0-<hash>`; the side-effects cache spells the SAME
  # package `@scarf__scarf@1.4.0`. The first version of this line reused the store's `+` (and a raw
  # `$PKG` fallback) and would have silently purged NOTHING for every scoped package — a no-op purge
  # that reads as a working guard, on the largest slice of the corpus. Caught by installing
  # `@scarf/scarf@1.4.0` and looking at the directory instead of trusting the sibling convention.
  #
  # ⛔ BY PACKAGE, NEVER THE WHOLE TREE. A blanket `rm -rf` of `side-effects-v1` would also close the
  # path, and would also destroy a concurrently-running lane's cache on a shared box.
  #
  # ⛔ AND THE PURGE IS COUNTED AND PRINTED, because a purge that silently no-ops when the path shape
  # changes is indistinguishable from a working one — which is the exact failure the `+` spelling
  # above would have shipped.
  #
  # ⛔ READ THE COUNT CORRECTLY: `SE-PURGE 0` IS THE HEALTHY STATE AND MEANS NOTHING WAS THERE TO
  # REMOVE. `side-effects-cache=false` stops any entry being written in the first place, so a
  # production arm should print 0 every time and a NON-ZERO count is the interesting one — it says an
  # entry existed, i.e. something wrote to this cache despite the setting. An earlier draft of this
  # comment had it exactly backwards and called 0 the tell, which would have trained a reader to
  # ignore the only value that carries information.
  local sedir="$jailcache/pm/side-effects-v1/$(printf '%s' "$PKG" | sed 's|/|__|g')"
  local sen=0
  for d in "$sedir"@*; do [ -e "$d" ] && { rm -rf "$d" 2>/dev/null; sen=$((sen + 1)); }; done
  echo "  SE-PURGE  $sen side-effects-cache entr$([ "$sen" -eq 1 ] && echo y || echo ies) for $PKG"
  # ⛔⛔ AN EMPTY GRANT CANNOT BE WRITTEN AS AN ENTRY, AND GETTING THIS WRONG SILENTLY DESTROYS THE
  # MODAL CASE. nub REJECTS a catalog entry that widens nothing — "`default` widens nothing and
  # there are no version bands, so the entry grants exactly the base profile; drop it" — and then
  # falls back to the COMPILED-IN catalog, so the arm trips the override assertion and comes back
  # VOID. VOID is not "insufficient", but the caller cannot tell the difference, so the driver
  # escalated up the ladder and reported a spuriously WIDE minimum.
  #
  # MEASURED, and this is the largest error the harness has produced: `yorkie@2.0.0` and
  # `@progress/kendo-licensing@1.9.1` both need NOTHING, and both were reported as
  # `MINIMUM {"write":{"deps":true,"project":true,"userHome":true},"network":true}`. With the
  # construction below they verify at `{}` on the first arm. Roughly half the corpus synthesizes
  # the empty grant, so unfixed this turns the modal case into a near-total grant.
  #
  # The fix follows from what the base profile already IS: nothing. So express the empty grant by
  # OMITTING the package under test, and carry a sentinel entry for an unrelated name purely so the
  # override still engages and the assertion below stays meaningful.
  #
  # ⛔ AND UNDER `--at-catalog` NONE OF THAT CONSTRUCTION APPLIES — THE FILE IS THE HYPOTHESIS. It is
  # copied VERBATIM, sentinel or no sentinel, because the question that mode asks is whether the
  # catalog AS COLLATED installs the package. Rewriting it here to be likelier to engage would answer
  # about a catalog nobody ships. A collated catalog that does not engage the override leaves the arm
  # VOID, and VOID saying so is the honest reading of "this file would not have worked".
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
  # `$tracer` is empty for a normal arm and `strace -f -o <file>` for the DIAGNOSE arm below. Kept
  # as a parameter rather than a second copy of this function so the preconditions above — unique
  # name, explicit `buildJail`, memo drop, override assertion — cannot drift between the arm that
  # decides the verdict and the arm that explains it.
  # ⛔ `RUST_LOG=debug` IS LOAD-BEARING, NOT VERBOSITY. `side-effects-cache: restored` is a
  # `tracing::debug!` (`install/side_effects_cache.rs:153`) and is the ONLY line that distinguishes a
  # built arm from a replayed one — see the long note below the arm for why every default-level
  # candidate was measured and rejected. Without this the replay assertion below is unfalsifiable.
  ( cd "$v"
    RUST_LOG=debug NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-i.txt} "$NUB" install > "$v/i.log" 2>&1
    RUST_LOG=debug NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-a.txt} "$NUB" approve-builds --all > "$v/a.log" 2>&1 )
  local rc=$?
  # ⛔ THE ARM MUST PROVE THE SCRIPT ACTUALLY RAN, because a replayed arm is indistinguishable from
  # a real one by rc and by every other precondition. A genuine first touch runs the lifecycle
  # script; a replay materializes from cache and never spawns it.
  #
  # ⛔⛔ THIS CHECK CRIED WOLF, WHICH IS WORSE THAN HAVING NO CHECK. It required
  # `installed [0-9]+ package` in `i.log`, and that was wrong on two counts:
  #
  #   1. THAT LINE IS ONE OF TWO SUMMARY SHAPES, NOT THE SUMMARY. nub prints
  #      `✓ installed N packages in Xs` in some runs and `✓ resolved N · reused N · downloaded N`
  #      in others (`vendor/aube/crates/aube/src/progress/`), so the predicate held or failed on
  #      which shape happened to appear rather than on whether anything ran. MEASURED: a 1-dep
  #      install printed `✓ installed 1 package in 6.5s`; a 70-dep install printed
  #      `✓ resolved 70 · reused 36 · downloaded 34 … in 2.8s` and false-fired.
  #      ⛔ An earlier revision of this comment claimed nub prints no such line at all. That was
  #      WRONG — a grep for the literal missed it because the string is assembled, not literal —
  #      and it is recorded here because a confidently false comment is worse than none.
  #   2. IT READ THE WRONG LOG. Lifecycle scripts run under `approve-builds`, whose output goes to
  #      `a.log`. `i.log` is the install step and cannot hold that evidence even in principle.
  #
  # ⛔⛔ AND THE REPLACEMENT WAS WRONG TOO, IN BOTH DIRECTIONS — MEASURED, NOT ARGUED. It required
  # `running build scripts for` somewhere in the arm's logs. That string comes from
  # `install/lifecycle.rs:580` and is emitted ONLY for a DEFAULT-TRUSTED package; everything else
  # takes `unreviewed_builds.rs:47` (`ignored build scripts for N package(s)`) and runs later under
  # `approve-builds`, which prints neither line. Both halves measured on the corpus VM:
  #
  #   es5-ext@0.10.64        cold, scripts approved and rebuilt   0 occurrences  -> FALSE FIRE
  #                          (`a.log` says `Approved 1 package(s) in package.json:`)
  #   msgpackr-extract@3.0.4 second install, genuinely RESTORED   1 occurrence   -> STAYED QUIET
  #
  # ⛔ AND THE CORPUS ALREADY HELD THE REFUTATION, WITH NO VM AND NO RE-RUN. `hugo-extended@0.141.0`
  # carries `REPLAY SUSPECTED` while its own descent arm reads
  # `VERIFY[drop-network] rc=1 artifacts=9/12 missing=3`. A REPLAYED ARM CANNOT FAIL FOR MISSING
  # ARTIFACTS — restored build output is present by definition. That script provably ran and provably
  # responded to the grant. 10 of 45 committed linux-x64 records carry the flag and their verdicts all
  # stand; the flag was noise. `Approved N package(s)` cannot discriminate either: it appears in the
  # replayed run too, and it evidences "was handed to rebuild", not "was built".
  #
  # ⇒ NO LINE IN THE DEFAULT OUTPUT DISTINGUISHES RAN FROM REPLAYED. The only line that does is the
  # cache's own, at debug level, which is why the arms above run under `RUST_LOG=debug`.
  #
  # ⛔ THIS IS AN ASSERTION ON AN EXISTING GUARD, NOT A DISCOVERY INSTRUMENT, AND THE DIFFERENCE IS
  # THE WHOLE POINT. Every arm writes `side-effects-cache=false` into its own `.npmrc`, so this line
  # SHOULD never appear. It fires only if that guard regresses — someone drops the `.npmrc` line, or
  # nub stops honouring the setting. That is a question with exactly one answer, which is why it can
  # be trusted where two predecessors that guessed at trust paths could not.
  #
  # ⛔⛔ AND ITS GREEN IS NARROW: it means "the side-effects cache did not restore", NOT "no replay
  # happened". The store-eviction, unique-root-name and persistent-leaf paths are covered by their own
  # evictions and are untouched by this check. Read it as one guard reporting on itself.
  #
  # Red-greened both ways against real runs of `msgpackr-extract@3.0.4` on the corpus VM: two installs
  # sharing a cache WITHOUT the arm's `.npmrc` produce `saved` then `restored` (RED); the same pair
  # WITH it produce neither, and write no cache entry at all (GREEN).
  if grep -qE 'side-effects-cache: restored' "$v"/*.log 2>/dev/null; then
    echo "     ⛔ REPLAY CONFIRMED — nub restored this package's build output from the side-effects"
    echo "        cache, so the script did NOT run in this arm and its result is not a measurement."
    # ⛔ SINGLE-QUOTED: backticks inside a double-quoted `echo` are COMMAND SUBSTITUTION, so the
    # obvious spelling of this sentence tries to run `side-effects-cache=false` as a command.
    echo '        side-effects-cache=false did not take effect for this arm; do not trust it.'
  fi
  # ⛔ A malformed override WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  # assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  local ovr rej files
  ovr=$(cat "$v"/*.log | grep -c 'catalog OVERRIDDEN'); rej=$(cat "$v"/*.log | grep -c 'REJECTED')
  # ⛔ `-L` IS LOAD-BEARING AND ITS ABSENCE INVERTS THE VERDICT. nub's global virtual store makes
  # every node_modules entry a SYMLINK, so a bare `find -type f` counts ~30 files where the npm
  # control counted 456 — and the `files >= OBS_FILES` gate below then fails an arm that installed
  # perfectly. MEASURED on @nuxt/components@2.1.0: the write:"disk" arm exited 0 with a complete
  # install and was reported as "NO-STATE-PASSED". Following the links counts the real artifacts.
  files=$(find -L "$v" -type f ! -name '*.log' ! -name 'cat.json' ! -path '*/nubcache/*' 2>/dev/null | wc -l | tr -d ' ')
  # ⛔ THE STORE LAYOUT IS OBSERVED FROM THE ARM TREE, NEVER INFERRED FROM `CI` (PORTABILITY R3).
  # Deriving it from the env var would encode the very rule this field exists to let us CHECK, and it
  # would then agree with itself forever. MEASURED, and this is why it matters: a `CI`-unset install
  # on the corpus VM still produced a `node_modules/.store`, so "CI implies isolated" is not a
  # biconditional. Emitted once, from the first arm that can actually SEE a layout.
  #
  # ⛔ THE LATCH IS SET INSIDE EACH EMITTING BRANCH, NEVER AFTER THE `if`, AND THE DIFFERENCE IS A
  # WHOLE PACKAGE'S FIELD. An arm with NO `node_modules` at all — a failed install, which is the
  # normal shape of the first rung of a descent ladder — matches neither branch and emits no marker.
  # With the latch outside, that arm still LATCHED, so every later arm was silenced and `record.mjs`
  # wrote `storeLayout: null` for the entire package even though every subsequent arm installed
  # perfectly and had the answer on disk. "Emitted once" has to mean once SUCCESSFULLY, not once
  # ATTEMPTED, because the thing being latched is the emission and not the visit.
  if [ -z "${STORE_LAYOUT_REPORTED:-}" ]; then
    if [ -d "$v/node_modules/.store" ]; then
      echo "  VENUE-STORE-LAYOUT isolated"; STORE_LAYOUT_REPORTED=1
    elif [ -d "$v/node_modules" ]; then
      echo "  VENUE-STORE-LAYOUT hoisted"; STORE_LAYOUT_REPORTED=1
    fi
  fi
  # ⛔⛔ `files >= OBS_FILES` IS NOT A SUCCESS GATE AND MUST NOT BE READ AS ONE. `find -L` follows the
  # isolated layout's symlinks into the machine-global store, so the number is dominated by the
  # dependency closure and is nearly insensitive to whether THIS package's script produced anything.
  # MEASURED on `@apollo/rover@0.2.1`: an arm that produced NONE of the package's three artifacts
  # counted 704 against a 718-file reference and passed. The direction of that error is the dangerous
  # one — on a DESCENT arm it reports a capability as droppable when it is necessary, and on the
  # SYNTH arm it would record an under-predicting grant as VERIFIED.
  #
  # The gate is the per-file ARTIFACT MANIFEST, ported from `measure-windows.mjs` so the two drivers
  # agree on what "the arm succeeded" means. See `artifact-gate.mjs` for why a count gate and a
  # byte-total gate were both measured and rejected, and for the sibling-package limit that the
  # transitive store eviction above covers instead. `files/OBS_FILES` stays PRINTED for continuity
  # with the existing corpus logs, but nothing branches on it any more.
  local gate grc
  gate=$(node "$HERE/artifact-gate.mjs" --obs "$OBS" --arm "$v" --pkg "$PKG" --ver "$VER" 2>&1); grc=$?
  echo "  VERIFY[$label] rc=$rc $(printf '%s' "$gate" | head -1) (tree $files/$OBS_FILES) OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  printf '%s\n' "$gate" | tail -n +2 | sed 's/^/     /'
  # ── Ledger for the grant-INDEPENDENCE test at the foot of the ladder. See the ARTIFACT-GATE-SUSPECT
  # block there for what it decides. Only the arms that actually WIDEN the grant are recorded: the
  # `diag` arm is the SAME grant re-run under strace, so counting it would let a repeated point pose as
  # corroboration, and `at-grant` belongs to DIRECT mode, which never reaches the ladder.
  case "$label" in
    diag|at-grant|at-catalog) ;;
    *)
      local sig; sig=$(printf '%s' "$gate" | head -1 | sed -n 's/.*shortfall=\([A-Za-z0-9]*\).*/\1/p')
      # `?` for a gate line with no digest at all (an OBSERVE-less rc=3 arm, or a gate that failed to
      # run). It can never equal another arm's digest, so an unreadable arm can only ever REFUSE the
      # invariance claim — never silently support it.
      local nmiss; nmiss=$(printf '%s' "$gate" | head -1 | sed -n 's/.*missing=\([0-9]*\).*/\1/p')
      ARM_LEDGER="$ARM_LEDGER$rc:${sig:-?}:$(printf '%s' "$gate" | grep -qE 'artifacts=ABSENT|package absent' && echo abs || echo ok):${nmiss:-?}
"
      ;;
  esac
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

# ⛔⛔ THE VERDICT ARM'S VOID CASE MUST ABORT, NOT LADDER. Same three-outcome rule as the descent
# below, and here the cost of collapsing them is the whole record: a VOID synth arm measured the
# COMPILED-IN catalog, so falling through to the ladder walks upward from a hypothesis that was
# never tested and publishes whichever rung happens to pass as this package's MINIMUM. That is the
# exact shape of the largest error this harness has produced (the empty-grant bug), and the
# construction that fixed that one does not stop a VOID arriving by some other route — a malformed
# grant, a binary built without the override feature, a crash before the log line.
# ── DIRECT MODE: one arm at the caller's grant, no synthesis, no ladder. ──────────────────────
#
# ⛔ THE VERDICT VOCABULARY IS DELIBERATELY DIFFERENT FROM THE LADDER'S, because the question is.
# The ladder reports a MINIMUM; this reports whether ONE stated grant SUFFICES. Conflating them is
# how a wider-than-expected minimum gets read as an under-grant — the exact confusion this mode
# exists to prevent. VOID stays VOID: an arm whose override did not engage measured nothing, and
# must never be reported as either outcome.
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

verify "$GRANT" "synth"; SRC=$?
if [ "$SRC" -eq 2 ]; then
  echo "  => ⛔ VOID — the override did not engage on the verdict arm; NOTHING was measured."
  echo "     Not a result. Do NOT record it, and do NOT read the absence of a verdict as a wide grant."
  exit 3
fi
# ── 3a. DESCEND — is a verified grant actually MINIMAL, or did OBSERVE over-predict? ──────────
#
# ⛔⛔ A FUNCTION, AND CALLED FROM THE LADDER PATH TOO — THAT IS WHY IT IS ONE. This block used to sit
# inline under `if [ "$SRC" -eq 0 ]`, so it could only ever narrow a SYNTHESIZED grant, and the ladder
# at step 4 published whichever rung passed exactly as it stood. A rung is a BUNDLE by construction —
# rung 0 alone grants `deps` + `project` + `userHome`, and `userHome` is the PERSISTENCE capability —
# so publishing one un-narrowed hands out three capabilities because ONE arm passed. The descent can
# only ever narrow to something that still verifies in the real jail, so it cannot under-grant. Same
# repair Windows took in `0f1aeecf2` and macOS in `89599dd9b`; Linux was the last driver whose ladder
# published without descending.
#
# ⛔ `$1` IS THE GRANT TO DESCEND FROM, NOT `$GRANT`. On the ladder path the two DIFFER — `$GRANT` is
# the synthesized value that FAILED — and reading the global here would narrow against a hypothesis no
# arm ever verified. The provenance argument only changes the WORDING of the messages naming the grant
# being kept; calling a rung "synthesized" in a log someone is using to audit a `write.userHome` entry
# would misdescribe where that grant came from.
descend () {
  local g0="$1" provenance="$2"
  # ⛔ `ARM_LEDGER` AND `STORE_LAYOUT_REPORTED` ARE DELIBERATELY ABSENT FROM THIS LIST. `verify`
  # appends to both, and bash `local` is DYNAMICALLY scoped — declaring them here would make every
  # descent arm's ledger entry and the venue's store layout vanish the moment this function returned.
  local kept CAPS NARROWER INCONCLUSIVE cap SUB drc DROPPED_N JOINT jrc
  case "$provenance" in ladder) kept="ladder-rung" ;; *) kept="synthesized" ;; esac
  # ⛔ THIS IS THE ONLY HONEST OVER-PREDICTION MEASUREMENT AVAILABLE, AND IT NEEDS NO ORACLE.
  # Comparing a synthesized grant against a v1 corpus record does not answer the question. A v1
  # record is the output of a blind pass/fail ladder that can only ever report "this grant was
  # insufficient" — never WHAT was missing — and it carries every harness and nub defect live at
  # the moment it was taken. At least one record is already known stale (`iedriver@4.0.0` records
  # `write:"disk"` and installs today under a narrow grant). So a disagreement with the record is
  # not evidence against v2; it is not evidence about v2 at all.
  #
  # What IS evidence: drop one capability from the VERIFIED grant and re-verify in the same real
  # jail. If a strictly narrower grant also passes, OBSERVE over-predicted by exactly that
  # capability — measured, not inferred. One leave-one-out level is enough to detect and size
  # over-prediction, and it is deliberately NOT a lattice search: the point is to characterise the
  # synthesis, not to re-derive a minimum by searching, which is precisely what v1 did.
  #
  # ⛔ EACH DESCENT ARM IS A FULL `verify` CALL, so it inherits the store eviction, the unique root
  # name, the explicit `buildJail`, and the override assertion. An arm run any cheaper than the
  # verdict arm would not be comparable to the verdict arm.
  # ⛔⛔ THE NAMES ARE A CONTRACT WITH `record.mjs`, NOT LABELS FOR A HUMAN — AND THIS DRIVER SPELLED
  # THEM WRONG FOR THE WHOLE LIFE OF THE DESCENT. `applyGrantSourceRule` recomputes the descended
  # grant by matching the literal `no-network` / `no-write-<scope>` out of `overPredictedBy`. Linux
  # emitted the bare `network` / `write.deps`, which match neither, so the recomputation deleted
  # NOTHING: `descendedGrant` came back identical to the synthesized grant and a record published
  # `grantSource: "descended"` beside an un-narrowed value. MEASURED against the committed logs —
  # all five Linux records carrying an over-prediction re-parse with `descendedGrant === grant`.
  # macOS and Windows already use the `no-*` spelling; Linux was the odd one out.
  #
  # ⛔ `read` IS ENUMERATED, AND ONLY BECAUSE `record.mjs` LEARNED THE NAME FIRST. `classify.mjs` never
  # synthesizes a `read` key, but LADDER RUNG 1 carries `read:"disk"` literally and this function is
  # called from the ladder path, so the key is reachable. It was skipped for as long as
  # `applyGrantSourceRule` had no `no-read` case: a droppable `read` landed in `unparsedNames`, which
  # forced the WHOLE record back to the wide grant and threw away the network and write narrowings that
  # DID parse — a strictly worse record than not enumerating it. `366936ce3` added that case, so the
  # drop now recomputes, and `measure-macos.sh` gained this in the same change so the two POSIX drivers
  # cannot diverge. What it buys is not symmetry: `read:"disk"` is the grant under which a project's
  # `.env` files are readable, and before this every rung-1 record kept it granted and unquestioned.
  #
  # ⛔ `write:"disk"` IS STILL NOT DESCENDED, AND IT IS NOT THE SAME CASE. `write` reaches this
  # generator as a MAP of scopes, so `Object.keys` over the string form would fabricate four
  # `no-write-<digit>` arms the recorder cannot parse; the ladder refuses the top rung outright for
  # that reason ("no droppable terms, so no descent", below). `read` is a SCOPE rather than a map of
  # scopes, so the whole key drops under ONE name — there is deliberately no `no-read-<scope>` spelling
  # mirroring `no-write-<scope>`, because a second vocabulary is what the recorder's unparsed-name
  # guard exists to prevent.
  CAPS=$(node -e '
    const g = JSON.parse(process.argv[1]); const out = [];
    if (g.network) out.push("no-network");
    for (const k of Object.keys(g.write ?? {})) out.push("no-write-" + k);
    if (g.read) out.push("no-read");
    console.log(out.join(" "));
  ' "$g0")
  if [ -z "$CAPS" ]; then
    echo "  DESCEND   grant is already empty — nothing to narrow; MINIMAL by construction."
  else
    # ⛔⛔ `verify` HAS THREE OUTCOMES AND THIS LOOP MUST NOT COLLAPSE THEM TO TWO. rc 0 = the narrower
    # grant passed, rc 1 = it was genuinely insufficient, rc 2 = the arm was VOID (the override did
    # not engage, so nub silently ran the COMPILED-IN catalog and nothing about `$SUB` was measured).
    # An `if verify …; else NECESSARY; fi` reads VOID as necessity — it manufactures evidence that a
    # capability is needed out of an arm that measured nothing, and it does so in the direction that
    # HIDES over-prediction, which is the direction we are least able to detect by other means.
    #
    # MEASURED, and it fired on the control package: `wordpos@2.1.0`'s `drop-writedeps` arm came back
    # `REJECTED=2` / VOID and the driver printed `'write.deps' is NECESSARY` anyway, so that package's
    # `MINIMAL` verdict was never earned. Reported rather than fatal — the other capabilities' arms
    # are still valid, so the run yields a partial answer instead of none.
    NARROWER=""; INCONCLUSIVE=""
    for cap in $CAPS; do
      SUB=$(node -e '
        const [g0, cap] = process.argv.slice(1); const g = JSON.parse(g0);
        if (cap === "no-network") delete g.network;
        else if (cap === "no-read") delete g.read;
        else { const k = /^no-write-(.+)$/.exec(cap)[1]; delete g.write[k];
               if (!Object.keys(g.write).length) delete g.write; }
        console.log(JSON.stringify(g));
      ' "$g0" "$cap")
      verify "$SUB" "drop-$(printf '%s' "$cap" | tr -d '.')"; drc=$?
      case "$drc" in
        0) echo "     ⛔ OVER-PREDICTED: dropping '$cap' STILL VERIFIES — $SUB is sufficient"
           NARROWER="$NARROWER $cap" ;;
        2) echo "     ⛔ INCONCLUSIVE for '$cap' — the arm was VOID, so nothing was measured; NOT evidence of necessity"
           INCONCLUSIVE="$INCONCLUSIVE $cap" ;;
        *) echo "     '$cap' is NECESSARY — dropping it fails to verify" ;;
      esac
    done
    if [ -n "$NARROWER" ]; then
      echo "  => OVER-PREDICTED by:$NARROWER  ($kept $g0; each named capability drops on its own)"
    elif [ -n "$INCONCLUSIVE" ]; then
      echo "  => DESCENT INCOMPLETE — no capability dropped, but$INCONCLUSIVE was never measured; MINIMALITY IS UNPROVEN"
    else
      echo "  => MINIMAL — every capability in $g0 is independently necessary"
    fi

    # ⛔ THE JOINT ARM. The descent is LEAVE-ONE-OUT, so N droppable capabilities give N arms proving
    # each drops ON ITS OWN and nothing proving they drop TOGETHER. The joint grant is strictly
    # narrower than any arm that ran, so publishing it off the individual results would be an
    # inference dressed as a measurement — in the UNDER-grant direction, the one that breaks installs.
    # One extra arm converts it into a real one, and only when there is something to convert: N<2
    # needs no joint arm because the single leave-one-out arm IS the joint case. `record.mjs` keeps
    # the wider synthesized value for N>=2 unless it sees `JOINT-NARROW VERIFIED`.
    #
    # ⛔ THREE OUTCOMES, NOT TWO — the same rule the loop above is built around. A VOID arm (rc 2: the
    # override did not engage, so nothing was measured) read as a genuine joint FAILURE is merely
    # conservative — the wide grant is kept either way — but it files a measurement that never happened
    # as evidence that the capabilities do not drop together. `INCONCLUSIVE` is the honest label.
    # macOS spelled this `if verify …; then VERIFIED; else FAILED; fi` and now carries the same `case`;
    # Windows distinguishes VOID from TIMED-OUT in its own equivalent. All three branch three ways.
    DROPPED_N=$(printf '%s\n' $NARROWER | grep -c . || true)
    if [ "${DROPPED_N:-0}" -ge 2 ]; then
      JOINT=$(node -e '
        const g = JSON.parse(process.argv[1]);
        for (const n of process.argv[2].split(/\s+/).filter(Boolean)) {
          if (n === "no-network") { delete g.network; continue; }
          if (n === "no-read") { delete g.read; continue; }
          const w = /^no-write-(.+)$/.exec(n);
          if (w && g.write) { delete g.write[w[1]]; if (!Object.keys(g.write).length) delete g.write; }
        }
        console.log(JSON.stringify(g));
      ' "$g0" "$NARROWER")
      verify "$JOINT" "joint-narrow"; jrc=$?
      case "$jrc" in
        0) echo "  => JOINT-NARROW VERIFIED $JOINT — all $DROPPED_N capabilities drop TOGETHER, measured" ;;
        2) echo "  => JOINT-NARROW INCONCLUSIVE — the arm was VOID, so the joint drop is unmeasured;"
           echo "     the record keeps the wider $kept grant, which is the honest answer" ;;
        *) echo "  => JOINT-NARROW FAILED $JOINT — each capability drops alone but not together;"
           echo "     the record keeps the wider $kept grant, which is the honest answer" ;;
      esac
    fi
  fi
}

if [ "$SRC" -eq 0 ]; then
  echo "  => VERIFIED $GRANT   (observed, then verified)"
  descend "$GRANT" synth
  exit 0
fi

# ── 3b. DIAGNOSE — re-run the SAME failing grant JAILED, under strace, and name the refusal. ───
#
# ⛔ THIS EXISTS BECAUSE OBSERVING AN UNJAILED RUN STRUCTURALLY CANNOT PREDICT EVERY REFUSAL.
# Step 1 enumerates what the script TOUCHED; it cannot enumerate what confinement will later REFUSE
# on an axis the tracer does not cover, and it cannot see a path the script only reaches once some
# earlier read succeeds. So an under-prediction is expected, and "the synthesized grant did not
# verify" is worth nothing on its own — the ladder that follows says a WIDER grant worked, never
# WHICH capability was missing.
#
# Every Linux `write:"disk"` package resolved so far was closed by exactly this arm, run BY HAND:
# `dotnet-2.0.0@1.4.4`, `@nuxt/components@2.1.0`, `@tensorflow/tfjs-backend-wasm`, `codeceptjs`,
# `postman-code-generators`, `react-native-purchases` — all six turned out to be ONE refused read
# (`/proc/self/stat`, via yarn v1's `initPeakMemoryCounter` -> `process.memoryUsage()` -> libuv's
# `uv_resident_set_memory`). Doing it by hand six times is what this automates.
#
# ⛔ THE GREP IS `= -1 EACCES`, NOT `EACCES`. A bare grep matches the `AT_EACCESS` FLAG NAME in
# every `faccessat2(...)` line — measured, that read 26/13/1 where the truth was 11/0/0.
#
# ⛔⛔ THE OUTPUT IS A LEAD AND THE "LAST REFUSAL" LINE HAS ALREADY BEEN WRONG ONCE — READ THIS
# BEFORE ACTING ON IT. On `@opencode-ai/cli@0.0.0-next-16573` the last refusal before `tgkill(SIGABRT)`
# really was `/proc/self/cgroup`, confirmed by strace. It was a TRAILING RED HERRING: a
# single-variable arm granting `/proc/self/cgroup` ALONE still aborts, while granting
# `/proc/self/maps` alone exits 0 (3/3 runs), and a negative control granting cgroup +
# mmap_min_addr + version_signature together still aborts — so `maps` is necessary and cgroup is
# merely the last thing tried before death.
#
# ⇒ TREAT THE LIST AS A CANDIDATE SET AND SETTLE IT WITH A SINGLE-VARIABLE ARM PER PATH. Grant one,
# re-run, repeat; then a negative control granting all the OTHERS to prove the survivor is
# necessary and not merely sufficient. The full refusal census above is the more honest output of
# the two, which is why it prints first and unabridged.
diagnose () {
  command -v strace > /dev/null 2>&1 || { echo "  DIAGNOSE skipped (no strace)"; return 0; }
  local d="$ROOT/diag"; mkdir -p "$d"
  verify "$GRANT" "diag" "strace -f -o $d/tr" > /dev/null 2>&1
  local refusals
  refusals=$(cat "$d"/tr-*.txt 2>/dev/null | grep -oE '"[^"]+"\)?[^=]*= -1 (EACCES|EPERM|EROFS)' \
    | grep -oE '^"[^"]+"' | sort | uniq -c | sort -rn)
  if [ -z "$refusals" ]; then
    echo "  DIAGNOSE  ZERO filesystem refusals under the failing grant."
    echo "     ⇒ the missing capability is NOT a path this tracer covers — look at the network axis,"
    echo "       or a resource class strace's file+network filter does not carry."
    return 0
  fi
  echo "  DIAGNOSE  refused paths under the failing grant (count, path):"
  echo "$refusals" | head -12 | sed 's/^/     /'
  # The last refusal before a process exits non-zero is the strongest single lead available.
  local fatal
  fatal=$(cat "$d"/tr-*.txt 2>/dev/null | grep -E '= -1 (EACCES|EPERM|EROFS)|\+\+\+ exited with [1-9]' \
    | grep -B1 'exited with [1-9]' | grep -E '= -1 ' | tail -1)
  [ -n "$fatal" ] && echo "     LAST REFUSAL BEFORE A NON-ZERO EXIT (a lead, not proof):" \
    && echo "       $fatal" | cut -c1-200
}
diagnose

# ── 4. FALL BACK — the ladder, retained, but walked UPWARD FROM the synthesized grant. ─────────
# This is the ladder's real job: repairing a hypothesis, over a handful of states rather than 55.
#
# ⛔⛔ AND THE RUNG IT LANDS ON IS THEN DESCENDED, WHICH IT WAS NOT FOR THE WHOLE LIFE OF THIS LADDER.
# Every rung is a BUNDLE — rung 0 alone grants `deps` + `project` + `userHome` + `network`, and
# `userHome` is the PERSISTENCE capability, write access to `~/.ssh` and every shell profile — so
# publishing the first passing rung verbatim hands out four capabilities on the strength of ONE arm.
# That is a far wider catalog entry than the package earned, and the record said `verifiedBy: ladder`
# beside it with no `minimality` at all, so nothing downstream could tell the difference.
#
# The descent below can only ever narrow to a grant that STILL VERIFIES in the same real jail, so it
# cannot under-grant — which is what makes widening-then-narrowing the right repair rather than a
# trade. Windows took this repair in `0f1aeecf2` and macOS in `89599dd9b`; this was the last driver
# whose ladder published un-narrowed.
echo "  synthesized grant did not verify — falling back to a bounded ladder"
for g in \
  '{"write":{"deps":true,"project":true,"userHome":true},"network":true}' \
  '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}' \
  '{"write":"disk","network":true}'
do
  verify "$g" "fb$(echo "$g" | cksum | cut -d' ' -f1)"; frc=$?
  # A VOID rung is not a failed rung. Collapsing them makes the ladder CLIMB PAST a grant it never
  # tested and publish the next one as the minimum — over-granting on the strength of no measurement.
  [ "$frc" -eq 2 ] && { echo "     ⛔ VOID rung — override did not engage; the ladder cannot continue honestly"; exit 3; }
  if [ "$frc" -eq 0 ]; then
    echo "  => MINIMUM $g   (ladder fallback; synthesized grant was insufficient)"
    echo "  ⛔ OBSERVE UNDER-PREDICTED — the gap between $GRANT and $g is worth reading"
    # ⛔ NOT DESCENDED FROM `write:"disk"`, AND THE GUARD IS THE RUNG'S SHAPE, NOT ITS POSITION.
    # `write` is a STRING on that rung, and the variant generator above does `Object.keys(g.write)` —
    # which on `"disk"` yields `["0","1","2","3"]` and would manufacture four `no-write-<digit>` arms.
    # `record.mjs` can parse none of them, so they land in `unparsedNames` and the record carries
    # `descent-name-unparsed` off a measurement of four states that mean nothing. It is also the
    # ABSENCE of confinement rather than a path grant with droppable terms, so a leave-one-out over it
    # has nothing to leave out.
    case "$g" in
      *'"write":"disk"'*) echo "  !! top rung is write:\"disk\" — no droppable terms, so no descent" ;;
      *) descend "$g" ladder ;;
    esac
    exit 0
  fi
done
# ── 5. BEFORE DECLARING NOTHING PASSED: DID THE SHORTFALL EVER RESPOND TO THE GRANT? ───────────
#
# ⛔ A SHORTFALL INVARIANT UNDER WIDENING IS NOT A CAPABILITY GAP, and everything above this line
# assumes the opposite. The top rung is `{"write":"disk","network":true}` and the rung below it adds
# `"read":"disk"`, so every axis this harness models reaches its maximum somewhere in the ladder; a
# shortfall unchanged across all of them cannot be caused by a denied write, read or socket. But the
# ladder reads one boolean per rung, so four arms that each exited 0 and each fell
# short by the SAME files are indistinguishable from four arms that failed for four different reasons.
# Both land here and the record is discarded. MEASURED on the 45 linux-x64 records in this repo: that
# is 3 of 45, and one of them (`windows-foreground-love@0.6.1`) had a CORRECT narrow grant in hand —
# its `{"write":{"project":true},"network":true}` arm exited 0 with all 18 artifacts present and 3
# node-gyp bookkeeping files a few hundred bytes short, and the identical shortfall survived every rung
# up to `write:"disk"`, under which no write can be denied at all.
#
# The predicate lives in `shortfall-invariance.mjs` — five clauses, one of them the safety clause that
# keeps `<package absent>` out, all of them unit-tested in both polarities. It reads the SEQUENCE of
# gate verdicts; it does not soften any one of them, and nothing here can make an arm pass that did not.
#
# ⛔ THE VERDICT IS `SUSPECT`, NOT `VERIFIED`, AND THE DIFFERENCE IS THE POINT. Grant-independence
# proves the shortfall is not a capability gap; it does not prove the install was good, and this is
# now the ONLY path that publishes a grant without a leave-one-out DESCENT behind it — `=> VERIFIED`
# descends from the synthesized grant and `=> MINIMUM (ladder fallback)` descends from the rung it
# landed on, so minimality here is unproven and the grant is a CANDIDATE. The record keeps it so the
# package is triageable instead of discarded; `collate.mjs` keeps it out of the catalog, because
# publishing an unverified NARROW grant is the under-granting direction and that is the one that
# breaks a real install.
INV=$(printf '%s' "$ARM_LEDGER" | node "$HERE/shortfall-invariance.mjs" --arms 4); IRC=$?
# ⛔⛔ AN EXIT CODE ALONE DOES NOT SAY THE PREDICATE RAN, AND THIS BRANCH USED TO ASSUME IT DID. The
# CLI block below `classify` prints `GRANT-INDEPENDENT …` or `NOT-ESTABLISHED …` on every path it
# takes, so an EMPTY `$INV` means it never executed — and the failure that produces that exits 0, so
# `[ "$IRC" -eq 0 ]` on its own reads a script that did nothing as the strongest verdict this stage
# can issue. `$MISS_N` would then be the empty string and the line would read "the SAME -artifact
# shortfall", published off no evidence at all.
#
# MEASURED, and the trigger is not exotic: `shortfall-invariance.mjs`'s main-module guard compares
# `import.meta.url` (physical) against `pathToFileURL(process.argv[1])` (as given), while `HERE` here
# is `cd "$(dirname "$0")" && pwd`, i.e. the LOGICAL path. Reproduced by invoking the same script
# through a symlinked directory: via the real path a `1:aa:ok:9` ledger prints `NOT-ESTABLISHED an arm
# exited non-zero` and exits 1, and through the symlink the identical invocation prints NOTHING and
# exits 0. macOS is where this bites first (`/tmp` is a symlink to `/private/tmp`), and whether a real
# Linux runner ever traverses one is UNMEASURED — which is the argument for the guard, not against it.
#
# ⛔ `HARNESS-ERROR`, NOT A NEW NOUN AND NOT `NO-STATE-PASSED`. `record.mjs` already parses this
# spelling (`measure-windows.mjs` produces it), and `claim-slice.mjs` returns a `HARNESS-*` row to
# `pending` instead of closing it — which is exactly right, because a re-run off a checkout with no
# symlink in its path would answer the question. Falling through to `NO-STATE-PASSED` would instead
# record "nothing installed this package" as a MEASUREMENT, when the rescue never got to run. Tested
# in the direction that matters: `linux-ladder.test.mjs` stubs the predicate to exit 0 silently and
# asserts the refusal, with a printing stub as the control.
if [ -z "$INV" ]; then
  echo "  => HARNESS-ERROR: shortfall-invariance.mjs printed nothing (rc=$IRC) — the predicate never"
  echo "     ran, so grant-independence is UNANSWERED and no verdict here would rest on evidence."
  exit 1
fi
if [ "$IRC" -eq 0 ]; then
  MISS_N=$(printf '%s' "$INV" | cut -d' ' -f2)
  echo "  => ARTIFACT-GATE-SUSPECT $GRANT   (every arm rc=0 and the SAME $MISS_N-artifact shortfall at every"
  echo "     grant up to write:\"disk\" — invariant under widening, so it is not a capability gap)"
  echo "     ⇒ The grant is the SYNTHESIZED one and is UNVERIFIED — minimality was never descended."
  echo "        Triage the shortfall against the arm's toolchain, not against the jail."
  exit 0
fi
echo "  NOT-GRANT-INDEPENDENT ${INV#NOT-ESTABLISHED }"
echo "  => NO-STATE-PASSED even at write:disk — investigate; do not widen the catalog blindly"
