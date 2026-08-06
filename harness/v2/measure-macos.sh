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
PKG="${1:?usage: measure-macos.sh <pkg> <version> [nub]}"
VER="${2:?usage: measure-macos.sh <pkg> <version> [nub]}"
NUB="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNUSER="${SUDO_USER:-$(id -un)}"
NPM_BIN="$(command -v npm)"

# ⛔ NOT UNDER /tmp — that path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all.
ROOT="$(mktemp -d "$HOME/v2m-XXXXXX")" || exit 1
# The driver runs under sudo (dtrace needs uid 0) but every measured process is dropped back to the
# invoking user — so the tree they write into must be theirs, or npm fails on its own fixture and
# the run reports a package problem that is really a harness problem.
chown -R "$RUNUSER" "$ROOT" 2>/dev/null
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)   nub=${NUB:-<none>}"

# ── 1. OBSERVE ─────────────────────────────────────────────────────────────────────────────────
OBS="$ROOT/observe"; mkdir -p "$OBS"; cd "$OBS" || exit 1
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

# dtrace's `-c` word-splits its argument and execs it directly — there is no shell, so the command
# cannot carry a redirect and cannot report its own exit status. A wrapper file supplies both.
# ⛔ THE WRAPPER MUST NOT BE `sh -c`. The decoder identifies the lifecycle script as the only
# `sh -c` in the subtree (npm execs one per script); a `-c` wrapper here would be indistinguishable
# from it and would attribute the ENTIRE npm subtree to the package.
cat > "$OBS/run.sh" <<WRAP
cd "$OBS"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" "$NPM_BIN" rebuild --no-audit --no-fund "$PKG" > "$OBS/npm.log" 2>&1
echo \$? > "$OBS/rc"
WRAP

PRE=$(find -L "$OBS" -type f ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
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

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe-macos.mjs" "$OBS/trace.txt" "$OBS" "/Users/$RUNUSER" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }

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
  # ⛔⛔ A UNIQUE NAME IS NOT ENOUGH AND NEITHER IS DROPPING THE MEMO — PROVEN ON THE WINDOWS
  # DRIVER, which carries both and replayed anyway. The surviving replay source is the GLOBAL
  # VIRTUAL STORE: a package already materialized there is RELINKED, not reinstalled, so its
  # scripts never run again. The signature is `materialized …` with no `installed N packages`,
  # while every precondition stays green. Hence a fresh cache per ARM, not per run.
  local cache="$v/nubcache"; rm -rf "$cache"
  node -e '
    const fs=require("fs");const [r,p,g]=process.argv.slice(1);
    fs.writeFileSync(r+"/cat.json",JSON.stringify({packages:{[p]:{default:JSON.parse(g)}}}));
  ' "$v" "$PKG" "$grant" || return 1
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
  echo "  VERIFY[$label] rc=$rc files=$files OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "     ⛔ override did not engage — arm is VOID"; return 2; }
  # Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  # failure mode. Compare against what the unjailed OBSERVE arm produced.
  [ "$rc" -eq 0 ] && [ "$files" -ge "$OBS_FILES" ]
}

VERIFIED=0
if verify "$GRANT" "synth"; then
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
    # ⛔ An empty `default` block is REJECTED by the parser, which would make the arm VOID and read
    # as a failure. That is not the same answer as "the narrower grant did not work", so say so.
    if [ "$gg" = "{}" ]; then
      echo "  NARROW[$nm] grant is empty — the catalog cannot express an empty default block, so"
      echo "     this variant is UNTESTABLE rather than failing. Reported, not counted."
      continue
    fi
    if verify "$gg" "nar-$nm"; then
      echo "     ⛔ OVER-PREDICTED — the strictly narrower $gg also verifies; '$nm' was not needed"
    else
      echo "     narrowing '$nm' fails ⇒ that capability IS necessary"
    fi
  done < "$ROOT/variants.tsv"
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
