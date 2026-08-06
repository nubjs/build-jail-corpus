#!/usr/bin/env bash
# Harness v2 driver: OBSERVE -> SYNTHESIZE -> VERIFY -> (fall back to the ladder).
#
# See README.md for why. The short version: v1's only signal was pass/fail of a jailed run, so it
# had to SEARCH 55 states to find the minimum, and could never say WHAT a package touched. The
# generation harness may run as root, so it does not have to guess — it watches, then checks.
#
#   usage: measure.sh <pkg> <version> [nub-binary]
set -uo pipefail
PKG="${1:?usage: measure.sh <pkg> <version> [nub]}"
VER="${2:?usage: measure.sh <pkg> <version> [nub]}"
NUB="${3:-$HOME/nub/target/fast/nub}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# ⛔ NOT UNDER /tmp. That path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all — it already produced one wrong all-clear.
ROOT="$(mktemp -d "$HOME/v2-XXXXXX")" || exit 1
# Per-run cache, so two packages measured concurrently cannot share a store — and so clearing the
# side-effects memo between arms (below) touches only this run. Without it the memo drop is a
# global mutation and concurrent runs corrupt each other's arms silently.
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)"

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
# `-f` is mandatory: the interesting syscall is routinely a grandchild of the postinstall.
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

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe.mjs" "$OBS/trace.txt" "$OBS" "$HOME" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }

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
  # ⛔ AND THE UNIQUE NAME IS NOT ENOUGH ON ITS OWN. The memo is keyed on the DEPENDENCY's identity
  # too, which is identical across arms by construction — so arm N would replay arm 1's outcome
  # with every precondition still green. Dropping the store's side-effects memo is the only thing
  # that makes two arms of the SAME package@version independent.
  rm -rf "$NUB_CACHE_DIR/pm/side-effects-v1" 2>/dev/null
  node -e '
    const fs=require("fs");const [r,p,g]=process.argv.slice(1);
    fs.writeFileSync(r+"/cat.json",JSON.stringify({packages:{[p]:{default:JSON.parse(g)}}}));
  ' "$v" "$PKG" "$grant" || return 1
  # `$tracer` is empty for a normal arm and `strace -f -o <file>` for the DIAGNOSE arm below. Kept
  # as a parameter rather than a second copy of this function so the preconditions above — unique
  # name, explicit `buildJail`, memo drop, override assertion — cannot drift between the arm that
  # decides the verdict and the arm that explains it.
  ( cd "$v" && NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-i.txt} "$NUB" install > "$v/i.log" 2>&1
    NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-a.txt} "$NUB" approve-builds --all > "$v/a.log" 2>&1 )
  local rc=$?
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
  echo "  VERIFY[$label] rc=$rc files=$files OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "     ⛔ override did not engage — arm is VOID"; return 2; }
  # Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  # failure mode. Compare against what the unjailed OBSERVE arm produced.
  [ "$rc" -eq 0 ] && [ "$files" -ge "$OBS_FILES" ]
}

if verify "$GRANT" "synth"; then
  echo "  => MINIMUM $GRANT   (observed, then verified)"
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
# The output is a LEAD, not a verdict: "last refusal before the process died" is correlation. It is
# still the single most useful line the loop can print, because it turns "some grant was too narrow"
# into a named path a human can act on in one step.
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
echo "  synthesized grant did not verify — falling back to a bounded ladder"
for g in \
  '{"write":{"deps":true,"project":true,"userHome":true},"network":true}' \
  '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}' \
  '{"write":"disk","network":true}'
do
  if verify "$g" "fb$(echo "$g" | cksum | cut -d' ' -f1)"; then
    echo "  => MINIMUM $g   (ladder fallback; synthesized grant was insufficient)"
    echo "  ⛔ OBSERVE UNDER-PREDICTED — the gap between $GRANT and $g is worth reading"
    exit 0
  fi
done
echo "  => NO-STATE-PASSED even at write:disk — investigate; do not widen the catalog blindly"
