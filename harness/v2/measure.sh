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
MAX='{"write":"disk","read":"disk","network":true}'
echo "### $PKG@$VER   ($ROOT)"

# ── The fixture. Lifted from v1 (`search.mjs:makeFixture`), because every element of it is load-
# bearing and the first v2 driver had none of them:
#
#  * HOME REDIRECTED INTO THE FIXTURE. This is what makes the artifact set CONTAINED BY
#    CONSTRUCTION: the nub store resolves to `<fx>/home/.cache/nub/pm/store`, so a dep write is
#    inside the scanned tree instead of in the real `~/.cache`. Without it the store is shared and
#    WARM across arms, so a later arm inherits an earlier arm's dependency writes and measures as
#    needing less than it does.
#  * `side-effects-cache=false`. nub memoises a lifecycle outcome keyed on package identity, so a
#    second arm on the same package REPLAYS the first arm's result with every precondition green.
#    The previous driver tried to dodge this by generating a unique fixture package name — but the
#    name it computed was assigned to a shell variable and never used, and the identity that
#    actually keys the cache is the DEPENDENCY's, which no fixture name can vary. This is the knob
#    v1 uses and it is the one that works.
#  * THE JAIL IS TURNED OFF BY `nub.jsonc`, NOT BY `dependenciesMeta`. c5651408f4 deleted every
#    path that read the per-package opt-out, so the old key is a silently inert no-op and a "jail
#    off" arm written that way runs WITH THE JAIL ON — an OBSERVE arm that measures the jail
#    instead of the package.
#  * A REAL GIT REPO AND THE HOOK-MANAGER CONFIG KEYS. A script that bails for a missing key
#    measures as "needs nothing", which is the verdict that ships a broken grant.
mkfix () {
  local fx="$1" jailoff="$2"
  mkdir -p "$fx/proj" "$fx/home"
  cat > "$fx/proj/package.json" <<EOF
{"name":"searchfix","version":"1.0.0","private":true,"main":"src/index.ts",
 "engines":{"node":">=18"},"scripts":{"build":"echo build","test":"echo test"},
 "dependencies":{"$PKG":"$VER"},
 "simple-git-hooks":{"pre-commit":"echo nub-fixture"},
 "husky":{"hooks":{"pre-commit":"echo nub-fixture"}}}
EOF
  printf 'side-effects-cache=false\n' > "$fx/proj/.npmrc"
  [ "$jailoff" = 1 ] && printf '{"install":{"buildJail":false}}\n' > "$fx/proj/nub.jsonc"
  node -e 'const fs=require("fs");const[d,p,g]=process.argv.slice(1);
    fs.writeFileSync(d+"/cat.json",JSON.stringify({packages:{[p]:{default:JSON.parse(g)}}}));' \
    "$fx" "$PKG" "${3:-$MAX}" || return 1
  ( cd "$fx/proj" && git init -q . && git config user.email n@n && git config user.name n \
      && git commit -q --allow-empty -m init ) >/dev/null 2>&1
  return 0
}

# The artifact set of an arm: the sorted, tokenised relative path list under the WHOLE fixture —
# project AND store. v1: "enumerating a few roots was UNSOUND once the control began running at
# write:disk". Not a file count; see artifact.mjs for why the count was never comparable.
arts () { node "$HERE/artifact.mjs" "$1"; }

# ── 1. OBSERVE — unjailed, traced. This is the DISCOVERY step and it needs no jail at all. ─────
#
# ⛔ OBSERVE TRACES `nub`, NOT `npm`. The jail confines nub's lifecycle execution, and the two
# managers do not even put the files in the same places: under npm a dependency's own files are
# `$proj/node_modules/...` (scope `deps`), under nub they are in the content-addressed store. An
# npm-derived observation is scoped against roots the verified run does not have.
OBS="$ROOT/observe"; mkfix "$OBS" 1 || exit 1
OSTORE="$OBS/home/.cache/nub/pm/store"
# `-f` is mandatory: the interesting syscall is routinely a grandchild of the postinstall.
# `process` is mandatory too — without clone/execve there is no parentage, so neither cwd
# inheritance nor lifecycle-subtree attribution can work (see observe.mjs).
( cd "$OBS/proj" && HOME="$OBS/home" strace -f -e trace=file,network,process -o "$OBS/trace.txt" \
    "$NUB" install > "$OBS/i.log" 2>&1
  HOME="$OBS/home" strace -f -e trace=file,network,process -o "$OBS/trace2.txt" \
    "$NUB" approve-builds --all > "$OBS/a.log" 2>&1 )
OBS_RC=$?
cat "$OBS/trace2.txt" >> "$OBS/trace.txt" 2>/dev/null
# ⛔ PROVE THE ARM RAN UNJAILED. A jail-off fixture that silently ran confined measures the jail.
grep -q 'without the build sandbox' "$OBS"/*.log || echo "  ⚠ jail-off not announced by nub"
arts "$OBS" > "$ROOT/obs.paths"
echo "  OBSERVE   rc=$OBS_RC paths=$(wc -l < "$ROOT/obs.paths" | tr -d ' ') trace=$(wc -l < "$OBS/trace.txt" | tr -d ' ') lines"
if [ "$OBS_RC" -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed; nothing to measure)"; exit 0
fi

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe.mjs" "$OBS/trace.txt" "$OBS/proj" "$OBS/home" "$OSTORE" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }

# ── 3. VERIFY — the real, UNPRIVILEGED jail. The only arm whose result may enter the catalog. ──
run_arm () {
  local grant="$1" label="$2"
  local v="$ROOT/arm-$label"
  mkfix "$v" 0 "$grant" || return 3
  ( cd "$v/proj" && HOME="$v/home" NUB_BUILD_JAIL_CATALOG="$v/cat.json" "$NUB" install > "$v/i.log" 2>&1
    HOME="$v/home" NUB_BUILD_JAIL_CATALOG="$v/cat.json" "$NUB" approve-builds --all > "$v/a.log" 2>&1 )
  ARM_RC=$?
  # ⛔ A malformed override WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  # assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  local ovr rej
  ovr=$(cat "$v"/proj/*.log 2>/dev/null | grep -c 'catalog OVERRIDDEN'); rej=$(cat "$v"/proj/*.log 2>/dev/null | grep -c 'REJECTED')
  ovr=$(( ovr + $(cat "$v"/*.log 2>/dev/null | grep -c 'catalog OVERRIDDEN') ))
  rej=$(( rej + $(cat "$v"/*.log 2>/dev/null | grep -c 'REJECTED') ))
  arts "$v" > "$ROOT/$label.paths"
  ARM_N=$(wc -l < "$ROOT/$label.paths" | tr -d ' ')
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "  ⛔ [$label] override did not engage — arm VOID"; return 3; }
  return 0
}

# The control is a NUB run at the widest grant, run TWICE. v1: "a single control cannot tell 'this
# cell lacks a capability' from 'this path is nondeterministic'". Only paths BOTH controls produced
# are required of a cell; the rest are the package's own noise.
run_arm "$MAX" ctlA; A_RC=$ARM_RC; run_arm "$MAX" ctlB; B_RC=$ARM_RC
comm -12 "$ROOT/ctlA.paths" "$ROOT/ctlB.paths" > "$ROOT/stable.paths"
STABLE=$(wc -l < "$ROOT/stable.paths" | tr -d ' ')
echo "  CONTROL   rcA=$A_RC rcB=$B_RC pathsA=$(wc -l < "$ROOT/ctlA.paths" | tr -d ' ') pathsB=$(wc -l < "$ROOT/ctlB.paths" | tr -d ' ') stable=$STABLE"
if [ "$A_RC" -ne 0 ] || [ "$B_RC" -ne 0 ]; then
  echo "  => BROKEN-EVEN-WITH-EVERYTHING (control failed at $MAX)"; exit 0
fi

# A cell passes iff it reproduces the control's exit code AND every path both controls produced.
verify () {
  local grant="$1" label="$2"
  run_arm "$grant" "$label" || return 2
  local missing; missing=$(comm -23 "$ROOT/stable.paths" "$ROOT/$label.paths" | wc -l | tr -d ' ')
  echo "  VERIFY[$label] rc=$ARM_RC paths=$ARM_N missing=$missing grant=$grant"
  [ "$ARM_RC" -eq "$A_RC" ] && [ "$missing" -eq 0 ]
}

if verify "$GRANT" synth; then
  echo "  => MINIMUM $GRANT   (observed, then verified)"; exit 0
fi

# ── 4. FALL BACK — the ladder, retained, but walked UPWARD FROM the synthesized grant. ─────────
# This is the ladder's real job: repairing a hypothesis, over a handful of states rather than 55.
echo "  synthesized grant did not verify — falling back to a bounded ladder"
i=0
for g in \
  '{"write":{"deps":true},"network":true}' \
  '{"write":{"deps":true,"project":true},"network":true}' \
  '{"write":{"deps":true,"project":true,"userHome":true},"network":true}' \
  '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}' \
  "$MAX"
do
  i=$((i+1))
  if verify "$g" "fb$i"; then
    echo "  => MINIMUM $g   (ladder fallback; synthesized grant was insufficient)"
    echo "  ⛔ OBSERVE UNDER-PREDICTED — the gap between $GRANT and $g is worth reading"
    exit 0
  fi
done
echo "  => NO-STATE-PASSED even at $MAX — investigate; do not widen the catalog blindly"
