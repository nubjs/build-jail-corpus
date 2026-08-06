#!/bin/bash
# Does eslogger's OWN-PROCESS-GROUP SUPPRESSION account for the coverage blackout?
#
# `es-coverage-control.sh` launched the three esloggers AND all six fixture shapes from one shell
# script. A non-interactive shell has no job control, so backgrounded children stay in the SCRIPT's
# process group, and pgid is inherited across fork+exec — every fixture therefore shared a process
# group with the tracer. If eslogger suppresses its own process group, the control reproduced the
# exact artifact it was built to rule out, and "ES is structurally blind" is wrong.
#
# This script decides it with an A/B that varies ONE thing: the SAME six shapes are observed by two
# esloggers, one left in the script's process group and one moved out of it via setsid. There is no
# setsid(1) on macOS (util-linux only), so perl's POSIX::setsid does the work.
#
# Runs as root. A negative answer IS the deliverable; never exits non-zero for one.
set +e

OUT="${1:?usage: es-pgroup-control.sh <outdir>}"
mkdir -p "$OUT"
TAG="pg$(date +%s)$$"
DIR="$HOME/pgctl-$TAG"
mkdir -p "$DIR"
say() { echo "[pgctl] $*"; }

echo "=============================== HOST FACTS ================================="
say "tag=$TAG uid=$(id -u) sudo_user=${SUDO_USER:-none}"
echo "--- csrutil status (VERBATIM) ---"
csrutil status 2>&1
echo "--- end csrutil ---"
sw_vers 2>&1

# ---------------------------------------------------------------------------
# CLAIM VERIFICATION. The suppression sentence was read on a DIFFERENT macOS version; a behaviour
# documented in one is not guaranteed in another. Confirm it is present in THIS version's man page
# before any cell below is interpreted, and print it verbatim either way.
# ---------------------------------------------------------------------------
echo
echo "======= DOES THIS VERSION'S man eslogger DOCUMENT PGROUP SUPPRESSION? ====="
man eslogger 2>/dev/null | col -b > "$OUT/man-eslogger.txt"
echo "man page bytes: $(wc -c < "$OUT/man-eslogger.txt" | tr -d ' ')"
if grep -qi 'process group' "$OUT/man-eslogger.txt"; then
  echo "CLAIM-PRESENT: yes. Verbatim context:"
  grep -i -B3 -A3 'process group' "$OUT/man-eslogger.txt"
else
  echo "CLAIM-PRESENT: NO — this version's man page does not mention a process group."
  echo "The A/B below still decides the behaviour empirically; it just is not documented here."
fi

# ---------------------------------------------------------------------------
# SHAPE A — pre-existing long-lived, started before either tracer.
# ---------------------------------------------------------------------------
cat > "$DIR/shapeA.sh" <<EOF
#!/bin/bash
echo \$\$ > "$DIR/shapeA.pid"
while [ ! -f "$DIR/go" ]; do sleep 0.2; done
echo x > "$DIR/A-preexisting-longlived-$TAG.txt"
sleep 40
EOF
chmod +x "$DIR/shapeA.sh"
"$DIR/shapeA.sh" &
SHAPE_A_BG=$!
sleep 1

# ---------------------------------------------------------------------------
# THE A/B. Same event set, same window, same fixtures. The ONLY difference is the process group.
# ---------------------------------------------------------------------------
EV="open create unlink rename exec"

# ARM 1 — IN the script's process group. This is exactly what es-coverage-control.sh did, and it is
# the CONTROL: if it now sees the shapes, the reproduction is wrong and no other row means anything.
eslogger $EV > "$OUT/es-samepg.json" 2> "$OUT/es-samepg.err" &
P_SAME=$!

# ARM 2 — moved to its OWN session/process group first. setsid() fails for a process that is already
# a group leader; a backgrounded child of this script is not one, so it succeeds here.
perl -e 'use POSIX; POSIX::setsid(); exec @ARGV or die "exec failed: $!"' \
  -- /usr/bin/eslogger $EV > "$OUT/es-newpg.json" 2> "$OUT/es-newpg.err" &
P_NEW=$!

fs_usage -w -f filesys > "$OUT/fsu.txt" 2> "$OUT/fsu.err" &
PF=$!

sleep 10

# ---------------------------------------------------------------------------
# POSITIVE CONTROL FOR THE FIX ITSELF. Without this there is no way to tell "the fix worked" from
# "the fix silently did not apply" — a failed setsid would leave arm 2 identical to arm 1 and the
# whole A/B would read as "pgroup is not the mechanism".
# ---------------------------------------------------------------------------
echo
echo "=============== PROCESS GROUPS (the fix's own positive control) ============"
SCRIPT_PGID=$(ps -o pgid= -p $$ | tr -d ' ')
echo "  script      pid=$$ pgid=$SCRIPT_PGID"
for nm in P_SAME P_NEW PF SHAPE_A_BG; do
  eval "v=\$$nm"
  echo "  $nm pid=$v pgid=$(ps -o pgid= -p "$v" 2>/dev/null | tr -d ' ') cmd=$(ps -o comm= -p "$v" 2>/dev/null)"
done
# perl exec's in place, so P_NEW IS the eslogger. Resolve its real pgid and assert the split.
SAME_PGID=$(ps -o pgid= -p "$P_SAME" 2>/dev/null | tr -d ' ')
NEW_PGID=$(ps -o pgid= -p "$P_NEW" 2>/dev/null | tr -d ' ')
echo "  SAME_PGID=$SAME_PGID  NEW_PGID=$NEW_PGID  SCRIPT_PGID=$SCRIPT_PGID"
if [ "$SAME_PGID" = "$SCRIPT_PGID" ] && [ -n "$NEW_PGID" ] && [ "$NEW_PGID" != "$SCRIPT_PGID" ]; then
  echo "  SETSID-APPLIED: YES — arm 1 shares the script's group, arm 2 does not. A/B is valid."
else
  echo "  ⛔ SETSID-APPLIED: NO — the two arms are NOT separated. Every cell below is UNINTERPRETABLE."
fi

date +%H:%M:%S.%N > "$OUT/t-window-open"

# ---------------------------------------------------------------------------
# THE SIX SHAPES — identical to es-coverage-control.sh so the tables line up.
# ---------------------------------------------------------------------------
touch "$DIR/go"
sleep 2

(
  sleep 1
  echo x > "$DIR/B-postlived-$TAG.txt"
  sleep 25
) &
SHAPE_B_BG=$!
# NOT $BASHPID: macOS ships bash 3.2 and BASHPID arrived in bash 4.0, so it expands to nothing here.
echo "$SHAPE_B_BG" > "$DIR/shapeB.pid"
sleep 3

/bin/sh -c "echo \$\$ > $DIR/shapeC.pid; echo x > $DIR/C-shortlived-root-$TAG.txt"
sleep 1

if [ -n "${SUDO_USER:-}" ]; then
  chmod 777 "$DIR"
  sudo -u "$SUDO_USER" /bin/sh -c "echo \$\$ > $DIR/shapeD.pid; echo x > $DIR/D-shortlived-user-$TAG.txt"
fi
sleep 1

echo $$ > "$DIR/shapeE.pid"
echo x > "$DIR/E-selfshell-$TAG.txt"
sleep 2

NOISE_PIDS=""
for w in 1 2 3 4; do
  ( for i in $(seq 1 6000); do : > "$DIR/noise-$w-$i"; rm -f "$DIR/noise-$w-$i"; done ) &
  NOISE_PIDS="$NOISE_PIDS $!"
done
sleep 2
/bin/sh -c "echo \$\$ > $DIR/shapeF.pid; echo x > $DIR/F-shortlived-underload-$TAG.txt"
sleep 1
for p in $NOISE_PIDS; do wait "$p" 2>/dev/null; done

# ---------------------------------------------------------------------------
# SHAPE G — a shape in a THIRD process group, observed by BOTH arms. If pgroup suppression is the
# mechanism, G is visible to arm 2 AND to arm 1, which separates "arm 2 works" from "arm 2 sees
# everything for some unrelated reason".
# ---------------------------------------------------------------------------
perl -e 'use POSIX; POSIX::setsid(); exec @ARGV' -- /bin/sh -c \
  "echo \$\$ > $DIR/shapeG.pid; echo x > $DIR/G-own-pgroup-$TAG.txt"
sleep 3

# ---------------------------------------------------------------------------
# TEARDOWN — SIGTERM. MEASURED: eslogger IGNORES SIGINT off the foreground process group and needed
# SIGKILL, which discards whatever it still had buffered.
# ---------------------------------------------------------------------------
for p in $P_SAME $P_NEW $PF; do kill -TERM "$p" 2>/dev/null; done
for p in $P_SAME $P_NEW $PF; do
  for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || break; sleep 0.2; done
  kill -0 "$p" 2>/dev/null && { say "tracer $p did NOT exit on SIGTERM; SIGKILL"; kill -9 "$p" 2>/dev/null; }
done
kill -9 $SHAPE_A_BG $SHAPE_B_BG 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
echo
echo "=============================== GROUND TRUTH ==============================="
for s in A B C D E F G; do
  echo "  shape$s pid=$(cat "$DIR/shape$s.pid" 2>/dev/null || echo NONE)"
done
echo "  es-samepg records: $(wc -l < "$OUT/es-samepg.json" 2>/dev/null | tr -d ' ')"
echo "  es-newpg  records: $(wc -l < "$OUT/es-newpg.json"  2>/dev/null | tr -d ' ')"
echo "  fs_usage    lines: $(wc -l < "$OUT/fsu.txt"        2>/dev/null | tr -d ' ')"
echo "--- es-samepg.err ---"; head -10 "$OUT/es-samepg.err"
echo "--- es-newpg.err  ---"; head -10 "$OUT/es-newpg.err"

echo
echo "===== THE A/B: DID EACH ARM NAME THE FILE, WITH THE SHAPE'S OWN PID? ======"
echo "A count alone is NOT a pass — Spotlight indexes every new file and produces exactly that"
echo "count. A cell passes only when the naming record's audit_token.pid is the shape's own pid."
printf "%-30s %10s %10s %10s %10s %8s\n" "shape" "same_n" "same_OWN" "new_n" "new_OWN" "fs_usage"
for s in A:A-preexisting-longlived B:B-postlived C:C-shortlived-root \
         D:D-shortlived-user E:E-selfshell F:F-shortlived-underload G:G-own-pgroup; do
  lbl="${s%%:*}"; tok="${s#*:}-$TAG"
  own=$(cat "$DIR/shape$lbl.pid" 2>/dev/null)
  r=""
  for n in es-samepg es-newpg; do
    tot=$(grep -c -- "$tok" "$OUT/$n.json" 2>/dev/null | tr -d ' ')
    o=0
    [ -n "$own" ] && o=$(grep -- "$tok" "$OUT/$n.json" 2>/dev/null \
      | grep -c "\"audit_token\":{[^}]*\"pid\":$own[,}]" | tr -d ' ')
    r="$r $(printf '%10s' "$tot") $(printf '%10s' "$o")"
  done
  f=$(grep -c -- "$tok" "$OUT/fsu.txt" 2>/dev/null | tr -d ' ')
  printf "%-30s%s %8s\n" "$lbl (pid ${own:-NONE})" "$r" "$f"
done

echo
echo "===== WHO NAMED IT — the raw attribution, arm 2 (the setsid arm) =========="
for s in A:A-preexisting-longlived C:C-shortlived-root E:E-selfshell G:G-own-pgroup; do
  lbl="${s%%:*}"; tok="${s#*:}-$TAG"
  echo "--- shape $lbl (own pid $(cat "$DIR/shape$lbl.pid" 2>/dev/null)) ---"
  grep -- "$tok" "$OUT/es-newpg.json" 2>/dev/null | head -5 | while IFS= read -r line; do
    pid=$(printf '%s' "$line" | grep -o '"audit_token":{[^}]*}' | grep -o '"pid":[0-9]*' | head -1)
    exe=$(printf '%s' "$line" | grep -o '"executable":{.*"path":"[^"]*"' | sed 's/.*"path":"//;s/\\//g' | head -1)
    echo "    $pid  $exe"
  done
done

echo
echo "===== TOP EXECUTABLES PER ARM — the tell. If arm 1 is all Apple daemons and =="
echo "===== arm 2 contains sh/bash/cat, process-group suppression IS the mechanism. ="
for n in es-samepg es-newpg; do
  echo "--- $n ($(wc -l < "$OUT/$n.json" 2>/dev/null | tr -d ' ') records) ---"
  grep -o '"executable":{[^}]*"path":"[^"]*"' "$OUT/$n.json" 2>/dev/null \
    | sed 's/.*"path":"//' | sort | uniq -c | sort -rn | head -12
done

for n in es-samepg es-newpg; do head -c 4000000 "$OUT/$n.json" > "$OUT/$n.head.json"; rm -f "$OUT/$n.json"; done
head -c 2000000 "$OUT/fsu.txt" > "$OUT/fsu.head.txt"; rm -f "$OUT/fsu.txt"
rm -rf "$DIR"
echo "[pgctl] DONE"
exit 0
