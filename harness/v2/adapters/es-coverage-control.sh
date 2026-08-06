#!/bin/bash
# Standalone Endpoint Security COVERAGE CONTROL. No adapter in the path, on purpose.
#
# The macOS god-mode adapter resolves 2556 eslogger records to 17 processes and NONE of them are
# ours, so every file event is filtered out by an empty pid closure. Two mutually exclusive stories
# fit that: (a) ES structurally does not report the process shapes we care about, in which case no
# adapter change fixes it; (b) the adapter's 9-event subscription or its consumption of the stream
# is at fault. This script decides between them by subscribing to eslogger DIRECTLY, at three
# different event-set sizes, while five deliberately-different process shapes each touch a
# uniquely-tokened file. The question per cell is only ever: did this eslogger name that file.
#
# Runs as root (both instruments require uid 0). Never exits non-zero on a negative answer — a
# negative answer IS the deliverable.
set +e

OUT="${1:?usage: es-coverage-control.sh <outdir>}"
mkdir -p "$OUT"
TAG="k$(date +%s)$$"
# NOT under /tmp: that path is inside the build jail's private-temp redirect and has bitten this
# effort before. Root's home is stable and outside every redirect we operate.
DIR="$HOME/covctl-$TAG"
mkdir -p "$DIR"

say() { echo "[covctl] $*"; }

say "tag=$TAG dir=$DIR uid=$(id -u) sudo_user=${SUDO_USER:-none}"
say "sip: $(csrutil status 2>&1)"
say "eslogger: $(command -v eslogger || echo MISSING)"
eslogger --list-events > "$OUT/es-events.txt" 2>&1
say "eslogger --list-events -> $(wc -l < "$OUT/es-events.txt") lines"

# ---------------------------------------------------------------------------
# SHAPE A is started BEFORE any tracer, so it is a pre-existing long-lived process — the same shape
# as the adapter's own node process, which ES demonstrably never named. It blocks on a trigger file
# so its write lands squarely inside the tracing window.
# ---------------------------------------------------------------------------
cat > "$DIR/shapeA.sh" <<EOF
#!/bin/bash
echo \$\$ > "$DIR/shapeA.pid"
while [ ! -f "$DIR/go" ]; do sleep 0.2; done
echo x > "$DIR/A-preexisting-longlived-$TAG.txt"
sleep 30
EOF
chmod +x "$DIR/shapeA.sh"
"$DIR/shapeA.sh" &
SHAPE_A_BG=$!

sleep 1

# ---------------------------------------------------------------------------
# TRACERS. Three eslogger subscriptions of increasing width plus fs_usage as the known-good
# comparator (it already proved it sees our processes when eslogger did not).
# ---------------------------------------------------------------------------
# ⛔⛔ `set -m` IS THE WHOLE EXPERIMENT, NOT A TIDY-UP. `man eslogger`: "eslogger automatically
# suppresses events for all processes that are part of its process group." A non-interactive shell
# has NO job control, so every background job it starts inherits the SCRIPT's pgid, and pgid
# survives fork+exec — so the tracers and all six shapes shared one process group and eslogger
# discarded every shape BY DESIGN. That is the entire "ES is structurally blind" result: this
# script was measuring its own suppression. `set -m` turns job control on, which gives each
# background job its own pgid. MEASURED: with it, a background job gets pgid 89611 against the
# script's 89578; without it, 89578.
#
# ⛔ NOT `setsid` — it does not exist on macOS (util-linux, Linux-only), so the reflexive fix is
# unavailable. `perl -e 'use POSIX; POSIX::setsid(); exec @ARGV'` is the fallback.
#
# The ADAPTER already had this cure via node's `spawn(..., {detached: true})`. This control never
# did, because `detached` is a Node option and this is a shell script — so the control reproduced
# the exact bug it was written to rule out.
set -m

eslogger open \
  > "$OUT/es1.json" 2> "$OUT/es1.err" & P1=$!
eslogger open create unlink rename exec \
  > "$OUT/es5.json" 2> "$OUT/es5.err" & P5=$!
eslogger open create unlink rename link truncate exec fork exit \
  > "$OUT/es9.json" 2> "$OUT/es9.err" & P9=$!
fs_usage -w -f filesys \
  > "$OUT/fsu.txt" 2> "$OUT/fsu.err" & PF=$!

set +m

say "tracers: es1=$P1 es5=$P5 es9=$P9 fsu=$PF"

# ⛔ THE FIX MUST PROVE IT APPLIED, OR A SECOND BLIND RUN READS EXACTLY LIKE THE FIRST ONE. Every
# tracer's pgid must differ from this script's. If any matches, that tracer is still suppressing
# our shapes and its rows are VOID rather than negative.
SELF_PGID=$(ps -o pgid= -p $$ | tr -d ' ')
PG_OK=1
for _p in "$P1" "$P5" "$P9"; do
  _pg=$(ps -o pgid= -p "$_p" 2>/dev/null | tr -d ' ')
  say "PGID-CONTROL tracer pid=$_p pgid=${_pg:-GONE} script=$SELF_PGID"
  { [ -n "$_pg" ] && [ "$_pg" != "$SELF_PGID" ]; } || PG_OK=0
done
if [ "$PG_OK" -eq 1 ]; then
  say "PGID-CONTROL PASS — tracers sit outside the script's process group"
else
  say "PGID-CONTROL ⛔ FAIL — a tracer shares this script's process group, so eslogger will"
  say "PGID-CONTROL ⛔ suppress every shape below. The run is VOID, not a negative result."
fi

date +%H:%M:%S.%N > "$OUT/t-tracers-started"

# Generous fixed warmup. A readiness poll is what obscured this in an earlier run; a wall-clock wait
# is dumber and cannot lie about what it observed.
sleep 12
date +%H:%M:%S.%N > "$OUT/t-window-open"
say "window open"

# ---------------------------------------------------------------------------
# THE FIVE SHAPES. Each writes exactly one uniquely-tokened file and records its own pid.
# ---------------------------------------------------------------------------

# A — pre-existing long-lived (released by the trigger)
touch "$DIR/go"
sleep 2

# B — long-lived shell STARTED AFTER the tracers were live
(
  # $$ in a subshell reports the PARENT's pid in bash; $BASHPID is the subshell's own.
  echo "$BASHPID" > "$DIR/shapeB.pid"
  sleep 1
  echo x > "$DIR/B-postlived-$TAG.txt"
  sleep 20
) &
SHAPE_B_BG=$!
sleep 3

# C — short-lived `/bin/sh -c`, running as ROOT. This is the shape npm lifecycle scripts take.
/bin/sh -c "echo \$\$ > $DIR/shapeC.pid; echo x > $DIR/C-shortlived-root-$TAG.txt"
sleep 1

# D — short-lived `/bin/sh -c`, running as the ORIGINAL NON-ROOT USER. Isolates the uid axis from
# the lifetime axis; without it a negative on C is unattributable.
if [ -n "${SUDO_USER:-}" ]; then
  chmod 777 "$DIR"
  sudo -u "$SUDO_USER" /bin/sh -c "echo \$\$ > $DIR/shapeD.pid; echo x > $DIR/D-shortlived-user-$TAG.txt"
fi
sleep 1

# E — this script's OWN shell doing a plain redirect, no fork at all.
echo $$ > "$DIR/shapeE.pid"
echo x > "$DIR/E-selfshell-$TAG.txt"
sleep 2

date +%H:%M:%S.%N > "$OUT/t-quiet-done"

# ---------------------------------------------------------------------------
# LOAD ARM. 2556 records against 43,073 fs_usage lines is a suspicious ratio, and ES has bounded
# queues that DROP rather than block. Shape F is the same short-lived `sh -c` as C, fired while four
# workers churn the filesystem. If C is seen and F is not, the mechanism is drops under load, which
# is a completely different and far more fixable story than a coverage gap.
# ---------------------------------------------------------------------------
NOISE_PIDS=""
for w in 1 2 3 4; do
  ( for i in $(seq 1 6000); do : > "$DIR/noise-$w-$i"; rm -f "$DIR/noise-$w-$i"; done ) &
  NOISE_PIDS="$NOISE_PIDS $!"
done
sleep 2
/bin/sh -c "echo \$\$ > $DIR/shapeF.pid; echo x > $DIR/F-shortlived-underload-$TAG.txt"
sleep 1
for p in $NOISE_PIDS; do wait "$p" 2>/dev/null; done
date +%H:%M:%S.%N > "$OUT/t-load-done"
say "load arm done"

sleep 5

# ---------------------------------------------------------------------------
# TEARDOWN — clean exit, never SIGKILL. (An earlier agent proved buffering is not the mechanism, but
# a dirty teardown would put that back on the table and it costs nothing to rule out again.)
# ---------------------------------------------------------------------------
# MEASURED run 1: eslogger ignores SIGINT when it is not the foreground process group, so all three
# tracers had to be SIGKILLed. SIGTERM is the one it honours.
for p in $P1 $P5 $P9 $PF; do kill -TERM "$p" 2>/dev/null; done
for p in $P1 $P5 $P9 $PF; do
  for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || break; sleep 0.2; done
  kill -0 "$p" 2>/dev/null && { say "tracer $p did NOT exit cleanly; SIGKILL"; kill -9 "$p" 2>/dev/null; }
done
kill -9 $SHAPE_A_BG $SHAPE_B_BG 2>/dev/null
date +%H:%M:%S.%N > "$OUT/t-tracers-stopped"

# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
echo
echo "=============================== GROUND TRUTH ==============================="
for f in "$DIR"/[A-F]-*.txt; do
  [ -e "$f" ] && echo "  exists: $(basename "$f")"
done
for s in A B C D E F; do
  p=$(cat "$DIR/shape$s.pid" 2>/dev/null)
  echo "  shape$s pid=${p:-NONE}"
done

echo
echo "=============================== TRACER VOLUME ==============================="
for n in es1 es5 es9; do
  printf "  %-4s records=%-8s stderr_bytes=%-8s\n" "$n" \
    "$(wc -l < "$OUT/$n.json" 2>/dev/null | tr -d ' ')" \
    "$(wc -c < "$OUT/$n.err" 2>/dev/null | tr -d ' ')"
done
printf "  %-4s lines=%s\n" fsu "$(wc -l < "$OUT/fsu.txt" 2>/dev/null | tr -d ' ')"

echo
echo "=============================== TRACER STDERR (drop indications live here) ==="
for n in es1 es5 es9 fsu; do
  echo "--- $n.err ---"
  head -40 "$OUT/$n.err" 2>/dev/null
done

echo
echo "======================= DID ESLOGGER NAME THE FILE? ========================"
printf "%-34s %8s %8s %8s %8s\n" "shape / token" "es1" "es5" "es9" "fs_usage"
for s in A:A-preexisting-longlived B:B-postlived C:C-shortlived-root \
         D:D-shortlived-user E:E-selfshell F:F-shortlived-underload; do
  lbl="${s%%:*}"; tok="${s#*:}-$TAG"
  row=""
  for n in es1 es5 es9; do
    row="$row $(printf '%8s' "$(grep -c -- "$tok" "$OUT/$n.json" 2>/dev/null | tr -d ' ')")"
  done
  row="$row $(printf '%8s' "$(grep -c -- "$tok" "$OUT/fsu.txt" 2>/dev/null | tr -d ' ')")"
  printf "%-34s%s\n" "$lbl $tok" "$row"
done

echo
echo "============ WHO NAMED IT? (a count alone cannot exclude Spotlight) ========"
# A record naming the path proves nothing on its own: mdworker indexes every new file and would
# produce exactly this count. The cell is only a PASS if the naming record's audit_token.pid is the
# shape's own pid. Print pid + euid + executable for every matching record.
for s in A:A-preexisting-longlived B:B-postlived C:C-shortlived-root \
         D:D-shortlived-user E:E-selfshell F:F-shortlived-underload; do
  lbl="${s%%:*}"; tok="${s#*:}-$TAG"
  echo "--- shape $lbl (own pid $(cat "$DIR/shape$lbl.pid" 2>/dev/null)) ---"
  for n in es1 es5 es9; do
    grep -- "$tok" "$OUT/$n.json" 2>/dev/null | head -6 | while IFS= read -r line; do
      pid=$(printf '%s' "$line" | grep -o '"audit_token":{[^}]*}' | grep -o '"pid":[0-9]*' | head -1)
      euid=$(printf '%s' "$line" | grep -o '"audit_token":{[^}]*}' | grep -o '"euid":[0-9]*' | head -1)
      exe=$(printf '%s' "$line" | grep -o '"executable":{.*"path":"[^"]*"' | sed 's/.*"path":"//;s/\\//g' | head -1)
      ev=$(printf '%s' "$line" | grep -o '"event":{"[a-z_]*"' | head -1)
      echo "    $n  $pid $euid  ${ev}  ${exe}"
    done
  done
done

echo
echo "============ fs_usage lines naming each token (command column) ============="
for s in A:A-preexisting-longlived C:C-shortlived-root F:F-shortlived-underload; do
  tok="${s#*:}-$TAG"
  echo "--- ${s%%:*} ---"
  grep -- "$tok" "$OUT/fsu.txt" 2>/dev/null | head -6 | cut -c1-160
done

echo
echo "=================== DID ESLOGGER NAME THE PID? ============================="
printf "%-16s %8s %8s %8s\n" "shape (pid)" "es1" "es5" "es9"
for s in A B C D E F; do
  p=$(cat "$DIR/shape$s.pid" 2>/dev/null)
  [ -z "$p" ] && continue
  row=""
  for n in es1 es5 es9; do
    row="$row $(printf '%8s' "$(grep -c "\"pid\":$p[,}]" "$OUT/$n.json" 2>/dev/null | tr -d ' ')")"
  done
  printf "%-16s%s\n" "$s ($p)" "$row"
done

echo
echo "=============== WHICH PROCESSES DID EACH ESLOGGER ACTUALLY SEE? ============="
for n in es1 es5 es9; do
  tot=$(wc -l < "$OUT/$n.json" 2>/dev/null | tr -d ' ')
  # executable path is the cheapest stable identity in the record; count distinct.
  distinct=$(grep -o '"path":"[^"]*"' "$OUT/$n.json" 2>/dev/null | sort -u | wc -l | tr -d ' ')
  echo "--- $n: $tot records, $distinct distinct path strings; top 15 executables ---"
  grep -o '"executable":{[^}]*"path":"[^"]*"' "$OUT/$n.json" 2>/dev/null \
    | sed 's/.*"path":"//' | sort | uniq -c | sort -rn | head -15
  echo "    first record ts: $(head -1 "$OUT/$n.json" 2>/dev/null | grep -o '"time":"[^"]*"' | head -1)"
  echo "    last  record ts: $(tail -1 "$OUT/$n.json" 2>/dev/null | grep -o '"time":"[^"]*"' | head -1)"
done

echo
echo "=============================== WINDOW ====================================="
for t in t-tracers-started t-window-open t-quiet-done t-load-done t-tracers-stopped; do
  echo "  $t = $(cat "$OUT/$t" 2>/dev/null)"
done

echo
echo "=============== RAW SAMPLE — one es9 record, so the schema is on record ====="
head -1 "$OUT/es9.json" 2>/dev/null | cut -c1-1200

# Keep the raw streams small enough to upload.
for n in es1 es5 es9; do head -c 4000000 "$OUT/$n.json" > "$OUT/$n.head.json"; rm -f "$OUT/$n.json"; done
head -c 4000000 "$OUT/fsu.txt" > "$OUT/fsu.head.txt"; rm -f "$OUT/fsu.txt"
rm -rf "$DIR"
echo "[covctl] DONE"
exit 0
