#!/bin/bash
# dtrace COVERAGE + CONTRACT control for macOS. The mirror image of es-coverage-control.sh, run
# against the same six process shapes so the two tables can be read side by side.
#
# Context: eslogger was MEASURED, twice, to name none of the six shapes — the only records carrying
# our tokens were Spotlight (mds/mdworker_shared) indexing the files afterwards. Every previous
# "dtrace is refused" measurement in this effort came from a SIP-ENABLED local Mac. A hosted runner
# reports SIP DISABLED, and nobody has tried dtrace there. If dtrace runs and attributes correctly,
# macOS gets the strace-equivalent the Linux lane already has.
#
# Runs as root. Never exits non-zero on a negative answer — a negative answer IS the deliverable.
set +e

OUT="${1:?usage: dtrace-coverage-control.sh <outdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
TAG="dt$(date +%s)$$"
DIR="$HOME/dtctl-$TAG"
mkdir -p "$DIR"

say() { echo "[dtctl] $*"; }

echo "=============================== HOST FACTS ================================="
say "tag=$TAG dir=$DIR uid=$(id -u) sudo_user=${SUDO_USER:-none}"
echo "--- csrutil status (VERBATIM) ---"
csrutil status 2>&1
echo "--- end csrutil ---"
say "dtrace: $(command -v dtrace || echo MISSING)"
say "fs_usage: $(command -v fs_usage || echo MISSING)"
sysctl kern.dtrace.dof_mode 2>&1 | sed 's/^/[dtctl] /'
sysctl security.mac.amfi 2>&1 | sed 's/^/[dtctl] /'

# ---------------------------------------------------------------------------
# GATE 1 — does dtrace run AT ALL? If this is refused the hypothesis is dead and everything
# downstream is noise, so it is reported on its own and the script says so explicitly.
# ---------------------------------------------------------------------------
echo
echo "=============================== GATE 1: dtrace hello ======================="
dtrace -n 'BEGIN { trace("hello"); exit(0); }' > "$OUT/hello.out" 2> "$OUT/hello.err"
HELLO_RC=$?
echo "HELLO_RC=$HELLO_RC"
echo "--- stdout ---"; cat "$OUT/hello.out"
echo "--- stderr ---"; cat "$OUT/hello.err"

if [ "$HELLO_RC" -ne 0 ]; then
  echo
  echo "VERDICT: dtrace REFUSED on this host. Hypothesis DEAD. Nothing below would mean anything."
  rm -rf "$DIR"
  exit 0
fi

# A second gate: `hello` only proves the BEGIN probe fires. The syscall provider is a separate
# thing and is what the whole design rests on, so prove it independently before the real run.
echo
echo "=============================== GATE 2: syscall provider ==================="
dtrace -n 'syscall::open*:entry { @[execname] = count(); } tick-3s { exit(0); }' \
  > "$OUT/gate2.out" 2> "$OUT/gate2.err"
G2_RC=$?
echo "GATE2_RC=$G2_RC"
head -20 "$OUT/gate2.out"
head -20 "$OUT/gate2.err"

# ---------------------------------------------------------------------------
# GATE 3 — does the real D script COMPILE? `-e` compiles and exits without enabling anything, so a
# syntax error is caught here rather than costing the whole run. If it does not compile the probe
# falls back to a stripped inline script: a partial answer on this push beats a full answer two
# pushes from now, and the fallback deliberately keeps the pid/ppid attribution question intact,
# which is the one thing the run exists to answer.
# ---------------------------------------------------------------------------
echo
echo "=============================== GATE 3: D script compiles =================="
dtrace -e -s "$HERE/macos-dtrace.d" "$TAG" > "$OUT/gate3.out" 2> "$OUT/gate3.err"
G3_RC=$?
echo "GATE3_RC=$G3_RC"
cat "$OUT/gate3.err"
DSCRIPT="$HERE/macos-dtrace.d"
if [ "$G3_RC" -ne 0 ]; then
  echo "D SCRIPT DID NOT COMPILE — falling back to the stripped inline script."
  cat > "$OUT/fallback.d" <<'EOD'
#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=32m
#pragma D option strsize=1024
dtrace:::BEGIN { printf("DTRACE-LIVE|filter=%s\n", $$1); }
syscall::open*:entry  { self->p = copyinstr(arg0); self->fl = arg1; self->on = 1; }
syscall::open*:return /self->on && strstr(self->p, $$1) != NULL/
{ printf("OPEN|%d|%d|%s|flags=0x%x|ret=%d|errno=%d|%s\n", pid, ppid, execname,
    (int)self->fl, (int)arg0, (int)arg0 < 0 ? errno : 0, self->p); }
syscall::open*:return { self->on = 0; self->p = 0; self->fl = 0; }
syscall::connect*:entry { printf("CONN-ENTRY|%d|%d|%s|len=%d\n", pid, ppid, execname, (int)arg2); }
dtrace:::END { printf("DTRACE-END\n"); }
EOD
  DSCRIPT="$OUT/fallback.d"
  dtrace -e -s "$DSCRIPT" "$TAG" 2>&1 | head -10
fi
echo "USING D SCRIPT: $DSCRIPT"

# ---------------------------------------------------------------------------
# SHAPE A — pre-existing long-lived process, started BEFORE the tracer. This is the shape the
# eslogger adapter's own node process took, and ES never named it.
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
# THE TRACER. fs_usage runs alongside as the known-good comparator, exactly as in the ES control.
# ---------------------------------------------------------------------------
dtrace -s "$DSCRIPT" "$TAG" > "$OUT/dt.txt" 2> "$OUT/dt.err" &
PD=$!
fs_usage -w -f filesys > "$OUT/fsu.txt" 2> "$OUT/fsu.err" &
PF=$!
say "tracers: dtrace=$PD fs_usage=$PF"

# Fixed wall-clock warmup. A readiness poll obscured this once already.
sleep 12
grep -q 'DTRACE-LIVE' "$OUT/dt.txt" 2>/dev/null \
  && say "dtrace reported LIVE" || say "WARNING: no DTRACE-LIVE line yet"
date +%H:%M:%S.%N > "$OUT/t-window-open"

# ---------------------------------------------------------------------------
# THE SIX SHAPES — byte-for-byte the same set es-coverage-control.sh used.
# ---------------------------------------------------------------------------

# A — released by the trigger
touch "$DIR/go"
sleep 2

# B — long-lived shell STARTED AFTER the tracer was live
(
  echo "$BASHPID" > "$DIR/shapeB.pid"
  sleep 1
  echo x > "$DIR/B-postlived-$TAG.txt"
  sleep 20
) &
SHAPE_B_BG=$!
sleep 3

# C — short-lived `/bin/sh -c` as ROOT. THE shape an npm lifecycle script takes.
/bin/sh -c "echo \$\$ > $DIR/shapeC.pid; echo x > $DIR/C-shortlived-root-$TAG.txt"
sleep 1

# D — the same, as the ORIGINAL NON-ROOT USER. Isolates uid from lifetime.
if [ -n "${SUDO_USER:-}" ]; then
  chmod 777 "$DIR"
  sudo -u "$SUDO_USER" /bin/sh -c "echo \$\$ > $DIR/shapeD.pid; echo x > $DIR/D-shortlived-user-$TAG.txt"
fi
sleep 1

# E — this script's OWN shell, plain redirect, no fork at all.
echo $$ > "$DIR/shapeE.pid"
echo x > "$DIR/E-selfshell-$TAG.txt"
sleep 2

# F — the C shape again, under 4-way filesystem load. dtrace has bounded per-cpu buffers and DROPS
# rather than blocks, same failure class ES has; if C is seen and F is not, that is the mechanism.
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
# CONTRACT PROBES — the three EVENT fields that neither existing macOS source can supply.
# Each one is a POSITIVE control paired with its negative, so a field reported as "covered" has
# been shown to differ between the two arms rather than merely being present.
# ---------------------------------------------------------------------------

# (1) WRITE INTENT. A read-open and a write-open of the same path must differ in the flags field.
cat > "$DIR/G-intent-$TAG.txt" <<< "seed"
/bin/sh -c "cat $DIR/G-intent-$TAG.txt > /dev/null"          # read-open  -> O_RDONLY (0)
/bin/sh -c "echo more >> $DIR/G-intent-$TAG.txt"             # write-open -> O_WRONLY|O_APPEND
sleep 1

# (2) REFUSAL as a numeric errno. root bypasses mode bits, so the denied arm MUST run as the
# unprivileged user; without that the "denied" cell can never go red and the probe proves nothing.
: > "$DIR/H-denied-$TAG.txt"
chmod 000 "$DIR/H-denied-$TAG.txt"
: > "$DIR/H-allowed-$TAG.txt"
chmod 666 "$DIR/H-allowed-$TAG.txt"
if [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$SUDO_USER" /bin/sh -c "cat $DIR/H-denied-$TAG.txt"  2>/dev/null
  sudo -u "$SUDO_USER" /bin/sh -c "cat $DIR/H-allowed-$TAG.txt" 2>/dev/null
fi
sleep 1

# (3) TCP PEER. A real outbound connect to a known address, plus a connect that is REFUSED, so the
# host/port fields and the connect errno are both exercised.
/bin/sh -c "printf '' | nc -w 3 -G 3 1.1.1.1 443 >/dev/null 2>&1"
/bin/sh -c "printf '' | nc -w 2 -G 2 127.0.0.1 9 >/dev/null 2>&1"
/usr/bin/curl -s -m 5 -o /dev/null https://registry.npmjs.org/ 2>/dev/null
sleep 2

date +%H:%M:%S.%N > "$OUT/t-quiet-done"

# ---------------------------------------------------------------------------
# TEARDOWN. SIGTERM, never SIGINT: eslogger was MEASURED to ignore SIGINT off the foreground
# process group. dtrace flushes its aggregations from the END probe, so a SIGKILL here would
# discard the entire breadth control.
# ---------------------------------------------------------------------------
for p in $PD $PF; do kill -TERM "$p" 2>/dev/null; done
for p in $PD $PF; do
  for _ in $(seq 1 100); do kill -0 "$p" 2>/dev/null || break; sleep 0.2; done
  kill -0 "$p" 2>/dev/null && { say "tracer $p did NOT exit cleanly; SIGKILL"; kill -9 "$p" 2>/dev/null; }
done
kill -9 $SHAPE_A_BG $SHAPE_B_BG 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
echo
echo "=============================== GROUND TRUTH ==============================="
for s in A B C D E F; do
  echo "  shape$s pid=$(cat "$DIR/shape$s.pid" 2>/dev/null || echo NONE)"
done
echo "  dtrace stream lines: $(wc -l < "$OUT/dt.txt" 2>/dev/null | tr -d ' ')"
echo "  fs_usage lines:      $(wc -l < "$OUT/fsu.txt" 2>/dev/null | tr -d ' ')"
echo "--- dt.err (dtrace drops and errors are reported HERE, not in the stream) ---"
head -40 "$OUT/dt.err"

echo
echo "======== DID DTRACE REPORT IT, AND WITH THE CORRECT PID? =================="
echo "PASS requires BOTH: a line naming the token, AND that line's pid == the shape's own pid."
printf "%-38s %8s %10s %10s %8s\n" "shape / token" "dt_lines" "dt_ownpid" "verdict" "fs_usage"
for s in A:A-preexisting-longlived B:B-postlived C:C-shortlived-root \
         D:D-shortlived-user E:E-selfshell F:F-shortlived-underload; do
  lbl="${s%%:*}"; tok="${s#*:}-$TAG"
  own=$(cat "$DIR/shape$lbl.pid" 2>/dev/null)
  n=$(grep -c -- "$tok" "$OUT/dt.txt" 2>/dev/null | tr -d ' ')
  # field 2 of an OPEN| line is the reporting pid.
  m=0
  [ -n "$own" ] && m=$(grep -- "$tok" "$OUT/dt.txt" 2>/dev/null | awk -F'|' -v p="$own" '$2==p' | wc -l | tr -d ' ')
  f=$(grep -c -- "$tok" "$OUT/fsu.txt" 2>/dev/null | tr -d ' ')
  v="MISS"
  [ "$n" -gt 0 ] && v="SEEN-WRONGPID"
  [ "${m:-0}" -gt 0 ] && v="PASS"
  printf "%-38s %8s %10s %10s %8s\n" "$lbl $tok" "$n" "${m:-0}" "$v" "$f"
done

echo
echo "======== THE ACTUAL LINES (so a count can never stand in for attribution) =="
for s in A B C D E F; do
  own=$(cat "$DIR/shape$s.pid" 2>/dev/null)
  echo "--- shape $s (own pid ${own:-NONE}) ---"
  grep -- "-$TAG" "$OUT/dt.txt" 2>/dev/null | grep -- "/$s-" | head -6
done

echo
echo "======== CONTRACT FIELD 1: WRITE INTENT (flags must DIFFER between arms) ==="
grep -- "G-intent-$TAG" "$OUT/dt.txt" 2>/dev/null | head -12

echo
echo "======== CONTRACT FIELD 2: REFUSAL (denied arm must carry a nonzero errno) ="
echo "--- denied (mode 000, opened as $SUDO_USER; EACCES=13 expected) ---"
grep -- "H-denied-$TAG" "$OUT/dt.txt" 2>/dev/null | head -8
echo "--- allowed (mode 666, same user; errno must be 0) ---"
grep -- "H-allowed-$TAG" "$OUT/dt.txt" 2>/dev/null | head -8
echo "--- fs_usage on the denied file, for comparison ---"
grep -- "H-denied-$TAG" "$OUT/fsu.txt" 2>/dev/null | head -4 | cut -c1-160

echo
echo "======== CONTRACT FIELD 3: TCP PEER (host + port from the sockaddr) ========"
grep '^CONN|' "$OUT/dt.txt" 2>/dev/null | head -30
echo "--- how many CONN records total: $(grep -c '^CONN|' "$OUT/dt.txt" 2>/dev/null) ---"
echo "--- fs_usage connect lines, for comparison (FMT_FD: fd + errno, no sockaddr) ---"
grep -i 'connect' "$OUT/fsu.txt" 2>/dev/null | head -6 | cut -c1-160

echo
echo "======== CONTRACT FIELD 4: EXEC (pid, ppid, argv) ========================="
grep '^EXEC|' "$OUT/dt.txt" 2>/dev/null | grep -c '' | sed 's/^/  total EXEC records: /'
grep '^EXEC|' "$OUT/dt.txt" 2>/dev/null | grep -E "$TAG|/bin/sh" | head -12

echo
echo "======== BREADTH CONTROL — what dtrace saw system-wide ===================="
sed -n '/all opens by execname/,$p' "$OUT/dt.txt" 2>/dev/null | head -30

echo
echo "======== RAW HEAD/TAIL of the dtrace stream =============================="
head -5 "$OUT/dt.txt"
echo "  ..."
tail -5 "$OUT/dt.txt"

# Keep the artifacts uploadable.
head -c 4000000 "$OUT/fsu.txt" > "$OUT/fsu.head.txt"; rm -f "$OUT/fsu.txt"
rm -rf "$DIR"
echo "[dtctl] DONE"
exit 0
