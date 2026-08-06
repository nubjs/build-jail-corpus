#!/bin/bash
# Both-directions validation of the macOS adapter against a fixture whose behaviour is fully known.
#
# TWO ARMS, and the second is the reason to believe the first.
#   full        the fixture performs all five behaviours; every MUST-SEE and MUST-NOT must hold.
#   skip-home   the fixture provably does NOT write under $HOME; the same assertion must now be
#               FALSE. An adapter that passes both arms identically is reporting from imagination,
#               and a probe with no failing control is not evidence of anything.
#
# ⛔ ROOTS ARE NOT UNDER /tmp. That path is inside the jail's private-temp redirect, so a fixture
# placed there cannot test a filesystem claim at all.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "validate-macos.sh must run as root (the TRACER needs it; the fixture does not)"; exit 2; }
REALUSER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
REALHOME="$(dscl . -read "/Users/$REALUSER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -d "$REALHOME" ] || REALHOME="/Users/$REALUSER"
echo "validate: tracer=root fixture-user=$REALUSER home=$REALHOME"

ROOT="$(sudo -u "$REALUSER" mktemp -d "$REALHOME/adapter-val-XXXXXX")" || exit 1
PROJ="$ROOT/project"; FIXHOME="$ROOT/home"
sudo -u "$REALUSER" mkdir -p "$PROJ" "$FIXHOME"

# The fixture reads this and must never be reported as writing it.
sudo -u "$REALUSER" sh -c "printf 'input\n' > '$PROJ/read-only-input.txt'"
# The near-miss target: a SUCCESSFUL openat whose dirfd fs_usage renders as `[ 3]/nearmiss.txt`.
sudo -u "$REALUSER" sh -c "printf 'nearmiss\n' > '$PROJ/nearmiss.txt'"
# Never touched by anything. If it shows up in an event, the adapter is attributing foreign activity.
sudo -u "$REALUSER" sh -c "printf 'untouched\n' > '$PROJ/untouched.txt'"
# The genuine refusal. Mode 000 denies the OWNER too — but only for a non-root opener, which is why
# the fixture is dropped to $REALUSER while the tracer stays root.
sudo -u "$REALUSER" sh -c "printf 'secret\n' > '$PROJ/denied.txt'; chmod 000 '$PROJ/denied.txt'"

clang -O0 -o "$ROOT/fixture" "$HERE/fixture/fixture.c" || { echo "validate: fixture build FAILED"; exit 1; }
cp "$HERE/fixture/run-fixture.sh" "$HERE/fixture/level1.sh" "$HERE/fixture/level2.sh" "$ROOT/"
chmod +x "$ROOT/run-fixture.sh" "$ROOT/level1.sh" "$ROOT/level2.sh" "$ROOT/fixture"
chown -R "$REALUSER" "$ROOT"

# A loopback listener: deterministic, offline, and it exercises the same socket()+connect() path a
# real download would. What it does NOT exercise is DNS — stated in README-macos.md.
PORT=54321
/usr/bin/python3 -c "
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$PORT)); s.listen(8)
sys.stderr.write('listener up\n'); sys.stderr.flush()
while True:
    try: c,_=s.accept(); c.close()
    except Exception: break
" > "$ROOT/listener.log" 2>&1 &
LISTENER=$!
sleep 2

RC_TOTAL=0
for ARM in full skip-home; do
  echo; echo "############ ARM: $ARM ############"
  EV="$ROOT/events-$ARM.ndjson"; DG="$ROOT/diag-$ARM.json"
  SKIPENV=""; [ "$ARM" = "skip-home" ] && SKIPENV="home"
  rm -f "$FIXHOME/home-write.txt" "$PROJ/project-write.txt"

  FIXTURE_SKIP="$SKIPENV" /usr/bin/node "$HERE/macos.mjs" --out "$EV" --diag "$DG" -- \
    "$ROOT/run-fixture.sh" "$PROJ" "$FIXHOME" "$PORT" > "$ROOT/adapter-$ARM.log" 2>&1
  ADAPTER_RC=$?
  echo "adapter rc=$ADAPTER_RC"
  sed 's/^/  | /' "$ROOT/adapter-$ARM.log"

  # Ground truth from the filesystem, independent of the adapter. If the fixture did not actually do
  # what the arm claims, every assertion below is meaningless — so check the artifact first.
  echo "  ground truth: project-write.txt exists=$([ -f "$PROJ/project-write.txt" ] && echo yes || echo no)  home-write.txt exists=$([ -f "$FIXHOME/home-write.txt" ] && echo yes || echo no)"

  /usr/bin/node "$HERE/expect-macos.mjs" "$EV" "$PROJ" "$FIXHOME" "$ARM"
  [ $? -ne 0 ] && RC_TOTAL=1
  echo "  --- events ---"; sed 's/^/  | /' "$EV" | head -40
done

kill $LISTENER 2>/dev/null
echo; echo "############ RESULT ############"
if [ $RC_TOTAL -eq 0 ]; then echo "BOTH ARMS PASSED — adapter validated in both directions"; else echo "VALIDATION FAILED"; fi
echo "artifacts: $ROOT"
exit $RC_TOTAL
