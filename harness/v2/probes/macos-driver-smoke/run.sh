#!/usr/bin/env bash
# Smoke-test measure-macos.sh's variable setup WITHOUT a runner, a tracer or root.
#
# ⛔ WHY THIS EXISTS. `bash -n` checks SYNTAX and cannot see an unbound-variable ORDERING fault, so a
# `set -u` driver can pass every local gate and still die on its first real invocation. That happened:
# `JAIL_HOME="$ROOT/jailhome"` was placed beside the other root derivations, which run BEFORE `$ROOT`
# is created, and the run died at `line 86: ROOT: unbound variable` — clobbering two good published
# records with HARNESS-ERROR. The evidence survived only because the raw archives are retained.
#
# The driver is stubbed down to the point where it would need dtrace, which is as far as a Mac
# without root can go. That is enough: every variable derivation happens before then.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRIVER="$HERE/../../measure-macos.sh"
BIN="$(mktemp -d)"; trap 'rm -rf "$BIN"' EXIT
# Stubs. `dtrace` is the wall we expect to hit; everything before it must succeed.
for c in dtrace sudo npm dscl sw_vers csrutil chown; do
  printf '#!/bin/sh\nexit 0\n' > "$BIN/$c"; chmod +x "$BIN/$c"
done
printf '#!/bin/sh\necho /Users/%s\n' "$(id -un)" > "$BIN/dscl"; chmod +x "$BIN/dscl"
out="$(PATH="$BIN:$PATH" bash "$DRIVER" some-pkg 1.0.0 2>&1)"; rc=$?
if printf '%s' "$out" | grep -qE 'unbound variable|command not found: *$'; then
  echo "FAIL — the driver has an unbound-variable ordering fault:"
  printf '%s\n' "$out" | grep -E 'unbound variable' | head -3
  exit 1
fi
echo "ok — no unbound variable through variable setup (driver rc=$rc)"
