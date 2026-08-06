#!/usr/bin/env bash
# Smoke-test `measure.sh`'s variable setup WITHOUT a tracer, a jail, or a real install.
#
# ⛔ WHY THIS EXISTS, and it is the macOS lane's reasoning ported unchanged because the hole is the
# same one: `bash -n` checks SYNTAX and is structurally incapable of seeing an unbound-variable
# ORDERING fault, so a `set -u` driver can pass every local gate and still die on its first real
# invocation. On the macOS driver that happened — `JAIL_HOME="$ROOT/jailhome"` was placed beside root
# derivations that run BEFORE `$ROOT` exists, the run died at `ROOT: unbound variable`, and the
# runner published HARNESS-ERROR over two good records. A Linux driver ordering fault would cost the
# same thing, and `measure.sh` has since grown an R7 guard and an R5 check near the top that both
# read variables derived elsewhere.
#
# ⛔ IT IS HERMETIC, AND THAT IS LOAD-BEARING RATHER THAN TIDY. `HOME` is redirected to a throwaway
# directory, so `ROOT`, `JAIL_CACHE`, `GLOBAL_STORE` and every path derived from them land inside it.
# Without that, the driver's per-arm STORE EVICTION would delete entries from the real
# `~/.cache/nub/pm/store` — corrupting whatever measurement happens to be running on the same box.
#
# ⛔ WHAT IT DOES NOT CLAIM. This proves no variable is READ before it is DERIVED along the path the
# stubs allow. It is not a functional test of the driver and cannot be: with a stub tracer there is
# no real trace, so how far past synthesis it reaches depends on what the stub emits. The assertion
# below is on `unbound variable` only, and the reported reach is printed so a regression in COVERAGE
# is visible rather than silent.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DRIVER="$HERE/../../measure.sh"

BIN="$(mktemp -d)"; FAKE_HOME="$(mktemp -d)"
trap 'rm -rf "$BIN" "$FAKE_HOME"' EXIT

# `npm` succeeds and produces the minimal tree the driver reads afterwards.
cat > "$BIN/npm" <<'STUB'
#!/bin/sh
case "$1" in
  install) mkdir -p node_modules/stub-pkg && printf '{"name":"stub-pkg"}' > node_modules/stub-pkg/package.json ;;
esac
exit 0
STUB

# `strace` writes a minimal parseable trace to its `-o` target, so the decoder has something to read
# and the driver can reach its synthesis step rather than dying on a missing file.
cat > "$BIN/strace" <<'STUB'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -V) echo "strace -- version 6.8"; exit 0 ;; *) shift ;; esac
done
[ -n "$out" ] && printf '100 openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\n100 +++ exited with 0 +++\n' > "$out"
exit 0
STUB

# A stub `nub`, so a verify arm exercises its own derivations instead of stopping at a missing binary.
printf '#!/bin/sh\nexit 0\n' > "$BIN/nub-stub"
chmod +x "$BIN/npm" "$BIN/strace" "$BIN/nub-stub"

out="$(PATH="$BIN:$PATH" HOME="$FAKE_HOME" bash "$DRIVER" stub-pkg 1.0.0 "$BIN/nub-stub" 2>&1)"; rc=$?

if printf '%s' "$out" | grep -q 'unbound variable'; then
  echo "FAIL — the driver has an unbound-variable ordering fault:"
  printf '%s\n' "$out" | grep -n 'unbound variable' | head -5
  exit 1
fi

# Report how far the stubs carried it, so a silent LOSS of coverage is visible. A probe that stops
# getting past OBSERVE would otherwise keep printing "ok" while checking almost nothing.
reach="variable setup"
printf '%s' "$out" | grep -q 'OBSERVE '            && reach="OBSERVE"
printf '%s' "$out" | grep -q 'SYNTHESIZED GRANT'   && reach="SYNTHESIZE"
printf '%s' "$out" | grep -q 'VERIFY\['            && reach="VERIFY"
echo "ok — no unbound variable; stubs carried the driver as far as: $reach (driver rc=$rc)"
