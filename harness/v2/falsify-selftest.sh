#!/usr/bin/env bash
# Does the falsification control itself still work?
#
#   usage: falsify-selftest.sh <nub-binary>
#   exit 0 = falsify.mjs went RED against a deliberately broken driver, for the right reasons
#   exit 1 = ⛔ falsify.mjs passed a driver that cannot detect a wrong grant — the oracle is blind
#
# ⛔ AN ORACLE THAT HAS NEVER GONE RED IS THE THING IT EXISTS TO CATCH. `falsify.mjs` proves the
# HARNESS can reject a known-insufficient grant; this proves `falsify.mjs` can notice when it stops
# being able to. Without this, the falsification control is just one more check that passes — which
# is the exact shape of the three failures FALSIFICATION.md records.
#
# THE MUTATION models the real `|| (exit 0)` failure: the lifecycle script's non-zero exit never
# reaches the driver. One line, in `verify()`, so nothing else about the driver moves.
#
# ⛔ THE COPY MUST LIVE BESIDE `measure.sh`. The driver resolves `artifact-gate.mjs` through
# `$HERE`, so a copy under /tmp fails the gate for a reason that has nothing to do with the
# mutation and would make this self-test pass for the wrong reason.
#
# ⛔ AND THE TWO CASES MUST GO RED DIFFERENTLY, WHICH IS WHY BOTH ARE ASSERTED SEPARATELY:
#   @apollo/rover  the artifact gate already passes its wrong arm (the artifact lands in a SIBLING
#                  package), so suppressing rc leaves NOTHING to catch it -> the driver reports
#                  SUFFICIENT and falsify must raise the P0 line.
#   hugo-extended  the gate still catches it, so the verdict stays INSUFFICIENT -> falsify must
#                  fail it on the LOST DETECTOR instead.
# A self-test that only checked the exit code would pass even if the second assertion had rotted.
set -uo pipefail
NUB="${1:?usage: falsify-selftest.sh <nub-binary>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/measure.sh"
DST="$HERE/.measure-sabotaged.sh"

trap 'rm -f "$DST"' EXIT

n=$(grep -c '^  local rc=\$?$' "$SRC")
if [ "$n" -ne 1 ]; then
  echo "⛔ expected exactly one '  local rc=\$?' line in measure.sh, found $n."
  echo "   The mutation target moved; re-point it rather than deleting this self-test."
  exit 2
fi
sed 's|^  local rc=\$?$|  local rc=$?; rc=0   # SABOTAGE: the install exit code never reaches the driver|' \
  "$SRC" > "$DST"
changed=$(diff "$SRC" "$DST" | grep -c '^[<>]')
if [ "$changed" -ne 2 ]; then
  echo "⛔ the mutation changed $changed diff lines, expected 2 (one out, one in) — not a one-line change"
  exit 2
fi
echo "selftest: mutated driver at $DST (1 line: install rc suppressed)"

out=$(node "$HERE/falsify.mjs" --nub "$NUB" --driver "$DST" --quick 2>&1); rc=$?
printf '%s\n' "$out" | sed 's/^/  | /'

fails=0
if [ "$rc" -eq 0 ]; then
  echo "⛔⛔ falsify.mjs PASSED a driver that cannot detect a wrong grant. The oracle is blind;"
  echo "    every green falsify run since it last worked is worthless."
  fails=1
fi
printf '%s' "$out" | grep -q 'P0: the harness reported a KNOWN-INSUFFICIENT grant as SUFFICIENT' || {
  echo "⛔ no P0 line — the rover case did not report the suppressed-rc arm as a false SUFFICIENT"
  fails=1
}
printf '%s' "$out" | grep -q "detector 'rc' did not fire" || {
  echo "⛔ no lost-detector line — the hugo case did not notice that rc had stopped catching it"
  fails=1
}

if [ "$fails" -ne 0 ]; then echo "selftest: ⛔ FAIL"; exit 1; fi
echo "selftest: PASS — falsify.mjs went red against the broken driver, on both of its two mechanisms"
