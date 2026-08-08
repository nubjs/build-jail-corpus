#!/usr/bin/env bash
# Sourced by the POSIX v2 drivers. A screen has exactly three outcomes: cleared, terminal malicious
# refusal, or harness error. Callers never turn an unavailable/partial OSV answer into a clean tree.

SECURITY_CACHE="$ROOT/security/clearances"

security_screen_run () {
  local label="$1"; shift
  local out="$ROOT/security/$label.json"
  node "$HERE/../osv-screen.mjs" "$@" --kind "$label" --cache-dir "$SECURITY_CACHE" --out "$out"
  local rc=$?
  case "$rc" in
    0) return 0 ;;
    42)
      # osv-screen already printed the terminal `=> REFUSED-MALICIOUS` line parsed by record.mjs.
      exit 0
      ;;
    *)
      echo "  => HARNESS-ERROR: fail-closed OSV $label screen did not complete (rc=$rc); no lifecycle script ran"
      exit 1
      ;;
  esac
}

security_screen_direct () {
  security_screen_run direct --spec "$1"
}

security_screen_tree () {
  local project="$1" label="$2"
  security_screen_run "$label" --tree "$project"
}
