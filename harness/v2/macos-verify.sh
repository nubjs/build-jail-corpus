#!/bin/bash
# Run both lifecycle stages even if install fails, then preserve both statuses for the direct-arm
# diagnostic. This is deliberately separate from the dtrace path: tracing observes only `install`.
set -u -o pipefail

arm=$1
nub=$2
cd "$arm" || exit 99

"$nub" install > "$arm/i.log" 2>&1
install_rc=$?
"$nub" approve-builds --all > "$arm/a.log" 2>&1
approve_rc=$?
printf 'install=%s approve=%s\n' "$install_rc" "$approve_rc" > "$arm/verify-status"

[ "$install_rc" -eq 0 ] && [ "$approve_rc" -eq 0 ]
