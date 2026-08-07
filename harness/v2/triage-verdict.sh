#!/usr/bin/env bash
# Triage a NO-STATE-PASSED record: is it the HARNESS or a GENUINE nub failure?
# Discriminant: does a plain `nub install` + `approve-builds` succeed, jailed and unjailed?
#   both rc=0            -> HARNESS artifact (the verify arm, e.g. the double-run)
#   both rc=1            -> GENUINE nub failure (compare npm to see if nub is at fault)
#   jailed 1, unjailed 0 -> a REAL jail capability finding (the only case that touches the catalog)
export PATH=$HOME/node/bin:$PATH
NUB=~/nub-catalog-override.bin
SPEC="$1"; PKG="${SPEC%@*}"; VER="${SPEC##*@}"
[ "${SPEC:0:1}" = "@" ] && { PKG="@${SPEC:1}"; PKG="${PKG%@*}"; }
echo "### $PKG@$VER"
for mode in JAIL-ON JAIL-OFF; do
  d=$(mktemp -d /tmp/tri-XXXX); cd $d
  printf '{"name":"p","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$PKG" "$VER" > package.json
  [ $mode = JAIL-OFF ] && printf '{"install":{"buildJail":false}}\n' > nub.jsonc
  $NUB install > i.log 2>&1; irc=$?
  $NUB approve-builds --all > a.log 2>&1; arc=$?
  printf '  %-9s install=%s approve=%s' "$mode" "$irc" "$arc"
  grep -q 'ran .*install\|ran postinstall' i.log && printf ' [script ran in INSTALL too]'
  echo
  [ $arc -ne 0 ] && grep -m1 -E 'Cannot find module|error:|× lifecycle' a.log | sed 's/^/      /'
done
d=$(mktemp -d /tmp/trinpm-XXXX); cd $d
npm install --no-audit --no-fund "$PKG@$VER" > n.log 2>&1
echo "  npm        rc=$?"
