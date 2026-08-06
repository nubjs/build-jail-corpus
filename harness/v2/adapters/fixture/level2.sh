# Depth 2. Exists only to put the fixture at depth 3, so an adapter that resolves the direct child —
# or the child and grandchild — fails here loudly instead of silently in the corpus.
#
# The trailing `echo` prevents `sh` from exec-optimising the fixture over this process. Without it
# the fixture lands at depth 2 and the test is weaker than it reads.
PROJ="$1"; FIXHOME="$2"; PORT="$3"; HERE="$4"
echo "level2: depth2 pid=$$ ppid=$PPID comm=sh"
"$HERE/fixture" "$PROJ" "$FIXHOME" "$PROJ/read-only-input.txt" "$PORT"
rc=$?
echo "level2: fixture rc=$rc"
exit $rc
