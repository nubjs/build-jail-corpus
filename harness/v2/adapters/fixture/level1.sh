# Depth 1, running as `sh`. Performs the PROJECT write as a shell REDIRECT — the write is made by
# this shell process itself, not by any child, which is precisely what fs_usage's default `sh`
# exclusion hides.
#
# The trailing `echo` is load-bearing: `sh` exec-optimises its LAST command over itself, so without
# a statement after the level2 call this process would be REPLACED and the tree would flatten.
PROJ="$1"; FIXHOME="$2"; PORT="$3"; HERE="$4"
echo "level1: depth1 pid=$$ ppid=$PPID comm=sh"
echo 'written by the shell, via redirect' > "$PROJ/project-write.txt"
/bin/sh "$HERE/level2.sh" "$PROJ" "$FIXHOME" "$PORT" "$HERE"
rc=$?
echo "level1: level2 rc=$rc"
exit $rc
