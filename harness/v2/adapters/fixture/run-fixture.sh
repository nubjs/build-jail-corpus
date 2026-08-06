#!/bin/bash
# The traced ROOT. Everything interesting happens BELOW it, on purpose.
#
#   run-fixture.sh   depth 0   the pid the adapter is given
#     └── level1.sh  depth 1   performs the PROJECT write, as a `>` REDIRECT, from a `sh`
#           └── level2.sh depth 2
#                 └── fixture  depth 3   home write, read, connect, denial, near-miss
#
# Split into real files rather than nested `sh -c` strings because the nesting is the POINT and
# quoting it inline is how it silently stops nesting.
#
# Two things this shape exists to catch:
#
#  1. GRANDCHILD REACH. `dotnet-2.0.0@1.4.4`'s entire story is one syscall inside a bundled yarn that
#     is a grandchild of the postinstall. An adapter that resolves only the direct child reports a
#     clean run for a package that needs a grant.
#
#  2. THE SHELL'S OWN WRITES. `echo > file` is performed by the SHELL PROCESS, not by any child. It
#     is here because `fs_usage` EXCLUDES processes named `sh` and `zsh` BY DEFAULT (source:
#     system_cmds/fs_usage/fs_usage.c, the `if (exclude_pids || argc == 0)` block), so a bare
#     `fs_usage -w -f filesys` cannot see this write at all — a silent undercount of exactly the
#     redirect-writes lifecycle scripts are full of.
set -uo pipefail
PROJ="${1:?usage: run-fixture.sh <projDir> <homeDir> <port>}"
FIXHOME="${2:?}"
PORT="${3:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "run-fixture: depth0 pid=$$ ppid=$PPID"
/bin/sh "$HERE/level1.sh" "$PROJ" "$FIXHOME" "$PORT" "$HERE"
rc=$?
echo "run-fixture: rc=$rc"
exit $rc
