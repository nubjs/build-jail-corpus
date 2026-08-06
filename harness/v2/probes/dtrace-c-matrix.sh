#!/bin/bash
# Why does `dtrace -c "/bin/sh <wrapper>"` produce a child that never completes?
#
# Single-variable matrix. Every arm runs the SAME wrapper shape — narrate, then write a sentinel —
# and varies exactly one of: dtrace present, the shell binary, `-x`, an inner `sudo -u`, the D
# script, and whether the body is real work. The sentinel is the answer: it exists iff the wrapper
# reached its last line. The wrapper narrates to its OWN file as well as to stderr, so "dtrace.log
# was empty" can be told apart from "the wrapper never ran".
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
set -u
WORK="${1:?usage: dtrace-c-matrix.sh <workdir>}"
RUNUSER="${SUDO_USER:-$(id -un)}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OBSERVE_D="$HERE/../adapters/macos-observe.d"
mkdir -p "$WORK"

# An UNSIGNED copy of /bin/sh: a copy loses the code signature, so if the platform binary's
# signature or its restrictions are what dtrace trips over, this arm is the one that diverges.
cp /bin/sh "$WORK/mysh" 2>/dev/null; chmod +x "$WORK/mysh" 2>/dev/null

cat > "$WORK/min.d" <<'MIND'
#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=32m
#pragma D option dynvarsize=64m

dtrace:::BEGIN { printf("MIN-LIVE|target=%d\n", $target); }
proc:::exec-success /progenyof($target)/
{ printf("EXEC|pid=%d|ppid=%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs); }
proc:::exit /progenyof($target)/
{ printf("PEXIT|pid=%d|%s|arg0=%d\n", pid, execname, (int)arg0); }
/* No predicate: a kill from OUTSIDE the tree (dtrace itself, the kernel) is exactly the case a
 * progenyof() predicate on the SENDER would hide. Correlate by pid against the EXEC lines. */
proc:::signal-send
{ printf("SIGSEND|from=%d(%s)|to=%d(%s)|sig=%d\n",
    pid, execname, args[1]->pr_pid, stringof(args[1]->pr_fname), args[2]); }
dtrace:::END { printf("MIN-END\n"); }
MIND

cat > "$WORK/min-nosig.d" <<'MIND2'
#pragma D option quiet
dtrace:::BEGIN { printf("MIN-LIVE|target=%d\n", $target); }
proc:::exec-success /progenyof($target)/
{ printf("EXEC|pid=%d|ppid=%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs); }
dtrace:::END { printf("MIN-END\n"); }
MIND2

dtrace -e -s "$WORK/min.d" -c /usr/bin/true > "$WORK/mind-compile.log" 2>&1
MIND_RC=$?
if [ "$MIND_RC" -ne 0 ]; then
  echo "NOTE: min.d did not compile (rc=$MIND_RC); falling back to min-nosig.d"
  sed -n '1,6p' "$WORK/mind-compile.log" | sed 's/^/     /'
  MIN_D="$WORK/min-nosig.d"
else
  MIN_D="$WORK/min.d"
fi
echo "instrument: $MIN_D"

SUDO_BODY='sudo -u '"$RUNUSER"' -H env "PATH=$PATH" /usr/bin/true'
NOSUDO_BODY='/usr/bin/true'

# mkwrapper <arm-name> <body>  -> writes $WORK/w-<arm>.sh, whose sentinel is $WORK/<arm>.SENTINEL
mkwrapper () {
  local n="$1" body="$2" f="$WORK/w-$1.sh"
  rm -f "$WORK/$n.SENTINEL"
  : > "$WORK/$n.wtrace"
  {
    printf 'echo "W-START pid=$$ uid=$(id -u)" >> "%s/%s.wtrace"\n' "$WORK" "$n"
    printf 'echo "W-START" >&2\n'
    printf '%s\n' "$body"
    printf 'B=$?\n'
    printf 'echo "W-BODY-RC=$B" >> "%s/%s.wtrace"\n' "$WORK" "$n"
    printf 'echo "W-BODY-RC=$B" >&2\n'
    printf 'echo "$B" > "%s/%s.SENTINEL"\n' "$WORK" "$n"
    printf 'echo "W-END" >> "%s/%s.wtrace"\n' "$WORK" "$n"
  } > "$f"
}

# run_arm <arm-name> <use-dtrace:0|1> <dscript-or-dash> <cmd...>
run_arm () {
  local name="$1" usedt="$2" dsc="$3"; shift 3
  local d="$WORK/$name.stderr" t="$WORK/$name.trace"
  local t0 t1 rc
  t0=$(python3 -c 'import time;print(time.time())' 2>/dev/null || date +%s)
  if [ "$usedt" = "1" ]; then
    dtrace -q -s "$dsc" -o "$t" -c "$*" > "$d" 2>&1
    rc=$?
  else
    "$@" > "$d" 2>&1
    rc=$?
  fi
  t1=$(python3 -c 'import time;print(time.time())' 2>/dev/null || date +%s)
  local sent="ABSENT" srcv="-"
  if [ -f "$WORK/$name.SENTINEL" ]; then sent="PRESENT"; srcv=$(cat "$WORK/$name.SENTINEL"); fi
  local wl=0 dl=0 tl=0
  [ -f "$WORK/$name.wtrace" ] && wl=$(wc -l < "$WORK/$name.wtrace" | tr -d ' ')
  [ -f "$d" ] && dl=$(wc -l < "$d" | tr -d ' ')
  [ -f "$t" ] && tl=$(wc -l < "$t" | tr -d ' ')
  echo "------------------------------------------------------------------"
  echo "ARM $name"
  echo "  cmd           : $*"
  echo "  outer_exit    : $rc"
  echo "  SENTINEL      : $sent (body rc=$srcv)"
  echo "  wrapper trace : $wl lines -> $(tr '\n' ';' < "$WORK/$name.wtrace" 2>/dev/null)"
  echo "  child stderr  : $dl lines"
  sed 's/^/      | /' "$d" 2>/dev/null | head -12
  echo "  dtrace trace  : $tl lines"
  if [ "$tl" -gt 0 ]; then
    grep -E 'MIN-LIVE|DTRACE-LIVE|EXEC\||PEXIT|SIGSEND' "$t" 2>/dev/null | head -20 | sed 's/^/      > /'
  fi
  echo "  elapsed       : $(python3 -c "print(round($t1-$t0,3))" 2>/dev/null || echo '?')s"
}

echo "=================================================================="
echo "MATRIX: dtrace -c child completion.  runuser=$RUNUSER  uid=$(id -u)"
echo "=================================================================="

# 1-2. POSITIVE CONTROLS — no dtrace at all. If these fail, dtrace is exonerated.
mkwrapper ctl-direct-nosudo "$NOSUDO_BODY"; run_arm ctl-direct-nosudo 0 - /bin/sh -x "$WORK/w-ctl-direct-nosudo.sh"
mkwrapper ctl-direct-sudo   "$SUDO_BODY";   run_arm ctl-direct-sudo   0 - /bin/sh -x "$WORK/w-ctl-direct-sudo.sh"

# 3. does `-c` work at all?
run_arm dt-true 1 "$MIN_D" /usr/bin/true

# 4-6. shell + -x + sudo, one variable at a time
mkwrapper dt-sh-nosudo   "$NOSUDO_BODY"; run_arm dt-sh-nosudo   1 "$MIN_D" /bin/sh    "$WORK/w-dt-sh-nosudo.sh"
mkwrapper dt-sh-x-nosudo "$NOSUDO_BODY"; run_arm dt-sh-x-nosudo 1 "$MIN_D" /bin/sh -x "$WORK/w-dt-sh-x-nosudo.sh"
mkwrapper dt-sh-x-sudo   "$SUDO_BODY";   run_arm dt-sh-x-sudo   1 "$MIN_D" /bin/sh -x "$WORK/w-dt-sh-x-sudo.sh"

# 7-8. a different shell, and an UNSIGNED copy of /bin/sh
mkwrapper dt-bash-x-sudo "$SUDO_BODY"; run_arm dt-bash-x-sudo 1 "$MIN_D" /bin/bash   -x "$WORK/w-dt-bash-x-sudo.sh"
mkwrapper dt-mysh-x-sudo "$SUDO_BODY"; run_arm dt-mysh-x-sudo 1 "$MIN_D" "$WORK/mysh" -x "$WORK/w-dt-mysh-x-sudo.sh"

# 9-10. the REAL observe D script — isolates the D script from the `-c` mechanism
mkwrapper dt-obs-sudo   "$SUDO_BODY";   run_arm dt-obs-sudo   1 "$OBSERVE_D" /bin/sh -x "$WORK/w-dt-obs-sudo.sh"
mkwrapper dt-obs-nosudo "$NOSUDO_BODY"; run_arm dt-obs-nosudo 1 "$OBSERVE_D" /bin/sh -x "$WORK/w-dt-obs-nosudo.sh"

# 11. REPEATABILITY. The live evidence is non-deterministic — 2 of 6 arms narrated, 4 did not — so
#     a single green arm above proves nothing.
echo "=================================================================="
echo "REPEATABILITY: dt-sh-x-sudo x8 (min.d) then dt-obs-sudo x8 (observe.d)"
echo "=================================================================="
for tag in min obs; do
  D="$MIN_D"; [ "$tag" = "obs" ] && D="$OBSERVE_D"
  P=0
  for i in 1 2 3 4 5 6 7 8; do
    mkwrapper rep "$SUDO_BODY"
    dtrace -q -s "$D" -o "$WORK/rep-$tag-$i.trace" -c "/bin/sh -x $WORK/w-rep.sh" > "$WORK/rep-$tag-$i.log" 2>&1
    RC=$?
    S=ABSENT
    if [ -f "$WORK/rep.SENTINEL" ]; then S=PRESENT; P=$((P+1)); fi
    echo "  $tag rep$i dtrace_exit=$RC sentinel=$S wtrace=$(wc -l < "$WORK/rep.wtrace" | tr -d ' ') stderr=$(wc -l < "$WORK/rep-$tag-$i.log" | tr -d ' ')"
    grep -E 'SIGSEND' "$WORK/rep-$tag-$i.trace" 2>/dev/null | grep -vE 'sig=0' | head -4 | sed 's/^/       > /'
  done
  echo "  REPEATABILITY[$tag]: $P / 8 sentinels present"
done

echo "=================================================================="
echo "MATRIX DONE"
