#!/bin/bash
# KNOWN-ANSWER fixture for the `*at`-family hole in the macOS OBSERVE adapter.
#
# The sibling of rename-dest-fixture.sh, and built to the same bar: the control must go RED, or
# nothing may be read off the fix. What differs is where the known answer comes from.
#
# ⛔ THE KNOWN ANSWER IS MEASURED IN THIS RUN, NOT ASSUMED FROM THE SOURCE. A C program that calls
# `mkdirat(2)` N times is only evidence that the SYSCALL fired N times if the libc wrapper really
# routes there — and on Darwin several do not (`utimensat` and `renamex_np` have no dtrace probe at
# all, and `mkfifo` may reach `mknod`). So a third arm counts the syscalls directly with a catch-all
# `syscall:::entry` census, and THAT count is the denominator every capture arm is scored against.
# A fixture whose denominator is its own author's assumption cannot fail for the right reason.
#
#   ARM             what it proves
#   census          how many times each syscall actually fired  (the DENOMINATOR)
#   pre             the shipping-before adapter captures ZERO of the *at family (the control)
#   post            the fixed adapter captures the census count, exactly            (the fix)
#
# A `pre` arm that captures ANY *at record means this fixture is not exercising the hole, and the
# verdict is INCONCLUSIVE rather than a pass — the same refusal rename-dest-fixture.sh makes.
#
# ⛔ NO node IN THE WORKLOAD, DELIBERATELY. The rename-dest probe was invalid on its first run
# because node writes its V8 compile cache on a COLD run only, so arm 1 performed 541 renames and
# arm 2 performed none. A self-contained C program has no such state, so the arms are independent
# by construction rather than by a cache reset that has to be remembered.
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
#   usage: at-family-fixture.sh <workdir>
set -u
WORK="${1:?usage: at-family-fixture.sh <workdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NEW_D="$HERE/../adapters/macos-observe.d"
PRE_D="$HERE/macos-observe-PRE-AT.d"
N=64
mkdir -p "$WORK"

# The ops under test, and the distinctive name prefix each one's path carries. Scoring is
# NAME-ANCHORED: an arm that emitted N unrelated records cannot score N, and two ops can never be
# confused for each other.
OPS="mkdirat unlinkat renameat renameatx_np linkat symlinkat clonefileat fchmodat fchownat mkfifo"

cat > "$WORK/atfix.c" <<'CSRC'
/* Exactly N of each `*at`-family call, every path under AT_FDCWD so a decoder can resolve it, and
 * every path string heap-allocated and written by THIS process immediately before the syscall — so
 * both pages are resident and a copyinstr residency fault is impossible by construction. That is
 * the single variable this fixture removes: whatever is missing is missing for a subscription
 * reason, not a paging one. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if __has_include(<sys/clonefile.h>)
#include <sys/clonefile.h>
#define HAVE_CLONEFILE 1
#endif

static int touch(const char *p) {
	int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) return -1;
	ssize_t w = write(fd, "x", 1); (void)w;
	close(fd);
	return 0;
}

int main(int argc, char **argv) {
	if (argc != 3) { fprintf(stderr, "usage: atfix <workdir> <n>\n"); return 2; }
	const char *w = argv[1];
	int n = atoi(argv[2]);
	int ok_mkdirat = 0, ok_unlinkat = 0, ok_renameat = 0, ok_renameatx = 0, ok_linkat = 0;
	int ok_symlinkat = 0, ok_clonefileat = 0, ok_fchmodat = 0, ok_fchownat = 0, ok_mkfifo = 0;

	for (int i = 0; i < n; i++) {
		char *a = malloc(512), *b = malloc(512);
		if (!a || !b) return 2;

		snprintf(a, 512, "%s/atfix-mkdirat-%04d.d", w, i);
		if (mkdirat(AT_FDCWD, a, 0755) == 0) ok_mkdirat++;

		snprintf(a, 512, "%s/atfix-unlinkat-%04d.f", w, i);
		touch(a);
		if (unlinkat(AT_FDCWD, a, 0) == 0) ok_unlinkat++;

		snprintf(a, 512, "%s/atfix-renameat-src-%04d.f", w, i);
		snprintf(b, 512, "%s/atfix-renameat-dst-%04d.f", w, i);
		touch(a);
		if (renameat(AT_FDCWD, a, AT_FDCWD, b) == 0) ok_renameat++;

		snprintf(a, 512, "%s/atfix-renameatx-src-%04d.f", w, i);
		snprintf(b, 512, "%s/atfix-renameatx-dst-%04d.f", w, i);
		touch(a);
		if (renameatx_np(AT_FDCWD, a, AT_FDCWD, b, 0) == 0) ok_renameatx++;

		snprintf(a, 512, "%s/atfix-linkat-src-%04d.f", w, i);
		snprintf(b, 512, "%s/atfix-linkat-dst-%04d.f", w, i);
		touch(a);
		if (linkat(AT_FDCWD, a, AT_FDCWD, b, 0) == 0) ok_linkat++;

		/* The link CONTENT is deliberately a name that is never created, so if it ever shows up as
		 * a written path it is provably a phantom: nothing on the system could have written it. */
		snprintf(b, 512, "%s/atfix-symlinkat-%04d.l", w, i);
		if (symlinkat("ATFIXSYMTGT_never_created", AT_FDCWD, b) == 0) ok_symlinkat++;

#ifdef HAVE_CLONEFILE
		snprintf(a, 512, "%s/atfix-clonefileat-src-%04d.f", w, i);
		snprintf(b, 512, "%s/atfix-clonefileat-dst-%04d.f", w, i);
		touch(a);
		if (clonefileat(AT_FDCWD, a, AT_FDCWD, b, 0) == 0) ok_clonefileat++;
#endif

		snprintf(a, 512, "%s/atfix-fchmodat-%04d.f", w, i);
		touch(a);
		if (fchmodat(AT_FDCWD, a, 0600, 0) == 0) ok_fchmodat++;

		snprintf(a, 512, "%s/atfix-fchownat-%04d.f", w, i);
		touch(a);
		if (fchownat(AT_FDCWD, a, getuid(), getgid(), 0) == 0) ok_fchownat++;

		snprintf(a, 512, "%s/atfix-mkfifo-%04d.p", w, i);
		if (mkfifo(a, 0644) == 0) ok_mkfifo++;

		free(a); free(b);
	}
	fprintf(stderr, "FIXTURE mkdirat=%d unlinkat=%d renameat=%d renameatx_np=%d linkat=%d "
	        "symlinkat=%d clonefileat=%d fchmodat=%d fchownat=%d mkfifo=%d of %d\n",
	        ok_mkdirat, ok_unlinkat, ok_renameat, ok_renameatx, ok_linkat, ok_symlinkat,
	        ok_clonefileat, ok_fchmodat, ok_fchownat, ok_mkfifo, n);
	return 0;
}
CSRC

cc -O0 -o "$WORK/atfix" "$WORK/atfix.c" > "$WORK/cc.log" 2>&1
CC_RC=$?
if [ "$CC_RC" -ne 0 ]; then
  echo "⛔ cc failed rc=$CC_RC — cannot run the known-answer fixture"
  sed 's/^/     /' "$WORK/cc.log"
  exit 1
fi

cat > "$WORK/census.d" <<'DSC'
#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option dynvarsize=256m
dtrace:::BEGIN { printf("CENSUS-LIVE|target=%d\n", $target); }
syscall:::entry /progenyof($target)/ { @c[probefunc] = count(); }
dtrace:::END { printa("SYSCALL %-24s %@d\n", @c); }
DSC

fresh () { rm -rf "$WORK/run"; mkdir -p "$WORK/run"; }

echo "=================================================================="
echo "KNOWN-ANSWER FIXTURE: the \`*at\` family (N=$N of each op)"
echo "=================================================================="

# ── ARM census: the DENOMINATOR ────────────────────────────────────────────────────────────────
fresh
dtrace -q -s "$WORK/census.d" -o "$WORK/census.txt" -c "$WORK/atfix $WORK/run $N" \
  > "$WORK/census.stderr" 2>&1
CENSUS_RC=$?
echo "ARM census   dtrace_exit=$CENSUS_RC"
grep FIXTURE "$WORK/census.stderr" 2>/dev/null | sed 's/^/    /'
if ! grep -q CENSUS-LIVE "$WORK/census.txt" 2>/dev/null; then
  echo "⛔ the census tracer never started — no arm below has a denominator"
  sed 's/^/     /' "$WORK/census.stderr" | head -20
  exit 1
fi
truth () { awk -v n="$1" '$1=="SYSCALL" && $2==n {print $3}' "$WORK/census.txt" | head -1; }

# ── capture arms ───────────────────────────────────────────────────────────────────────────────
arm () {   # arm <label> <dscript>
  local label="$1" dsc="$2"
  fresh
  dtrace -q -s "$dsc" -o "$WORK/$label.trace" -c "$WORK/atfix $WORK/run $N" \
    > "$WORK/$label.stderr" 2>&1
  echo "ARM $label   dtrace_exit=$?  PATHOP=$(grep -c '^PATHOP|' "$WORK/$label.trace" 2>/dev/null)" \
       " TRACER-ERROR=$(grep -c '^TRACER-ERROR|' "$WORK/$label.trace" 2>/dev/null)"
  grep FIXTURE "$WORK/$label.stderr" 2>/dev/null | sed 's/^/    /'
  grep 'invalid address' "$WORK/$label.stderr" 2>/dev/null | sort | uniq -c | head -3 | sed 's/^/    | /'
}
arm pre  "$PRE_D"
arm post "$NEW_D"

# ⛔ NAME-ANCHORED, NOT A COUNT. Each op is scored against the paths ITS OWN calls created, so an
# arm cannot borrow another op's records, and `$5` (the call name) must match too — a record
# emitted under the wrong call name is a decoder bug, not a capture.
captured () {   # captured <label> <call> <name-prefix>
  grep -E '^PATHOP\|' "$WORK/$1.trace" 2>/dev/null \
    | awk -F'|' -v c="$2" '$5==c {print $NF}' \
    | grep -cE "$3" | tr -d ' '
}

echo
printf '  %-14s %8s %8s %8s   %s\n' OP FIRED PRE POST VERDICT
FAIL=0; CONTROL_RED=1; EXERCISED=0
for op in $OPS; do
  t=$(truth "$op"); t="${t:-0}"
  case "$op" in
    mkdirat)      pat='atfix-mkdirat-' ;;
    unlinkat)     pat='atfix-unlinkat-' ;;
    renameat)     pat='atfix-renameat-(src|dst)-' ;;
    renameatx_np) pat='atfix-renameatx-(src|dst)-' ;;
    linkat)       pat='atfix-linkat-dst-' ;;
    symlinkat)    pat='atfix-symlinkat-' ;;
    clonefileat)  pat='atfix-clonefileat-dst-' ;;
    fchmodat)     pat='atfix-fchmodat-' ;;
    fchownat)     pat='atfix-fchownat-' ;;
    mkfifo)       pat='atfix-mkfifo-' ;;
  esac
  p=$(captured pre "$op" "$pat"); q=$(captured post "$op" "$pat")
  # rename-family calls emit TWO records each (both ends are genuinely mutated), so the expected
  # POST count is 2x the number of times the syscall fired.
  case "$op" in
    renameat|renameatx_np) want=$((t * 2)) ;;
    *)                     want=$t ;;
  esac
  v="ok"
  if [ "$t" -eq 0 ]; then
    v="NOT EXERCISED — the libc wrapper did not reach this syscall on this kernel"
  else
    EXERCISED=$((EXERCISED + 1))
    [ "$p" -gt 0 ] && { v="⛔ CONTROL NOT RED (pre captured $p)"; CONTROL_RED=0; }
    [ "$q" -ne "$want" ] && { v="⛔ POST $q != expected $want"; FAIL=$((FAIL + 1)); }
  fi
  printf '  %-14s %8s %8s %8s   %s\n' "$op" "$t" "$p" "$q" "$v"
done

# The phantom check, carried over from the symlink-target defect: the link CONTENT must never
# appear as a path in any arm.
PHANTOM=$(grep -c 'ATFIXSYMTGT_never_created' "$WORK/post.trace" 2>/dev/null)
echo
echo "  phantom check: the symlinkat CONTENT appears $PHANTOM time(s) in the POST trace (must be 0)"
[ "$PHANTOM" -ne 0 ] && FAIL=$((FAIL + 1))

# The pairing check: renameat must emit a p1 and a p2 for every call, and they must share an `ev`.
P1=$(grep -E '^PATHOP\|' "$WORK/post.trace" 2>/dev/null | awk -F'|' '$5=="renameat"' | grep -c 'role=p1')
P2=$(grep -E '^PATHOP\|' "$WORK/post.trace" 2>/dev/null | awk -F'|' '$5=="renameat"' | grep -c 'role=p2')
EVS=$(grep -E '^PATHOP\|' "$WORK/post.trace" 2>/dev/null | awk -F'|' '$5=="renameat"' \
      | grep -oE 'ev=[0-9]+' | sort | uniq -c | awk '$1==2' | wc -l | tr -d ' ')
echo "  pairing check: renameat p1=$P1 p2=$P2 ; ev values seen exactly twice: $EVS"
[ "$P1" -ne "$P2" ] && { echo "  ⛔ p1/p2 counts disagree — a destination record was lost"; FAIL=$((FAIL + 1)); }

echo "=================================================================="
if [ "$EXERCISED" -eq 0 ]; then
  echo "VERDICT: INCONCLUSIVE — not one target syscall fired, so no arm means anything."
  exit 1
elif [ "$CONTROL_RED" -eq 0 ]; then
  echo "VERDICT: INCONCLUSIVE — the PRE control captured *at records, so it did NOT go red."
  echo "         This fixture is not exercising the hole and nothing may be read off POST."
  exit 1
elif [ "$FAIL" -eq 0 ]; then
  echo "VERDICT: PASS — the control captures none of the $EXERCISED exercised ops, the fix captures"
  echo "         exactly the number of times each syscall fired, and no phantom path appears."
  exit 0
else
  echo "VERDICT: FAIL — $FAIL check(s) did not hold. See the table above."
  exit 1
fi
