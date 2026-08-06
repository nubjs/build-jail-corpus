#!/bin/bash
# KNOWN-ANSWER fixture for the truncated-`self->np2` defect: the rename DESTINATION path.
#
# The sibling of copyinstr-fixture.sh, and deliberately its OPPOSITE in one respect. That fixture
# had to work hard to make a page NON-resident (each path string in its own untouched page of a
# PROT_READ mapping) because it reproduces a RESIDENCY fault. This one does the reverse: every path
# string is malloc'd and then WRITTEN by the process itself, so both pages are provably resident and
# a residency fault is impossible by construction. Whatever still fails here is not about paging.
#
# That is the single variable the fixture exists to isolate. The prior art's answer to
# "dtrace: invalid address" is always "copy at :return so the kernel has faulted the page in" — the
# adapter has done exactly that since 8fec3c5e and the rename destination was STILL lost 26/26 on
# run 31109041194. A pointer truncated from 64 bits to 32 is wrong rather than un-resident, so no
# amount of residency buys it back.
#
# The two ends of the rename carry DIFFERENT name prefixes (`rsrc-` / `rdst-`) so the arms can be
# scored independently. The known answer:
#
#            sources seen   destinations seen   faults
#   PRE       N              0                   N        <- 100% loss, and it is total, not partial
#   POST      N              N                   0
#
# A PRE arm that scores any destinations at all means this fixture is not exercising the defect and
# NOTHING may be read off the POST arm — that is the INCONCLUSIVE verdict below, not a pass.
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
#   usage: rename-dest-fixture.sh <workdir>
set -u
WORK="${1:?usage: rename-dest-fixture.sh <workdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NEW_D="$HERE/../adapters/macos-observe.d"
PRE_D="$HERE/macos-observe-PRE-NP2.d"
N=128
mkdir -p "$WORK/rn"

cat > "$WORK/renfix.c" <<'CSRC'
/* Rename N files. Both path strings are heap-allocated and written by THIS process immediately
 * before the syscall, so both pages are resident at entry and at return. */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc != 3) { fprintf(stderr, "usage: renfix <workdir> <n>\n"); return 2; }
	const char *work = argv[1];
	int n = atoi(argv[2]);
	int ok = 0;
	FILE *ptrs = fopen("/dev/stderr", "w");
	for (int i = 0; i < n; i++) {
		char *src = malloc(512), *dst = malloc(512);
		if (!src || !dst) return 2;
		snprintf(src, 512, "%s/rn/rsrc-%04d.probe", work, i);
		snprintf(dst, 512, "%s/rn/rdst-%04d.probe", work, i);
		int fd = open(src, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd >= 0) { ssize_t w = write(fd, "x", 1); (void)w; close(fd); }
		/* The pointer the tracer will be handed as rename's arg1. Printing it lets the harness
		 * check dtrace's reported "invalid address" against this value's LOW 32 BITS — which is
		 * what turns "the fix works" into "we know why it was broken". */
		if (i < 4) fprintf(ptrs, "FIXTURE-DSTPTR=%p low32=0x%08x\n",
		                   (void *)dst, (unsigned)(uintptr_t)dst);
		if (rename(src, dst) == 0) ok++;
		free(src);
		free(dst);
	}
	fprintf(stderr, "FIXTURE-RENAMED=%d/%d\n", ok, n);
	return ok == n ? 0 : 1;
}
CSRC

cc -O0 -o "$WORK/renfix" "$WORK/renfix.c" > "$WORK/cc.log" 2>&1
CC_RC=$?
if [ "$CC_RC" -ne 0 ]; then
  echo "⛔ cc failed rc=$CC_RC — cannot run the known-answer fixture"
  sed 's/^/     /' "$WORK/cc.log"
  exit 1
fi

# A third arm: the same fix spelled `uint64_t` instead of `uintptr_t`. Both are in D's type set, but
# only a run on a real runner settles which macOS dtrace accepts, and finding that out in the same
# job costs seconds where a second push costs a queue.
sed 's/^self uintptr_t /self uint64_t /' "$NEW_D" > "$WORK/alt-u64.d"
if ! grep -q '^self uint64_t np2;' "$WORK/alt-u64.d"; then
  echo "⛔ could not derive the uint64_t variant — the declaration block moved; arm skipped"
  rm -f "$WORK/alt-u64.d"
fi

arm () {   # arm <label> <dscript>
  local label="$1" dsc="$2"
  local t="$WORK/$label.trace" e="$WORK/$label.stderr"
  dtrace -q -s "$dsc" -o "$t" -c "$WORK/renfix $WORK $N" > "$e" 2>&1
  local rc=$?
  # ⛔ ATTRIBUTION, NOT A COUNT. Each end is matched against its own known name set, so an arm that
  # emitted N unrelated PATHOPs cannot score N — and the two ends cannot be confused for each other.
  local src dst faults ledger
  src=$(grep -E '^PATHOP\|' "$t" 2>/dev/null | awk -F'|' '$5=="rename"{print $NF}' \
        | grep -oE 'rsrc-[0-9]{4}\.probe' | sort -u | wc -l | tr -d ' ')
  dst=$(grep -E '^PATHOP\|' "$t" 2>/dev/null | awk -F'|' '$5=="rename"{print $NF}' \
        | grep -oE 'rdst-[0-9]{4}\.probe' | sort -u | wc -l | tr -d ' ')
  faults=$(grep -c 'invalid address' "$e" 2>/dev/null)
  # Only the fixed adapter carries the dtrace:::ERROR clause, so this is empty on the PRE arm by
  # design. It is the in-band ledger the DECODER reads; the stderr count above is dtrace's own.
  ledger=$(grep -c '^TRACER-ERROR|' "$t" 2>/dev/null)
  echo "  ARM $label"
  echo "    dtrace_exit          : $rc"
  echo "    rename SOURCES seen  : $src / $N"
  echo "    rename DESTS seen    : $dst / $N     <- the number this fixture exists to move"
  echo "    stderr faults        : $faults"
  echo "    in-band TRACER-ERROR : $ledger"
  echo "    END-time total       : $(grep '^TRACER-ERROR-TOTAL|' "$t" 2>/dev/null | head -1)"
  echo "    fixture says         : $(grep FIXTURE-RENAMED "$e" 2>/dev/null | head -1)"
  grep 'FIXTURE-DSTPTR' "$e" 2>/dev/null | head -2 | sed 's/^/      | /'
  grep 'invalid address' "$e" 2>/dev/null | head -2 | sed 's/^/      | /'
  echo "$dst" > "$WORK/$label.dst"
  echo "$src" > "$WORK/$label.src"
}

echo "=================================================================="
echo "KNOWN-ANSWER FIXTURE: the rename DESTINATION path (truncated self->np2)"
echo "=================================================================="
echo "--- NEGATIVE CONTROL: the PRE adapter (self->np2 inferred as int) must lose EVERY dest ---"
arm pre "$PRE_D"
echo "--- THE FIX: explicit \`self uintptr_t np2\` ---"
arm post "$NEW_D"
if [ -f "$WORK/alt-u64.d" ]; then
  echo "--- SPELLING ALTERNATIVE: \`self uint64_t np2\` (does macOS dtrace take it?) ---"
  arm u64 "$WORK/alt-u64.d"
fi

PRE_DST=$(cat "$WORK/pre.dst" 2>/dev/null || echo -1)
POST_DST=$(cat "$WORK/post.dst" 2>/dev/null || echo -1)
PRE_SRC=$(cat "$WORK/pre.src" 2>/dev/null || echo -1)
echo "=================================================================="
echo "RESULT  destinations: pre=$PRE_DST/$N  post=$POST_DST/$N   (pre sources=$PRE_SRC/$N)"
# The mechanism check, printed rather than asserted: a match is strong confirmation, a mismatch just
# means malloc handed out a different block and proves nothing either way.
echo "MECHANISM  fixture dst pointers vs the address dtrace called invalid:"
grep 'FIXTURE-DSTPTR' "$WORK/pre.stderr" 2>/dev/null | head -2 | sed 's/^/    /'
grep -oE 'invalid address \(0x[0-9a-f]+\)' "$WORK/pre.stderr" 2>/dev/null | sort -u | head -2 | sed 's/^/    /'
echo "  (expect the invalid address to equal the LOW 32 BITS of a dst pointer)"

if [ "$PRE_SRC" -lt "$N" ]; then
  echo "VERDICT: INCONCLUSIVE — the PRE arm did not even see the rename SOURCES ($PRE_SRC/$N), so the"
  echo "         tracer was not attached to the fixture at all and no arm means anything."
  exit 1
elif [ "$PRE_DST" -gt 0 ]; then
  echo "VERDICT: INCONCLUSIVE — the control captured $PRE_DST destination(s), so it did NOT go red."
  echo "         This fixture is not exercising the defect and nothing may be read off the POST arm."
  exit 1
elif [ "$POST_DST" -eq "$N" ]; then
  echo "VERDICT: PASS — the control loses every destination and the fix captures every one."
  exit 0
else
  echo "VERDICT: FAIL — the fix captured $POST_DST/$N destinations."
  exit 1
fi
