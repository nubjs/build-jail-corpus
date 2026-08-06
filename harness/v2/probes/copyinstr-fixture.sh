#!/bin/bash
# KNOWN-ANSWER fixture for the `copyinstr`-at-entry defect.
#
# The fixture opens an EXACT, named set of N files, so "how many did the tracer report?" has a known
# right answer. Each path string is placed in its OWN page of a PROT_READ file mapping that the
# process never touches, so at syscall ENTRY the page is provably not resident and `copyinstr(arg0)`
# must fault. That is what makes this a CONTROL rather than a hopeful re-run: the old adapter has to
# go RED here, and if it does not, the fixture is not exercising the defect and no conclusion may be
# read off it.
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
set -u
WORK="${1:?usage: copyinstr-fixture.sh <workdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
NEW_D="$HERE/../adapters/macos-observe.d"
OLD_D="$HERE/macos-observe-OLD.d"
N=200
mkdir -p "$WORK/kaf"

cat > "$WORK/fixture.c" <<'CSRC'
/* Open N files whose path strings live in untouched, file-backed pages. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc != 4) { fprintf(stderr, "usage: fixture <pathsfile> <n> <pagesz>\n"); return 2; }
	const char *pathsfile = argv[1];
	int n = atoi(argv[2]);
	long pg = atol(argv[3]);
	int fd = open(pathsfile, O_RDONLY);
	if (fd < 0) { perror("open pathsfile"); return 2; }
	/* MAP_PRIVATE + PROT_READ: pages are populated lazily, on first touch. The process never
	 * touches them — only the kernel does, inside open(2), which is precisely AFTER the entry
	 * probe fires. */
	char *base = mmap(NULL, (size_t)n * (size_t)pg, PROT_READ, MAP_PRIVATE, fd, 0);
	if (base == MAP_FAILED) { perror("mmap"); return 2; }
	int ok = 0;
	for (int i = 0; i < n; i++) {
		int f = open(base + (size_t)i * (size_t)pg, O_RDONLY);
		if (f >= 0) { ok++; close(f); }
	}
	fprintf(stderr, "FIXTURE-OPENED=%d/%d\n", ok, n);
	return ok == n ? 0 : 1;
}
CSRC

PG=$(getconf PAGESIZE)
echo "pagesize=$PG  N=$N"

# Materialize the N target files, then the page-aligned path blob.
python3 - "$WORK" "$N" "$PG" <<'PY'
import os, sys
work, n, pg = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
blob = bytearray()
for i in range(n):
    p = os.path.join(work, "kaf", "kaf-%04d.probe" % i)
    open(p, "w").write("x")
    b = p.encode() + b"\0"
    assert len(b) < pg
    blob += b + b"\0" * (pg - len(b))
open(os.path.join(work, "paths.bin"), "wb").write(bytes(blob))
PY
echo "materialized: $(ls "$WORK/kaf" | wc -l | tr -d ' ') files, blob $(stat -f%z "$WORK/paths.bin") bytes"

cc -O0 -o "$WORK/fixture" "$WORK/fixture.c" > "$WORK/cc.log" 2>&1
CC_RC=$?
if [ "$CC_RC" -ne 0 ]; then
  echo "⛔ cc failed rc=$CC_RC — cannot run the known-answer fixture"
  sed 's/^/     /' "$WORK/cc.log"
  exit 1
fi

arm () {   # arm <label> <dscript>
  local label="$1" dsc="$2"
  local t="$WORK/$label.trace" e="$WORK/$label.stderr"
  dtrace -q -s "$dsc" -o "$t" -c "$WORK/fixture $WORK/paths.bin $N $PG" > "$e" 2>&1
  local rc=$?
  # ⛔ ATTRIBUTION, NOT A COUNT: every reported path is matched against the known set by NAME, so a
  # tracer that emitted 200 unrelated opens cannot score 200.
  local seen
  seen=$(grep -E '^OPEN\|' "$t" 2>/dev/null | awk -F'|' '{print $NF}' \
         | grep -oE 'kaf-[0-9]{4}\.probe' | sort -u | wc -l | tr -d ' ')
  local faults
  faults=$(grep -c 'invalid address' "$e" 2>/dev/null)
  echo "  ARM $label"
  echo "    dtrace_exit      : $rc"
  echo "    known paths seen : $seen / $N"
  echo "    copyinstr faults : $faults"
  echo "    fixture says     : $(grep FIXTURE-OPENED "$e" 2>/dev/null | head -1)"
  sed 's/^/      | /' "$e" 2>/dev/null | grep 'invalid address' | head -3
  echo "$seen" > "$WORK/$label.seen"
}

echo "=================================================================="
echo "KNOWN-ANSWER FIXTURE: copyinstr at entry vs at return"
echo "=================================================================="
echo "--- NEGATIVE CONTROL: the OLD adapter (copyinstr at entry) must MISS paths ---"
arm old "$OLD_D"
echo "--- THE FIX: the NEW adapter (pointer at entry, copyinstr at return) ---"
arm new "$NEW_D"

OLD_SEEN=$(cat "$WORK/old.seen" 2>/dev/null || echo -1)
NEW_SEEN=$(cat "$WORK/new.seen" 2>/dev/null || echo -1)
echo "=================================================================="
echo "RESULT  old=$OLD_SEEN/$N  new=$NEW_SEEN/$N"
if [ "$NEW_SEEN" -eq "$N" ] && [ "$OLD_SEEN" -lt "$N" ]; then
  echo "VERDICT: PASS — the fix reports every known path and the control goes RED without it."
elif [ "$OLD_SEEN" -ge "$N" ]; then
  echo "VERDICT: INCONCLUSIVE — the control did NOT go red, so this fixture does not exercise the"
  echo "         defect and nothing may be concluded from the new arm's score."
else
  echo "VERDICT: FAIL — the fix did not report every known path."
fi
