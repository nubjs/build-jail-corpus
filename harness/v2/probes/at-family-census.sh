#!/bin/bash
# RECON: which path-mutating syscalls does real macOS userland ACTUALLY issue, and how many of them
# is `adapters/macos-observe.d` blind to?
#
# This is the denominator step for the known-answer fixture that follows it. The adapter subscribes
# to a hand-written list — open/openat/mkdir/rmdir/unlink/rename/link/symlink/truncate/chmod — and
# the `*at` family plus the Darwin rename variants are absent from it. That is an UNDER-GRANT hole
# by construction (every one of those calls can create or destroy a path), but "a hole exists" is
# not a measurement. Two numbers make it one:
#
#   1. WHICH probe names exist at all on this kernel. A `syscall::foo:entry` naming a probe the
#      kernel does not publish makes dtrace REFUSE TO RUN THE WHOLE SCRIPT — so guessing at names
#      does not degrade gracefully, it takes the adapter offline. Each candidate is compiled ALONE.
#   2. HOW OFTEN each one fires under a workload made of the things install scripts really do.
#      A catch-all `syscall:::entry` census gives the denominator; the adapter's own capture over
#      the SAME workload gives the numerator.
#
# ⛔ THE CENSUS AND THE CAPTURE MUST SEE THE SAME WORKLOAD, so both arms drive one script from one
# file. Running "roughly the same commands" twice is how a miss rate acquires an error bar nobody
# can size afterwards.
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
#   usage: at-family-census.sh <workdir>
set -u
WORK="${1:?usage: at-family-census.sh <workdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ADAPTER="$HERE/../adapters/macos-observe.d"
RUNUSER="${SUDO_USER:-$(id -un)}"
mkdir -p "$WORK"
# The node arm of the workload is half the point — a JS postinstall issues node's fs calls, not the
# shell's. Print the resolution rather than discovering its absence as a silently shorter census.
echo "census: user=$RUNUSER node=$(command -v node || echo MISSING) PATH=$PATH"

# Every Darwin syscall that can CREATE, DESTROY, RENAME or RE-PERMISSION a path, plus the two
# read-side path syscalls a future read-scope model would need. Ordered so the report reads as a
# checklist rather than a dump. `SUBSCRIBED` names what macos-observe.d covers TODAY; everything
# else in MUTATORS is, by definition, a path the adapter cannot see.
SUBSCRIBED="open open_nocancel openat openat_nocancel mkdir rmdir unlink rename link symlink truncate chmod chdir connect connect_nocancel execve"
MUTATORS="mkdir mkdirat rmdir unlink unlinkat rename renameat renamex_np renameatx_np link linkat symlink symlinkat clonefile clonefileat fclonefileat truncate ftruncate chmod fchmod fchmodat lchmod chown lchown fchown fchownat mknod mkfifo undelete exchangedata setattrlist setattrlistat fsetattrlist setxattr fsetxattr removexattr fremovexattr utimes futimes utimensat futimens copyfile openbyid_np"
READERS="stat stat64 lstat lstat64 fstatat fstatat64 access faccessat readlink readlinkat getattrlist getattrlistat getxattr listxattr open_dprotected_np"

# ── 1. WHICH PROBE NAMES EXIST ────────────────────────────────────────────────────────────────
# `dtrace -l -n` lists without enabling; a name the kernel does not publish simply lists nothing.
# Compiling each candidate ALONE is the load-bearing part: one bad name in a combined script is
# fatal to the script, so the adapter edit that follows may only use names proven present here.
echo "=================================================================="
echo "1. PROBE-NAME EXISTENCE on $(sw_vers -productVersion) / $(uname -m)"
echo "=================================================================="
: > "$WORK/present.txt"
: > "$WORK/absent.txt"
for n in $MUTATORS $READERS; do
  cnt=$(dtrace -l -n "syscall::$n:entry" 2>/dev/null | grep -c "syscall.*$n")
  if [ "$cnt" -ge 1 ]; then printf '%s\n' "$n" >> "$WORK/present.txt"
  else printf '%s\n' "$n" >> "$WORK/absent.txt"; fi
done
sort -u -o "$WORK/present.txt" "$WORK/present.txt"
sort -u -o "$WORK/absent.txt" "$WORK/absent.txt"
echo "PRESENT ($(grep -c . "$WORK/present.txt")):"; sed 's/^/    /' "$WORK/present.txt" | paste -sd' ' -
echo "ABSENT  ($(grep -c . "$WORK/absent.txt")):"; sed 's/^/    /' "$WORK/absent.txt" | paste -sd' ' -

# ── 2. THE WORKLOAD ───────────────────────────────────────────────────────────────────────────
# Written once, driven twice. Every line is something a real lifecycle script does: the shell
# utilities a postinstall shells out to, and the node fs calls a JS postinstall makes. `ln -f` is
# the one already MEASURED to emit no `link` record at all, so it is the positive control for the
# hole this file exists to size.
cat > "$WORK/workload.sh" <<'WL'
set -u
W="$1"
R="$W/run"; rm -rf "$R"; mkdir -p "$R"; cd "$R" || exit 1

# ── shell utilities ──
mkdir -p a/b/c
: > src.txt
echo payload > src.txt
ln -s src.txt symlink.txt          # symlink or symlinkat?
ln -f src.txt hardlink.txt         # MEASURED to emit no `link` record: the positive control
cp src.txt copy.txt                # plain copy
cp -c src.txt clone.txt 2>/dev/null || cp src.txt clone.txt   # APFS clonefile if supported
mv copy.txt moved.txt              # rename or renameat?
touch moved.txt
chmod 0755 moved.txt
install -m 0644 src.txt installed.txt 2>/dev/null || cp src.txt installed.txt
mkdir -p deep/x/y/z
rm -f hardlink.txt
rm -rf deep
sed -i '' 's/payload/edited/' src.txt 2>/dev/null || true
tar -cf bundle.tar src.txt
mkdir -p untar && tar -xf bundle.tar -C untar

# ── node fs, which is what a JS postinstall really issues ──
node -e '
  const fs = require("fs"), path = require("path");
  const r = process.argv[1];
  fs.mkdirSync(path.join(r, "n/deep/dir"), { recursive: true });
  fs.writeFileSync(path.join(r, "n/a.txt"), "x");
  fs.renameSync(path.join(r, "n/a.txt"), path.join(r, "n/b.txt"));
  fs.symlinkSync("b.txt", path.join(r, "n/s.txt"));
  fs.linkSync(path.join(r, "n/b.txt"), path.join(r, "n/h.txt"));
  fs.copyFileSync(path.join(r, "n/b.txt"), path.join(r, "n/c.txt"));
  fs.copyFileSync(path.join(r, "n/b.txt"), path.join(r, "n/cl.txt"), fs.constants.COPYFILE_FICLONE);
  fs.chmodSync(path.join(r, "n/b.txt"), 0o600);
  fs.utimesSync(path.join(r, "n/b.txt"), new Date(), new Date());
  fs.truncateSync(path.join(r, "n/c.txt"), 0);
  fs.rmSync(path.join(r, "n/h.txt"));
  fs.cpSync(path.join(r, "n"), path.join(r, "n2"), { recursive: true });
  fs.rmSync(path.join(r, "n2"), { recursive: true, force: true });
' "$R"
echo "WORKLOAD-DONE"
WL
chmod +x "$WORK/workload.sh"

# ── 3. THE CENSUS: every syscall the workload issued ──────────────────────────────────────────
# A catch-all aggregation, no path copying at all — nothing here can fault, so this arm's count is
# the denominator against which any capture arm is scored.
cat > "$WORK/census.d" <<'DSC'
#pragma D option quiet
#pragma D option bufsize=64m
#pragma D option dynvarsize=256m
/* @err is SEEDED here so END always prints a number: `printa` on an empty aggregation prints
 * nothing at all, and a missing count reads identically to a zero count. */
dtrace:::BEGIN { printf("CENSUS-LIVE|target=%d\n", $target); @err = sum(0); }
syscall:::entry /progenyof($target)/ { @c[probefunc] = count(); }
dtrace:::ERROR  { @err = sum(1); }
dtrace:::END {
	printf("--- syscall census ---\n");
	printa("SYSCALL %-24s %@d\n", @c);
	printf("--- census tracer errors ---\n");
	printa("CENSUS-ERRORS %@d\n", @err);
}
DSC

echo
echo "=================================================================="
echo "2. SYSCALL CENSUS over the workload (the DENOMINATOR)"
echo "=================================================================="
dtrace -q -s "$WORK/census.d" -o "$WORK/census.txt" \
       -c "/bin/bash $WORK/workload.sh $WORK" > "$WORK/census.stderr" 2>&1
CENSUS_RC=$?
echo "census dtrace_exit=$CENSUS_RC  lines=$(wc -l < "$WORK/census.txt" 2>/dev/null | tr -d ' ')"
grep -q 'CENSUS-LIVE' "$WORK/census.txt" 2>/dev/null || {
  echo "⛔ CENSUS TRACER NEVER STARTED — nothing below is a measurement"
  sed 's/^/     /' "$WORK/census.stderr" | head -20
  exit 1
}
grep 'WORKLOAD-DONE' "$WORK/census.stderr" > /dev/null 2>&1 \
  && echo "workload completed under the census arm" \
  || echo "⛔ workload did NOT print its done marker under the census arm"

count_of () {   # count_of <syscall-name> <census-file>
  awk -v n="$1" '$1=="SYSCALL" && $2==n {print $3}' "$2" | head -1
}

echo
echo "--- PATH-MUTATING syscalls the workload issued, and whether the adapter subscribes ---"
printf '  %-22s %8s   %s\n' SYSCALL COUNT 'ADAPTER'
MISSED=0; COVERED=0
: > "$WORK/hole.txt"
for n in $MUTATORS; do
  c=$(count_of "$n" "$WORK/census.txt")
  [ -n "${c:-}" ] || continue
  case " $SUBSCRIBED " in
    *" $n "*) printf '  %-22s %8s   subscribed\n' "$n" "$c"; COVERED=$((COVERED + c)) ;;
    *)        printf '  %-22s %8s   ⛔ UNSUBSCRIBED — every one of these is an invisible path\n' "$n" "$c"
              printf '%s %s\n' "$n" "$c" >> "$WORK/hole.txt"
              MISSED=$((MISSED + c)) ;;
  esac
done
TOTAL=$((COVERED + MISSED))
echo
echo "  path-mutating syscalls issued : $TOTAL"
echo "  captured by the adapter today : $COVERED"
echo "  INVISIBLE to the adapter      : $MISSED"
[ "$TOTAL" -gt 0 ] && echo "  ⇒ blind fraction: $(( MISSED * 100 / TOTAL ))% of path-mutating calls"

echo
echo "--- READ-side path syscalls (no grant model reads these today; sized for the future) ---"
for n in $READERS; do
  c=$(count_of "$n" "$WORK/census.txt")
  [ -n "${c:-}" ] && printf '  %-22s %8s\n' "$n" "$c"
done

# ── 4. THE CAPTURE ARM: the same workload under the SHIPPING adapter ──────────────────────────
echo
echo "=================================================================="
echo "3. THE SHIPPING ADAPTER over the SAME workload (the NUMERATOR)"
echo "=================================================================="
dtrace -q -s "$ADAPTER" -o "$WORK/capture.txt" \
       -c "/bin/bash $WORK/workload.sh $WORK" > "$WORK/capture.stderr" 2>&1
CAP_RC=$?
echo "capture dtrace_exit=$CAP_RC  lines=$(wc -l < "$WORK/capture.txt" 2>/dev/null | tr -d ' ')"
echo "  OPEN records   : $(grep -c '^OPEN|' "$WORK/capture.txt" 2>/dev/null)"
echo "  PATHOP records : $(grep -c '^PATHOP|' "$WORK/capture.txt" 2>/dev/null)"
echo "  TRACER-ERROR   : $(grep -c '^TRACER-ERROR|' "$WORK/capture.txt" 2>/dev/null)"
echo "  PATHOP by op:"
grep '^PATHOP|' "$WORK/capture.txt" 2>/dev/null | awk -F'|' '{print $5}' | sort | uniq -c | sed 's/^/     /'

# THE NAMED-PATH CHECK. Each workload path has a distinctive name, so "did the adapter see the
# path this operation created?" is answerable by NAME rather than by count — the same discipline
# rename-dest-fixture.sh uses. A path the adapter never emitted is a write a grant would miss.
echo
echo "--- did the adapter emit each path the workload CREATED? (name-anchored) ---"
for want in symlink.txt hardlink.txt copy.txt clone.txt moved.txt installed.txt bundle.tar \
            n/b.txt n/s.txt n/h.txt n/c.txt n/cl.txt; do
  base="${want##*/}"
  hits=$(grep -c "$base" "$WORK/capture.txt" 2>/dev/null)
  if [ "$hits" -ge 1 ]; then printf '  %-16s seen   (%s records)\n' "$want" "$hits"
  else printf '  %-16s ⛔ NEVER EMITTED — a created path the grant cannot see\n' "$want"; fi
done

echo
echo "=================================================================="
echo "SUMMARY"
echo "=================================================================="
echo "unsubscribed path-mutating syscalls this workload actually issued:"
if [ -s "$WORK/hole.txt" ]; then
  sed 's/^/    /' "$WORK/hole.txt"
  echo "⇒ THE HOLE IS REAL AND THESE ARE ITS MEMBERS. Add exactly these to the adapter."
  exit 1
else
  echo "    (none)"
  echo "⇒ Either the workload does not reach them on this kernel, or the adapter already covers"
  echo "  everything it issues. Read the census before concluding the second."
  exit 0
fi
