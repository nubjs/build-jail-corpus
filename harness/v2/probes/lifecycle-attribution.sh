#!/bin/bash
# Why does the macOS decoder find `lifecycle pids: 0`?
#
# KNOWN-ANSWER by construction: the fixture package's lifecycle script is one WE author, so its
# exact argv and the exact marker it writes are known before the tracer runs. "Did the decoder
# attribute the right pids?" therefore has a checkable answer, not merely a non-zero count.
#
# The decoder's matcher is `execname in {sh,bash,dash,zsh} && psargs =~ / -c /`. This probe prints,
# for every exec in the subtree, all three candidate argv sources side by side so the trace says
# which one actually carries `-c` on macOS:
#
#   EXEC       proc:::exec-success + curpsinfo->pr_psargs   (what the decoder reads today)
#   EXECARGV   syscall::execve:entry, copyin of argv[]      (the caller just built it, so resident)
#   SPAWNARGV  syscall::posix_spawn entry+return            (Darwin's 5-arg form: argv is arg3)
#
# ⛔ Exit codes are captured on their own line, never through a pipe.
set -u
WORK="${1:?usage: lifecycle-attribution.sh <workdir>}"
RUNUSER="${SUDO_USER:-$(id -un)}"
NPM_BIN="$(command -v npm)"
HERE_PROBES="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$WORK"

# ── the known-answer fixture package ───────────────────────────────────────────────────────────
# TOKEN appears verbatim in the lifecycle script's argv[2], and the script writes MARKER. Both are
# known in advance, so attribution can be checked by NAME rather than by count.
#
# The script also exercises symlink/link/rename with DISTINCTIVE, non-overlapping names on each
# side, so the same trace settles which path each PATHOP record carries:
#
#   symlink(target=KAFSYMTGT…, linkpath=kaf-sym-link…)  only the LINKPATH is a write
#   link(old=kaf-lnk-src…,     new=kaf-lnk-dst…)        only the NEW name is a write
#   rename(old=kaf-ren-old…,   new=kaf-ren-new…)        BOTH are writes
#
# KAFSYMTGT is a dangling relative target that is never created, so if it shows up as a write it is
# provably a phantom path: nothing on the system could have written it.
TOKEN="KAF_LIFECYCLE_7f3a"
SYMTGT="KAFSYMTGT_9c1d_never_created"
PKG="$WORK/kafpkg"; mkdir -p "$PKG"
cat > "$PKG/package.json" <<PJ
{
  "name": "kaf-lifecycle",
  "version": "1.0.0",
  "scripts": { "install": "echo $TOKEN && mkdir -p ./kaf-marker-dir && : > ./kaf-marker-file && ln -sf $SYMTGT ./kaf-sym-link-4e2b && : > ./kaf-lnk-src-a1b2 && ln -f ./kaf-lnk-src-a1b2 ./kaf-lnk-dst-c3d4 && : > ./kaf-ren-old-e5f6 && mv ./kaf-ren-old-e5f6 ./kaf-ren-new-g7h8" }
}
PJ

PROJ="$WORK/proj"; mkdir -p "$PROJ"
printf '{"name":"o","version":"1.0.0","private":true}\n' > "$PROJ/package.json"
chown -R "$RUNUSER" "$WORK" 2>/dev/null

# Fetch OUTSIDE the trace, scripts off — same discipline as the driver.
( cd "$PROJ" && sudo -u "$RUNUSER" -H env "PATH=$PATH" "$NPM_BIN" install --no-audit --no-fund \
    --ignore-scripts "file:$PKG" ) > "$WORK/fetch.log" 2>&1
FETCH_RC=$?
echo "FETCH_EXIT=$FETCH_RC"
[ "$FETCH_RC" -ne 0 ] && { sed 's/^/     /' "$WORK/fetch.log" | tail -20; exit 1; }
chown -R "$RUNUSER" "$WORK" 2>/dev/null

# ── the instrument ─────────────────────────────────────────────────────────────────────────────
cat > "$WORK/argv.d" <<'DSC'
#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m
#pragma D option dynvarsize=256m
#pragma D option strsize=1024

dtrace:::BEGIN { printf("DTRACE-LIVE|target=%d\n", $target); }

/* What the decoder reads today. */
proc:::exec-success
/progenyof($target)/
{ printf("EXEC|%d|%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs); }

/* argv[] as the CALLER built it. The pointer array and the strings were just written by the
 * caller, so they are resident and copyin at ENTRY is safe here — unlike a path argument the
 * caller never touched, which is the copyinstr-at-entry defect fixed in macos-observe.d. */
syscall::execve:entry
/progenyof($target)/
{
	this->v = (user_addr_t *)copyin(arg1, sizeof(user_addr_t) * 3);
	printf("EXECARGV|%d|%d|%s|[0]=%s|[1]=%s|[2]=%s\n",
	    pid, curpsinfo->pr_ppid, execname,
	    this->v[0] != 0 ? copyinstr(this->v[0]) : "",
	    this->v[1] != 0 ? copyinstr(this->v[1]) : "",
	    this->v[2] != 0 ? copyinstr(this->v[2]) : "");
}

/* Darwin's posix_spawn SYSCALL is the 5-arg form — (pid*, path, adesc, argv, envp) — so argv is
 * arg3, not arg4 as in the libc prototype. The child pid is an out-param, readable at return. */
syscall::posix_spawn:entry
/progenyof($target)/
{
	self->sp_pidp = arg0;
	self->sp_argv = arg3;
	self->sp = 1;
}

syscall::posix_spawn:return
/self->sp/
{
	this->w = (user_addr_t *)copyin(self->sp_argv, sizeof(user_addr_t) * 3);
	printf("SPAWNARGV|parent=%d|%s|[0]=%s|[1]=%s|[2]=%s\n",
	    pid, execname,
	    this->w[0] != 0 ? copyinstr(this->w[0]) : "",
	    this->w[1] != 0 ? copyinstr(this->w[1]) : "",
	    this->w[2] != 0 ? copyinstr(this->w[2]) : "");
	self->sp = 0;
	self->sp_argv = 0;
	self->sp_pidp = 0;
}

dtrace:::END { printf("DTRACE-END\n"); }
DSC

# ⛔ /bin/bash, never /bin/sh: /bin/sh is a stub that re-execs, and `dtrace -c` does not survive its
# target re-execing (MEASURED, run 31086076352).
cat > "$WORK/run.sh" <<WRAP
cd "$PROJ"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" "$NPM_BIN" rebuild --no-audit --no-fund kaf-lifecycle > "$WORK/npm.log" 2>&1
echo \$? > "$WORK/rc"
WRAP

dtrace -q -s "$WORK/argv.d" -o "$WORK/trace.txt" -c "/bin/bash $WORK/run.sh" > "$WORK/dtrace.log" 2>&1
DT_RC=$?
RC=$(cat "$WORK/rc" 2>/dev/null || echo 99)
echo "=================================================================="
echo "OBSERVE rc=$RC dtrace_exit=$DT_RC trace=$(wc -l < "$WORK/trace.txt" | tr -d ' ') lines"
echo "  marker dir : $([ -d "$PROJ/kaf-marker-dir" ] && echo PRESENT || echo ABSENT)"
echo "  marker file: $([ -f "$PROJ/kaf-marker-file" ] && echo PRESENT || echo ABSENT)"
echo "  npm says   : $(grep -c "$TOKEN" "$WORK/npm.log" 2>/dev/null) lines carry $TOKEN"
sed 's/^/     /' "$WORK/dtrace.log" | head -6

echo "=================================================================="
echo "A. proc:::exec-success + pr_psargs  (what the decoder reads today)"
echo "=================================================================="
grep -E '^EXEC\|' "$WORK/trace.txt" | sort -u | head -40 | sed 's/^/  /'
echo "  --- of those, how many carry ' -c ' in psargs? ---"
grep -E '^EXEC\|' "$WORK/trace.txt" | grep -cE ' -c( |$)'
echo "  --- how many psargs fields contain a SPACE at all? (i.e. any argv beyond argv[0]) ---"
grep -E '^EXEC\|' "$WORK/trace.txt" | awk -F'|' '{print $5}' | grep -c ' '

echo "=================================================================="
echo "B. syscall::execve:entry + copyin(argv)"
echo "=================================================================="
grep -E '^EXECARGV\|' "$WORK/trace.txt" | sort -u | head -40 | sed 's/^/  /'
echo "  --- carrying -c ---"
grep -E '^EXECARGV\|' "$WORK/trace.txt" | grep -c '\[1\]=-c'
echo "  --- carrying the KNOWN token $TOKEN ---"
grep -E '^EXECARGV\|' "$WORK/trace.txt" | grep -c "$TOKEN"

echo "=================================================================="
echo "C. syscall::posix_spawn + copyin(argv)"
echo "=================================================================="
grep -E '^SPAWNARGV\|' "$WORK/trace.txt" | sort -u | head -40 | sed 's/^/  /'
echo "  --- carrying -c ---"
grep -E '^SPAWNARGV\|' "$WORK/trace.txt" | grep -c '\[1\]=-c'
echo "  --- carrying the KNOWN token $TOKEN ---"
grep -E '^SPAWNARGV\|' "$WORK/trace.txt" | grep -c "$TOKEN"

echo "=================================================================="
echo "VERDICT: the source that carries both '-c' and $TOKEN is the one the matcher must read."
echo "=================================================================="

# ── D. symlink/link/rename path selection: OLD adapter vs NEW ─────────────────────────────────
#
# MEASURED, run 31087159355 — read the expectations below with these three results in hand:
#
#   symlink  SETTLED. old reported KAFSYMTGT_9c1d (a target nothing ever created — a proven
#            phantom path); new reports ./kaf-sym-link-4e2b. The control went red.
#   link     NOT EXERCISED. macOS `ln -f` emitted only unlink(dst) — no `link` PATHOP at all, so
#            it used linkat(2), which this adapter does NOT subscribe to. The kaf-lnk-dst row
#            below is satisfied by that unlink, NOT by a link record; it is not a link assertion.
#   rename   SETTLED (2026-08-06) — the "cause not yet established" this line used to carry is now
#            established, and the row passes. `self->np2` holds the rename DESTINATION pointer and
#            was typed `int` by inference: D takes a thread-local's type from its first assignment
#            in program text order, and the reset `self->np2 = 0;` in the shared path-op entry
#            clause preceded `self->np2 = arg1;`. Every 64-bit pointer was therefore truncated to
#            its low word, which on macOS always lands inside the 4 GiB __PAGEZERO — so `copyinstr`
#            faulted on EVERY rename rather than intermittently, and the clause aborted before
#            emitting. Fixed by declaring the pointer thread-locals explicitly in macos-observe.d.
#            MEASURED, run 31114516278: kaf-ren-new-g7h8 count=1 under ARM new, having been 0 here
#            on run 31087159355. The isolated known-answer control is probes/rename-dest-fixture.sh
#            — 0/128 destinations before, 128/128 after, with both path strings provably resident
#            so a residency fault is excluded by construction.
#
# So the adapter has a further UNDER-PREDICTION blind spot beyond the ones settled above: the *at(2)
# and *_np(2) variants (linkat, renameat, renamex_np, unlinkat, mkdirat, openat is already covered)
# are unsubscribed, and macOS userland reaches for them. Tracked, not fixed here.
# Known answer, by construction:
#   symlink -> kaf-sym-link-4e2b   MUST appear;  KAFSYMTGT_9c1d MUST NOT (nothing ever created it)
#   link    -> kaf-lnk-dst-c3d4    MUST appear
#   rename  -> BOTH kaf-ren-old-e5f6 and kaf-ren-new-g7h8 MUST appear (old is unlinked, new created)
pathop_arm () {   # pathop_arm <label> <dscript>
  local label="$1" dsc="$2"
  dtrace -q -s "$dsc" -o "$WORK/po-$label.trace" -c "/bin/bash $WORK/run.sh" \
      > "$WORK/po-$label.log" 2>&1
  local rc=$?
  local po="$WORK/po-$label.trace"
  echo "  ARM $label (dtrace_exit=$rc, $(grep -c '^PATHOP|' "$po" 2>/dev/null) PATHOP records)"
  local name expect got
  for name in kaf-sym-link-4e2b KAFSYMTGT_9c1d kaf-lnk-dst-c3d4 kaf-lnk-src-a1b2 \
              kaf-ren-old-e5f6 kaf-ren-new-g7h8; do
    case "$name" in
      KAFSYMTGT_9c1d|kaf-lnk-src-a1b2) expect="MUST-NOT-APPEAR" ;;
      *)                               expect="MUST-APPEAR" ;;
    esac
    got=$(grep -E '^PATHOP\|' "$po" 2>/dev/null | grep -c "$name")
    printf '    %-24s %-16s count=%s\n' "$name" "$expect" "$got"
  done
}

echo "=================================================================="
echo "D. symlink/link/rename PATH SELECTION — known answer by construction"
echo "=================================================================="
echo "--- NEGATIVE CONTROL: the OLD adapter (arg0 for every path op) ---"
pathop_arm old "$HERE_PROBES/macos-observe-OLD.d"
echo "--- THE FIX: the NEW adapter (arg1 for symlink/link; both ends for rename) ---"
pathop_arm new "$HERE_PROBES/../adapters/macos-observe.d"
echo "=================================================================="
echo "A phantom path is proven by KAFSYMTGT_9c1d appearing: nothing on this system ever created it,"
echo "so any write record naming it was invented by the parser."
echo "=================================================================="
