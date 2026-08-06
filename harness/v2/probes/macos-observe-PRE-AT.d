/*
 * macOS OBSERVE adapter — the direct analogue of `strace -f` for harness/v2's measure loop.
 *
 * Differs from the sibling `macos-dtrace.d` (the attribution CONTROL) in exactly one way that
 * matters: the control filters opens by a path substring so its log stays readable, which is
 * useless for measurement — a lifecycle script opens arbitrary paths carrying no token. Here the
 * subscription is scoped by PROCESS ANCESTRY instead, via `progenyof($target)`. The target is the
 * command dtrace itself launched with `-c`, so the stream is exactly that subtree and nothing else
 * on a busy runner leaks in.
 *
 * Attribution to the LIFECYCLE SCRIPT specifically (as opposed to npm) is a second, finer filter
 * and it lives in observe-macos.mjs, because it needs the psargs text. Every event line therefore
 * carries both pid and ppid so the decoder can rebuild the tree from the events themselves rather
 * than depending on a fork edge appearing.
 *
 * The four EVENT-contract fields (MAPPING.md) come out as: pid (who), open flags (write intent),
 * errno on a negative return (refusal), and the AF_INET sockaddr (peer).
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=64m
/* MEASURED on the attribution control (run 31078241875): 32m dropped thousands of dynamic
 * variables under filesystem load and MISSED a whole process shape. The thread-local path string
 * is what consumes the space. */
#pragma D option dynvarsize=256m
#pragma D option strsize=1024

/* ── NP2-DECL-BEGIN ────────────────────────────────────────────────────────────────────────────
 * ⛔ EVERY THREAD-LOCAL HOLDING A USER POINTER IS DECLARED HERE, EXPLICITLY. THAT IS NOT STYLE —
 * IT IS THE FIX FOR A 100%-LOSS DEFECT.
 *
 * D gives an undeclared thread-local the type of its FIRST assignment in PROGRAM TEXT ORDER
 * (Oracle/illumos: "thread-local variables are created automatically on their first assignment and
 * assume the type that's used on the right-hand side"). `self->np2`'s first assignment was the
 * RESET `self->np2 = 0;` in the shared path-op entry clause, which textually precedes
 * `self->np2 = arg1;` in the rename clause below — so np2 was typed `int`, i.e. 32 BITS, and every
 * 64-bit path pointer stored into it was silently TRUNCATED to its low word.
 *
 * The truncated value can never be readable: macOS reserves the whole first 4 GiB of every 64-bit
 * process as __PAGEZERO, so a low-32 word always lands inside it. `copyinstr(self->np2)` therefore
 * did not fault occasionally under memory pressure — it faulted EVERY TIME, and the rename
 * DESTINATION path (the path a rename CREATES) was never recorded even once.
 *
 * MEASURED on run 31109041194, @apollo/rover@0.2.1: 26 renames, 26 faults, 0 destinations captured.
 *   dtrace: error on enabled probe ID 31 (ID 425: syscall::rename:return):
 *           invalid address (0x2396f00) in action #6 at DIF offset 24
 * epid 31 is the SECOND `rename:return` clause — counting clause-probe tuples through this file in
 * order puts the np2 clause at 31 and `execve:entry` at 33, matching both ids the run reported —
 * and action #6 is that clause's sixth printf argument, `copyinstr(self->np2)`. The faulting
 * address 0x2396f00 is the low word of a nano-zone pointer shaped exactly like the sibling execve
 * fault's UNtruncated 0x6000020cc190; the two spellings side by side in one log are what named it.
 *
 * ⛔ THIS IS NOT THE copyinstr-AT-ENTRY DEFECT, AND THE STANDARD PRIOR-ART CURE DOES NOT TOUCH IT.
 * Every guide answers "invalid address" with "copy at :return, once the kernel has faulted the page
 * in" — done here since 8fec3c5e, and still 100% lost, because a truncated pointer is WRONG rather
 * than un-resident. A residency fault would have varied with load and with the package; this one
 * cannot, which is also why it hid: it looked like the noise we had already explained.
 *
 * A missed rename destination is an UNDER-prediction — the direction that breaks real installs — so
 * the declarations stay even though np/p/cdp happen to infer correctly today. Their reset lines are
 * one clause reorder away from becoming the first assignment too, and the failure is silent.
 * `probes/rename-dest-fixture.sh` is the known-answer guard; its control is this file with the
 * block below deleted. */
self uintptr_t cdp;    /* chdir path */
self uintptr_t p;      /* open path */
self uintptr_t np;     /* path-op path; rename OLD */
self uintptr_t np2;    /* rename NEW — the path a rename CREATES */
/* ── NP2-DECL-END ───────────────────────────────────────────────────────────────────────────── */

dtrace:::BEGIN
{
	/* Seeded so END always prints a NUMBER. `printa` on an empty aggregation prints nothing at
	 * all, and a missing count is indistinguishable from a zero count to whatever reads it. */
	@tracer_errors = sum(0);
	printf("DTRACE-LIVE|target=%d\n", $target);
}

/* ── cwd tracking. dtrace reports the path exactly as the syscall received it, so a script that
 * chdir's into its own package dir and opens "../dist/app.js" yields a string that prefix-matches
 * no scope at all. The decoder resolves it; this is where the base comes from. ─────────────── */

/* ⛔ SAVE THE POINTER AT ENTRY, copyinstr AT RETURN — never copyinstr at entry.
 *
 * copyin/copyinstr run in probe context, which cannot take a page fault, so they read only memory
 * that is ALREADY RESIDENT. A path argument whose page the caller has not touched since it was
 * mapped is not resident at syscall ENTRY, and the copy aborts the WHOLE CLAUSE with
 *
 *   dtrace: error on enabled probe ID n (ID m: syscall::open:entry): invalid address (0x…)
 *
 * MEASURED on run 31082536882 (two of six arms) and reproduced deterministically by
 * probes/copyinstr-fixture.sh. The clause aborting is what makes this dangerous rather than merely
 * noisy: `self->on` is never set, so the matching :return probe stays silent and the OPEN record is
 * dropped SILENTLY. A dropped open is a path the classifier never sees, and a path never seen is a
 * capability never granted — an UNDER-prediction, the one direction that breaks real installs.
 *
 * By the time the syscall RETURNS the kernel has itself copied the path in, so the page is resident
 * and the copy is safe. This is what Apple's shipped /usr/bin/opensnoop does (`self->pathp = arg0`
 * at entry, `copyinstr(self->pathp)` at return, commented "checked on return to ensure pathp is
 * mapped"), and what the DTrace guide's "Avoiding Errors" prescribes.
 */

syscall::chdir:entry
/progenyof($target)/
{
	self->cdp = arg0;
	self->cd = 1;
}

syscall::chdir:return
/self->cd/
{
	printf("CHDIR|%d|%d|%s|ret=%d|%s\n", pid, curpsinfo->pr_ppid, execname, (int)arg0,
	    copyinstr(self->cdp));
	self->cd = 0;
	self->cdp = 0;
}

/* ── OPEN: path + flags (write intent) + errno (refusal) ───────────────────────────────────── */

syscall::open:entry, syscall::open_nocancel:entry
/progenyof($target)/
{
	self->p = arg0;
	self->fl = arg1;
	self->on = 1;
}

syscall::openat:entry, syscall::openat_nocancel:entry
/progenyof($target)/
{
	self->p = arg1;
	self->fl = arg2;
	self->on = 1;
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/self->on/
{
	/* Darwin flags: O_WRONLY 0x1 O_RDWR 0x2 O_APPEND 0x8 O_CREAT 0x200 O_TRUNC 0x400 */
	printf("OPEN|%d|%d|%s|flags=0x%x|ret=%d|errno=%d|%s\n",
	    pid, curpsinfo->pr_ppid, execname,
	    (int)self->fl, (int)arg0, (int)arg0 < 0 ? errno : 0, copyinstr(self->p));
	@allopens[execname] = count();
	self->on = 0;
	self->p = 0;
	self->fl = 0;
}

/* ── Namespace mutations. An open with O_CREAT is not the only way to write; mkdir/unlink/rename
 * are writes with no flags word, so they are reported as their own op and classified as writes
 * unconditionally by the decoder. ──────────────────────────────────────────────────────────── */

syscall::mkdir:entry, syscall::rmdir:entry, syscall::unlink:entry,
syscall::rename:entry, syscall::link:entry, syscall::symlink:entry,
syscall::truncate:entry, syscall::chmod:entry
/progenyof($target)/
{
	self->np = arg0;
	self->np2 = 0;
	self->nop = probefunc;
	self->nn = 1;
}

/* ⛔ arg0 IS NOT THE PATH BEING CREATED for symlink(2) or link(2).
 *
 *   symlink(target, linkpath) — `target` is opaque link CONTENT the kernel stores verbatim and
 *                               never resolves. The path created is linkpath, arg1.
 *   link(oldpath, newpath)    — oldpath already exists. The path created is newpath, arg1.
 *
 * Reporting arg0 invents a PHANTOM PATH: link targets are usually relative, so the decoder resolves
 * one against a cwd and emits a plausible path, in a plausible scope, that NO PROCESS EVER WROTE —
 * enough on its own to hold a whole capability scope alive. The Linux lane shipped exactly this bug
 * in observe.mjs and fixed it by taking the LAST path for symlink/link. These clauses come after
 * the one above and override self->np for just those two probes.
 *
 * rename(2) is deliberately NOT here: it unlinks `old` as well as creating `new`, so BOTH ends are
 * genuine writes and both are reported, via self->np2 below. */
syscall::symlink:entry, syscall::link:entry
/progenyof($target)/
{
	self->np = arg1;
}

syscall::rename:entry
/progenyof($target)/
{
	self->np2 = arg1;
}

syscall::mkdir:return, syscall::rmdir:return, syscall::unlink:return,
syscall::rename:return, syscall::link:return, syscall::symlink:return,
syscall::truncate:return, syscall::chmod:return
/self->nn/
{
	printf("PATHOP|%d|%d|%s|%s|ret=%d|errno=%d|%s\n",
	    pid, curpsinfo->pr_ppid, execname, self->nop,
	    (int)arg0, (int)arg0 < 0 ? errno : 0, copyinstr(self->np));
	self->nn = 0;
	self->np = 0;
	self->nop = 0;
}

/* The second half of a rename: `new` is created. Declared after the clause above, which clears
 * self->nn and self->np but deliberately not self->np2. */
syscall::rename:return
/self->np2/
{
	printf("PATHOP|%d|%d|%s|rename|ret=%d|errno=%d|%s\n",
	    pid, curpsinfo->pr_ppid, execname,
	    (int)arg0, (int)arg0 < 0 ? errno : 0, copyinstr(self->np2));
	self->np2 = 0;
}

/* ── EXEC. Two records per exec, because neither one alone is sufficient on macOS.
 *
 * EXEC (proc:::exec-success) rebuilds the PROCESS TREE — pid, ppid, and the post-exec execname.
 * It is the only one of the two that fires for the new image, so parentage comes from here.
 *
 * ⛔ IT CANNOT IDENTIFY THE LIFECYCLE SHELL. `curpsinfo->pr_psargs` on macOS carries only the
 * COMMAND NAME, never the argv. MEASURED on run 31087159355 over a real `npm rebuild`: of 9 EXEC
 * records, ZERO contained a space at all — `sudo -u runner -H env PATH=<400 chars> …` came out as
 * the four characters `sudo`, and the lifecycle shell `sh -c "<script>"` came out as `sh`. So the
 * decoder's `psargs =~ / -c /` test could never match for any process on this platform, which is
 * why every macOS arm reported `lifecycle pids: 0`. This is a SEPARATE macOS fact from the
 * /bin/sh stub re-exec that broke `dtrace -c`; the re-exec is visible here (one pid, two EXEC
 * records, `sh` then `bash`) but harmless, since both names pass the shell-name test anyway.
 *
 * EXECARGV supplies the argv the tree cannot. copyin at ENTRY is safe here — and only here —
 * because the CALLER has just written the pointer array and the strings, so they are resident;
 * contrast the path argument of open(2), which the caller may never have touched, and which is the
 * copyinstr-at-entry defect fixed above. posix_spawn was measured as the weaker alternative: it
 * reports the PARENT's pid rather than the shell's, and faulted 5x against execve's 1x.
 *
 * Three argv slots is deliberate: `sh -c <script>` needs exactly [0], [1], [2], and copying only
 * what is needed keeps a short argv from reading past the array's NULL terminator.
 *
 * FIELD ORDER: the script body is LAST because it is free-form and routinely contains `|`. The
 * decoder rejoins everything from field 5 on. ──────────────────────────────────────────────── */

proc:::exec-success
/progenyof($target)/
{
	printf("EXEC|%d|%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs);
	@allexecs[execname] = count();
}

syscall::execve:entry
/progenyof($target)/
{
	this->v = (user_addr_t *)copyin(arg1, sizeof(user_addr_t) * 3);
	printf("EXECARGV|%d|%d|%s|%s|%s\n", pid, curpsinfo->pr_ppid,
	    this->v[0] != 0 ? copyinstr(this->v[0]) : "",
	    this->v[1] != 0 ? copyinstr(this->v[1]) : "",
	    this->v[2] != 0 ? copyinstr(this->v[2]) : "");
}

/* ── CONNECT. The sockaddr is copied at ENTRY because the kernel may have consumed it by return.
 * Darwin sockaddr_in: [0]=sin_len [1]=sin_family [2..3]=sin_port(BE) [4..7]=sin_addr(BE). ──── */

syscall::connect:entry, syscall::connect_nocancel:entry
/progenyof($target) && arg2 >= 16/
{
	self->sa = (uint8_t *)copyin(arg1, 16);
	self->fam = self->sa[1];
	/* MEASURED: `(self->sa[2] << 8) | self->sa[3]` reports port 187 for a connect to :443 — D
	 * does the shift in the operand's own uint8_t width and the high byte is truncated before the
	 * OR. The uint16_t cast is what makes the shift meaningful. */
	self->pt = ((uint16_t)self->sa[2] << 8) | (uint16_t)self->sa[3];
	self->b0 = self->sa[4];
	self->b1 = self->sa[5];
	self->b2 = self->sa[6];
	self->b3 = self->sa[7];
	self->cn = 1;
}

/* ⛔ DECODE THE FAMILY BEFORE THE ADDRESS. An AF_LOCAL sockaddr read as IPv4 yields a plausible
 * dotted quad that is really the socket path's characters — a real run reported "97.114.47.114".
 * Every non-AF_INET family is reported as itself with NO host rather than guessed at. */
syscall::connect:return, syscall::connect_nocancel:return
/self->cn && self->fam == 2/
{
	printf("CONN|%d|%d|%s|af=%d|%d.%d.%d.%d|port=%d|ret=%d|errno=%d\n",
	    pid, curpsinfo->pr_ppid, execname, self->fam,
	    self->b0, self->b1, self->b2, self->b3, self->pt,
	    (int)arg0, (int)arg0 < 0 ? errno : 0);
}

syscall::connect:return, syscall::connect_nocancel:return
/self->cn && self->fam != 2/
{
	printf("CONN-OTHERFAMILY|%d|%d|%s|af=%d|host=UNAVAILABLE|port=%d|ret=%d|errno=%d\n",
	    pid, curpsinfo->pr_ppid, execname, self->fam, self->pt,
	    (int)arg0, (int)arg0 < 0 ? errno : 0);
}

syscall::connect:return, syscall::connect_nocancel:return
/self->cn/
{
	self->cn = 0;
	self->fam = 0;
}

dtrace:::END
{
	printf("DTRACE-END\n");
	printf("TRACER-ERROR-TOTAL|");
	printa("%@d\n", @tracer_errors);
	printf("--- all opens by execname (breadth control) ---\n");
	printa("  %-40s %@d\n", @allopens);
	printf("--- all execs by execname ---\n");
	printa("  %-40s %@d\n", @allexecs);
}

/* ── THE LOSS LEDGER. Declared LAST on purpose: clause-probe tuples take their enabled-probe ids in
 * program order, so appending here leaves every existing epid where it was and keeps a future
 * "probe ID 31" report comparable to the enumeration in the np2 note above.
 *
 * ⛔ A COPY FAULT ABORTS THE WHOLE CLAUSE, SO THE EVENT IS DROPPED — AND UNTIL NOW IT WAS DROPPED
 * SILENTLY. dtrace's own complaint goes to STDERR, which the driver captures into `dtrace.log` and
 * which nothing downstream reads; `trace.txt` showed no gap at all, and the decoder went on to
 * print a confident grant synthesized from a stream it did not know was incomplete. A dropped event
 * is a path never seen, and a path never seen is a capability never granted — an UNDER-prediction,
 * the one direction that breaks real installs. The silence is the defect; the errors are only its
 * symptom. So the census belongs IN the event stream, where the decoder reads it.
 *
 * ERROR-probe args are the documented ones: arg1 epid, arg2 action index, arg3 DIF offset, arg4
 * fault type, arg5 the value that faulted (for a bad address, the address). `pid`/`execname` still
 * describe the thread that faulted, so a loss is attributable to a process. Nothing here can itself
 * fault: every field is kernel-side, with no copyin. */
dtrace:::ERROR
{
	@tracer_errors = sum(1);
	printf("TRACER-ERROR|%d|%d|%s|epid=%d|action=%d|fault=%d|addr=0x%x\n",
	    pid, curpsinfo->pr_ppid, execname, (int)arg1, (int)arg2, (int)arg4, arg5);
}
