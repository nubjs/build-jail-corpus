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

dtrace:::BEGIN
{
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

/* ── EXEC. psargs is the only place the lifecycle shell's `-c <script>` text appears, and that
 * text is what separates the package's script from npm's own subtree. ─────────────────────── */

proc:::exec-success
/progenyof($target)/
{
	printf("EXEC|%d|%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs);
	@allexecs[execname] = count();
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
	printf("--- all opens by execname (breadth control) ---\n");
	printa("  %-40s %@d\n", @allopens);
	printf("--- all execs by execname ---\n");
	printa("  %-40s %@d\n", @allexecs);
}
