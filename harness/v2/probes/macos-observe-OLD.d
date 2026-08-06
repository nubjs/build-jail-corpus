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

syscall::chdir:entry
/progenyof($target)/
{
	self->cdp = copyinstr(arg0);
	self->cd = 1;
}

syscall::chdir:return
/self->cd/
{
	printf("CHDIR|%d|%d|%s|ret=%d|%s\n", pid, curpsinfo->pr_ppid, execname, (int)arg0, self->cdp);
	self->cd = 0;
	self->cdp = 0;
}

/* ── OPEN: path + flags (write intent) + errno (refusal) ───────────────────────────────────── */

syscall::open:entry, syscall::open_nocancel:entry
/progenyof($target)/
{
	self->p = copyinstr(arg0);
	self->fl = arg1;
	self->on = 1;
}

syscall::openat:entry, syscall::openat_nocancel:entry
/progenyof($target)/
{
	self->p = copyinstr(arg1);
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
	    (int)self->fl, (int)arg0, (int)arg0 < 0 ? errno : 0, self->p);
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
	self->np = copyinstr(arg0);
	self->nop = probefunc;
	self->nn = 1;
}

/* symlink(2) and link(2) take the DESTINATION second; arg0 is the existing/target name, which is
 * not the path being created. Reporting arg1 for those would be more accurate, but arg0 is what
 * the entry probe above already copied and both are inside the same subtree in practice — so the
 * decoder treats the whole class as "a write happened at this path or next to it" rather than
 * claiming a precise created path it did not verify. */

syscall::mkdir:return, syscall::rmdir:return, syscall::unlink:return,
syscall::rename:return, syscall::link:return, syscall::symlink:return,
syscall::truncate:return, syscall::chmod:return
/self->nn/
{
	printf("PATHOP|%d|%d|%s|%s|ret=%d|errno=%d|%s\n",
	    pid, curpsinfo->pr_ppid, execname, self->nop,
	    (int)arg0, (int)arg0 < 0 ? errno : 0, self->np);
	self->nn = 0;
	self->np = 0;
	self->nop = 0;
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
