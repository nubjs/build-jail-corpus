/*
 * macOS syscall tracer — the direct analogue of `strace -f` on Linux.
 *
 * The EVENT contract (harness/v2/MAPPING.md) needs four things that the two previously-measured
 * macOS sources cannot jointly supply: the pid that PERFORMED the operation, write-vs-read INTENT,
 * a numeric ERRNO for a genuine refusal, and a TCP PEER. Endpoint Security NOTIFY events fire only
 * on operations that were ALLOWED, so a refusal is structurally unreportable there; `fs_usage`
 * formats connect as FMT_FD and never shows the sockaddr. dtrace sits at the syscall boundary and
 * sees the return value, so it has all four or none.
 *
 * $$1 is a substring filter on the path. Everything routed through this probe writes files carrying
 * a per-run token, so the filter keeps the stream readable without hiding whether the tracer was
 * broadly live — the @allopens/@allexecs aggregations at END prove that independently.
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=32m
#pragma D option dynvarsize=32m
#pragma D option strsize=2048

dtrace:::BEGIN
{
	printf("DTRACE-LIVE|filter=%s\n", $$1);
}

/* ── OPEN: path + flags (write intent) + errno (refusal) ───────────────────────────────────── */

syscall::open:entry, syscall::open_nocancel:entry
{
	self->p = copyinstr(arg0);
	self->fl = arg1;
	self->on = 1;
}

syscall::openat:entry, syscall::openat_nocancel:entry
{
	self->p = copyinstr(arg1);
	self->fl = arg2;
	self->on = 1;
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/self->on/
{
	@allopens[execname] = count();
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/self->on && strstr(self->p, $$1) != NULL/
{
	/* flags carry O_WRONLY(1)/O_RDWR(2)/O_CREAT(0x200)/O_TRUNC(0x400)/O_APPEND(8) */
	printf("OPEN|%d|%d|%s|flags=0x%x|ret=%d|errno=%d|%s\n",
	    pid, curpsinfo->pr_ppid, execname,
	    (int)self->fl, (int)arg0, (int)arg0 < 0 ? errno : 0, self->p);
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
{
	self->on = 0;
	self->p = 0;
	self->fl = 0;
}

/* ── EXEC ──────────────────────────────────────────────────────────────────────────────────── */

proc:::exec-success
{
	@allexecs[execname] = count();
	printf("EXEC|%d|%d|%s|%s\n", pid, curpsinfo->pr_ppid, execname, curpsinfo->pr_psargs);
}

/* ── CONNECT: the sockaddr is copied in at entry because the kernel may have consumed it by the
 * time the syscall returns. AF_INET sockaddr_in on Darwin is
 *   [0]=sin_len [1]=sin_family [2..3]=sin_port(BE) [4..7]=sin_addr(BE)
 * so the peer is read out of raw bytes rather than a struct definition we would have to include. */

syscall::connect:entry, syscall::connect_nocancel:entry
/arg2 >= 16/
{
	self->sa = (uint8_t *)copyin(arg1, 16);
	self->fam = self->sa[1];
	self->pt = (self->sa[2] << 8) | self->sa[3];
	self->b0 = self->sa[4];
	self->b1 = self->sa[5];
	self->b2 = self->sa[6];
	self->b3 = self->sa[7];
	self->cn = 1;
}

syscall::connect:return, syscall::connect_nocancel:return
/self->cn/
{
	printf("CONN|%d|%d|%s|af=%d|%d.%d.%d.%d|port=%d|ret=%d|errno=%d\n",
	    pid, curpsinfo->pr_ppid, execname, self->fam,
	    self->b0, self->b1, self->b2, self->b3, self->pt,
	    (int)arg0, (int)arg0 < 0 ? errno : 0);
	self->cn = 0;
}

dtrace:::END
{
	printf("DTRACE-END\n");
	printf("--- all opens by execname (breadth control) ---\n");
	printa("  %-40s %@d\n", @allopens);
	printf("--- all execs by execname ---\n");
	printa("  %-40s %@d\n", @allexecs);
}
