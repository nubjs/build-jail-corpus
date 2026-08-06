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
#pragma D option bufsize=64m
// MEASURED (run 31078241875, macos-14): at dynvarsize=32m the 4-way-filesystem-load arm produced
// 2700-6100 "dynamic variable drops with non-empty dirty list" per report and the shape under load
// was MISSED entirely, while macos-15 — same script, less contention — caught it. The thread-local
// path string is what consumes the space, so the fix is more dynvar space and a shorter string,
// not a narrower subscription. This is a TUNABLE limit; it is not the structural blindness that
// made eslogger unusable.
#pragma D option dynvarsize=256m
#pragma D option strsize=1024

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
	/* MEASURED: `(self->sa[2] << 8) | self->sa[3]` reported port 187 for a connect to :443. D does
	 * the shift in the operand's own uint8_t width, so the high byte is truncated away before the
	 * OR and only 0xBB survives. The cast to uint16_t is what makes the shift meaningful. */
	self->pt = ((uint16_t)self->sa[2] << 8) | (uint16_t)self->sa[3];
	self->b0 = self->sa[4];
	self->b1 = self->sa[5];
	self->b2 = self->sa[6];
	self->b3 = self->sa[7];
	self->cn = 1;
}

/* AF_INET (2) is the only family whose bytes 4..7 ARE an IPv4 address. The first run decoded an
 * AF_LOCAL sockaddr as "97.114.47.114:118" — a path's characters read as octets. That is exactly
 * the fabricated field the EVENT contract forbids, so every other family is reported as itself
 * with no host at all rather than guessed at. */
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
{
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
