// The KNOWN ANSWER. Every syscall this program makes on purpose is listed in EXPECTED.json, and the
// validator asserts the adapter reports that set exactly — nothing missing, nothing invented.
//
// Written in C rather than node/python on purpose: an interpreter makes thousands of incidental
// syscalls, and "exactly this set" stops being assertable. Here the deliberate calls are the only
// interesting ones, so a false NEGATIVE (adapter missed a real access) and a false POSITIVE
// (adapter reported one that never happened) are both directly observable.
//
// ⛔ MUST NOT RUN AS ROOT. Two of the checks depend on ordinary permission enforcement:
// the EACCES open, and the fact that root would bypass mode 000 entirely. The tracer runs as
// root; the traced fixture does not.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static void die(const char *what) { fprintf(stderr, "fixture: %s: %s\n", what, strerror(errno)); exit(1); }

int main(int argc, char **argv) {
	if (argc != 5) { fprintf(stderr, "usage: fixture <projDir> <homeDir> <readFile> <port>\n"); return 2; }
	const char *proj = argv[1], *home = argv[2], *readfile = argv[3];
	int port = atoi(argv[4]);
	char p[4096];
	fprintf(stderr, "fixture: pid=%d ppid=%d\n", getpid(), getppid());

	// THE FALSIFICATION CONTROL. `FIXTURE_SKIP=home` omits behaviour (1) and nothing else, so the
	// validator can be run a second time against a fixture that provably did NOT write there. If
	// that arm still reports the write, the adapter is inventing events and every green result from
	// the first arm is worthless. A probe with no failing control is not evidence.
	const char *skip = getenv("FIXTURE_SKIP");
	int skip_home = skip && !strcmp(skip, "home");

	// (1) WRITE under the throwaway HOME. O_CREAT|O_WRONLY — write intent is in these flags, which
	// is the only place it is visible; a later write(2) carries an fd and no path.
	int fd;
	if (skip_home) {
		fprintf(stderr, "fixture: SKIPPING home write (falsification control)\n");
	} else {
		snprintf(p, sizeof p, "%s/home-write.txt", home);
		fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) die("home write open");
		write(fd, "home\n", 5); close(fd);
	}

	// (2) READ a file the fixture never writes. The adapter must report this as a read and MUST NOT
	// report it as a write — that specific false positive is what over-grants a scope.
	fd = open(readfile, O_RDONLY);
	if (fd < 0) die("read-only open");
	char buf[64]; read(fd, buf, sizeof buf); close(fd);

	// (3) TCP connect to a listener the harness started on loopback. Deterministic and offline;
	// it exercises the same socket()+connect() path as a real download without depending on DNS
	// or the network. What it does NOT exercise is name resolution — stated in README-macos.md.
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) die("socket");
	struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)port);
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) die("connect");
	close(s);

	// (4) THE DENIAL. A mode-000 file the harness pre-created. This must surface as result:"denied"
	// and it is the only genuine refusal the fixture performs.
	snprintf(p, sizeof p, "%s/denied.txt", proj);
	fd = open(p, O_RDONLY);
	if (fd >= 0) { fprintf(stderr, "fixture: FATAL denied.txt was READABLE (running as root?)\n"); return 3; }
	if (errno != EACCES) { fprintf(stderr, "fixture: FATAL denied.txt gave %s, wanted EACCES\n", strerror(errno)); return 3; }

	// (5) THE NEAR-MISS CONTROL — the macOS analogue of Linux's AT_EACCESS trap, and the reason a
	// free-text scan for a bracketed number is wrong. fs_usage renders an openat's DIRECTORY FD in
	// the pathname column as "[ 3]/relative/path", using the same [%3d] bracket form it uses for an
	// errno. This call SUCCEEDS. Any adapter that reports it as denied has a false-positive
	// refusal predicate, and the validator fails on exactly that.
	int dirfd = open(proj, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) die("open projdir");
	fd = openat(dirfd, "nearmiss.txt", O_RDONLY);
	if (fd < 0) die("openat nearmiss (must SUCCEED — it is the control)");
	close(fd); close(dirfd);

	fprintf(stderr, "fixture: all 5 behaviours performed\n");
	return 0;
}
