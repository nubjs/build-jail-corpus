// KNOWN-ANSWER fixture for "does `strace -f -e trace=file,network,process` + observe.mjs's decoder
// see every path an install script writes?"
//
// Every operation below CREATES OR MUTATES a file at a path whose basename names the operation, so
// the expected write set is knowable by construction rather than read off the trace. The program
// prints that expected set to stdout as `EXPECT <path>`; the comparison script diffs it against the
// write set observe.mjs reports. A path in EXPECT but not in observe's output is a MISSED WRITE,
// which is the under-grant direction this whole system may not take.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <time.h>

static char P[512];
static void expect(const char *rel) { printf("EXPECT %s/%s\n", P, rel); }
static void note(const char *s) { printf("NOTE %s\n", s); }

static char *abspath(const char *rel) {
  static char buf[8][1024]; static int i = 0;
  char *b = buf[i++ & 7]; snprintf(b, 1024, "%s/%s", P, rel); return b;
}

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: probe <dir>\n"); return 2; }
  snprintf(P, sizeof P, "%s", argv[1]);
  mkdir(P, 0755);
  int dfd = open(P, O_RDONLY | O_DIRECTORY);
  if (dfd < 0) { perror("open dir"); return 1; }
  int fd; char *p;

  // A — plain absolute open for write. The baseline: if THIS is missed nothing else matters.
  p = abspath("A-open-abs");
  fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644); write(fd, "a", 1); close(fd);
  expect("A-open-abs");

  // B — openat relative to a REAL dirfd. strace prints the dirfd as a NUMBER, not `AT_FDCWD`.
  fd = openat(dfd, "B-openat-dirfd", O_WRONLY | O_CREAT | O_TRUNC, 0644); write(fd, "b", 1); close(fd);
  expect("B-openat-dirfd");

  // C — rename. BOTH arguments are writes: `src` is unlinked, `dst` is created.
  p = abspath("C-rename-src");
  fd = open(p, O_WRONLY | O_CREAT, 0644); write(fd, "c", 1); close(fd);
  rename(abspath("C-rename-src"), abspath("C-rename-dst"));
  expect("C-rename-src"); expect("C-rename-dst");

  // D — renameat2 with real dirfds on both sides.
  fd = openat(dfd, "D-renameat2-src", O_WRONLY | O_CREAT, 0644); write(fd, "d", 1); close(fd);
  syscall(SYS_renameat2, dfd, "D-renameat2-src", dfd, "D-renameat2-dst", 0);
  expect("D-renameat2-src"); expect("D-renameat2-dst");

  // E — O_TMPFILE then linkat(AT_EMPTY_PATH). The file is created with NO path at all, then given
  // one by a syscall whose first argument is a number and whose second is the empty string.
  fd = open(P, O_TMPFILE | O_RDWR, 0644);
  if (fd >= 0) {
    char proc[64]; snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    write(fd, "e", 1);
    linkat(AT_FDCWD, proc, AT_FDCWD, abspath("E-linkat-tmpfile"), AT_SYMLINK_FOLLOW);
    close(fd);
    expect("E-linkat-tmpfile");
  } else note("E SKIPPED - O_TMPFILE unsupported on this fs");

  // F — mkdirat relative to a real dirfd.
  mkdirat(dfd, "F-mkdirat-dirfd", 0755);
  expect("F-mkdirat-dirfd");

  // G — unlinkat relative to a real dirfd. The CREATE is absolute (and should be seen); the
  // DELETE is the operation under test. A deletion is a write: it needs the grant.
  p = abspath("G-unlinkat-dirfd");
  fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
  unlinkat(dfd, "G-unlinkat-dirfd", 0);
  expect("G-unlinkat-dirfd");

  // H — symlinkat relative to a real dirfd. The LINKPATH is what gets created.
  symlinkat("irrelevant-content", dfd, "H-symlinkat-dirfd");
  expect("H-symlinkat-dirfd");

  // I — plain symlink. Control for H: the decoder's `linkTarget` fix should take the LAST argument.
  symlink("I-content-not-a-path", abspath("I-symlink-abs"));
  expect("I-symlink-abs");

  // J — ftruncate through an fd. The path is only ever named by the open.
  p = abspath("J-ftruncate");
  fd = open(p, O_RDWR | O_CREAT, 0644); write(fd, "jjjjjj", 6); ftruncate(fd, 2); close(fd);
  expect("J-ftruncate");

  // K — copy_file_range. Neither argument is a path; the destination is only named by its open.
  {
    int s = open(abspath("A-open-abs"), O_RDONLY);
    int d = open(abspath("K-cfr-dst"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    loff_t off_in = 0, off_out = 0;
    syscall(SYS_copy_file_range, s, &off_in, d, &off_out, (size_t)1, 0u);
    close(s); close(d);
    expect("K-cfr-dst");
  }

  // L — sendfile. Same shape as K.
  {
    int s = open(abspath("A-open-abs"), O_RDONLY);
    int d = open(abspath("L-sendfile-dst"), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    off_t off = 0; sendfile(d, s, &off, 1);
    close(s); close(d);
    expect("L-sendfile-dst");
  }

  // M — MAP_SHARED|PROT_WRITE mmap. Bytes reach the file with no write() and no path in sight.
  {
    p = abspath("M-mmap-shared");
    fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0644); ftruncate(fd, 4096);
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m != MAP_FAILED) { memcpy(m, "mmap", 4); munmap(m, 4096); }
    close(fd);
    expect("M-mmap-shared");
  }

  // N — a path far longer than strace's default `-s 32` string limit. strace documents filenames as
  // exempt from that limit; this row is what proves it rather than trusting the man page.
  {
    char longrel[400]; memset(longrel, 'n', sizeof longrel); longrel[0] = 'N';
    memcpy(longrel, "N-long-", 7);
    longrel[300] = 0;
    p = abspath(longrel);
    fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
    expect(longrel);
  }

  // O — a path containing a space, then one containing a double quote. strace escapes the quote,
  // and the decoder's `"([^"]*)"` capture stops at the escaped quote — a real truncation.
  {
    fd = open(abspath("O-with space-file"), O_WRONLY | O_CREAT, 0644); close(fd);
    expect("O-with space-file");
    fd = open(abspath("O-with\"quote-file"), O_WRONLY | O_CREAT, 0644); close(fd);
    expect("O-with\"quote-file");
  }

  // P — openat with the AT_FDCWD sentinel. The form the decoder explicitly handles; a control.
  fd = openat(AT_FDCWD, abspath("P-openat-atfdcwd"), O_WRONLY | O_CREAT, 0644); close(fd);
  expect("P-openat-atfdcwd");

  // Q — chdir, then a RELATIVE open. Exercises the decoder's per-pid cwd tracking.
  if (chdir(P) == 0) {
    fd = open("Q-relative-after-chdir", O_WRONLY | O_CREAT, 0644); close(fd);
    expect("Q-relative-after-chdir");
    if (chdir("/") != 0) note("Q chdir back failed");
  } else note("Q SKIPPED - chdir failed");

  // R — fchmodat with a real dirfd. A mode change is a write to metadata and needs the grant.
  p = abspath("R-fchmodat-dirfd");
  fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
  fchmodat(dfd, "R-fchmodat-dirfd", 0700, 0);
  expect("R-fchmodat-dirfd");

  // S — chmod on an ABSOLUTE path. Control for R: the decoder's outer filter DOES list `chmod`.
  p = abspath("S-chmod-abs");
  fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
  chmod(p, 0700);
  expect("S-chmod-abs");

  // T — openat2. A newer syscall with a different argument shape (`how={flags=...}`).
  {
    struct open_how how; memset(&how, 0, sizeof how);
    how.flags = O_WRONLY | O_CREAT; how.mode = 0644;
    long r = syscall(SYS_openat2, AT_FDCWD, abspath("T-openat2"), &how, sizeof how);
    if (r >= 0) { close((int)r); expect("T-openat2"); } else note("T SKIPPED - openat2 unsupported");
  }

  // U — mknod (a FIFO). Creates a filesystem entry through a syscall the decoder's filter omits.
  if (mknod(abspath("U-mknod-fifo"), S_IFIFO | 0644, 0) == 0) expect("U-mknod-fifo");
  else note("U SKIPPED - mknod failed");

  // V — chown to the SAME uid/gid (always permitted, still a metadata write).
  p = abspath("V-chown-abs");
  fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
  if (chown(p, getuid(), getgid()) == 0) expect("V-chown-abs"); else note("V SKIPPED - chown failed");

  // W — utimensat with a real dirfd.
  p = abspath("W-utimensat-dirfd");
  fd = open(p, O_WRONLY | O_CREAT, 0644); close(fd);
  { struct timespec ts[2] = {{1000000000, 0}, {1000000000, 0}};
    if (utimensat(dfd, "W-utimensat-dirfd", ts, 0) == 0) expect("W-utimensat-dirfd");
    else note("W SKIPPED - utimensat failed"); }

  // X — truncate on an absolute path.
  p = abspath("X-truncate-abs");
  fd = open(p, O_WRONLY | O_CREAT, 0644); write(fd, "xxxx", 4); close(fd);
  truncate(p, 1);
  expect("X-truncate-abs");

  // Y — write through a REINHERITED fd. The open happens here; the write happens in a child that
  // never names the path. Included to show the decoder is right to bill the open, not the write.
  p = abspath("Y-inherited-fd");
  fd = open(p, O_WRONLY | O_CREAT, 0644);
  if (fork() == 0) { write(fd, "y", 1); _exit(0); }
  close(fd);
  expect("Y-inherited-fd");

  close(dfd);
  return 0;
}
