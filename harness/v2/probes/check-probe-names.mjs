// ⛔ OFFLINE GUARD: does every syscall the adapter subscribes actually EXIST as a dtrace probe?
//
// This is the failure that does not degrade gracefully. A `syscall::foo:entry` naming a probe the
// kernel does not publish makes dtrace refuse to run the WHOLE script — so one bad name does not
// lose one syscall, it takes the entire adapter offline and every arm downstream fails for a reason
// that has nothing to do with what it was measuring. And it is only discoverable on a machine with
// dtrace, which the maintainer's SIP-enabled Mac is not, so the loop is a CI round trip per typo.
//
// The PRESENT/ABSENT split below was MEASURED on macOS 15.7.7 / arm64 (run 31116027627) by
// compiling each candidate name ALONE — the only safe way to ask, for the same reason. This file
// turns that one measurement into a check that runs in milliseconds, offline, forever.
//
// ⛔ IT IS A NECESSARY CONDITION, NOT A SUFFICIENT ONE. It cannot catch a wrong ARGUMENT INDEX
// (`mkdirat`'s path is arg1, not arg0), a type error, or a clause that never fires — only CI and
// `at-family-fixture.sh` can. A green result here means "no name will kill the script", nothing more.
//
//   usage: node check-probe-names.mjs [path/to/macos-observe.d]
import fs from 'node:fs';

const file = process.argv[2] ?? new URL('../adapters/macos-observe.d', import.meta.url).pathname;
const src = fs.readFileSync(file, 'utf8');

// Measured present on macOS 15.7.7 / arm64. The base set (open/openat/chdir/connect/execve and
// their `_nocancel` twins) predates that run and has been live in every trace this lane has taken.
const PRESENT = new Set(`
access chmod chown clonefileat copyfile exchangedata faccessat fchmod fchmodat fchown fchownat
fclonefileat fremovexattr fsetattrlist fsetxattr fstatat fstatat64 ftruncate futimes getattrlist
getattrlistat getxattr lchown link linkat listxattr lstat lstat64 mkdir mkdirat mkfifo mknod
open_dprotected_np openbyid_np readlink readlinkat removexattr rename renameat renameatx_np rmdir
setattrlist setattrlistat setxattr stat stat64 symlink symlinkat truncate undelete unlink unlinkat
utimes
open open_nocancel openat openat_nocancel chdir connect connect_nocancel execve
`.trim().split(/\s+/));

// ⛔ MEASURED ABSENT — unreachable from the `syscall` provider on this kernel, not merely
// unsubscribed. `renamex_np` and `utimensat` are the two that matter: both are real Darwin syscalls
// a modern libc reaches for, and no `syscall:::entry` census can even COUNT them. Closing that gap
// needs Endpoint Security, whose `rename` event fires for the VFS operation whichever syscall
// entered it. Listed separately so a future edit that reaches for one gets a specific error rather
// than "unknown name".
const ABSENT = new Set(['clonefile', 'futimens', 'lchmod', 'renamex_np', 'utimensat']);

const used = [...new Set([...src.matchAll(/syscall::([a-z_0-9]+):(entry|return)/g)].map((m) => m[1]))].sort();
const bad = used.filter((n) => !PRESENT.has(n));
const absent = bad.filter((n) => ABSENT.has(n));
const unknown = bad.filter((n) => !ABSENT.has(n));

console.log(`${file}: ${used.length} distinct syscalls subscribed`);
for (const n of absent) {
  console.error(`  ⛔ ${n} — MEASURED ABSENT on macOS 15.7.7/arm64. dtrace will refuse the whole script.`);
}
for (const n of unknown) {
  console.error(`  ⛔ ${n} — not in the measured PRESENT set. Prove it exists (\`dtrace -l -n `
    + `'syscall::${n}:entry'\`) before subscribing it, or the adapter stops running entirely.`);
}
if (bad.length === 0) console.log('  all names measured present — no name can kill the script');
process.exit(bad.length ? 1 : 0);
