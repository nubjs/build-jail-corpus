// The two socket syscalls nub's Linux seccomp filter guards, as a LEAF that imports nothing.
//
// ⛔⛔ IT IS A LEAF FOR THE SAME REASON `windows-status.mjs` IS ONE, IN MIRROR, AND
// `three-driver-parity.test.mjs` is what forces both. `denial-witness.mjs` is reached by ALL THREE
// drivers, so a constant it imports drags the whole module holding that constant into all three
// closures. While this set lived in `adapters/linux.mjs`, wiring the win32 driver to the scorer pulled
// the STRACE DECODER into the win32 driver's closure and staled its platform exemption — the same move
// that, in the other direction, had dragged `windows-retain.mjs`, `windows-shortnames.mjs` and
// `windows.ps1` into both POSIX drivers and staled three exemptions at once.
//
// ⛔ AND IT IS ONE DEFINITION, NOT A COPY. `adapters/linux.mjs` re-exports this rather than restating
// it, so the decoder that EMITS these syscall names and the scorer that uses them as a positive
// control cannot come to disagree. Two copies of a vocabulary is how `measure.sh` came to emit
// `network` where `record.mjs` matched `no-network`, with both sides' tests green.

/**
 * The two the seccomp filter actually guards. `denial-witness.mjs` uses them as its POSITIVE CONTROL:
 * a stream in which the decoder saw not one `socket`/`socketpair` outcome anywhere — not even from the
 * tool processes, which open registry sockets on every arm — did not capture the syscall the jail
 * refuses, so an absence of refusals in it is not evidence and must not read CLEAN.
 *
 * ⛔ THE JAIL DOES NOT REFUSE AT `connect`, WHICH IS WHY THE CONTROL IS THESE TWO AND NOT THAT ONE.
 * `vendor/aube/crates/aube-scripts/src/linux_jail.rs` attaches its denied-family rules to `SYS_socket`
 * and `SYS_socketpair` alone, with `match_action = Errno(EPERM)`. A refused network attempt therefore
 * emits no `connect` event at all, and scoring an absence of `connect` refusals would have shipped an
 * under-grant.
 */
export const SOCKET_SYSCALLS = new Set(['socket', 'socketpair']);
