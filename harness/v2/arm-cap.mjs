// A wall-clock cap on one measured arm that kills the whole PROCESS GROUP, not just the child.
//
// ⛔ THE MEASURED FAILURE. `optipng-bin@2.0.0`'s postinstall re-spawns
// `node .../optipng-bin/vendor/optipng --version` without bound. A re-measure of the primordials
// class hit it and reached **211 live children** with PIDs still climbing before it was killed by
// hand. One package like that takes a runner down and every record behind it in the shard is lost.
//
// ⛔ AND THE EXISTING CAPS DO NOT CATCH IT, WHICH IS THE POINT OF THIS FILE.
//   - `measure.sh` and `measure-macos.sh` enforce NOTHING: no `--arm-timeout`, no `timeout`, no
//     `ulimit`. Only `measure-windows.mjs` caps its arms. Verified by grep across all three.
//   - `run-batch-v2.mjs`'s 40-minute per-package budget is a `spawnSync` timeout, which signals the
//     DIRECT CHILD only. Orphaned grandchildren survive it and accumulate across a shard.
//   - `harness/portable-timeout.sh` (v1, unused by v2) does `kill "KILL", $pid` — again one pid, so
//     it would not have caught this either. It also `exec`s bare `perl`, and on at least one dev box
//     the MacPorts perl on PATH never returns and ignores SIGTERM.
//
// So the cap is written here, in node — already the harness's own runtime, so it adds no dependency
// and dodges the perl question entirely.
//
// ⛔ `detached: true` IS THE WHOLE MECHANISM. It puts the child in a NEW PROCESS GROUP whose id
// equals its pid, which is what makes `process.kill(-pid)` reach every descendant however deeply
// the package nests them. Without it the negative-pid kill would signal the HARNESS's own group.
//
// Exit 124 on the cap, matching GNU `timeout`, because `record.mjs:429` and `run-batch-v2.mjs:292`
// already read 124 as the timeout convention. A new spelling would be a third dialect.

import { spawn } from 'node:child_process';

export const TIMEOUT_EXIT = 124;

/** Run `command` with `args`, killing its entire process group after `ms`.
 *
 *  Resolves `{ code, timedOut, signal }`. A caller that only reads `code` still behaves correctly,
 *  because a capped run reports 124. */
export function runCapped(command, args, { ms, spawnImpl = spawn, ...opts } = {}) {
  return new Promise((resolve) => {
    const child = spawnImpl(command, args, { ...opts, detached: true });
    let timedOut = false;
    let settled = false;
    const done = (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: timedOut ? TIMEOUT_EXIT : (code ?? 1), timedOut, signal: signal ?? null });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      // ⛔ SIGKILL, NOT SIGTERM. What is being capped is a package's own install script, which may
      // ignore TERM — and the runaway case above was a spawn loop that would simply keep spawning
      // through a graceful signal. A cap that can be ignored is not a cap.
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* group already gone */ }
      // Belt and braces: if the group kill failed because the child never got its own group, the
      // direct kill still stops the thing we launched.
      try { child.kill('SIGKILL'); } catch { /* already dead */ }
      done(TIMEOUT_EXIT, 'SIGKILL');
    }, ms);
    child.on('error', () => done(127, null));
    child.on('exit', (code, signal) => done(code, signal));
  });
}

if (import.meta.filename === process.argv[1]) {
  const [secs, ...rest] = process.argv.slice(2);
  if (!secs || !rest.length) {
    process.stderr.write('usage: arm-cap.mjs <seconds> <command> [args...]\n');
    process.exit(2);
  }
  const r = await runCapped(rest[0], rest.slice(1), { ms: Number(secs) * 1000, stdio: 'inherit' });
  if (r.timedOut) process.stderr.write(`ARM-CAP KILLED the process group after ${secs}s\n`);
  process.exit(r.code);
}
