// How to invoke npm from a harness process, on every platform.
//
// ⛔ THIS EXISTS BECAUSE THE SAME BUG WAS FIXED ONCE AND LEFT STANDING SOMEWHERE ELSE. npm ships on
// Windows as a `.cmd` shim, and `spawnSync('npm', …)` cannot execute one: it returns 127, and
// switching to `npm.cmd` fails EARLIER with status null, because Node refuses to spawn a `.cmd`
// without `shell: true` (the CVE-2024-27980 fix). `shell: true` would work and would re-introduce
// quoting hazards on every spec containing a scope or a caret.
//
// observe-only.mjs was converted to run npm's JS entry point directly. era-node.mjs was not, and its
// `enginesAndDate` kept the default `npmArgv: ['npm']` — which fails silently to
// `{engines: null, published: null}`. The result went unnoticed for two full sweeps: ALL 570 win32
// rows carried eraMajor null AND before null, so every Windows record was measured on a modern Node
// with undated resolution while the ledger showed a confident `PINNED 22.23.2`. That is the harness
// default, not an era.
//
// npm's entry point is plain JS and sits predictably next to the interpreter: POSIX puts it under
// `lib/node_modules`, Windows directly under the install root.
import fs from 'node:fs';
import path from 'node:path';

/** `{ cmd, prefix }` — spawn `cmd` with `[...prefix, ...npmArgs]`. Falls back to the shim only when
 *  the JS entry cannot be found, so a POSIX box with an unusual layout still works. */
export function npmInvocation(execPath = process.execPath, platform = process.platform) {
  const dir = path.dirname(execPath);
  for (const candidate of [
    path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ]) {
    if (fs.existsSync(candidate)) return { cmd: execPath, prefix: [candidate] };
  }
  return { cmd: platform === 'win32' ? 'npm.cmd' : 'npm', prefix: [] };
}

/** The same thing shaped as the `npmArgv` that `enginesAndDate` takes. */
export function npmArgv(execPath = process.execPath, platform = process.platform) {
  const { cmd, prefix } = npmInvocation(execPath, platform);
  return [cmd, ...prefix];
}
