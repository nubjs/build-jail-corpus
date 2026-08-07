// Did the lifecycle script fail to LAUNCH, as opposed to running and exiting non-zero?
//
// ⛔⛔ WHY THIS MATTERS, AND IT IS NOT A COSMETIC DISTINCTION. An arm whose script never spawned
// leaves the package tree exactly as the tarball unpacked it — which is BYTE-IDENTICAL to an arm
// whose script spawned and died on its first statement. Both produce the same artifact set, the
// same shortfall digest, and the same `rc=1`. Nothing downstream can tell them apart.
//
// MEASURED on 2026-08-07: `postman-code-generators@0.2.4` on win32 produced shortfall
// `f648aa40f798` at BOTH `fb0` (script ran, died on its first `shell.exec`) and `fb1` (script never
// spawned at all — the `read:"disk"` rung goes into a reduced mode where the launch fails
// `ERROR_INVALID_PARAMETER`). The grant-INDEPENDENCE test then read that agreement as evidence the
// shortfall did not respond to the grant. It was two unrelated failures wearing one digest.
//
// ⇒ A never-spawned arm MEASURED NOTHING, which is precisely what VOID already means in all three
// drivers ("the override did not engage; NOTHING was measured"). This reuses that outcome rather
// than inventing a fourth one, so every existing VOID consumer handles it correctly for free.
//
// ⛔ SAFE DIRECTION: VOID refuses to conclude. It cannot narrow a grant, so a false positive here
// costs a re-measure, never an under-grant. That is the direction this project requires.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * nub's own message when it could not launch the script at all. The `failed to spawn` tail is on
 * the same line as `failed for <pkg>`, so this needs no multi-line matching.
 *
 * ⛔ Deliberately NOT a bare /failed to spawn/: that phrase can appear in a script's OWN output
 * (a package reporting that IT could not spawn something), which is a real measurement, not a void.
 * Anchoring on nub's `lifecycle script … failed for …:` prefix keeps it to nub's launch failure.
 */
export const NEVER_SPAWNED = /lifecycle script\s+\S+\s+failed for\s+\S+:\s*failed to spawn/;

/** Did any of this text show nub failing to LAUNCH a lifecycle script? */
export const neverSpawned = (logText) => NEVER_SPAWNED.test(String(logText ?? ''));

/** Same question asked of an arm directory: true if any *.log in it shows a launch failure. */
export function armNeverSpawned(armDir) {
  let names;
  try { names = fs.readdirSync(armDir); } catch { return false; }
  for (const n of names) {
    if (!n.endsWith('.log')) continue;
    try { if (neverSpawned(fs.readFileSync(path.join(armDir, n), 'utf8'))) return true; } catch { /* unreadable */ }
  }
  return false;
}

// CLI for the bash drivers: `node never-spawned.mjs <armDir>` — exit 0 means NEVER SPAWNED (so the
// caller should VOID the arm), exit 1 means it spawned. No output; the caller prints its own line.
// ⛔ `process.argv[1]` compared by REALPATH — on macOS `/tmp` is a symlink to `/private/tmp`, so a
// plain string compare silently skips this branch when the script is reached through one.
// ⛔⛔ AND VIA `fileURLToPath`, NEVER `.pathname`: that yields `/C:/…` on Windows, and the WINDOWS
// driver imports this module. The repo's `cli-guard.test.mjs` exists for exactly this and has now
// caught it three times in this effort — I wrote `.pathname` here first too.
if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(armNeverSpawned(process.argv[2] || '.') ? 0 : 1);
}
