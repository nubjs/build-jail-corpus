// The WIDE-BUT-CONFINED probe: the widest write scope that still keeps the sandbox ENGAGED.
//
// ⛔⛔ THE CONFOUND THIS EXISTS TO REMOVE. The ladder's terminal rung is `{"write":"disk"}`, and that
// rung is NOT a wider sandbox — it is NO SANDBOX. Exactly one function produces it, and it flips three
// things at once (`crates/nub-sandbox/src/compiler/preset.rs`, `relax_fs_to_full_disk`):
//
//     policy.fs.rules.entries.clear();              // the secret/.env floor lives in `entries`
//     policy.fs.rules.default_effect = Effect::Allow;
//     policy.fs.tmp = TmpMode::Shared;              // the host tmp comes back
//
// and each backend then stands down: `linux_landlock.rs` emits a single `/` `FullDisk` rule, and
// `windows.rs` returns `plain_command` with `Degradation::full()` and `net` on `lost` — no LowBox
// token, no filesystem axis, no network axis. So a package that passes ONLY at the terminal rung may
// need a wide write scope, or may be failing for a sandbox-compatibility reason that no path grant can
// fix, and the ladder cannot tell those apart. `measure-windows.mjs` has said so in a comment since it
// was written; this module is the measurement that answers it.
//
// ⛔ IT IS A PROBE, NOT A PUBLISHING RUNG, AND THAT IS WHAT MAKES IT FAIL-CLOSED. The widening below is
// delivered through the catalog's GLOBAL `baseline`, which the shipped per-package grant vocabulary has
// no spelling for — `catalog_v2::Reach` is `None | Scopes[deps|project|userHome] | Disk` and nothing
// else. Publishing a grant this probe passed at would therefore hand the catalog a narrower entry than
// the package was measured to need, which is the under-granting direction and the one that breaks real
// installs. So the probe RECORDS and the ladder then continues to the terminal rung, which still
// decides the published grant. Nothing here can narrow a record.
//
// ── WHY THE SANDBOX STAYS ENGAGED, from the backend source ────────────────────────────────────────
//
// All three backends share ONE predicate, spelled identically in each
// (`linux_grants.rs:37`, `windows.rs:390`, and the macOS equivalent):
//
//     fs_confines(fs) = fs.rules.default_effect != Effect::Allow || !fs.rules.entries.is_empty()
//
// A catalog `baseline` entry never touches `default_effect`. `preset.rs`'s `build_jail_surface` folds
// each one into the policy's fs map as an ordinary allow —
//
//     for b in crate::catalog_override::baseline_paths() {
//         fs.insert(b.path.clone(), json!(if b.write { "rw" } else { "r" }));
//     }
//
// — so the build jail's `default_effect` stays `Deny` and `entries` only grows. `fs_confines` stays
// TRUE and Landlock / Seatbelt / the LowBox token all stay on. This is the same shape the `read:"disk"`
// rung already uses (`relax_fs_read_to_disk_minus_secrets`), which is documented in that function as
// keeping confinement on all three platforms.
//
// ⛔⛔ NEVER A ROOT GLOB, AND THE TWO SPELLINGS THAT WOULD SILENTLY DESTROY THE PROBE ARE DIFFERENT ON
// EACH PLATFORM. Linux's `is_whole_root` accepts `"" | "**" | "/" | "/**"` and DROPS the grant
// entirely; Windows' `is_whole_fs` accepts `"**" | "/**" | "/"` and sets `degrade.generous_read`, which
// declines the LowBox token — i.e. it reproduces the exact confound this module removes. The catalog's
// own validator (`catalog_v2::parse_baseline`) refuses the bare `/`, `~` and `$home`, but it does NOT
// refuse `/**`. So the guard has to live here, and it is asserted by this module's own test.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

/** The marker the drivers print, and the only spelling `record.mjs` reads. */
export const CONFINED_WIDE_MARKER = 'CONFINED-WIDE';

/**
 * The probe's read-write path set, per platform. CONCRETE DIRECTORIES, never a glob over the root.
 *
 * The set is what the terminal rung adds over the last confined rung, minus what an unprivileged
 * process cannot be granted anyway:
 *
 *   - THE HOST TEMP, which is the single most likely member. Under Landlock there is no mount
 *     namespace, so `TmpMode::Private` is only a per-run scratch dir with `TMPDIR` repointed
 *     (`linux_landlock.rs`, "There is no mount namespace to rebind here"). The real `/tmp` is simply
 *     ungranted at every confined rung, so a script writing a hardcoded `/tmp/...` path can only ever
 *     work at `write:"disk"` — which is exactly the residual failure `relax_fs_to_full_disk`'s own
 *     doc says the terminal tier exists to have none of.
 *   - THE SYSTEM ROOTS a build script writes to when it installs a toolchain beside itself
 *     (`/usr/local`, `/opt`), plus the state and config trees under them.
 *
 * ⛔ macOS DOES NOT GET `/usr`. It is SIP-protected, so granting it measures nothing and only inflates
 * the ACE/rule count; `/usr/local` is the writable part and is the one named. `/tmp` and `/var` are
 * symlinks into `/private`, so BOTH spellings are listed — a policy matcher that resolves one does not
 * necessarily resolve the other, and naming both costs one rule each.
 *
 * ⛔⛔ WINDOWS IS DELIBERATELY SHORT, AND THE REASON IS A MEASURED CEILING RATHER THAN CAUTION.
 * `.frizz/sandbox-MECHANISM-FACTS.md` §5l (2026-08-01, runs 30688900451 / 30689267117 / 30689583039,
 * both images, FAILURES=0 on every run) measured an AppContainer holding a BROAD filesystem grant: the
 * token SURVIVES a wide grant, so "a wide grant kills the LowBox token" is false. What bounds the grant
 * is OWNERSHIP — an unprivileged caller can only install an ACE on what it owns. Measured there:
 * `C:\`, `C:\ProgramData`, `C:\Users` and `C:\Users\Public` all return ERR 5 on the DACL write, and
 * `C:\Program Files` and `C:\Windows` refuse it EVEN ELEVATED because `TrustedInstaller` owns them.
 * Naming an un-ACE-able path buys no access and costs a failed grant, so the Windows set is the part of
 * the ceiling the last confined rung does not already cover. The consequence for reading a win32
 * result is stated in `interpretation()` and carried in the marker.
 */
export const CONFINED_WIDE_PATHS = {
  linux: ['/tmp', '/var/tmp', '/usr', '/usr/local', '/opt', '/srv', '/var', '/etc', '/run'],
  darwin: [
    '/tmp',
    '/private/tmp',
    '/private/var',
    '/private/var/tmp',
    '/usr/local',
    '/opt',
    '/Library',
    '/Applications',
  ],
  // `C:\Windows\Temp` is the one machine-wide directory §5l measured as DACL-writable de-elevated. It
  // is flagged there as image-specific (both GitHub images share a build pipeline), which is fine for a
  // probe: an uninstallable ACE costs a refused grant, never a wrong answer.
  win32: ['C:/Windows/Temp'],
};

/**
 * The four spellings that mean "the whole filesystem" to one backend or the other. A path set
 * containing any of them stops being a probe and becomes the confound it was written to remove.
 *
 * Union of Linux's `is_whole_root` (`"" | "**" | "/" | "/**"`) and Windows' `is_whole_fs`
 * (`"**" | "/**" | "/"`), plus the two the catalog validator rejects on its own so this module refuses
 * them BEFORE nub does — a rejected catalog leaves the arm VOID, which reads as "no measurement" rather
 * than as "the probe was authored wrong".
 */
const WHOLE_FILESYSTEM_SPELLINGS = new Set(['', '**', '/', '/**', '~', '$home']);

/**
 * The catalog `baseline` array for the probe arm, or `null` when this platform has no probe.
 *
 * Throws rather than returning a degraded set: every caller here builds a MEASUREMENT, and a probe that
 * quietly widened to the whole filesystem would publish "confined and wide" off an unconfined arm —
 * the one wrong answer this module has no defence against downstream.
 */
export function confinedWideBaseline(platform = process.platform) {
  const paths = CONFINED_WIDE_PATHS[platform];
  if (!paths) return null;
  for (const p of paths) {
    if (WHOLE_FILESYSTEM_SPELLINGS.has(p.trim())) {
      throw new Error(
        `confined-wide: \`${p}\` is a whole-filesystem spelling — it would relax the fs axis and the `
          + 'probe would measure the very absence of confinement it exists to rule out',
      );
    }
  }
  return paths.map((path) => ({
    path,
    write: true,
    notes: 'wide-but-confined ladder probe; grants write while default_effect stays Deny',
  }));
}

/**
 * How much a result on this platform is worth, carried in the marker so a reader of `results.json`
 * cannot take the win32 answer for the POSIX one.
 *
 * `full`   — the probe grants materially more than the last confined rung, so a FAIL is real evidence
 *            that no path grant fixes this package.
 * `bounded` — the probe grants barely more than the last confined rung, because the OS refuses to grant
 *            more to an unprivileged confined process at all. A PASS still proves the package is
 *            confinable; a FAIL does NOT separate a token problem from a path problem, because the
 *            paths that would settle it were never grantable.
 */
export function interpretation(platform = process.platform) {
  return platform === 'win32' ? 'bounded' : 'full';
}

/** The three outcomes a probe arm can have. `verify`'s own rc contract: 0 / 1 / 2. */
export const RESULTS = ['pass', 'fail', 'void'];

/** The one line a driver prints. `record.mjs` reads the JSON payload, never the prose. */
export function marker(result, platform = process.platform) {
  if (!RESULTS.includes(result)) throw new Error(`confined-wide: unknown result \`${result}\``);
  return `  ${CONFINED_WIDE_MARKER} ${JSON.stringify({
    result,
    platform,
    interpretation: interpretation(platform),
    paths: CONFINED_WIDE_PATHS[platform] ?? [],
  })}`;
}

// CLI entry for the two shell drivers: `confined-wide.mjs --marker <pass|fail|void>`.
//
// ⛔ THE SPELLING IS NOT DUPLICATED INTO BASH. `measure-windows.mjs` imports `marker()`; the shell
// drivers call this. Three hand-written `printf`s of the same JSON is exactly how the `events LOST`
// note ended up live on one platform of three.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const i = process.argv.indexOf('--marker');
  const result = i === -1 ? null : process.argv[i + 1];
  if (!RESULTS.includes(result)) {
    console.error(`usage: confined-wide.mjs --marker <${RESULTS.join('|')}>`);
    process.exit(2);
  }
  console.log(marker(result));
}
