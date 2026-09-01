# shellcheck shell=bash
# THE XDG BASE-DIRECTORY SCRUB, shared by the two POSIX drivers. It removes the four per-user
# `XDG_*_HOME` variables from the TRACED CHILD ONLY, because the real jail removes them from the
# confined child and OBSERVE must reproduce that.
#
# ⛔ THE DEFECT, AND IT MANUFACTURES OVER-GRANTS RATHER THAN UNDER-GRANTS. GitHub's ubuntu runner
# image exports `XDG_CONFIG_HOME=/home/runner/.config` — an ABSOLUTE path into the REAL home
# (actions/runner-images#2954; the arm64 images use `/home/runneradmin/.config`, #11409). macOS
# images set nothing, which is why this only ever bit linux. The observe arm inherited it and
# redirected only `HOME`, so `configstore`/`xdg-basedir`, `env-paths`, Go's `os.UserConfigDir()` and
# cabal — every one of which PREFERS `XDG_CONFIG_HOME` over `$HOME` — wrote their config into the
# real home. The classifier saw a write that did NOT follow `$HOME`, which is exactly its definition
# of `userHome`, and synthesis billed the package `write:{userHome}`: THE WHOLE HOME DIRECTORY, the
# persistence capability, for a variable the runner set and the jail does not pass on.
#
# MEASURED on the committed corpus, from the retained event logs rather than argued: `bootstrap-
# slider@4.2.0`, linux, pid 52342 writes `/home/runner/.config/configstore/bower-github.json` (REAL
# home) and `$JAIL_HOME/.cache/bower/...` (JAIL home) from ONE process. `.cache` followed `$HOME` and
# `.config` did not, so the split can only be the environment variable. That same pid pair is the
# proof `XDG_CACHE_HOME` is NOT set on this venue: had it been, `.cache` would have gone to the real
# home too. Across all 241 linux records carrying `write:{userHome}`, 45 have their ENTIRE real-home
# write set under `.config/` — 15 distinct packages — and 38 of those 45 already carry
# `OVER-PREDICTED by no-write-userHome`, i.e. the jailed install exits 0 with the grant dropped.
#
# ⛔ SCRUB, NOT REDIRECT, AND THE JAIL IS WHAT DECIDES THAT. `compiler/preset.rs` sets
# `policy.env = defaults::lifecycle_scrubbed_env(&ambient_env)`, a DEFAULT-DENY allowlist over
# `build_jail_env_allowed`; `grep -c XDG` on `compiler/defaults.rs` is 0, so no `XDG_*` name is
# admitted on any platform. The confined child therefore sees the variable ABSENT and falls back to
# `$HOME/.config` — which is the private jail home, already read-write in the base profile. Pointing
# the observe child at `$JAIL_HOME/.config` instead would land the same bytes in the same place, but
# it would observe a run that never happens: a package that BRANCHES on the variable being set takes
# the wrong branch, and the arms would again differ in two variables rather than one. Absence is what
# the jail produces, so absence is what is reproduced. (Same reasoning as `ci-env-scrub.sh`'s
# "SCRUBBED, NEVER FORCED TO A VALUE", reached from the other direction.)
#
# ⛔⛔ THE CHILD, NEVER THIS SHELL — AND `XDG_CACHE_HOME` IS WHY THAT DISTINCTION IS LOAD-BEARING.
# `ci-env-scrub.sh` `unset`s in the driver's own environment. Doing that here would BREAK the driver:
# `measure.sh` derives `JAIL_CACHE`, `GLOBAL_STORE`, `JAIL_TOOLS`, the per-arm store eviction root and
# the jail-home purge root from `${XDG_CACHE_HOME:-$HOME/.cache}` — seven expansions, all in the
# driver's shell, all pointing at nub's own cache — and a driver that lost the variable would evict
# the wrong store and hand the arms a `toolsDir` the jail does not use. `env -u` is scoped to the one
# exec, so the child loses the name and every one of those expansions is untouched. That is the whole
# reason this is an `env` argument list and not an `unset` loop, and it must not be "simplified" into
# one.
#
# ⛔ THE LIST IS THE FOUR PER-USER BASE DIRS AND STOPS THERE. `XDG_DATA_DIRS`/`XDG_CONFIG_DIRS` are
# colon-lists of SYSTEM search paths (`/usr/share`, `/etc/xdg`) that no library uses as a write
# target, and `XDG_RUNTIME_DIR` points at `/run/user/<uid>`, which classifies `outside` and earns no
# scope at all. None of the three can manufacture the `userHome` grant this file exists to remove, so
# none is scrubbed — leaving them alone keeps the change to the demonstrated defect.
#
# ⛔ ALL FOUR ARE PASSED UNCONDITIONALLY, INCLUDING THE ONES THE VENUE DID NOT SET. `env -u <name>` on
# an absent name is a no-op on GNU coreutils and on BSD `env` alike (verified on both), so an
# unconditional list makes the child's environment INDEPENDENT of the venue rather than a function of
# it — which is the property the whole parity contract rests on. `XDG_SCRUBBED` reports what was
# actually there, for the record; it does not decide what is removed.
#
# ⛔ NO `inherit` ESCAPE HATCH, DELIBERATELY, AND THE ASYMMETRY WITH `ci-env-scrub.sh` IS THE POINT.
# `NUB_CORPUS_CI_ENV=inherit` exists because CI-vs-not is a REAL axis a package's behaviour splits on
# and both states are worth measuring. There is no such axis here: the jail strips these names
# unconditionally, so an "inherit" mode would measure an environment no jailed script can ever be in.
# The knob would only ever re-open the defect. The scrub's falsifiability is covered instead by
# `xdg-scrub.test.mjs`, which runs the driver's own extracted arm with and without the list.
#
# ⛔ NOT MIRRORED IN `measure-windows.mjs`. The decision stands, but TWO OF THE THREE REASONS THIS
# BLOCK ONCE GAVE FOR IT WERE WRONG, and they are recorded rather than deleted because both read as
# measurements and would have been re-derived the same way by the next reader.
#
# ⛔ THE OLD EVIDENCE WAS CIRCULAR. It said "across the 1,688 committed win32 captures, ZERO carry an
# `XDG` name in `observeEnv`". `measure-windows.mjs:1375` emits `observeEnv: {set: OBS_ENV, unset: []}`
# — the variables the driver SETS. An INHERITED name can never appear there, on any platform, under
# any venue, so the zero was a tautology about the emitter and not a fact about the runner.
#
# ⛔ AND "WINDOWS APPLICATIONS USE `%APPDATA%`" IS FALSE FOR THE LIBRARY THAT MATTERS. `xdg-basedir`
# 2/3/4 carry no platform branch at all — `exports.config = env.XDG_CONFIG_HOME || join(home,
# '.config')` runs identically on win32 — and `configstore` 3.1.2/5.0.1 depend on it. (`env-paths`
# does branch on `process.platform`, so it alone is immune.) A Windows leak would therefore
# manufacture the same over-grant this file exists to remove on linux.
#
# THE NON-CIRCULAR EVIDENCE, AND IT SETTLES `XDG_CACHE_HOME` ONLY. `measure-windows.mjs:1244` resolves
# `CACHE = XDG_CACHE_HOME || LOCALAPPDATA` from the DRIVER'S OWN inherited environment, before any
# per-arm value exists, and `roots.globalStore` is `CACHE/store` (`:1320`). All 1,688 of 1,688
# committed win32 captures resolve `globalStore` under `%LOCALAPPDATA%` — the branch taken ONLY when
# the venue left `XDG_CACHE_HOME` unset. That is a property of the runner rather than of the emitter,
# which is exactly what the old evidence was not.
#
# ⛔ `XDG_CONFIG_HOME` ON WIN32 REMAINS UNVERIFIED, and the honest reason is that nothing committed can
# answer it: the config-home split is visible only through the home redirect, and only 15 win32
# records carry one. The decision is very likely still right — both runner-image issues cited above
# are Linux-only — but it rests on that, not on a measurement. What would settle it is emitting the
# INHERITED `XDG_*` names into win32 `capture.json`, the way `XDG_INHERITED` does here.
#
# The one original reason that DOES hold: the Windows driver SETS `XDG_CACHE_HOME` itself, per arm
# (`:1967`), to relocate nub's store, so a blanket scrub of that name there would be actively wrong.
# `xdg-scrub.test.mjs` pins the asymmetry so it is not "harmonised" away by someone reading only this
# file.

# The per-user base dirs, in the order the spec lists them. A name added here is removed from the
# traced child on BOTH POSIX drivers, because both source this file.
XDG_KEYS="XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME"

# Captured for the record, BEFORE anything is reported as removed — same reason `CI_INHERITED` is.
# `VENUE-OVERRIDES.passedThrough` carries these, so a record can prove the venue set
# `XDG_CONFIG_HOME=/home/runner/.config` rather than leaving a future reader to take it on trust.
XDG_INHERITED="$(for k in $XDG_KEYS; do
  eval "v=\${$k:-}"; [ -n "${v:-}" ] && printf '%s=%s\n' "$k" "$v"
done)"

# The `env` argument list, and the names that were actually present. The two are deliberately
# different things: the first is unconditional, the second is provenance.
XDG_UNSET=""
XDG_SCRUBBED=""
for k in $XDG_KEYS; do
  XDG_UNSET="$XDG_UNSET -u $k"
  eval "v=\${$k:-}"
  if [ -n "${v:-}" ]; then XDG_SCRUBBED="$XDG_SCRUBBED $k"; fi
done
# An `if` rather than `[ … ] && echo`, so sourcing this file cannot hand its caller a non-zero status
# on the (normal, developer-machine) path where nothing was set.
if [ -n "$XDG_SCRUBBED" ]; then
  echo "  XDG-ENV scrubbed from the traced child:$XDG_SCRUBBED"
fi
