#!/usr/bin/env bash
# Harness v2 driver, macOS lane: OBSERVE -> SYNTHESIZE -> VERIFY -> NARROW -> DIAGNOSE.
#
# The sibling of measure.sh. Two structural differences, both forced by the platform:
#
#   1. The tracer is dtrace, scoped by PROCESS ANCESTRY (`progenyof($target)`) rather than by
#      strace's `-f`. dtrace needs uid 0, so the traced command is dropped back to the invoking
#      user with `sudo -u` inside the wrapper — otherwise npm would run as root and every
#      `userHome` write would land in /var/root and be misclassified as `outside`.
#
#   2. NARROWING replaces the corpus record as the over-prediction measure. A v1 corpus record is
#      the output of a blind pass/fail ladder: it can say a grant was insufficient, never what was
#      missing, and it carries every harness defect that was live when it was taken. So it is not
#      an oracle and this driver does not consult it. Instead, once a synthesized grant VERIFIES,
#      each capability is dropped in turn and re-verified. A narrower grant that also passes is
#      over-prediction, measured directly rather than inferred from a comparison.
#
#   usage: measure-macos.sh <pkg> <version> [nub-binary]
set -uo pipefail
PKG="${1:?usage: measure-macos.sh <pkg> <version> [nub]}"
VER="${2:?usage: measure-macos.sh <pkg> <version> [nub]}"
NUB="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNUSER="${SUDO_USER:-$(id -un)}"
NPM_BIN="$(command -v npm)"
# nub's global virtual store, resolved the way the ARM will resolve it rather than the way this
# driver would. The driver runs as root (dtrace needs uid 0) while every arm is dropped back with
# `sudo -u -H`, whose env_reset drops XDG_CACHE_HOME — so an arm always lands on the invoking user's
# `~/.cache/nub/pm/{store,tools}`: `aube_store::dirs::cache_dir()` has no macOS `~/Library/Caches`
# branch, and nub's embedder pins `cache_namespace: "nub/pm"` + `virtual_store_subdir: "store"`
# (`identity.rs`). Hence the paths are byte-identical to the Linux driver's; only the ANCHOR differs.
# ⛔ ANCHORING ON THE DRIVER'S OWN `$HOME` WOULD RESOLVE TO /var/root UNDER sudo AND EVICT NOTHING,
# SILENTLY — the same shape as the scoped-slug bug `measure.sh` records, and just as invisible.
USER_HOME="$(dscl . -read "/Users/$RUNUSER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
USER_HOME="${USER_HOME:-/Users/$RUNUSER}"
STORE="$USER_HOME/.cache/nub/pm/store"
TOOLS="$USER_HOME/.cache/nub/pm/tools"

# ⛔ NOT UNDER /tmp — that path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all.
ROOT="$(mktemp -d "$HOME/v2m-XXXXXX")" || exit 1
# The driver runs under sudo (dtrace needs uid 0) but every measured process is dropped back to the
# invoking user — so the tree they write into must be theirs, or npm fails on its own fixture and
# the run reports a package problem that is really a harness problem.
chown -R "$RUNUSER" "$ROOT" 2>/dev/null
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)   nub=${NUB:-<none>}"

# ── 1. OBSERVE ─────────────────────────────────────────────────────────────────────────────────
OBS="$ROOT/observe"; mkdir -p "$OBS"; cd "$OBS" || exit 1
printf '{"name":"o","version":"1.0.0","private":true}\n' > package.json
# ⛔ THE FETCH IS NOT TRACED AND THAT IS THE WHOLE POINT. Tracing `npm install` traces NPM: its
# registry TLS and its `~/.npm/_cacache` writes land in the same event stream as the lifecycle
# script's. MEASURED on Linux: that made EVERY package synthesize `network:true` + `write:userHome`
# regardless of behaviour. Fetch with `--ignore-scripts` outside the trace; trace `npm rebuild`,
# which runs the lifecycle scripts and nothing else.
npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER" > "$OBS/fetch.log" 2>&1
if [ $? -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed; nothing to measure)"; exit 0
fi
# ⛔ CHOWN AFTER THE FETCH, NOT ONLY BEFORE IT. The chown at $ROOT creation predates this fetch, and
# the fetch runs as ROOT (the driver is under sudo for dtrace) — so every file npm just wrote is
# root-owned, and the traced `npm rebuild`, which is dropped back to $RUNUSER, then dies on
# `EACCES: permission denied, mkdir .../node_modules`. MEASURED on run 31086358188: that is what
# @nuxt/components and codeceptjs reported once the dtrace -c defect stopped masking it.
chown -R "$RUNUSER" "$ROOT" 2>/dev/null

# dtrace's `-c` word-splits its argument and execs it directly — there is no shell, so the command
# cannot carry a redirect and cannot report its own exit status. A wrapper file supplies both.
# ⛔ THE WRAPPER MUST NOT BE `sh -c`. The decoder identifies the lifecycle script as the only
# `sh -c` in the subtree (npm execs one per script); a `-c` wrapper here would be indistinguishable
# from it and would attribute the ENTIRE npm subtree to the package.
cat > "$OBS/run.sh" <<WRAP
cd "$OBS"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" "$NPM_BIN" rebuild --no-audit --no-fund "$PKG" > "$OBS/npm.log" 2>&1
echo \$? > "$OBS/rc"
WRAP

PRE=$(find -L "$OBS" -type f ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
# `-x` and an unconditional dump of both the wrapper and dtrace's own stderr: the first run of this
# driver produced a live tracer, a clean dtrace exit, and NO npm.log at all — i.e. the `-c` child
# exited without executing its body, which is invisible unless the wrapper narrates itself.
#
# ⛔ /bin/bash, NEVER /bin/sh. macOS's /bin/sh is a 101 KB STUB that immediately RE-EXECS the real
# 1.29 MB /bin/bash, and `dtrace -c` does not survive its target re-execing: the grip dtrace took on
# the process it spawned is invalidated, dtrace tears down, and the child dies without running its
# body. MEASURED by probes/dtrace-c-matrix.sh — `/bin/sh` 0/8 sentinels, `/bin/bash` 1/1 with the
# full exec tree including the inner `sudo`. The tell in the trace is an `EXEC` record at the
# TARGET's own pid whose execname is `bash`; /bin/bash produces no such record.
#
# Single-variable: an UNSIGNED copy of /bin/sh fails identically, so this is the re-exec and not a
# code-signature or SIP restriction; `-x` and the inner `sudo` were each independently exonerated.
# Not `sh -c`/`bash -c` either — the decoder identifies the lifecycle script as the only `-c` shell
# in the subtree, so the wrapper stays a FILE argument.
dtrace -q -s "$HERE/adapters/macos-observe.d" -o "$OBS/trace.txt" \
       -c "/bin/bash -x $OBS/run.sh" > "$OBS/dtrace.log" 2>&1
DT_RC=$?
echo "  --- wrapper (run.sh) ---"; sed 's/^/     /' "$OBS/run.sh"
echo "  --- dtrace stderr + wrapper trace ---"; sed 's/^/     /' "$OBS/dtrace.log" | head -30
OBS_RC=$(cat "$OBS/rc" 2>/dev/null || echo 99)
OBS_FILES=$(find -L "$OBS" -type f ! -name 'trace.txt' ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
TRACE_LINES=$(wc -l < "$OBS/trace.txt" 2>/dev/null | tr -d ' ')
echo "  OBSERVE   rc=$OBS_RC dtrace_rc=$DT_RC files=$OBS_FILES (pre=$PRE) trace=$TRACE_LINES lines"
# ⛔ A tracer that never attached produces an empty file and a synthesized `{}` that reads as a
# confident "needs nothing". Fail loudly instead.
if ! grep -q 'DTRACE-LIVE' "$OBS/trace.txt" 2>/dev/null; then
  echo "  ⛔ DTRACE NEVER STARTED — see dtrace.log; the run below is NOT a measurement"
  sed 's/^/     /' "$OBS/dtrace.log" | head -20
  exit 1
fi
if [ "$OBS_RC" -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed rc=$OBS_RC; nothing to measure)"
  tail -20 "$OBS/npm.log" | sed 's/^/     /'
  exit 0
fi

# The dependency closure npm actually installed to run this lifecycle script, read off the OBSERVE
# arm's own hoisted `node_modules` — MEASURED rather than guessed. Consumed by the per-arm store
# eviction in `verify()`; see the long note there for why evicting `$PKG` alone leaves a live replay
# path through a transitive dependency's entry.
CLOSURE=$(node -e '
  const fs = require("fs"), path = require("path");
  const nm = process.argv[1], out = [];
  let ents; try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { process.exit(0); }
  for (const e of ents) {
    if (!e.isDirectory() || e.name.startsWith(".")) continue;
    if (e.name.startsWith("@")) {
      for (const s of fs.readdirSync(path.join(nm, e.name))) out.push(e.name + "/" + s);
    } else out.push(e.name);
  }
  console.log(out.join("\n"));
' "$OBS/node_modules" 2>/dev/null)
echo "  CLOSURE   $(printf '%s\n' $CLOSURE | grep -c . ) packages evicted per arm   store=$STORE"

# ── 1b. RETAIN THE EVENT LOG ───────────────────────────────────────────────────────────────────
#
# ⛔ THE TRACE DIES WITH THIS DIRECTORY AND THAT IS THE DEFECT. `$OBS/trace.txt` is the complete
# event stream — thousands of lines — and everything downstream of here reduces it to a one-line
# verdict plus a scope COUNT. `$ROOT` is a `mktemp -d` on an ephemeral runner, so the moment the
# job ends the evidence is gone: a package with 651 script writes publishes about a dozen
# path-looking lines, and a surprising grant can only ever be RE-MEASURED, never RE-READ.
#
# The cost of that is not curiosity, it is the corpus: every harness fix currently invalidates
# every record it touched, because a verdict cannot be re-derived. With the events kept, most
# harness fixes become a RE-PARSE — minutes instead of the runner-hours a re-measure costs.
#
# ⛔ WHAT IS RETAINED IS THE RAW EVENT, NOT ITS CLASSIFICATION. A path tagged with today's scope
# would bake in today's classifier and would need a re-measure the moment the scope set changes —
# which it is changing right now, with `tmp`. So the log carries the syscall, its arguments, its
# errno and the process identity, and no scope at all.
#
# ⛔ TWO PUBLISH PATHS EXIST AND THIS HONOURS BOTH, DELIBERATELY. The Linux lane writes STRAIGHT into
# the record dir from `NUB_V2_EVENTS_OUT`, which `run-batch-v2.mjs` sets (and currently sets only for
# linux); this lane also prints `EVENTLOG-FILE`, which `record.mjs` copies from. The env path is
# cheaper when the batch runner is driving; the stdout path is the only one that works when the
# driver is run STANDALONE, which is how every probe branch and every manual re-measure invokes it.
# Honouring the variable here means the day that gate widens to darwin, nothing has to change.
EVENTS="$OBS/events.ndjson"
node "$HERE/adapters/macos-eventlog.mjs" "$OBS/trace.txt" --out "$EVENTS" \
     --pkg "$PKG" --version "$VER" --project "$OBS" --home "$USER_HOME" \
     > "$OBS/eventlog-stats.json" 2>&1
EV_RC=$?
if [ "$EV_RC" -eq 0 ] && [ -n "${NUB_V2_EVENTS_OUT:-}" ] && [ -s "$EVENTS.gz" ]; then
  cp "$EVENTS.gz" "$NUB_V2_EVENTS_OUT" 2>/dev/null
fi
if [ "$EV_RC" -eq 0 ] && [ -s "$EVENTS.gz" ]; then
  # The record writer copies this file into the record dir. A path on stdout is the contract
  # because the three drivers already communicate with `record.mjs` through their stdout alone.
  echo "  EVENTLOG-FILE $EVENTS.gz"
  echo "  EVENTLOG-STATS $(tr -d '\n ' < "$OBS/eventlog-stats.json")"
else
  # ⛔ NOT FATAL, BUT NEVER SILENT. Retention is additive to the measurement; losing it must not
  # cost a measured package. Saying so is what stops a corpus quietly reverting to verdict-only.
  echo "  ⛔ EVENTLOG NOT WRITTEN (rc=$EV_RC) — this record will carry a verdict and no evidence"
  sed 's/^/     /' "$OBS/eventlog-stats.json" 2>/dev/null | head -5
fi

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe-macos.mjs" "$OBS/trace.txt" "$OBS" "$USER_HOME" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }
# ⛔ AN EMPTY GRANT IS A REAL ANSWER; AN UNATTRIBUTED RUN IS NOT. The decoder emits this token
# instead of `{}` when the subtree filter matched nothing, precisely so the two cannot be confused.
if [ "$GRANT" = "UNKNOWN-ATTRIBUTION-FAILED" ]; then
  echo "  => UNKNOWN (attribution failed — the lifecycle shell was never identified, so there is no"
  echo "     measurement here. This is NOT a package that needs nothing.)"
  exit 0
fi

if [ -z "$NUB" ] || [ ! -x "$NUB" ]; then
  echo "  => OBSERVE-ONLY: $GRANT"
  echo "  ⛔ VERIFY NOT RUN — no feature-enabled nub binary was supplied. This is a HYPOTHESIS,"
  echo "     not a measurement: NUB_BUILD_JAIL_CATALOG is inert without"
  echo "     --features nub-cli/build-jail-catalog-override, so a run without it would have"
  echo "     silently measured the compiled-in catalog instead of this grant."
  exit 0
fi

# ── 3. VERIFY — the real, UNPRIVILEGED jail. Runs as the invoking user, never root. ────────────
verify () {
  local grant="$1" label="$2" tracer="${3:-}"
  local v="$ROOT/verify-$label"; mkdir -p "$v"; chown -R "$RUNUSER" "$v" 2>/dev/null
  # A unique root package name per arm: nub's side-effects memo replays a lifecycle outcome keyed
  # on package identity, and a replayed arm is indistinguishable from a real one by exit code.
  local name="v$(echo "$label" | tr -dc 'a-z0-9')$RANDOM"
  printf '{"name":"%s","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$name" "$PKG" "$VER" > "$v/package.json"
  # ⛔ STATE THE JAIL EXPLICITLY RATHER THAN INHERITING IT. An arm that silently ran UNCONFINED
  # passes every time and reports the synthesized grant as sufficient — it inflates the agreement
  # rate rather than breaking anything, which is what makes it the most dangerous false green here.
  printf '{"install":{"buildJail":true}}\n' > "$v/nub.jsonc"
  # THREE REPLAY PATHS, THREE GUARDS, AND NO ONE OF THEM SUBSUMES ANOTHER (`measure.sh` proved the
  # last point directly: with the memo dropped in every arm, the only variable being whether a
  # transitive store entry was evicted, `@apollo/rover@0.2.1` went rc=0 with an EMPTY `bin/` to rc=1
  # with `bin/` absent):
  #
  #   unique root name      — nub memoises a lifecycle outcome keyed on package identity
  #   side-effects-cache=no — the memo says "this script already ran, skip it"
  #   store eviction        — the store says "this package is already materialised, relink it"
  local cache="$v/nubcache"; rm -rf "$cache"
  # ⛔ A PER-ARM `NUB_CACHE_DIR` DROPS NEITHER THE MEMO NOR THE STORE, AND AN EARLIER REVISION OF
  # THIS FILE SAID IT DROPPED BOTH. `NUB_CACHE_DIR` governs the resolver PRIMER cache
  # (`pm_engine/mod.rs`, `config_env("CACHE_DIR")`); the store comes from `aube_store::dirs::
  # cache_dir()`, and the memo from `side_effects_cache_root()` = `virtual_store_dir()/../
  # side-effects-v1`, i.e. BOTH live beside the store under the XDG cache and neither moves with it.
  # So the memo needs its own opt-out, read by `aube_settings::resolved::side_effects_cache`.
  printf 'side-effects-cache=false\n' > "$v/.npmrc"
  # ⛔ AN EMPTY GRANT CANNOT BE EXPRESSED AS `{"<pkg>":{"default":{}}}` — the parser REJECTS an empty
  # default block, which would make the arm VOID and read as "the grant did not work" rather than
  # "the package needs nothing". The override REPLACES the compiled-in table rather than merging
  # into it, so OMITTING the package makes it run at the base profile, which IS the empty grant. A
  # throwaway sentinel entry keeps the file non-empty so the override still engages and the
  # OVERRIDDEN>=1 / REJECTED==0 assertion below stays meaningful. Ported from measure.sh; the
  # Windows lane took husky@4.3.8 from write:"disk" to a verified {} on exactly this construction.
  node -e '
    const fs=require("fs");const [r,p,g]=process.argv.slice(1);
    const grant=JSON.parse(g);
    const cat = Object.keys(grant).length
      ? {packages:{[p]:{default:grant}}}
      : {packages:{"__v2_empty_grant_sentinel__":{default:{network:true}}}};
    fs.writeFileSync(r+"/cat.json",JSON.stringify(cat));
  ' "$v" "$PKG" "$grant" || return 1
  # ⛔⛔ EVICT THIS PACKAGE **AND ITS CLOSURE** FROM THE MACHINE-GLOBAL STORE. Ported from
  # `measure.sh`, whose comments carry the measurements; the load-bearing ones, restated because
  # this lane was hard-disabled for lacking exactly this:
  #
  #   * A relinked package runs NO lifecycle script, so the arm PASSES at whatever grant is under
  #     test — including one NARROWER than the package needs. That is an under-grant, the one
  #     unacceptable direction, and it presents with every precondition green.
  #   * `$PKG` ALONE IS NOT ENOUGH. `@apollo/rover@0.2.1`'s postinstall writes into a SIBLING
  #     package's directory (`binary-install/bin/`), which the jail refuses because
  #     `store_entry_write_root` grants the package's OWN entry only. Leaving `binary-install`
  #     populated by a prior arm let a `{"network":true}` arm relink it and pass.
  #   * TARGETED, NOT `rm -rf` ON THE STORE. It is machine-global and a sibling agent may be
  #     measuring on the same box. Anchor `<slug>@` with `/`→`+` — the store's own naming
  #     (`@babel+core@7.29.7-<hash>`); a `tr '/@' '--'` slug matched zero scoped packages, silently.
  #   * SPARE THE ENTRIES nub'S OWN TOOLING LINKS THROUGH (67c01911). nub bootstraps node-gyp into
  #     `<cache>/nub/pm/tools/` against this same store, and `semver`/`tar`/`which`/`graceful-fs`
  #     are ordinary members of a native package's closure — evicting by name leaves a dangling
  #     symlink and `gyp ERR! Cannot find module 'semver'`, which reads as INSUFFICIENT and inflates
  #     the grant. Resolve the sparing set by FOLLOWING SYMLINKS, never by matching the link dir's
  #     name: it is `.store` on one binary and `.nub` on another, so a name match stops matching
  #     silently. Sparing cannot manufacture a false pass — nub's tool closure is pure-JS library
  #     code that declares no lifecycle script, so no arm can leave build output in a spared entry.
  #
  # Cost: each arm re-materializes the closure. That is the price of independent arms.
  if [ -d "$STORE" ]; then
    printf '%s\n' "$PKG" $CLOSURE | sort -u | node -e '
      const fs=require("fs"), path=require("path");
      const [store, tools] = process.argv.slice(1);
      // Every store entry any nub tool project links through, at whatever depth and under whatever
      // name that project gives its virtual-store dir.
      const keep = new Set();
      const walk = (dir, depth) => {
        if (depth > 6) return;
        let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
        for (const e of ents) {
          const p = path.join(dir, e.name);
          if (e.isSymbolicLink()) {
            let t; try { t = path.resolve(dir, fs.readlinkSync(p)); } catch { continue; }
            const rel = path.relative(store, t);
            if (rel && !rel.startsWith("..") && !path.isAbsolute(rel)) keep.add(rel.split(path.sep)[0]);
          } else if (e.isDirectory()) walk(p, depth + 1);
        }
      };
      walk(tools, 0);
      const prefixes = [...new Set(fs.readFileSync(0, "utf8").split("\n").filter(Boolean)
        .map(n => n.replace(/\//g, "+") + "@"))];
      let removed = 0, spared = 0;
      let entries; try { entries = fs.readdirSync(store); } catch { entries = []; }
      for (const e of entries) {
        if (!prefixes.some(n => e.startsWith(n))) continue;
        if (keep.has(e)) { spared++; continue; }
        fs.rmSync(path.join(store, e), { recursive: true, force: true });
        removed++;
      }
      console.log(`  EVICT[${process.argv[3]}] ${removed} store entries removed, ${spared} spared as nub tooling, ${entries.length} in store`);
    ' "$STORE" "$TOOLS" "$label" ||
      echo "  ⛔ EVICTION FAILED — this arm may REPLAY a prior arm's build and UNDER-report"
  else
    echo "  EVICT[$label] no store at $STORE yet (first arm on this box)"
  fi
  if [ -n "$tracer" ]; then
    ( cd "$v" && export NUB_CACHE_DIR="$cache" NUB_BUILD_JAIL_CATALOG="$v/cat.json"
      cat > "$v/jail.sh" <<JW
cd "$v"
sudo -u "$RUNUSER" -H env "PATH=\$PATH" NUB_CACHE_DIR="$cache" NUB_BUILD_JAIL_CATALOG="$v/cat.json" \
  "$NUB" install > "$v/i.log" 2>&1
echo \$? > "$v/rc"
JW
      dtrace -q -s "$HERE/adapters/macos-observe.d" -o "$v/trace.txt" \
             -c "/bin/bash -x $v/jail.sh" > "$v/dtrace.log" 2>&1 )   # /bin/sh re-execs; see OBSERVE
    local rc; rc=$(cat "$v/rc" 2>/dev/null || echo 99)
  else
    # ⛔ THE JAILED RUN MUST NOT BE ROOT. This driver is invoked under sudo because dtrace needs
    # uid 0, and a build jail evaluated as root is not the jail that ships — root defeats several
    # of its own confinement primitives, so an arm left at uid 0 would pass for a reason that has
    # nothing to do with the grant.
    chown -R "$RUNUSER" "$v" 2>/dev/null
    sudo -u "$RUNUSER" -H env "PATH=$PATH" NUB_CACHE_DIR="$cache" \
      NUB_BUILD_JAIL_CATALOG="$v/cat.json" sh -c "cd '$v' && '$NUB' install > '$v/i.log' 2>&1; \
      '$NUB' approve-builds --all > '$v/a.log' 2>&1"
    local rc=$?
  fi
  # The replay signature: `materialized` with no install line. Reported, not fatal — a package with
  # no lifecycle script legitimately shows neither.
  if grep -qE '^\s*materialized ' "$v/i.log" 2>/dev/null && ! grep -qE 'installed [0-9]+ package' "$v/i.log" 2>/dev/null; then
    echo "     ⛔ REPLAY SUSPECTED — 'materialized' with no install line; the script may not have run"
  fi
  # ⛔ A malformed override WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  # assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  local ovr rej files
  ovr=$(cat "$v"/*.log 2>/dev/null | grep -c 'catalog OVERRIDDEN')
  rej=$(cat "$v"/*.log 2>/dev/null | grep -c 'REJECTED')
  # ⛔ `-L` IS LOAD-BEARING. nub's global virtual store makes every node_modules entry a SYMLINK,
  # so a bare `find -type f` counts ~30 files where the npm control counted 456, and the artifact
  # gate below then fails an arm that installed perfectly.
  files=$(find -L "$v" -type f ! -name '*.log' ! -name 'cat.json' ! -name 'trace.txt' ! -path '*/nubcache/*' 2>/dev/null | wc -l | tr -d ' ')
  # ⛔⛔ `files >= OBS_FILES` WAS THE GATE HERE AND IT IS NOT A SUCCESS GATE. `find -L` follows the
  # isolated layout's symlinks into the machine-global store, so the number is dominated by the
  # dependency closure and is nearly insensitive to whether THIS package's script produced anything
  # — and the eviction above only makes an arm ATTEMPT the work, so it needs a gate that can see
  # whether the work landed. MEASURED on `@apollo/rover@0.2.1` (Linux): an arm that produced NONE of
  # the package's three artifacts counted 704 files against a 718-file reference. The per-file
  # ARTIFACT MANIFEST is the gate in `measure.sh` and on Windows; the three drivers now agree on what
  # "the arm succeeded" means. `files/OBS_FILES` stays PRINTED for continuity with existing logs.
  local gate grc
  gate=$(node "$HERE/artifact-gate.mjs" --obs "$OBS" --arm "$v" --pkg "$PKG" --ver "$VER" 2>&1); grc=$?
  echo "  VERIFY[$label] rc=$rc $(printf '%s' "$gate" | head -1) (tree $files/$OBS_FILES) OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  printf '%s\n' "$gate" | tail -n +2 | sed 's/^/     /'
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "     ⛔ override did not engage — arm is VOID"; return 2; }
  # rc 3 = OBSERVE produced no files for this package at all, so the manifest can gate on nothing.
  # Fall back to the exit code rather than passing an ungated arm off as measured.
  if [ "$grc" -eq 3 ]; then
    echo "     NOTE no artifact reference for $PKG — gating on rc alone"
    [ "$rc" -eq 0 ]; return $?
  fi
  # Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  # failure mode. Both must hold.
  [ "$rc" -eq 0 ] && [ "$grc" -eq 0 ]
}

VERIFIED=0
if verify "$GRANT" "synth"; then
  VERIFIED=1
  echo "  => VERIFIED $GRANT"
else
  echo "  => UNDER-PREDICTED — the synthesized grant did NOT verify. This is the correctness"
  echo "     finding: OBSERVE saw a run that the jail then refused on some axis it did not cover."
fi

# ── 3b. NARROW — the direct over-prediction measure. ───────────────────────────────────────────
#
# Only meaningful once a grant has verified: dropping a capability from a grant that already fails
# tells you nothing. Each variant removes exactly ONE capability, so a passing variant names the
# capability the synthesis did not need. Single-variable by construction.
if [ "$VERIFIED" -eq 1 ]; then
  # ⛔ NO `mapfile` AND NO ARRAYS HERE. macOS ships bash 3.2 at /bin/bash, where `mapfile` does not
  # exist and `${arr[@]}` on an empty array is an unbound-variable error under `set -u`. A plain
  # file plus a read loop works on both.
  node -e '
    const g = JSON.parse(process.argv[1]); const out = [];
    if (g.network) { const c = JSON.parse(JSON.stringify(g)); delete c.network; out.push(["no-network", c]); }
    for (const k of Object.keys(g.write ?? {})) {
      const c = JSON.parse(JSON.stringify(g)); delete c.write[k];
      if (!Object.keys(c.write).length) delete c.write;
      out.push(["no-write-" + k, c]);
    }
    for (const [n, c] of out) console.log(n + "\t" + JSON.stringify(c));
  ' "$GRANT" > "$ROOT/variants.tsv" 2>/dev/null
  if [ ! -s "$ROOT/variants.tsv" ]; then
    echo "  NARROW    no capability to drop — the grant is already empty; over-prediction is 0 by construction"
  fi
  while IFS=$'\t' read -r nm gg; do
    [ -n "${nm:-}" ] || continue
    # An empty variant used to be UNTESTABLE here, because the parser rejects an empty `default`
    # block and the arm came back VOID. `verify` now expresses it the way measure.sh does — omit the
    # package so it runs at the base profile — so the fully-narrowed variant is a real arm, and a
    # package that needs nothing is measurable rather than skipped.
    if verify "$gg" "nar-$nm"; then
      echo "     ⛔ OVER-PREDICTED — the strictly narrower $gg also verifies; '$nm' was not needed"
    else
      echo "     narrowing '$nm' fails ⇒ that capability IS necessary"
    fi
  done < "$ROOT/variants.tsv"
fi

# ── 3c. DIAGNOSE — run the FAILING grant JAILED, under dtrace, and name the refusal. ───────────
#
# The open question this answers for macOS: Seatbelt denies at the MAC layer, so the syscall still
# returns to userspace with an errno — which is where dtrace reads it. If that holds, the macOS
# lane gets the same closing tool the Linux lane has. If Seatbelt kills the process before the
# return probe fires, it does not, and that is worth knowing precisely.
if [ "$VERIFIED" -eq 0 ]; then
  echo "  DIAGNOSE  re-running the failing grant JAILED, under dtrace"
  verify "$GRANT" "diag" "dtrace" > /dev/null 2>&1
  D="$ROOT/verify-diag/trace.txt"
  if [ ! -s "$D" ]; then
    echo "     ⛔ no diagnose trace produced — dtrace could not observe the jailed run"
  else
    echo "     trace lines: $(wc -l < "$D" | tr -d ' ')"
    # errno 1 EPERM / 13 EACCES / 30 EROFS. ⛔ NOT errno 2 (ENOENT): a jail that hides a path
    # reports it missing, and so does an ordinary probe for a file that was never there — counting
    # ENOENT would bury the real refusals under thousands of module-resolution misses.
    echo "     refused paths under the failing grant (count, path):"
    grep -E '^(OPEN|PATHOP)\|' "$D" | awk -F'|' '$0 ~ /errno=(1|13|30)\|/ {print $NF}' \
      | sort | uniq -c | sort -rn | head -15 | sed 's/^/       /'
    echo "     ⇒ TREAT THIS AS A CANDIDATE SET, NOT AN ANSWER. On Linux the last refusal before a"
    echo "       fatal exit was a trailing red herring once already; settle it with a"
    echo "       single-variable arm per path plus a negative control granting all the others."
  fi
fi

echo "### DONE $PKG@$VER  synthesized=$GRANT verified=$VERIFIED"
