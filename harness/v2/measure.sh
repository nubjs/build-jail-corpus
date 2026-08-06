#!/usr/bin/env bash
# Harness v2 driver: OBSERVE -> SYNTHESIZE -> VERIFY -> (fall back to the ladder).
#
# See README.md for why. The short version: v1's only signal was pass/fail of a jailed run, so it
# had to SEARCH 55 states to find the minimum, and could never say WHAT a package touched. The
# generation harness may run as root, so it does not have to guess — it watches, then checks.
#
#   usage: measure.sh <pkg> <version> [nub-binary]
set -uo pipefail
PKG="${1:?usage: measure.sh <pkg> <version> [nub]}"
VER="${2:?usage: measure.sh <pkg> <version> [nub]}"
NUB="${3:-$HOME/nub/target/fast/nub}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# ⛔ NOT UNDER /tmp. That path is inside the jail's own private-temp redirect, so a fixture placed
# there cannot test a filesystem-denial claim at all — it already produced one wrong all-clear.
ROOT="$(mktemp -d "$HOME/v2-XXXXXX")" || exit 1
# ⛔ THIS DOES NOT ISOLATE THE STORE, AND AN EARLIER COMMENT HERE CLAIMED IT DID. `NUB_CACHE_DIR`
# governs the RESOLVER PRIMER CACHE only; the global virtual store comes from a different function
# (see the long note in `verify()`). It is kept because a per-run primer cache is still worth
# having, but the thing that makes two arms independent is the per-arm STORE EVICTION below.
export NUB_CACHE_DIR="$ROOT/nubcache"
echo "### $PKG@$VER   ($ROOT)"

# ── 1. OBSERVE — unjailed, traced. This is the DISCOVERY step and it needs no jail at all. ─────
OBS="$ROOT/observe"; mkdir -p "$OBS"; cd "$OBS" || exit 1
printf '{"name":"o","version":"1.0.0"}\n' > package.json
# ⛔ THE FETCH IS NOT TRACED, AND THAT IS THE WHOLE POINT. Tracing `npm install` traces NPM —
# its registry TLS connections and its `~/.npm/_cacache` writes land in the same event stream as
# the lifecycle script's, so EVERY package synthesizes `network:true` + `write:userHome` no matter
# what its script does. MEASURED: that is over-prediction on 100% of packages and it makes the
# per-path question (can `writePaths` replace `write:"disk"`?) unanswerable. So: fetch and unpack
# with `--ignore-scripts` OUTSIDE the trace, then trace `npm rebuild`, which runs the lifecycle
# scripts and nothing else.
npm install --no-audit --no-fund --ignore-scripts "$PKG@$VER" > "$OBS/fetch.log" 2>&1
FETCH_RC=$?
if [ "$FETCH_RC" -ne 0 ]; then
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed fetch failed; nothing to measure)"; exit 0
fi
PRE_FILES=$(find "$OBS" -type f ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
# ⛔ OBSERVE WITH THE SAME `HOME` THE JAIL WILL GIVE THE SCRIPT, OR EVERY npm-CACHE WRITE IS BILLED
# AS A CAPABILITY THE PACKAGE DOES NOT NEED. The jail redirects `HOME`/`USERPROFILE` to a per-package
# private home (`preset.rs` `private_home_dir`, RW-granted by the base profile), so inside the jail
# `$HOME/.npm/_cacache/...` lands in already-granted space. Observing under the AMBIENT `$HOME` put
# those same writes under the real home and synthesized `write:{userHome}` — measured on
# `vanilla-cookieconsent@3.0.0-rc.9`, 51 of its 52 writes were npm's own cache.
#
# ⛔ THE REDIRECT IS THE POINT, AND A `$HOME`-PREFIX EXCLUSION WOULD NOT DO. Filtering the paths
# afterwards would silently swallow a script that hardcodes a real-home path — an UNDER-prediction,
# the one direction that breaks installs. Redirecting instead makes `jailHome` a MEASUREMENT of
# which writes actually follow `$HOME`: a hardcoded path still lands in `userHome` and still earns
# the grant.
JAIL_HOME="$ROOT/jailhome"; mkdir -p "$JAIL_HOME"
# `-f` is mandatory: the interesting syscall is routinely a grandchild of the postinstall.
HOME="$JAIL_HOME" strace -f -e trace=file,network,process -o "$OBS/trace.txt" \
  npm rebuild --no-audit --no-fund "$PKG" > "$OBS/npm.log" 2>&1
OBS_RC=$?
OBS_FILES=$(find "$OBS" -type f ! -name 'trace.txt' ! -name '*.log' 2>/dev/null | wc -l | tr -d ' ')
echo "  OBSERVE   rc=$OBS_RC files=$OBS_FILES trace=$(wc -l < "$OBS/trace.txt" | tr -d ' ') lines"
if [ "$OBS_RC" -ne 0 ]; then
  # An unjailed failure means the package is broken HERE — a jailed result would be meaningless.
  # v1 calls this BROKEN-WITHOUT-JAIL-TOO and it is a real verdict, not an error.
  echo "  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed; nothing to measure)"
  exit 0
fi

# The dependency closure npm actually installed to run this lifecycle script, read off the OBSERVE
# arm's own hoisted `node_modules`. Consumed by the per-arm store eviction in `verify()` — see the
# long note there for why evicting `$PKG` alone leaves a live replay path.
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
echo "  CLOSURE   $(printf '%s\n' $CLOSURE | grep -c . ) packages evicted per arm"

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe.mjs" "$OBS/trace.txt" "$OBS" "$HOME" "$JAIL_HOME" "$PKG" > "$ROOT/observed.txt" 2>&1
sed 's/^/  /' "$ROOT/observed.txt"
GRANT=$(grep -A1 'SYNTHESIZED GRANT' "$ROOT/observed.txt" | tail -1 | sed 's/^ *//')
[ -n "$GRANT" ] || { echo "  SYNTHESIZE FAILED"; exit 1; }

# ── 3. VERIFY — the real, UNPRIVILEGED jail. The only arm whose result may enter the catalog. ──
verify () {
  local grant="$1" label="$2" tracer="${3:-}"
  local v="$ROOT/verify-$label"; mkdir -p "$v/pkg"
  # A unique package name per arm: nub's side-effects cache memoises a lifecycle outcome keyed on
  # package identity, so a reused name REPLAYS the previous arm's result with every precondition
  # still green. Measured — the most dangerous failure shape here, because nothing looks wrong.
  local name="v$(basename "$v" | tr -dc 'a-z0-9')"
  printf '{"name":"%s","version":"1.0.0","dependencies":{"%s":"%s"}}\n' "$name" "$PKG" "$VER" > "$v/package.json"
  # ⛔ STATE THE JAIL EXPLICITLY RATHER THAN INHERITING A DEFAULT. A VERIFY arm that silently ran
  # UNCONFINED passes every time and reports the synthesized grant as sufficient — the single most
  # dangerous false green available here, because it inflates the agreement rate rather than
  # breaking anything. The catalog override engaging is NOT evidence the jail engaged.
  printf '{"install":{"buildJail":true}}\n' > "$v/nub.jsonc"
  # ⛔ THE THIRD REPLAY GUARD, AND IT IS NOT REDUNDANT WITH THE OTHER TWO — MEASURED, NOT ASSUMED.
  # v1 used this and the v2 drivers never inherited it (`harness/search.mjs`: "a warm cache replays a
  # prior build and the lifecycle script NEVER SPAWNS, which reads exactly like a jail denial").
  # The engine really reads it: `aube_settings::resolved::side_effects_cache`, consulted in
  # `vendor/aube/crates/aube/src/commands/rebuild.rs` and the `install/finalize.rs` path.
  #
  # THE THREE GUARDS CLOSE THREE DIFFERENT REPLAY PATHS, and dropping any one reopens its own:
  #   unique root name      — nub memoises a lifecycle outcome keyed on package identity
  #   side-effects-cache=no — the memo says "this script already ran, skip it"
  #   store eviction        — the store says "this package is already materialised, relink it"
  #
  # Tested directly on `@apollo/rover@0.2.1` with this line PRESENT in every arm and the only
  # variable being whether the transitive dependency's store entry was evicted:
  #
  #   evict binary-install=no    {"network":true}   rc=0   bin/ POPULATED  -> false PASS survives
  #   evict binary-install=yes   {"network":true}   rc=1   bin/ empty      -> correct FAIL
  #
  # So the config line does NOT subsume the eviction. Keep both.
  printf 'side-effects-cache=false\n' > "$v/.npmrc"
  # ⛔⛔ A UNIQUE NAME IS NOT ENOUGH, AND NEITHER IS DROPPING THE MEMO. THIS ARM EVICTS THE STORE.
  #
  # The memo keys on the DEPENDENCY's identity, which is identical across arms by construction, so
  # the unique ROOT name above does not separate them. Dropping `pm/side-effects-v1` was the fix for
  # that — and it is INSUFFICIENT, proven on the Windows driver, which carries both mitigations and
  # replayed anyway: three runs of the same binary and package gave rc=1 with a real refusal once,
  # then rc=0 twice, and diffing the install logs showed the later runs printed only
  # `materialized …` / `installed 1 package in 2.4s` where the first had downloaded 84 packages and
  # run the script. **The lifecycle script never executed.** The surviving replay source is the
  # GLOBAL VIRTUAL STORE — a package already materialized there is relinked, not reinstalled, so its
  # scripts do not run again.
  #
  # ⛔ AND EVERY PRECONDITION STAYED GREEN THROUGHOUT — override engaged, jail stated, unique name,
  # fixture outside temp. That is what makes this the most dangerous failure shape in the harness:
  # it does not break, it silently measures nothing.
  #
  # ⛔⛔ A PER-ARM `NUB_CACHE_DIR` DOES **NOT** CLOSE THIS, AND AN EARLIER REVISION OF THIS FILE
  # CLAIMED IT DID. That is worse than no fix, because it looks like protection. `NUB_CACHE_DIR`
  # governs the RESOLVER PRIMER CACHE only — `pm_engine/mod.rs` says so where it maps
  # `config_env("CACHE_DIR")`, and the store comes from a DIFFERENT function,
  # `aube_store::dirs::cache_dir()` joined with the embedder's `virtual_store_subdir`
  # (`vite_compat.rs:248`). MEASURED on Windows: with a fresh cache dir per arm, the arm's cache
  # ended the run with ZERO files while the old store still served the package.
  #
  # So evict the package from the STORE instead. The positive control that settles it: before
  # eviction the install log holds only `materialized …` (1.2s); after eviction it holds the
  # package's OWN script output — both binary downloads, the extractions, `Success!` (5.8s). The
  # script's stdout appears only in the evicted arm.
  #
  # ⛔ TARGETED, NOT `rm -rf` ON THE WHOLE STORE. The store is MACHINE-GLOBAL and a sibling agent
  # may be measuring on the same box; wiping it would silently corrupt their run. Match the
  # package's own entries only.
  #
  # Cost: each arm re-materializes this package from scratch. That is the price of independent arms.
  # Both, not either: the memo drop is NECESSARY and never SUFFICIENT, so keeping it costs nothing
  # and removing it would reintroduce a second replay path behind the one being fixed here.
  rm -rf "$NUB_CACHE_DIR/pm/side-effects-v1" 2>/dev/null
  # ⛔ THE SLUG MUST MATCH THE STORE'S OWN NAMING, AND THE FIRST REVISION OF THIS EVICTION DID NOT
  # — so it silently NO-OPPED FOR EVERY SCOPED PACKAGE, leaving open exactly the replay it was
  # added to close. The store names each directory `<name, with `/` as `+`>@<version>-<hash>`, e.g.
  # `@babel+core@7.29.7-ee0b878d8515d4c9`. `tr '/@' '--'` turned `@babel/core` into `-babel-core`,
  # which matches nothing. MEASURED on the Linux box against a populated 802-entry store: the old
  # pattern found 0 entries for `@babel/core` while that package was demonstrably present in it;
  # the pattern below found 1. Scoped packages are a large share of the corpus, so this was not an
  # edge case — and it fails silently, which is the shape this whole comment block exists to warn
  # about.
  #
  # Anchoring on `<slug>@` instead of wrapping in `*…*` also keeps the eviction TARGETED, as the
  # note above requires: the store is machine-global and a sibling agent may be measuring on the
  # same box, so a bare `*yorkie*` would take out an unrelated `yorkie-foo` alongside it.
  # ⛔⛔ AND EVICTING `$PKG` ALONE IS STILL NOT ENOUGH — THE REPLAY ALSO ARRIVES THROUGH A
  # TRANSITIVE DEPENDENCY'S STORE ENTRY, AND WHEN IT DOES IT MANUFACTURES A FALSE **OVER**-PREDICTION.
  #
  # MEASURED on `@apollo/rover@0.2.1`. Its postinstall writes into a SIBLING package's directory —
  # `node_modules/binary-install/bin/{rover,README.md,LICENSE}`, not its own — because it delegates to
  # the `binary-install` package. In the jail that path resolves through a SYMLINK out of rover's own
  # store entry into `binary-install@0.1.1-<hash>`'s entry, which `preset.rs`'s
  # `store_entry_write_root` deliberately does NOT grant (it grants the package's own entry root
  # only). So the write is genuinely refused and `write.deps` is genuinely NECESSARY.
  #
  # Evicting `@apollo+rover@*` alone left `binary-install@*` populated by the PREVIOUS arm, so the
  # descent arm relinked an already-built dependency, never attempted the write, and passed. Two arms
  # with the same binary, differing only in what was evicted:
  #
  #   evict rover only          {"network":true}                       rc=0   bin/ EMPTY  -> false PASS
  #   evict rover + binary-install  {"network":true}                   rc=1   bin/ absent -> correct FAIL
  #   evict rover + binary-install  {"write":{"deps":true},...}        rc=0   bin/ rover,README.md,LICENSE
  #
  # ⛔ THE DIRECTION MATTERS. A replay in the VERDICT arm inflates agreement; a replay in a DESCENT
  # arm reports a capability as droppable that is not — an UNDER-prediction, the one direction that
  # breaks installs. So the descent is only as honest as this eviction is complete.
  #
  # The closure comes from the OBSERVE arm's own hoisted `node_modules`, i.e. it is MEASURED rather
  # than guessed: exactly the packages npm needed to run this lifecycle script.
  #
  # ⛔ COST, weighed and accepted. The store is machine-global, so this reaches further than the
  # single-entry eviction it replaces and a sibling agent measuring a package that SHARES one of
  # these dependencies pays a re-materialization. That is strictly better than the alternative it
  # replaces, which was a silent false verdict. Still targeted — exact `<slug>@*` names from this
  # package's own closure, never a wildcard sweep of the store.
  local store="${XDG_CACHE_HOME:-$HOME/.cache}/nub/pm/store"
  if [ -d "$store" ]; then
    printf '%s\n' "$PKG" $CLOSURE | sort -u | while IFS= read -r n; do
      [ -n "$n" ] || continue
      find "$store" -maxdepth 1 -name "$(printf '%s' "$n" | tr '/' '+')@*" -exec rm -rf {} + 2>/dev/null
    done
  fi
  # ⛔⛔ AN EMPTY GRANT CANNOT BE WRITTEN AS AN ENTRY, AND GETTING THIS WRONG SILENTLY DESTROYS THE
  # MODAL CASE. nub REJECTS a catalog entry that widens nothing — "`default` widens nothing and
  # there are no version bands, so the entry grants exactly the base profile; drop it" — and then
  # falls back to the COMPILED-IN catalog, so the arm trips the override assertion and comes back
  # VOID. VOID is not "insufficient", but the caller cannot tell the difference, so the driver
  # escalated up the ladder and reported a spuriously WIDE minimum.
  #
  # MEASURED, and this is the largest error the harness has produced: `yorkie@2.0.0` and
  # `@progress/kendo-licensing@1.9.1` both need NOTHING, and both were reported as
  # `MINIMUM {"write":{"deps":true,"project":true,"userHome":true},"network":true}`. With the
  # construction below they verify at `{}` on the first arm. Roughly half the corpus synthesizes
  # the empty grant, so unfixed this turns the modal case into a near-total grant.
  #
  # The fix follows from what the base profile already IS: nothing. So express the empty grant by
  # OMITTING the package under test, and carry a sentinel entry for an unrelated name purely so the
  # override still engages and the assertion below stays meaningful.
  node -e '
    const fs=require("fs");const [r,p,g]=process.argv.slice(1);
    const grant=JSON.parse(g);
    const cat = Object.keys(grant).length
      ? {packages:{[p]:{default:grant}}}
      : {packages:{"__v2_empty_grant_sentinel__":{default:{network:true}}}};
    fs.writeFileSync(r+"/cat.json",JSON.stringify(cat));
  ' "$v" "$PKG" "$grant" || return 1
  # `$tracer` is empty for a normal arm and `strace -f -o <file>` for the DIAGNOSE arm below. Kept
  # as a parameter rather than a second copy of this function so the preconditions above — unique
  # name, explicit `buildJail`, memo drop, override assertion — cannot drift between the arm that
  # decides the verdict and the arm that explains it.
  ( cd "$v"
    NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-i.txt} "$NUB" install > "$v/i.log" 2>&1
    NUB_BUILD_JAIL_CATALOG="$v/cat.json" ${tracer:+$tracer-a.txt} "$NUB" approve-builds --all > "$v/a.log" 2>&1 )
  local rc=$?
  # ⛔ THE ARM MUST PROVE THE SCRIPT ACTUALLY RAN, because a replayed arm is indistinguishable from
  # a real one by rc and by every other precondition. A genuine first touch runs the lifecycle
  # script; a replay materializes from cache and never spawns it.
  #
  # ⛔⛔ THIS CHECK WAS INERT AND CRIED WOLF ON EVERY ARM, WHICH IS WORSE THAN HAVING NO CHECK. It
  # required `installed [0-9]+ package` in `i.log`, and that was wrong on BOTH halves at once:
  #
  #   1. nub PRINTS NO SUCH LINE. The install summary is `resolved N · reused N`
  #      (`vendor/aube/crates/aube/src/progress/ci.rs`); grepping every crate finds
  #      `installed .* package` only in unrelated prose. The negation was therefore ALWAYS true.
  #   2. IT READ THE WRONG LOG. Lifecycle scripts run under `approve-builds`, whose output goes to
  #      `a.log`. `i.log` is the install step and cannot hold that evidence even in principle.
  #
  # A warning that fires on 100% of arms trains its reader to skip it, so a REAL replay would have
  # sailed straight through — precisely the failure this check exists to catch. Both halves are
  # fixed by searching every log the arm wrote (the same `"$v"/*.log` the override assertion just
  # below already uses) for the one line that actually evidences a script being invoked.
  #
  # Reported, not fatal, and deliberately: the corpus only measures packages that DECLARE an install
  # script, so missing evidence is a real signal here — but a script nub declines to run would also
  # land here and is not a replay.
  if ! grep -qE 'running build scripts for' "$v"/*.log 2>/dev/null; then
    echo "     ⛔ REPLAY SUSPECTED — no 'running build scripts' line in any arm log; the script may not have run"
  fi
  # ⛔ A malformed override WARNS AND FALLS BACK to the compiled-in catalog SILENTLY. Without this
  # assertion an arm can measure the SHIPPED policy while you believe it measured yours.
  local ovr rej files
  ovr=$(cat "$v"/*.log | grep -c 'catalog OVERRIDDEN'); rej=$(cat "$v"/*.log | grep -c 'REJECTED')
  # ⛔ `-L` IS LOAD-BEARING AND ITS ABSENCE INVERTS THE VERDICT. nub's global virtual store makes
  # every node_modules entry a SYMLINK, so a bare `find -type f` counts ~30 files where the npm
  # control counted 456 — and the `files >= OBS_FILES` gate below then fails an arm that installed
  # perfectly. MEASURED on @nuxt/components@2.1.0: the write:"disk" arm exited 0 with a complete
  # install and was reported as "NO-STATE-PASSED". Following the links counts the real artifacts.
  files=$(find -L "$v" -type f ! -name '*.log' ! -name 'cat.json' ! -path '*/nubcache/*' 2>/dev/null | wc -l | tr -d ' ')
  # ⛔⛔ `files >= OBS_FILES` IS NOT A SUCCESS GATE AND MUST NOT BE READ AS ONE. `find -L` follows the
  # isolated layout's symlinks into the machine-global store, so the number is dominated by the
  # dependency closure and is nearly insensitive to whether THIS package's script produced anything.
  # MEASURED on `@apollo/rover@0.2.1`: an arm that produced NONE of the package's three artifacts
  # counted 704 against a 718-file reference and passed. The direction of that error is the dangerous
  # one — on a DESCENT arm it reports a capability as droppable when it is necessary, and on the
  # SYNTH arm it would record an under-predicting grant as VERIFIED.
  #
  # The gate is the per-file ARTIFACT MANIFEST, ported from `measure-windows.mjs` so the two drivers
  # agree on what "the arm succeeded" means. See `artifact-gate.mjs` for why a count gate and a
  # byte-total gate were both measured and rejected, and for the sibling-package limit that the
  # transitive store eviction above covers instead. `files/OBS_FILES` stays PRINTED for continuity
  # with the existing corpus logs, but nothing branches on it any more.
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

# ⛔⛔ THE VERDICT ARM'S VOID CASE MUST ABORT, NOT LADDER. Same three-outcome rule as the descent
# below, and here the cost of collapsing them is the whole record: a VOID synth arm measured the
# COMPILED-IN catalog, so falling through to the ladder walks upward from a hypothesis that was
# never tested and publishes whichever rung happens to pass as this package's MINIMUM. That is the
# exact shape of the largest error this harness has produced (the empty-grant bug), and the
# construction that fixed that one does not stop a VOID arriving by some other route — a malformed
# grant, a binary built without the override feature, a crash before the log line.
verify "$GRANT" "synth"; SRC=$?
if [ "$SRC" -eq 2 ]; then
  echo "  => ⛔ VOID — the override did not engage on the verdict arm; NOTHING was measured."
  echo "     Not a result. Do NOT record it, and do NOT read the absence of a verdict as a wide grant."
  exit 3
fi
if [ "$SRC" -eq 0 ]; then
  echo "  => VERIFIED $GRANT   (observed, then verified)"

  # ── 3a. DESCEND — is the verified grant actually MINIMAL, or did OBSERVE over-predict? ────────
  #
  # ⛔ THIS IS THE ONLY HONEST OVER-PREDICTION MEASUREMENT AVAILABLE, AND IT NEEDS NO ORACLE.
  # Comparing a synthesized grant against a v1 corpus record does not answer the question. A v1
  # record is the output of a blind pass/fail ladder that can only ever report "this grant was
  # insufficient" — never WHAT was missing — and it carries every harness and nub defect live at
  # the moment it was taken. At least one record is already known stale (`iedriver@4.0.0` records
  # `write:"disk"` and installs today under a narrow grant). So a disagreement with the record is
  # not evidence against v2; it is not evidence about v2 at all.
  #
  # What IS evidence: drop one capability from the VERIFIED grant and re-verify in the same real
  # jail. If a strictly narrower grant also passes, OBSERVE over-predicted by exactly that
  # capability — measured, not inferred. One leave-one-out level is enough to detect and size
  # over-prediction, and it is deliberately NOT a lattice search: the point is to characterise the
  # synthesis, not to re-derive a minimum by searching, which is precisely what v1 did.
  #
  # ⛔ EACH DESCENT ARM IS A FULL `verify` CALL, so it inherits the store eviction, the unique root
  # name, the explicit `buildJail`, and the override assertion. An arm run any cheaper than the
  # verdict arm would not be comparable to the verdict arm.
  CAPS=$(node -e '
    const g = JSON.parse(process.argv[1]); const out = [];
    if (g.network) out.push("network");
    for (const k of Object.keys(g.write ?? {})) out.push("write." + k);
    if (g.read) out.push("read");
    console.log(out.join(" "));
  ' "$GRANT")
  if [ -z "$CAPS" ]; then
    echo "  DESCEND   grant is already empty — nothing to narrow; MINIMAL by construction."
  else
    # ⛔⛔ `verify` HAS THREE OUTCOMES AND THIS LOOP MUST NOT COLLAPSE THEM TO TWO. rc 0 = the narrower
    # grant passed, rc 1 = it was genuinely insufficient, rc 2 = the arm was VOID (the override did
    # not engage, so nub silently ran the COMPILED-IN catalog and nothing about `$SUB` was measured).
    # An `if verify …; else NECESSARY; fi` reads VOID as necessity — it manufactures evidence that a
    # capability is needed out of an arm that measured nothing, and it does so in the direction that
    # HIDES over-prediction, which is the direction we are least able to detect by other means.
    #
    # MEASURED, and it fired on the control package: `wordpos@2.1.0`'s `drop-writedeps` arm came back
    # `REJECTED=2` / VOID and the driver printed `'write.deps' is NECESSARY` anyway, so that package's
    # `MINIMAL` verdict was never earned. Reported rather than fatal — the other capabilities' arms
    # are still valid, so the run yields a partial answer instead of none.
    NARROWER=""; INCONCLUSIVE=""
    for cap in $CAPS; do
      SUB=$(node -e '
        const [g0, cap] = process.argv.slice(1); const g = JSON.parse(g0);
        if (cap === "network") delete g.network;
        else if (cap === "read") delete g.read;
        else { const k = cap.split(".")[1]; delete g.write[k];
               if (!Object.keys(g.write).length) delete g.write; }
        console.log(JSON.stringify(g));
      ' "$GRANT" "$cap")
      verify "$SUB" "drop-$(printf '%s' "$cap" | tr -d '.')"; drc=$?
      case "$drc" in
        0) echo "     ⛔ OVER-PREDICTED: dropping '$cap' STILL VERIFIES — $SUB is sufficient"
           NARROWER="$NARROWER $cap" ;;
        2) echo "     ⛔ INCONCLUSIVE for '$cap' — the arm was VOID, so nothing was measured; NOT evidence of necessity"
           INCONCLUSIVE="$INCONCLUSIVE $cap" ;;
        *) echo "     '$cap' is NECESSARY — dropping it fails to verify" ;;
      esac
    done
    if [ -n "$NARROWER" ]; then
      echo "  => OVER-PREDICTED by:$NARROWER  (synthesized $GRANT; each named capability drops on its own)"
    elif [ -n "$INCONCLUSIVE" ]; then
      echo "  => DESCENT INCOMPLETE — no capability dropped, but$INCONCLUSIVE was never measured; MINIMALITY IS UNPROVEN"
    else
      echo "  => MINIMAL — every capability in $GRANT is independently necessary"
    fi
  fi
  exit 0
fi

# ── 3b. DIAGNOSE — re-run the SAME failing grant JAILED, under strace, and name the refusal. ───
#
# ⛔ THIS EXISTS BECAUSE OBSERVING AN UNJAILED RUN STRUCTURALLY CANNOT PREDICT EVERY REFUSAL.
# Step 1 enumerates what the script TOUCHED; it cannot enumerate what confinement will later REFUSE
# on an axis the tracer does not cover, and it cannot see a path the script only reaches once some
# earlier read succeeds. So an under-prediction is expected, and "the synthesized grant did not
# verify" is worth nothing on its own — the ladder that follows says a WIDER grant worked, never
# WHICH capability was missing.
#
# Every Linux `write:"disk"` package resolved so far was closed by exactly this arm, run BY HAND:
# `dotnet-2.0.0@1.4.4`, `@nuxt/components@2.1.0`, `@tensorflow/tfjs-backend-wasm`, `codeceptjs`,
# `postman-code-generators`, `react-native-purchases` — all six turned out to be ONE refused read
# (`/proc/self/stat`, via yarn v1's `initPeakMemoryCounter` -> `process.memoryUsage()` -> libuv's
# `uv_resident_set_memory`). Doing it by hand six times is what this automates.
#
# ⛔ THE GREP IS `= -1 EACCES`, NOT `EACCES`. A bare grep matches the `AT_EACCESS` FLAG NAME in
# every `faccessat2(...)` line — measured, that read 26/13/1 where the truth was 11/0/0.
#
# ⛔⛔ THE OUTPUT IS A LEAD AND THE "LAST REFUSAL" LINE HAS ALREADY BEEN WRONG ONCE — READ THIS
# BEFORE ACTING ON IT. On `@opencode-ai/cli@0.0.0-next-16573` the last refusal before `tgkill(SIGABRT)`
# really was `/proc/self/cgroup`, confirmed by strace. It was a TRAILING RED HERRING: a
# single-variable arm granting `/proc/self/cgroup` ALONE still aborts, while granting
# `/proc/self/maps` alone exits 0 (3/3 runs), and a negative control granting cgroup +
# mmap_min_addr + version_signature together still aborts — so `maps` is necessary and cgroup is
# merely the last thing tried before death.
#
# ⇒ TREAT THE LIST AS A CANDIDATE SET AND SETTLE IT WITH A SINGLE-VARIABLE ARM PER PATH. Grant one,
# re-run, repeat; then a negative control granting all the OTHERS to prove the survivor is
# necessary and not merely sufficient. The full refusal census above is the more honest output of
# the two, which is why it prints first and unabridged.
diagnose () {
  command -v strace > /dev/null 2>&1 || { echo "  DIAGNOSE skipped (no strace)"; return 0; }
  local d="$ROOT/diag"; mkdir -p "$d"
  verify "$GRANT" "diag" "strace -f -o $d/tr" > /dev/null 2>&1
  local refusals
  refusals=$(cat "$d"/tr-*.txt 2>/dev/null | grep -oE '"[^"]+"\)?[^=]*= -1 (EACCES|EPERM|EROFS)' \
    | grep -oE '^"[^"]+"' | sort | uniq -c | sort -rn)
  if [ -z "$refusals" ]; then
    echo "  DIAGNOSE  ZERO filesystem refusals under the failing grant."
    echo "     ⇒ the missing capability is NOT a path this tracer covers — look at the network axis,"
    echo "       or a resource class strace's file+network filter does not carry."
    return 0
  fi
  echo "  DIAGNOSE  refused paths under the failing grant (count, path):"
  echo "$refusals" | head -12 | sed 's/^/     /'
  # The last refusal before a process exits non-zero is the strongest single lead available.
  local fatal
  fatal=$(cat "$d"/tr-*.txt 2>/dev/null | grep -E '= -1 (EACCES|EPERM|EROFS)|\+\+\+ exited with [1-9]' \
    | grep -B1 'exited with [1-9]' | grep -E '= -1 ' | tail -1)
  [ -n "$fatal" ] && echo "     LAST REFUSAL BEFORE A NON-ZERO EXIT (a lead, not proof):" \
    && echo "       $fatal" | cut -c1-200
}
diagnose

# ── 4. FALL BACK — the ladder, retained, but walked UPWARD FROM the synthesized grant. ─────────
# This is the ladder's real job: repairing a hypothesis, over a handful of states rather than 55.
echo "  synthesized grant did not verify — falling back to a bounded ladder"
for g in \
  '{"write":{"deps":true,"project":true,"userHome":true},"network":true}' \
  '{"write":{"deps":true,"project":true,"userHome":true},"read":"disk","network":true}' \
  '{"write":"disk","network":true}'
do
  verify "$g" "fb$(echo "$g" | cksum | cut -d' ' -f1)"; frc=$?
  # A VOID rung is not a failed rung. Collapsing them makes the ladder CLIMB PAST a grant it never
  # tested and publish the next one as the minimum — over-granting on the strength of no measurement.
  [ "$frc" -eq 2 ] && { echo "     ⛔ VOID rung — override did not engage; the ladder cannot continue honestly"; exit 3; }
  if [ "$frc" -eq 0 ]; then
    echo "  => MINIMUM $g   (ladder fallback; synthesized grant was insufficient)"
    echo "  ⛔ OBSERVE UNDER-PREDICTED — the gap between $GRANT and $g is worth reading"
    exit 0
  fi
done
echo "  => NO-STATE-PASSED even at write:disk — investigate; do not widen the catalog blindly"
