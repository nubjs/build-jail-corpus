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
# `-f` is mandatory: the interesting syscall is routinely a grandchild of the postinstall.
strace -f -e trace=file,network,process -o "$OBS/trace.txt" \
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

# ── 2. SYNTHESIZE ──────────────────────────────────────────────────────────────────────────────
node "$HERE/observe.mjs" "$OBS/trace.txt" "$OBS" "$HOME" > "$ROOT/observed.txt" 2>&1
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
  local slug; slug=$(printf '%s' "$PKG" | tr '/' '+')
  local store="${XDG_CACHE_HOME:-$HOME/.cache}/nub/pm/store"
  if [ -d "$store" ]; then
    find "$store" -maxdepth 1 -name "${slug}@*" -exec rm -rf {} + 2>/dev/null
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
  # a real one by rc and by every other precondition. `materialized` with no install line is the
  # replay signature; a genuine first touch downloads and runs. Reported, not fatal — a package with
  # no lifecycle script legitimately shows neither.
  if grep -qE '^\s*materialized ' "$v/i.log" 2>/dev/null && ! grep -qE 'installed [0-9]+ package' "$v/i.log" 2>/dev/null; then
    echo "     ⛔ REPLAY SUSPECTED — 'materialized' with no install line; the script may not have run"
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
  echo "  VERIFY[$label] rc=$rc files=$files OVERRIDDEN=$ovr REJECTED=$rej grant=$grant"
  [ "$ovr" -ge 1 ] && [ "$rej" -eq 0 ] || { echo "     ⛔ override did not engage — arm is VOID"; return 2; }
  # Artifacts, not exit codes: a jailed run that exits 0 having produced nothing is the normal
  # failure mode. Compare against what the unjailed OBSERVE arm produced.
  [ "$rc" -eq 0 ] && [ "$files" -ge "$OBS_FILES" ]
}

if verify "$GRANT" "synth"; then
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
    NARROWER=""
    for cap in $CAPS; do
      SUB=$(node -e '
        const [g0, cap] = process.argv.slice(1); const g = JSON.parse(g0);
        if (cap === "network") delete g.network;
        else if (cap === "read") delete g.read;
        else { const k = cap.split(".")[1]; delete g.write[k];
               if (!Object.keys(g.write).length) delete g.write; }
        console.log(JSON.stringify(g));
      ' "$GRANT" "$cap")
      if verify "$SUB" "drop-$(printf '%s' "$cap" | tr -d '.')"; then
        echo "     ⛔ OVER-PREDICTED: dropping '$cap' STILL VERIFIES — $SUB is sufficient"
        NARROWER="$NARROWER $cap"
      else
        echo "     '$cap' is NECESSARY — dropping it fails to verify"
      fi
    done
    if [ -n "$NARROWER" ]; then
      echo "  => OVER-PREDICTED by:$NARROWER  (synthesized $GRANT; each named capability drops on its own)"
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
  if verify "$g" "fb$(echo "$g" | cksum | cut -d' ' -f1)"; then
    echo "  => MINIMUM $g   (ladder fallback; synthesized grant was insufficient)"
    echo "  ⛔ OBSERVE UNDER-PREDICTED — the gap between $GRANT and $g is worth reading"
    exit 0
  fi
done
echo "  => NO-STATE-PASSED even at write:disk — investigate; do not widen the catalog blindly"
