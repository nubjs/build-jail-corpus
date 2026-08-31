#!/usr/bin/env bash
# Publish ONE freshly-measured v2 record to origin, immediately.
#
# ⛔ A SEPARATE SCRIPT RATHER THAN A FLAG ON `publish-record.sh`, AND THAT IS THE POINT. That script
# is what the LIVE v1 fleet publishes through; parameterising its `records/*` prefix, its
# `--records records` reconcile and its `queue.ndjson` staging would put a change to a running
# fleet's publish path in the critical section of a new lane's bring-up. The v1 and v2 lanes touch
# DISJOINT files — `records/` + `queue.ndjson` against `records-v2/` + `queue-v2.ndjson` — so the
# only thing they contend for is the branch itself, which both already handle by retrying.
#
# ⛔ NEVER FORCE-PUSHES, AND `git add <dir>` IS BANNED HERE. Both rules are inherited from
# `publish-record.sh`, where they were learned in production: a bare `git add records` is
# `git add -A`, so it stages DELETIONS of every record another runner pushed after this runner's
# checkout — commit 561db3a deleted 14 of them while publishing one. Only the paths in this run's
# own manifest are ever staged.
#
# ⛔ ALWAYS EXITS 0. A record that does not land here is not lost: it stays on disk for the
# end-of-slice commit and the CI artifact. Killing a measuring run over a rejected push would trade
# the thing being protected for the protection.
#
# Usage: publish-record-v2.sh <record-dir>   (invoked by run-batch-v2.mjs via NUB_CORPUS_ON_RECORD)
set -uo pipefail

REC_DIR="${1:-}"
[ -n "$REC_DIR" ] && [ -f "$REC_DIR/results.json" ] || exit 0
REPO="${NUB_CORPUS_REPO:-}"
[ -n "$REPO" ] && [ -d "$REPO/.git" ] || exit 0
cd "$REPO" || exit 0

REL="${REC_DIR#"$REPO"/}"
case "$REL" in
  records-v2/*) ;;
  *) exit 0 ;;   # a v1 record is not this script's to publish
esac

BRANCH="${NUB_CORPUS_BRANCH:-main}"
QUEUE="${NUB_V2_QUEUE:-queue-v2.ndjson}"
MANIFEST="${NUB_CORPUS_MANIFEST:-/tmp/nub-corpus-v2-published.txt}"

STASH="$(mktemp -d 2>/dev/null)" || exit 0
trap 'rm -rf "$STASH" 2>/dev/null || true' EXIT
mkdir -p "$STASH/rec"
cp -R "$REC_DIR/." "$STASH/rec/" 2>/dev/null || exit 0

git config user.name  "corpus-runner"  2>/dev/null || true
git config user.email "corpus-runner@users.noreply.github.com" 2>/dev/null || true

# ⛔ THE MANIFEST IS APPENDED TO ONLY AFTER A PUBLISH VERDICT, FURTHER DOWN — NEVER HERE.
# It used to be appended at this point, before the guard ran, and that made the guard DECORATIVE:
# the manifest is replayed by every LATER invocation (`git add` per line, below) and by the
# end-of-slice bulk commit, so a withheld record was staged and pushed under the NEXT package's
# commit message. REPRODUCED: two invocations sharing one manifest, the first withheld — the
# withheld `{}` grant landed on origin under the second package's commit.
#
# The first test of this guard used a SEPARATE manifest per record and therefore could not have
# caught it, which is the "control that cannot fail" failure one level up from the thing it guards.

# ⛔ PARK A RECORD OUTSIDE `records-v2/` AND PUT ORIGIN'S BACK. Shared by the two things that
# withhold — the publish guard, and the instrument-failure check below — because they must leave the
# tree in exactly the same state, and a second copy of this would eventually drift from the first.
withhold_record () {
  local why="$1"
  echo "  ⛔ WITHHELD ($why): $REL" >&2
  local dir="${NUB_CORPUS_WITHHELD:-withheld-records}/$(basename "$(dirname "$REL")")-$(basename "$REL")"
  mkdir -p "$dir" 2>/dev/null
  cp -R "$STASH/rec/." "$dir/" 2>/dev/null
  if git cat-file -e "origin/$BRANCH:$REL/results.json" 2>/dev/null; then
    git checkout -q "origin/$BRANCH" -- "$REL" 2>/dev/null
  else
    rm -rf "$REL" 2>/dev/null
  fi
  echo "     Parked at $dir (outside records-v2, so no bulk commit can sweep it in)." >&2
}

# ⛔ A ROW THAT CANNOT PUBLISH AT THIS HASH MUST BE SETTLED, OR THE QUEUE HANDS IT BACK FOREVER.
# Withholding leaves origin's PRIOR record in place, and that record carries an OLD `harnessSha256`.
# `collect-verdicts.mjs` then reads the restored prior, `claim-slice.mjs --complete` stamps the row
# from it, and the next claim's invalidation pass sees a stale hash and returns the row to `pending`.
# The row can never converge: it is re-measured, re-withheld and re-opened by every slice.
#
# MEASURED on four consecutive linux slices (33011883250, 33016334427, 33020269262, 33024052763):
# each claimed 60, each withheld the SAME 35 package@versions -- `comm -12` on the sorted name lists
# gives 35 of 35 for every pair -- and each published 16. 58% of every slice was spent re-deriving
# an outcome the corpus had already refused, and the stuck set GROWS with every slice that adds to
# it. This manifest is what lets `--complete` close such a row AT THIS HASH, so it is retried when
# the harness genuinely changes and not before.
note_settled () {
  [ -n "${NUB_CORPUS_SETTLED:-}" ] || return 0
  node -e '
    const fs = require("fs");
    let r = {}; try { r = require(process.argv[1] + "/results.json"); } catch { }
    if (!r.pkg || !r.version) process.exit(0);
    fs.appendFileSync(process.argv[2],
      JSON.stringify({ pkg: r.pkg, version: r.version, settled: process.argv[3] }) + "\n");
  ' "$STASH/rec" "$NUB_CORPUS_SETTLED" "$1" 2>/dev/null || true
}

# ⛔ CARRY THE WITHHELD VERDICT PAST THE RESTORED RECORD, OR THE RETRY BELOW IS A FICTION.
#
# `withhold_record` puts origin's PRIOR record back, and `collect-verdicts.mjs` walks the records
# tree — so `--complete` sees that prior REAL verdict and marks the row done, stamped from a record
# whose `harnessSha256` is stale. The next claim's invalidation pass reopens it and the slice
# re-measures it, forever. This is the same non-convergence `note_settled` documents for the guard
# path, on the branch that was left without the fix.
#
# MEASURED 2026-08-30 across three linux slices 4.5 h apart (33272217260, 33278756575, 33283327384):
# each claimed 60 and each withheld the SAME 42 package@versions, and each logged `0 instrument
# failure(s) returned to pending`. The stuck set grew 27 -> 48 per slice over 15 hours and had taken
# 42 of the linux lane's last 105 rows.
#
# NOT `note_settled`: settling here would freeze a TRANSIENT instrument failure on its first
# attempt, and the bounded retry exists because some are transient. This restores the retry the
# message below already promises — two returns to `pending`, then an honest settle on the third.
note_instrument_failure () {
  [ -n "${NUB_CORPUS_INSTRUMENT_FAILURES:-}" ] || return 0
  node -e '
    const fs = require("fs");
    let r = {}; try { r = require(process.argv[1] + "/results.json"); } catch { }
    if (!r.pkg || !r.version) process.exit(0);
    fs.appendFileSync(process.argv[2],
      JSON.stringify({ pkg: r.pkg, version: r.version, verdict: process.argv[3] }) + "\n");
  ' "$STASH/rec" "$NUB_CORPUS_INSTRUMENT_FAILURES" "$1" 2>/dev/null || true
}

# ⛔ THE REASON, NOT JUST THE VERDICT. `run-batch-v2.mjs` KEEPS the driver log for a `HARNESS-*` and
# reports it by path — but that path is inside the record dir, which this script then parks outside
# `records-v2/`, and the slice artifact uploads only `records-v2/`. So the one line that says WHY
# reaches no reader at all: 42 packages failed identically for 15 hours with the cause on disk on a
# runner that was then destroyed. The driver prints it as `=> HARNESS-...: <reason>`.
#
# ⛔ THE LINES AFTER THE VERDICT, NOT JUST THE VERDICT LINE. The drivers already print nub's own
# stderr under it -- `measure.sh:1374` emits "── nub's own words (tail of security-resolve.log) ──"
# and 30 lines of it -- and epoch 28 grepped only the `=> HARNESS-` line, so the CAUSE was dropped
# one line short of being readable. MEASURED on run 33285785801: 20 of 21 reasons came back as
# "Nub could not materialize the tree with --ignore-scripts", which names the step and not the
# refusal, and the exit code that would have identified it (23 trust-policy vs 21 age-gate) was in
# the very next lines. Keeping the trailing context is the difference between a class and a cause.
#
# ⛔⛔ AND THE CLASS WITH NO MARKER AT ALL, WHICH THIS PRINTER WAS BLIND TO. `record.mjs:794` assigns
# `HARNESS-ERROR` as a FALLBACK when no verdict marker matched anywhere in the log — the driver died
# before it could print one. For that class the grep below matches nothing, so the printer emitted
# NOTHING: not a reason, and not the "no driver log stashed" line either, because the log is there.
# MEASURED on run 33293351038: 4 of the 11 withheld instrument failures — `@aws-amplify/cli` 1.12.0,
# 2.0.0 and 3.9.0, and `@nuxt/content@3.0.0-alpha.3` — printed a WITHHELD line, a Parked line, and then
# silence. They ran 51-137 s, so no timeout explains them, and nothing on that runner survived to say
# more. A failure with no marker is exactly the one whose log is the ONLY evidence, and it was the one
# case that produced no output. A tail cannot be worse than nothing.
show_failure_reason () {
  [ -f "$STASH/rec/.driver.out" ] || { echo "     (no driver log stashed — cannot say why)" >&2; return 0; }
  if grep -aqE '=> HARNESS-' "$STASH/rec/.driver.out"; then
    grep -aA 14 -E '=> HARNESS-' "$STASH/rec/.driver.out" | tail -30 | sed 's/^ */     WHY: /' >&2
  else
    # ⛔ NAME THE VERDICT THAT ACTUALLY LANDED, NOT A HARDCODED ONE. `record.mjs:793` picks between
    # TWO fallbacks — `rc === 124 || rc === 137 ? 'HARNESS-TIMEOUT' : 'HARNESS-ERROR'` — and epoch 32
    # wrote only the second into this message. MEASURED on run 33313922458: `node@24.18.0` was
    # withheld as HARNESS-TIMEOUT while this line told the reader it was HARNESS-ERROR, which sends
    # them hunting for a crash in a log whose real story is a deadline kill. `$RECORD_VERDICT` is
    # read from the stashed record at line 168, before the only call site, so it is always in scope
    # here; the `:-HARNESS-ERROR` default covers a record too broken to parse.
    echo "     WHY: (no verdict marker — record.mjs fell back to ${RECORD_VERDICT:-HARNESS-ERROR}; tail of the driver log follows)" >&2
    tail -30 "$STASH/rec/.driver.out" | sed 's/^ */     WHY: /' >&2 || true
  fi
}

# ⛔ AN INSTRUMENT FAILURE IS NOT A MEASUREMENT AND MUST NOT REACH THE MANIFEST. `record-validity.mjs`
# rejects a `HARNESS-*` verdict outright, and `claim-slice.mjs` returns such a row to `pending` for
# retry — but this script published it regardless, so the slice gate then failed on a record the
# harness already knew was not a result, and took the WHOLE SLICE with it: that gate runs before the
# commit step under `set -eu`. MEASURED on run 32665285301 — `netlify-cli@23.9.5` came back
# `HARNESS-*`, the gate said "instrument failure is not a measurement", and 49 good records were
# binned alongside it.
#
# Withheld rather than merely skipped, so the row stays open: `claim-slice --complete` already
# returns an instrument failure to pending, and that retry is the behaviour this preserves.
RECORD_VERDICT="$(node -e 'try{const r=require(process.argv[1]+"/results.json");process.stdout.write(String(r.verdict??""))}catch{}' "$STASH/rec" 2>/dev/null)"

for attempt in 1 2 3; do
  # MIXED reset, not --hard and not --soft. --hard would delete a record committed here but not yet
  # pushed, from the working tree the end-of-slice commit and the artifact both read. --soft leaves
  # the index holding a stale `.github/workflows/`, and GITHUB_TOKEN may not modify workflow files,
  # so every push is rejected outright.
  git fetch -q origin "$BRANCH" 2>/dev/null || { sleep $((attempt * 3)); continue; }
  git reset -q "origin/$BRANCH" 2>/dev/null || { sleep $((attempt * 3)); continue; }

  # Take origin's queue VERBATIM: this run's claim was published atomically before measuring, so it
  # is already there, and carrying a stale local copy across would silently release rows another
  # runner claimed while this package was measuring.
  git checkout -q "origin/$BRANCH" -- "$QUEUE" 2>/dev/null || true

  # An instrument failure never becomes a record. See the block above the loop for what it cost.
  case "$RECORD_VERDICT" in
    HARNESS-*)
      withhold_record "instrument failure, not a measurement: $RECORD_VERDICT"
      note_instrument_failure "$RECORD_VERDICT"
      show_failure_reason
      echo "     The row stays open; claim-slice --complete returns it to pending for retry." >&2
      exit 0 ;;
  esac

  # ⛔ THE ONE THING THAT MAY NOT BE OVERWRITTEN: a measured grant, replaced by a NARROWER one that
  # no arm could have falsified. `arm-falsifiability.mjs` is "flag, never fail" — correct for a
  # record that merely proves little, but it leaves a vacuous NARROWING to publish under a flag
  # nobody is required to read, which is an under-grant. `publish-guard.mjs` is that missing act.
  #
  # ⛔ FAILS OPEN, DELIBERATELY. Exit 10 is the only verdict that withholds; a missing guard, a
  # parse error or any other status publishes exactly as before. A publish path that starts dropping
  # records because a helper broke would cost more than the case it protects — and the guard's own
  # red-green lives in `publish-guard.test.mjs`, not in this script's behaviour.
  #
  # Read the PRIOR from origin rather than the working tree: the reset above has already put
  # origin's copy there, but only for a record that exists upstream, and `--prior /dev/null` (no
  # prior) must publish rather than compare against a half-written file.
  PRIOR_JSON="$STASH/prior.json"
  git show "origin/$BRANCH:$REL/results.json" > "$PRIOR_JSON" 2>/dev/null || : > "$PRIOR_JSON"
  if [ -s "$PRIOR_JSON" ]; then
    # ⛔ stderr is KEPT, not discarded. This fails open, so a guard that is broken publishes exactly
    # as before — and if the only trace of that is a silent `2>/dev/null`, the fail-open is
    # indistinguishable from a clean PUBLISH verdict in a slice log.
    node harness/v2/publish-guard.mjs --prior "$PRIOR_JSON" --incoming "$STASH/rec/results.json" \
      > "$STASH/guard.out" 2>"$STASH/guard.err"
    GUARD_RC=$?
    if [ "$GUARD_RC" != "0" ] && [ "$GUARD_RC" != "10" ]; then
      echo "  ⚠ publish-guard failed (rc=$GUARD_RC) — FAILING OPEN, this record is publishing" \
           "UNGUARDED: $(head -c 300 "$STASH/guard.err" 2>/dev/null)" >&2
    fi
    if [ "$GUARD_RC" = "10" ]; then
      withhold_record "not published"
      note_settled "publish-guard withheld the re-measure"
      sed 's/^/     /' "$STASH/guard.out" >&2
      # ⛔ THE RECORD MUST LEAVE THE WORKING TREE, NOT MERELY GO UNSTAGED. `record.mjs --out` writes
      # straight into `records-v2/runs/...`, i.e. the record is ALREADY at $REL before this script
      # runs. The MIXED reset above leaves the working tree alone, and both the end-of-slice bulk
      # commit and `.github/workflows/corpus-v2-runner.yml`'s `git add records-v2` sweep the whole
      # directory — so a withheld record left in place is published by the next thing that commits,
      # with no guard anywhere in that path. Restore origin's copy, and park the withheld one
      # OUTSIDE records-v2 so it stays inspectable without being sweepable.
      echo "     The corpus keeps its prior grant." >&2
      exit 0
    fi
  fi

  mkdir -p "$REL"
  cp -R "$STASH/rec/." "$REL/" 2>/dev/null

  # PUBLISH verdict reached: only now may this record join the replayed manifest.
  printf '%s\n' "$REL" >> "$MANIFEST" 2>/dev/null
  sort -u -o "$MANIFEST" "$MANIFEST" 2>/dev/null

  node harness/claim-slice.mjs --reconcile --require-current-instrument \
    --records records-v2 --queue "$QUEUE" >/dev/null 2>&1 || true

  # ⛔⛔ `--sparse` IS MANDATORY, AND WITHOUT IT THIS PUBLISHER CLOSES ROWS AGAINST RECORDS THAT
  # NEVER LAND. The runner checks out in CONE MODE with the cone set to `harness`, `inputs`,
  # `.github` (`corpus-v2-runner.yml`) — `records-v2/runs/<plat>/...` is OUTSIDE it, so a plain
  # `git add` on a record path stages NOTHING and says so only on stderr, which this line discards.
  # `queue-v2.ndjson` is a TOP-LEVEL file and a cone checkout always includes those, so the queue
  # staged every time. The result is a commit carrying the row-close and not the measurement.
  #
  # MEASURED 2026-08-31 on `probe/corpus-v2-lane`: of the last 72 per-package publish commits,
  # 72 touched `queue-v2.ndjson` ALONE and 0 carried a record. The rows they closed keep whatever
  # record was on the branch before — epochs 3, 26, 27 and 30 were still sitting under rows marked
  # `done` days later, invisible to coverage (which counts records) and unreachable by the
  # invalidation pass (which only reopens rows it judges stale). The end-of-slice bulk commit hid
  # this in a DRAIN because it uses `git add --sparse` and sweeps the whole tree; a debug PROBE has
  # no commit step at all, so its records only ever reach the artifact and every row it closes is
  # stranded permanently. Three of the five leaked rows are exactly one probe's subjects.
  #
  # The workflow's own bulk-commit step already carries this warning at the `git add --sparse` line.
  # It did not travel to the per-package path, which was added later.
  STAGE_MISSING=''
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    git add --sparse --ignore-removal -- "$rel" 2>/dev/null
    # ⛔ VERIFY THE INDEX, DO NOT TRUST THE ADD. The whole defect above was an `add` that failed
    # silently, so asking git what is actually there is the only check worth having here.
    #
    # ⛔ THE QUESTION IS "IS IT ON THE BRANCH", NOT "DID IT STAGE JUST NOW". The manifest is
    # REPLAYED by every later invocation, so a record an earlier publish already committed stages
    # nothing this time — a staged-only check calls that a failure and then withholds the queue for
    # the whole rest of the slice. Epoch 12 fixed the identical misreading in the end-of-slice
    # commit guard, whose note records the same discriminator.
    if ! git diff --cached --name-only -- "$rel/results.json" 2>/dev/null | grep -q . \
       && ! git cat-file -e "HEAD:$rel/results.json" 2>/dev/null; then
      STAGE_MISSING="$STAGE_MISSING $rel"
    fi
  done < "$MANIFEST"

  # ⛔ A ROW-CLOSE WITHOUT ITS RECORD IS WORSE THAN A DEFERRED ROW-CLOSE. If any record failed to
  # stage, leave the queue OUT of this commit: `--complete` and the end-of-slice bulk commit still
  # own the bookkeeping, and a row left open is re-measured, where a row closed over an absent
  # record is stranded with no signal anywhere. Loud on stderr, and never fatal — this script fails
  # open by design, and a publisher that started failing the job would cost more than it saves.
  if [ -n "$STAGE_MISSING" ]; then
    echo "  ⚠ record(s) did not stage — NOT closing the row in this commit:$STAGE_MISSING" >&2
  else
    git add -- "$QUEUE" 2>/dev/null
  fi
  if git diff --cached --quiet 2>/dev/null; then exit 0; fi

  PKG="$(node -e 'try{const r=require(process.argv[1]+"/results.json");console.log(r.pkg+"@"+r.version+" "+r.verdict)}catch{console.log("record")}' "$REC_DIR" 2>/dev/null)"
  git commit -q -m "corpus(v2): ${PKG}" 2>/dev/null || exit 0
  if git push -q origin "HEAD:$BRANCH" 2>/dev/null; then
    echo "  published: ${PKG}" >&2
    exit 0
  fi
  sleep $((attempt * 3))
done

echo "  publish deferred (branch busy): ${REL}" >&2
exit 0
