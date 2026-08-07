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
      echo "  ⛔ WITHHELD (not published): $REL" >&2
      sed 's/^/     /' "$STASH/guard.out" >&2
      # ⛔ THE RECORD MUST LEAVE THE WORKING TREE, NOT MERELY GO UNSTAGED. `record.mjs --out` writes
      # straight into `records-v2/runs/...`, i.e. the record is ALREADY at $REL before this script
      # runs. The MIXED reset above leaves the working tree alone, and both the end-of-slice bulk
      # commit and `.github/workflows/corpus-v2-runner.yml`'s `git add records-v2` sweep the whole
      # directory — so a withheld record left in place is published by the next thing that commits,
      # with no guard anywhere in that path. Restore origin's copy, and park the withheld one
      # OUTSIDE records-v2 so it stays inspectable without being sweepable.
      WITHHELD_DIR="${NUB_CORPUS_WITHHELD:-withheld-records}/$(basename "$(dirname "$REL")")-$(basename "$REL")"
      mkdir -p "$WITHHELD_DIR" 2>/dev/null
      cp -R "$STASH/rec/." "$WITHHELD_DIR/" 2>/dev/null
      if git cat-file -e "origin/$BRANCH:$REL/results.json" 2>/dev/null; then
        git checkout -q "origin/$BRANCH" -- "$REL" 2>/dev/null
      else
        rm -rf "$REL" 2>/dev/null
      fi
      echo "     Parked at $WITHHELD_DIR (outside records-v2, so no bulk commit can sweep it in)." >&2
      echo "     The corpus keeps its prior grant." >&2
      exit 0
    fi
  fi

  mkdir -p "$REL"
  cp -R "$STASH/rec/." "$REL/" 2>/dev/null

  # PUBLISH verdict reached: only now may this record join the replayed manifest.
  printf '%s\n' "$REL" >> "$MANIFEST" 2>/dev/null
  sort -u -o "$MANIFEST" "$MANIFEST" 2>/dev/null

  node harness/claim-slice.mjs --reconcile --records records-v2 --queue "$QUEUE" >/dev/null 2>&1 || true

  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    git add --ignore-removal -- "$rel" 2>/dev/null
  done < "$MANIFEST"
  git add -- "$QUEUE" 2>/dev/null
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
