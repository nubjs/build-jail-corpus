#!/usr/bin/env bash
# Publish ONE freshly-measured record to origin, immediately.
#
# ⛔ WHY PER-RECORD AND NOT PER-SLICE. A slice measures ~100 packages over two-plus hours and used to
# commit once at the end, which means a two-hour window where nothing is visible and everything is at
# risk: a runner that dies at minute 115 loses 100 measurements. Publishing each record as it lands
# caps the loss at ONE package and makes progress observable while the slice is still running.
#
# ⛔ FORCE-PUSHING WOULD BE THE ONE THING THAT ACTUALLY LOSES RESULTS. It is the obvious way to make a
# push "always succeed", and it is exactly wrong here: if the Windows runner force-pushes while macOS
# has just landed a record, the macOS record is gone. This script NEVER force-pushes. It does not need
# to, because the conflicts it might hit are not real:
#
#   - A record lives at records/runs/<platform>/<pkg>/<version>/. Two runners never write the same
#     path — different platforms are different directories, and within one platform the queue claim
#     guarantees disjoint packages. Record files are ADD-ONLY and content-addressed by that triple.
#   - The only genuinely shared file is queue.ndjson.
#
# So instead of merging, this REPLAYS ONTO ORIGIN: fetch, move HEAD onto the new origin with a SOFT
# reset (keeping the working tree), re-add whatever records are on disk, RE-DERIVE the queue from
# them, commit, push. A loser simply retries against the new head. Conflict-free by construction
# rather than by luck.
#
# The soft reset is load-bearing and was a --hard until a test caught it: a hard reset discards local
# commits and the files they carry, so a record committed here but not yet pushed would be deleted
# from the working tree — and therefore from the end-of-slice commit and the CI artifact too, since
# both read `records/` on disk. Verified: with a push forced to fail, the stranded record survives on
# disk AND is carried to origin by the next publish.
#
# ⛔ PUBLISHING IS BEST EFFORT AND MUST NEVER FAIL THE MEASUREMENT. This script always exits 0. A
# record that does not land here is not lost: it stays on disk, the end-of-slice commit sweeps it up,
# and the CI artifact carries it regardless. Killing a two-hour measurement run because a push was
# rejected would trade the thing we are protecting for the protection.
#
# Usage: publish-record.sh <record-dir>      (invoked by run-batch.sh via NUB_CORPUS_ON_RECORD)
set -uo pipefail

REC_DIR="${1:-}"
[ -n "$REC_DIR" ] && [ -f "$REC_DIR/results.json" ] || exit 0
REPO="${NUB_CORPUS_REPO:-}"
[ -n "$REPO" ] && [ -d "$REPO/.git" ] || exit 0

cd "$REPO" || exit 0

# The record's path RELATIVE to the repo — that is the only thing we must preserve across the reset.
REL="${REC_DIR#"$REPO"/}"
case "$REL" in
  records/*) ;;
  *) exit 0 ;;   # not ours to publish
esac

BRANCH="${NUB_CORPUS_BRANCH:-main}"
STASH="$(mktemp -d 2>/dev/null)" || exit 0
trap 'rm -rf "$STASH" 2>/dev/null || true' EXIT
mkdir -p "$STASH/rec"
cp -R "$REC_DIR/." "$STASH/rec/" 2>/dev/null || exit 0

git config user.name  "corpus-runner"  2>/dev/null || true
git config user.email "corpus-runner@users.noreply.github.com" 2>/dev/null || true

for attempt in 1 2 3; do
  # ⛔ MIXED, NOT --hard AND NOT --soft. All three keep HEAD correct; the difference is what else they
  # touch, and both of the obvious choices are wrong here.
  #
  # --hard would discard local commits AND the files they carry: a record committed here but not yet
  # pushed exists only in that commit, so a hard reset deletes it from the working tree — and then it
  # is gone from the end-of-slice commit and the CI artifact too, because both read `records/` on
  # disk. A silent loss of a measured result, inside the mechanism built to prevent exactly that.
  #
  # --soft was the first fix and it introduced a DIFFERENT silent failure. It leaves the INDEX as it
  # was at checkout, so the commit carries that entire stale tree — including a copy of
  # `.github/workflows/` from before any workflow edit. GITHUB_TOKEN may not modify workflow files, so
  # the push is rejected outright:
  #
  #     ! [remote rejected] HEAD -> main (refusing to allow a GitHub App to create or update
  #       workflow .github/workflows/corpus-queue-runner.yml without `workflows` permission)
  #
  # and because publishing is best-effort, that surfaced only as "publish deferred (branch busy)".
  # MEASURED on one live slice: 56 records deferred against 44 published, for the whole period after a
  # workflow edit landed mid-run. Nothing was lost — the end-of-slice commit still sweeps them up —
  # but per-record publishing had quietly stopped doing its job.
  #
  # A mixed reset (the default) moves HEAD and resets the INDEX to match it, while leaving the WORKING
  # TREE untouched. That is what was wanted all along: stranded records survive on disk and get
  # re-added, and only the paths this script explicitly stages end up in the commit.
  git fetch -q origin "$BRANCH" 2>/dev/null || { sleep $((attempt * 3)); continue; }
  git reset -q "origin/$BRANCH" 2>/dev/null || { sleep $((attempt * 3)); continue; }

  # ⛔ TAKE ORIGIN'S QUEUE VERBATIM — the working copy goes stale the moment any other runner
  # publishes a claim. --soft leaves the working tree alone, which is right for records and wrong for
  # the queue: reconciling and committing MY stale copy would write it over a newer origin and
  # silently release the rows another runner had just claimed, handing its packages to a third
  # runner while it was still measuring them.
  #
  # Nothing of ours is lost by taking theirs: this run's own claim was published atomically before
  # measuring, so it is already IN origin's queue. --reconcile then re-marks done from the records on
  # disk, which is the only thing this script needs the queue for.
  git checkout -q "origin/$BRANCH" -- queue.ndjson 2>/dev/null || true

  mkdir -p "$REL"
  cp -R "$STASH/rec/." "$REL/" 2>/dev/null

  # RE-DERIVE the queue rather than carrying a copy across: origin's queue may hold another
  # platform's claims made while this package was measuring, and overwriting it would silently
  # release their rows. --reconcile only ever marks a row done, and only when a record exists.
  node harness/claim-slice.mjs --reconcile --records records >/dev/null 2>&1 || true

  # ⛔⛔ STAGE ONLY THIS RECORD'S OWN PATH. NEVER `git add records`.
  #
  # In modern git, `git add <dir>` is `git add -A <dir>`: it stages DELETIONS of tracked files that
  # are absent from the working tree. This script deliberately does NOT reset the working tree to
  # origin — it keeps the runner's own records — so every record another runner pushed AFTER this
  # runner's checkout is tracked on origin and missing here. `git add records` staged all of those as
  # deletions, and the commit removed them.
  #
  # MEASURED IN PRODUCTION, and it was live: commit 561db3a ("corpus: husky@1.3.1 MINIMUM") deleted 14
  # records belonging to other runners in the act of publishing one of its own. 56 queue rows ended up
  # marked done, reconciled from a record that had since been deleted from origin.
  #
  # ⛔ THIS IS THE "we would lose a lot of results" FAILURE, arriving through a door nobody was
  # watching. It is not a merge conflict and not a force-push — both of those were designed against.
  # It is `git add` doing exactly what it documents. And it was DORMANT until same-OS runners went
  # parallel: with one runner per OS there was never another runner's record to delete.
  #
  # Staging the explicit path can only ever add or modify this one record, whatever else has landed.
  git add -- "$REL" queue.ndjson 2>/dev/null
  if git diff --cached --quiet 2>/dev/null; then exit 0; fi   # already published by someone

  PKG="$(node -e 'try{const r=require(process.argv[1]+"/results.json");console.log(r.pkg+"@"+r.version+" "+r.verdict)}catch{console.log("record")}' "$REC_DIR" 2>/dev/null)"
  git commit -q -m "corpus: ${PKG}" 2>/dev/null || exit 0
  if git push -q origin "HEAD:$BRANCH" 2>/dev/null; then
    echo "  published: ${PKG}" >&2
    exit 0
  fi
  sleep $((attempt * 3))
done

# Three rejections means the branch is busy. Say so and move on — the end-of-slice commit and the CI
# artifact both still carry this record.
echo "  publish deferred (branch busy): ${REL}" >&2
exit 0
