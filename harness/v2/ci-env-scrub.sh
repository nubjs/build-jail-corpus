# shellcheck shell=bash
# THE CI-DETECTION SCRUB, shared by the two POSIX drivers. `measure-windows.mjs` carries the same key
# list in JS; `ci-env-scrub.test.mjs` asserts the three stay identical, because a family that drifts
# apart per-driver is the defect class this file exists to end.
#
# ⛔ A PACKAGE THAT BRANCHES ON `CI` RUNS LESS CODE ON A RUNNER, SO A CI-MEASURED RECORD OMITS
# CAPABILITIES A DEVELOPER HITS. That is an under-grant, the one direction this project forbids. The
# v1 harness has scrubbed this family since its own sweeps (`tests/build-jail-search/search.mjs`);
# v2 did not, so every v2 record measured on a runner carried the defect.
#
# MEASURED, `node:22-slim` and again on the corpus VM: `core-js@3.50.0` writes
# `$TMPDIR/core-js-banners` with `CI` unset and writes NOTHING with `CI=1`. A runner-measured record
# would never see that write.
#
# ⛔ THE CITED PACKAGE MATTERS AND v1's COMMENT NAMED THE WRONG ONES. v1 justified this scrub with
# husky, puppeteer and cypress. VERIFIED STALE: husky has not read `CI` since v5 (checked 5.0.0
# through 9.1.7, which ships no lifecycle scripts at all), puppeteer never did, and cypress only
# forces colour. The guard is right; its stated evidence was not, and a comment whose examples are
# false is how a correct guard gets deleted by someone later. `core-js` is the demonstrated case.
#
# ⛔ SCRUBBED, NEVER FORCED TO A VALUE. MEASURED: the value semantics are inconsistent across
# packages — `ci-info` reads `CI=0` as CI-ON while `core-js` reads it as CI-OFF. No value means "not
# CI" to everyone. Only ABSENCE does.
#
# ⛔ SCRUBBED FROM THE DRIVER'S OWN ENVIRONMENT, so OBSERVE and VERIFY inherit the SAME answer.
# Scrubbing one arm only would break the parity contract that says the two arms differ in exactly one
# variable — enforcement — and would do it in a way that reads as a package behaviour difference.
#
# ⛔ THE AXIS STAYS MEASURABLE, which is what separates this from the normalisation
# VENUE-PORTABILITY.md forbids. `NUB_CORPUS_CI_ENV=inherit` disables the scrub and measures the real
# CI path; that is the CI row of the acceptance test, and the two results UNION rather than one
# replacing the other. A one-line `CI=1` would instead HIDE the axis and leave one state unmeasured.
#
# ⛔ NOT A MODEL FOR WHAT NUB SHOULD DO. Nub must NOT set `CI` for lifecycle scripts: that modifies
# dependency behaviour rather than adding to it, no package manager does it, and Yarn's
# `enableImmutableInstalls` defaults to `isCI`, so a script running a nested `yarn install` would
# hard-fail under nub and succeed under npm on identical inputs. This is a MEASUREMENT apparatus
# choice — the harness normalising its own instrument so it observes the developer path.
# See `wiki/research/ci-env-var-for-lifecycle-scripts.md`.

# The v1 list, verbatim (`search.mjs`), so the two harnesses cannot disagree about what "CI" means.
CI_KEYS="CI CONTINUOUS_INTEGRATION BUILD_NUMBER RUN_ID GITHUB_ACTIONS GITLAB_CI CIRCLECI TRAVIS
         JENKINS_URL TEAMCITY_VERSION BUILDKITE DRONE APPVEYOR CODEBUILD_BUILD_ID TF_BUILD"

# Captured BEFORE the scrub. `passedThrough` in the record must report what the VENUE actually had,
# not what this driver left behind — otherwise a real CI run files `CI: null`, claiming the venue was
# not CI precisely because we removed the proof.
CI_INHERITED="$(for k in $CI_KEYS; do
  eval "v=\${$k:-}"; [ -n "${v:-}" ] && printf '%s=%s\n' "$k" "$v"
done)"

CI_SCRUBBED=""
if [ "${NUB_CORPUS_CI_ENV:-unset}" = inherit ]; then
  echo "  CI-ENV inherit — the CI-detection family is NOT scrubbed (measuring the real CI path)"
else
  for k in $CI_KEYS; do
    eval "v=\${$k:-}"
    if [ -n "${v:-}" ]; then unset "$k"; CI_SCRUBBED="$CI_SCRUBBED $k"; fi
  done
  [ -n "$CI_SCRUBBED" ] && echo "  CI-ENV scrubbed:$CI_SCRUBBED"
fi
