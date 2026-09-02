// A driver-time check that this harness tree is internally coherent about which epoch it is.
//
// ⛔⛔ WHAT THIS CATCHES, AND — MORE IMPORTANTLY — WHAT IT CANNOT. `instrument.json`'s `harnessEpoch`
// and `invalidation.json`'s `currentEpoch` are two numbers in two files that must agree.
// `queue-settled.test.mjs` already asserts it, but a TEST only runs when someone runs the suite, and
// the failure this exists for happens when nobody does: a driver invoked standalone, on a tree
// assembled by hand.
//
// MEASURED 2026-09-01. A probe shipped its harness with `git archive origin/main harness` while the
// corpus, its records and its policy were 2,904 commits further on, and measured
// `playwright-chromium@0.17.0` at the empty grant as needing no network. The harness it ran was
// epoch 3; the lane was at 81.
//
// ⛔ AND THAT EXACT CASE IS NOT DETECTABLE FROM INSIDE, WHICH THIS FILE STATES RATHER THAN PRETENDS
// OTHERWISE. `origin/main` was epoch 3 in BOTH files, so it was perfectly self-consistent — an old
// harness knows its own epoch and cannot know that a newer one exists. Nothing shipped inside a stale
// tree can diagnose its own staleness; only merging the current harness to `main` cures that, and the
// real defence against the measurement error itself is `target-catalogued.mjs`, which asserts the
// invariant rather than the version.
//
// What this DOES catch is the adjacent and more common shape: a MIXED tree, where the code came from
// one revision and `instrument.json` / `invalidation.json` from another. That is the ordinary outcome
// of copying `harness/` around, and it presents as an epoch disagreement — at which point
// `instrumentCompatibility` refuses every record with "invalidation policy does not name the current
// harness epoch", which in a slice log reads as the entire corpus having gone stale rather than as
// the tree being wrong.
//
// ⛔ NO DIGEST HERE, DELIBERATELY. Hashing the tree would also flag an ordinary uncommitted harness
// edit and an in-flight epoch bump, both of which are normal and neither of which is a reason to
// refuse to measure. `record.mjs` already binds each record to a computed identity, which is where
// that question belongs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** `{ ok, marker }` — `marker` is the single line a driver prints either way. */
export function instrumentSelfCheck(dir = HERE) {
  const read = (name) => {
    try { return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8')); }
    catch (error) { return { __error: `${name}: ${error.message}` }; }
  };
  const instrument = read('instrument.json');
  const policy = read('invalidation.json');
  const broken = instrument.__error ?? policy.__error;
  if (broken) {
    return { ok: false, marker: `HARNESS-INSTRUMENT INCOHERENT (${broken})` };
  }
  if (instrument.harnessEpoch !== policy.currentEpoch) {
    return {
      ok: false,
      marker: `HARNESS-INSTRUMENT INCOHERENT (instrument.json says epoch ${instrument.harnessEpoch}, `
        + `invalidation.json says currentEpoch ${policy.currentEpoch} — this harness tree is MIXED, `
        + 'so every record it produces would read as stale)',
    };
  }
  return { ok: true, marker: `HARNESS-INSTRUMENT epoch=${instrument.harnessEpoch}` };
}

// CLI for the two shell drivers. Exit 0 = coherent, exit 1 = refuse to measure.
//
// ⛔ `process.argv[1]` COMPARED BY REALPATH — on macOS `/tmp` is a symlink to `/private/tmp`, so a
// plain string compare silently skips this branch when the script is reached through one.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const { ok, marker } = instrumentSelfCheck();
  console.log(`  ${marker}`);
  process.exit(ok ? 0 : 1);
}
