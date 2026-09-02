// Assert that the package under test is actually PRESENT in the catalog its arm is about to run
// under, and say so on a marker line whether it is or not.
//
// ⛔⛔ THE HOLE THIS CLOSES PRODUCED AN UNDER-GRANT, WHICH IS THE ONE DIRECTION THIS CORPUS MAY NOT
// ERR IN. An arm whose target is missing from `cat.json` is not measuring a narrow grant — it is
// measuring the BASELINE. `catalog_override.rs::v2_grant_for` is `packages.get(package)?`, so an
// absent package yields `None`, and `catalog_v2::baseline_caps()` returns `network: true`. The arm
// therefore runs with egress PERMITTED, the install succeeds, and the driver records the narrow
// grant as SUFFICIENT — "this package needs no network", which licenses removing a permission real
// users' installs depend on.
//
// MEASURED 2026-09-01. `dep-scaffold.mjs` used to build the empty rung by OMITTING the target:
//
//     if (Object.keys(grant).length) packages[target] = { default: grant };
//     if (!Object.keys(packages).length) packages.__v2_empty_grant_sentinel__ = { default: { network: true } };
//
// A probe shipping that construction (`git archive origin/main harness`, harnessEpoch 3) measured
// `playwright-chromium@0.17.0` at the empty grant: rc=0, 358 MB of Chromium downloaded, scored
// SUFFICIENT. Only the EMPTY grant diverges — at any non-empty grant the two constructions are
// byte-identical, which is why this stayed invisible for as long as it did.
//
// ⛔ AND THE EXISTING `OVERRIDDEN >= 1 && REJECTED == 0` GATE IS PROVABLY INSUFFICIENT AGAINST IT.
// That gate asks whether the override ENGAGED, not whether it engaged FOR THE PACKAGE UNDER TEST.
// The sentinel entry above is a real catalog entry, so nub prints its `catalog OVERRIDDEN from …`
// banner, `ovr` counts 1, `rej` counts 0, and the arm reads green while the subject of the whole
// experiment is absent from the document. A gate that cannot distinguish "the instrument engaged"
// from "the instrument engaged on the thing being measured" is not a gate on the measurement.
//
// ⛔ SHARED MODULE, NOT THREE COPIES — see `dep-scaffold.mjs`'s header for the two occasions a v2
// fix landed in `measure.sh` alone and was mistaken for done. `arm-prepare.test.mjs` carries the
// cross-driver assertion that all three actually call this.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Is `target` catalogued in the document at `catPath`?
 *
 * ⛔ IT READS THE FILE BACK RATHER THAN INSPECTING THE OBJECT THE BUILDER RETURNED. The arm runs
 * against the BYTES on disk — `NUB_BUILD_JAIL_CATALOG` names a path — so a builder that got it right
 * and a write that got it wrong (a truncated file, a stale copy from a previous arm, a `--at-catalog`
 * file nobody here constructed) are the same failure to the arm and must be the same failure here.
 * Asserting on the in-memory object would only re-check the code that just ran.
 */
export function targetCatalogued(catPath, target) {
  let text;
  try { text = fs.readFileSync(catPath, 'utf8'); }
  catch (error) { return { present: false, why: `cannot read ${path.basename(catPath)}: ${error.code ?? error.message}` }; }
  let doc;
  try { doc = JSON.parse(text); }
  catch (error) { return { present: false, why: `${path.basename(catPath)} is not JSON: ${error.message}` }; }
  const packages = doc?.packages;
  if (!packages || typeof packages !== 'object' || Array.isArray(packages)) {
    return { present: false, why: `${path.basename(catPath)} has no 'packages' object` };
  }
  if (!Object.prototype.hasOwnProperty.call(packages, target)) {
    return { present: false, why: `no 'packages.${target}' entry, so the arm runs at the BASELINE` };
  }
  const entry = packages[target];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { present: false, why: `'packages.${target}' is not an entry object` };
  }
  // ⛔ AN ENTRY WITH NEITHER KEY IS ABSENCE WEARING A KEY'S CLOTHING — `v2_grant_for` resolves
  // through `default`/`versions` and finds nothing, so the arm lands on the baseline exactly as if
  // the name had never appeared. `{ "default": {} }` is NOT this case and must pass: an empty
  // `default` is the deliberate spelling of the zero rung (`catalog_v2.rs:807` — "an empty `default`
  // says latest passes ungranted"), and it is the modal answer across this corpus.
  if (entry.default === undefined && entry.versions === undefined) {
    return { present: false, why: `'packages.${target}' has neither 'default' nor 'versions', so the arm runs at the BASELINE` };
  }
  return { present: true, why: null };
}

/**
 * The marker line a driver prints. ONE LINE, because `driver.out` is parsed line-wise.
 *
 * ⛔ THE TWO VALUES ARE `yes` AND `no(…)`, AND `no` MEANS VOID EVERYWHERE, WITHOUT EXCEPTION. A
 * conditional VOID would put the mode into the reader's head instead of the marker's text, which is
 * how a gate becomes advisory.
 *
 * ⛔ `--at-catalog` GETS ITS OWN VALUE RATHER THAN BORROWING EITHER. In that mode the FILE is the
 * hypothesis and an absent target is a legitimate answer, not a defect: `collate.mjs` deliberately
 * emits no entry for a package that needs nothing ("A package needing NOTHING at every measured
 * version earns no entry at all"), so an absent target there means the arm is measuring what an
 * uncatalogued package genuinely ships. Reporting that as `no` would VOID a correct arm; reporting
 * it as `yes` would be a lie. It is neither, and it never reads as a pass.
 */
export function targetCataloguedMarker({ present, why }, { atCatalog = false } = {}) {
  if (atCatalog) return `TARGET-CATALOGUED=at-catalog(${present ? 'present' : `absent: ${why}`})`;
  return present ? 'TARGET-CATALOGUED=yes' : `TARGET-CATALOGUED=no(${why})`;
}

// CLI for the two shell drivers: <catPath> <target> [--at-catalog]
//
// Exit 0 = the arm may proceed. Exit 1 = the arm is VOID. `--at-catalog` always exits 0, per the
// note above; it still prints its own explicit value so a reader can never mistake the mode for a
// pass or for an absent check.
//
// ⛔ `process.argv[1]` COMPARED BY REALPATH — on macOS `/tmp` is a symlink to `/private/tmp`, so a
// plain string compare silently skips this branch when the script is reached through one. Same trap,
// same spelling, as `dep-scaffold.mjs`.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const [catPath, target] = process.argv.slice(2);
  const atCatalog = process.argv.includes('--at-catalog');
  if (!catPath || !target) {
    console.error('usage: target-catalogued.mjs <cat.json> <package> [--at-catalog]');
    process.exit(2);
  }
  const result = targetCatalogued(catPath, target);
  console.log(`  ${targetCataloguedMarker(result, { atCatalog })}`);
  process.exit(atCatalog || result.present ? 0 : 1);
}
