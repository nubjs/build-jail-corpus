// Whether the run that produced this record was covered by a falsification control that proves the
// harness can DETECT a denied network — and, when it was not, which of the four escapes applied.
//
// ⛔⛔ THE FIELD EXISTS BECAUSE THE NETWORK AXIS FAILED OPEN AND NOTHING IN `results.json` SAID SO.
// A probe measured `playwright-chromium@0.17.0` at the empty grant, got rc=0 with 358 MB of Chromium
// downloaded, and recorded "this package needs no network". The catalog was the proximate cause
// (`target-catalogued.mjs`), but the reason it went unnoticed for a whole run is separate and is what
// this file addresses: the record could not say whether ANY control had established that a denied
// network is observable in that venue. Three routes get a record past the pre-flight in
// `run-batch-v2.mjs`, and NONE of them is visible downstream:
//
//   1. `--no-falsify`, which `corpus-v2-runner.yml` passes for a targeted re-measure;
//   2. a loud platform SKIP, when `falsify.mjs` has no case grounded on this platform;
//   3. invoking a driver DIRECTLY, outside `run-batch-v2.mjs` — which is what the probe did, and
//      which no gate in that file can ever see.
//
// ⛔⛔ SO THE DEFAULT RENDERS AS AN EXPLICIT NEGATIVE, NEVER AS ABSENCE, AND THAT IS THE WHOLE POINT
// OF THE FIELD. A missing value that reads as "fine" would rebuild the same hole one layer up: every
// record measured outside the batch runner would look exactly like a record the control covered.
// `null` is not available as an answer here. The same rule governs `record.mjs`, which substitutes a
// negative string when the marker is absent from the log entirely.
//
// Shaped like the era-node pin (`measure.sh`'s `ERA_STATUS`): a positive value carrying its detail,
// or a negative one carrying its reason in parentheses.
//
// ⛔ ONE MODULE, NOT THREE SPELLINGS. Two shell drivers and one JS driver cannot share a function but
// can share a process — the same argument `dep-scaffold.mjs` and `arm-prepare.mjs` record, with the
// same two occasions behind it. `arm-prepare.test.mjs` holds the cross-driver assertion.
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';

/** The env var `run-batch-v2.mjs` writes and every driver reads. */
export const NET_ENFORCEMENT_ENV = 'NUB_V2_NET_ENFORCEMENT';

/** The marker key. `record.mjs` parses on this exact token. */
export const NET_ENFORCEMENT_MARKER = 'VENUE-NET-ENFORCEMENT';

/**
 * The value the driver reports. THIS MODULE OWNS THE VALUE; THE DRIVERS OWN THE MARKER NAME.
 *
 * ⛔ THAT SPLIT IS NOT COSMETIC, AND GETTING IT WRONG COST A TEST FAILURE HERE.
 * `marker-contract.test.mjs` learns what a driver emits by scanning that driver's OWN source for an
 * `echo "  MARKER …"` / ``console.log(`  MARKER …`)`` emission site — deliberately, so that a marker
 * named only in a COMMENT cannot count as wired. A marker composed entirely inside a shared module
 * is invisible to that scan, and the guard then reports the field as one `record.mjs` parses and
 * nothing produces. So the literal token stays at each emission site where the scan can see it, and
 * only the VALUE — the part carrying the logic — lives here.
 *
 * ⛔ AN EMPTY OR WHITESPACE-ONLY VARIABLE IS TREATED AS UNSET, NOT AS A PASS. `sudo -E`, a CI matrix
 * that defines a variable without a value, and a shell that exports an empty string all produce the
 * same `''`, and an empty positive is the exact shape this field exists to refuse.
 *
 * ⛔ NEWLINES ARE FLATTENED HERE RATHER THAN AT THE CALL SITE, because `driver.out` is parsed
 * line-wise and a wrapped value would truncate the field at its first line in every record.
 */
export function netEnforcementValue(env = process.env) {
  const declared = (env[NET_ENFORCEMENT_ENV] ?? '').trim();
  const value = declared
    || `NOT-VERIFIED (${NET_ENFORCEMENT_ENV} is unset: this driver did not run under `
      + 'run-batch-v2.mjs, so no falsification control covered it)';
  return value.replace(/\s*\n\s*/g, ' ');
}

/**
 * The value `run-batch-v2.mjs` writes after its falsification pre-flight.
 *
 * ⛔ `ENFORCED` REQUIRES A CASE THAT REMOVED `network` AND PASSED — a green control is not enough.
 * `falsify.mjs` runs every case grounded on the platform, and on linux that includes `write.deps`
 * (`@apollo/rover`), which establishes nothing whatever about egress. Reporting the whole control's
 * verdict here would let a filesystem case vouch for the network axis, which is precisely the kind
 * of adjacent-artifact substitution that produced the finding this field reports on.
 */
export function netEnforcementFromFalsify(report, platform = process.platform) {
  const results = Array.isArray(report?.results) ? report.results : [];
  const net = results.filter((r) => r?.removed === 'network');
  if (!net.length) {
    return `NOT-VERIFIED (the falsification control ran ${results.length} case(s) on ${platform}, `
      + "none of which removes 'network', so the egress axis is unattested)";
  }
  const passed = net.filter((r) => r.verdict === 'PASS');
  if (!passed.length) {
    return `NOT-VERIFIED (the ${platform} network case(s) did not pass: `
      + `${net.map((r) => `${r.case}=${r.verdict}`).join(', ')})`;
  }
  const detail = passed
    .map((r) => `${r.pkg}@${r.version} refused at ${JSON.stringify(r.insufficient ?? {})}`)
    .join('; ');
  return `ENFORCED (falsify network case, ${detail})`;
}

// CLI for the two shell drivers: prints the VALUE alone, on one line, with no marker name and no
// indentation — the caller supplies both, per the split documented above.
//
// ⛔ `process.argv[1]` COMPARED BY REALPATH — on macOS `/tmp` is a symlink to `/private/tmp`, so a
// plain string compare silently skips this branch when the script is reached through one.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  console.log(netEnforcementValue());
}
