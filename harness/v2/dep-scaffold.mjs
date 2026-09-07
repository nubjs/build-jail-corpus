// Build the catalog override a verify arm runs under: the TARGET's rung, plus a fixed wide scaffold
// for every dependency that has a lifecycle script of its own.
//
// ⛔⛔ WHY THIS IS A SHARED MODULE AND NOT THREE COPIES. The dependency-scaffold fix landed in
// `measure.sh` on 2026-08-07 and was LINUX-ONLY for as long as it took to notice — `measure-macos.sh`
// and `measure-windows.mjs` kept the target-only construction, so the very defect it fixed stayed
// live on two of three platforms. That is the SECOND time a v2 fix reached one driver and was
// mistaken for landed (the first: the `T3` no-state tripwire, blind on macOS because that driver
// spells the verdict differently). The construction is pure JS over `package.json` files with
// nothing platform-specific in it, so three copies buy nothing and cost exactly this.
//
// ⛔ THE DEFECT IT FIXES. Granting only the target leaves any DEPENDENCY with its own lifecycle
// script running under the default deny. When that dependency fails, `approve-builds` returns
// non-zero at EVERY rung and the driver records `NO-STATE-PASSED` against the TARGET — a verdict
// about a package that was never the problem.
//
// MEASURED on `@hyperjump/json-schema@0.22.0`: target-only `{network:true}` rc=1 (`EAI_AGAIN`), and
// so did `{write:"disk",network:true}` and `{read:"disk",write:"disk",network:true}` — the widest
// grant the ladder can express. The SAME `{network:true}` applied to the target AND its three
// `@hyperjump/*` dependencies: rc=0. The failing `npm` belonged to `@hyperjump/json-schema-core`.
//
// ⛔ THE SCAFFOLD IS DELIBERATELY *NOT* THE RUNG. Giving dependencies the same grant as the target
// would make the DESCENT unable to attribute a capability: dropping `network` would fail because a
// DEP still needed it, so the target would keep a capability it never used — silently widening the
// published grant, the one direction this project forbids. A CONSTANT wide scaffold keeps the
// target's rung the only variable in the arm, which is what makes the arm a measurement at all.
//
// This over-grants the SCAFFOLDING only, and it cannot reach the catalog: `collate.mjs` publishes
// the grant recorded for the package under test, and every dependency is measured in its own run.
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

/** What a scaffolded dependency gets. Constant on purpose — see the note above. */
export const SCAFFOLD = { write: 'disk', network: true };

/** Every package in the observed tree that declares a lifecycle script, except the target. */
export function scriptBearingDeps(observeDir, target) {
  const nm = path.join(observeDir, 'node_modules');
  if (!fs.existsSync(nm)) return [];
  const manifests = [];
  for (const e of fs.readdirSync(nm, { withFileTypes: true })) {
    if (!e.isDirectory() || e.name === '.bin') continue;
    if (e.name.startsWith('@')) {
      for (const s of fs.readdirSync(path.join(nm, e.name), { withFileTypes: true })) {
        if (s.isDirectory()) manifests.push([`${e.name}/${s.name}`, path.join(nm, e.name, s.name, 'package.json')]);
      }
    } else manifests.push([e.name, path.join(nm, e.name, 'package.json')]);
  }
  const out = [];
  for (const [name, mf] of manifests) {
    if (name === target) continue;
    let sc;
    try { sc = JSON.parse(fs.readFileSync(mf, 'utf8')).scripts || {}; } catch { continue; }
    if (sc.install || sc.preinstall || sc.postinstall) out.push(name);
  }
  return out;
}

/**
 * The catalog object for one arm.
 *
 * ⛔⛔ THE TARGET IS ALWAYS WRITTEN, EVEN WHEN ITS GRANT IS EMPTY — and the version that omitted it
 * made every "needs nothing" answer UNFALSIFIABLE. The old rule read "an EMPTY grant is expressed by
 * OMITTING the target — the base profile already IS nothing". The second half stopped being true:
 * `catalog_v2::baseline_caps()` now returns `network: true` plus `write: {deps}`, because a package
 * published after a nub build is uncatalogued by construction and denying it does not converge.
 *
 * The two encodings therefore diverged, and nub is explicit that they mean opposite things — an
 * ABSENT package takes the baseline, while an entry's own value is used as-is and is deliberately NOT
 * unioned with it (`preset.rs::build_jail_net_allowed_for`, and the test
 * `an_empty_entry_grants_less_than_no_entry_at_all`). So omitting the target asked for the BASELINE,
 * which grants egress, exactly when the arm meant to grant nothing.
 *
 * MEASURED 2026-09-07, three packages on one unprivileged linux venue, each recorded MINIMUM/MINIMAL
 * `{"network":true}` by the previous instrument, each installing cleanly with the network term
 * dropped: hugo-extended@0.141.0 (12/12 artifacts), @sitespeed.io/chromedriver@100.0.4896-20 (5/5),
 * mozjpeg@6.0.1 (8/8). All three reported `OVER-PREDICTED by: no-network`; none logged a single
 * refusal. The pattern is exact: a case survives only while its residual grant is NON-EMPTY —
 * @apollo/rover keeps `{"network":true}` after dropping `write.deps` and is caught, and win32 mozjpeg
 * keeps `{"write":{...}}` after dropping `network` and is caught — so the defect hides wherever the
 * measured minimum is a SINGLE capability.
 *
 * ⛔ THE OTHER HALF OF THE OLD PREMISE IS ALSO STALE: nub no longer rejects an entry that widens
 * nothing. `catalog_v2.rs` says rejecting it "WAS A DEFECT", since an entry granting nothing is the
 * tightest grant there is and a high-value target deserves to be expressible. That rejection is what
 * the removed `__v2_empty_grant_sentinel__` existed to dodge; with the target always present the
 * catalog is never empty, so the sentinel could not fire and its absence changes no arm.
 */
export function buildCatalog(target, grant, observeDir) {
  const packages = {};
  for (const dep of scriptBearingDeps(observeDir, target)) packages[dep] = { default: SCAFFOLD };
  const scaffolded = Object.keys(packages).length;
  packages[target] = { default: grant };
  return { catalog: { packages }, scaffolded };
}

// CLI entry for the bash drivers: <armDir> <pkg> <grantJson> <observeDir>
// ⛔ `process.argv[1]` compared by REALPATH — on macOS `/tmp` is a symlink to `/private/tmp`, so a
// plain string compare silently skips the CLI branch when the script is reached through one.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const [armDir, target, grantJson, observeDir] = process.argv.slice(2);
  const { catalog, scaffolded } = buildCatalog(target, JSON.parse(grantJson), observeDir);
  fs.writeFileSync(path.join(armDir, 'cat.json'), JSON.stringify(catalog));
  if (scaffolded) console.log(`  scaffold: ${scaffolded} dependency package(s) with lifecycle scripts granted a fixed wide grant`);
}
