// Did this jailed arm reproduce what the unjailed OBSERVE arm produced?
//
// THE SHAPE IS PORTED FROM `measure-windows.mjs`, DELIBERATELY AND VERBATIM IN BEHAVIOUR, so the two
// drivers cannot disagree about what "the arm succeeded" means. That file's author measured and
// rejected the two cheaper gates; both rejections apply here unchanged:
//
//   * A WHOLE-TREE FILE COUNT is not comparable across the two layouts. npm's OBSERVE tree is flat
//     and local; nub's isolated layout puts every dependency behind a symlink into the machine-global
//     store, so the dependency bytes are not in the fixture at all. Following the links instead makes
//     the number depend on a shared, per-arm-evicted store — neither reproducible nor attributable.
//     MEASURED on Linux, `@apollo/rover@0.2.1`: a `{"network":true}` arm that produced NONE of the
//     package's artifacts still counted 704 files against a 718-file reference, so `files >= OBS_FILES`
//     passed it. That is the gate reporting a capability as droppable when it is not.
//   * A COUNT ALONE is too loose even when scoped. dprint@0.14.1 produced 10 artifact files under
//     both npm and the jail while the jailed tree held 6,306 B against npm's 11,071,650 B — the
//     download had been blocked and only the placeholder tree remained. Comparing the MANIFEST
//     catches that by NAME, with no threshold to tune.
//
// The gate: every file OBSERVE produced under the measured package's own directory must exist in the
// arm at >= its size. Extras are ignored — nub's layout legitimately adds `.nub-side-effects-cache`.
//
// ⛔ KNOWN AND DELIBERATE LIMIT, stated because it is exactly the case that motivated this file.
// The gate is scoped to the measured package's OWN directory, so it does NOT see an artifact the
// script wrote into a SIBLING package (`@apollo/rover` writes `node_modules/binary-install/bin/rover`).
// Widening it to the transitive set is what the Windows author rejected: under the isolated layout
// those artifacts are not at a fixed path relative to the fixture, so the check would be neither
// reproducible nor attributable. The sibling case is closed by the TRANSITIVE STORE EVICTION in
// `measure.sh` instead — with the dependency's entry evicted the write is actually attempted and the
// arm fails honestly on `rc`. The two mechanisms are complementary and neither subsumes the other.
//
//   usage: artifact-gate.mjs --obs <dir> --arm <dir> --pkg <name> --ver <version>
//   exit 0 = the arm reproduced OBSERVE; exit 1 = artifacts missing (named on stdout);
//   exit 3 = OBSERVE itself produced nothing for this package, so there is nothing to gate on.
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const OBS = val('--obs'), ARM = val('--arm'), PKG = val('--pkg'), VER = val('--ver');
if (!OBS || !ARM || !PKG || !VER) {
  console.error('usage: artifact-gate.mjs --obs <dir> --arm <dir> --pkg <name> --ver <version>');
  process.exit(2);
}

const isLog = (p) => /\.log$|cat\.json$|nub\.jsonc$|package-lock\.json$/.test(p);

// Files that ship inside the published tarball and that NO lifecycle script writes. See the long
// note at the walk for why excluding them is sound and why `.npmrc` is deliberately absent.
const PACKAGING_METADATA = new Set([
  '.npmignore',
  '.gitignore',
  '.gitattributes',
  '.editorconfig',
  '.DS_Store',
]);

// Where the measured package lives, in either layout. `<base>/node_modules/<pkg>` covers npm's flat
// OBSERVE tree AND nub's global-virtual-store layout, where that entry is a SYMLINK into
// `$cache/nub/pm/store/<slug>@<ver>-<hash>/node_modules/<pkg>`; the project-local `.store` variant is
// the other root aube materializes into (`PROJECT_VIRTUAL_STORE_LEAF` in `preset.rs`).
const slug = PKG.replace(/\//g, '+');
const pkgDir = (base) => {
  for (const c of [
    path.join(base, 'node_modules', PKG),
    path.join(base, 'node_modules', '.store', `${slug}@${VER}`, 'node_modules', PKG),
    path.join(base, 'node_modules', '.store', `${PKG}@${VER}`, 'node_modules', PKG),
  ]) if (fs.existsSync(c)) return c;
  return null;
};

// Follows symlinks (statSync, not lstat) and de-dupes by realpath so a self-referential link cannot
// spin. Returns null when the package is absent — an absent package is a FAILED arm, never a passing
// one.
const manifest = (base) => {
  const root = pkgDir(base);
  if (!root) return null;
  const seen = new Set();
  const m = new Map();
  const walk = (d) => {
    let rp; try { rp = fs.realpathSync(d); } catch { return; }
    if (seen.has(rp)) return; seen.add(rp);
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      // ⛔ A NESTED `node_modules` IS THE OTHER LAYOUT'S DEPENDENCY CLOSURE, NOT THIS PACKAGE'S
      // ARTIFACTS, AND WALKING INTO IT MANUFACTURES A FALSE UNDER-PREDICTION. npm parks a private
      // copy of any dependency it could not hoist INSIDE the package directory; nub's isolated
      // layout puts the same dependencies in the store as SIBLINGS of the package's store entry,
      // reachable only through symlinks. So the same install produces wildly different trees under
      // one root, and the difference is layout, never the grant.
      //
      // MEASURED on `jotai-devtools@0.5.1`: the package's own directory holds 13,206 files, of
      // which 13,181 (118 MB) are the nested `node_modules` and exactly 25 are the package. The
      // gate reported `artifacts=26/13206 missing=13181` and the driver walked the whole ladder to
      // `NO-STATE-PASSED` — for a package that verifies at `{"network":true}`.
      //
      // Skipping it restores the invariant the gate is built on: the ONE universe both layouts
      // genuinely share is the measured package's own files. Its dependencies' artifacts are out of
      // scope here by the same reasoning that put the transitive set out of scope on Windows.
      if (e.name === 'node_modules') continue;
      // ⛔ PACKAGING METADATA IS NOT AN ARTIFACT, AND COUNTING IT MANUFACTURES A FALSE FAILURE.
      // These files ship inside the published tarball; NO lifecycle script writes one. So a
      // missing entry here can never be caused by a denied write — it is a layout difference
      // between npm's extraction and nub's store materialisation, and nothing else.
      //
      // MEASURED on `truffle@5.11.5`: rc=0 on EVERY rung including the synthesized
      // `{"network":true}`, and all four rungs were failed by this gate on the same single file,
      // `test/.npmignore`. The driver reported NO-STATE-PASSED for a package that almost certainly
      // verifies at `{"network":true}` and agrees with its v1 record.
      //
      // ⛔ `.npmrc` IS DELIBERATELY ABSENT FROM THIS LIST. It is a credential-bearing file the jail
      // reasons about explicitly, so it must stay visible to the manifest even though it is also
      // packaging-adjacent — excluding it would blind the gate to exactly the file class this
      // project exists to protect.
      if (PACKAGING_METADATA.has(e.name)) continue;
      const p = path.join(d, e.name);
      if (isLog(p)) continue;
      let st; try { st = fs.statSync(p); } catch { continue; }
      if (st.isDirectory()) walk(p); else m.set(path.relative(root, p), st.size);
    }
  };
  walk(root);
  m.root = root;
  return m;
};

const obs = manifest(OBS);
if (!obs || obs.size === 0) {
  console.log(`NO-REFERENCE ${PKG}@${VER} produced no files under ${OBS} — cannot gate`);
  process.exit(3);
}
const got = manifest(ARM);
const missing = [];
if (!got) missing.push('<package absent>');
else for (const [f, size] of obs) {
  if (!got.has(f)) missing.push(f);
  else if (got.get(f) < size) missing.push(`${f} (${got.get(f)}B < ${size}B)`);
}
console.log(`artifacts=${got ? got.size : 'ABSENT'}/${obs.size} missing=${missing.length}`);
if (missing.length) {
  console.log(`  missing: ${missing.slice(0, 6).join(', ')}${missing.length > 6 ? ` (+${missing.length - 6})` : ''}`);
  process.exit(1);
}
