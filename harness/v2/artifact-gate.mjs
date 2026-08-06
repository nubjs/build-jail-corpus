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
// ⛔ THE GATE IS A SINGLE-ARM PREDICATE AND STAYS ONE. Whether a shortfall is grant-INDEPENDENT is a
// cross-arm question that only the driver can see, so the gate does not answer it and does not soften
// itself for it. What it adds is `shortfall=<digest>` — a stable identity for the shortfall, over the
// FULL missing list including the sizes, not the truncated display line and not the count. The driver
// compares those digests across arms. A count would be the wrong instrument: two arms each missing one
// DIFFERENT file both read `missing=1`, which is a varying shortfall reported as an invariant one.
//
//   usage: artifact-gate.mjs --obs <dir> --arm <dir> --pkg <name> --ver <version>
//   exit 0 = the arm reproduced OBSERVE; exit 1 = artifacts missing (named on stdout);
//   exit 3 = OBSERVE itself produced nothing for this package, so there is nothing to gate on.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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
// ⛔ A MAKE DEPENDENCY FILE IS SIZED BY WHERE ITS HEADERS LIVED, NOT BY WHETHER THE BUILD WORKED.
// A `.d` (node-gyp emits them as `<obj>.o.d`) contains nothing but the ABSOLUTE PATH of every header
// the compilation pulled in. node-gyp unpacks the Node headers into `/tmp/node-gyp-tmp-<random>`, so
// the same successful compile writes a different-LENGTH file on every run, and comparing sizes across
// arms asks a question the artifact cannot answer.
//
// MEASURED on `lmdb-store@2.0.0-alpha2`: all 16 of its flagged files were `.o.d`, each merely SHORT
// (`1528B < 1624B`, `12682B < 14305B`), while the arm reported `rc=0 artifacts=182/182` and
// `SOLINK_MODULE`/`COPY Release/lmdb-store.node` — the addon had compiled and linked. The package was
// nevertheless declared INSUFFICIENT at every grant INCLUDING the empty one, which is the tell: the
// identical shortfall digest across a grant range from `{}` upward cannot be a capability gap.
//
// TWO SIGNALS ARE DELIBERATELY KEPT. Presence: a `.d` that never appeared is a real shortfall. And
// EMPTINESS: a zero-byte `.d` against a non-empty reference is the download-blocked/truncated shape
// this gate exists to catch, and no path-length difference can produce it. Only the "shorter than
// reference but non-empty" comparison is dropped, and only for this extension.
const SIZE_VARIES_BY_PATH = /\.d$/;
for (const [f, size] of got ? obs : []) {
  if (!got.has(f)) { missing.push(f); continue; }
  const armSize = got.get(f);
  if (SIZE_VARIES_BY_PATH.test(f) && armSize > 0) continue;
  if (armSize < size) missing.push(`${f} (${armSize}B < ${size}B)`);
}
// Order the manifest walk produces is filesystem-dependent, so sort before digesting or two arms with
// the same shortfall can disagree on its identity.
const shortfall = missing.length
  ? crypto.createHash('sha1').update(missing.slice().sort().join('\n')).digest('hex').slice(0, 12)
  : 'none';
console.log(
  `artifacts=${got ? got.size : 'ABSENT'}/${obs.size} missing=${missing.length} shortfall=${shortfall}`,
);
if (missing.length) {
  console.log(`  missing: ${missing.slice(0, 6).join(', ')}${missing.length > 6 ? ` (+${missing.length - 6})` : ''}`);
  process.exit(1);
}
