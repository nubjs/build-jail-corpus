// Where gyp writes an INCLUDED `.gyp` file's makefiles, and why that place is not the same place in
// npm's hoisted tree and nub's isolated store.
//
// ⛔⛔ THIS IS A PATH DEFECT IN THE MANIFEST WALK, NOT AN EXCUSAL, AND THE DIFFERENCE IS THE WHOLE
// POINT. The files this module locates were reported ABSENT — 243 entries across 161 gate-failure
// lines in the archived corpus, every one an absence and not one a size difference. An absence is
// exactly what `excusesSizeDifference` refuses to touch, because a denied write is how an absence is
// normally produced. These absences are produced by ARITHMETIC instead, so the repair is to look in
// the right place rather than to stop looking.
//
// THE MECHANISM, MEASURED rather than read out of gyp:
//
//   `node-addon-api`'s `index.js` hands its consumer `path.relative('.', __dirname)` — a path
//   relative to the CWD of the `node -p` that asks, which is the package being built. Node resolves
//   `__dirname` through symlinks, so that string is the REALPATH of the dependency:
//
//     npm, flat hoisted      ../node-addon-api
//     nub, isolated store    ../../../node-addon-api@7.1.1-213592cd5b5ab75e/node_modules/node-addon-api
//
//   gyp then writes the sub-target's `<gyp>.Makefile` and `<target>.target.mk` at
//   `<generatorOutput>/<that relative path>`, with `<generatorOutput>` = `<pkgRoot>/<buildDir>`. The
//   relative path opens with `..`, so the join eats exactly ONE level of the build directory and the
//   answer lands one level SHALLOWER than the dependency itself — a phantom directory holding nothing
//   but the generated makefiles, in both layouts:
//
//     npm    node_modules/node-pty/node-addon-api/node_addon_api.target.mk
//     nub    <store>/node-pty@1.1.0-<h>/node-addon-api@7.1.1-<g>/node_modules/node-addon-api/…
//
//   MEASURED on `node-pty@1.1.0` + `node-addon-api@7.1.1`, darwin-arm64, by running `node-gyp
//   configure` in both layouts: four files each, identical names, and the nub arm's copies are LARGER
//   (3583B vs 3355B, …) because the paths they embed are longer.
//
//   Under npm the phantom is INSIDE the measured package, so `artifact-gate.mjs` walks it and the
//   reference manifest carries `node-addon-api/node_addon_api.target.mk`. Under nub it is TWO levels
//   ABOVE the package root, and the walk — which starts at the root and only descends — can never
//   reach it. rc=0, the file exists, the gate calls it missing.
//
// ⛔ THE ANSWER DOES NOT DEPEND ON THE BUILD DIRECTORY'S NAME, and that is worth stating because the
// neighbouring excusal list had to learn it the expensive way. `build/..` and node-pre-gyp's
// `build-tmp-napi-v3/..` both collapse to the package root, so this module never names a build dir.
//
// ⛔ IT ADDS TO THE ARM MANIFEST AND SUBTRACTS NOTHING. A key it cannot resolve stays missing and
// stays NAMED, so a genuinely absent sub-target still fails the gate exactly as before.
import fs from 'node:fs';
import path from 'node:path';

/**
 * The two files gyp's make generator emits per included `.gyp` file. Deliberately narrow: this
 * module only ever ADDS keys to a manifest, so the conservative choice is the one that adds fewest.
 */
export const isGypSubtargetFile = (basename) => /\.target\.mk$/.test(basename) || /\.Makefile$/.test(basename);

/**
 * The `node_modules` directory that holds the measured package, or null when it is not one.
 *
 * ⛔ THE ARGUMENT IS THE REALPATH, AND A SYNTHETIC FIXTURE WILL NOT TELL YOU WHY. In a real nub tree
 * `pkgDir` resolves the package to `<project>/node_modules/<pkg>`, which is a SYMLINK into the store;
 * `..` from THERE is the project's own `node_modules`, holding only the project's direct dependencies.
 * `node-addon-api` is not among them, so the search finds nothing and the defect survives its fix.
 * Following the link first lands on `<store>/<pkg>@<ver>-<h>/node_modules`, where the dependency's
 * symlink actually lives. MEASURED against a real `nub install node-pty@1.1.0` on darwin-arm64:
 * off the symlink path this returned zero keys, off the realpath it returns the four.
 */
const depsDir = (rootReal, pkg) => {
  const up = pkg.includes('/') ? ['..', '..'] : ['..'];
  const d = path.resolve(rootReal, ...up);
  return path.basename(d) === 'node_modules' ? d : null;
};

/** Every installed sibling of the measured package, scoped names included, as package names. */
const siblingNames = (nm, pkg) => {
  const out = [];
  let ents;
  try { ents = fs.readdirSync(nm, { withFileTypes: true }); } catch { return out; }
  for (const e of ents) {
    if (e.name.startsWith('.')) continue;
    if (!e.isDirectory() && !e.isSymbolicLink()) continue;
    if (!e.name.startsWith('@')) { if (e.name !== pkg) out.push(e.name); continue; }
    let inner;
    try { inner = fs.readdirSync(path.join(nm, e.name), { withFileTypes: true }); } catch { continue; }
    for (const i of inner) {
      if (i.name.startsWith('.')) continue;
      const n = `${e.name}/${i.name}`;
      if (n !== pkg) out.push(n);
    }
  }
  return out;
};

/**
 * The gyp sub-target makefiles that this arm wrote OUTSIDE the measured package's own directory,
 * keyed the way the reference manifest keys them: `<depName>/<path under the phantom>`.
 *
 * ⛔ THE KEY IS THE DEPENDENCY NAME, NOT THE PHANTOM'S PATH, and that is what makes the two layouts
 * comparable at all. npm's phantom IS `<root>/<depName>`, so the reference key already reads
 * `node-addon-api/node_addon_api.target.mk`; nub's phantom ends in `…/<depName>` after a store slug
 * no other layout has. Naming the dependency is the one thing both agree on.
 *
 * Recursive, because `node-addon-api` 8.x moved its `.gyp` into `src/` and the corpus carries both
 * shapes — 185 sightings at `node-addon-api/<file>` and 58 at `node-addon-api/src/<file>`.
 *
 * @param root the measured package's own directory, as `pkgDir` resolved it
 * @param pkg the measured package's name
 * @returns Map of manifest key -> size, empty when nothing spilled
 */
export const gypSubtargetSpill = (root, pkg) => {
  const m = new Map();
  let rootReal;
  try { rootReal = fs.realpathSync(root); } catch { return m; }
  const nm = depsDir(rootReal, pkg);
  if (!nm) return m;
  const inRoot = (p) => p === rootReal || p.startsWith(rootReal + path.sep);

  for (const dep of siblingNames(nm, pkg)) {
    let depReal;
    try { depReal = fs.realpathSync(path.join(nm, ...dep.split('/'))); } catch { continue; }
    const parts = path.relative(rootReal, depReal).split(path.sep);
    // A dependency the walk can already reach — nested under the package, or the package itself.
    // `..` is what makes the join eat a level of the build directory; without it there is no spill.
    if (parts[0] !== '..') continue;
    const spill = path.resolve(rootReal, parts.slice(1).join(path.sep));
    // Already walked: npm's flat layout always lands the phantom inside the package.
    if (inRoot(spill)) continue;
    // ⛔ NEVER INDEX THE DEPENDENCY'S REAL DIRECTORY. It cannot happen under the arithmetic above —
    // the phantom is always one level shallower — but if it ever did, a `.Makefile` that SHIPS in the
    // dependency's tarball would silently satisfy a reference key the build never wrote.
    if (spill === depReal) continue;

    const seen = new Set();
    const walk = (d, prefix) => {
      let rp;
      try { rp = fs.realpathSync(d); } catch { return; }
      if (seen.has(rp)) return;
      seen.add(rp);
      let ents;
      try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
      for (const e of ents) {
        const p = path.join(d, e.name);
        let st;
        try { st = fs.statSync(p); } catch { continue; }
        if (st.isDirectory()) { walk(p, `${prefix}${e.name}/`); continue; }
        if (!isGypSubtargetFile(e.name)) continue;
        const key = `${dep}/${prefix}${e.name}`;
        if (!m.has(key)) m.set(key, st.size);
      }
    };
    walk(spill, '');
  }
  return m;
};
