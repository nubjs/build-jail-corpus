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

// ───────────────────────────────────────────────────────────────────────────────────────────────
// THE SECOND, LARGER FAMILY: the same arithmetic, displaced INSIDE `build/` instead of escaping it.
//
// The walk above finds the files that leave the package root. It does NOT find the ones that stay
// inside `build/` at a DIFFERENT path, and those are the bigger half of the corpus's shortfall —
// 37 of the 41 archived records that name a `node-addon-api` spill carry this shape.
//
// MEASURED with a real `node-gyp@11 rebuild` on `drivelist@12.0.2` + `node-addon-api@8.9.2`,
// darwin-arm64, in a real `npm install` tree and a real `nub install` store tree. The generated
// `nothing.target.mk` is IDENTICAL in shape in both arms; only one substring differs:
//
//     OBJS := $(obj).target/$(TARGET)/../node-addon-api/nothing.o                         (npm)
//     OBJS := $(obj).target/$(TARGET)/../../../node-addon-api@8.9.2-c7cd…/node_modules/…  (nub)
//
// and `make` echoed exactly that, un-normalised, as it compiled:
//
//     CC(target) Release/obj.target/nothing/../node-addon-api/nothing.o                         (npm)
//     CC(target) Release/obj.target/nothing/../../../node-addon-api@8.9.2-c7cd…/…/nothing.o     (nub)
//
// ⛔ SO THE COMPONENT COUNT DOES NOT ACTUALLY VARY PER FAMILY, AND BELIEVING IT DOES IS WHAT MAKES
// THIS LOOK LIKE IT NEEDS GYP'S ARITHMETIC RE-DERIVED PER OUTPUT KIND. Every one of these paths has
// the one shape
//
//     <fixed prefix, decided by the output kind> / <relDep> / <tail>
//
// where `<relDep>` is the string `node-addon-api/index.js` handed over — `path.relative('.',
// __dirname)`, resolved through symlinks — and the ONLY layout-dependent quantity is `k`, its count
// of leading `..`: 1 under npm's flat hoist, 3 under nub's isolated store. `k` is a property of the
// LAYOUT and is the same for every family. What varies is the fixed prefix's DEPTH, which decides
// how much of it survives being eaten and therefore where the file comes to rest — measured, all
// four kinds, one package, one build:
//
//   kind            fixed prefix under `build/`                      npm (k=1)                                    nub (k=3)
//   makefiles       (none — `--generator-output build` is the root)  ../node-addon-api           => pkgRoot        2 levels ABOVE pkgRoot
//   object          Release/obj.target/$(TARGET)          depth 3    Release/obj.target/…        => inside build/  build/  (prefix exactly consumed)
//   dep record      Release/.deps/Release/obj.target/$(TARGET) d. 5  Release/.deps/Release/…     => inside build/  build/Release/.deps/
//   static lib      $(builddir) on mac, $(obj).target on linux       no `..` on mac              => no spill at all
//
// ⛔ THE CONSEQUENCE IS THE WHOLE REPAIR: the reference key and the arm path differ by ONE number,
// `Δk = k_arm − k_ref`, and that number is a property of the (package, dependency) PAIR rather than
// of the output kind. Δk was 2 for all three spilling kinds above. So the arm's location is
// recoverable from the reference key without knowing the fixed prefix at all — take the reference
// key, find the dependency's own path components in it, drop Δk components from what precedes them
// (walking above the package root when there are not enough), and splice the ARM's components back
// in. Verified against all four kinds, including the static library, which this predicts is NOT a
// spill on mac and which is indeed byte-present in both arms.
//
// ⛔ AND IT IS RECOVERABLE ONLY FROM THE REFERENCE SIDE, WHICH IS WHY THIS IS A SECOND FUNCTION AND
// NOT A WIDER WALK. The eaten components are GONE from the arm path — `build/node-addon-api@…/…`
// carries no trace of the `Release/obj.target/nothing` it consumed — so no amount of walking the arm
// reconstructs the key. The reference manifest is the only place that prefix still exists. That
// makes this pass ASYMMETRIC (it probes the arm using the reference's keys) where the walk above is
// symmetric, and it is why the two coexist rather than one replacing the other.
//
// ⛔ IT ADDS NOTHING THE REFERENCE DID NOT ALREADY DEMAND. Every key it can produce is a key already
// in the reference manifest and already MISSING from the arm, and it produces one only when a real
// file is at the computed path. A key it cannot resolve stays missing and stays NAMED, and the size
// comparison downstream is untouched — a zero-byte relocated file still fails exactly as before.

/** The leading `..` run and the descent that follows it, for a path relative to the package root. */
const split = (rel) => {
  const parts = rel.split(path.sep);
  let k = 0;
  while (k < parts.length && parts[k] === '..') k++;
  return { k, descent: parts.slice(k) };
};

/** Where each installed sibling really lives, relative to the package root, in one tree. */
const depRels = (root, pkg) => {
  const out = new Map();
  let rootReal;
  try { rootReal = fs.realpathSync(root); } catch { return out; }
  const nm = depsDir(rootReal, pkg);
  if (!nm) return out;
  for (const dep of siblingNames(nm, pkg)) {
    let depReal;
    try { depReal = fs.realpathSync(path.join(nm, ...dep.split('/'))); } catch { continue; }
    out.set(dep, { ...split(path.relative(rootReal, depReal)), depReal, rootReal });
  }
  return out;
};

/** Does `parts` contain `run` as a contiguous slice? Returns its start index, or -1. */
const indexOfRun = (parts, run) => {
  outer: for (let i = 0; i + run.length <= parts.length; i++) {
    for (let j = 0; j < run.length; j++) if (parts[i + j] !== run[j]) continue outer;
    return i;
  }
  return -1;
};

/**
 * Reference keys the arm DID produce, at the place this layout's gyp arithmetic put them.
 *
 * @param obs the reference manifest, carrying `.root` (the OBSERVE package directory)
 * @param arm the arm manifest, carrying `.root`
 * @param pkg the measured package's name
 * @returns Map of reference manifest key -> the size found in the arm, empty when nothing relocated
 */
export const gypSubtargetRelocations = (obs, arm, pkg) => {
  const found = new Map();
  if (!obs || !arm || !obs.root || !arm.root) return found;
  const refs = depRels(obs.root, pkg);
  const arms = depRels(arm.root, pkg);
  if (refs.size === 0 || arms.size === 0) return found;

  // Only the keys the arm is actually short of — a key it already has needs no relocation, and
  // probing one could only ever overwrite a real measurement with a coincidence.
  const wanted = [];
  for (const k of obs.keys()) if (!arm.has(k)) wanted.push(k);
  if (wanted.length === 0) return found;

  for (const [dep, r] of refs) {
    const a = arms.get(dep);
    if (!a) continue;
    const delta = a.k - r.k;
    // Δk ≤ 0: the arm ate no more than the reference did. Either the paths already agree, or the
    // arm kept components the reference lost — which is not recoverable from either side, so the
    // key stays missing rather than being guessed at.
    if (delta <= 0) continue;

    for (const key of wanted) {
      if (found.has(key)) continue;
      const parts = key.split('/');
      const at = indexOfRun(parts, r.descent);
      if (at < 0) continue;
      const base = parts.slice(0, at);
      const tail = parts.slice(at + r.descent.length);
      const up = delta - base.length;
      const kept = up > 0 ? [] : base.slice(0, base.length - delta);
      const abs = path.resolve(a.rootReal, ...(up > 0 ? Array(up).fill('..') : []), ...kept, ...a.descent, ...tail);
      // ⛔ NEVER INDEX THE DEPENDENCY'S OWN REAL DIRECTORY, WHERE A FILE THAT SHIPS IN THE TARBALL
      // WOULD SILENTLY SATISFY A KEY THE BUILD NEVER WROTE. It is reachable: when the reference
      // tree resolves the dependency to a path INSIDE the measured package — an npm `file:` or
      // workspace link, where the sibling entry in `node_modules` points back into the package —
      // the reference ate no components at all, and the arm's Δk then lands this computation
      // squarely on the dependency itself. Pinned by its own case in the test file.
      if (abs === a.depReal || abs.startsWith(a.depReal + path.sep)) continue;
      let st;
      try { st = fs.statSync(abs); } catch { continue; }
      if (!st.isFile()) continue;
      found.set(key, st.size);
    }
  }
  return found;
};
