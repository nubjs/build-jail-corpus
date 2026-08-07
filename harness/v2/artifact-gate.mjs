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
      // ⛔ MANIFEST KEYS ARE FORWARD-SLASHED ON EVERY PLATFORM, AND THAT IS LOAD-BEARING RATHER THAN
      // TIDY. `path.relative` yields `build\config.gypi` on Windows, and every R4 exclusion pattern
      // below is written with `/` — so on Windows NONE of them matched and the gate billed
      // node-gyp's toolchain-invocation records as a shortfall, failing arms for a difference R4
      // exists to say is meaningless. `measure-windows.mjs` already normalises its own manifest the
      // same way; this file did not, so the two disagreed about the same tree.
      if (st.isDirectory()) walk(p); else m.set(path.relative(root, p).replace(/\\/g, '/'), st.size);
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
// ⛔ A TOOLCHAIN-INVOCATION RECORD IS NOT BUILD OUTPUT, AND COMPARING ITS SIZE ACROSS TWO PACKAGE
// MANAGERS ASKS A QUESTION THE ARTIFACT CANNOT ANSWER (PORTABILITY R4).
//
// These files are written by node-gyp/gyp to record WHO INVOKED THE BUILD and WHERE ITS INPUTS LIVED
// — not what the package produced. Both of those legitimately differ between the OBSERVE arm
// (`npm rebuild`, flat hoisted tree) and a jailed arm (`nub`, isolated store), so a size difference
// here carries no information about whether the build succeeded.
//
// ⛔ THIS REPLACES THE EARLIER "arm roots are equal length" THEORY, WHICH MEASUREMENT KILLED, and the
// old mechanism is retracted rather than quietly dropped: it predicted the JAILED file would be
// LARGER because its root is longer (58 chars vs 28), and the jailed `config.gypi` is SMALLER. Path
// length was never the mechanism. What is:
//
//   * `config.gypi` differs STRUCTURALLY — it is node-gyp's dump of the invoking PM's whole config
//     surface, so `npm rebuild` injects ~14 keys a jailed `nub` arm has no analogue for, plus
//     `user_agent: npm/10.9.3` vs `nub/0.6.0`. No root length adds or removes a key.
//   * `*.target.mk` and `Makefile` differ because `nodedir` differs in KIND (downloaded headers vs
//     the Node installation) and because the include path reflects hoisted-vs-isolated layout —
//     which is ENVIRONMENT that VENUE-PORTABILITY.md forbids normalising away.
//   * a `.d` holds nothing but the ABSOLUTE PATH of every header the compile pulled in, and node-gyp
//     unpacks headers into `/tmp/node-gyp-tmp-<random>`, so the same successful compile writes a
//     different-LENGTH file every run. (Formerly its own `/\.d$/` exemption; retired into this one
//     rule rather than kept as a parallel extension allowlist.)
//
// MEASURED on `lmdb-store@2.0.0-alpha2`, linux-x64, the case this rule exists for. Every arm from the
// synthesized `{"network":true}` up to `write:"disk"` reported `rc=0 artifacts=182/182` with the
// IDENTICAL shortfall digest `c61b7c0adbd6` — a shortfall invariant under widening cannot be a
// capability gap — and the package landed `ARTIFACT-GATE-SUSPECT` with its grant left UNVERIFIED:
//     build/config.gypi           18704B < 19199B
//     build/lmdb-store.target.mk   5565B <  5939B
// while `build/Release/lmdb-store.node` was BYTE-IDENTICAL at 429,328 B in both arms. `build/Makefile`
// also differs (13,847 vs 13,934) and is listed here for the same mechanism; today it happens to
// differ in the direction the gate ignores, which makes it a trap rather than a non-issue.
//
// ⛔ THE LIST IS EXACTLY WHAT MEASUREMENT JUSTIFIES, AND IT IS SCOPED TO `build/`, BECAUSE A TOO-WIDE
// GATE UNDER-GRANTS. The gate decides whether a REDUCED grant still installed; excusing a file that
// a denied write really did truncate lets a broken descent arm read as passing, and the catalog then
// publishes a grant SMALLER than the package needs — the one direction this project forbids. So
// `binding.Makefile` is deliberately absent: it was measured IDENTICAL (118 B in both arms), and an
// exclusion with no evidence behind it is exactly the widening this comment is warning about.
//
// ⛔ THE `.target.mk` PATTERN WAS NARROWER THAN R4'S OWN WORDING, AND THAT COST A FALSE VERDICT.
// R4 names `*.target.mk`; `build\/[^/]+\.target\.mk$` required the file DIRECTLY under `build/`. gyp
// emits a sub-target per vendored dependency at `build/deps/<lib>/<lib>.target.mk`, so every package
// that vendors anything — most real native builds — had its sub-targets size-compared. Widened to any
// depth, which is what the rule said in the first place.
//
// MEASURED on `cpu-features@0.0.10`, darwin-arm64: `rc=0`, all 156 artifacts PRESENT, verdict
// UNDER-PREDICTED on three files that were merely smaller —
//     build/deps/cpu_features/cpu_features.target.mk      6315B <  6553B
//     build/gyp-mac-tool                                 30502B < 30515B
//     build/Release/obj.target/cpufeatures/src/binding.o 314200B < 314288B
//
//   * `gyp-mac-tool` is written only by gyp's mac generator, which is why linux never surfaced it.
//   * an `.o` embeds the absolute path of its translation unit and of every header in its debug
//     info, so its size tracks path length exactly as a `.d` does. Excusing its SIZE is safe for a
//     reason worth stating: a denied write that truncated an object file fails the LINK, so the
//     `.node` is then absent — and absence is checked for every file, toolchain-generated included.
//     The linked output itself is never excused.
const TOOLCHAIN_GENERATED = [
  /(^|\/)build\/config\.gypi$/,
  /(^|\/)build\/Makefile$/,
  /(^|\/)build\/.*\.target\.mk$/,
  /(^|\/)build\/.*\.d$/,
  /(^|\/)build\/gyp-mac-tool$/,
  /(^|\/)build\/.*\.o$/,
];
const isToolchainGenerated = (f) => TOOLCHAIN_GENERATED.some((r) => r.test(f));
for (const [f, size] of got ? obs : []) {
  // ⛔ ABSENCE IS CHECKED FIRST AND FOR EVERY FILE, TOOLCHAIN-GENERATED INCLUDED. A generator
  // difference can change a file's CONTENTS; it can never fail to write the file at all.
  if (!got.has(f)) { missing.push(f); continue; }
  const armSize = got.get(f);
  // ⛔ ONLY THE "shorter than the reference but NON-EMPTY" COMPARISON IS DROPPED. A zero-byte file
  // against a non-empty reference falls through to the check below and still fails — that is the
  // download-blocked/truncated shape the gate exists to catch, and no generator difference and no
  // layout difference can produce it.
  if (isToolchainGenerated(f) && armSize > 0) continue;
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
