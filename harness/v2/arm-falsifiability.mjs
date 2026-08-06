// Could this package's arms have FAILED at all?
//
// ⛔ WHAT THIS EXISTS TO CATCH, AND IT IS A CLASS RATHER THAN A PACKAGE. `artifact-gate.mjs` passes an
// arm when every file OBSERVE produced under the package's own directory is present at >= its size.
// That is a real gate for a package whose script PRODUCES something. For a package that SHIPS its
// build output prebuilt, the manifest is the tarball's own file set — every file is present in every
// arm before any script runs — so the gate cannot distinguish a working arm from a broken one, and a
// green arm carries no evidence.
//
// MEASURED, and it is what motivated this file. `ttf2woff2@1.2.3` publishes 124 files including a
// working `build/Release/addon.node` and a 43-entry `build/Release/` tree. Its install script is
// `(node-gyp rebuild > builderror.log) || (exit 0)`. On the corpus runner node-gyp never even reached
// a compiler — 5 execs in the whole run, no python, no clang, no make — yet the arm reported
// `artifacts=122/122 missing=0` and the descent recorded a clean `{}`. BOTH signals were vacuous: the
// 122 artifacts are the shipped files, and `|| (exit 0)` guarantees `rc=0` whatever happens. The
// grant is substantively right; the MEASUREMENT proved nothing. It was found by hand, which is
// exactly why it needs to be mechanical — the next one gets no such attention.
//
// ⛔ FLAG, NEVER FAIL. These packages are still measurable and their grants are still usable. What
// they lose is the EVIDENCE VALUE of a green arm. A record that says "MINIMAL, and here is why that
// is weak" is worth more than a refused record, and far more than a vacuous arm recorded as a clean
// measurement — which is the shape that erodes trust in a whole corpus.
//
// Two independent discriminants; either one flags. They are independent on purpose: a package can
// swallow its exit code while still producing artifacts (gate meaningful, rc not), or produce nothing
// while reporting honestly (rc meaningful, gate not).
//
//   usage: arm-falsifiability.mjs --snapshot <dir> --pkg <name> --ver <v> --out <file>
//          arm-falsifiability.mjs --obs <dir> --pre <file> --pkg <name> --ver <v>
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
const PKG = val('--pkg'), VER = val('--ver');

// ⛔ THE SAME RESOLUTION `artifact-gate.mjs` USES, AND IT MUST STAY THE SAME. This file answers "could
// that gate have failed?", so if it looked at a different directory it would answer about a different
// gate. Kept as a copy rather than shared because the gate is the authority and a shared helper would
// let a change here silently redefine what the gate measures.
const slug = (PKG ?? '').replace(/\//g, '+');
const pkgDir = (base) => {
  for (const c of [
    path.join(base, 'node_modules', PKG),
    path.join(base, 'node_modules', '.store', `${slug}@${VER}`, 'node_modules', PKG),
    path.join(base, 'node_modules', '.store', `${PKG}@${VER}`, 'node_modules', PKG),
  ]) if (fs.existsSync(c)) return c;
  return null;
};

const isLog = (p) => /\.log$|cat\.json$|nub\.jsonc$|package-lock\.json$/.test(p);

// path -> size, relative to the package root. Mirrors the gate: follows symlinks, skips a nested
// `node_modules` (the other layout's dependency closure, never this package's artifacts).
const manifest = (base) => {
  const root = pkgDir(base);
  if (!root) return null;
  const out = new Map();
  const seen = new Set();
  const walk = (d) => {
    let rp; try { rp = fs.realpathSync(d); } catch { return; }
    if (seen.has(rp)) return; seen.add(rp);
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name === 'node_modules') continue;
      const full = path.join(d, e.name);
      let st; try { st = fs.statSync(full); } catch { continue; }
      if (st.isDirectory()) walk(full);
      else if (!isLog(full)) out.set(path.relative(root, full), st.size);
    }
  };
  walk(root);
  return out;
};

// ── snapshot mode: called BEFORE the lifecycle script runs ────────────────────────────────────
if (args.includes('--snapshot')) {
  const m = manifest(val('--snapshot'));
  fs.writeFileSync(val('--out'), JSON.stringify(m ? Object.fromEntries(m) : null));
  process.exit(0);
}

// ── report mode: called AFTER OBSERVE ─────────────────────────────────────────────────────────
const OBS = val('--obs');
const post = manifest(OBS);
let pre = null;
try { pre = JSON.parse(fs.readFileSync(val('--pre'), 'utf8')); } catch { /* absent = unknown */ }

const reasons = [];
let producedCount = null;

if (post && pre) {
  // ⛔ THE DISCRIMINANT IS "DID THE SCRIPT CHANGE ANY FILE THE GATE KEYS ON?", not "is the manifest a
  // subset of the tarball". A file that existed before and GREW is something the script produced, and
  // the gate's `>= size` comparison can genuinely fail on it. A file present before at its final size
  // cannot make the gate fail no matter what the arm does.
  const produced = [...post.entries()].filter(([p, sz]) => !(p in pre) || sz > pre[p]);
  producedCount = produced.length;
  if (produced.length === 0) {
    reasons.push('gate-vacuous: the script changed no file the artifact gate keys on — every file in '
      + `the manifest (${post.size}) was already present at its final size before the script ran, so `
      + 'the gate passes in every arm including a completely broken one');
  }
}

// The rc discriminant. Read from the package's own manifest rather than the trace: it is exact, and
// it is what npm will run.
let scripts = {};
try {
  const root = pkgDir(OBS);
  scripts = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts ?? {};
} catch { /* no package.json readable */ }
// ⛔ ANCHORED AT THE END, because a `|| true` in the MIDDLE of a chain does not swallow the script's
// final status — only a trailing one does. `cmd || true && other` still reports other's status.
// The trailing swallow, in every spelling seen in the wild. `(exit 0)` wraps the WHOLE construct in
// a subshell — `cmd || (exit 0)` — which the first version of this pattern missed because it only
// allowed a closing paren AFTER `exit 0`. Caught by running the detector against the very package it
// was written for and seeing one of its two discriminants stay silent.
const SWALLOWS = /(\|\||;)\s*\(?\s*(true|:|exit\s+0)\s*\)?\s*$/;
for (const k of ['preinstall', 'install', 'postinstall']) {
  const body = scripts[k];
  if (typeof body === 'string' && SWALLOWS.test(body.trim())) {
    reasons.push(`rc-vacuous: \`${k}\` ends in a status-swallowing construct (\`${body.trim()}\`), so `
      + 'its exit code is 0 whether the work succeeded or failed');
  }
}

console.log(`ARM-FALSIFIABILITY ${JSON.stringify({
  manifestFiles: post ? post.size : null,
  filesTheScriptProduced: producedCount,
  reasons: reasons.map((r) => r.split(':')[0]),
})}`);
if (reasons.length) {
  console.log('⛔ ARMS-UNFALSIFIABLE — a green arm for this package carries no evidence:');
  for (const r of reasons) console.log(`     ${r}`);
  console.log('     The grant may still be correct; what is missing is a signal that could have gone');
  console.log('     red. Do not read this record\'s MINIMAL as a passing measurement.');
}
