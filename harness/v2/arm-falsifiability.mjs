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
import { INSTALL_SCRIPTS } from './observed-effect.mjs';

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
// ⛔ THE DECLARES HALF RIDES HERE BECAUSE THIS IS THE ONLY STAGE THAT ALREADY READS THE INSTALLED
// TREE ON ALL THREE PLATFORMS. `observed-effect.mjs` has to tell "the script did nothing" from "npm
// ran nothing", and the second is a property of the manifest npm actually wrote — never of
// `npm view`, whose `scripts` come from the DEVELOPMENT package.json and are routinely stripped
// before packing. Adding a fourth copy of that probe is how the three drivers' inline copies would
// come to disagree; adding a field to a payload every driver already emits and `record.mjs` already
// parses costs one line at each end.
let declares = null;
try {
  const root = pkgDir(OBS);
  scripts = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).scripts ?? {};
  const named = INSTALL_SCRIPTS.filter((k) => typeof scripts[k] === 'string' && scripts[k].trim() !== '');
  // `binding.gyp` counts even with no explicit script: npm runs `node-gyp rebuild` for a package
  // that ships one, so the native builds would otherwise be scored as "runs nothing".
  declares = named.length > 0 || fs.existsSync(path.join(root, 'binding.gyp'));
} catch { /* no package.json readable — `declares` stays null, which scores as UNKNOWN */ }
// ⛔ ANCHORED AT THE END, because a `|| true` in the MIDDLE of a chain does not swallow the script's
// final status — only a trailing one does. `cmd || true && other` still reports other's status.
// The trailing swallow, in every spelling seen in the wild. `(exit 0)` wraps the WHOLE construct in
// a subshell — `cmd || (exit 0)` — which the first version of this pattern missed because it only
// allowed a closing paren AFTER `exit 0`. Caught by running the detector against the very package it
// was written for and seeing one of its two discriminants stay silent.
// ⛔⛔ `echo` AND `printf` ARE SWALLOWS TOO, AND MISSING THEM COST A RECORD ITS ONLY HONEST FLAG.
// MEASURED 2026-09-01: `backport@12.0.4`'s postinstall is
// `test -f ./dist/src/scripts/run-postinstall.js && node ./dist/… || echo 'Dist folder missing'`.
// `echo` cannot fail, so the script's exit code is 0 whether the work happened or not — but the
// alternation was `true|:|exit 0`, so the package was flagged `gate-vacuous` ALONE and `record.mjs`
// computed `rcLive === true` for a package whose rc cannot be non-zero. Verified against the
// `ttf2woff2@1.2.3` positive control, which still matches.
//
// ⛔ THE LIST IS COMMANDS THAT CANNOT FAIL, NOT "ANYTHING AFTER `||`". `cmd || node fallback.js` is a
// real fallback whose own status is reported, so treating every trailing `||` as a swallow would flag
// honest scripts and withhold correct narrowings — the blanket-refusal mistake this harness has
// already paid for once. Anything added here has to be a command with no failing path.
const SWALLOWS = /(\|\||;)\s*\(?\s*(true|:|exit\s+0|echo(\s[^|;&]*)?|printf(\s[^|;&]*)?)\s*\)?\s*$/;
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
  declaresInstallWork: declares,
})}`);
if (reasons.length) {
  // ⛔⛔ SAY WHICH DETECTOR DIED, BECAUSE THE TWO ARE INDEPENDENT AND THE BLANKET SENTENCE IS FALSE
  // FOR THE COMMON CASE.
  //
  // `gate-vacuous` kills the artifact gate; `rc-vacuous` kills the exit code. A package flagged
  // `gate-vacuous` ALONE still has rc as a live detector — `publish-guard.mjs` says so in its own
  // header and acts on it with a three-term rule, justified by a measured pair
  // (`playwright-chromium@0.17.0`, gate-vacuous with both drop arms rc=1, is real evidence;
  // `@pulumi/gcp@0.16.9`, gate-vacuous with ZERO drop arms, is not).
  //
  // MEASURED 2026-08-31 across the valid corpus: 1,099 records carry this note and 1,030 of them are
  // `gate-vacuous` ALONE. Telling all 1,099 that a green arm "carries no evidence" is wrong for 94%
  // of them, and it cost two separate audit passes that each set out to find the defect it implies.
  // The note is deliberately still emitted for both cases — `record.mjs` keys on the
  // `ARMS-UNFALSIFIABLE` token to keep the WIDER grant, which is the safe direction for a jail — but
  // the prose now matches what was actually lost.
  const rcDead = reasons.some((r) => r.startsWith('rc-vacuous'));
  console.log(`⛔ ARMS-UNFALSIFIABLE — ${rcDead
    ? 'a green arm for this package carries no evidence:'
    : 'the artifact gate carries no signal for this package:'}`);
  for (const r of reasons) console.log(`     ${r}`);
  if (rcDead) {
    console.log('     The grant may still be correct; what is missing is a signal that could have gone');
    console.log('     red. Do not read this record\'s MINIMAL as a passing measurement.');
  } else {
    console.log('     The EXIT CODE is still a live detector here, so a descent arm that actually');
    console.log('     FAILED is evidence. What is missing is the gate, not every signal — do not read');
    console.log('     a green arm as proof on its own, and do not read this note as "no evidence".');
  }
}
