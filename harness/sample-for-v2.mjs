#!/usr/bin/env node
// Draw a UNIFORM RANDOM sample of v1 records to re-measure under v2.
//
// WHY THIS EXISTS, AND WHY IT IS NOT A ONE-LINER. Every v2 measurement so far has been drawn from
// the SUSPICIOUS tail — the `write:"disk"` population, the packages a ladder flagged, the ones a
// gate failed. That is the right way to find defects and the wrong way to estimate a RATE. Those
// samples cannot answer the question that actually gates re-running the corpus:
//
//     how often does a v1 record UNDER-grant, across records nobody had a reason to suspect?
//
// Under-granting is the only direction that breaks a real install (over-granting is safe, per the
// project's standing rule), so that rate — not the disagreement rate — is the decision.
//
// ⛔ THE SEED IS THE POINT, AND WITHOUT IT THIS SCRIPT IS WORSE THAN NOTHING. An unseeded sample can
// be re-rolled until it produces a comfortable answer, and nobody — including the person drawing it —
// can tell afterwards whether it was. So: the PRNG is seeded, the seed is printed with the sample,
// and re-running with the same seed reproduces the draw exactly. RECORD THE SEED WITH THE RESULT.
// If you re-draw, say so and say why; a second draw reported as a first is fabrication.
//
// ⛔ ALREADY-MEASURED RECORDS ARE EXCLUDED BY PACKAGE NAME, not by name@version, and not because
// they are uninteresting: they are NOT INDEPENDENT. Each was chosen because something looked wrong
// with it, so letting any version back in re-imports the exact selection bias this script removes.
// Excluding every version of a package one version of which was measured is the conservative choice.
//
// THE EXCLUSION COUNT LOOKS TOO BIG FOR THE LIST, AND IT IS NOT. ~30 names remove 265 linux records,
// which reads like a matching bug until you check the concentration: `hugo-extended` alone has 101
// versions in the corpus, `electron-chromedriver` 41, `dprint` 39, `@apollo/rover` 38 — four
// packages are 219 of the 265. Verified by direct count, not inferred.
//
//   usage: sample-for-v2.mjs [--runs records/runs] [--platform linux-x64] [--n 30] [--seed 20260806]
//          --all-platforms   draw n per platform
//          --verify          print the population size and the exclusion tally, then exit

import fs from 'node:fs';
import path from 'node:path';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const has = (f) => process.argv.includes(f);

const RUNS = arg('--runs', 'records/runs');
const N = Number(arg('--n', '30'));
const SEED = Number(arg('--seed', '20260806'));
const PLATFORMS = has('--all-platforms')
  ? ['linux-x64', 'darwin-arm64', 'win32-x64']
  : [arg('--platform', 'linux-x64')];

// Packages whose v2 answer is already known. Excluded so the sample estimates a rate over
// UNSUSPECTED records. Keep this list append-only and dated; shrinking it silently re-imports bias.
const ALREADY_MEASURED = new Set([
  // linux, from the egress-agreement batch and the convergence batch
  '@apollo/rover', 'jotai-devtools', 'use-mask-input', 'vanilla-cookieconsent', 'wordpos',
  'yorkie', '@progress/kendo-licensing', '@shoelace-style/shoelace', 'azure-streamanalytics-cicd',
  'docxtemplater', 'truffle', 'wrtc', '@tensorflow/tfjs-backend-wasm', 'codeceptjs',
  '@apollo/protobufjs',
  // win32, from batch3 and the ladder walks
  'husky', 'lefthook', 'electron-chromedriver', 'purescript', 'jpegtran-bin', 'dprint',
  'opencode-ai', 'redis-memory-server', 'hugo-extended',
  // the linux /proc residual — a named, already-understood mechanism
  '@nuxt/components', '@opencode-ai/cli', 'dotnet-2.0.0', 'iedriver',
  'postman-code-generators', 'react-native-purchases',
]);

/** mulberry32 — a small, well-behaved seeded PRNG. Deterministic across Node versions. */
const rng = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

for (const platform of PLATFORMS) {
  const root = path.join(RUNS, platform);
  if (!fs.existsSync(root)) {
    console.error(`no records at ${root}`);
    continue;
  }

  const pool = [];
  let seen = 0;
  let notMinimum = 0;
  let excluded = 0;
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        walk(p);
        continue;
      }
      if (e.name !== 'results.json') continue;
      let r;
      try {
        r = JSON.parse(fs.readFileSync(p, 'utf8'));
      } catch {
        continue; // a half-written record is not a sampling unit
      }
      seen++;
      // Only MINIMUM records carry a v1 verdict to disagree with. A HARNESS-* or TIMEOUT record
      // has no claim to check, so including it would dilute the denominator with non-answers.
      if (r.verdict !== 'MINIMUM') {
        notMinimum++;
        continue;
      }
      if (ALREADY_MEASURED.has(r.pkg)) {
        excluded++;
        continue;
      }
      pool.push(`${r.pkg}@${r.version}`);
    }
  })(root);

  // Sort before shuffling. Directory iteration order is not guaranteed stable across machines or
  // filesystems, so an unsorted pool would make the SEED reproduce a different draw elsewhere —
  // which quietly defeats the whole point of seeding it.
  pool.sort();

  // Fisher-Yates with the seeded PRNG, then take the first N.
  const rand = rng(SEED);
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  const draw = pool.slice(0, Math.min(N, pool.length));

  console.log(`# ${platform}: ${seen} records → ${pool.length} eligible (MINIMUM, not already v2-measured)`);
  console.log(`#   ${notMinimum} skipped: no MINIMUM verdict to disagree with`);
  console.log(`#   ${excluded} skipped: already v2-measured, so not independent`);
  console.log(`# SEED=${SEED}  n=${draw.length}  ⛔ RECORD THIS SEED WITH THE RESULT`);
  if (!has('--verify')) for (const s of draw) console.log(s);
  console.log();
}
