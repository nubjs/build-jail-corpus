// Randomized shakeout: draw random package sets, then judge the resulting records against explicit
// tripwires. A bug-FINDING instrument, not a progress bar.
//
//   node shakeout.mjs draw  --os linux --sets 10 --per-set 10 --seed 20260807 --out round1.json
//   node shakeout.mjs judge --manifest round1.json --records records-v2/runs
//
// ⛔ WHY RANDOM AND NOT HAND-PICKED. Every list I would choose is a list of packages I already have
// a theory about, so a hand-picked sweep confirms what I already believe. The defects that have
// actually cost this project time — an msys PATH separator, a POSIX temp path, a URL-to-path
// conversion — all lived in packages nobody had a reason to single out.
//
// ⛔ WHY DRAW AND JUDGE ARE SEPARATE COMMANDS. The manifest (seed + exact spec list) is written
// BEFORE anything runs. A tripwire that cannot be re-run is not a finding, and a draw regenerated
// after the fact is not the draw that produced the result.
import fs from 'node:fs';
import path from 'node:path';

const RECORD_DIR = { linux: 'linux-x64', macos: 'darwin-arm64', windows: 'win32-x64' };

// ⛔ A SCOPED SPEC IS NOT ITS OWN PATH. `@sitespeed.io/chromedriver@84.0.4147-30` lives at
// `@sitespeed.io+chromedriver/84.0.4147-30/` — the scope slash becomes `+`, so the record is one
// directory deep, not two. MEASURED on shakeout round 1: the first version of this reader used the
// spec verbatim and reported 4 of 10 specs "not measured" while the batch log said 10 recorded.
// The mismatch was visible only because the run printed its own count; a reader that under-finds
// records makes a DIRTY round look INCOMPLETE and an incomplete one look clean.
export const recordPath = (spec) => {
  const at = spec.lastIndexOf('@');
  return [spec.slice(0, at).replace('/', '+'), spec.slice(at + 1)];
};

// mulberry32 — small, seedable, and good enough for choosing packages. `Math.random()` would make
// the manifest a record of nothing.
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const flag = (n, d) => {
  const i = process.argv.indexOf(n);
  return i > -1 ? process.argv[i + 1] : d;
};

function draw() {
  const os = flag('--os');
  const sets = Number(flag('--sets', '10'));
  const perSet = Number(flag('--per-set', '10'));
  const seed = Number(flag('--seed'));
  const queue = flag('--queue', 'queue-v2.ndjson');
  const out = flag('--out');
  if (!os || !Number.isFinite(seed) || !out) {
    console.error('usage: shakeout.mjs draw --os <linux|macos|windows> --seed <int> --out <file> [--sets 10] [--per-set 10]');
    process.exit(2);
  }
  const rows = fs.readFileSync(queue, 'utf8').trim().split('\n').map((l) => JSON.parse(l))
    .filter((r) => r.os === os && r.status === 'pending');
  if (rows.length < sets * perSet) {
    console.error(`⛔ only ${rows.length} pending rows for ${os}; need ${sets * perSet}`);
    process.exit(1);
  }
  // Fisher-Yates over a COPY, so the queue file is never reordered on disk.
  const pool = rows.slice();
  const rand = rng(seed);
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  const manifest = {
    os, seed, sets, perSet, drawnFrom: rows.length,
    set: Array.from({ length: sets }, (_, s) =>
      pool.slice(s * perSet, (s + 1) * perSet).map((r) => `${r.pkg}@${r.version}`)),
  };
  fs.writeFileSync(out, JSON.stringify(manifest, null, 2));
  console.log(`drew ${sets}x${perSet} = ${sets * perSet} specs for ${os} from ${rows.length} pending (seed ${seed}) -> ${out}`);
  for (const [i, s] of manifest.set.entries()) console.log(`  set ${i + 1}: ${s.join(' ')}`);
}

// ── the tripwires ────────────────────────────────────────────────────────────
// Each returns a reason string when it FIRES, else null. Exported so the test can drive them
// against a known-dirty record — an evaluator nobody has seen fire is not an evaluator.
export const TRIPWIRES = {
  T1_harness: (r) => (/^HARNESS-/.test(r.verdict || '') ? `verdict ${r.verdict}` : null),
  T2_disk: (r) => {
    const g = r.grant;
    if (!g || typeof g !== 'object') return null;
    const hits = [];
    if (g.write === 'disk') hits.push('write:"disk"');
    if (g.read === 'disk') hits.push('read:"disk"');
    return hits.length ? hits.join(' + ') : null;
  },
  // ⛔⛔ TWO SPELLINGS, ONE PHENOMENON — AND MATCHING ONLY ONE MADE THIS TRIPWIRE BLIND ON AN ENTIRE
  // PLATFORM. `measure.sh` and `measure-windows.mjs` print `=> NO-STATE-PASSED even at write:disk`;
  // `measure-macos.sh:1230` prints `=> UNDER-PREDICTED — no state passed, up to and including
  // write:"disk"` for the IDENTICAL condition (every rung failed AND the shortfall responded to the
  // grant).
  //
  // MEASURED 2026-08-07 across the published corpus, and the split is total: linux 12
  // NO-STATE-PASSED / 0 UNDER-PREDICTED, darwin 0 / 17. So a macOS round could never report T3 and
  // would have read CLEAN on exactly the packages Linux reports DIRTY — an unearned pass, which is
  // worse than no check at all.
  //
  // Matched here rather than renamed in either driver: the recorded verdict is what the published
  // records already carry, and rewriting that vocabulary mid-corpus would invalidate them.
  T3_noState: (r) => (r.verdict === 'NO-STATE-PASSED' || r.verdict === 'UNDER-PREDICTED'
    ? `${r.verdict} (no state passed even at write:"disk")` : null),
  T4_ladder: (r) => (r.verifiedBy === 'ladder' || /^ladder/.test(r.grantSource || '')
    ? `fell back to the ladder (verifiedBy=${r.verifiedBy}, grantSource=${r.grantSource})` : null),
  // ⛔ ATTRIBUTABLE MEANS "I CAN TELL WHICH BINARY PRODUCED THIS", NOT "one specific field is set".
  // The first version demanded `nubGitSha` and flagged 6 of 10 records in shakeout round 1 — but
  // those records carry `nubBinary.sha256`, a hash of the exact bytes that ran, which pins the
  // binary MORE precisely than a git sha does (a git sha does not tell you what was compiled from
  // it). `nubGitSha` is null there for a good reason: the binary was copied onto the box, so there
  // is no checkout to ask. Either identifier satisfies this; neither is the real defect.
  T5_provenance: (r) => {
    const p = r.provenance || {};
    const id = p.nubGitSha || p.nubBinary?.sha256;
    if (!id) return 'unattributable: no nubGitSha and no nubBinary.sha256 — cannot tell which binary ran';
    // Venue is a SEPARATE, weaker question (which machine class), and it is a known gap tracked as
    // task 2.8. Kept as a tripwire because an unknown venue makes a cross-venue comparison unsound,
    // but reported distinctly so it is never confused with "we do not know what binary ran".
    if (!p.venue || p.venue === 'unknown') return 'venue is unknown — set NUB_CORPUS_VENUE on the runner';
    return null;
  },
  T6_truncated: (r) => (r.grantSource === 'descended-incomplete' || r.verdict === 'UNPROVEN'
    ? `budget-truncated (grantSource=${r.grantSource}, verdict=${r.verdict})` : null),
  // ⛔ A CONFIRMED REPLAY MEANS THE ARM MEASURED NOTHING. The lifecycle script was restored from the
  // side-effects cache instead of running, so the grant it "verified" was never exercised. Distinct
  // from `replay-suspected`, which the heuristic predicates emit and which has false-fired in
  // production — only the confirmed form is a finding.
  T8_replay: (r) => ((r.notes || []).includes('replay-confirmed')
    ? 'replay-confirmed — the script was restored from cache, so this arm measured nothing' : null),
  T7_rc: (r) => {
    const rc = r.driverRc;
    // 0 fine; 124 is the timeout the budget imposes and T6 already names it; anything else is unknown.
    return rc !== undefined && rc !== null && rc !== 0 && rc !== 124 ? `driverRc=${rc}` : null;
  },
};

function judge() {
  const manifestPath = flag('--manifest');
  const recordsRoot = flag('--records', 'records-v2/runs');
  if (!manifestPath) { console.error('usage: shakeout.mjs judge --manifest <file> [--records dir]'); process.exit(2); }
  const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const dir = RECORD_DIR[m.os];

  let dirtySets = 0, totalMissing = 0;
  const allFindings = [];
  for (const [i, specs] of m.set.entries()) {
    const findings = [];
    let missing = 0;
    for (const spec of specs) {
      const p = path.join(recordsRoot, dir, ...recordPath(spec), 'results.json');
      if (!fs.existsSync(p)) { missing++; continue; }
      let r; try { r = JSON.parse(fs.readFileSync(p, 'utf8')); }
      catch (e) { findings.push(`${spec}: UNPARSEABLE results.json (${e.message})`); continue; }
      for (const [name, fn] of Object.entries(TRIPWIRES)) {
        const why = fn(r);
        if (why) findings.push(`${spec}: ${name} — ${why}`);
      }
    }
    totalMissing += missing;
    const dirty = findings.length > 0;
    if (dirty) dirtySets++;
    console.log(`set ${String(i + 1).padStart(2)}: ${dirty ? 'DIRTY' : 'clean'}  ${specs.length - missing}/${specs.length} measured${findings.length ? '' : ''}`);
    for (const f of findings) console.log(`    ${f}`);
    allFindings.push(...findings);
  }
  console.log(`\n${m.os} seed ${m.seed}: ${m.sets - dirtySets}/${m.sets} sets clean, ${allFindings.length} tripwire hit(s), ${totalMissing} spec(s) not measured`);
  // ⛔ Unmeasured specs are NOT clean. A round that silently measured half its draw would otherwise
  // report a perfect score, which is the vacuous green this whole phase exists to avoid.
  if (totalMissing) console.log(`⛔ ${totalMissing} spec(s) produced no record — the round is INCOMPLETE, not clean.`);
  process.exit(allFindings.length || totalMissing ? 1 : 0);
}

const cmd = process.argv[2];
if (cmd === 'draw') draw();
else if (cmd === 'judge') judge();
else if (cmd) { console.error(`unknown command: ${cmd}`); process.exit(2); }
