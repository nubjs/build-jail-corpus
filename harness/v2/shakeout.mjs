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
  T3_noState: (r) => (r.verdict === 'NO-STATE-PASSED' ? 'NO-STATE-PASSED' : null),
  T4_ladder: (r) => (r.verifiedBy === 'ladder' || /^ladder/.test(r.grantSource || '')
    ? `fell back to the ladder (verifiedBy=${r.verifiedBy}, grantSource=${r.grantSource})` : null),
  T5_provenance: (r) => {
    const p = r.provenance || {};
    const missing = [];
    if (!p.nubGitSha) missing.push('nubGitSha');
    if (!p.venue || p.venue === 'unknown') missing.push('venue');
    return missing.length ? `unattributable: missing ${missing.join(', ')}` : null;
  },
  T6_truncated: (r) => (r.grantSource === 'descended-incomplete' || r.verdict === 'UNPROVEN'
    ? `budget-truncated (grantSource=${r.grantSource}, verdict=${r.verdict})` : null),
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
      const at = spec.lastIndexOf('@');
      const p = path.join(recordsRoot, dir, spec.slice(0, at), spec.slice(at + 1), 'results.json');
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
