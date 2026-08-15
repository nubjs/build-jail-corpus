// Split a spec list into N lanes of roughly EQUAL WALL CLOCK, using each platform's own recorded
// per-package durations.
//
// ⛔ WHY COST AND NOT COUNT. A corpus slice's wall clock is dominated by a small native-build tail, not
// by the median: measured on win32 records, p50 is 45 s while p90 is 628 s and 11.89% exceed ten
// minutes. Splitting 1,706 rows into 4 equal-COUNT lanes therefore does NOT give four equal lanes — it
// gives whichever lane drew `duckdb`, `electron` and friends a multi-hour tail while the others idle.
// Measured live: one `duckdb@1.4.4` held a serial lane for 25+ minutes against a 4–49 s spread.
//
// ⛔ THE DURATIONS COME FROM THE RECORDS, PER PLATFORM, because the platforms are not interchangeable:
// win32's mean is 189 s against linux's 48 s, a 4× difference. Estimating one platform's shard cost
// from another's records is the same mistake as estimating a slow tail from fast samples, and this
// effort made both.
//
// A package with no prior record gets the platform's MEAN rather than zero — an unknown is far more
// likely to be ordinary than free, and treating it as free is what silently overloads a lane.
//
//   node shard-by-cost.mjs --specs <file> --platform win32-x64 --lanes 4 [--out-prefix shard]
//
// Prints the predicted wall clock per lane, so an unbalanced split is visible BEFORE the run rather
// than inferred from a lane that finished hours late.
import fs from 'node:fs';
import path from 'node:path';

/** Recorded duration in seconds for each `pkg@version` on one platform, from the record tree. */
export function durationsFor(runsRoot, platform, read = fs) {
  const out = new Map();
  const base = path.join(runsRoot, platform);
  if (!read.existsSync(base)) return out;
  for (const pkgDir of read.readdirSync(base)) {
    const pkgPath = path.join(base, pkgDir);
    let versions;
    try { versions = read.readdirSync(pkgPath); } catch { continue; }
    for (const v of versions) {
      const f = path.join(pkgPath, v, 'results.json');
      if (!read.existsSync(f)) continue;
      let r;
      try { r = JSON.parse(read.readFileSync(f, 'utf8')); } catch { continue; }
      const ms = ['durationMs', 'elapsedMs', 'wallMs', 'ms']
        .map((k) => r[k]).find((x) => typeof x === 'number') ?? r.timing?.totalMs;
      if (typeof ms !== 'number') continue;
      // The directory encodes `+` for `/` in a scoped name; the spec list uses `/`.
      out.set(`${pkgDir.replace('+', '/')}@${v}`, ms / 1000);
    }
  }
  return out;
}

/** Longest-processing-time-first: sort by descending cost, always place on the lightest lane.
 *
 *  ⛔ LPT, NOT ROUND-ROBIN. Round-robin over a cost-sorted list still clusters the heavy rows one per
 *  lane, which is fine, but it ignores the long tail beneath them and drifts. LPT is the standard 4/3
 *  approximation for exactly this problem and it is three lines. What matters more than the algorithm
 *  is that the HEAVY rows are placed FIRST — placing them last is what produces a lane that is 40
 *  minutes longer than every other, because by then there is nowhere cheap to put them.
 */
export function shard(specs, costs, lanes, fallback) {
  const weighted = specs.map((s) => ({ spec: s, cost: costs.get(s) ?? fallback }))
    .sort((a, b) => b.cost - a.cost);
  const out = Array.from({ length: lanes }, () => ({ specs: [], seconds: 0 }));
  for (const { spec, cost } of weighted) {
    const lightest = out.reduce((a, b) => (b.seconds < a.seconds ? b : a));
    lightest.specs.push(spec);
    lightest.seconds += cost;
  }
  return out;
}

if (import.meta.filename === process.argv[1]) {
  const argv = process.argv.slice(2);
  const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const specsFile = opt('--specs');
  const platform = opt('--platform');
  const lanes = Number(opt('--lanes', '4'));
  const prefix = opt('--out-prefix', 'shard');
  const runs = opt('--runs', path.join(import.meta.dirname, '..', '..', 'records-v2', 'runs'));
  if (!specsFile || !platform || !Number.isInteger(lanes) || lanes < 1) {
    process.stderr.write('usage: shard-by-cost.mjs --specs <file> --platform <plat> --lanes <n> '
      + '[--out-prefix shard] [--runs dir]\n');
    process.exit(2);
  }
  const specs = fs.readFileSync(specsFile, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  const costs = durationsFor(runs, platform);
  const known = specs.filter((s) => costs.has(s)).length;
  const values = [...costs.values()];
  const fallback = values.length ? values.reduce((a, b) => a + b, 0) / values.length : 60;
  const out = shard(specs, costs, lanes, fallback);

  process.stdout.write(`platform ${platform}: ${costs.size} recorded durations; `
    + `${known}/${specs.length} specs have one (unknown rows priced at the ${fallback.toFixed(0)}s mean)\n`);
  out.forEach((lane, i) => {
    const file = `${prefix}-${i + 1}.txt`;
    fs.writeFileSync(file, `${lane.specs.join('\n')}\n`);
    process.stdout.write(`  ${file}: ${String(lane.specs.length).padStart(5)} rows  `
      + `${(lane.seconds / 3600).toFixed(1).padStart(6)} h predicted\n`);
  });
  const hours = out.map((l) => l.seconds / 3600);
  const spread = Math.max(...hours) - Math.min(...hours);
  process.stdout.write(`  spread across lanes: ${spread.toFixed(2)} h `
    + `(serial would be ${hours.reduce((a, b) => a + b, 0).toFixed(1)} h)\n`);
}
