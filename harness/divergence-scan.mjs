#!/usr/bin/env node
/**
 * Find packages whose measured grant DISAGREES across operating systems.
 *
 * ⛔ WHY THIS EXISTS. The same package, same version, same nub, same script cannot genuinely need
 * whole-disk write on one OS and nothing on another. When it does, one of the platforms is producing
 * a WRONG ANSWER, and a wrong answer that is wider than the truth ships a jail that confines nothing
 * for that package. Divergence is the cheapest available detector for that class, because it needs no
 * ground truth — the platforms check each other.
 *
 * ⛔ AND WHY IT RANKS RATHER THAN LISTS. Most divergences do not matter. A package measuring
 * `(nothing)` on one OS and `read.project` on another is a rounding error: both are tight, neither
 * ships a hole, and chasing it costs more than it returns. What matters is a divergence that WIDENS —
 * `write:"disk"` here versus `{network}` there — because the wide side is what the collator unions
 * into the shipped catalog. So findings are ranked by how far apart the two grants are on the
 * containment ladder, and the output leads with the ones that actually cost security.
 *
 *   SEVERITY 3  disk vs non-disk        — the wide side confines nothing; on Windows it takes no
 *                                         sandbox at all. THIS is the bucket worth investigating.
 *   SEVERITY 2  userHome vs narrower    — real widening, worth a look
 *   SEVERITY 1  narrow vs narrow / none — noise unless it clusters; do not spend a day here
 *
 * ⛔ KEEP PERSPECTIVE — the maintainer's standing instruction, and it is easy to lose while staring
 * at a divergence list. A harness bug that causes a SMALL OVERGRANT on a handful of packages is not
 * a reason to discard a corpus that took ~30 h of runner time. Over-granting is the SAFE direction:
 * it breaks nothing, it only fails to confine. Re-run the whole corpus only for a defect that makes
 * measurements WRONG AT SCALE or in the UNSAFE direction (under-granting, which would break real
 * installs). Everything else is a targeted re-measure of the affected packages via the workflow's
 * `packages` debug input, which costs minutes.
 *
 * Usage:
 *   node harness/divergence-scan.mjs [--runs records] [--min-severity 1] [--json]
 */
import fs from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const arg = (name, dflt) => {
  const i = argv.indexOf(name);
  return i === -1 ? dflt : argv[i + 1];
};
const RUNS = arg('--runs', 'records');
const MIN_SEV = Number(arg('--min-severity', '1'));
const AS_JSON = argv.includes('--json');

const KNOWN = new Set(['--runs', '--min-severity', '--json']);
{
  const bad = argv.filter((a, i) => a.startsWith('--') && !KNOWN.has(a) && argv[i - 1] !== '--runs' && argv[i - 1] !== '--min-severity');
  if (bad.length) {
    console.error(`unknown argument(s): ${bad.join(' ')}`);
    console.error('usage: divergence-scan.mjs [--runs <dir>] [--min-severity <n>] [--json]');
    process.exit(2);
  }
}

const rows = [];
(function walk(d) {
  let entries;
  try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(d, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name === 'results.json') {
      try { const r = JSON.parse(fs.readFileSync(p, 'utf8')); r.__p = p; rows.push(r); } catch {}
    }
  }
})(RUNS);

const osOf = (r) => {
  const p = r.provenance?.platform ?? '';
  if (p.startsWith('darwin')) return 'macos';
  if (p.startsWith('linux')) return 'linux';
  if (p.startsWith('win')) return 'windows';
  return null;
};
/** name@version from the PATH, which is authoritative — the record has no reliable name field. */
const keyOf = (r) => {
  const m = /records?[/\\]runs[/\\][^/\\]+[/\\](.+)[/\\]([^/\\]+)[/\\]results\.json$/.exec(r.__p.replace(/\\/g, '/'));
  return m ? `${m[1].replace('+', '/')}@${m[2]}` : null;
};

/** How far a grant sits up the containment ladder. Only ORDER matters, not the numbers. */
function reach(g) {
  if (!g || !Object.keys(g).filter((k) => k !== 'notes' && k !== 'platforms').length) return 0;
  if (g.write === 'disk') return 4;
  if (g.read === 'disk') return 3;
  if (g.write?.userHome) return 2;
  return 1; // any other narrow fs scope, or network-only
}
const show = (g) => (g && Object.keys(g).filter((k) => k !== 'notes').length ? JSON.stringify(g) : '(nothing)');

const by = new Map();
for (const r of rows) {
  if (r.verdict !== 'MINIMUM') continue;      // only real measurements can disagree meaningfully
  const os = osOf(r);
  const k = keyOf(r);
  if (!os || !k) continue;
  if (!by.has(k)) by.set(k, {});
  by.get(k)[os] = {
    grant: r.grant ?? null,
    cells: Array.isArray(r.cells) ? r.cells.length : null,
    nub: r.provenance?.nubGitSha ?? null,
    node: r.provenance?.nodeSelection?.chosenMajor ?? null,
  };
}

const findings = [];
let comparable = 0;
for (const [k, v] of by) {
  const present = Object.entries(v);
  if (present.length < 2) continue;
  comparable++;
  const reaches = present.map(([, d]) => reach(d.grant));
  const severity = Math.max(...reaches) - Math.min(...reaches);
  if (severity === 0) continue;
  // ⛔ A DIVERGENCE MEASURED UNDER DIFFERENT NUBS IS NOT A PLATFORM FINDING. Flag it rather than
  // silently ranking it — this is the confound that would otherwise turn tooling drift into a
  // fake OS bug, and it has to be visible in the output, not assumed away.
  const nubs = new Set(present.map(([, d]) => d.nub).filter(Boolean));
  const nodes = new Set(present.map(([, d]) => d.node).filter(Boolean));
  findings.push({
    package: k,
    severity,
    sameNub: nubs.size <= 1,
    sameNode: nodes.size <= 1,
    platforms: Object.fromEntries(present.map(([os, d]) => [os, { grant: show(d.grant), cells: d.cells }])),
  });
}

findings.sort((a, b) => b.severity - a.severity || a.package.localeCompare(b.package));
const kept = findings.filter((f) => f.severity >= MIN_SEV);

if (AS_JSON) {
  console.log(JSON.stringify({ comparable, diverging: findings.length, findings: kept }, null, 2));
  process.exit(0);
}

console.log(`  records: ${rows.length}   measured on >1 OS: ${comparable}   DIVERGING: ${findings.length} (${((findings.length / Math.max(comparable, 1)) * 100).toFixed(1)}%)`);
console.log(`  showing severity >= ${MIN_SEV}\n`);
const label = { 4: 'disk', 3: 'read-disk', 2: 'userHome', 1: 'narrow', 0: 'nothing' };
for (const f of kept) {
  const flags = [f.sameNub ? null : '⚠ DIFFERENT NUB', f.sameNode ? null : '⚠ DIFFERENT NODE'].filter(Boolean).join(' ');
  console.log(`  [sev ${f.severity}] ${f.package}${flags ? '   ' + flags : ''}`);
  for (const [os, d] of Object.entries(f.platforms)) {
    console.log(`        ${os.padEnd(8)} ${String(d.cells ?? '?').padStart(3)}c  ${d.grant}`);
  }
}
const bySev = {};
for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
console.log('\n  by severity (3 = disk-vs-not, the bucket that actually costs security):');
for (const s of Object.keys(bySev).sort((a, b) => b - a)) console.log(`     sev ${s}: ${bySev[s]}`);
console.log('\n  ⛔ PERSPECTIVE: a small overgrant on a few packages is NOT a reason to re-run the corpus.');
console.log('     Over-granting is the SAFE direction — it fails to confine, it does not break installs.');
console.log('     Re-run wholesale only for a defect that is wrong AT SCALE or UNDER-grants. Otherwise');
console.log('     re-measure the affected packages with the workflow `packages` input, which costs minutes.');
