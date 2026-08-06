// Which committed records were measured BEFORE their platform's descent could narrow anything?
//
// ⛔ WHY THIS EXISTS. `record.mjs` gates the whole grant-source rule on an `ARM-FALSIFIABILITY` line
// and reads its ABSENCE as "the check never ran" — correct and deliberate, because treating an absent
// flag as falsifiable would retroactively narrow a whole corpus on the strength of a test nobody
// performed. The consequence is a corpus split by MEASUREMENT DATE rather than by fact: once a driver
// starts emitting the line, its new records can narrow while its old ones stay `synthesized` forever,
// and nothing in either record says which it is. A reader would take the old record's width as a fact
// about the PACKAGE when it is a fact about the HARNESS.
//
// ⛔ THE SPLIT IS NARROWER THAN IT LOOKS, AND SAYING "45 RECORDS ARE SUSPECT" WOULD BE THE WRONG
// MARKING. A record whose descent found NOTHING droppable is unaffected: `synthesized IS the minimum`
// is that record's answer with or without the flag, and it is not date-dependent. Only a record that
// over-predicted publishes a grant wider than its own arms measured. MEASURED on the linux-x64 lane:
// 45 records lack the flag, 5 of them over-predicted. Those 5 are the split; the other 40 are fine.
//
// ⛔ THIS CANNOT BE FIXED BY RE-SCORING THE ARCHIVES, which is the obvious move and it is wrong. The
// flag answers "could this package's arms have FAILED?" — a property of the RUN (what the jail did,
// what the gate could have keyed on), not of the retained trace. Re-parsing recovers nothing, and
// backfilling the flag onto an old log would manufacture exactly the evidence the rule exists to
// demand. The honest repair is re-MEASUREMENT, folded into the cross-section rather than run
// separately, at which point this index empties out on its own.
//
// Re-derivable by design: the list is a measurement of the committed logs, never a hand-maintained
// roster that can silently go stale. Regenerate with `node harness/v2/pre-descent-index.mjs`.

import fs from 'node:fs';
import path from 'node:path';

const BASE = 'records-v2/runs';
const OUT = 'records-v2/PRE-DESCENT.json';

const out = {
  v: 1,
  kind: 'pre-descent-index',
  what: 'Records measured before their driver emitted ARM-FALSIFIABILITY, so record.mjs pins them to '
    + 'grantSource: "synthesized" regardless of what their descent measured.',
  affectedMeans: 'The descent PROVED a capability droppable, but the published grant keeps it. The '
    + 'grant is wider than this package needs — safe, but it is a fact about the harness, not the '
    + 'package. Re-measure to resolve.',
  unaffectedMeans: 'The descent found nothing droppable, so "synthesized is the minimum" is this '
    + "record's answer with or without the flag. Not date-dependent; nothing to redo.",
  cannotBeBackfilled: 'The flag is a property of the RUN, not of the retained trace. Re-parsing the '
    + 'archive cannot recover it and backfilling it would manufacture the evidence the rule demands.',
  generatedBy: 'node harness/v2/pre-descent-index.mjs',
  platforms: {},
};

for (const plat of fs.readdirSync(BASE).sort()) {
  const unaffected = [];
  const affected = [];
  for (const pkg of fs.readdirSync(path.join(BASE, plat)).sort()) {
    for (const ver of fs.readdirSync(path.join(BASE, plat, pkg)).sort()) {
      const log = path.join(BASE, plat, pkg, ver, 'driver.out');
      if (!fs.existsSync(log)) continue;
      const src = fs.readFileSync(log, 'utf8');
      // The same test `record.mjs:301` applies, spelled the same way, so the two cannot disagree
      // about which records are in this state.
      if (/ARM-FALSIFIABILITY\s/.test(src)) continue;
      (/=>\s*OVER-PREDICTED/.test(src) ? affected : unaffected).push(`${pkg}@${ver}`);
    }
  }
  if (!affected.length && !unaffected.length) continue;
  out.platforms[plat] = { affectedCount: affected.length, affected, unaffectedCount: unaffected.length, unaffected };
}

fs.writeFileSync(OUT, `${JSON.stringify(out, null, 2)}\n`);
for (const [plat, v] of Object.entries(out.platforms)) {
  console.log(`${plat}  affected=${v.affectedCount}  unaffected=${v.unaffectedCount}`);
  for (const a of v.affected) console.log(`     ${a}`);
}
