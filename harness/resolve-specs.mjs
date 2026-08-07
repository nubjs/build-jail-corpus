// Resolve `pkg` or `pkg@latest` to `pkg@<concrete version>` before measuring.
//
// ⛔⛔ WHY THIS EXISTS. On 2026-08-07 I fed `pkg@latest` worklists to all three venues. The harness
// took the tag LITERALLY: 54 records landed under a directory named `latest`, with
// `version: "latest"` and `resolvedVersion: "latest"`. A record keyed on a floating tag pins
// NOTHING — it cannot be re-checked, cannot be compared against a later run, and its grant cannot
// be matched to a version band. 24 of them reached origin before I caught it.
//
// The catalog escaped damage only by luck of two independent filters: `collate.mjs` publishes only
// `MINIMUM`, and a regen with the bad records present emitted 0 version bands containing "latest".
// ⛔ DO NOT rely on that a second time — resolve first.
//
//   usage: node resolve-specs.mjs <infile> [outfile]     ("-" reads stdin)
//
// Unresolvable specs are dropped and NAMED on stderr. A silently shorter worklist is the failure
// this whole file exists to prevent, so the count is always printed.
import fs from 'node:fs';

const [, , inFile, outFile] = process.argv;
if (!inFile) {
  console.error('usage: node resolve-specs.mjs <infile|-> [outfile]');
  process.exit(2);
}
const raw = (inFile === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(inFile, 'utf8'))
  .split('\n').map((l) => l.trim()).filter(Boolean);

// A scoped name keeps its leading `@`, so split on the LAST `@` only when one follows the name.
const nameOf = (spec) => {
  const at = spec.lastIndexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
};

const out = [];
const failed = [];
for (const spec of raw) {
  const name = nameOf(spec);
  try {
    const res = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
      headers: { accept: 'application/vnd.npm.install-v1+json' },
    });
    if (!res.ok) { failed.push(`${name} (HTTP ${res.status})`); continue; }
    const j = await res.json();
    const v = j['dist-tags']?.latest;
    // ⛔ A concrete version is required. `latest` reaching the output is the exact bug this prevents.
    if (!v || v === 'latest') { failed.push(`${name} (no dist-tags.latest)`); continue; }
    out.push(`${name}@${v}`);
  } catch (e) {
    failed.push(`${name} (${e.message})`);
  }
}

const text = out.join('\n') + (out.length ? '\n' : '');
if (outFile) fs.writeFileSync(outFile, text); else process.stdout.write(text);
console.error(`resolved ${out.length}/${raw.length}`);
if (failed.length) console.error(`⛔ DROPPED ${failed.length}: ${failed.join(', ')}`);
