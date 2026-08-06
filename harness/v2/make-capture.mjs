// Write a minimal `capture.json` for a one-off / probe classification.
//
// ⛔ THIS EXISTS SO A PROBE CANNOT OPT OUT OF R1 BY BEING SMALL. `classify.mjs` takes its roots from
// `capture.json` and refuses to run when one is undeclared, which is the whole of VENUE-PORTABILITY
// R2 — a root the classifier re-derives is a root re-derived from AMBIENT state, so it produces a
// plausible answer on the machine that happens to match and a wrong one everywhere else. The
// measurement driver writes a full capture with tracer parameters and decoder digests; a probe
// needs none of that but still has to say what a path MEANS. Without this the cheapest way to keep
// a probe working would be to hand-roll the JSON inline in a workflow, and an inline copy is where
// the ten-key set silently becomes an eight-key one.
//
// ⛔ EVERY REQUIRED ROOT IS EMITTED, `null` WHERE NOT SUPPLIED — never omitted. An absent key and an
// inapplicable root read the same downstream, which is exactly the ambiguity R1 removes, so the
// default here is an explicit `null` and the caller supplies what it knows.
//
//   usage: node make-capture.mjs --out capture.json --project D --home D
//                                [--pkg N] [--version V] [--temp D] [--interpreter P]
//                                [--global-store D] [--project-store D] [--tools-dir D]
//                                [--jail-home D] [--npm-prefix D] [--own-pkg D]
import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const val = (f, d = null) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };

const out = val('--out');
const project = val('--project');
const home = val('--home');
if (!out || !project || !home) {
  console.error('usage: make-capture.mjs --out capture.json --project D --home D [...]');
  process.exit(2);
}
const pkg = val('--pkg');
const sep = process.platform === 'win32' ? '\\' : '/';

const capture = {
  v: 1,
  kind: 'capture',
  platform: `${process.platform}-${process.arch}`,
  pkg,
  version: val('--version'),
  // ⛔ NAMED FOR WHAT IT IS. A probe capture carries no tracer parameters and no decoder digests, so
  // a reader must not mistake it for a measurement archive — the absence of a keyword mask here is
  // not "the mask was default", it is "this file never knew one".
  tracer: 'probe (no tracer parameters recorded — not a measurement archive)',
  roots: {
    project,
    home,
    jailHome: val('--jail-home'),
    globalStore: val('--global-store'),
    projectStore: val('--project-store'),
    interpreter: val('--interpreter'),
    toolsDir: val('--tools-dir'),
    temp: val('--temp'),
    npmPrefix: val('--npm-prefix'),
    ownPkg: val('--own-pkg') ?? (pkg ? path.join(project, 'node_modules', ...pkg.split('/')) : null),
    cwd: null,
  },
  at: new Date().toISOString(),
};
fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
fs.writeFileSync(out, `${JSON.stringify(capture, null, 2)}\n`);
console.log(`${out}  roots: ${Object.entries(capture.roots).filter(([, v]) => v).map(([k]) => k).join(' ')}`
  + `  (null: ${Object.entries(capture.roots).filter(([, v]) => !v).map(([k]) => k).join(' ') || 'none'})`
  + `  sep=${sep}`);
