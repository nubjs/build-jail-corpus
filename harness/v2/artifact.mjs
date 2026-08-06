// The artifact set of one arm: the sorted relative path list under a fixture root.
//
// WHY A PATH LIST AND NOT A FILE COUNT. v2's first driver compared `find -type f` in the VERIFY
// arm against the same count in an `npm install` OBSERVE arm. npm materialises a flat
// node_modules; nub symlinks into a content-addressed store, so `-type f` inside the project
// counts a fraction of the same install. MEASURED on @airbnb/node-memwatch@3.0.0: npm 103 files,
// nub 42, with the addon built and `gyp info ok` in both — every jailed arm scored as failed and
// the package (true minimum: null) was reported NO-STATE-PASSED. The counts were never comparable.
//
// The store hash is stripped so two arms that resolve the same dependency to different content
// addresses still compare equal.
import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2];
const SKIP = new Set(['.git']);
const out = [];
const walk = (d, rel) => {
  let ents;
  try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (SKIP.has(e.name)) continue;
    const r = rel ? `${rel}/${e.name}` : e.name;
    // Harness bookkeeping is not an artifact of the package.
    if (/^(trace\.txt|cat\.json|.*\.log)$/.test(e.name) && !rel.includes('/')) continue;
    out.push(r);
    if (e.isDirectory() && !e.isSymbolicLink()) walk(path.join(d, e.name), r);
  }
};
walk(root, '');
const tok = (p) => p
  // store entry: `<name>@<version>-<contenthash>` -> drop the hash so arms compare
  .replace(/(@[^/]*?)-[0-9a-f]{8,}(?=\/|$)/g, '$1')
  // node-gyp's devdir and npm's tmp dirs carry a per-run random suffix
  .replace(/node-gyp-tmp-[A-Za-z0-9]+/g, 'node-gyp-tmp-X')
  .replace(/\.tmp-[A-Za-z0-9]+/g, '.tmp-X');
console.log([...new Set(out.map(tok))].sort().join('\n'));
