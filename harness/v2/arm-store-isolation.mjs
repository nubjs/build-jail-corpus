// Prove a DIRECT-mode verify tree linked its dependencies to the cache allocated
// for this measurement.  The falsifier accepts `STORE isolated` as an alternative
// to an eviction count, so that spelling must come from observed symlink targets,
// never merely from the NUB_CACHE_DIR setting that requested a fresh cache.
import fs from 'node:fs';
import path from 'node:path';

const [arm, cache, label = 'verify'] = process.argv.slice(2);
if (!arm || !cache) {
  console.error('usage: arm-store-isolation.mjs ARM NUB_CACHE_DIR [LABEL]');
  process.exit(2);
}

const store = path.join(cache, 'store', 'v1');
const linkDir = path.join(arm, 'node_modules', '.store');
const within = (root, candidate) => {
  const rel = path.relative(root, candidate);
  return Boolean(rel) && !rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel);
};

let expected;
let entries;
try {
  expected = fs.realpathSync(store);
  entries = fs.readdirSync(linkDir, { withFileTypes: true });
} catch {
  console.log(`  STORE unavailable label=${label} root=${store}`);
  process.exit(0);
}

const links = [];
for (const entry of entries) {
  if (!entry.isSymbolicLink()) continue;
  const link = path.join(linkDir, entry.name);
  try {
    const target = fs.realpathSync(link);
    links.push({ entry: entry.name, target, inside: within(expected, target) });
  } catch {
    links.push({ entry: entry.name, target: null, inside: false });
  }
}

if (links.length > 0 && links.every((link) => link.inside)) {
  console.log(`  STORE isolated label=${label} links=${links.length} root=${expected}`);
} else if (links.length > 0) {
  const outside = links.find((link) => !link.inside);
  console.log(`  STORE shared label=${label} links=${links.length} root=${expected} target=${outside.target ?? 'unresolved'}`);
} else {
  console.log(`  STORE unavailable label=${label} root=${expected}`);
}
