import fs from 'node:fs';
import path from 'node:path';
import { inspectCjpeg } from './cjpeg-oracle.mjs';

// Preserve failed calibration arms even when the batch refuses to create records.
const [log, destination] = process.argv.slice(2);
if (!log || !destination) throw new Error('usage: collect-preflight.mjs <measure.log> <destination>');
fs.mkdirSync(destination, { recursive: true });
if (!fs.existsSync(log)) process.exit(0);
const contents = fs.readFileSync(log, 'utf8');
fs.copyFileSync(log, path.join(destination, 'measure.log'));
const roots = [...new Set([...contents.matchAll(/kept for inspection: ([^\r\n]+)/g)].map((match) => match[1].trim()))];
const MAX_FILE_BYTES = 8 * 1024 * 1024;

// A failed preflight has no record directory, so its arm root is the only place where the exact
// experiment still exists.  Retain the inputs and raw install logs, but never follow a store link:
// the machine-global store is not part of the arm and can be both large and concurrently mutated.
// Its link targets are instead captured as provenance below.  This lets a later reader distinguish
// a real isolated materialization from an arm whose package links resolved into a prior store entry.
const ARM_FILES = [
  'package.json', 'nub.jsonc', '.npmrc', 'cat.json',
  'security-resolve.log', 'i.log', 'a.log', 'rc',
  'observe/fetch.log',
  'verify-at-grant/package.json', 'verify-at-grant/nub.jsonc', 'verify-at-grant/.npmrc',
  'verify-at-grant/cat.json', 'verify-at-grant/security-resolve.log',
  'verify-at-grant/i.log', 'verify-at-grant/a.log', 'verify-at-grant/rc',
  'verify-at-grant/cjpeg-oracle.json',
];

const copyArmFile = (realRoot, destinationRoot, relative, files) => {
  const source = path.join(realRoot, relative);
  let stat;
  try { stat = fs.lstatSync(source); } catch { return; }
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return;
  let canonical;
  try { canonical = fs.realpathSync(source); } catch { return; }
  const contained = path.relative(realRoot, canonical);
  if (contained.startsWith(`..${path.sep}`) || path.isAbsolute(contained)) return;
  const target = path.join(destinationRoot, relative);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  files.push(relative);
};

const storeProvenance = (realRoot) => {
  const nodeModules = path.join(realRoot, 'verify-at-grant', 'node_modules');
  const links = [];
  const visit = (dir, depth) => {
    if (depth > 3 || links.length >= 256) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const source = path.join(dir, entry.name);
      // Artifact manifests are cross-platform evidence.  Use slash paths even when the runner is
      // Windows, so the same arm inventory is comparable with the POSIX calibration artifacts.
      const relative = path.relative(realRoot, source).split(path.sep).join('/');
      if (entry.isSymbolicLink()) {
        let target;
        try { target = fs.realpathSync(source); } catch { target = null; }
        links.push({ path: relative, target });
      } else if (entry.isDirectory() && entry.name !== '.bin') visit(source, depth + 1);
      if (links.length >= 256) return;
    }
  };
  visit(nodeModules, 0);
  return { nodeModulesPresent: fs.existsSync(nodeModules), links, truncated: links.length >= 256 };
};
// The Windows falsification control needs one answer the ordinary package manifest cannot provide:
// did the prebuilt executable in a failed `mozjpeg` arm come from that arm's package tree, or did
// its `node_modules` link resolve to the right control's shared virtual store?  Retain metadata for
// this one fixed artifact rather than a cache-tree inventory.  In particular, do not follow an
// external link for copying: the physical path, size, and digest establish provenance without
// collecting arbitrary runner files.
const manifest = [];
for (const [index, root] of roots.entries()) {
  if (!path.isAbsolute(root)) continue;
  let realRoot;
  try { realRoot = fs.realpathSync(root); } catch { continue; }
  const files = [];
  const armDestination = path.join(destination, String(index));
  for (const relative of ARM_FILES) copyArmFile(realRoot, armDestination, relative, files);
  const store = storeProvenance(realRoot);
  fs.mkdirSync(armDestination, { recursive: true });
  fs.writeFileSync(path.join(armDestination, 'store-provenance.json'), `${JSON.stringify(store, null, 2)}\n`);
  files.push('store-provenance.json');
  manifest.push({ root, files, store, cjpeg: inspectCjpeg(path.join(realRoot, 'verify-at-grant')) });
}
fs.writeFileSync(path.join(destination, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
