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
  for (const relative of ['observe/fetch.log', 'verify-at-grant/i.log', 'verify-at-grant/a.log', 'verify-at-grant/cjpeg-oracle.json']) {
    const source = path.join(root, relative);
    let stat;
    try { stat = fs.lstatSync(source); } catch { continue; }
    if (!stat.isFile() || stat.size > 8 * 1024 * 1024) continue;
    const relativeTarget = path.relative(realRoot, fs.realpathSync(source));
    if (relativeTarget.startsWith(`..${path.sep}`) || path.isAbsolute(relativeTarget)) continue;
    const target = path.join(destination, String(index), relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
    files.push(relative);
  }
  manifest.push({ root, files, cjpeg: inspectCjpeg(path.join(realRoot, 'verify-at-grant')) });
}
fs.writeFileSync(path.join(destination, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
