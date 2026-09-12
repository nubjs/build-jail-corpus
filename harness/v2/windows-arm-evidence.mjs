import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
export const MAX_REPORT_BYTES = 512 * 1024;
export const MAX_COPY_BYTES = MAX_TOTAL_BYTES - MAX_REPORT_BYTES;
export const MAX_MANIFEST_ENTRIES = 2048;
export const MAX_MANIFEST_DEPTH = 32;
export const MAX_BUILD_METADATA_ENTRIES = 128;
export const MAX_TRAVERSAL_ENTRIES = 8192;
const LOG_FILES = ['fetch.log', 'security-resolve.log', 'i.log', 'a.log'];
const BUILD_NAMES = new Set(['config.gypi', 'buildcheck.gypi']);
const BUILD_EXTENSIONS = new Set(['.vcxproj', '.props', '.targets', '.sln']);

const inside = (parent, child) => {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};

const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

const locatePackage = (base, pkg, ver) => {
  for (const candidate of [
    path.join(base, 'node_modules', pkg),
    path.join(base, 'node_modules', '.store', `${pkg}@${ver}`, 'node_modules', pkg),
    path.join(base, 'node_modules', '.store', `${pkg}@${ver}`),
  ]) if (fs.existsSync(candidate)) return candidate;
  return null;
};

const fullManifest = (root) => {
  const entries = [];
  const seen = new Set();
  const traversal = { maxEntries: MAX_MANIFEST_ENTRIES, maxDepth: MAX_MANIFEST_DEPTH,
    maxVisited: MAX_TRAVERSAL_ENTRIES, visited: 0,
    entryCap: false, depthCap: false, outsidePackage: 0, unreadable: 0, cycles: 0 };
  const walk = (dir, depth) => {
    if (depth > MAX_MANIFEST_DEPTH) { traversal.depthCap = true; return; }
    let real; try { real = fs.realpathSync(dir); } catch { return; }
    if (!inside(root, real)) { traversal.outsidePackage += 1; return; }
    if (seen.has(real)) { traversal.cycles += 1; return; }
    seen.add(real);
    let children; try { children = fs.readdirSync(dir, { withFileTypes: true }); } catch { traversal.unreadable += 1; return; }
    for (const child of children) {
      if (++traversal.visited > MAX_TRAVERSAL_ENTRIES) { traversal.entryCap = true; return; }
      if (entries.length >= MAX_MANIFEST_ENTRIES) { traversal.entryCap = true; return; }
      if (child.name === 'node_modules') continue;
      const file = path.join(dir, child.name);
      let stat; try { stat = fs.statSync(file); } catch { traversal.unreadable += 1; continue; }
      let childReal; try { childReal = fs.realpathSync(file); } catch { traversal.unreadable += 1; continue; }
      if (!inside(root, childReal)) { traversal.outsidePackage += 1; continue; }
      if (stat.isDirectory()) walk(file, depth + 1);
      else if (stat.isFile()) entries.push({ path: path.relative(root, file).split(path.sep).join('/'), bytes: stat.size });
    }
  };
  walk(root, 0);
  return { entries: entries.sort((a, b) => a.path.localeCompare(b.path)), traversal };
};

const buildCandidates = (packageRoot) => {
  const out = ['buildcheck.gypi'];
  const seen = new Set();
  const traversal = { maxEntries: MAX_BUILD_METADATA_ENTRIES, maxDepth: MAX_MANIFEST_DEPTH,
    maxVisited: MAX_TRAVERSAL_ENTRIES, visited: 0,
    entryCap: false, depthCap: false, outsidePackage: 0, unreadable: 0, cycles: 0 };
  const walk = (dir, depth) => {
    if (depth > MAX_MANIFEST_DEPTH) { traversal.depthCap = true; return; }
    let real; try { real = fs.realpathSync(dir); } catch { traversal.unreadable += 1; return; }
    if (!inside(packageRoot, real)) { traversal.outsidePackage += 1; return; }
    if (seen.has(real)) { traversal.cycles += 1; return; }
    seen.add(real);
    let children; try { children = fs.readdirSync(dir, { withFileTypes: true }); } catch { traversal.unreadable += 1; return; }
    for (const child of children) {
      if (++traversal.visited > MAX_TRAVERSAL_ENTRIES) { traversal.entryCap = true; return; }
      if (out.length >= MAX_BUILD_METADATA_ENTRIES) { traversal.entryCap = true; return; }
      const file = path.join(dir, child.name);
      let stat; try { stat = fs.statSync(file); } catch { traversal.unreadable += 1; continue; }
      let childReal; try { childReal = fs.realpathSync(file); } catch { traversal.unreadable += 1; continue; }
      if (!inside(packageRoot, childReal)) { traversal.outsidePackage += 1; continue; }
      if (stat.isDirectory()) walk(file, depth + 1);
      else if (BUILD_NAMES.has(child.name) || BUILD_EXTENSIONS.has(path.extname(child.name))) {
        out.push(path.relative(packageRoot, file).split(path.sep).join('/'));
      }
    }
  };
  walk(path.join(packageRoot, 'build'), 0);
  return { paths: [...new Set(out)].sort(), traversal };
};

export const createWindowsArmEvidence = ({ destination, fixtureRoot, pkg, ver }) => {
  const root = fs.realpathSync(path.resolve(fixtureRoot));
  const out = path.resolve(destination);
  fs.mkdirSync(out, { recursive: true });
  let total = 0;

  const copy = (sourceRoot, relative, destinationRoot, records) => {
    const source = path.join(sourceRoot, relative);
    const record = { path: relative.split(path.sep).join('/') };
    let link;
    try { link = fs.lstatSync(source); } catch { records.push({ ...record, status: 'missing' }); return; }
    if (!link.isFile()) { records.push({ ...record, status: 'not-regular' }); return; }
    let real;
    try { real = fs.realpathSync(source); } catch { records.push({ ...record, status: 'unreadable' }); return; }
    if (!inside(sourceRoot, real)) { records.push({ ...record, status: 'outside-root' }); return; }
    if (link.size > MAX_FILE_BYTES) { records.push({ ...record, status: 'too-large', bytes: link.size }); return; }
    if (total + link.size > MAX_COPY_BYTES) { records.push({ ...record, status: 'bundle-cap', bytes: link.size }); return; }
    try {
      const contents = fs.readFileSync(source);
      const target = path.join(destinationRoot, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, contents);
      total += contents.length;
      records.push({ ...record, status: 'copied', bytes: contents.length, sha256: hash(contents) });
    } catch { records.push({ ...record, status: 'unreadable' }); }
  };

  const capture = ({ label, armRoot }) => {
    let arm;
    try { arm = fs.realpathSync(path.resolve(armRoot)); }
    catch { arm = path.resolve(armRoot); }
    const armDir = path.join(out, label);
    fs.mkdirSync(armDir, { recursive: true });
    const logs = [];
    for (const file of LOG_FILES) copy(arm, file, armDir, logs);
    const packagePath = locatePackage(arm, pkg, ver);
    const packageRecord = { status: 'missing', manifest: [], manifestTraversal: null, build: [], buildTraversal: null };
    if (packagePath) {
      let packageReal;
      try { packageReal = fs.realpathSync(packagePath); } catch { packageReal = null; }
      if (!packageReal) packageRecord.status = 'unreadable';
      else if (!inside(root, packageReal)) packageRecord.status = 'outside-fixture-root';
      else {
        packageRecord.status = 'present';
        const manifest = fullManifest(packageReal);
        packageRecord.manifest = manifest.entries;
        packageRecord.manifestTraversal = manifest.traversal;
        const build = buildCandidates(packageReal);
        packageRecord.buildTraversal = build.traversal;
        for (const file of build.paths) copy(packageReal, file, armDir, packageRecord.build);
      }
    }
    const report = { schemaVersion: 1, label, package: packageRecord, logs, totalCopiedBytes: total,
      limits: { maxFileBytes: MAX_FILE_BYTES, maxCopiedBytes: MAX_COPY_BYTES, maxBundleBytes: MAX_TOTAL_BYTES, maxReportBytes: MAX_REPORT_BYTES } };
    let encoded = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
    while (encoded.length > MAX_REPORT_BYTES && packageRecord.manifest.length) {
      packageRecord.manifest.pop();
      packageRecord.manifestTraversal.reportCap = true;
      encoded = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
    }
    if (encoded.length > MAX_REPORT_BYTES) throw new Error(`diagnostic manifest exceeds ${MAX_REPORT_BYTES} bytes after truncation`);
    if (total + encoded.length > MAX_TOTAL_BYTES) throw new Error(`diagnostic bundle exceeds ${MAX_TOTAL_BYTES} bytes including manifests`);
    fs.writeFileSync(path.join(armDir, 'manifest.json'), encoded);
    total += encoded.length;
    return report;
  };
  return { dir: out, capture };
};
