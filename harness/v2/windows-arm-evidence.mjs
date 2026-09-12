import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
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
  const walk = (dir) => {
    let real; try { real = fs.realpathSync(dir); } catch { return; }
    if (seen.has(real)) return;
    seen.add(real);
    let children; try { children = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const child of children) {
      if (child.name === 'node_modules') continue;
      const file = path.join(dir, child.name);
      let stat; try { stat = fs.statSync(file); } catch { continue; }
      if (stat.isDirectory()) walk(file);
      else if (stat.isFile()) entries.push({ path: path.relative(root, file).split(path.sep).join('/'), bytes: stat.size });
    }
  };
  walk(root);
  return entries.sort((a, b) => a.path.localeCompare(b.path));
};

const buildCandidates = (packageRoot) => {
  const out = ['buildcheck.gypi'];
  const build = path.join(packageRoot, 'build');
  const walk = (dir) => {
    let children; try { children = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const child of children) {
      const file = path.join(dir, child.name);
      if (child.isDirectory()) walk(file);
      else if (BUILD_NAMES.has(child.name) || BUILD_EXTENSIONS.has(path.extname(child.name))) {
        out.push(path.relative(packageRoot, file).split(path.sep).join('/'));
      }
    }
  };
  walk(build);
  return [...new Set(out)].sort();
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
    if (total + link.size > MAX_TOTAL_BYTES) { records.push({ ...record, status: 'bundle-cap', bytes: link.size }); return; }
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
    const packageRecord = { status: 'missing', manifest: [], build: [] };
    if (packagePath) {
      let packageReal;
      try { packageReal = fs.realpathSync(packagePath); } catch { packageReal = null; }
      if (!packageReal) packageRecord.status = 'unreadable';
      else if (!inside(root, packageReal)) packageRecord.status = 'outside-fixture-root';
      else {
        packageRecord.status = 'present';
        packageRecord.manifest = fullManifest(packageReal);
        for (const file of buildCandidates(packageReal)) copy(packageReal, file, armDir, packageRecord.build);
      }
    }
    const report = { schemaVersion: 1, label, package: packageRecord, logs, totalCopiedBytes: total,
      limits: { maxFileBytes: MAX_FILE_BYTES, maxBundleBytes: MAX_TOTAL_BYTES } };
    fs.writeFileSync(path.join(armDir, 'manifest.json'), `${JSON.stringify(report, null, 2)}\n`);
    return report;
  };
  return { dir: out, capture };
};
