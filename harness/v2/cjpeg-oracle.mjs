import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const CJPEG_PATH = 'node_modules/mozjpeg/vendor/cjpeg.exe';
export const MAX_CJPEG_BYTES = 64 * 1024 * 1024;
export const MAX_CJPEG_OUTPUT_BYTES = 8 * 1024;

export const boundedText = (value, limit = MAX_CJPEG_OUTPUT_BYTES) => {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value ?? '');
  const captured = bytes.subarray(0, Math.min(bytes.length, limit));
  return {
    text: captured.toString('utf8'),
    bytes: bytes.length,
    capturedBytes: captured.length,
    truncated: bytes.length > limit,
  };
};

const inside = (parent, child) => {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};

// Read the one fixed falsification artifact without turning failed-arm retention into a cache-tree
// collector. A GVS package-directory link is expected, so the resolved package root may be outside
// the arm. The final executable must instead be a regular file whose resolved path remains inside
// that package root: a final symlink/reparse target cannot redirect this collector to an arbitrary
// runner file.
export const inspectCjpeg = (base) => {
  const artifact = path.join(base, CJPEG_PATH);
  const packageDir = path.join(base, 'node_modules', 'mozjpeg');
  let packageReal;
  try { packageReal = fs.realpathSync(packageDir); } catch { return { path: CJPEG_PATH, status: 'missing' }; }
  let link;
  try { link = fs.lstatSync(artifact); } catch { return { path: CJPEG_PATH, status: 'missing' }; }
  if (link.isSymbolicLink()) return { path: CJPEG_PATH, status: 'final-symlink' };
  if (!link.isFile()) return { path: CJPEG_PATH, status: 'not-file' };
  let realpath;
  try { realpath = fs.realpathSync(artifact); } catch { return { path: CJPEG_PATH, status: 'unresolved-link' }; }
  if (!inside(packageReal, realpath)) return { path: CJPEG_PATH, status: 'outside-package', realpath, packageReal };

  let fd;
  try {
    fd = fs.openSync(artifact, 'r');
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) return { path: CJPEG_PATH, status: 'not-file' };
    if (stat.size > MAX_CJPEG_BYTES) return { path: CJPEG_PATH, status: 'too-large', realpath, bytes: stat.size };
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(fd, bytes, offset, bytes.length - offset, null);
      if (read === 0) return { path: CJPEG_PATH, status: 'changed-during-read', realpath, bytes: stat.size };
      offset += read;
    }
    return {
      path: CJPEG_PATH,
      status: 'present',
      realpath,
      bytes: stat.size,
      sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
    };
  } catch {
    return { path: CJPEG_PATH, status: 'unreadable', realpath };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
};
