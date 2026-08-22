// Downloads and unpacks the era Node a record needs, and PROVES it runs before handing it back.
//
// ⛔ THIS EXISTS BECAUSE THE FIRST VERSION FAILED OPEN ON WINDOWS. It hardcoded
// `platform === 'darwin' ? 'darwin' : 'linux'`, so a win32 runner downloaded a LINUX tarball and
// then tested for `<dir>/bin/node`, a path the Windows layout never has. Every win32 row came back
// `NOT-PINNED (not provisionable)` with no clue why: 333 of 333, era pins 0. On linux/macos the era
// pin recovers 31 `primordials is not defined` records outright, so those 333 rows were confirming
// failures the era Node may well have fixed.
//
// Two rules follow from that, and both are load-bearing:
//   1. The archive kind, the URL, the extractor and the resulting bin directory are ALL per-platform.
//      Getting one right and the rest wrong is how the silent failure happened.
//   2. `existsSync` is not proof. The binary is EXECUTED and its `--version` matched against the
//      version asked for, so a truncated download or a wrong-arch build is a loud mismatch rather
//      than a pin that quietly is not the era.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const run = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 26, ...opts });

/** Where nodejs.org publishes a given version for a given host, and where the binary lands. */
export function eraLayout(version, { platform = process.platform, arch = process.arch } = {}) {
  const major = Number(String(version).split('.')[0]);
  let plat;
  let a = arch === 'arm64' ? 'arm64' : 'x64';
  if (platform === 'win32') plat = 'win';
  else if (platform === 'darwin') {
    plat = 'darwin';
    // nodejs.org ships NO darwin-arm64 build below 16. The x64 build runs under Rosetta, measured
    // working for 4.9.1 and 10.24.1 on this host.
    if (major < 16) a = 'x64';
  } else plat = 'linux';
  // win-arm64 only exists from 20 onwards; below that the x64 build runs under Windows' emulation.
  if (plat === 'win' && a === 'arm64' && major < 20) a = 'x64';
  const stem = `node-v${version}-${plat}-${a}`;
  const ext = plat === 'win' ? 'zip' : 'tar.gz';
  return {
    url: `https://nodejs.org/dist/v${version}/${stem}.${ext}`,
    archive: `${stem}.${ext}`,
    // The win zip puts node.exe at the archive root; the POSIX tarballs put node under bin/.
    binSubdir: plat === 'win' ? '.' : 'bin',
    exe: plat === 'win' ? 'node.exe' : 'node',
  };
}

/** The cache root. `process.env.HOME` is unset on Windows — `os.homedir()` is the portable form,
 *  and the first version's `HOME ?? '/tmp'` produced a literal `\tmp\...` there. */
export function eraRootDir() {
  return path.join(os.homedir() || os.tmpdir(), '.cache', 'nub', 'era-node');
}

/**
 * @returns {{binDir: string|null, status: string}} `status` always names the stage that failed, so a
 *          missing pin is diagnosable from the ledger alone.
 */
export function provisionEraNode(version, { root = eraRootDir(), platform = process.platform,
                                            arch = process.arch, exec = run } = {}) {
  const { url, archive, binSubdir, exe } = eraLayout(version, { platform, arch });
  const dir = path.join(root, version);
  const binDir = path.resolve(dir, binSubdir);
  const binary = path.join(binDir, exe);

  const verify = () => {
    if (!fs.existsSync(binary)) return null;
    const v = exec(binary, ['--version']);
    if (v.status !== 0) return `binary present but will not run (status=${v.status})`;
    const got = String(v.stdout ?? '').trim();
    if (got !== `v${version}`) return `binary reports ${got}, wanted v${version}`;
    return 'ok';
  };

  let state = verify();
  if (state === 'ok') return { binDir, status: `PINNED ${version}` };

  if (!state) {
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(root, archive);
    const dl = exec('curl', ['-fsSL', url, '-o', dest]);
    if (dl.status !== 0) {
      return { binDir: null, status: `NOT-PINNED (download failed rc=${dl.status} ${url})` };
    }
    // bsdtar ships with Windows 10+ and reads zip, so one extractor covers every host.
    const ex = exec('tar', ['-xf', dest, '-C', dir, '--strip-components=1']);
    if (ex.status !== 0) {
      return { binDir: null, status: `NOT-PINNED (extract failed rc=${ex.status} ${archive})` };
    }
    state = verify();
  }
  if (state === 'ok') return { binDir, status: `PINNED ${version}` };
  return { binDir: null, status: `NOT-PINNED (${state ?? `no ${exe} under ${binSubdir}/`})` };
}
