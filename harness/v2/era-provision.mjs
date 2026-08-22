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
    stem,
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
  const { url, archive, stem, binSubdir, exe } = eraLayout(version, { platform, arch });
  const dir = path.join(root, version);
  // Nothing is stripped during extraction, so the payload sits under the archive's own stem —
  // except on a re-run of a cache written before that change, so both layouts are accepted.
  const candidates = [path.resolve(dir, stem, binSubdir), path.resolve(dir, binSubdir)];
  let binDir = candidates[0];
  const binaryAt = (d) => path.join(d, exe);

  const verify = () => {
    const found = candidates.find((d) => fs.existsSync(binaryAt(d)));
    if (!found) return null;
    binDir = found;
    const v = exec(binaryAt(found), ['--version']);
    if (v.status !== 0) return `binary present but will not run (status=${v.status})`;
    const got = String(v.stdout ?? '').trim();
    if (got !== `v${version}`) return `binary reports ${got}, wanted v${version}`;
    return 'ok';
  };

  // ⛔ THE ERA npm's OWN ENTRY POINT, RESOLVED PER PLATFORM. The runner computed this itself as
  // `<binDir>/../lib/node_modules/npm/bin/npm-cli.js` — the POSIX layout. Windows has no `lib/`
  // level, so the path never existed there, the era-npm branch silently fell back to the HARNESS
  // npm, and a MODERN npm ended up running its node-gyp under an ERA Node that reached it through
  // the arm PATH:
  //   C:\hostedtoolcache\windows\node\22.23.2\x64\node_modules\npm\node_modules\node-gyp\lib\node-gyp.js:154
  //   this.opts[name.replaceAll('_', '-').toLowerCase()] = process.env[key]
  //   TypeError: name.replaceAll is not a function
  // (String.replaceAll is Node 15+.) 78 of the 96 rows in that family were win32. Both layouts are
  // tried and the one that EXISTS wins, so this cannot silently pick a path that is not there.
  const npmCliFor = (dir) => [
    path.join(dir, 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ].find((p) => fs.existsSync(p)) ?? null;
  const versionRoot = () => (binSubdir === '.' ? binDir : path.dirname(binDir));

  let state = verify();
  if (state === 'ok') return { binDir, npmCli: npmCliFor(versionRoot()), status: `PINNED ${version}` };

  if (!state) {
    fs.mkdirSync(dir, { recursive: true });
    const dest = path.join(root, archive);
    const dl = exec('curl', ['-fsSL', url, '-o', dest]);
    if (dl.status !== 0) {
      return { binDir: null, npmCli: null, status: `NOT-PINNED (download failed rc=${dl.status} ${url})` };
    }
    // ⛔ WINDOWS DOES NOT GO THROUGH `tar`. A sweep of all 570 win32 records came back
    // `extract failed rc=128` on every single zip, while the identical bsdtar command extracts the
    // same archive on macOS with rc=0 — the runner's PATH resolves `tar` to something that cannot
    // read a zip. Expand-Archive is built into Windows PowerShell and needs no PATH lookup.
    // Neither extractor strips a leading directory portably, so nothing is stripped and the nested
    // directory is resolved afterwards instead.
    const ex = platform === 'win32'
      ? exec('powershell', ['-NoProfile', '-NonInteractive', '-Command',
             `Expand-Archive -LiteralPath '${dest}' -DestinationPath '${dir}' -Force`])
      : exec('tar', ['-xf', dest, '-C', dir]);
    if (ex.status !== 0) {
      // Carry the extractor's own words: a bare rc sent one whole sweep back for another round.
      const why = String(ex.stderr ?? '').split('\n').map((l) => l.trim()).filter(Boolean)[0] ?? '';
      return { binDir: null, npmCli: null, status: `NOT-PINNED (extract failed rc=${ex.status} ${archive}${why ? `: ${why}` : ''})` };
    }
    state = verify();
  }
  if (state === 'ok') return { binDir, npmCli: npmCliFor(versionRoot()), status: `PINNED ${version}` };
  return { binDir: null, npmCli: null, status: `NOT-PINNED (${state ?? `no ${exe} under ${binSubdir}/`})` };
}
