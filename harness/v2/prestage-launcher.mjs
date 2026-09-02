// Resolve a SELF-DOWNLOADING tool launcher during the scaffold, so its payload never lands in the
// measured HOME.
//
// ⛔⛔ THE DEFECT THIS CLOSES, MEASURED RATHER THAN ARGUED. The npm `pulumi` package is not the CLI —
// it is a launcher. `node_modules/pulumi/lib/cache.js` is four lines:
//
//     const home = process.env.PULUMI_HOME || path.join(os.homedir(), ".pulumi");
//     return path.join(home, "versions", version);
//
// so the first invocation downloads a 100 MB tarball and extracts the real CLI into `$HOME/.pulumi/
// versions/<v>/bin`, then executes it from there. Under every driver `HOME` is the arm's `jailhome`,
// which is the exact scope the measurement exists to characterise.
//
// MEASURED 2026-09-01, `@pulumi/awsx@2.9.0`, HOME redirected to a scratch dir, the package's real
// `install` script run with and without `pulumi` on PATH:
//
//   arm      pulumi on PATH   script rc   HOME files   what landed
//   before        no              0            0       the ENOENT branch and nothing else
//   after        yes              0           18       5 package files + 13 TOOL files
//
// and the 18 split cleanly:
//
//   .pulumi/plugins/resource-awsx-v2.9.0/**   5 files    ~78 MB   THE PACKAGE'S OWN REQUIREMENT
//   .pulumi/logs/*plugin_install.log                              (what justifies the catalog's
//   .pulumi/versions/3.260.0/bin/**          13 files    291 MB   userHome grant)
//                                                                 THE TOOL'S PAYLOAD — contamination
//
// Wiring the tools tier without this step therefore writes 291 MB of TOOL into the measured home and
// makes the tool itself need a home read+execute grant. That converts a fixture fix into a home-READ
// question, which is a different axis entirely.
//
// ⛔ WHY NOT SIMPLY SET `PULUMI_HOME` FOR THE MEASURED RUN. Because one variable controls BOTH the CLI
// cache and the plugin directory. Pointing it at a tools dir moves the 291 MB out of home — and moves
// the package's own `plugins/` write out with it, so the arm would record no home write at all and the
// catalog entry would narrow to nothing it earned. That is the UNDER-granting direction, the one that
// breaks real installs. The two writes have to be separated, not relocated together.
//
// ⛔ SO THE LAUNCHER IS BYPASSED INSTEAD. `PULUMI_HOME` is set only for this UNJAILED scaffold step,
// pointed at a staging dir outside the arm; the real binaries are then copied into the arm's
// `node_modules/.bin`, replacing the launcher shim. At measure time `PULUMI_HOME` is UNSET, so the CLI
// resolves from the granted deps subtree and `pulumi plugin install` still writes `$HOME/.pulumi/
// plugins` where the classifier can see it. `stage-arm-tools.mjs` carries the placement rule this
// depends on and measured it on a real kernel: the jail grants execute only inside
// `<project>/node_modules`, and a symlink pointing out of it is refused because Landlock resolves it.
//
// ⛔ THE SIBLING BINARIES COME TOO, AND LEAVING THEM IS A SILENT HALF-FIX. `run.js` prepends
// `path.dirname(bin)` to PATH before spawning, precisely so the CLI finds `pulumi-language-nodejs`,
// `pulumi-resource-pulumi-nodejs` and the rest beside it. Copying only `pulumi` reproduces a CLI that
// starts and then fails on its first plugin operation. The whole `bin/` directory moves.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

/** Launchers that fetch their real payload on first use, and the env var that redirects that fetch.
 *
 *  Deliberately tiny and evidence-gated: an entry belongs here only once a measurement shows the
 *  package's payload landing in the measured home. `pnpm`, `yarn` and `bun` are NOT here — their npm
 *  packages carry their own binaries and write nothing to home to start up. */
export const SELF_DOWNLOADING = {
  pulumi: { homeEnv: 'PULUMI_HOME', versionsDir: 'versions' },
};

/** Copy every regular file in `srcBin` into `destBin`, executable bits kept. Returns the names moved. */
export function copyBinDir(srcBin, destBin) {
  fs.mkdirSync(destBin, { recursive: true });
  const moved = [];
  for (const entry of fs.readdirSync(srcBin, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const to = path.join(destBin, entry.name);
    // The launcher shim already owns this name; it has to go before the real binary can take it.
    try { fs.rmSync(to, { force: true }); } catch { /* nothing there */ }
    fs.copyFileSync(path.join(srcBin, entry.name), to);
    try { fs.chmodSync(to, 0o755); } catch { /* a filesystem without modes */ }
    moved.push(entry.name);
  }
  return moved;
}

/**
 * Materialise `tool`'s real binaries into the arm, out of band from the measured HOME.
 *
 * Runs the launcher ONCE with its home env pointed at `stageDir`, which is unjailed scaffold time and
 * so may write anywhere, then copies the resulting `bin/` into `<observeDir>/node_modules/.bin`.
 *
 * @returns {{tool:string, staged:boolean, why:string|null, binaries:string[]}}
 */
export function prestageLauncher(tool, { observeDir, stageDir, env = process.env, run = spawnSync }) {
  const spec = SELF_DOWNLOADING[tool];
  if (!spec) return { tool, staged: false, why: 'not a self-downloading launcher', binaries: [] };
  const binDir = path.join(observeDir, 'node_modules', '.bin');
  const launcher = path.join(binDir, tool);
  if (!fs.existsSync(launcher)) return { tool, staged: false, why: 'the launcher is not in the arm .bin', binaries: [] };

  fs.mkdirSync(stageDir, { recursive: true });
  // `version` is the cheapest subcommand that still forces `resolve()` to download.
  const r = run(launcher, ['version'], {
    env: { ...env, [spec.homeEnv]: stageDir }, encoding: 'utf8', maxBuffer: 1 << 26,
  });
  const versions = path.join(stageDir, spec.versionsDir);
  if (!fs.existsSync(versions)) {
    const why = `${spec.homeEnv}=${stageDir} produced no ${spec.versionsDir}/ (rc=${r?.status ?? 'null'})`;
    return { tool, staged: false, why, binaries: [] };
  }
  // One version dir is the normal case; take the newest if a stage dir was reused.
  const dirs = fs.readdirSync(versions).map((v) => path.join(versions, v, 'bin')).filter((p) => fs.existsSync(p));
  if (!dirs.length) return { tool, staged: false, why: 'no bin/ under the staged version', binaries: [] };
  const binaries = copyBinDir(dirs.sort().at(-1), binDir);
  return { tool, staged: true, why: null, binaries };
}

/** The `driver.out` line. One per line — `driver.out` is parsed line-wise. */
export function prestageMarker(result) {
  return result.staged
    ? `ARM-SCAFFOLD-PRESTAGE ${result.tool} ${result.binaries.length} binaries into node_modules/.bin`
    : `ARM-SCAFFOLD-PRESTAGE ${result.tool} skipped (${result.why})`;
}
