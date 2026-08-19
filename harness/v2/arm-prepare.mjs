// ONE entry point the three drivers call to prepare an observe arm: the PATH it runs under, the
// tools that leaked onto it anyway, and the packages its lifecycle scripts need in order to run.
//
// ⛔⛔ WHY A SINGLE CLI RATHER THAN THREE CALL SITES PER DRIVER. `dep-scaffold.mjs` records the two
// times a v2 fix landed in `measure.sh` alone and was mistaken for done — the dependency scaffold
// itself, and the `T3` no-state tripwire, each blind on the drivers that spell things differently.
// Two shell drivers and one JS driver cannot share a function, but they CAN share a process. This
// prints one JSON object; a driver that reads a field the others ignore is a drift bug, so the
// cross-driver test asserts all three consume the same keys.
//
//   usage: arm-prepare.mjs --observe <dir> --pkg <name> [--era-bin <dir>]
//   stdout: {"armPath":…,"dropped":[…],"ambientTools":{…},"scaffold":{…},"markers":[…]}
//
// ⛔ IT NEVER INSTALLS ANYTHING. It reports; the driver acts. Keeping the side effect in the driver
// is what lets the shell drivers keep their own `strace`/`sudo -u` spawn strategy, which
// `driver-invocation.mjs` already establishes is per-platform and must not be guessed centrally.

import fs from 'node:fs';
import path from 'node:path';
import { armPath, armPathMarker, ambientTools, ambientToolsMarker } from './arm-path.mjs';
import { scriptScaffold } from './script-scaffold.mjs';

/** Resolve `name` as an executable in `dirs`. Real filesystem; injected in tests. */
export function resolveInDirs(name, dirs) {
  for (const d of dirs) {
    for (const ext of process.platform === 'win32' ? ['.cmd', '.exe', '.bat', ''] : ['']) {
      const p = path.join(d, name + ext);
      try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* next */ }
    }
  }
  return null;
}

/** The installed manifest for `pkg` inside an observe tree, or null when the fetch did not land it. */
export function installedManifest(observeDir, pkg) {
  const p = path.join(observeDir, 'node_modules', ...pkg.split('/'), 'package.json');
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

/** Everything a driver needs to start an arm, as plain data.
 *
 *  ⛔ THE ORDER MATTERS AND IS NOT ARBITRARY. The PATH is sanitised FIRST, then probed, and the probe
 *  result is what tells the scaffold which binaries are already reachable. Computing the scaffold
 *  against the UNSANITISED path would let a leaked `tsc` suppress a scaffold entry that the arm then
 *  needs — the contamination would hide itself. */
export function prepareArm({ observeDir, pkg, eraBin = null, ambient = process.env.PATH ?? '', resolve = resolveInDirs }) {
  const fixtureBin = path.join(observeDir, 'node_modules', '.bin');
  const { armPath: value, dropped, kept } = armPath({ ambient, eraBin, fixtureBin });
  const leaked = ambientTools(value, { resolve });
  const manifest = installedManifest(observeDir, pkg);
  const scaffold = manifest
    ? scriptScaffold(manifest, { has: (bin) => bin in leaked })
    : { install: [], unprovidable: [], ambient: [], note: 'manifest absent — the fetch did not land the package' };
  return {
    armPath: value, dropped, kept, ambientTools: leaked, scaffold,
    markers: [
      armPathMarker({ dropped }),
      ambientToolsMarker(leaked),
      scaffold.install.length
        ? `ARM-SCAFFOLD ${scaffold.install.length} added: ${scaffold.install.join(' ')}`
        : 'ARM-SCAFFOLD none',
      scaffold.unprovidable?.length
        ? `ARM-UNPROVIDABLE ${scaffold.unprovidable.map((u) => `${u.bin} (${u.why})`).join('; ')}`
        : 'ARM-UNPROVIDABLE none',
    ],
  };
}

if (import.meta.filename === process.argv[1]) {
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? undefined : process.argv[i + 1]; };
  const observeDir = arg('observe'); const pkg = arg('pkg');
  if (!observeDir || !pkg) {
    process.stderr.write('usage: arm-prepare.mjs --observe <dir> --pkg <name> [--era-bin <dir>]\n');
    process.exit(2);
  }
  process.stdout.write(`${JSON.stringify(prepareArm({ observeDir, pkg, eraBin: arg('era-bin') ?? null }))}\n`);
}
