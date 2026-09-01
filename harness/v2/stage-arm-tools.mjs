// Put the fixture's tool bin INSIDE the arm's project, because that is the only place the build
// jail grants execute.
//
// ⛔⛔ THE DEFECT THIS CLOSES, MEASURED ON A REAL KERNEL RATHER THAN ARGUED. `arm-path.mjs` puts
// `<observeDir>/node_modules/.bin` first on the arm PATH and its own doc comment calls it "the
// fixture's own node_modules/.bin". That is true of the OBSERVE arm, whose cwd IS the observe tree
// and which runs unjailed. It is FALSE of every `verify-*` arm: those run in `$ROOT/verify-<label>`,
// a SIBLING of `$ROOT/observe`, so the tool sits outside the project the jail grants.
//
// nub's build jail grants `<project>/package.json` and `<project>/node_modules` as read subtrees
// (`compiler/preset.rs`, `grant_build_jail_dependency_reads`) and a Landlock read grant carries
// EXECUTE (`LandlockAccess::ReadExecute`). Nothing grants a sibling directory. So a scaffolded tool
// is refused at `execve` with `EACCES`, which `dash` reports as `Permission denied` and exit 126 —
// indistinguishable, in the ladder, from the package needing a wider grant.
//
// Measured on kernel 6.17 / Landlock ABI 7 with nub at `30757a70`, one local package whose `install`
// script is the single word `mytool`, every arm at the EMPTY grant:
//
//   <project>/node_modules/.bin/mytool                          rc=0  ran
//   <project>/node_modules/.harness-tools/node_modules/.bin     rc=0  ran        <- what this stages
//   $ROOT/side/bin/mytool                                       rc=1  126 Permission denied
//   $ROOT/observe/node_modules/.bin + project $ROOT/verify-x    rc=1  126 Permission denied
//
// The first two rows are the positive control: the instrument can produce rc=0, so the denials are
// real rather than some other upstream failure.
//
// ⛔ A SYMLINK INTO THE OBSERVE TREE IS NOT A FIX, AND IT IS THE OBVIOUS ONE. Landlock evaluates the
// RESOLVED path, so `<project>/node_modules/.bin/x -> $ROOT/observe/...` is refused exactly as the
// original was — measured, same fixture, 126. The tool's bytes have to be reachable through a
// granted path, which is why this mirrors rather than links across.
//
// ⛔ AND IT MUST BE A DOT-DIRECTORY. nub's install PRUNES an extraneous top-level entry from
// `node_modules`: a plain `node_modules/toolpkg` staged before the measured install was gone by the
// time the script ran, leaving a dangling `.bin` symlink and exit 127. A dot-directory survives —
// measured both ways in the same run.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Where a staged tree lives inside an arm. Under `node_modules` because that is the granted
 *  subtree; dot-prefixed because that is what survives nub's prune. */
export const STAGE_REL = path.join('node_modules', '.harness-tools');

/** The bin directory an arm should put first on its PATH once `stageArmTools` has run. */
export function stagedBinDir(armDir) {
  return path.join(armDir, STAGE_REL, 'node_modules', '.bin');
}

/** Mirror `src` into `dest`, preferring hardlinks so a large fixture tree costs inodes and not bytes.
 *
 *  Symlinks that stay INSIDE `src` are recreated verbatim, because an npm `.bin` entry is a relative
 *  link and the script it points at reads `__dirname` — materializing the target under the link's own
 *  name would move the script and break its own `require`s. A link escaping `src` is materialized
 *  instead: recreating it would point back out of the granted subtree, which is the failure this
 *  module exists to remove. */
export function mirrorTree(src, dest, tally = { files: 0, linked: 0, copied: 0, symlinks: 0 }, root = src) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      mirrorTree(from, to, tally, root);
      continue;
    }
    if (entry.isSymbolicLink()) {
      const target = fs.readlinkSync(from);
      const resolved = path.resolve(path.dirname(from), target);
      // ⛔ AGAINST THE MIRROR ROOT, NEVER `src` — `src` is the CURRENT directory under recursion, so
      // the check read `<root>/node_modules/bower/...`.startsWith(`<root>/node_modules/.bin`) and
      // called every `.bin` entry an escape. Caught by the first test written against this module:
      // it materialized the whole `.bin`, which silently moves each shim away from its own package.
      const inside = resolved === root || resolved.startsWith(root + path.sep);
      if (inside) {
        try {
          fs.symlinkSync(target, to);
          tally.symlinks++;
          continue;
        } catch { /* Windows without developer mode: fall through and materialize. */ }
      }
      // Materialize whatever the link resolves to. A dangling or directory target is skipped —
      // it cannot be executed anyway, and a throw here would cost the whole arm.
      try {
        if (!fs.statSync(resolved).isFile()) continue;
      } catch { continue; }
      materialize(resolved, to, tally);
      continue;
    }
    if (!entry.isFile()) continue;
    materialize(from, to, tally);
  }
  return tally;
}

function materialize(from, to, tally) {
  tally.files++;
  try {
    fs.linkSync(from, to);
    tally.linked++;
  } catch {
    // EXDEV, EPERM, or a filesystem with no hardlinks. Bytes cost more than inodes; correctness
    // costs neither.
    try {
      fs.copyFileSync(from, to);
      tally.copied++;
    } catch { tally.files--; }
  }
}

/** Stage the observe tree's tools into `armDir` so the jailed arm can execute them.
 *
 *  Returns `{ binDir: null }` when there is nothing to stage — an observe tree that never
 *  materialized, or one with no `.bin` at all. A driver treats that as "leave the PATH alone",
 *  never as an error: the arm is then exactly as badly off as it is today, and no worse. */
export function stageArmTools({ observeDir, armDir }) {
  const src = path.join(observeDir, 'node_modules');
  const bin = path.join(src, '.bin');
  let entries = [];
  try { entries = fs.readdirSync(bin); } catch { /* no bin, nothing to stage */ }
  if (!entries.length) {
    return { binDir: null, staged: 0, tally: null, marker: 'ARM-TOOLS none (observe tree has no .bin)' };
  }
  const dest = path.join(armDir, STAGE_REL, 'node_modules');
  const tally = mirrorTree(src, dest);
  const binDir = path.join(dest, '.bin');
  const mode = tally.copied ? (tally.linked ? 'hardlink+copy' : 'copy') : 'hardlink';
  return {
    binDir,
    staged: entries.length,
    tally,
    marker: `ARM-TOOLS staged ${entries.length} bin entr${entries.length === 1 ? 'y' : 'ies'} `
      + `(${tally.files} files, ${tally.symlinks} symlinks, ${mode}) into ${STAGE_REL}`,
  };
}

/** The arm PATH with the observe tree's bin swapped for the staged one.
 *
 *  A SWAP rather than a prepend: leaving the observe entry on the PATH would let a tool resolve
 *  from the ungranted copy on the venue where it happens to be reachable — which is precisely the
 *  accident that made a whole-home grant look like a package's capability need. */
export function stagedArmPath(armPath, observeDir, binDir, sep = path.delimiter) {
  const observeBin = path.join(observeDir, 'node_modules', '.bin');
  const kept = armPath.split(sep).filter(Boolean).filter((e) => e !== observeBin);
  return [binDir, ...kept].join(sep);
}

// ⛔ `fileURLToPath`, NEVER `new URL(...).pathname` — that spelling yields `/C:/…` on Windows and
// the CLI branch then never runs. Realpath-compared because macOS `/tmp` is a symlink to `/private/tmp`.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? undefined : process.argv[i + 1]; };
  const observeDir = arg('observe'); const armDir = arg('arm'); const armPath = arg('arm-path') ?? '';
  if (!observeDir || !armDir) {
    process.stderr.write('usage: stage-arm-tools.mjs --observe <dir> --arm <dir> [--arm-path <PATH>]\n');
    process.exit(2);
  }
  const r = stageArmTools({ observeDir, armDir });
  process.stdout.write(`${JSON.stringify({
    binDir: r.binDir,
    armPath: r.binDir ? stagedArmPath(armPath, observeDir, r.binDir) : armPath,
    staged: r.staged,
    marker: r.marker,
  })}\n`);
}
