// ⛔ THE TWO ARMS THAT DECIDE FAULT MUST HOLD THE SAME TOOLCHAIN.
//
// When every verify rung has failed, the driver asks the jail-off control whether nub can install
// the package at all. If nub fails there and npm succeeds, the record is filed BROKEN-UNJAILED-NUB:
// a nub install defect. That verdict is only as trustworthy as the claim that the two arms differ
// in NOTHING BUT THE SUBJECT — and three times now they have differed in something else.
//
//   epoch 4  — the npm reference arm ran undated on the harness toolchain
//   epoch 13 — every nub arm fell back to the runner's ambient Python
//   epoch 15 — this one: on Linux the control ran the RUNNER's Node while npm ran the era Node
//
// The Linux gap is structural rather than an oversight in one line. `measure.sh` NEVER modifies its
// own PATH — `ERA_PATH="$ERA_NODE_BIN:$PATH"` is a separate variable — so every arm opts in locally,
// and an arm that opts into nothing silently gets the runner's toolchain. Darwin was never exposed
// because `sudo` resets the environment and forced it to pass PATH explicitly; that protection was a
// side effect of the spawn strategy, not a decision, so Linux never received it.
//
// ⛔⛔ AND `--spawn-path` WAS ACCEPTED AND IGNORED THERE. `asIdentity` returns [cmd, args] unchanged
// when there is no sudo user, so the flag only ever reached the sudo `env` vector. Passing it from
// the Linux driver is therefore NOT sufficient on its own — the child env is what carries it — which
// is exactly the mistake epoch 13 half-made: it set PYTHON on the child env and left PATH behind, so
// node-gyp ran the era interpreter under the runner's Node, a combination no real install ever has.
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const HERE = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');

// The spawn helper inside the run phase, bounded by its own `spawn(` call — never the whole file,
// which mentions PATH in prose in at least four places that would satisfy a loose match.
function spawnSite(src) {
  const i = src.indexOf('const run = ({ cmd, args, cwd }) =>');
  assert.notEqual(i, -1, 'the run helper is gone — re-read unjailed-nub.mjs');
  const j = src.indexOf('let out = ', i);
  assert.notEqual(j, -1, 'the spawn site has been restructured — re-read it');
  return src.slice(i, j);
}

test('the control spawns its child with the era PATH, not the runner\'s', () => {
  const site = spawnSite(read('unjailed-nub.mjs'));
  assert.match(site, /--spawn-path/, 'the spawn site never reads --spawn-path');
  assert.match(site, /PATH: spawnPath/,
    'the child env does not carry PATH. On Linux and Windows `asIdentity` is a no-op, so the sudo '
    + 'env vector never runs and the child inherits the HARNESS toolchain — which is read as a nub '
    + 'install defect when the npm arm, holding the era toolchain, succeeds');
});

test('the control spawns its child with the era PYTHON too — both halves, or neither is safe', () => {
  const site = spawnSite(read('unjailed-nub.mjs'));
  assert.match(site, /PYTHON: python/,
    'the child env dropped PYTHON. Era Node with the ambient interpreter is the epoch-13 bug; era '
    + 'Python with the ambient Node is its mirror. The arm needs the whole toolchain or neither half.');
});

test('the linux driver hands the control the era PATH', () => {
  const src = read('measure.sh');
  const i = src.indexOf('\nunjailed_nub_ok () {');
  assert.notEqual(i, -1, 'unjailed_nub_ok is gone from the linux driver');
  const fn = src.slice(i, src.indexOf('\n}', i));
  assert.match(fn, /--spawn-path/,
    'the linux control is invoked without --spawn-path, so it inherits the driver\'s harness PATH');
  assert.match(fn, /ARM_PATH/,
    'the linux control should be handed the same ARM_PATH the verify rungs and npm_ok use');
});

test('the darwin driver still hands the control the era PATH', () => {
  // Two-sided on purpose: darwin has had this since the sudo work, and a refactor that "unified"
  // the two drivers by deleting the darwin flag would leave both arms wrong with the linux test green.
  const src = read('measure-macos.sh');
  const i = src.indexOf('\nunjailed_nub_ok () {');
  assert.notEqual(i, -1, 'unjailed_nub_ok is gone from the darwin driver');
  const fn = src.slice(i, src.indexOf('\n}', i));
  assert.match(fn, /--spawn-path/, 'the darwin control lost --spawn-path');
});

test('the control prints what nub actually said before accusing it', () => {
  const src = read('unjailed-nub.mjs');
  const i = src.indexOf("console.log('  jail-off control: nub failed with the jail OFF");
  assert.notEqual(i, -1, 'the consult-npm branch is gone — re-read unjailed-nub.mjs');
  const branch = src.slice(i, src.indexOf('process.exit(CONSULT_NPM)', i));
  assert.match(branch, /result\.nub\.logs/,
    'the branch that goes on to accuse nub does not print the arm\'s own output. It is captured and '
    + 'then written into a scratch dir that is discarded, so a real defect and a harness asymmetry '
    + 'leave identical records — measured on linux-x64 @stdlib/math-base-special-signum@0.0.6');
  assert.match(branch, /slice\(-20\)/, 'the printed tail is unbounded — print a tail, not the whole log');
});

// ⛔ AND THE SAME IDENTITY, WHICH IS THE OTHER HALF OF "NOTHING BUT THE SUBJECT".
//
//   epoch 82 — the darwin npm reference arm ran as ROOT while every arm it is compared against runs
//              as $RUNUSER, and its `mktemp -d` tree was root-owned 0700. npm de-escalates the
//              lifecycle child off root; that child could not search its own cwd and died in
//              `getcwd()` — `Error: EACCES: permission denied, uv_cwd` — before running a line of
//              the package's script.
//
// The direction is the dangerous one: a spurious failure in THIS arm exonerates nub and files a
// candidate nub defect as a dead package. MEASURED on the committed corpus at the time of the fix:
// all 55 darwin records that reached this branch are BROKEN-WITHOUT-JAIL-TOO and NOT ONE is
// BROKEN-UNJAILED-NUB, against 27 of 97 on linux — the driver that never runs as root.
//
// Scoped to darwin ON PURPOSE. `measure.sh` never drops privileges, so its reference arm already
// shares the arms' identity; `measure-windows.mjs` cannot reach this mechanism because npm does not
// de-escalate on win32. A blanket three-driver assertion here would be a false parity claim.
function npmOkBody(src) {
  const i = src.indexOf('      npm_ok () {');
  assert.notEqual(i, -1, 'npm_ok is gone from the darwin driver — re-read measure-macos.sh');
  const j = src.indexOf('# ⛔ ONE `=>` LINE PER PATH', i);
  assert.notEqual(j, -1, 'the npm_ok branch has been restructured — re-read it');
  return src.slice(i, j);
}

test('the darwin reference arm hands its tree to the user that will run in it', () => {
  assert.match(npmOkBody(read('measure-macos.sh')), /chown -R "\$RUNUSER" "\$d"/,
    'npm_ok leaves its `mktemp -d` tree root-owned and 0700. npm de-escalates the lifecycle child '
    + 'off root, and that child then cannot getcwd() — the arm dies with EACCES/uv_cwd before the '
    + 'package runs, and the failure is read as "npm cannot install this either"');
});

test('the darwin reference arm drops to $RUNUSER, and only when it is actually root', () => {
  const fn = npmOkBody(read('measure-macos.sh'));
  assert.match(fn, /sudo -u "\$RUNUSER"/,
    'npm_ok still spawns npm as root, so it runs as a user no arm it is compared against runs as');
  assert.match(fn, /id -u/,
    'the drop is ungated. The ladder suites drive both branches of this control with a shell '
    + 'function `npm () { return $rc; }`, and `sudo … env npm` EXECS a binary that cannot see one — '
    + 'so an unconditional drop takes the REAL npm and the suite goes red against the network');
});

// The mechanism itself, executed rather than asserted about: this is WHY the chown above is
// load-bearing. If Node ever stopped failing this way the guard above would be protecting nothing.
test('a process that cannot search its cwd dies exactly the way the corpus records show', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'uvcwd-'));
  const inner = path.join(d, 'inner');
  fs.mkdirSync(inner);
  const probe = path.join(d, 'probe.js');
  fs.writeFileSync(probe, 'try{process.cwd();console.log("OK")}catch(e){console.log(e.code+" "+e.syscall)}');
  try {
    // The child must already BE in the directory when it becomes unsearchable — which is the arm's
    // situation exactly. Chmod-then-spawn cannot reproduce it: the parent fails to chdir and the
    // spawn errors before Node ever starts.
    const r = spawnSync('sh', ['-c', 'cd "$1" && chmod 000 . && exec "$2" "$3"', 'sh',
      inner, process.execPath, probe], { encoding: 'utf8' });
    assert.match(`${r.stdout}`, /EACCES uv_cwd/,
      'an unsearchable cwd no longer produces EACCES/uv_cwd — re-derive what the darwin arm was dying of');
  } finally {
    fs.chmodSync(inner, 0o755);
    fs.rmSync(d, { recursive: true, force: true });
  }
});
