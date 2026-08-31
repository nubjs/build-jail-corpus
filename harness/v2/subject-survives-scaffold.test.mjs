// ⛔⛔ THE SUBJECT MUST BE IN THE OBSERVE TREE, OR THERE IS NO MEASUREMENT. UNDER-PREDICTION GUARD.
//
// The observe arm is `npm rebuild <pkg>`. Run against a tree that does not contain `<pkg>`, it
// executes nothing, the decoder attributes zero lifecycle pids, and the synthesized grant is `{}` —
// byte-identical to the grant of a package that genuinely needs nothing. The record then lands as
// MINIMUM: "this package needs no permissions", asserted from a run that never happened.
//
// MEASURED 2026-08-31 over all 6,880 committed records, cross-tabulating `ARM-FALSIFIABILITY`'s
// `manifestFiles` (null exactly when `arm-falsifiability.mjs`'s `pkgDir()` finds no layout for the
// subject) against the `ARM-SCAFFOLD` marker beside it:
//
//   scaffold = 0   ->  5,279 records,    0 null
//   scaffold > 0   ->    340 records,   51 null   (37 linux, 14 darwin, 0 win32)
//
// Every null has a scaffold; no scaffold-free record is null; all 51 attributed zero pids; and all 51
// print `ARM-SCAFFOLD-INSTALL rc=0`, so the eviction is silent. `arm-prepare.mjs` derives the scaffold
// from the subject's INSTALLED manifest and prints `ARM-SCAFFOLD none` when that read fails, so the
// subject was present immediately before the scaffold install and gone immediately after it.
//
// ⛔ THE MECHANISM IS NOT ESTABLISHED AND THIS GUARD DOES NOT ASSUME ONE. All 37 linux cases were
// replayed with each record's own `--before` and scaffold specs under era npm 6.14.12, and 36 of 37
// kept the subject. What is pinned here is the INVARIANT the drivers now enforce instead: the subject
// is the thing under measurement, so it is the LAST thing written into the observe tree, and an arm
// whose tree lacks it REFUSES rather than measures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = import.meta.dirname;

/// An observe tree, with or without the subject installed in it.
const observeTree = (withSubject, pkg = 'p') => {
  const obs = fs.mkdtempSync(path.join(os.tmpdir(), 'subj-tree-'));
  // The scaffold closure is always there — it is the thing that survived.
  fs.mkdirSync(path.join(obs, 'node_modules', 'rollup'), { recursive: true });
  fs.writeFileSync(path.join(obs, 'scaffold.log'), 'added 137 packages in 2s\n');
  if (withSubject) {
    const own = path.join(obs, 'node_modules', ...pkg.split('/'));
    fs.mkdirSync(own, { recursive: true });
    fs.writeFileSync(path.join(own, 'package.json'), JSON.stringify({ name: pkg, version: '1.0.0' }));
  }
  return obs;
};

/// Run a POSIX driver's OWN refusal branch, lifted out of the file rather than paraphrased — a
/// paraphrase drifts from the thing it claims to cover, invisibly. The `npm install` re-install line
/// directly above it is asserted structurally instead, because executing it would need the network.
const runBranch = (driver, obs, pkg = 'p') => {
  const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
  // ⛔ ANCHORED ON THE SHAPE OF THE TEST, NOT ITS EXACT TEXT. A first version matched the whole
  // `if [ ! -d … ]; then` line, so mutating the CONDITION — the obvious way to prove this guard
  // bites — broke the extractor instead, and every test failed for the wrong reason. A red that
  // cannot distinguish "the logic changed" from "the anchor moved" proves nothing.
  const m = /^ {4}if \[ .*node_modules\/\$PKG.*\]; then$/m.exec(src);
  assert.notEqual(m, null, `${driver}: the subject-eviction branch is gone`);
  const start = m.index;
  const end = src.indexOf('\n    fi\n', start) + '\n    fi\n'.length;
  const body = src.slice(start, end);
  return execFileSync('bash', ['-c',
    `OBS=${JSON.stringify(obs)}\nPKG=${JSON.stringify(pkg)}\n${body}\n`
    + 'echo "REACHED-THE-ARM"'], { encoding: 'utf8' });
};

for (const driver of ['measure.sh', 'measure-macos.sh']) {
  test(`${driver} refuses an observe tree the subject is missing from`, () => {
    const gone = runBranch(driver, observeTree(false));
    assert.match(gone, /ARM-SUBJECT-EVICTED/, `${driver} did not report the eviction`);
    assert.match(gone, /=> UNKNOWN \(the subject is not in the observe tree/,
      `${driver} did not refuse a tree without the subject`);
    assert.doesNotMatch(gone, /REACHED-THE-ARM/,
      `${driver} carried on to the arm with no subject in the tree, so the empty grant will still be `
      + 'verified and can still land MINIMUM');
    // The tail of `scaffold.log` is the only artifact that could name the mechanism, and the corpus
    // does not keep the file — so it has to be printed here, on the runner where it happens.
    assert.match(gone, /added 137 packages/,
      `${driver} refused without printing the scaffold log, so the mechanism stays unobservable`);
  });

  // ⛔ THE CONTROL, AND IT IS THE HALF THAT MATTERS. A blanket refusal would turn every scaffolded
  // package — 340 records, 289 of them measured correctly — into a non-answer. That is exactly the
  // shape epoch 44 shipped and epoch 45 had to undo, so it is pinned here from the start.
  test(`${driver} leaves a tree that still holds the subject alone`, () => {
    const kept = runBranch(driver, observeTree(true));
    assert.match(kept, /REACHED-THE-ARM/,
      `${driver} refused a tree that DOES contain the subject — that erases a true measurement`);
    assert.doesNotMatch(kept, /ARM-SUBJECT-EVICTED|=> UNKNOWN/,
      `${driver} reported an eviction for a subject that is present`);
  });

  test(`${driver} handles a scoped subject, whose directory is two levels deep`, () => {
    const pkg = '@antv/g-base'; // one of the 51: `@antv/g-base@0.1.0-beta.1`, linux.
    assert.match(runBranch(driver, observeTree(true, pkg), pkg), /REACHED-THE-ARM/,
      `${driver} cannot see a scoped package that is present, so it would refuse every scoped subject`);
    assert.match(runBranch(driver, observeTree(false, pkg), pkg), /ARM-SUBJECT-EVICTED/,
      `${driver} missed an evicted scoped package`);
  });

  test(`${driver} re-installs the subject AFTER the scaffold, so it is the last write`, () => {
    // Structural: the re-install needs the network, so what is pinned is that it exists, that it
    // names the subject rather than the scaffold, and that it runs BEFORE the check above. Order is
    // the whole property — a re-install after the check would repair nothing.
    const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
    const scaffold = src.indexOf('ARM-SCAFFOLD-INSTALL rc=');
    const resubject = src.indexOf('"$OBS/resubject.log"');
    const check = src.search(/^ {4}if \[ .*node_modules\/\$PKG.*\]; then$/m);
    assert.notEqual(resubject, -1, `${driver}: the subject is no longer re-installed after the scaffold`);
    assert.notEqual(check, -1, `${driver}: the eviction check is gone`);
    assert.ok(scaffold < resubject && resubject < check,
      `${driver}: the re-install must sit between the scaffold install and the check, not at `
      + `${scaffold}/${resubject}/${check}`);
    assert.match(src.slice(resubject - 300, resubject), /"\$PKG@\$VER"/,
      `${driver}: the re-install does not name the subject`);
  });
}

test('the windows driver enforces the same invariant', () => {
  // ⛔ STRUCTURAL, AND SAYING SO. Running `measure-windows.mjs` end-to-end needs an ETW capture and a
  // Windows host. Win32 also has exactly ONE scaffolded record in the whole corpus, so there is no
  // win32 evidence to execute against — the guard exists because that lane has barely run, not
  // because it is known clean.
  const win = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  const scaffold = win.indexOf('ARM-SCAFFOLD-INSTALL rc=');
  const check = win.indexOf('if (!pkgDir(OBS, PKG, VER)) {');
  assert.notEqual(check, -1, 'measure-windows.mjs no longer checks that the subject survived');
  assert.ok(scaffold < check, 'the check must follow the scaffold install');

  const between = win.slice(scaffold, check);
  assert.match(between, /`\$\{PKG\}@\$\{VER\}`/,
    'measure-windows.mjs does not re-install the subject between the scaffold and the check');
  const branch = win.slice(check, check + 1400);
  assert.match(branch, /ARM-SUBJECT-EVICTED/);
  assert.match(branch, /=> UNKNOWN \(the subject is not in the observe tree/);
  assert.match(branch, /process\.exit\(0\)/,
    'measure-windows.mjs reports the eviction but does not stop, so the arm still runs');
});
