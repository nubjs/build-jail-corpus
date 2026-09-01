// The tool bin has to sit inside the arm's project, because that is the only place the jail grants
// execute. These tests pin the three properties that were each measured on a real Landlock kernel
// before being encoded here — see `stage-arm-tools.mjs` for the fixture matrix.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { stageArmTools, stagedArmPath, stagedBinDir, STAGE_REL } from './stage-arm-tools.mjs';

const HERE = import.meta.dirname;

/** An observe tree shaped like npm's: a package with a bin, and a relative `.bin` link to it. */
function observeTree() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'stagetools-'));
  const nm = path.join(d, 'node_modules');
  fs.mkdirSync(path.join(nm, 'bower', 'bin'), { recursive: true });
  fs.mkdirSync(path.join(nm, '.bin'), { recursive: true });
  fs.writeFileSync(path.join(nm, 'bower', 'bin', 'bower'), '#!/usr/bin/env node\n');
  fs.writeFileSync(path.join(nm, 'bower', 'lib.js'), 'module.exports = 1;\n');
  fs.symlinkSync(path.join('..', 'bower', 'bin', 'bower'), path.join(nm, '.bin', 'bower'));
  return d;
}

test('stages the observe tree under the arm project, keeping the relative .bin link intact', () => {
  const observeDir = observeTree();
  const armDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stagearm-'));
  const r = stageArmTools({ observeDir, armDir });

  assert.equal(r.binDir, stagedBinDir(armDir), 'the bin dir the drivers put on PATH');
  assert.ok(r.binDir.startsWith(path.join(armDir, 'node_modules')),
    `staged outside the granted subtree: ${r.binDir}`);
  // ⛔ THE LINK IS RECREATED, NOT MATERIALIZED. An npm `.bin` entry is a relative symlink and the
  // script it points at reads `__dirname`; copying the target under the link's own name moves the
  // script and breaks its own `require`s.
  const link = path.join(r.binDir, 'bower');
  assert.ok(fs.lstatSync(link).isSymbolicLink(), 'the .bin entry must stay a symlink');
  assert.equal(fs.readFileSync(link, 'utf8'), '#!/usr/bin/env node\n', 'and it must resolve');
  assert.ok(fs.realpathSync(link).startsWith(fs.realpathSync(armDir)),
    'the link must resolve INSIDE the arm — a target outside it is refused at exec exactly as the '
    + 'unstaged copy was');
});

test('a link escaping the observe tree is materialized, never recreated', () => {
  // Recreating it would point back out of the granted subtree, which is the failure being removed.
  const observeDir = observeTree();
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'stageout-'));
  fs.writeFileSync(path.join(outside, 'grunt'), '#!/bin/sh\n');
  fs.symlinkSync(path.join(outside, 'grunt'), path.join(observeDir, 'node_modules', '.bin', 'grunt'));
  const armDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stagearm-'));
  const r = stageArmTools({ observeDir, armDir });
  const staged = path.join(r.binDir, 'grunt');
  assert.ok(!fs.lstatSync(staged).isSymbolicLink(), 'an escaping link must not survive as a link');
  assert.equal(fs.readFileSync(staged, 'utf8'), '#!/bin/sh\n');
});

test('the arm PATH SWAPS the observe bin out rather than prepending the staged one', () => {
  // Leaving the observe entry on the PATH lets a tool resolve from the ungranted copy on whichever
  // venue happens to reach it — the accident that made a whole-home grant look like a package need.
  const observeDir = '/tmp/obs';
  const observeBin = path.join(observeDir, 'node_modules', '.bin');
  const armBin = '/tmp/arm/node_modules/.harness-tools/node_modules/.bin';
  const before = [observeBin, '/era/bin', '/usr/bin'].join(path.delimiter);
  const after = stagedArmPath(before, observeDir, armBin).split(path.delimiter);
  assert.deepEqual(after, [armBin, '/era/bin', '/usr/bin']);
  assert.ok(!after.includes(observeBin), 'the ungranted copy must not stay reachable');
});

test('an observe tree with no .bin stages nothing and leaves the PATH alone', () => {
  const observeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stagenobin-'));
  const armDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stagearm-'));
  const r = stageArmTools({ observeDir, armDir });
  assert.equal(r.binDir, null);
  assert.match(r.marker, /ARM-TOOLS none/);
  assert.ok(!fs.existsSync(path.join(armDir, STAGE_REL)), 'nothing staged means nothing created');
});

test('⛔ ALL THREE DRIVERS STAGE — the guard that makes landed mean landed', () => {
  // `dep-scaffold.mjs` records two v2 fixes wired into one driver and mistaken for done. A fix that
  // reaches only Linux produces a platform-split result that reads as a real finding.
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('stage-arm-tools.mjs'),
      `${d} does not stage the arm's tools — a scaffolded tool is unexecutable there`);
  }
});
