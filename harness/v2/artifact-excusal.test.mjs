// The artifact-shortfall excusal must be ONE implementation shared by every driver that decides it.
//
// ⛔ WHY THIS EXISTS. `measure-windows.mjs` carried its own `missingArtifacts` with NO toolchain
// excusal, so every Windows record counted the node-gyp output family as shortfall while both POSIX
// drivers excused it. Found while chasing the corpus's only `write:"disk"` grant, and the two failed
// predictions before it were both spent theorising about the grant rather than checking whether the
// gate was the same gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { TOOLCHAIN_GENERATED, isToolchainGenerated, excusesSizeDifference } from './artifact-excusal.mjs';

const HERE = import.meta.dirname;

test('a regenerated toolchain file may shrink; an EMPTY one may not', () => {
  // The envelope is the safety property. Both halves asserted together, because dropping the second
  // is exactly how an excusal list turns into a blindfold.
  assert.equal(excusesSizeDifference('build/config.gypi', 400), true, 'a non-empty regenerated file is excused');
  assert.equal(excusesSizeDifference('build/config.gypi', 0), false,
    'a ZERO-BYTE file is the truncated/blocked shape the gate exists to catch — never excused');
  assert.equal(excusesSizeDifference('lib/binding.node', 400), false, 'a real build artifact is never excused');
});

test('the shrinkwrap case that motivated the fix is matched at a NESTED path', () => {
  // `postman-code-generators` vendors its codegens inside its own tree, so the real paths are nested.
  // A pattern anchored only at the string start would silently miss every one of them.
  assert.equal(isToolchainGenerated('codegens/csharp-restsharp/npm-shrinkwrap.json'), true);
  assert.equal(isToolchainGenerated('npm-shrinkwrap.json'), true);
  assert.equal(isToolchainGenerated('docs/not-a-shrinkwrap.json'), false);
});

test('the node-gyp output family is present — the part Windows was missing entirely', () => {
  // Named explicitly so a future trim of the list fails here rather than in the corpus.
  for (const f of ['build/config.gypi', 'build/Makefile', 'build/nothing.target.mk',
    'build/Release/.deps/x.d', 'build/Release/obj.target/a.o']) {
    assert.equal(isToolchainGenerated(f), true, `${f} must be excused — both POSIX drivers already do`);
  }
  assert.ok(TOOLCHAIN_GENERATED.length >= 8, 'the list must not be silently emptied');
});

// ⛔ THE BUILD DIRECTORY IS NOT ALWAYS CALLED `build/`, AND ANCHORING ON THAT NAME MANUFACTURED
// `NO-STATE-PASSED` — the harness's strongest possible claim about a package — for installs that
// exited rc=0 with 100% of their artifacts present.
test('a build directory that is not named `build/` is still the toolchain\'s', () => {
  // node-pre-gyp builds each NAPI target in `build-tmp-napi-v<N>/`. Same generator, same file, same
  // reason to excuse it. MEASURED: @tensorflow/tfjs-node@4.22.0 (darwin, v8) and @discordjs/opus@0.10.0
  // (linux, v3), both rc=0 with every artifact present and this as the SOLE shortfall.
  assert.equal(isToolchainGenerated('build-tmp-napi-v8/config.gypi'), true);
  assert.equal(isToolchainGenerated('build-tmp-napi-v3/config.gypi'), true);
  // ⛔ AND THE WHOLE FAMILY, NOT JUST `config.gypi`. A narrower first cut of this fix excused only
  // `config.gypi`; re-measuring @discordjs/opus@0.10.0 at the pinned Nub under that rule produced
  // `rc=0 artifacts=750/750 missing=161`, every entry a merely-shorter `.o.d` at the SAME unanchored
  // directory. Fixing one file at a time moves the shortfall to the next member of the family.
  assert.equal(isToolchainGenerated(
    'build-tmp-napi-v3/Release/.deps/Release/obj.target/libopus/deps/opus/celt/bands.o.d'), true);
  assert.equal(isToolchainGenerated('build-tmp-napi-v3/Makefile'), true);
  assert.equal(isToolchainGenerated('build-tmp-napi-v8/nothing.target.mk'), true);
  assert.equal(isToolchainGenerated('build-tmp-napi-v8/Release/obj.target/a.o'), true);
  // CMake's configure transcript, which was absent from the list entirely. Anchored on `CMakeFiles/`
  // rather than on `build/` for the same reason the case above exists.
  assert.equal(isToolchainGenerated('build/CMakeFiles/CMakeConfigureLog.yaml'), true);
  assert.equal(isToolchainGenerated('build-tmp-napi-v8/CMakeFiles/CMakeConfigureLog.yaml'), true);
  // The ninja generator's `build/Makefile`.
  assert.equal(isToolchainGenerated('build/build.ninja'), true);
});

test('⛔ CONTROL: the widened anchors did not swallow anything they should still compare', () => {
  // Each of these is one plausible over-generalisation of the three patterns added above, and each
  // would hide a real shortfall. Pinned so a future widening has to break a named assertion.
  assert.equal(isToolchainGenerated('build-tmp-napi-v8/Release/binding.node'), false,
    'the linked addon is never excused, whatever the build directory is called');
  assert.equal(isToolchainGenerated('config.gypi'), false,
    'the anchor is a BUILD directory, not any config.gypi anywhere in the tree');
  assert.equal(isToolchainGenerated('build-tmp/config.gypi'), false,
    'only node-pre-gyp\'s versioned napi directory, not any build-tmp-ish name');
  assert.equal(isToolchainGenerated('CMakeConfigureLog.yaml'), false,
    'the anchor is CMake\'s own generated CMakeFiles/ directory');
  assert.equal(isToolchainGenerated('src/build.ninja'), false,
    'a ninja file outside build/ was not written by the configure step');
});

test('⛔ CONTROL: the three classes measured and deliberately NOT excused stay unexcused', () => {
  // ⛔ THESE ARE THE DIRECTION THAT UNDER-GRANTS, so they are asserted rather than left to a comment.
  // `CMakeCache.txt` belongs by mechanism but its only corpus sightings sit beside 1,725-4,315
  // genuinely ABSENT files, so excusing it changes no verdict and only widens the gate.
  assert.equal(isToolchainGenerated('build/CMakeCache.txt'), false);
  // gyp's node-addon-api sub-targets appear in the corpus 161 times and ALWAYS as ABSENT entries — a
  // layout difference that relocates the file, which is a manifest-walk defect, not a size excusal.
  assert.equal(isToolchainGenerated('node-addon-api/node_api.Makefile'), false);
  assert.equal(isToolchainGenerated('node-addon-api/nothing.target.mk'), false);
  // vue-demi rewrites its own entry points per installed Vue major: package-owned source, not a
  // toolchain record.
  assert.equal(isToolchainGenerated('lib/index.cjs'), false);
  assert.equal(isToolchainGenerated('lib/index.d.ts'), false);
});

test('⭑⭑ EVERY driver that decides shortfall uses the shared module — none re-implements it', () => {
  // ⛔ THE GUARD THAT MAKES "LANDED" MEAN LANDED. This is the third fix this effort to reach one
  // driver and be mistaken for done. A file that grows its own excusal (or, worse, omits one while
  // still comparing sizes) fails here rather than in the corpus hours later.
  const DECIDERS = ['artifact-gate.mjs', 'measure-windows.mjs'];
  for (const d of DECIDERS) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.match(src, /artifact-excusal\.mjs/, `${d} must take its excusal from the shared module`);
    // Comments are stripped so the prose explaining the old inline list does not satisfy the guard.
    const code = src.split('\n').filter((l) => !/^\s*(\/\/|#)/.test(l)).join('\n');
    assert.doesNotMatch(code, /const\s+TOOLCHAIN_GENERATED\s*=/,
      `${d} declares its own excusal list — that is the exact drift this module exists to prevent`);
  }
});

test('⭑ CONTROL: the guard detects the pre-fix shape, so it is not passing vacuously', () => {
  const preFix = 'const TOOLCHAIN_GENERATED = [\n  /(^|\\/)build\\/config\\.gypi$/,\n];';
  assert.match(preFix, /const\s+TOOLCHAIN_GENERATED\s*=/, 'the guard pattern must match the real pre-fix code');
  // And the comment-stripper must not be what saves a real declaration.
  const stripped = preFix.split('\n').filter((l) => !/^\s*(\/\/|#)/.test(l)).join('\n');
  assert.match(stripped, /const\s+TOOLCHAIN_GENERATED\s*=/, 'stripping comments must not hide a real declaration');
});
