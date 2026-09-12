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
import {
  TOOLCHAIN_GENERATED,
  PACKAGING_METADATA,
  isToolchainGenerated,
  isPackagingMetadata,
  excusesSizeDifference,
} from './artifact-excusal.mjs';

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

test('packaging metadata is shared and `.npmrc` remains visible', () => {
  assert.equal(isPackagingMetadata('.npmignore'), true);
  assert.equal(isPackagingMetadata('.gitignore'), true);
  assert.equal(isPackagingMetadata('.npmrc'), false,
    'credential-bearing npm configuration must remain in the manifest');
  assert.ok(PACKAGING_METADATA.has('.npmignore'));
});

test('the Windows package manifest applies the shared metadata rule', () => {
  const windows = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');
  const manifest = /const pkgManifest = \(base, pkg, ver\) => \{([\s\S]*?)\n\};\n\n\/\/ Returns the artifacts/.exec(windows)?.[1] ?? '';
  assert.match(manifest, /if \(isPackagingMetadata\(e\.name\)\) continue;/,
    'the comparison manifest, rather than only a diagnostic walk, must skip packaging metadata');
});

test('Windows object and tracking files may shrink but must remain nonempty', () => {
  for (const file of [
    'build/deps/cpu_features/Release/obj/cpu_features/deps/cpu_features/src/filesystem.obj',
    'build/deps/cpu_features/Release/obj/cpu_features/cpu_features.tlog/CL.read.1.tlog',
  ]) {
    assert.equal(excusesSizeDifference(file, 100), true, file);
    assert.equal(excusesSizeDifference(file, 0), false, file);
  }
  for (const file of ['vendor/payload.obj', 'vendor/payload.tlog',
    'build/Release/cpufeatures.node', 'build/Release/tool.exe', 'build/Release/tool.dll']) {
    assert.equal(excusesSizeDifference(file, 100), false, file);
  }
});

test('the node-gyp output family is present — the part Windows was missing entirely', () => {
  // Named explicitly so a future trim of the list fails here rather than in the corpus.
  for (const f of ['build/config.gypi', 'build/Makefile', 'build/nothing.target.mk',
    'build/Release/.deps/x.d', 'build/Release/obj.target/a.o']) {
    assert.equal(isToolchainGenerated(f), true, `${f} must be excused — both POSIX drivers already do`);
  }
  assert.ok(TOOLCHAIN_GENERATED.length >= 8, 'the list must not be silently emptied');
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
    assert.doesNotMatch(code, /const\s+PACKAGING_METADATA\s*=/,
      `${d} declares its own packaging-metadata list — that would let manifests drift`);
    assert.match(code, /isPackagingMetadata/,
      `${d} must apply the shared packaging-metadata decision to its manifest`);
  }
});

test('⭑ CONTROL: the guard detects the pre-fix shape, so it is not passing vacuously', () => {
  const preFix = 'const TOOLCHAIN_GENERATED = [\n  /(^|\\/)build\\/config\\.gypi$/,\n];';
  assert.match(preFix, /const\s+TOOLCHAIN_GENERATED\s*=/, 'the guard pattern must match the real pre-fix code');
  // And the comment-stripper must not be what saves a real declaration.
  const stripped = preFix.split('\n').filter((l) => !/^\s*(\/\/|#)/.test(l)).join('\n');
  assert.match(stripped, /const\s+TOOLCHAIN_GENERATED\s*=/, 'stripping comments must not hide a real declaration');
});
