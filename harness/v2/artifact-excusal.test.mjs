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
import os from 'node:os';
import path from 'node:path';
import {
  TOOLCHAIN_GENERATED,
  PACKAGING_METADATA,
  isToolchainGenerated,
  isPackagingMetadata,
  excusesSizeDifference,
} from './artifact-excusal.mjs';

const HERE = import.meta.dirname;
const WINDOWS_DRIVER = fs.readFileSync(path.join(HERE, 'measure-windows.mjs'), 'utf8');

// Execute the driver's real manifest/comparison bodies without importing the
// driver (which starts a Windows workload at module evaluation). The injected
// collaborators are its existing imports; no package manager or lifecycle
// script is run by this test.
const windowsManifestFunctions = (source = WINDOWS_DRIVER) => {
  const start = source.indexOf('const pkgDir =');
  const end = source.indexOf('// Do not generalize this into a postinstall executable scanner.', start);
  assert.ok(start >= 0 && end > start, 'could not locate the Windows manifest functions under test');
  const body = source.slice(start, end);
  return new Function('fs', 'path', 'isLog', 'isPackagingMetadata', 'excusesSizeDifference',
    `${body}\nreturn { pkgDir, pkgManifest, missingArtifacts };`)(
    fs, path, (p) => /\.log$|cat\.json$|nub\.jsonc$|package-lock\.json$/.test(p),
    isPackagingMetadata, excusesSizeDifference);
};

const windowsTree = (root, files) => {
  for (const [rel, contents] of Object.entries(files)) {
    const file = path.join(root, 'node_modules', 'fixture-pkg', rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
};

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

test('the real Windows manifest ignores nested packaging metadata but not `.npmrc` or build output', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'win-manifest-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const observed = path.join(root, 'observed');
  const arm = path.join(root, 'arm');
  windowsTree(observed, {
    'index.js': 'source',
    'deps/cpu_features/.npmignore': 'generated',
    '.npmrc': '//registry:_authToken=token',
    'build/Release/fixture.node': 'REAL-OUTPUT',
  });
  windowsTree(arm, { 'index.js': 'source' });

  const compare = (functions) => functions.missingArtifacts(
    functions.pkgManifest(observed, 'fixture-pkg', '1.0.0'),
    functions.pkgManifest(arm, 'fixture-pkg', '1.0.0'),
  );
  const actual = windowsManifestFunctions();
  assert.deepEqual(compare(actual).sort(), ['.npmrc', 'build/Release/fixture.node'],
    'the executed driver must ignore nested .npmignore but retain credentials and real output');

  const withoutMetadataFilter = windowsManifestFunctions(WINDOWS_DRIVER.replace(
    'if (isPackagingMetadata(e.name)) continue;',
    '// withheld metadata filter',
  ));
  assert.ok(compare(withoutMetadataFilter).includes('deps/cpu_features/.npmignore'),
    'CONTROL: the pre-fix manifest must report the nested packaging file');

  windowsTree(arm, { '.npmrc': '//registry:_authToken=token', 'build/Release/fixture.node': '' });
  const guarded = compare(actual);
  assert.ok(!guarded.includes('deps/cpu_features/.npmignore'), 'metadata remains excluded after arm changes');
  assert.ok(!guarded.includes('.npmrc'), 'present credential metadata is not a false failure');
  assert.ok(guarded.includes('build/Release/fixture.node (0B < 11B)'),
    'an empty real build output must remain a failure');
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
