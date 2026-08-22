import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const here = import.meta.dirname;
const source = fs.readFileSync(path.join(here, 'activate-msvc.ps1'), 'utf8');
const referenceWorkflow = fs.readFileSync(path.join(here, '../../.github/workflows/reference-accounting.yml'), 'utf8');
const corpusWorkflow = fs.readFileSync(path.join(here, '../../.github/workflows/corpus-v2-runner.yml'), 'utf8');
const observeWorkflow = fs.readFileSync(path.join(here, '../../.github/workflows/observe-only.yml'), 'utf8');
const referenceProfiles = fs.readdirSync(here)
  .filter((name) => /^reference-profile(?:-[^.]+)*\.json$/.test(name))
  .map((name) => [name, fs.readFileSync(path.join(here, name), 'utf8')]);

test('MSVC activation locates the C++ workload and pins Cargo to its linker', () => {
  assert.match(source, /Microsoft\.VisualStudio\.Component\.VC\.Tools\.x86\.x64/);
  assert.match(source, /VsDevCmd\.bat/);
  for (const name of ['Path', 'INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VSINSTALLDIR',
    'WindowsSdkDir', 'VCToolsInstallDir', 'UCRTVersion', 'WindowsSDKVersion']) {
    assert.match(source, new RegExp(`['"]${name}['"]`), name);
  }
  assert.match(source, /Join-Path \$values\['VCToolsInstallDir'\] 'bin\\HostX64\\x64\\link\.exe'/);
  assert.match(source, /CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=/);
  for (const [name, profile] of referenceProfiles) {
    assert.doesNotMatch(profile, /CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER/, name);
  }
  assert.doesNotMatch(source, /Get-ChildItem\s+Env:|\benv:\*|GITHUB_TOKEN|NPM_TOKEN/);
});

test('Windows CI activates MSVC before the one-time harness suite and both measurement paths', () => {
  const buildStart = referenceWorkflow.indexOf('\n  build:\n');
  const testStart = referenceWorkflow.indexOf('\n  test:\n');
  const measureStart = referenceWorkflow.indexOf('Capture the fixed harness runtime');
  const buildActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', buildStart);
  const subjectBuild = referenceWorkflow.indexOf('cargo build -p nub-cli', buildStart);
  const testActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', testStart);
  const referenceTests = referenceWorkflow.indexOf('harness/run-tests.mjs', testStart);
  const referenceActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', measureStart);
  assert.equal([...referenceWorkflow.matchAll(/harness\/v2\/activate-msvc\.ps1/g)].length, 3);
  assert.ok(buildActivation > buildStart);
  assert.ok(buildActivation < subjectBuild);
  assert.ok(testActivation > testStart);
  assert.ok(testActivation < referenceTests);
  assert.ok(referenceActivation > measureStart);

  // ⛔ THE OBSERVE LANE IS IN THIS LIST BECAUSE IT WAS MISSING FOR A WHOLE SWEEP. 166 CONFIRMED rows
  // — 29% of the win32 population and the largest single failure family in the corpus — died on
  // `gyp ERR! find VS` while Visual Studio 18 sat installed on the runner, because node-gyp cannot
  // recognise a version that new and its PowerShell probe overruns its own stdout buffer. Exporting
  // VCINSTALLDIR makes node-gyp skip the detection. A lane that measures native builds on Windows
  // without activating MSVC files a runner-image artefact as a package defect.
  for (const [label, workflow] of [['corpus runner', corpusWorkflow], ['observe-only', observeWorkflow]]) {
    const activation = workflow.indexOf('harness/v2/activate-msvc.ps1');
    // The corpus runner activates before its own test suite; the observe lane has no suite, so the
    // thing activation must precede there is the sweep that runs third-party lifecycle scripts.
    const tests = label === 'observe-only'
      ? workflow.indexOf('observe-only.mjs --file')
      : workflow.indexOf('harness/run-tests.mjs');
    assert.ok(activation >= 0, `${label}: activation step is absent`);
    assert.ok(activation < tests, `${label}: activation must precede the harness and package measurement`);
  }
});
