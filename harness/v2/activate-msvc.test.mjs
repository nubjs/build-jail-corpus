import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const here = import.meta.dirname;
const source = fs.readFileSync(path.join(here, 'activate-msvc.ps1'), 'utf8');
const referenceWorkflow = fs.readFileSync(path.join(here, '../../.github/workflows/reference-accounting.yml'), 'utf8');
const corpusWorkflow = fs.readFileSync(path.join(here, '../../.github/workflows/corpus-v2-runner.yml'), 'utf8');

test('MSVC activation locates the C++ workload and exports only the profile build variables', () => {
  assert.match(source, /Microsoft\.VisualStudio\.Component\.VC\.Tools\.x86\.x64/);
  assert.match(source, /VsDevCmd\.bat/);
  for (const name of ['Path', 'INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VSINSTALLDIR',
    'WindowsSdkDir', 'VCToolsInstallDir', 'UCRTVersion', 'WindowsSDKVersion']) {
    assert.match(source, new RegExp(`['"]${name}['"]`), name);
  }
  assert.doesNotMatch(source, /Get-ChildItem\s+Env:|\benv:\*|GITHUB_TOKEN|NPM_TOKEN/);
});

test('Windows CI activates MSVC before the one-time harness suite and both measurement paths', () => {
  const testStart = referenceWorkflow.indexOf('\n  test:\n');
  const measureStart = referenceWorkflow.indexOf('Capture the fixed harness runtime');
  const testActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', testStart);
  const referenceTests = referenceWorkflow.indexOf('harness/run-tests.mjs', testStart);
  const referenceActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', measureStart);
  assert.equal([...referenceWorkflow.matchAll(/harness\/v2\/activate-msvc\.ps1/g)].length, 3);
  assert.ok(testActivation > testStart);
  assert.ok(testActivation < referenceTests);
  assert.ok(referenceActivation > measureStart);

  for (const [label, workflow] of [['corpus runner', corpusWorkflow]]) {
    const activation = workflow.indexOf('harness/v2/activate-msvc.ps1');
    const tests = workflow.indexOf('harness/run-tests.mjs');
    assert.ok(activation >= 0, `${label}: activation step is absent`);
    assert.ok(activation < tests, `${label}: activation must precede the harness and package measurement`);
  }
});
