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

test('both production Windows measurement paths activate MSVC before running the harness', () => {
  const measureStart = referenceWorkflow.indexOf('Capture the fixed harness runtime');
  const referenceActivation = referenceWorkflow.indexOf('harness/v2/activate-msvc.ps1', measureStart);
  const referenceTests = referenceWorkflow.indexOf('harness/run-tests.mjs', measureStart);
  assert.equal([...referenceWorkflow.matchAll(/harness\/v2\/activate-msvc\.ps1/g)].length, 2);
  assert.ok(referenceActivation > measureStart);
  assert.ok(referenceActivation < referenceTests);

  for (const [label, workflow] of [['corpus runner', corpusWorkflow]]) {
    const activation = workflow.indexOf('harness/v2/activate-msvc.ps1');
    const tests = workflow.indexOf('harness/run-tests.mjs');
    assert.ok(activation >= 0, `${label}: activation step is absent`);
    assert.ok(activation < tests, `${label}: activation must precede the harness and package measurement`);
  }
});
