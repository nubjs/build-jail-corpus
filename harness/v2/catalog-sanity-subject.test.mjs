import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { FIXTURE_TIMEOUT_MS } from './catalog-sanity-budget.mjs';

const script = fileURLToPath(new URL('./catalog-sanity-subject.mjs', import.meta.url));

function fixture(t, failingSubject, engagedExit = 0, largeLog = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-sanity-subject-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const binArg = path.join(root, 'fake-nub.mjs');
  fs.writeFileSync(binArg, `const p = process.env.NUB_BUILD_JAIL_CATALOG ?? ''; if (p.endsWith('bad.json')) console.log('REJECTED'); else { console.log('OVERRIDDEN'); process.exitCode = ${engagedExit}; }\n`);
  const fixtures = path.join(root, 'fixtures'); fs.mkdirSync(fixtures);
  for (const name of ['packages', 'network', 'relocated-store']) {
    fs.writeFileSync(path.join(fixtures, `${name}.mjs`), `${largeLog && name === 'packages' ? "process.stdout.write('x'.repeat(1200000));" : ''} if (process.env.SUBJECT === ${JSON.stringify(failingSubject)}) process.exitCode = 1;\n`);
  }
  for (const name of ['catalog.json', 'bad.json']) fs.writeFileSync(path.join(root, name), '{}');
  return { root, bin: process.execPath, binArg, fixtures };
}

function run(f, subject) {
  const report = path.join(f.root, subject);
  const result = spawnSync(process.execPath, [script, '--subject', subject, '--bin', f.bin, '--bin-arg', f.binArg, '--catalog', path.join(f.root, 'catalog.json'), '--bad-catalog', path.join(f.root, 'bad.json'), '--fixtures', f.fixtures, '--report', report], { env: { ...process.env, SUBJECT: subject }, encoding: 'utf8' });
  return { result, report };
}

test('retains a failing candidate and still permits an independent baseline run', (t) => {
  const f = fixture(t, 'candidate');
  assert.equal(run(f, 'candidate').result.status, 1);
  const baseline = run(f, 'baseline');
  assert.equal(baseline.result.status, 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(baseline.report, 'result.json'))).fixtures.length, 3);
});

test('retains a failing baseline after an independent candidate succeeds', (t) => {
  const f = fixture(t, 'baseline');
  assert.equal(run(f, 'candidate').result.status, 0);
  const baseline = run(f, 'baseline');
  assert.equal(baseline.result.status, 1);
  assert.match(fs.readFileSync(path.join(baseline.report, 'packages.log'), 'utf8'), /(?:^|\n)/);
});

test('does not certify an OVERRIDDEN marker from a nonzero process', (t) => {
  const f = fixture(t, '', 7);
  const result = run(f, 'candidate');
  assert.equal(result.result.status, 1);
  assert.equal(JSON.parse(fs.readFileSync(path.join(result.report, 'result.json'))).override.engaged.status, 7);
  assert.equal(fs.existsSync(path.join(result.report, 'packages.log')), false);
});

test('streams a fixture log larger than spawnSync default buffering', (t) => {
  const f = fixture(t, '', 0, true);
  const result = run(f, 'candidate');
  assert.equal(result.result.status, 0);
  assert.ok(fs.statSync(path.join(result.report, 'packages.log')).size > 1024 * 1024);
  assert.equal(JSON.parse(fs.readFileSync(path.join(result.report, 'result.json'))).fixtures[0].timeout, FIXTURE_TIMEOUT_MS.packages);
});
