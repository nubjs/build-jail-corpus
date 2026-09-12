import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { materializeChunk, screenWorklist, selectChunk, selectRun } from './catalog-campaign-input.mjs';

const root = () => fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-campaign-input-'));
const manifest = (chunks) => ({ schemaVersion: 2, chunks });
const write = (dir, value) => { const file = path.join(dir, 'manifest.json'); fs.writeFileSync(file, JSON.stringify(value)); return file; };

test('materializes exactly the requested bounded platform chunk', () => {
  const dir = root(); const file = write(dir, manifest([{ index: 1, specs: ['a@1.0.0', '@scope/b@2.0.0'] }]));
  const result = materializeChunk({ manifestFile: file, chunk: '1', platform: 'linux', out: path.join(dir, 'worklist.txt') });
  assert.equal(result.platform, 'linux');
  assert.equal(result.specs.length, 2);
  assert.equal(fs.readFileSync(path.join(dir, 'worklist.txt'), 'utf8'), 'a@1.0.0\n@scope/b@2.0.0\n');
  assert.match(result.manifestSha256, /^[a-f0-9]{64}$/);
});

test('rejects invalid chunk, platform, duplicate, and oversized selections before screening', () => {
  assert.throws(() => selectChunk(manifest([{ index: 1, specs: ['a@1.0.0'] }]), '0', 'linux'), /positive integer/);
  assert.throws(() => selectChunk(manifest([{ index: 1, specs: ['a@1.0.0'] }]), '1', 'solaris'), /platform/);
  assert.throws(() => selectChunk(manifest([{ index: 1, specs: ['a@1.0.0', 'a@1.0.0'] }]), '1', 'linux'), /duplicate/);
  assert.throws(() => selectChunk(manifest([{ index: 1, specs: ['a@1.0.0', 'b@1.0.0', 'c@1.0.0', 'd@1.0.0', 'e@1.0.0', 'f@1.0.0'] }]), '1', 'linux'), /invalid size/);
});

test('run plans map only validated selections to fixed runners', () => {
  const data = manifest([{ index: 1, specs: ['a@1.0.0'] }, { index: 2, specs: ['b@2.0.0'] }]);
  assert.deepEqual(selectRun(data, { chunks: [2], platforms: ['linux', 'macos', 'windows'] }), {
    include: [
      { chunk: 2, platform: 'linux', runner: 'ubuntu-24.04' },
      { chunk: 2, platform: 'macos', runner: 'macos-14' },
      { chunk: 2, platform: 'windows', runner: 'windows-2022' },
    ],
  });
  for (const plan of [
    { chunks: [], platforms: ['linux'] }, { chunks: [1], platforms: [] },
    { chunks: [1, 1], platforms: ['linux'] }, { chunks: [1], platforms: ['linux', 'linux'] },
    { chunks: [3], platforms: ['linux'] }, { chunks: [1], platforms: ['custom-runner'] },
  ]) assert.throws(() => selectRun(data, plan));
});

test('worklist OSV screen recognizes a known MAL positive without executing any package', () => {
  const dir = root(); const file = path.join(dir, 'worklist.txt'); fs.writeFileSync(file, 'clean@1.0.0\n@ctrl/tinycolor@4.1.2\n');
  let requests = 0;
  const result = screenWorklist({ file, out: path.join(dir, 'screen.json'), cacheDir: path.join(dir, 'cache'), request: (queries) => {
    requests++; return { results: queries.map((query) => query.package.name === '@ctrl/tinycolor' ? { vulns: [{ id: 'MAL-2025-47141' }] } : {}) };
  } });
  assert.equal(requests, 1);
  assert.equal(result.status, 'refused-malicious');
  assert.deepEqual(result.maliciousAdvisories, [{ spec: '@ctrl/tinycolor@4.1.2', ids: ['MAL-2025-47141'] }]);
  assert.ok(fs.existsSync(path.join(dir, 'screen.json')));
});

test('checked-in campaign manifest and artifact workflow stay bounded and publisher-free', () => {
  const rootDir = path.resolve(import.meta.dirname, '..', '..');
  const campaign = JSON.parse(fs.readFileSync(path.join(rootDir, 'inputs', 'catalog-campaign-inputs.json'), 'utf8'));
  const finalSeven = JSON.parse(fs.readFileSync(path.join(rootDir, 'inputs', 'final-fresh-seven-inputs.json'), 'utf8'));
  const finalPlan = JSON.parse(fs.readFileSync(path.join(rootDir, 'inputs', 'final-fresh-seven-run.json'), 'utf8'));
  assert.equal(campaign.schemaVersion, 2);
  assert.equal(campaign.summary.uniqueSpecs, 447);
  assert.equal(campaign.chunks.length, 90);
  assert.ok(campaign.chunks.every((chunk, index) => chunk.index === index + 1 && chunk.specs.length <= 5));
  assert.equal(finalSeven.schemaVersion, 2);
  assert.equal(finalSeven.pins.candidate.commit, '1daa98c23343cd50563823cdf3a2dc3230343b3e');
  assert.equal(finalSeven.pins.candidate.catalogSha256, 'dcb770937e85347f67230cb830d7206445ba160b14cc4315eef16baf922803e4');
  assert.deepEqual(finalSeven.chunks.map((chunk) => chunk.specs), [
    ['esbuild@0.24.0', 'better-sqlite3@11.8.1', 'bcrypt@5.1.1', 'sharp@0.33.5', '@swc/core@1.15.46'],
    ['cpu-features@0.0.10', 'mozjpeg@6.0.1'],
  ]);
  assert.deepEqual(selectRun(finalSeven, finalPlan).include.map(({ chunk, platform }) => [chunk, platform]), [
    [1, 'windows'], [2, 'windows'],
  ]);
  // The checked-in diagnostic pass is Windows-only; the complete acceptance matrix remains supported.
  assert.deepEqual(selectRun(finalSeven, { chunks: [1, 2], platforms: ['linux', 'macos', 'windows'] })
    .include.map(({ chunk, platform }) => [chunk, platform]), [
    [1, 'linux'], [2, 'linux'], [1, 'macos'], [2, 'macos'], [1, 'windows'], [2, 'windows'],
  ]);
  const workflow = fs.readFileSync(path.join(rootDir, '.github', 'workflows', 'catalog-boundary-artifact-records.yml'), 'utf8');
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /NUB_CORPUS_ON_RECORD: ''/);
  assert.match(workflow, /unset NUB_CORPUS_ON_RECORD NUB_CORPUS_REPO NUB_CORPUS_BRANCH NUB_CORPUS_MANIFEST/);
  assert.doesNotMatch(workflow, /publish-record-v2|claim-slice|queue-v2|self-dispatch/);
  assert.match(workflow, /actions\/cache\/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9/);
  assert.match(workflow, /actions\/cache\/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9/);
  assert.doesNotMatch(workflow, /restore-keys:/);
  assert.match(workflow, /RUNTIME_BUNDLE_CACHE_PATH="\$\(cygpath -w/);
  assert.match(workflow, /runtime-bundle\.mjs --verify/);
  assert.match(workflow, /catalog-replay\.mjs/);
  assert.match(workflow, /--catalog catalog-v2\.json --worklist reports\/worklist\.txt/);
  assert.match(workflow, /--context reports\/campaign-context\.json --out reports\/catalog-replay/);
  assert.match(workflow, /Materialize the pinned current-v2 catalog input/);
  assert.match(workflow, /pins\?\.candidate/);
  assert.match(workflow, /test "\$PIN_COMMIT" = "\$NUB_REF"/);
  assert.match(workflow, /pinned-git-blob\.mjs/);
  assert.match(workflow, /--repo \/tmp\/nub-catalog-input --ref HEAD --commit "\$PIN_COMMIT" --path "\$PIN_PATH"/);
  assert.doesNotMatch(workflow, /cp "\/tmp\/nub-catalog-input\/\$PIN_PATH" reports\/candidate-catalog-v2\.json/);
  assert.match(workflow, /reports\/candidate-catalog-v2\.json/);
  assert.match(workflow, /--context reports\/candidate-catalog-context\.json --out reports\/candidate-307-replay/);
  assert.match(workflow, /id: campaigncontext/);
  assert.match(workflow, /always\(\) && !cancelled\(\) && steps\.campaigncontext\.outcome == 'success'/);
  assert.match(workflow, /inputs\/final-fresh-seven-inputs\.json/);
  assert.match(workflow, /inputs\/final-fresh-seven-run\.json/);
  assert.match(workflow, /NUB_REF: 1daa98c23343cd50563823cdf3a2dc3230343b3e/);
  assert.match(workflow, /NUB_V2_DRIVER_ARGS='\["--root","C:\\\\p\\\\jail-record-probe"\]'/);
  assert.match(workflow, /args\+=\(--driver-root 'C:\/p\/jail-record-probe'\)/);
  assert.match(workflow, /RUNTIME_CACHE_KEY=\$\(node harness\/v2\/runtime-bundle\.mjs --cache-key/);
  assert.match(workflow, /Smoke the source-free runtime sidecar/);
  assert.ok(workflow.indexOf('Materialize and screen one bounded worklist') < workflow.indexOf('Build the exact full Nub runtime'));
  assert.ok(workflow.indexOf('Materialize and screen one bounded worklist') < workflow.indexOf('Measure the screened worklist'));
  assert.ok(workflow.indexOf('Smoke the source-free runtime sidecar') < workflow.indexOf('Materialize the pinned current-v2 catalog input'));
  assert.ok(workflow.indexOf('Measure the screened worklist') < workflow.indexOf('Replay the bound external catalog directly'));
  assert.ok(workflow.indexOf('Replay the bound external catalog directly') < workflow.indexOf('Replay the pinned current-v2 catalog grants directly'));
  assert.ok(workflow.indexOf('Replay the bound external catalog directly') < workflow.indexOf('Require complete exact-candidate measurements'));
});
