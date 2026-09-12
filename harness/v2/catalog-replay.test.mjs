import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createCampaignContext } from './campaign-provenance.mjs';
import { cellName, classifyDirect, parseExactSpec, readWorklist, replayCatalog } from './catalog-replay.mjs';
import { writeBundleManifest } from './runtime-bundle.mjs';

const direct = '── DIRECT: does esbuild@0.24.0 install under the catalog?\n=> SUFFICIENT (installed, artifacts matched OBSERVE)\n';

test('direct classification requires both the banner and SUFFICIENT terminal', () => {
  assert.equal(classifyDirect({ status: 0 }, direct).status, 'sufficient');
  assert.deepEqual(classifyDirect({ status: 1 }, '── DIRECT:\n=> INSUFFICIENT\n').status, 'insufficient');
  assert.deepEqual(classifyDirect({ status: 3 }, '── DIRECT:\n=> VOID\n').status, 'void');
  assert.equal(classifyDirect({ status: 0 }, '=> SUFFICIENT\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 0 }, '── DIRECT:\n=> ordinary ladder\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 0 }, '── DIRECT:\n=> SUFFICIENT stale line\n=> ordinary ladder\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 1 }, '── DIRECT:\ndriver crashed\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 1 }, '── DIRECT:\n=> ⛔ VOID\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 3 }, '── DIRECT:\n=> INSUFFICIENT\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 1, error: Object.assign(new Error('stderr maxBuffer length exceeded'), { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }) }, '── DIRECT:\n=> INSUFFICIENT\n').status, 'infrastructure-error');
  assert.equal(classifyDirect({ status: 124 }, direct).status, 'infrastructure-error');
});

test('exact worklist parsing rejects ranges, unsafe names, duplicates, and more than five cells', () => {
  assert.deepEqual(parseExactSpec('@swc/core@1.15.46'), { pkg: '@swc/core', version: '1.15.46', spec: '@swc/core@1.15.46' });
  for (const line of ['esbuild@latest', 'esbuild@^0.24.0', '../escape@1.2.3', 'esbuild']) {
    assert.throws(() => parseExactSpec(line), /exact-version/);
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-replay-worklist-'));
  const duplicate = path.join(root, 'duplicate.txt');
  fs.writeFileSync(duplicate, 'esbuild@0.24.0\nesbuild@0.24.0\n');
  assert.throws(() => readWorklist(duplicate), /duplicate/);
  const many = path.join(root, 'many.txt');
  fs.writeFileSync(many, ['a@1.0.0', 'b@1.0.0', 'c@1.0.0', 'd@1.0.0', 'e@1.0.0', 'f@1.0.0'].join('\n'));
  assert.throws(() => readWorklist(many), /bounded to 5/);
  assert.equal(cellName({ pkg: '@swc/core', version: '1.15.46' }), 'swc+core@1.15.46');
});

test('replay binds the exact context before and after every run, retains cells, and continues after an insufficiency', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-replay-'));
  const worklist = path.join(root, 'worklist.txt');
  const catalog = path.join(root, 'catalog.json');
  const nub = path.join(root, 'nub');
  fs.writeFileSync(worklist, 'esbuild@0.24.0\nbcrypt@5.1.1\n'); fs.writeFileSync(catalog, '{}'); fs.writeFileSync(nub, 'nub');
  const context = { verification: { files: { catalog, worklist } } };
  const commands = [], binds = [];
  const summary = replayCatalog({ nub, nubGitSha: 'a'.repeat(40), catalog, worklist, context, out: path.join(root, 'out'), platform: 'linux', arch: 'x64' }, {
    verifyCampaignContext(value) { binds.push(['verify', value]); },
    assertCampaignInvocation(value, invocation) { binds.push(['assert', value, invocation]); },
    hashFile() { return 'hash'; },
    driverInvocation() { return { cmd: 'mock-driver', pre: ['--fixed'], file: '/driver' }; },
    spawnSync(command, args, options) { commands.push([command, args, options]); return commands.length === 1
      ? { status: 1, stdout: '── DIRECT:\n=> INSUFFICIENT\n', stderr: '' }
      : { status: 0, stdout: direct, stderr: '' }; },
  });
  assert.equal(summary.ok, false);
  assert.deepEqual(summary.cells.map((cell) => cell.status), ['insufficient', 'sufficient']);
  assert.equal(commands.length, 2, 'the second cell ran after the first result did not decide the campaign');
  assert.deepEqual(commands[0], ['mock-driver', ['--fixed', '/driver', 'esbuild', '0.24.0', nub, '--at-catalog', catalog],
    { encoding: 'utf8', maxBuffer: 1 << 28, timeout: 20 * 60_000 }]);
  assert.equal(binds.length, 8, 'verify and invocation binding run before and after each cell');
  for (const cell of summary.cells) {
    assert.ok(fs.existsSync(cell.log));
    assert.ok(fs.existsSync(path.join(path.dirname(cell.log), 'summary.json')));
  }
  assert.ok(fs.existsSync(path.join(root, 'out', 'summary.json')));
});

test('win32 is refused before it can claim a direct replay', () => {
  assert.throws(() => replayCatalog({ platform: 'win32' }), /unsupported on win32/);
});

test('subprocess errors stay infrastructure failures with their detail in the cell log', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-replay-subprocess-'));
  const worklist = path.join(root, 'worklist.txt'), catalog = path.join(root, 'catalog.json'), nub = path.join(root, 'nub');
  fs.writeFileSync(worklist, 'a@1.0.0\n'); fs.writeFileSync(catalog, '{}'); fs.writeFileSync(nub, 'nub');
  const error = Object.assign(new Error('stderr maxBuffer length exceeded'), { code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' });
  const summary = replayCatalog({ nub, nubGitSha: 'a'.repeat(40), catalog, worklist,
    context: { verification: { files: { catalog, worklist } } }, out: path.join(root, 'out'), platform: 'linux' }, {
    verifyCampaignContext() {}, assertCampaignInvocation() {}, hashFile() { return 'hash'; },
    driverInvocation() { return { cmd: 'mock', pre: [], file: '/driver' }; },
    spawnSync() { return { status: null, error, stdout: '── DIRECT:\n', stderr: '' }; },
  });
  assert.match(summary.cells[0].reason, /ERR_CHILD_PROCESS_STDIO_MAXBUFFER/);
  assert.match(fs.readFileSync(summary.cells[0].log, 'utf8'), /ERR_CHILD_PROCESS_STDIO_MAXBUFFER/);
});

test('a post-run binding change invalidates that cell but does not skip the remaining worklist', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-replay-post-bind-'));
  const worklist = path.join(root, 'worklist.txt'), catalog = path.join(root, 'catalog.json'), nub = path.join(root, 'nub');
  fs.writeFileSync(worklist, 'a@1.0.0\nb@1.0.0\n'); fs.writeFileSync(catalog, '{}'); fs.writeFileSync(nub, 'nub');
  let assertions = 0, runs = 0;
  const summary = replayCatalog({ nub, nubGitSha: 'a'.repeat(40), catalog, worklist,
    context: { verification: { files: { catalog, worklist } } }, out: path.join(root, 'out'), platform: 'linux' }, {
    verifyCampaignContext() {}, hashFile() { return 'hash'; }, driverInvocation() { return { cmd: 'mock', pre: [], file: '/driver' }; },
    assertCampaignInvocation() { if (++assertions === 2) throw new Error('catalog digest changed'); },
    spawnSync() { runs++; return { status: 0, stdout: direct, stderr: '' }; },
  });
  assert.equal(runs, 2);
  assert.equal(summary.cells[0].status, 'infrastructure-error');
  assert.equal(summary.cells[1].status, 'sufficient');
});

function realContext(root, worklist) {
  const bundle = path.join(root, 'bundle');
  const identity = { candidateSha: 'a'.repeat(40), platform: 'linux', arch: 'x64', profile: 'fast',
    features: ['nub-cli/build-jail-catalog-override'], recipeSha256: 'e'.repeat(64), nodeVersion: 'v22.23.2', rustcSha256: 'd'.repeat(64) };
  fs.mkdirSync(path.join(bundle, 'runtime', 'addons'), { recursive: true });
  fs.writeFileSync(path.join(bundle, 'nub'), 'nub'); fs.writeFileSync(path.join(bundle, 'runtime', 'preload.mjs'), 'preload');
  fs.writeFileSync(path.join(bundle, 'runtime', 'addons', 'nub-native.node'), 'addon');
  for (const name of ['@js-temporal/polyfill', '@oxc-project/runtime', '@petamoriken/float16', 'jsbi', 'urlpattern-polyfill']) {
    const dir = path.join(bundle, 'runtime', 'node_modules', name); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'package.json'), '{}');
  }
  writeBundleManifest(bundle, identity);
  const catalog = path.join(root, 'catalog.json'); fs.writeFileSync(catalog, '{}');
  const files = Object.fromEntries(['manifest', 'runPlan', 'workflow'].map((key) => { const file = path.join(root, key); fs.writeFileSync(file, key); return [key, file]; }));
  return { bundle, catalog, context: createCampaignContext({ bundleRoot: bundle, runtimeRecipeSha256: identity.recipeSha256, catalog, worklist, ...files }), identity };
}

test('a real campaign context rejects a catalog mutation after a mocked direct driver run', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-replay-real-context-'));
  const worklist = path.join(root, 'worklist.txt'); fs.writeFileSync(worklist, 'a@1.0.0\nb@1.0.0\n');
  const { bundle, catalog, context, identity } = realContext(root, worklist);
  let runs = 0;
  const summary = replayCatalog({ nub: path.join(bundle, 'nub'), nubGitSha: identity.candidateSha, catalog, worklist, context,
    out: path.join(root, 'out'), platform: 'linux', arch: 'x64' }, {
    driverInvocation() { return { cmd: 'mock', pre: [], file: '/driver' }; },
    spawnSync() { runs++; fs.writeFileSync(catalog, '{"changed":true}'); return { status: 0, stdout: direct, stderr: '' }; },
  });
  assert.equal(runs, 1, 'the second cell is refused by its real pre-run catalog digest check');
  assert.deepEqual(summary.cells.map((cell) => cell.status), ['infrastructure-error', 'infrastructure-error']);
  assert.match(fs.readFileSync(summary.cells[0].log, 'utf8'), /DIRECT/);
});
