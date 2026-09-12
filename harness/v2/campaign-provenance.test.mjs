import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createCampaignContext, verifyCampaignContext } from './campaign-provenance.mjs';
import { writeBundleManifest } from './runtime-bundle.mjs';

const identity = { candidateSha: '9d349f7c300a41fd9401d3d3c2e706b2d75c5fff', platform: 'linux', arch: 'x64', profile: 'fast', features: ['nub-cli/build-jail-catalog-override'], recipeSha256: 'e'.repeat(64), nodeVersion: 'v22.23.2', rustcSha256: 'd'.repeat(64) };
test('campaign context binds actual inputs and rejects sidecar/input mutation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'campaign-context-')), bundle = path.join(root, 'bundle');
  fs.mkdirSync(path.join(bundle, 'runtime', 'addons'), { recursive: true }); fs.writeFileSync(path.join(bundle, 'nub'), 'nub'); fs.writeFileSync(path.join(bundle, 'runtime', 'preload.mjs'), 'preload'); fs.writeFileSync(path.join(bundle, 'runtime', 'addons', 'nub-native.node'), 'addon');
  for (const name of ['@js-temporal/polyfill', '@oxc-project/runtime', '@petamoriken/float16', 'jsbi', 'urlpattern-polyfill']) { const dir = path.join(bundle, 'runtime/node_modules', name); fs.mkdirSync(dir, { recursive: true }); fs.writeFileSync(path.join(dir, 'package.json'), '{}'); }
  writeBundleManifest(bundle, identity);
  const files = Object.fromEntries(['catalog', 'worklist', 'manifest', 'runPlan', 'workflow'].map((key) => { const file = path.join(root, key); fs.writeFileSync(file, key); return [key, file]; }));
  const context = createCampaignContext({ bundleRoot: bundle, runtimeRecipeSha256: 'c'.repeat(64), ...files });
  assert.doesNotThrow(() => verifyCampaignContext(context));
  fs.writeFileSync(files.worklist, 'changed');
  assert.throws(() => verifyCampaignContext(context), /digest changed/);
});
