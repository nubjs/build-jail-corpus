import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { assertFixedDeniedControl, effectiveNetwork } from './catalog-sanity-network.mjs';

test('resolves a platform network withdrawal over the default', () => {
  assert.equal(effectiveNetwork({ default: { network: true, linux: { network: null } } }, 'linux'), false);
  assert.equal(effectiveNetwork({ default: { network: true, linux: { network: null } } }, 'macos'), true);
});

test('keeps an omitted current-catalog network grant denied', () => {
  assert.equal(effectiveNetwork({ default: { write: { deps: true } } }, 'linux'), false);
});

test('anchors the denied control in the checked-out current catalog', () => {
  const catalog = JSON.parse(fs.readFileSync('catalog-v2.json', 'utf8'));
  for (const platform of ['linux', 'macos', 'win']) assertFixedDeniedControl(catalog.packages.compresion, platform);
});

test('rejects a version-banded control instead of guessing its effective grant', () => {
  assert.throws(() => assertFixedDeniedControl({ default: {}, versions: { '<2.0.0': {} } }, 'linux'), /fixed-default/);
});
