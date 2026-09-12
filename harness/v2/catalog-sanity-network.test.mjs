import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { effectiveNetwork } from './catalog-sanity-network.mjs';

test('resolves a platform network withdrawal over the default', () => {
  assert.equal(effectiveNetwork({ default: { network: true }, linux: { network: null } }, 'linux'), false);
  assert.equal(effectiveNetwork({ default: { network: true }, linux: { network: null } }, 'macos'), true);
});

test('keeps an omitted current-catalog network grant denied', () => {
  assert.equal(effectiveNetwork({ default: { write: { deps: true } } }, 'linux'), false);
});

test('anchors the denied control in the checked-out current catalog', () => {
  const catalog = JSON.parse(fs.readFileSync('catalog-v2.json', 'utf8'));
  assert.equal(effectiveNetwork(catalog.packages.compresion, 'linux'), false);
  assert.equal(effectiveNetwork(catalog.packages.compresion, 'macos'), false);
  assert.equal(effectiveNetwork(catalog.packages.compresion, 'win'), false);
});
