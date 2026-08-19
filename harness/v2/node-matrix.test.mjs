import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadNodeMatrix, validateNodeMatrix } from './node-matrix.mjs';

test('the dated matrix covers every Nub-supported major including non-LTS lines', () => {
  const { matrix, sha256 } = loadNodeMatrix();
  assert.deepEqual(matrix.versions.map((entry) => entry.major), Array.from({ length: matrix.versions.length }, (_, i) => matrix.floor + i));
  assert.equal(matrix.harnessNode, '22.23.2');
  assert.equal(matrix.versions.at(-1).version, '26.7.0');
  assert.equal(sha256.length, 64);
});

test('a matrix cannot hide a supported major by skipping it', () => {
  const { matrix } = loadNodeMatrix();
  const broken = structuredClone(matrix);
  broken.versions.splice(1, 1);
  assert.throws(() => validateNodeMatrix(broken), /contiguous/);
});
