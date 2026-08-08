import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_NODE_MATRIX = path.join(import.meta.dirname, 'node-matrix.json');

export function validateNodeMatrix(matrix) {
  if (matrix?.schemaVersion !== 1 || !/^\d{4}-\d{2}-\d{2}$/.test(matrix.selectedAt ?? '')
    || typeof matrix.source !== 'string' || !matrix.source || matrix.nubMinimum !== '18.19.0'
    || !/^\d+\.\d+\.\d+$/.test(matrix.harnessNode ?? '')) {
    throw new Error('Node matrix must name schema 1, its selection date/source, harness Node, and Nub minimum 18.19.0');
  }
  if (!Array.isArray(matrix.versions) || !matrix.versions.length) throw new Error('Node matrix versions are required');
  const majors = matrix.versions.map((entry) => entry.major);
  const expected = Array.from({ length: Math.max(...majors) - 17 }, (_, index) => 18 + index);
  if (JSON.stringify(majors) !== JSON.stringify(expected)) {
    throw new Error(`Node matrix majors must be contiguous from 18, got ${majors.join(',')}`);
  }
  for (const entry of matrix.versions) {
    if (!new RegExp(`^${entry.major}\\.\\d+\\.\\d+$`).test(entry.version)
      || !/^\d{4}-\d{2}-\d{2}$/.test(entry.released ?? '') || typeof entry.npm !== 'string') {
      throw new Error(`invalid Node matrix entry for major ${entry.major}`);
    }
  }
  return matrix;
}

export function loadNodeMatrix(file = DEFAULT_NODE_MATRIX) {
  const bytes = fs.readFileSync(file);
  const matrix = validateNodeMatrix(JSON.parse(bytes));
  return { matrix, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), file };
}
