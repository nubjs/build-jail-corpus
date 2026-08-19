import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DEFAULT_NODE_MATRIX = path.join(import.meta.dirname, 'node-matrix.json');

// ⛔ THE FLOOR IS DECLARED BY THE MATRIX, NOT HARDCODED HERE — schema 2. It was 18, in two places
// (`nubMinimum !== '18.19.0'` and `contiguous from 18`), on the reasoning that 18.19.0 is Nub's own
// support minimum. That reasoning conflated two different things and the maintainer settled it:
// Nub's floor governs Nub as a FILE RUNNER; as a PACKAGE MANAGER it must install into a project on
// ANY Node, and the corpus is an artefact that exists independently of Nub either way. Measured
// against the population the floor excluded: 448 of the 719 package-versions in the BROKEN-* buckets
// were published before Node 18 existed, so the matrix could not offer a single one of them the
// runtime its author targeted.
//
// `nubMinimum` stays in the file as a RECORDED FACT — a record should be able to say whether the
// Node it measured on is one Nub augments — but it is no longer the floor.
//
// ⛔ `darwinArm64From` IS NOT DECORATION. nodejs.org publishes NO darwin-arm64 build below 16
// (verified against dist/index.json: majors 4-15 have none). So on an Apple-silicon runner an era
// pin below 16 needs an x64 build under Rosetta, or it cannot be honoured at all — and a driver that
// does not check this would silently NOT-PIN every pre-2021 package on exactly the platform where
// most of this corpus's native-addon failures live.
export function validateNodeMatrix(matrix) {
  if (matrix?.schemaVersion !== 2 || !/^\d{4}-\d{2}-\d{2}$/.test(matrix.selectedAt ?? '')
    || typeof matrix.source !== 'string' || !matrix.source
    || !/^\d+\.\d+\.\d+$/.test(matrix.nubMinimum ?? '')
    || !Number.isInteger(matrix.floor) || !Number.isInteger(matrix.darwinArm64From)
    || !/^\d+\.\d+\.\d+$/.test(matrix.harnessNode ?? '')) {
    throw new Error('Node matrix must name schema 2, its selection date/source, harness Node, Nub minimum, floor and darwinArm64From');
  }
  if (!Array.isArray(matrix.versions) || !matrix.versions.length) throw new Error('Node matrix versions are required');
  const majors = matrix.versions.map((entry) => entry.major);
  const expected = Array.from({ length: Math.max(...majors) - matrix.floor + 1 }, (_, index) => matrix.floor + index);
  if (JSON.stringify(majors) !== JSON.stringify(expected)) {
    throw new Error(`Node matrix majors must be contiguous from ${matrix.floor}, got ${majors.join(',')}`);
  }
  for (const entry of matrix.versions) {
    if (!new RegExp(`^${entry.major}\\.\\d+\\.\\d+$`).test(entry.version)
      || !/^\d{4}-\d{2}-\d{2}$/.test(entry.released ?? '') || typeof entry.npm !== 'string'
      || typeof entry.darwinArm64 !== 'boolean') {
      throw new Error(`invalid Node matrix entry for major ${entry.major}`);
    }
    // A build that does not exist upstream must not be claimable as a pin.
    if (entry.darwinArm64 !== (entry.major >= matrix.darwinArm64From)) {
      throw new Error(`major ${entry.major} disagrees with darwinArm64From=${matrix.darwinArm64From}`);
    }
  }
  return matrix;
}

export function loadNodeMatrix(file = DEFAULT_NODE_MATRIX) {
  const bytes = fs.readFileSync(file);
  const matrix = validateNodeMatrix(JSON.parse(bytes));
  return { matrix, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), file };
}
