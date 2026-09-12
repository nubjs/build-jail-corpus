import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./assert-cjpeg-oracle.mjs', import.meta.url));

function report(t, arms, cjpegGvsProvenance = [
  'before-right', 'after-right-before-wrong-warm', 'after-wrong-warm',
].map((phase) => ({ phase, artifact: { status: 'missing', store: 'C:\\cache\\nub\\pm\\store\\v1' } }))) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'assert-cjpeg-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const output = path.join(dir, 'falsify.json');
  fs.writeFileSync(output, JSON.stringify({ results: [{ arms, cjpegGvsProvenance }] }));
  return output;
}

const oracleRecord = () => ({
  label: 'at-grant',
  artifact: { status: 'missing' },
  execution: null,
});

test('accepts exactly the three retained oracle arms', (t) => {
  const output = report(t, ['wrong-cold', 'right', 'wrong-warm']
    .map((label) => ({ label, cjpegOracle: [{}], cjpegOracleRecord: oracleRecord() })));
  execFileSync(process.execPath, [script, output]);
});

test('rejects a missing oracle result instead of treating artifact presence as a control', (t) => {
  const output = report(t, ['wrong-cold', 'right', 'wrong-warm']
    .map((label) => ({ label, cjpegOracle: [], cjpegOracleRecord: oracleRecord() })));
  assert.throws(() => execFileSync(process.execPath, [script, output]), /expected one structured cjpeg oracle record/);
});

test('rejects a missing GVS phase instead of silently losing warm-state provenance', (t) => {
  const output = report(t, ['wrong-cold', 'right', 'wrong-warm']
    .map((label) => ({ label, cjpegOracle: [{}], cjpegOracleRecord: oracleRecord() })), []);
  assert.throws(() => execFileSync(process.execPath, [script, output]), /expected GVS provenance phases/);
});
