import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { classifyWarmReuse, requiresCjpegOracle } from './warm-reuse.mjs';

const fixturePath = fileURLToPath(new URL('./fixtures/warm-reuse-mozjpeg-34670953158.json', import.meta.url));
const captured = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const copy = () => structuredClone(captured);
const verdict = (input) => classifyWarmReuse(input).kind;

test('classifies the captured Windows cjpeg warm arm as reuse, never cold sufficiency', () => {
  const result = classifyWarmReuse(copy());
  assert.equal(result.kind, 'warm-reused');
  assert.match(result.message, /not cold-grant evidence/);
});

test('requires the cjpeg oracle from the case descriptor in ordinary preflight', () => {
  assert.equal(requiresCjpegOracle({ oracle: 'cjpeg' }), true);
  assert.equal(requiresCjpegOracle({ name: 'another-case' }), false);
});

for (const [name, mutate] of [
  ['a changed payload hash', (v) => { v.provenance[2].artifact.artifact.sha256 = '0'.repeat(64); }],
  ['a changed payload path', (v) => { v.provenance[2].artifact.artifact.realpath += '.new'; }],
  ['a payload present before the right arm', (v) => { v.provenance[0].artifact.status = 'present'; }],
  ['a missing denied-network control', (v) => { v.warm.refusalSeen = false; }],
  ['a failed executable smoke run', (v) => { v.warm.cjpegOracleRecord.execution.status = 1; }],
  ['a generic case with no oracle', (v) => { delete v.kase.oracle; }],
]) {
  test(`rejects ${name}`, () => {
    const input = copy();
    mutate(input);
    assert.equal(verdict(input), 'fail');
  });
}

test('treats missing structured evidence as inconclusive rather than as a warm pass', () => {
  const input = copy();
  delete input.warm.cjpegOracleRecord;
  assert.equal(verdict(input), 'inconclusive');
});

test('treats a missing warm control field as inconclusive but a false field as a P0 failure', () => {
  const missing = copy();
  delete missing.warm.refusalSeen;
  assert.equal(verdict(missing), 'inconclusive');

  const falseControl = copy();
  falseControl.warm.refusalSeen = false;
  assert.equal(verdict(falseControl), 'fail');
});
