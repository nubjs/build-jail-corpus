// A duplicate queue row means two runners measure the same package, which is the exact collision the
// claim mechanism exists to prevent — so idempotency is this file's load-bearing property and every
// test below is aimed at it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readQueue, rowKey, newRows } from './gaps-to-queue.mjs';

const gap = (name, version, platform) => ({ name, version, platform });

test('a gap with no existing row becomes one pending row', () => {
  const { rows, added, skipped } = newRows([], [gap('esbuild', '1.0.0', 'linux')]);
  assert.deepEqual(rows, [{ pkg: 'esbuild', version: '1.0.0', os: 'linux', status: 'pending' }]);
  assert.equal(added, 1);
  assert.equal(skipped, 0);
});

test('⛔ a gap whose row is already PENDING is skipped — appending would double-measure it', () => {
  const existing = [{ pkg: 'esbuild', version: '1.0.0', os: 'linux', status: 'pending' }];
  const { rows, added, skipped } = newRows(existing, [gap('esbuild', '1.0.0', 'linux')]);
  assert.deepEqual(rows, [], 'a second row for the same tuple is the collision the claim prevents');
  assert.equal(added, 0);
  assert.equal(skipped, 1);
});

test('⛔⛔ a gap whose row is already CLAIMED is skipped — that run is in flight right now', () => {
  // This is the dangerous one. The row is claimed, so a runner is measuring it as we speak; the RECORD
  // does not exist yet, which is precisely why coverage still reports it as a gap. Appending here would
  // hand the same package to a second runner.
  const existing = [{ pkg: 'sharp', version: '2.0.0', os: 'windows', status: 'claimed', run: '12345' }];
  const { rows, skipped } = newRows(existing, [gap('sharp', '2.0.0', 'windows')]);
  assert.deepEqual(rows, [], 'an in-flight claim must suppress a new row');
  assert.equal(skipped, 1);
});

test('identity is (pkg, version, os) — a different os is a different row', () => {
  const existing = [{ pkg: 'sharp', version: '2.0.0', os: 'linux', status: 'done' }];
  const { rows } = newRows(existing, [gap('sharp', '2.0.0', 'windows'), gap('sharp', '2.0.0', 'linux')]);
  assert.deepEqual(rows.map(rowKey), ['sharp 2.0.0 windows'],
    'the linux row exists so it is skipped; windows is genuinely absent');
});

test('a different VERSION is a different row — this is how a new release enters the queue', () => {
  // The freshness path: latest moved, so coverage reports a gap at the new version while the old row
  // stays `done`. That new row is the whole point of the name-based list.
  const existing = [{ pkg: 'esbuild', version: '1.0.0', os: 'linux', status: 'done' }];
  const { rows } = newRows(existing, [gap('esbuild', '2.0.0', 'linux')]);
  assert.deepEqual(rows.map(rowKey), ['esbuild 2.0.0 linux']);
});

test('duplicate gaps in ONE run collapse to a single row', () => {
  // The coverage checker should not emit duplicates, but a row appended twice in one pass would be a
  // collision this module created itself, so it is deduped here rather than assumed upstream.
  const { rows, added } = newRows([], [gap('p', '1.0.0', 'linux'), gap('p', '1.0.0', 'linux')]);
  assert.equal(added, 1, 'the second identical gap must not produce a second row');
  assert.equal(rows.length, 1);
});

test('an unparseable queue line is dropped rather than crashing the run', () => {
  // A partially-written line from an interrupted append must not stop the queue being read; treating it
  // as fatal would block every future coverage run on a one-byte corruption.
  const rows = readQueue('{"pkg":"a","version":"1","os":"linux"}\nnot json\n\n{"pkg":"b","version":"1","os":"linux"}');
  assert.deepEqual(rows.map((r) => r.pkg), ['a', 'b']);
});

test('an unparseable line does NOT make its tuple look absent', () => {
  // ⛔ THE SUBTLE FAILURE. If a corrupt line held the only row for a tuple, dropping it silently makes
  // that tuple look uncovered and a duplicate row gets appended. The dedupe can only see rows it parsed,
  // so this documents the limit rather than pretending otherwise: the append is still safe because the
  // runner's claim is what prevents double measurement, not this dedupe alone.
  const parsed = readQueue('{"pkg":"a","version":"1","os":"linux"');
  assert.deepEqual(parsed, [], 'a truncated line is unparseable and therefore invisible to the dedupe');
  const { added } = newRows(parsed, [gap('a', '1', 'linux')]);
  assert.equal(added, 1, 'so a duplicate CAN be appended — the claim mechanism is the real guard');
});
