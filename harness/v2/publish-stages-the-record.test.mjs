// Pins the fix for a defect that closed queue rows against records that never landed on the branch.
//
// The corpus runner checks out in CONE MODE with the cone set to `harness`, `inputs`, `.github`
// (`corpus-v2-runner.yml`). `records-v2/runs/<plat>/...` is outside that cone, so a plain `git add`
// on a record path stages NOTHING — and the publisher discarded its stderr, so the failure was
// invisible. `queue-v2.ndjson` is a TOP-LEVEL file, and a cone checkout always includes those, so
// the queue staged every time. Every per-package publish therefore committed the row-close WITHOUT
// the measurement it was closing on.
//
// MEASURED 2026-08-31 on `probe/corpus-v2-lane`: of the last 72 per-package publish commits, 72
// carried `queue-v2.ndjson` alone and 0 carried a record.
//
// ⛔ THE FIRST TWO TESTS ARE THE POSITIVE CONTROL AND THEY ARE THE POINT. They exercise real git in
// a real sparse checkout rather than asserting on the script's text, so they would still fail if
// git changed this behaviour under us — which is the only way this guard can be shown to bite.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = import.meta.dirname;
const RECORD = 'records-v2/runs/linux-x64/p/1.0.0/results.json';

/** A repo checked out in cone mode with the runner's cone, holding an out-of-cone record. */
const sparseRepo = () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sparse-publish-'));
  const git = (...a) => execFileSync('git', ['-C', dir, ...a], { encoding: 'utf8' });
  git('init', '-q', '-b', 'main');
  git('config', 'user.email', 't@t');
  git('config', 'user.name', 't');
  fs.writeFileSync(path.join(dir, 'seed'), 'seed\n');
  git('add', '-A');
  git('commit', '-qm', 'seed');
  git('sparse-checkout', 'init', '--cone');
  git('sparse-checkout', 'set', 'harness', 'inputs', '.github');
  fs.mkdirSync(path.join(dir, path.dirname(RECORD)), { recursive: true });
  fs.writeFileSync(path.join(dir, RECORD), '{"pkg":"p","verdict":"MINIMUM"}\n');
  fs.writeFileSync(path.join(dir, 'queue-v2.ndjson'), '{"pkg":"p","status":"done"}\n');
  return { dir, git, staged: () => git('diff', '--cached', '--name-only').split('\n').filter(Boolean) };
};

test('⭑ CONTROL: a plain `git add` silently stages NO record under the runner\'s sparse cone', () => {
  const { git, staged } = sparseRepo();
  try { git('add', '--ignore-removal', '--', RECORD); } catch { /* git may also exit non-zero */ }
  assert.deepEqual(staged(), [], 'a plain add must be shown to drop the record — otherwise this suite proves nothing');
});

test('⭑ `git add --sparse` DOES stage the out-of-cone record — the fix', () => {
  const { git, staged } = sparseRepo();
  git('add', '--sparse', '--ignore-removal', '--', RECORD);
  assert.deepEqual(staged(), [RECORD], 'the record must reach the index');
});

test('⭑ CONTROL: the queue stages WITHOUT --sparse, which is why the commits were queue-only', () => {
  const { git, staged } = sparseRepo();
  git('add', '--', 'queue-v2.ndjson');
  assert.deepEqual(staged(), ['queue-v2.ndjson'],
    'the asymmetry between a top-level queue and an out-of-cone record IS the defect');
});

/** The publisher's own "is this record on the branch?" test, lifted verbatim from the script. */
const missingCheck = (src) => {
  const start = src.indexOf('if ! git diff --cached --name-only -- "$rel/results.json"');
  assert.notEqual(start, -1, 'the staged-or-committed check is gone');
  // ⛔ ANCHOR THE TERMINATOR TO ITS OWN LINE. A bare indexOf('fi') matches inside `git cat-file`
  // and slices the snippet mid-word, producing a bash syntax error that reads like a broken guard.
  const end = src.indexOf('\n    fi\n', start);
  assert.notEqual(end, -1, 'the check does not close on its own line');
  return src.slice(start, end + '\n    fi'.length);
};

test('\u2b51 CONTROL: a record ALREADY COMMITTED by an earlier publish is not called missing', () => {
  // The manifest is replayed by every later invocation, so this is the common case, not an edge
  // one — a staged-only check withholds the queue for the whole rest of the slice.
  const { dir, git } = sparseRepo();
  git('add', '--sparse', '--ignore-removal', '--', RECORD);
  git('commit', '-qm', 'record landed earlier');
  const src = fs.readFileSync(path.join(HERE, 'publish-record-v2.sh'), 'utf8');
  const out = execFileSync('bash', ['-c',
    `set -u\ncd ${JSON.stringify(dir)}\nrel=${JSON.stringify(path.dirname(RECORD))}\nSTAGE_MISSING=''\n${missingCheck(src)}\nprintf '%s' "$STAGE_MISSING"\n`,
  ], { encoding: 'utf8' });
  assert.equal(out, '', 'a record already on the branch must not be reported missing');
});

test('\u2b51 CONTROL: a record that is neither staged nor committed IS called missing', () => {
  const { dir } = sparseRepo();
  const src = fs.readFileSync(path.join(HERE, 'publish-record-v2.sh'), 'utf8');
  const out = execFileSync('bash', ['-c',
    `set -u\ncd ${JSON.stringify(dir)}\nrel=${JSON.stringify(path.dirname(RECORD))}\nSTAGE_MISSING=''\n${missingCheck(src)}\nprintf '%s' "$STAGE_MISSING"\n`,
  ], { encoding: 'utf8' });
  assert.match(out, /records-v2/, 'an absent record must be reported, or the guard cannot bite');
});

test('⭑ the publisher stages records with --sparse', () => {
  const src = fs.readFileSync(path.join(HERE, 'publish-record-v2.sh'), 'utf8');
  const add = /git add [^\n]*-- "\$rel"/.exec(src);
  assert.ok(add, 'the per-record add is gone');
  assert.match(add[0], /--sparse/, 'the per-record add must pass --sparse');
});

test('⭑ the queue add is gated on every record having actually staged', () => {
  const src = fs.readFileSync(path.join(HERE, 'publish-record-v2.sh'), 'utf8');
  const gate = src.indexOf('if [ -n "$STAGE_MISSING" ]');
  const queueAdd = src.indexOf('git add -- "$QUEUE"');
  assert.notEqual(gate, -1, 'the staged-record verification is gone');
  assert.ok(queueAdd > gate,
    'the queue add must sit inside the else of the STAGE_MISSING gate, so a row is never closed without its record');
});
