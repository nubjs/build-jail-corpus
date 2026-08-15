// The provisioner decides whether a run can pin at all, so its present/missing call is load-bearing.
//
// ⛔ WHY THE "MISSING" DIRECTION MATTERS MORE THAN "PRESENT". A false PRESENT means the driver builds a
// PATH entry pointing at a Node that is not there, and the arm then runs on whatever `node` resolves to
// next — a silently unpinned measurement that the record would claim was pinned. A false MISSING only
// costs a redundant install. So the classification is asserted against a real directory layout rather
// than a mocked `existsSync`, and the layout itself was verified against `nub node install` rather than
// inferred — PER PLATFORM, because they differ: POSIX is `<root>/node/<version>/bin/node`, and the
// Windows zip is FLAT, putting `node.exe` at `<root>/node/<version>` with no `bin/`. Neither has a `v`
// prefix. Assuming one layout for both made every Windows version read MISSING after a successful
// install, which is the silent-and-total failure the per-platform cases below pin down.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { eraNodeRoot, isProvisioned, nodeBinDir, provisionMatrix } from './provision-node-matrix.mjs';
import { loadNodeMatrix } from './node-matrix.mjs';

const { matrix } = loadNodeMatrix();

test('the bin dir matches the layout a real `nub node install` produces, PER PLATFORM', () => {
  // ⛔ THE TWO LAYOUTS ARE DIFFERENT PATHS, NOT A DETAIL, and both are verified against real installs.
  // POSIX has `bin/node`; the Windows zip puts `node.exe` at the version ROOT with no `bin/` at all
  // (listed on nub-win3: CHANGELOG.md, node.exe, npm.cmd, node_modules — no bin).
  //
  // Getting Windows wrong is SILENT AND TOTAL: `bin/node.exe` never exists, so every version reads
  // MISSING straight after a successful install, the pin never engages, and the hard gate blocks
  // forever. That is exactly what happened — `0/9 provisioned` while nub printed "Installed in 6.6s"
  // nine times.
  assert.equal(nodeBinDir('/r', '18.20.8', 'linux'), path.join('/r', 'node', '18.20.8', 'bin'));
  assert.equal(nodeBinDir('/r', '18.20.8', 'darwin'), path.join('/r', 'node', '18.20.8', 'bin'));
  assert.equal(nodeBinDir('/r', '18.20.8', 'win32'), path.join('/r', 'node', '18.20.8'),
    'the Windows archive is FLAT — node.exe sits at the version root, with no bin/');
  // No `v` prefix on the version directory — the trap if you assume nvm's layout.
  assert.ok(!nodeBinDir('/r', '18.20.8', 'linux').includes('v18'), 'the directory is not `v`-prefixed');
});

test('a Windows-shaped install is detected, and a POSIX-shaped read of it is not', () => {
  // The regression this locks down, from both sides: the same tree must read PRESENT under win32 and
  // MISSING under a posix reading, so a future refactor cannot quietly restore the `bin/` assumption.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-win-'));
  const flat = path.join(root, 'node', '18.20.8');
  fs.mkdirSync(flat, { recursive: true });
  fs.writeFileSync(path.join(flat, 'node.exe'), 'MZ');
  assert.equal(isProvisioned(root, '18.20.8', fs.existsSync, 'win32'), true,
    'a flat Windows install must be detected');
  assert.equal(isProvisioned(root, '18.20.8', fs.existsSync, 'linux'), false,
    'the same tree read as POSIX must NOT match — that asymmetry is the bug being pinned');
  fs.rmSync(root, { recursive: true, force: true });
});

test('present vs missing is decided by the executable, on a real tree', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-'));
  assert.equal(isProvisioned(root, '18.20.8', fs.existsSync, 'linux'), false, 'an empty root provisions nothing');

  // A directory alone is NOT provisioned — a half-finished install must not read as complete, or the
  // driver would pin PATH at a bin dir with no node in it.
  fs.mkdirSync(nodeBinDir(root, '18.20.8', 'linux'), { recursive: true });
  assert.equal(isProvisioned(root, '18.20.8', fs.existsSync, 'linux'), false,
    'a bin directory with no node executable must count as MISSING');

  fs.writeFileSync(path.join(nodeBinDir(root, '18.20.8', 'linux'), 'node'), '#!/bin/sh\n');
  assert.equal(isProvisioned(root, '18.20.8', fs.existsSync, 'linux'), true);

  // Windows spells it node.exe, and the same root must answer for both.
  fs.mkdirSync(nodeBinDir(root, '22.23.2', 'linux'), { recursive: true });
  fs.writeFileSync(path.join(nodeBinDir(root, '22.23.2', 'linux'), 'node.exe'), 'MZ');
  assert.equal(isProvisioned(root, '22.23.2', fs.existsSync, 'linux'), true,
    'node.exe must count even under a posix layout — a cross-compiled tree is still runnable');
  fs.rmSync(root, { recursive: true, force: true });
});

test('--check reports every matrix version and installs nothing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-check-'));
  let installs = 0;
  const { rows } = provisionMatrix({ root, check: true, run: () => { installs++; return { status: 0 }; } });
  assert.equal(installs, 0, '--check must never install');
  assert.equal(rows.length, matrix.versions.length, 'every matrix version is reported');
  assert.ok(rows.every((r) => r.present === false), 'nothing is present in an empty root');
  fs.rmSync(root, { recursive: true, force: true });
});

test('a per-version install failure does not abandon the other versions', () => {
  // A box that cannot fetch Node 19 must still be able to measure everything wanting 18 or 22 —
  // otherwise one bad mirror costs the whole run.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prov-fail-'));
  const attempted = [];
  const { rows } = provisionMatrix({
    root,
    run: (_cmd, args) => {
      const version = args[2];
      attempted.push(version);
      return version.startsWith('19.') ? { status: 1, stderr: 'mirror down' } : { status: 0 };
    },
  });
  assert.equal(attempted.length, matrix.versions.length,
    `every version must be attempted even after a failure, got ${attempted.length}`);
  const failed = rows.find((r) => r.version.startsWith('19.'));
  assert.equal(failed.present, false);
  assert.match(failed.error, /mirror down/, 'the failure reason must reach the row, not be swallowed');
  fs.rmSync(root, { recursive: true, force: true });
});

test('the era-node root honours NUB_ERA_NODE_ROOT and never defaults to a per-run cache', () => {
  assert.equal(eraNodeRoot({ NUB_ERA_NODE_ROOT: '/custom' }), '/custom');
  const fallback = eraNodeRoot({});
  assert.equal(fallback, path.join(os.homedir(), '.cache', 'nub'),
    'the default must be nub’s STABLE cache — a per-run NUB_CACHE_DIR would refetch ~20MB per package');
});
