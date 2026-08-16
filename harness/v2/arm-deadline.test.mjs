// The per-arm deadline must admit a SLOW arm while still cutting a HUNG one, and it must stay under
// the batch's per-package budget or it is dead code.
//
// What forced this: 40 of 448 win32 records in the 25% run came back HARNESS-TIMEOUT (against 1 of
// 2,569 on Linux) with durations clustered in a 637-819 s band -- one fixed 600 s ceiling, not 40
// per-package causes. A HARNESS-TIMEOUT carries no measurement at all, so each one is a package the
// catalog must fall back to a base profile for. Asserted on source because both drivers run a whole
// measurement at import.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const WIN = fs.readFileSync(path.join(import.meta.dirname, 'measure-windows.mjs'), 'utf8');
const BATCH = fs.readFileSync(path.join(import.meta.dirname, 'run-batch-v2.mjs'), 'utf8');

const armDefault = (src) => {
  const m = /flag\('--arm-timeout',\s*'(\d+)'\)/.exec(src);
  assert.ok(m, "the win32 driver's --arm-timeout default is gone — the deadline has been rewritten");
  return Number(m[1]);
};

const budgetDefault = (src) => {
  // BUDGET_MS is expressed in SECONDS and multiplied by 1000, so read the multiplier too rather
  // than assuming the unit — that assumption is exactly how the two limits got compared wrongly.
  const m = /opt\('--budget',\s*process\.env\.NUB_CORPUS_PKG_BUDGET\s*\?\?\s*'(\d+)'\)\)\s*\*\s*1000/.exec(src);
  assert.ok(m, 'run-batch-v2 BUDGET_MS default is gone — re-derive the relationship below');
  return Number(m[1]) * 1000;
};

test('the arm deadline is long enough for a slow Windows arm', () => {
  // ⛔ THE FLOOR IS A MEASUREMENT, NOT A PREFERENCE. `redis-memory-server@0.17.1` times out at
  // 600 s and completes `rc=0 artifacts=42/42` at 1800 s, so any default at or below 600 s
  // re-introduces the 8.9% coverage loss this file exists to prevent.
  const arm = armDefault(WIN);
  assert.ok(arm > 600_000,
    `arm deadline ${arm} ms is back at or below the 600 s ceiling that lost 40 of 448 win32 records`);
  assert.ok(arm >= 1_800_000,
    `arm deadline ${arm} ms is below the 1800 s at which a known-slow arm was PROVEN to complete`);
});

test('the arm deadline stays BELOW the per-package budget, or it never fires', () => {
  // ⛔ THE CROSS-FILE INVARIANT, AND THE ONE A SINGLE-FILE REVIEW MISSES. run-batch-v2 spawns the
  // driver under BUDGET_MS. If the arm deadline were >= that budget, the budget would always cut
  // first, the arm deadline would be unreachable, and every slow package would land as a
  // whole-driver kill (rc 124) instead of a per-arm TIMED-OUT that names which arm hung.
  const arm = armDefault(WIN);
  const budget = budgetDefault(BATCH);
  assert.ok(arm < budget,
    `arm deadline ${arm} ms >= per-package budget ${budget} ms — the arm deadline can never fire`);
});

test('the deadline is still overridable, so a lane can lower it', () => {
  // The fix raised a DEFAULT; it must not have hardcoded a constant. A lane on a slower box, or a
  // deliberate probe, needs to set this down without editing the driver.
  assert.match(WIN, /flag\('--arm-timeout'/,
    '--arm-timeout must remain a flag — a hardcoded deadline cannot be tuned per lane');
});
