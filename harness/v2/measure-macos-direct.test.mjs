// Direct-mode argument handling for `measure-macos.sh`. `node --test harness/v2/measure-macos-direct.test.mjs`
//
// ⛔ WHAT IS TESTABLE HERE AND WHAT IS NOT. Every case below exits BEFORE the driver needs dtrace or
// root, so they run on any Mac. The arms themselves need a runner and are not covered here — this
// file pins the contract that decides whether an arm is even attempted, and whether its caller can
// tell the three outcomes apart.
//
// ⛔ THE EXIT CODES ARE THE CONTRACT. `falsify.mjs` and `e2e.mjs` both branch on them, and the three
// outcomes are genuinely different things:
//     0  SUFFICIENT    installed, artifacts matched OBSERVE
//     1  INSUFFICIENT  the package needs MORE than this grant
//     3  VOID          the override never engaged; NOTHING was measured
// Collapsing VOID into INSUFFICIENT would turn an instrument failure into a fabricated capability
// finding — "the package needs more" asserted from a run that measured nothing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const DRIVER = join(new URL('.', import.meta.url).pathname, 'measure-macos.sh');

// ⛔ STUBBED, BECAUSE A "VALIDATION" TEST THAT REACHES OBSERVE IS NOT A VALIDATION TEST. The first
// version ran the real driver: the refusal cases exited at a gate, but every POSITIVE control fell
// through to a real `npm install` and left a fixture directory in $HOME. Measured: ~/v2m-* grew by
// two per run, each holding a fetch.log with `ETARGET … No matching version for p@1.0.0`. They were
// fast only because that version does not exist on npm — publish it and the suite starts doing real
// measurements. Same stub pattern as probes/macos-driver-smoke/run.sh.
const STUB = mkdtempSync(join(tmpdir(), 'drvstub-'));
for (const c of ['dtrace', 'sudo', 'npm', 'dscl', 'sw_vers', 'csrutil', 'chown']) {
  writeFileSync(join(STUB, c), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
}
const run = (...args) => {
  const r = spawnSync('bash', [DRIVER, ...args], {
    encoding: 'utf8', env: { ...process.env, PATH: `${STUB}:${process.env.PATH}`, HOME: STUB },
  });
  return { rc: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') };
};

test('a malformed --at-grant is refused before anything is measured', () => {
  // RED ON REVERT: drop the JSON shape check and the driver proceeds to build a catalog from a
  // string that is not an object, producing an arm whose failure says nothing about the package.
  for (const bad of ['notjson', 'deps', 'write.deps', '[]']) {
    const { rc, out } = run('p', '1.0.0', '/bin/nub', '--at-grant', bad);
    assert.equal(rc, 2, `\`${bad}\` must be refused: ${out}`);
    assert.match(out, /--at-grant needs a JSON object/);
  }
});

test('a well-formed --at-grant is NOT refused by the shape check', () => {
  // The positive control. Without it every assertion above is satisfied by a driver that rejects
  // every possible value, which would make direct mode unusable while looking well-guarded.
  const { rc, out } = run('p', '1.0.0', '/bin/nub', '--at-grant', '{"network":true}');
  assert.notEqual(rc, 2, `a valid grant must get past validation, got rc=${rc}: ${out}`);
  assert.doesNotMatch(out, /needs a JSON object/);
});

test('the two flags ask different questions, so passing both is refused', () => {
  const { rc, out } = run('p', '1.0.0', '/bin/nub', '--at-grant', '{}', '--at-catalog', '/etc/hosts');
  assert.equal(rc, 2);
  assert.match(out, /ask two different questions/);
});

test('--at-catalog refuses a missing or empty file rather than measuring nothing', () => {
  // An empty catalog engages no override, so the arm would come back VOID after a full OBSERVE.
  // Refusing up front costs one exit instead of one measurement.
  for (const f of ['/nope/nothere.json', '/dev/null']) {
    const { rc, out } = run('p', '1.0.0', '/bin/nub', '--at-catalog', f);
    assert.equal(rc, 2, `\`${f}\` must be refused: ${out}`);
    assert.match(out, /--at-catalog needs a non-empty catalog FILE/);
  }
});

test('a real catalog file is NOT refused — the paired positive control', () => {
  const dir = mkdtempSync(join(tmpdir(), 'atcat-'));
  const f = join(dir, 'cat.json');
  writeFileSync(f, JSON.stringify({ packages: { p: { default: { network: true } } } }));
  const { rc, out } = run('p', '1.0.0', '/bin/nub', '--at-catalog', f);
  assert.notEqual(rc, 2, `a non-empty catalog must get past validation, got rc=${rc}: ${out}`);
});

test('a flag in the nub-binary slot is a FLAG, not a path — asserted on the header it prints', () => {
  // ⛔ THE BUG THIS PORTS A FIX FOR. `measure.sh` took `${3:-}` blindly, so the documented form
  // `<pkg> <ver> --at-grant '<json>'` exec'd `--at-grant install` — every arm rc=127
  // `--at-grant: command not found`, reported as VOID. The verdict was honest, which is exactly why
  // it survived: nothing was ever mis-recorded, the flag was just unusable without also naming a
  // binary. Here the tell is that validation still runs, rather than the driver treating the flag
  // as a nub path and failing later for an unrelated reason.
  // ⛔ THE FIRST VERSION OF THIS CASE COULD NOT FAIL ON THE THING IT NAMED. It passed a MALFORMED
  // grant, so validation refused it either way — reverting the `case "${3:-}"` guard to a blind
  // `NUB="${3:-}"` left all six tests green. The arg loop scans "$@" independently of $3, so the
  // only observable difference is what the driver believes the BINARY is, and the header line is
  // where it says so. A valid grant is required to get past validation and reach that line.
  const { out } = run('p', '1.0.0', '--at-grant', '{"network":true}');
  assert.match(out, /nub=<none>/,
    `with no binary named the header must say nub=<none>, not treat the flag as a path:\n${out}`);
  assert.doesNotMatch(out, /nub=--at-grant/, 'the flag must never be taken as the nub path');
});
