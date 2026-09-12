// Regression coverage for Bash 3.2's `set -u` handling of empty arrays in measure-macos.sh.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const HERE = import.meta.dirname;
const DRIVER = path.join(HERE, 'measure-macos.sh');
const macosShellTest = (name, fn) => test(name, { skip: process.platform === 'win32' }, fn);
const source = fs.readFileSync(DRIVER, 'utf8');
const functionMatch = source.match(/^(run_macos_verify \(\) \{[\s\S]*?^\})$/m);
assert.ok(functionMatch, 'measure-macos.sh must retain the executable verifier invocation helper');
const VERIFY_FUNCTION = functionMatch[1];

const bashCandidates = [...new Set(['/bin/bash', '/opt/homebrew/bin/bash', '/usr/local/bin/bash', process.env.BASH].filter((candidate) =>
  candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile()))];
const bashVersion = (bash) => execFileSync(bash, ['--version'], { encoding: 'utf8' }).match(/version ([0-9]+\.[0-9]+)/)?.[1];
const bash3 = bashCandidates.find((bash) => bashVersion(bash)?.startsWith('3.'));

const invoke = (bash, policy, implementation = VERIFY_FUNCTION) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'macos-empty-array-'));
  const bin = path.join(dir, 'bin');
  const args = path.join(dir, 'sudo-args.txt');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'sudo'), '#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_LOG"\n', { mode: 0o755 });
  const script = path.join(dir, 'invoke.sh');
  fs.writeFileSync(script, [
    'set -u',
    implementation,
    "HERE='/fixture/harness v2'",
    'RUNUSER=runner',
    'NUB=/fixture/nub',
    policy === undefined ? 'unset NUB_JAIL_DUMP_POLICY' : `NUB_JAIL_DUMP_POLICY=${JSON.stringify(policy)}`,
    "run_macos_verify '/fixture/arm with spaces' '/fixture/cache with spaces'",
  ].join('\n'));
  try {
    const result = spawnSync(bash, [script], {
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`, ARGV_LOG: args },
    });
    const captured = fs.existsSync(args) ? fs.readFileSync(args, 'utf8').trimEnd().split('\n') : [];
    return { result, args: captured };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
};

for (const bash of bashCandidates) {
  const label = `${bash} (${bashVersion(bash)})`;
  for (const [kind, policy] of [['unset', undefined], ['explicitly empty', '']]) {
    macosShellTest(`${kind} policy reaches env without an empty-array expansion on ${label}`, () => {
      const { result, args } = invoke(bash, policy);
      assert.equal(result.status, 0, result.stderr);
      assert.deepEqual(args.slice(-4), ['/bin/bash', '/fixture/harness v2/macos-verify.sh', '/fixture/arm with spaces', '/fixture/nub']);
      assert.ok(args.includes('NUB_CACHE_DIR=/fixture/cache with spaces'), args.join('\n'));
      assert.ok(!args.some((arg) => arg.startsWith('NUB_JAIL_DUMP_POLICY=')), args.join('\n'));
    });
  }

  macosShellTest(`nonempty policy stays one whitespace-preserving env argument on ${label}`, () => {
    const policy = '  retain internal spaces  ';
    const { result, args } = invoke(bash, policy);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(args.includes(`NUB_JAIL_DUMP_POLICY=${policy}`), args.join('\n'));
  });
}

macosShellTest('CONTROL: the withheld empty-array implementation aborts under Bash 3 with set -u', (t) => {
  if (!bash3) {
    t.skip('Bash 3 is unavailable on this host; macOS CI exercises this control with /bin/bash');
    return;
  }
  const legacy = `run_macos_verify () {
  local verify_dir="$1" verify_cache="$2"
  local -a dump_env=()
  [ -n "${'${NUB_JAIL_DUMP_POLICY:-}'}" ] && dump_env=("NUB_JAIL_DUMP_POLICY=$${'NUB_JAIL_DUMP_POLICY'}")
  sudo -u "$RUNUSER" -H env "PATH=$PATH" NUB_CACHE_DIR="$verify_cache" \\
    NUB_BUILD_JAIL_CATALOG="$verify_dir/cat.json" "${'${dump_env[@]}'}" \\
    /bin/bash "$HERE/macos-verify.sh" "$verify_dir" "$NUB"
}`;
  const { result, args } = invoke(bash3, undefined, legacy);
  assert.notEqual(result.status, 0, 'the prior empty-array invocation unexpectedly ran under Bash 3');
  assert.deepEqual(args, [], 'the prior form must fail before sudo/env executes');
  assert.match(result.stderr, /dump_env.*unbound variable/);
});
