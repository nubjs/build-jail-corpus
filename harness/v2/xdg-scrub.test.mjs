// The XDG base-directory scrub, EXECUTED — the drivers' own observe-arm invocation, run under real
// bash against a real child, and asserted on what that child's environment actually contained.
//
// ⛔ THE DEFECT THIS GUARDS. GitHub's ubuntu runner images export `XDG_CONFIG_HOME=/home/runner/
// .config`, an absolute path into the REAL home (actions/runner-images#2954). The observe arm
// redirected `HOME` and inherited that variable, so `configstore`/`xdg-basedir`, `env-paths` and
// friends — all of which PREFER `XDG_CONFIG_HOME` over `$HOME` — wrote into the real home. The
// classifier's definition of `userHome` is "a write that did not follow `$HOME`", so synthesis billed
// the package `write:{userHome}`: the whole home directory. The jail meanwhile withholds every
// `XDG_*` from the confined child (`defaults::lifecycle_scrubbed_env`, a default-deny allowlist), so
// the two arms differed in TWO variables where the parity contract allows exactly one.
//
// MEASURED on the committed corpus, from retained event logs: `bootstrap-slider@4.2.0`, linux, pid
// 52342 writes `/home/runner/.config/configstore/bower-github.json` (REAL home) and
// `$JAIL_HOME/.cache/bower/...` (JAIL home) from ONE process — `.cache` followed `$HOME` and
// `.config` did not. 45 of the 241 linux records carrying `write:{userHome}` have their entire
// real-home write set under `.config/`.
//
// ⛔ WHY THIS FILE EXECUTES SHELL INSTEAD OF GREPPING FOR `-u XDG_CONFIG_HOME`. A source match cannot
// tell a flag that reaches `env` from one that lands after the `VAR=VALUE` operands, where POSIX says
// it is the COMMAND NAME rather than an option — which is the same class of parse trap the driver
// already records beside this very line for `${ERA_PYTHON:+PYTHON=…}`. It also cannot tell whether
// the list word-splits: quoted, `$XDG_UNSET` is ONE argument spelled `-u XDG_CONFIG_HOME -u …` and
// the arm dies before npm runs. Both failures are invisible to a regex and immediate to a child that
// prints its own environment.
//
// ⛔ AND THE RED CONTROL IS IN THE FILE, NOT IN A COMMIT MESSAGE. `withoutScrub()` deletes
// `$XDG_UNSET` from the extracted invocation and re-runs the identical child; the control case
// asserts the variable comes BACK. Without it every case here would keep passing with the fix
// reverted.
import test from 'node:test';
import { test as nodeTest } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// ⛔ SKIPPED ON WINDOWS — the cases below drive `bash`, and MEASURED on the corpus Windows VM there
// is none: `where bash` finds nothing and Git-for-Windows is absent, so they die `spawnSync bash
// ENOENT`, a failure that says nothing about the scrub. The source-only cases stay armed, and they
// are the ones that matter on that platform: they hold the DECISION that `measure-windows.mjs` is
// deliberately out of scope, which is exactly the kind of asymmetry a reader would otherwise
// "harmonise" away.
const SHELL_SKIP = process.platform === 'win32'
  ? 'no bash on Windows: this case executes an extracted driver invocation'
  : false;
const shellTest = (name, fn) => nodeTest(name, { skip: SHELL_SKIP }, fn);

const HERE = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');
const SCRUB = read('xdg-scrub.sh');
const LINUX = read('measure.sh');
const MACOS = read('measure-macos.sh');

/**
 * The Linux driver's observe-arm invocation, verbatim: the env-prefix assignment through the line
 * that captures its exit status. Anchored on the two literal lines rather than on offsets, so an
 * edit above cannot silently shift the slice.
 */
const OBSERVE_ARM = (() => {
  const lines = LINUX.split('\n');
  const start = lines.findIndex((l) => l.startsWith('PATH="${ARM_PATH:-${ERA_PATH:-$PATH}}" HOME="$JAIL_HOME"'));
  const end = lines.findIndex((l, i) => i > start && l === 'OBS_RC=$?');
  return start < 0 || end < 0 ? '' : lines.slice(start, end + 1).join('\n');
})();

test('INSTRUMENT: the observe arm was located and is the real one', () => {
  // Without this, "the child has no XDG_CONFIG_HOME" is satisfied by running the empty string.
  assert.ok(OBSERVE_ARM.length > 200, `the observe arm was not found in measure.sh (got ${OBSERVE_ARM.length} chars)`);
  for (const needle of ['HOME="$JAIL_HOME"', 'strace', 'npm rebuild', '$XDG_UNSET', 'OBS_RC=$?']) {
    assert.ok(OBSERVE_ARM.includes(needle), `the extracted arm no longer contains \`${needle}\``);
  }
});

/**
 * Run the extracted arm with `strace` and `npm` replaced by stubs that let the chain terminate in a
 * dump of the child's environment. Everything else is the driver's own text and the harness's own
 * `arm-cap.mjs`, run by the real node.
 *
 * ⛔ THE STUBS ARE THE TWO THINGS THAT CANNOT RUN HERE, AND NOTHING ELSE IS STUBBED. `strace` is
 * Linux-only (this suite also runs on the macOS dev box) and `npm rebuild` would hit the registry.
 * The env-prefix assignment, the `env` invocation, the `-u` word-splitting, the option/operand order
 * and the process-group cap are all executed as shipped.
 */
const runArm = ({ venue, source = OBSERVE_ARM }) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'xdgscrub-'));
  const bin = path.join(root, 'bin');
  const obs = path.join(root, 'observe');
  fs.mkdirSync(bin); fs.mkdirSync(obs);
  // `strace -f -e trace=… -o <file> <cmd…>`: consume the options, exec the rest. Written as a loop
  // rather than a `shift <n>`, because a fixed count silently execs the WRONG word the moment the
  // driver's flag list changes — which reads as the arm failing rather than as a stale stub.
  fs.writeFileSync(path.join(bin, 'strace'),
    '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -f) shift ;; -e|-o) shift 2 ;; *) break ;; esac; done\nexec "$@"\n');
  // Stands in for `npm rebuild`, and dumps what the traced process actually inherited.
  fs.writeFileSync(path.join(bin, 'npm'), `#!/bin/sh\nexec /usr/bin/env > '${obs}/child-env.txt' 2>&1\n`);
  fs.chmodSync(path.join(bin, 'strace'), 0o755);
  fs.chmodSync(path.join(bin, 'npm'), 0o755);

  const script = [
    'set -uo pipefail',
    `. '${path.join(HERE, 'xdg-scrub.sh')}'`,
    `HERE='${HERE}'`,
    `HARNESS_NODE='${process.execPath}'`,
    `OBS='${obs}'`,
    `ARM_PATH='${bin}:${process.env.PATH}'`,
    `JAIL_HOME='${root}/jailhome'`,
    `JAIL_TMP='${root}/jailtmp'`,
    `JAIL_TOOLS='${root}/tools'`,
    "REBUILD_SPEC='fixture@1.0.0'",
    'ARM_CAP_SECS=60',
    source,
    'echo "ARM_RC=$OBS_RC"',
  ].join('\n');

  const stdout = execFileSync('bash', ['-c', script], {
    encoding: 'utf8',
    // Reduced to what the arm needs plus the venue under test, so an `XDG_*` seen in the child came
    // from `venue` and from nowhere else. NOT a claim that the child's env is exactly this map:
    // MEASURED on the macOS dev box, `bash -c` with this same explicit env still hands the child
    // `NVM_DIR`/`NVM_BIN`/`SHLVL`. None of them is an XDG name, so the assertions below name specific
    // keys rather than asserting over the whole environment.
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...venue },
  });
  const childEnv = fs.readFileSync(path.join(obs, 'child-env.txt'), 'utf8');
  const get = (k) => {
    const m = new RegExp(`^${k}=(.*)$`, 'm').exec(childEnv);
    return m ? m[1] : null;
  };
  fs.rmSync(root, { recursive: true, force: true });
  return { stdout, childEnv, get };
};

/** The same arm with `$XDG_UNSET` deleted — the fix reverted, and nothing else changed. */
const withoutScrub = () => OBSERVE_ARM.replace(' env $XDG_UNSET ', ' env ');

const RUNNER_VENUE = {
  // The real value from the ubuntu runner image (actions/runner-images#2954).
  XDG_CONFIG_HOME: '/home/runner/.config',
  XDG_DATA_HOME: '/home/runner/.local/share',
  XDG_STATE_HOME: '/home/runner/.local/state',
  XDG_CACHE_HOME: '/home/runner/.cache',
};

// ── Behaviour ─────────────────────────────────────────────────────────────────────────────────────

shellTest('the traced child sees NO XDG base directory, so a config write follows $HOME into the jail home', () => {
  const { get, childEnv, stdout } = runArm({ venue: RUNNER_VENUE });
  assert.match(stdout, /ARM_RC=0/, `the arm must have run at all:\n${stdout}`);
  for (const k of Object.keys(RUNNER_VENUE)) {
    assert.equal(get(k), null,
      `${k} reached the traced script, so a package resolving its config dir lands in the REAL home and is billed write:{userHome}\n${childEnv}`);
  }
  // The positive half: the redirect the scrub depends on is still in place, so the fallback target
  // is the private jail home rather than the real one. An assertion that only checks ABSENCE would
  // pass just as well on a child that never started.
  assert.match(get('HOME') ?? '', /\/jailhome$/, `HOME must still be redirected:\n${childEnv}`);
});

shellTest('⛔ RED CONTROL: with `$XDG_UNSET` removed, the venue variable reaches the child again', () => {
  const { get, childEnv } = runArm({ venue: RUNNER_VENUE, source: withoutScrub() });
  assert.equal(get('XDG_CONFIG_HOME'), '/home/runner/.config',
    `the control must reproduce the DEFECT, or the case above proves nothing:\n${childEnv}`);
});

shellTest('CONTROL: on a machine that sets no XDG variable the scrub is a silent no-op', () => {
  const { stdout, childEnv, get } = runArm({ venue: {} });
  assert.equal(get('XDG_CONFIG_HOME'), null, `nothing was set, so nothing may appear:\n${childEnv}`);
  assert.doesNotMatch(stdout, /XDG-ENV scrubbed/, `a no-op must not claim it removed something:\n${stdout}`);
});

shellTest('⛔ the scrub REMOVES rather than blanking, because absence and empty are not the same answer', () => {
  // `xdg-basedir` treats `''` as falsy and falls back, but Go's `os.UserConfigDir()` and any consumer
  // testing `'XDG_CONFIG_HOME' in env` do not. The jail produces ABSENCE, so absence is the contract.
  const { childEnv } = runArm({ venue: RUNNER_VENUE });
  assert.doesNotMatch(childEnv, /^XDG_CONFIG_HOME=$/m, `an empty XDG_CONFIG_HOME is not the jail's answer:\n${childEnv}`);
});

shellTest('what the venue actually had is reported, so a record can name the image that set it', () => {
  const { stdout } = runArm({ venue: { XDG_CONFIG_HOME: '/home/runner/.config' } });
  assert.match(stdout, /XDG-ENV scrubbed from the traced child:.*XDG_CONFIG_HOME/,
    `the scrub must say what it found:\n${stdout}`);
});

// ── The two POSIX drivers cannot drift, and Windows is out of scope ON PURPOSE ────────────────────

test('both POSIX drivers SOURCE the shared scrub rather than copying its key list', () => {
  for (const [name, src] of [['measure.sh', LINUX], ['measure-macos.sh', MACOS]]) {
    assert.match(src, /\.\s+"\$HERE\/xdg-scrub\.sh"/,
      `${name} does not source xdg-scrub.sh, so its key list can drift from the other driver's`);
  }
});

test('both POSIX drivers pass the list to the TRACED child, after `env` and before its operands', () => {
  // Order is the whole trap: POSIX requires options to precede `VAR=VALUE` operands, so a list that
  // lands after one is read as the command name and the arm dies before npm runs.
  assert.match(LINUX, /\n  env \$XDG_UNSET \$\{ERA_PYTHON:\+PYTHON="\$ERA_PYTHON"\} \\/,
    'measure.sh no longer passes $XDG_UNSET immediately after `env`');
  const macosChains = MACOS.split('\n').filter((l) => l.includes('-H env $XDG_UNSET'));
  assert.equal(macosChains.length, 2,
    `measure-macos.sh must carry the list in BOTH the traced chain and the child-env dump that claims to reproduce it — found ${macosChains.length}`);
});

test('⛔ the driver keeps XDG_CACHE_HOME for ITSELF — the scrub is `env -u`, never an `unset`', () => {
  // This is the one that would break the harness rather than a record. `measure.sh` derives nub's
  // store, tools, eviction root and jail-home purge root from `${XDG_CACHE_HOME:-$HOME/.cache}`; an
  // `unset` in the driver's own shell would silently move all of them. `env -u` is scoped to the one
  // exec, which is what lets the child lose the name while the driver keeps it.
  // ⛔ THE ANCHOR ALLOWS A SEPARATOR, NOT JUST A LINE START. Written as `/^\s*unset\s/m` this case
  // passed against a real `…; unset "$k"; fi` injected into the loop — a mid-line `unset` is the
  // shape this would actually be added in, and it was the shape the first version could not see.
  assert.doesNotMatch(SCRUB, /(?:^|[;&|(])\s*unset\s/m,
    'xdg-scrub.sh must not unset anything in the sourcing shell — see its header');
  assert.ok(LINUX.includes('${XDG_CACHE_HOME:-$HOME/.cache}'),
    'measure.sh no longer derives nub\'s cache root from XDG_CACHE_HOME — re-read this test before deleting it');
});

test('⛔ measure-windows.mjs is deliberately NOT given this scrub, and the reason is recorded', () => {
  // MEASURED across the 1,688 committed win32 captures: zero carry an XDG name, every real-home
  // write is USERPROFILE-derived, and the Windows driver SETS `XDG_CACHE_HOME` itself per arm to
  // relocate nub's store — so a blanket scrub of that name there would be actively wrong. Pinned so
  // the asymmetry reads as a decision rather than as the gap `ci-env-scrub.test.mjs` guards against.
  const win = read('measure-windows.mjs');
  assert.ok(!/XDG_UNSET|xdg-scrub/.test(win),
    'measure-windows.mjs has grown an XDG scrub; if that is intended, update the carve-out in xdg-scrub.sh and this case');
  assert.match(win, /XDG_CACHE_HOME: armCache/,
    'the per-arm XDG_CACHE_HOME this carve-out is about is gone from measure-windows.mjs');
  assert.match(SCRUB, /NOT MIRRORED IN `measure-windows\.mjs`/,
    'xdg-scrub.sh no longer carries the Windows carve-out reasoning');
});

test('the scrubbed set is the four per-user base dirs, and the search-path names are excluded', () => {
  const m = /XDG_KEYS="([^"]+)"/.exec(SCRUB);
  assert.ok(m, 'ANCHOR DRIFT: xdg-scrub.sh no longer defines XDG_KEYS');
  const keys = m[1].trim().split(/\s+/);
  assert.deepEqual(keys, ['XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_STATE_HOME', 'XDG_CACHE_HOME']);
  // `XDG_DATA_DIRS`/`XDG_CONFIG_DIRS` are colon-lists of SYSTEM paths and `XDG_RUNTIME_DIR` points
  // outside the home, so none can manufacture the `userHome` grant this scrub exists to remove.
  for (const excluded of ['XDG_DATA_DIRS', 'XDG_CONFIG_DIRS', 'XDG_RUNTIME_DIR']) {
    assert.ok(!keys.includes(excluded), `${excluded} is not a per-user write target and must stay out of the list`);
  }
});
