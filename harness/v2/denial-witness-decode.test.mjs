// THE PRODUCER CHAIN, END TO END WITHOUT A JAIL: raw strace text -> `adapters/linux.mjs --jailed`
// -> `denial-witness.mjs` -> a marker `record.mjs` parses.
// `node --test harness/v2/denial-witness-decode.test.mjs`.
//
// ⛔ WHY THIS EXISTS SEPARATELY FROM `denial-witness.test.mjs`. That file feeds the scorer normalized
// event objects it constructs itself, so it proves the SCORER is right and proves nothing about
// whether the adapter ever produces that shape from a real trace. Two things sit between them and
// both have broken silently before: the adapter's `life` attribution (whether the lifecycle subtree
// is identified at all) and its errno decode. Here the input is raw strace text in the exact syntax
// of a committed trace, so the whole chain is exercised.
//
// ⛔ THE LINE FORMATS ARE COPIED FROM A COMMITTED TRACE, NOT INVENTED.
// `records-v2/runs/linux-x64/@pulumi+gcp/0.16.9/trace.txt.gz` contains, verbatim in shape:
//
//   16301 execve("…/npm-lifecycle/node-gyp-bin/sh", ["sh", "-c", "node scripts/install-pulumi-plug"...], …) = 0
//   16315 openat(AT_FDCWD, "/home/runner/.pulumi/logs/pulumi-…-plugin_install.log", O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4
//
// A fixture in a different syntax would certify this chain against a tracer nobody runs.
//
// ⛔ WHAT THIS CANNOT PROVE, AND IT IS THE ONE ASSUMPTION LEFT. It shows the chain works when the
// jailed arm's trace contains a successful `execve` of a shell with `-c` — the adapter's lifecycle
// predicate. Whether a jailed `nub install` produces that shape is a property of nub's own spawn
// path and can only be settled on a Linux runner. If it does not, the adapter attributes no
// lifecycle process, the witness returns VOID, and the record keeps the wide grant — the marker
// reports `lifecyclePids: 0`, so the first re-measure says so in `driver.out` rather than silently
// licensing anything.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const HOME = '/home/runner';
const ROOT = '/home/runner/v2-uyXXxI';
const ARM = `${ROOT}/verify-drop-nowriteuserHome`;

const LIFECYCLE_EXEC = '16301 execve("/home/runner/.cache/nub/era-node/10.24.1/node-v10.24.1-linux-x64/'
  + 'lib/node_modules/npm/node_modules/npm-lifecycle/node-gyp-bin/sh", ["sh", "-c", '
  + '"node scripts/install-pulumi-plugin.js resource gcp"], 0xeb64d60 /* 286 vars */) = 0';

// The chain: write a trace, decode it with the shipped adapter, score it, return the marker payload.
const chain = (traceLines, { jailed = true } = {}) => {
  const dir = mkdtempSync(join(tmpdir(), 'dwd-'));
  const trace = join(dir, 'tr-i.txt');
  writeFileSync(trace, traceLines.join('\n') + '\n');
  const events = join(dir, 'events.ndjson');
  execFileSync(process.execPath, [join(HERE, 'adapters', 'linux.mjs'), trace,
    '--project', ARM, '--home', HOME, '--jail-home', `${ROOT}/jailhome`,
    '--jail-tmp', '/tmp/nub-tmp-x', '--pkg', '@pulumi/gcp', '--version', '0.16.9',
    ...(jailed ? ['--jailed'] : []), '--out', events], { stdio: 'ignore' });
  const out = execFileSync(process.execPath, [join(HERE, 'denial-witness.mjs'),
    '--cap', 'no-write-userHome', '--events', events, '--exclude', ROOT], { encoding: 'utf8' });
  return { out, header: JSON.parse(readFileSync(events, 'utf8').split('\n')[0]),
    payload: JSON.parse(/DENIAL-WITNESS (\{.*\})/.exec(out)[1]) };
};

// Enough decoded events to clear the scorer's liveness floor, all outside the home.
const filler = (n) => Array.from({ length: n }, (_, i) =>
  `16315 openat(AT_FDCWD, "/tmp/nub-tmp-x/f${i}", O_WRONLY|O_CREAT, 0666) = 4`);

test('a refused home write in a jailed trace reaches the scorer as WITNESSED', () => {
  const { payload, header } = chain([
    LIFECYCLE_EXEC,
    ...filler(250),
    '16315 openat(AT_FDCWD, "/home/runner/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp",'
      + ' O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EACCES (Permission denied)',
  ]);
  assert.equal(header.jailed, true, '--jailed must reach the header or the scorer refuses the stream');
  assert.equal(payload.verdict, 'WITNESSED',
    `expected WITNESSED; the adapter attributed ${payload.lifecyclePids} lifecycle pid(s) `
    + `and decoded ${payload.events} events`);
  assert.equal(payload.scope, 'userHome');
  assert.ok(payload.lifecyclePids > 0, 'the adapter must attribute the lifecycle subtree');
});

test('the same trace with the write SUCCEEDING decodes as CLEAN', () => {
  // The negative control for the pair above: identical input but `= 4` instead of `= -1 EACCES`. If
  // this also read WITNESSED the errno would not be reaching the scorer at all.
  const { payload } = chain([
    LIFECYCLE_EXEC,
    ...filler(250),
    '16315 openat(AT_FDCWD, "/home/runner/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp",'
      + ' O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 4',
  ]);
  assert.equal(payload.verdict, 'CLEAN');
});

test('a trace with no lifecycle shell is VOID — attribution failure never reads as CLEAN', () => {
  const { payload } = chain([...filler(250),
    '16315 openat(AT_FDCWD, "/home/runner/.pulumi/x", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)']);
  assert.equal(payload.verdict, 'VOID');
  assert.equal(payload.lifecyclePids, 0);
});

test('the adapter without --jailed produces a stream the scorer refuses', () => {
  // RED ON REVERT: delete the `jailed` key from the adapter header. The OBSERVE stream — unjailed, so
  // holding no jail refusal at all — then scores CLEAN for every package measured.
  const { payload } = chain([LIFECYCLE_EXEC, ...filler(250)], { jailed: false });
  assert.equal(payload.verdict, 'VOID');
  assert.match(payload.scope ?? 'null', /null/);
});

test('the emitted marker is the one record.mjs parses — producer and consumer agree', () => {
  const { out } = chain([
    LIFECYCLE_EXEC, ...filler(250),
    '16315 openat(AT_FDCWD, "/home/runner/.pulumi/x", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)',
  ]);
  const line = out.split('\n').find((l) => l.startsWith('DENIAL-WITNESS'));
  const r = parseDriverLog([
    '  ARM-FALSIFIABILITY {"reasons":["gate-vacuous"]}',
    '  ⛔ ARMS-UNFALSIFIABLE — the artifact gate carries no signal for this package:',
    '  VERIFY[synth] rc=0 grant={"write":{"userHome":true}}',
    '  => VERIFIED {"write":{"userHome":true}}',
    `  ${line}`,
    "     ⛔ OVER-PREDICTED — the strictly narrower {} also verifies; 'no-write-userHome' was not needed",
  ].join('\n'));
  assert.deepEqual(r.denialWitness, { 'no-write-userHome': 'WITNESSED' });
  assert.deepEqual(r.grant, { write: { userHome: true } }, 'the wide grant must survive');
});

test('the driver wires the witness to the userHome arm and to no other', () => {
  // ⛔ THE SHELL SIDE, MATCHED ON EXECUTABLE LINES ONLY. Searching raw source is what made the first
  // `descent-contract.test.mjs` vacuous — the tokens it looked for appeared in the comment that
  // explained the contract, so renaming the real code left every assertion green.
  const src = readFileSync(join(HERE, 'measure.sh'), 'utf8')
    .split('\n').map((l) => l.replace(/(^|\s)#.*$/, '')).join('\n');
  assert.match(src, /denial_witness \(\)/, 'measure.sh must define the helper');
  assert.match(src, /\[ -n "\$WTRACE" \] && denial_witness "\$DLBL" "\$cap"/,
    'the descent loop must call it for the arm it just ran');
  assert.match(src, /\[ "\$cap" = "no-write-userHome" \]/,
    'only the scope the scorer expresses may be traced');
  assert.match(src, /--jailed/, 'the arm decode must mark the stream jailed');
  // macOS is deliberately NOT wired: its traced branch runs `nub install` alone and skips
  // `approve-builds`, so tracing a descent arm there would change the arm's own verdict.
  const mac = readFileSync(join(HERE, 'measure-macos.sh'), 'utf8')
    .split('\n').map((l) => l.replace(/(^|\s)#.*$/, '')).join('\n');
  assert.ok(!/denial_witness/.test(mac),
    'if macOS gains this, its traced branch must first run approve-builds like the untraced one');
});
