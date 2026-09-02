// Pre-staging a self-downloading launcher, so its payload never reaches the measured HOME.
//
// ⛔ THE MEASUREMENT THESE TESTS PIN. `@pulumi/awsx@2.9.0`, real package, HOME redirected to a scratch
// dir, the package's own `install` script run three ways:
//
//   arm                       script rc   HOME files   HOME bytes   tool payload in home
//   no pulumi                      0           0            0       —
//   npm launcher on PATH           0          18        369 MB      yes — 291 MB of CLI
//   launcher pre-staged            0           5         78 MB      no
//
// The 5 that remain are `.pulumi/plugins/resource-awsx-v2.9.0/**` and one `.pulumi/logs/*` — the
// package's own requirement, and what the catalog's `write:{userHome:true}` is FOR. The 13 that leave
// are the CLI's own binaries. A test that only checked "pulumi ran" would pass in the middle row too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { prestageLauncher, prestageMarker, copyBinDir, SELF_DOWNLOADING } from './prestage-launcher.mjs';

/** An observe tree with a launcher shim in `.bin`, and a fake download the injected runner performs. */
function fixture({ payload = ['pulumi', 'pulumi-language-nodejs', 'pulumi-watch'] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'prestage-'));
  const observeDir = path.join(root, 'observe');
  const binDir = path.join(observeDir, 'node_modules', '.bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'pulumi'), '#!/usr/bin/env node\n// launcher shim\n');
  const stageDir = path.join(root, '.prestage-pulumi');
  // Stands in for the launcher's first-use download: it writes into whatever PULUMI_HOME names.
  const run = (_cmd, _args, opts) => {
    const home = opts.env.PULUMI_HOME;
    const out = path.join(home, 'versions', '3.260.0', 'bin');
    fs.mkdirSync(out, { recursive: true });
    for (const name of payload) fs.writeFileSync(path.join(out, name), `real ${name}\n`);
    return { status: 0, stdout: 'v3.260.0', stderr: '' };
  };
  return { root, observeDir, binDir, stageDir, run };
}

test('the payload lands in the arm bin and NOT in the home the launcher would have used', () => {
  const f = fixture();
  const home = path.join(f.root, 'jailhome');
  fs.mkdirSync(home);
  const r = prestageLauncher('pulumi', {
    observeDir: f.observeDir, stageDir: f.stageDir, env: { HOME: home }, run: f.run,
  });
  assert.equal(r.staged, true, r.why ?? '');
  assert.deepEqual(r.binaries.sort(), ['pulumi', 'pulumi-language-nodejs', 'pulumi-watch']);
  assert.equal(fs.readFileSync(path.join(f.binDir, 'pulumi'), 'utf8'), 'real pulumi\n',
    'the real binary must REPLACE the launcher shim, or the shim downloads again at measure time');
  assert.equal(fs.existsSync(path.join(home, '.pulumi')), false,
    'nothing may reach the measured home — that is the entire point of the module');
});

test('every sibling binary moves, not just the named one', () => {
  const f = fixture();
  const r = prestageLauncher('pulumi', { observeDir: f.observeDir, stageDir: f.stageDir, run: f.run });
  // `run.js` prepends dirname(bin) to PATH so the CLI finds these; copying only `pulumi` yields a CLI
  // that starts and then fails on its first plugin operation.
  assert.ok(fs.existsSync(path.join(f.binDir, 'pulumi-language-nodejs')),
    'the language host has to travel with the CLI');
  assert.equal(r.binaries.length, 3);
});

test('a tool that is not in the arm .bin is skipped with a reason, never an exception', () => {
  const f = fixture();
  fs.rmSync(path.join(f.binDir, 'pulumi'));
  const r = prestageLauncher('pulumi', { observeDir: f.observeDir, stageDir: f.stageDir, run: f.run });
  assert.equal(r.staged, false);
  assert.match(r.why, /not in the arm \.bin/);
  assert.match(prestageMarker(r), /^ARM-SCAFFOLD-PRESTAGE pulumi skipped \(/);
});

test('a launcher that downloads nothing is reported, not treated as success', () => {
  const f = fixture();
  const r = prestageLauncher('pulumi', {
    observeDir: f.observeDir, stageDir: f.stageDir, run: () => ({ status: 1, stdout: '', stderr: 'offline' }),
  });
  assert.equal(r.staged, false);
  assert.match(r.why, /produced no versions\/ \(rc=1\)/,
    'the marker has to name the rc, or a network failure reads as a package defect');
});

test('an unknown tool is refused rather than guessed at', () => {
  const f = fixture();
  const r = prestageLauncher('yarn', { observeDir: f.observeDir, stageDir: f.stageDir, run: f.run });
  assert.equal(r.staged, false);
  assert.match(r.why, /not a self-downloading launcher/);
});

test('SELF_DOWNLOADING stays evidence-gated', () => {
  assert.deepEqual(Object.keys(SELF_DOWNLOADING), ['pulumi'],
    'an entry belongs here only once a measurement shows its payload landing in the measured home; '
    + 'pnpm, yarn and bun ship their own binaries and write nothing to home to start up');
});

test('the marker is a single line, because driver.out is parsed line-wise', () => {
  const f = fixture();
  const r = prestageLauncher('pulumi', { observeDir: f.observeDir, stageDir: f.stageDir, run: f.run });
  const m = prestageMarker(r);
  assert.equal(m.includes('\n'), false);
  assert.match(m, /^ARM-SCAFFOLD-PRESTAGE pulumi 3 binaries into node_modules\/\.bin$/);
});

test('copyBinDir overwrites an existing name and keeps the executable bit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'copybin-'));
  const src = path.join(root, 'src'); const dest = path.join(root, 'dest');
  fs.mkdirSync(src); fs.mkdirSync(dest);
  fs.writeFileSync(path.join(src, 'tool'), 'new');
  fs.writeFileSync(path.join(dest, 'tool'), 'old');
  assert.deepEqual(copyBinDir(src, dest), ['tool']);
  assert.equal(fs.readFileSync(path.join(dest, 'tool'), 'utf8'), 'new');
  assert.ok(fs.statSync(path.join(dest, 'tool')).mode & 0o111, 'a copied binary must stay executable');
});
