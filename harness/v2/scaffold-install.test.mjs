// The resilient scaffold installer. The property that matters is the one the old single flat
// `npm install` did not have: a spec that will not resolve costs ITSELF and nothing else.
//
// `run` is injected throughout, so these exercise the bisect rather than the registry. The end-to-end
// behaviour it was built from is recorded in `script-scaffold.mjs`'s header, measured against the real
// registry on `@paypal/paypal-js@2.1.8`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { installResiliently, applyScaffold, scaffoldMarkers, whyFailed, npmInstall } from './scaffold-install.mjs';

const HERE = import.meta.dirname;

/** A fake npm that fails whenever the batch contains any spec in `bad`. Records every batch it saw. */
function fakeNpm(bad = []) {
  const seen = [];
  const run = (specs) => {
    seen.push([...specs]);
    const hit = specs.find((s) => bad.includes(s));
    return hit
      ? { status: 1, out: `npm error code ERESOLVE\nnpm error While resolving: ${hit}\n` }
      : { status: 0, out: `added ${specs.length} packages\n` };
  };
  return { run, seen };
}

test('a clean closure is ONE install, not one per spec', () => {
  // The cost argument for bisecting rather than looping per package: the common case must not pay for
  // the rare one. 29 specs that resolve together stay a single npm invocation.
  const specs = Array.from({ length: 29 }, (_, i) => `p${i}@^1.0.0`);
  const { run, seen } = fakeNpm();
  const r = installResiliently(specs, run);
  assert.equal(r.installs, 1, 'a resolvable batch must not be split');
  assert.equal(r.installed.length, 29);
  assert.deepEqual(r.failed, []);
  assert.deepEqual(seen, [specs]);
});

test('⛔ ONE BAD SPEC COSTS ONLY ITSELF — the whole point of the change', () => {
  // This is the defect. The old drivers issued one flat `npm install` with every spec, so npm's atomic
  // install meant a single unresolvable entry left `node_modules/.bin` EMPTY and the arm no better off
  // than with no scaffold at all. Measured on @paypal/paypal-js@2.1.8: rc=1, `.bin` absent, rebuild
  // back to rc=127.
  const specs = ['a@1', 'b@1', 'BAD@9', 'd@1', 'e@1', 'f@1', 'g@1', 'h@1'];
  const { run } = fakeNpm(['BAD@9']);
  const r = installResiliently(specs, run);
  assert.deepEqual(r.failed.map((f) => f.spec), ['BAD@9']);
  assert.deepEqual(r.installed.sort(), ['a@1', 'b@1', 'd@1', 'e@1', 'f@1', 'g@1', 'h@1'],
    'every resolvable spec must still land');
  assert.equal(r.requested, 8);
});

test('the bisect is logarithmic, not a per-spec loop', () => {
  // A per-spec fallback would be n installs for n specs AND would resolve each spec in isolation —
  // a strictly more permissive question than resolving them together, giving the arm a tree npm would
  // never have produced. Bisecting keeps whole-batch resolution and only splits toward the failure.
  const specs = Array.from({ length: 64 }, (_, i) => (i === 40 ? 'BAD@9' : `p${i}@^1.0.0`));
  const { run } = fakeNpm(['BAD@9']);
  const r = installResiliently(specs, run);
  assert.deepEqual(r.failed.map((f) => f.spec), ['BAD@9']);
  assert.equal(r.installed.length, 63);
  assert.ok(r.installs <= 16, `64 specs with one bad should cost far fewer than 64 installs, got ${r.installs}`);
  assert.ok(r.installs > 1, 'and it must actually have split');
});

test('every spec failing is reported as every spec failing, not as a silent empty tree', () => {
  const specs = ['x@1', 'y@1', 'z@1'];
  const { run } = fakeNpm(specs);
  const r = installResiliently(specs, run);
  assert.deepEqual(r.failed.map((f) => f.spec).sort(), ['x@1', 'y@1', 'z@1']);
  assert.deepEqual(r.installed, []);
});

test('npm\'s own diagnosis is carried, so a record says WHY rather than only rc', () => {
  // ⛔ The distinction the drivers already treat as worth preserving: "the scaffold was not applied"
  // versus "it was applied and did not help". A bare rc cannot express which spec was fatal.
  assert.match(whyFailed('npm error code ERESOLVE\nnpm error While resolving: rollup@2.39.0\n'),
    /ERESOLVE.*rollup@2\.39\.0/);
  // The old npm 6 spelling too — the era npm writes `npm ERR!`, not `npm error`.
  assert.match(whyFailed('npm ERR! code ETARGET\nnpm ERR! notarget No matching version\n'), /ETARGET/);
  assert.match(whyFailed('nothing npm-shaped here'), /no npm diagnosis/);
});

test('a log that is only boilerplate does not masquerade as a diagnosis', () => {
  // npm ends every failure with a `_logs` path; treating that as the reason would put a temp path in
  // the record where the cause belongs.
  const out = 'npm error code E404\nnpm error A complete log of this run can be found in: /tmp/x/_logs/a.log\n';
  const why = whyFailed(out);
  assert.match(why, /E404/);
  assert.ok(!why.includes('_logs'), `the log path is not a diagnosis: ${why}`);
});

test('the tiers are applied in order and only the UNDATED one skips --before', () => {
  // ⛔ The pulumi measurement, as a unit assertion. Dated, `pulumi` resolves to 0.0.1 — a deprecated
  // stub with no bin — and the arm stays at rc=127 exactly as if unscaffolded. Undated it resolves a
  // real launcher and the script runs. So the tier a spec lands in decides whether it works at all.
  const calls = [];
  const ok = (tier) => (specs) => { calls.push([tier, specs]); return { status: 0, out: '' }; };
  const r = applyScaffold({ tools: ['pulumi'], install: ['husky@^5.0.9'], closure: ['rollup@^2.39.0'] },
    { runDated: ok('dated'), runUndated: ok('undated') });
  assert.deepEqual(calls, [
    ['undated', ['pulumi']],
    ['dated', ['husky@^5.0.9']],
    ['dated', ['rollup@^2.39.0']],
  ]);
  assert.equal(r.requested, 3);
  assert.equal(r.installed, 3);
});

test('a REQUIRED failure is reported apart from a best-effort one', () => {
  // ⛔ A closure spec that will not resolve is expected and uninteresting. A script-NAMED binary that
  // will not resolve is the arm missing something the lifecycle script is about to invoke. Summing
  // them would leave a reader to disambiguate a number that cannot be disambiguated.
  const bad = fakeNpm(['husky@^5.0.9', 'rollup@^2.39.0']);
  const r = applyScaffold({ tools: [], install: ['husky@^5.0.9'], closure: ['rollup@^2.39.0', 'ok@1'] },
    { runDated: bad.run, runUndated: bad.run });
  assert.deepEqual(r.requiredFailed.map((f) => f.spec), ['husky@^5.0.9']);
  assert.deepEqual(r.failed.map((f) => f.spec).sort(), ['husky@^5.0.9', 'rollup@^2.39.0']);
  assert.deepEqual(r.tiers.closure.installed, ['ok@1'], 'the good closure spec still landed');
});

test('every marker is a single line, because driver.out is parsed line-wise', () => {
  const bad = fakeNpm(['BAD@9']);
  const r = applyScaffold({ tools: ['pnpm'], install: ['BAD@9'], closure: ['a@1', 'b@1'] },
    { runDated: bad.run, runUndated: bad.run });
  const markers = scaffoldMarkers(r);
  for (const m of markers) assert.ok(!m.includes('\n'), `multi-line marker: ${m}`);
  assert.ok(markers.some((m) => m.startsWith('ARM-SCAFFOLD-REQUIRED-INCOMPLETE 1')),
    `a script-named provider failed and no marker says so: ${JSON.stringify(markers)}`);
  assert.ok(markers.some((m) => /^ARM-SCAFFOLD-CLOSURE 2\/2 installed/.test(m)));
  assert.ok(markers.some((m) => /^ARM-SCAFFOLD-TOOLS 1\/1 installed/.test(m)));
});

test('an empty tier says `none` rather than being omitted', () => {
  // The same declare-it-or-it-did-not-happen rule the ERA-NODE and ARM-PATH markers follow: a silent
  // absence is indistinguishable from a stage that never ran.
  const markers = scaffoldMarkers(applyScaffold({ tools: [], install: [], closure: [] },
    { runDated: () => ({ status: 0, out: '' }), runUndated: () => ({ status: 0, out: '' }) }));
  assert.deepEqual(markers, [
    'ARM-SCAFFOLD-TOOLS none', 'ARM-SCAFFOLD-NAMED none',
    'ARM-SCAFFOLD-CLOSURE none', 'ARM-SCAFFOLD-REQUIRED-INCOMPLETE none',
  ]);
});

test('⛔ `--prefix` is a named option and never enters the batch the bisect slices', () => {
  // Folding `--prefix <dir>` into the spec list would make two flag words count toward the batch
  // LENGTH, so a failing batch would split on a boundary that separates the flag from its value and
  // hand npm a `--prefix` with nothing after it. macOS is the driver that passes one.
  const seen = [];
  const r = npmInstall({
    specs: ['a@1', 'b@1'], cwd: '/tmp', before: '2021-01-01T00:00:00.000Z', prefix: '/obs',
    npmArgv: [process.execPath, '-e', 'process.exit(0)'], env: process.env,
  });
  assert.equal(r.status, 0);
  // The argv shape itself, asserted through the module's own construction rather than a spawn.
  const argvOf = (opts) => {
    const captured = [];
    // Re-derive what npmInstall would pass by calling it with a node that echoes argv.
    const probe = npmInstall({ ...opts, npmArgv: [process.execPath, '-p', 'JSON.stringify(process.argv.slice(2))'] });
    captured.push(...JSON.parse(probe.out.trim()));
    return captured;
  };
  const argv = argvOf({ specs: ['a@1', 'b@1'], cwd: '/tmp', before: '2021-01-01T00:00:00.000Z',
    prefix: '/obs', env: process.env });
  assert.deepEqual(argv.slice(-2), ['a@1', 'b@1'], 'the specs are last and unmixed with flags');
  assert.equal(argv[argv.indexOf('--prefix') + 1], '/obs');
  assert.ok(argv.includes('--legacy-peer-deps'),
    'the flag that took paypal-js’s 29-spec closure from rc=1 to rc=0 must always be present');
  assert.ok(argv.includes('--before=2021-01-01T00:00:00.000Z'));
});

test('an UNDATED install carries no --before at all', () => {
  const probe = npmInstall({ specs: ['pulumi'], cwd: '/tmp', before: '2018-04-26T21:37:22.861Z',
    dated: false, npmArgv: [process.execPath, '-p', 'JSON.stringify(process.argv.slice(2))'],
    env: process.env });
  const argv = JSON.parse(probe.out.trim());
  assert.ok(!argv.some((a) => a.startsWith('--before')),
    `an undated tool install must not be dated: ${JSON.stringify(argv)}`);
  assert.deepEqual(argv.slice(-1), ['pulumi']);
});

test('⛔ ALL THREE DRIVERS CALL IT — landed means landed on every platform', () => {
  // `dep-scaffold.mjs` records the two v2 fixes that reached one driver and were mistaken for done.
  // The generic list in `arm-prepare.test.mjs` covers this too; the duplicate here is deliberate, so
  // that deleting this module's entry from that list still leaves the module itself guarded.
  for (const d of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = fs.readFileSync(path.join(HERE, d), 'utf8');
    assert.ok(src.includes('scaffold-install.mjs'),
      `${d} still issues its own flat npm install — the resilient scaffold is not landed there`);
  }
});

test('CONTROL: the driver scan can fail', () => {
  // A substring search over three files passes vacuously if the read or the name is wrong.
  assert.ok(fs.existsSync(path.join(HERE, 'scaffold-install.mjs')));
  const src = fs.readFileSync(path.join(HERE, 'measure.sh'), 'utf8');
  assert.ok(!src.includes('scaffold-install-that-was-never-written.mjs'),
    'the known-absent control string is present, so a green scan proves nothing');
});
