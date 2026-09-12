import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { FIXTURE_TIMEOUT_MS, OVERRIDE_TIMEOUT_MS } from './catalog-sanity-budget.mjs';

const values = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const key = process.argv[index];
  if (!key?.startsWith('--') || process.argv[index + 1] == null) throw new Error('usage: catalog-sanity-subject.mjs --subject <name> --bin <nub> [--bin-arg <arg>] --catalog <json> --bad-catalog <json> --fixtures <dir> --report <dir>');
  values[key.slice(2)] = process.argv[index + 1];
}
for (const key of ['subject', 'bin', 'catalog', 'bad-catalog', 'fixtures', 'report']) {
  if (!values[key]) throw new Error(`missing --${key}`);
}

fs.mkdirSync(values.report, { recursive: true });
const invoke = (file, args, env, logPath, timeout) => {
  // `packages.mjs` can legitimately print more than spawnSync's 1 MiB default while it serializes
  // fourteen arm logs. Direct descriptors retain the complete diagnostic without turning output
  // volume into an ENOBUFS failure or holding it in the runner's heap.
  const fd = fs.openSync(logPath, 'w');
  try {
    const result = spawnSync(file, args, {
      env: { ...process.env, ...env }, timeout, stdio: ['ignore', fd, fd],
    });
    return { status: result.status, signal: result.signal, error: result.error?.message ?? null };
  } finally {
    fs.closeSync(fd);
  }
};
const capture = (name, file, args, env, timeout) => {
  const logPath = path.join(values.report, `${name}.log`);
  const result = invoke(file, args, env, logPath, timeout);
  fs.writeFileSync(path.join(values.report, `${name}.exit`), `${result.status ?? 'null'}\n`);
  return { ...result, logPath };
};
const markerIn = (file, marker) => {
  const fd = fs.openSync(file, 'r');
  try {
    const bytes = Buffer.alloc(1024 * 1024);
    const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
    return bytes.subarray(0, count).includes(marker);
  } finally { fs.closeSync(fd); }
};
const binArgs = values['bin-arg'] ? [values['bin-arg']] : [];

// The established corpus control is marker-based: an invalid catalog prints REJECTED and falls
// back to compiled-in grants, so its exit status is evidence to retain—not a condition to invent.
const rejected = capture('override-rejected', values.bin, [...binArgs, '--version'], { NUB_BUILD_JAIL_CATALOG: values['bad-catalog'] }, OVERRIDE_TIMEOUT_MS);
const engaged = capture('override-engaged', values.bin, [...binArgs, '--version'], { NUB_BUILD_JAIL_CATALOG: values.catalog }, OVERRIDE_TIMEOUT_MS);
const override = { rejected, engaged, pass: markerIn(rejected.logPath, 'REJECTED') && markerIn(engaged.logPath, 'OVERRIDDEN') && engaged.status === 0 };
if (!override.pass) {
  fs.writeFileSync(path.join(values.report, 'fixtures-skipped.log'), 'catalog override markers did not both engage\n');
  fs.writeFileSync(path.join(values.report, 'result.json'), `${JSON.stringify({ subject: values.subject, override, fixtures: [] }, null, 2)}\n`);
  process.exitCode = 1;
} else {
  const fixtureSpecs = [
    ['packages', path.join(values.fixtures, 'packages.mjs'), { CORPUS_REPORT: path.join(values.report, 'packages') }, FIXTURE_TIMEOUT_MS.packages],
    ['network', path.join(values.fixtures, 'network.mjs'), {}, FIXTURE_TIMEOUT_MS.network],
    ['relocated-store', path.join(values.fixtures, 'relocated-store.mjs'), {}, FIXTURE_TIMEOUT_MS['relocated-store']],
  ];
  const fixtures = fixtureSpecs.map(([name, fixture, extra, timeout]) => {
    const result = capture(name, process.execPath, name === 'packages' ? [fixture] : ['--test', '--test-concurrency=1', fixture], {
      NUB_BUILD_JAIL_CATALOG: values.catalog, NUB_BIN: values.bin, ...extra,
    }, timeout);
    return { name, status: result.status, signal: result.signal, error: result.error, timeout };
  });
  fs.writeFileSync(path.join(values.report, 'result.json'), `${JSON.stringify({ subject: values.subject, override, fixtures }, null, 2)}\n`);
  process.exitCode = fixtures.every((fixture) => fixture.status === 0) ? 0 : 1;
}
