// Replay a deliberately small, pinned worklist against the complete catalog artifact.
//
// This is not `run-batch-v2.mjs`: a DIRECT replay has no MINIMUM record vocabulary, so writing a
// record here would turn a product answer into a corrupt measurement record.  The only output is
// retained per-cell evidence for the owning campaign.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { assertCampaignInvocation, hashFile, verifyCampaignContext } from './campaign-provenance.mjs';
import { driverInvocation } from './driver-invocation.mjs';

const DIRECT_BANNER = /^\s*(?:──|--)\s*DIRECT:/m;
const SUFFICIENT = /^\s*=>\s+SUFFICIENT\b/m;
const INSUFFICIENT = /^\s*=>\s+INSUFFICIENT\b/m;
const VOID = /^\s*=>\s+(?:⛔\s+)?VOID\b/m;
const PACKAGE = /^(?:@[-a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*|[a-z0-9][a-z0-9._-]*)$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parseExactSpec(line) {
  const spec = line.trim();
  const at = spec.lastIndexOf('@');
  const pkg = spec.slice(0, at);
  const version = spec.slice(at + 1);
  if (at <= 0 || !PACKAGE.test(pkg) || !VERSION.test(version)) {
    throw new Error(`worklist entry is not package@exact-version: ${JSON.stringify(line)}`);
  }
  return { pkg, version, spec: `${pkg}@${version}` };
}

export function readWorklist(file) {
  const specs = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter((line) => line.trim()).map(parseExactSpec);
  if (!specs.length) throw new Error('worklist is empty');
  if (specs.length > 5) throw new Error(`worklist has ${specs.length} specs; catalog replay is bounded to 5`);
  if (new Set(specs.map(({ spec }) => spec)).size !== specs.length) throw new Error('worklist contains duplicate exact specs');
  return specs;
}

export function cellName({ pkg, version }) {
  // The parser permits only package-name characters; replacing the one scoped-package slash gives
  // every cell one basename and prevents the worklist from selecting an output path.
  return `${pkg.replace(/^@/, '').replace('/', '+')}@${version}`;
}

export function classifyDirect(result, text) {
  const terminals = text.match(/^\s*=>\s+[^\r\n]+/gm) ?? [];
  const terminal = terminals.at(-1)?.trim() ?? '';
  const error = result.error;
  const detail = error ? `${error.code ? `${error.code}: ` : ''}${error.message ?? String(error)}` : '';
  if (result.error?.code === 'ETIMEDOUT' || result.status === 124 || result.signal === 'SIGTERM') {
    return { status: 'infrastructure-error', terminal, reason: `driver timed out${detail ? ` (${detail})` : ''}` };
  }
  if (error || result.signal) {
    return { status: 'infrastructure-error', terminal, reason: `driver subprocess failed${detail ? ` (${detail})` : result.signal ? ` (${result.signal})` : ''}` };
  }
  if (!DIRECT_BANNER.test(text)) {
    return { status: 'infrastructure-error', terminal, reason: 'driver printed no DIRECT banner' };
  }
  if (result.status === 0 && SUFFICIENT.test(terminal)) return { status: 'sufficient', terminal };
  if (result.status === 1 && INSUFFICIENT.test(terminal)) return { status: 'insufficient', terminal };
  if (result.status === 3 && VOID.test(terminal)) return { status: 'void', terminal };
  if (result.status === 0) return { status: 'infrastructure-error', terminal, reason: 'DIRECT run exited 0 without a SUFFICIENT terminal' };
  if (result.status === 1) return { status: 'infrastructure-error', terminal, reason: 'DIRECT run exited 1 without an INSUFFICIENT terminal' };
  if (result.status === 3) return { status: 'infrastructure-error', terminal, reason: 'DIRECT run exited 3 without a VOID terminal' };
  return { status: 'infrastructure-error', terminal, reason: `DIRECT driver exited ${result.status ?? 'without a status'}` };
}

function outputCell(out, platform, spec) {
  const base = path.resolve(out);
  const cell = path.resolve(base, platform, cellName(spec));
  if (!cell.startsWith(`${base}${path.sep}`)) throw new Error('refused unsafe output path');
  return cell;
}

function commandText(command, args, result) {
  const error = result.error;
  const detail = error ? `\n[spawnSync ${error.name ?? 'Error'}${error.code ? ` ${error.code}` : ''}: ${error.message ?? String(error)}]\n` : '';
  return `$ ${command} ${args.join(' ')}\n\n${result.stdout ?? ''}${result.stderr ?? ''}${detail}`;
}

export function replayCatalog(options, deps = {}) {
  const platform = options.platform ?? process.platform;
  const worklist = path.resolve(options.worklist);
  const catalog = path.resolve(options.catalog);
  const out = path.resolve(options.out);
  const context = options.context;
  const specs = readWorklist(worklist);
  const verify = deps.verifyCampaignContext ?? verifyCampaignContext;
  const assertInvocation = deps.assertCampaignInvocation ?? assertCampaignInvocation;
  const fileHash = deps.hashFile ?? hashFile;
  const run = deps.spawnSync ?? spawnSync;
  const driverFor = deps.driverInvocation ?? driverInvocation;
  const platformIdentity = options.platformIdentity ?? `${platform}-${options.arch ?? process.arch}`;
  const bind = () => {
    verify(context);
    if (path.resolve(context.verification.files.catalog) !== catalog) throw new Error('catalog path does not match campaign context');
    if (path.resolve(context.verification.files.worklist) !== worklist) throw new Error('worklist path does not match campaign context');
    assertInvocation(context, { nubSha256: fileHash(options.nub), nubGitSha: options.nubGitSha,
      platform: platformIdentity, worklist });
  };

  fs.mkdirSync(out, { recursive: true });
  const driver = driverFor(platform);
  const summary = { schemaVersion: 1, kind: 'catalog-direct-replay', catalog, worklist, platform: platformIdentity,
    cells: [] };
  for (const spec of specs) {
    const cell = outputCell(out, platform, spec);
    fs.mkdirSync(cell, { recursive: true });
    const args = [...driver.pre, driver.file, spec.pkg, spec.version,
      ...(platform === 'win32' ? ['--nub', options.nub] : [options.nub]),
      '--at-catalog', catalog];
    if (platform === 'win32' && options.driverRoot) args.push('--root', options.driverRoot);
    let result;
    let postError;
    try {
      bind();
      result = run(driver.cmd, args, { encoding: 'utf8', maxBuffer: 1 << 28, timeout: options.timeout ?? 20 * 60_000 });
    } catch (error) {
      result = { status: null, error, stdout: '', stderr: '' };
    } finally {
      // Re-check every digest even after a driver failure: a passing install is not evidence if the
      // binary, source, platform, worklist, or catalog changed while it ran.
      try { bind(); } catch (error) { postError = error; }
    }
    const log = commandText(driver.cmd, args, result);
    fs.writeFileSync(path.join(cell, 'direct.log'), log);
    const verdict = postError
      ? { status: 'infrastructure-error', terminal: '', reason: `campaign binding changed after run: ${postError.message}` }
      : classifyDirect(result, log);
    const item = { spec: spec.spec, log: path.join(cell, 'direct.log'), ...verdict };
    fs.writeFileSync(path.join(cell, 'summary.json'), `${JSON.stringify(item, null, 2)}\n`);
    summary.cells.push(item);
  }
  summary.ok = summary.cells.every((cell) => cell.status === 'sufficient');
  fs.writeFileSync(path.join(out, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

function cli(argv) {
  const names = new Set(['--nub', '--nub-git-sha', '--catalog', '--worklist', '--context', '--out', '--timeout', '--driver-root']);
  const option = (name) => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
  const unknown = argv.filter((arg, index) => arg.startsWith('--') && !names.has(arg) && !(index && names.has(argv[index - 1])));
  if (unknown.length) throw new Error(`unknown flag(s): ${unknown.join(', ')}`);
  if (argv.some((arg, index) => names.has(arg) && !argv[index + 1])) throw new Error('every option requires a value');
  const options = { nub: option('--nub'), nubGitSha: option('--nub-git-sha') ?? process.env.NUB_GIT_SHA,
    catalog: option('--catalog'), worklist: option('--worklist'), out: option('--out'), timeout: Number(option('--timeout') ?? 1_200_000) };
  const contextFile = option('--context');
  if (Object.values(options).some((value) => value === null || value === '' || Number.isNaN(value)) || !contextFile) {
    throw new Error('usage: catalog-replay.mjs --nub FILE --nub-git-sha SHA --catalog FILE --worklist FILE --context FILE --out DIR [--timeout MS]');
  }
  if (!Number.isInteger(options.timeout) || options.timeout <= 0) throw new Error('--timeout requires positive milliseconds');
  options.driverRoot = option('--driver-root');
  options.context = JSON.parse(fs.readFileSync(contextFile, 'utf8'));
  const summary = replayCatalog(options);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (!summary.ok) process.exitCode = 1;
}

const invokedPath = process.argv[1] && (() => {
  try { return fs.realpathSync(process.argv[1]); } catch { return path.resolve(process.argv[1]); }
})();
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`CATALOG-REPLAY-ERROR ${error.message}`); process.exitCode = 2; }
}
