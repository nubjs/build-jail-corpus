// OBSERVE-ONLY for one real package, on Windows. No jail, no nub, no verdict.
//
// ⛔ DELIBERATELY NOT `measure-windows.mjs`. That driver is hard-stopped behind
// `NUB_V2_WINDOWS_EVICTION_VERIFIED` for an unrelated under-grant risk, and it goes on to SYNTHESIZE
// and VERIFY -- neither of which this probe is asking about. Reproducing only its OBSERVE half here
// keeps the guard untouched, keeps nub out of the picture entirely, and makes the measurement about
// the TRACER rather than about the jail.
//
// The OBSERVE half is copied in substance from `measure-windows.mjs`, including the two traps that
// invalidate it if dropped:
//
//   * FETCH OUTSIDE THE TRACE. Tracing `npm install` traces NPM -- its registry TLS and its cache
//     writes under the user profile land in the same stream as the lifecycle script's. Fetch with
//     `--ignore-scripts` untraced, then trace `npm rebuild`, which runs lifecycle scripts and
//     nothing else.
//   * A PER-RUN npm CACHE. A lifecycle script that fetches its payload finds it already present
//     when the host cache is warm, so the trace records no egress at all and the measurement
//     silently describes a warm machine instead of a cold one.
//
//   usage: node observe-pkg.mjs <pkg> <version> --root <dir> [--storm-timeout ms]
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const argv = process.argv.slice(2);
const flag = (f, d) => { const i = argv.indexOf(f); return i >= 0 ? argv[i + 1] : d; };
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const [PKG, VER] = positional;
if (!PKG || !VER) { console.error('usage: observe-pkg.mjs <pkg> <version> --root <dir>'); process.exit(2); }

const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const ADAPTERS = path.resolve(HERE, '..', '..', 'adapters');
const V2 = path.resolve(HERE, '..', '..');
const BASE = flag('--root', 'C:\\obs');
const ROOT = path.join(BASE, `o-${PKG.replace(/[^a-z0-9]/gi, '')}-${Date.now().toString(36)}`);
fs.mkdirSync(ROOT, { recursive: true });

const NODE = process.execPath;
const NPM = path.join(path.dirname(NODE), 'node_modules', 'npm', 'bin', 'npm-cli.js');
if (!fs.existsSync(NPM)) { console.error(`FATAL npm-cli.js not found at ${NPM}`); process.exit(1); }

const run = (exe, args, opts = {}) =>
  spawnSync(exe, args, { encoding: 'utf8', maxBuffer: 1 << 28, windowsHide: true, ...opts });

console.log(`### OBSERVE ${PKG}@${VER}   (${ROOT})`);

// Free space, before anything large is written. A trace runs ~1.3 KB per event, so a heavy
// node-gyp build can be gigabytes of XML, and running out of disk mid-capture produces a SHORT
// trace with no error -- which reads exactly like a package that touched fewer files.
const freeBefore = run('powershell.exe', ['-NoProfile', '-Command',
  '(Get-PSDrive -Name (Split-Path -Qualifier $PWD).TrimEnd(":")).Free']);
console.log(`  free bytes on the trace volume: ${(freeBefore.stdout ?? '').trim()}`);

const OBS = path.join(ROOT, 'observe');
fs.mkdirSync(OBS, { recursive: true });
fs.writeFileSync(path.join(OBS, 'package.json'), JSON.stringify({ name: 'o', version: '1.0.0' }) + '\n');

const NPM_CACHE = path.join(ROOT, 'npm-cache');
const obsEnv = { ...process.env, npm_config_cache: NPM_CACHE };
const fetched = run(NODE, [NPM, 'install', '--no-audit', '--no-fund', '--ignore-scripts', `${PKG}@${VER}`],
  { cwd: OBS, env: obsEnv });
fs.writeFileSync(path.join(ROOT, 'fetch.log'), (fetched.stdout ?? '') + (fetched.stderr ?? ''));
if (fetched.status !== 0) {
  console.log(`  => FETCH FAILED rc=${fetched.status}; nothing to trace`);
  fs.writeFileSync(path.join(ROOT, 'probe.json'), JSON.stringify({ pkg: PKG, version: VER, status: 'FETCH-FAILED' }, null, 2));
  process.exit(0);
}

// `cmd /c` strips the outer quote pair when the string both starts and ends with a quote, so a
// quoted `C:\Program Files\nodejs\node.exe` degrades into a PATH-looking error. Hand cmd a single
// space-free wrapper path instead: a string with no spaces cannot be mis-split however it is
// re-parsed.
const WRAP = path.join(ROOT, 'rebuild.cmd');
fs.writeFileSync(WRAP, `@echo off\r\nset "npm_config_cache=${NPM_CACHE}"\r\n"${NODE}" "${NPM}" rebuild --no-audit --no-fund ${PKG}\r\n`, 'ascii');

const CAP = path.join(ROOT, 'cap');
const SESSION = `nubobs_${process.pid}_${Date.now().toString(36)}`;
const cap = run('powershell.exe', [
  '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', path.join(ADAPTERS, 'windows.ps1'),
  '-OutDir', CAP, '-Command', WRAP, '-WorkDir', OBS, '-Session', SESSION,
]);
fs.writeFileSync(path.join(ROOT, 'capture.log'), (cap.stdout ?? '') + (cap.stderr ?? ''));
console.log('  ' + ((cap.stdout ?? '') + (cap.stderr ?? '')).trim().split('\n').slice(-4).join('\n  '));
if (!fs.existsSync(path.join(CAP, 'meta.json'))) {
  console.log('  => CAPTURE FAILED (no meta.json)');
  fs.writeFileSync(path.join(ROOT, 'probe.json'), JSON.stringify({ pkg: PKG, version: VER, status: 'CAPTURE-FAILED' }, null, 2));
  process.exit(0);
}
const meta = JSON.parse(fs.readFileSync(path.join(CAP, 'meta.json'), 'utf8'));

const bytes = (p) => { try { return fs.statSync(p).size; } catch { return -1; } };

// ⛔ `--allow-lossy` ON PURPOSE. A lossy trace is exactly what this probe is here to CHARACTERISE,
// and the adapter's default refusal would hide the one number the whole question turns on.
const NDJSON = path.join(CAP, 'events.ndjson');
const parse = run(NODE, [path.join(ADAPTERS, 'windows.mjs'), CAP, '--out', NDJSON, '--allow-lossy']);
fs.writeFileSync(path.join(ROOT, 'parse.log'), (parse.stdout ?? '') + (parse.stderr ?? ''));
console.log('  ' + ((parse.stderr ?? '').trim() || '(no parser stats)'));

const summary = {
  pkg: PKG, version: VER, status: 'OK',
  rebuildExit: meta.exitCode,
  eventsTotal: meta.eventsTotal, eventsLost: meta.eventsLost,
  tracerptExit: meta.tracerptExit,
  etlBytes: bytes(path.join(CAP, 'trace.etl')),
  xmlBytes: bytes(path.join(CAP, 'trace.xml')),
  ndjsonBytes: bytes(NDJSON),
  temp: meta.temp, userProfile: meta.userProfile, rootPid: meta.rootPid,
  capDir: CAP, obsDir: OBS, root: ROOT,
};
fs.writeFileSync(path.join(ROOT, 'probe.json'), JSON.stringify(summary, null, 2));
console.log(`  events=${meta.eventsTotal} LOST=${meta.eventsLost} etl=${summary.etlBytes} xml=${summary.xmlBytes} ndjson=${summary.ndjsonBytes} rebuildRc=${meta.exitCode}`);
console.log(`  ROOT=${ROOT}`);
