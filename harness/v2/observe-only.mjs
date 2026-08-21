// Re-decide the UNJAILED verdicts without the jail, because they never needed it.
//
// ⛔ THE OBSERVATION THAT UNBLOCKS THE RE-MEASURE. `BROKEN-WITHOUT-JAIL-TOO` is emitted at
// `measure.sh:477` (the fetch gate) and `:673` (the observe control), BOTH in the observe phase and
// both BEFORE any jailed verify arm runs. So the verdict on 1,481 of the 1,529 BROKEN-* records is
// decided entirely by npm: fetch with `--ignore-scripts`, then `npm rebuild`. nub is never invoked.
//
// ⛔ WHICH MEANS `falsify` DOES NOT GATE THEM, AND SHOULD NOT. The falsification control proves the
// harness can detect an UNDER-GRANTED jail arm. That is a property of the verify ladder, and a record
// whose verdict is decided before the ladder starts never exercises it. Blocking this population on
// that control is a real cost being paid for no coverage: the corpus runner has been refusing to
// start since 2026-08-17 over a `hugo-extended@0.141.0` case that concerns the jail, while 1,481
// npm-decided records sit unmeasured behind it.
//
// ⛔ AND THE LIMIT IS EXPLICIT, BECAUSE THIS FILE COULD OTHERWISE BE MISREAD AS A WAY AROUND THE
// GATE. It re-decides ONLY the observe verdict. It CANNOT produce a grant, a minimality, or any
// `MINIMUM`/`NO-STATE-PASSED`/`UNDER-PREDICTED` verdict — every one of those needs the jail and the
// falsification control that guards it. A run of this tool is a DISPOSITION LEDGER, not a corpus
// record, and it writes to its own file rather than `records-v2/`.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fetchArgs } from './era-resolution.mjs';
import { armPath, ambientTools } from './arm-path.mjs';
import { scriptScaffold } from './script-scaffold.mjs';
import { pythonForEra } from './era-python.mjs';
import { runCapped } from './arm-cap.mjs';

/** The verdict the observe phase would reach, from the two gates' own outcomes. */
export function observeVerdict({ fetchRc, rebuildRc, capped, fetchCapped }) {
  // ⛔ A CAPPED FETCH IS A TIMEOUT, NOT A PACKAGE VERDICT — and it was recorded as one. The control
  // set caught it only on inspection: `ibm_db@0.0.9` came back fetch=124 and was dispositioned
  // CONFIRMED, which happened to MATCH the expected answer for that row, so the 5/5 tally looked
  // clean while one row was right by accident. Reading the detail is what found it. Left unfixed,
  // every slow-fetching package in the sweep would become a false CONFIRMED — the same
  // timeout-as-package-verdict trap already fixed in measure.sh and measure-macos.sh.
  if (capped || fetchCapped || fetchRc === 124 || rebuildRc === 124) return 'HARNESS-TIMEOUT';
  if (fetchRc !== 0) return 'BROKEN-WITHOUT-JAIL-TOO';
  if (rebuildRc !== 0) return 'BROKEN-WITHOUT-JAIL-TOO';
  // ⛔ NOT `MINIMUM`. A clean observe says only that the package installs unjailed; what the jail
  // would have concluded is a different question this tool cannot answer.
  return 'INSTALLS-UNJAILED';
}

/** Disposition for a row whose recorded verdict is being revisited. */
export function disposition(previous, now) {
  if (now === 'HARNESS-TIMEOUT') return 'UNMEASURED-TIMEOUT';

  // ⛔⛔ `BROKEN-UNJAILED-NUB` MEANS "npm INSTALLS IT, nub DOES NOT". This runner drives npm ONLY —
  // it never invokes nub — so an observe arm that SUCCEEDS re-confirms the half of that verdict
  // which was never in doubt, and says NOTHING about the half that made it a nub defect.
  //
  // Calling that STALE-RECORD is a false exoneration, and it is not hypothetical: the first CI sweep
  // dispositioned 22 of the 31 BROKEN-UNJAILED-NUB records as "stale — installs today", which would
  // have reported 22 open nub defects as fixed. They are the class the maintainer singled out as
  // severe. The npm half succeeding is the ORIGINAL FINDING, not a contradiction of it.
  //
  // A FAILING arm is different and IS informative: it removes the "npm installs it" premise the
  // verdict rests on, so the record no longer describes a nub defect and genuinely CHANGED.
  if (previous === 'BROKEN-UNJAILED-NUB') {
    return now === 'INSTALLS-UNJAILED' ? 'NUB-UNMEASURED' : 'CHANGED';
  }

  if (previous === now) return 'CONFIRMED';
  if (now === 'INSTALLS-UNJAILED') return 'STALE-RECORD';
  return 'CHANGED';
}

export { fetchArgs, armPath, ambientTools, scriptScaffold, pythonForEra, spawnSync, fs, path };

// ---------------------------------------------------------------------------------------------
// CLI: drive a worklist of `pkg@version` through the repaired observe arm and write a ledger.
//
//   usage: observe-only.mjs --file <worklist> --out <ledger.ndjson> [--cap-secs 900] [--limit N]
//
// ⛔ EVERY ROW IS CAPPED. `optipng-bin@2.0.0` re-spawns `optipng --version` without bound and reached
// 211 live children during an earlier sweep, which is what takes a runner down and loses every row
// behind it. `arm-cap.mjs` kills the whole process group; a capped row is HARNESS-TIMEOUT and never
// a package verdict.
if (import.meta.filename === process.argv[1]) {
  const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? d : process.argv[i + 1]; };
  const HERE = import.meta.dirname;
  const file = arg('file'); const out = arg('out');
  if (!file || !out) { process.stderr.write('usage: observe-only.mjs --file <worklist> --out <ledger.ndjson>\n'); process.exit(2); }
  const capSecs = Number(arg('cap-secs', '600'));
  const limit = Number(arg('limit', '0'));
  const harnessNode = process.execPath;      // never a bare `node`: the arm PATH may carry an era Node
  let specs = fs.readFileSync(file, 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
  if (limit > 0) specs = specs.slice(0, limit);

  const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 28, ...opts });
  const eraRoot = path.join(process.env.HOME ?? '/tmp', '.cache', 'nub', 'era-node');
  fs.mkdirSync(eraRoot, { recursive: true });
  // Discovered ONCE: probing per row would run `command -v` thousands of times for one answer.
  const pythonCandidates = ['python2.7', 'python2', 'python3', 'python'].map((n) => {
    const w = spawnSync('/bin/sh', ['-c', `command -v ${n}`], { encoding: 'utf8' });
    const pth = (w.stdout ?? '').trim(); if (!pth) return null;
    const v = spawnSync('/bin/sh', ['-c', `"${pth}" --version 2>&1`], { encoding: 'utf8' });
    return { path: pth, version: (v.stdout ?? '').trim() };
  }).filter(Boolean);
  const ledger = fs.createWriteStream(out, { flags: 'a' });
  let n = 0;
  for (const line of specs) {
    const [spec, prevVerdict = ''] = line.split('\t');
    const at = spec.lastIndexOf('@');
    const pkg = spec.slice(0, at); const version = spec.slice(at + 1);
    // ⛔ `os.tmpdir()`, NEVER `process.env.TMPDIR || '/tmp'`. Windows sets TEMP/TMP, not TMPDIR, so the
    // fallback fired and `path.join` produced the Windows-nonsense path `\tmp\obs-XXXXXX`:
    //   Error: ENOENT: no such file or directory, mkdtemp '\tmp\obs-XXXXXX'
    // All four win32 shards died on their first row while linux and macOS ran fine, because those
    // platforms do set TMPDIR. os.tmpdir() reads the right variable per platform.
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-'));
    const home = path.join(root, 'home'); fs.mkdirSync(home);
    const obs = path.join(root, 'observe'); fs.mkdirSync(obs);
    fs.writeFileSync(path.join(obs, 'package.json'), '{"name":"o","version":"1.0.0"}\n');
    const rec = { spec, pkg, version, previous: prevVerdict, platform: process.platform };
    try {
      // era selection -> dated resolution -> sanitised PATH -> scaffold -> era python
      const sel = sh(harnessNode, [path.join(HERE, 'era-node.mjs'), pkg, version]);
      let selection = {}; try { selection = JSON.parse(sel.stdout || '{}'); } catch { /* stays {} */ }
      const fa = fetchArgs({ spec, publishedAt: selection.publishedAt ?? null });
      rec.eraMajor = selection.eraMajor ?? null; rec.before = fa.before;
      const env0 = { ...process.env, HOME: home, npm_config_cache: path.join(root, 'npmcache') };
      // ⛔ THE FETCH IS CAPPED TOO. Only the rebuild was wrapped before, so a hanging
      // `npm install --before=…` bounded nothing and one row could stall an entire sweep.
      const fetchLog = path.join(root, 'fetch.log');
      const ffd = fs.openSync(fetchLog, 'w');
      const f = await runCapped('npm', [...fa.args, '--no-audit', '--no-fund'].filter((a, i, all) => all.indexOf(a) === i),
                                { ms: capSecs * 1000, cwd: obs, env: env0, stdio: ['ignore', ffd, ffd] });
      fs.closeSync(ffd);
      rec.fetchRc = f.code;
      rec.fetchCapped = f.timedOut;
      if (rec.fetchRc === 0) {
        // ⛔ PROVISION AND USE THE ERA NODE. The first version of this CLI computed the era selection
        // and then ran `npm rebuild` with the AMBIENT npm, so every old package was re-measured on
        // the same modern Node that broke it originally. The five-package control caught it: three
        // rows I had already proved install came back CONFIRMED-broken. Importing the pieces is not
        // wiring them.
        let eraBin = null;
        if (selection.version && selection.pinnable !== false) {
          const dir = path.join(eraRoot, selection.version);
          const bin = path.join(dir, 'bin');
          if (!fs.existsSync(path.join(bin, 'node'))) {
            fs.mkdirSync(dir, { recursive: true });
            const plat = process.platform === 'darwin' ? 'darwin' : 'linux';
            // nodejs.org ships NO darwin-arm64 build below 16; the x64 build runs under Rosetta,
            // which was measured working for 4.9.1 and 10.24.1 on this platform.
            const arch = plat === 'darwin' && selection.major < 16 ? 'x64'
              : (process.arch === 'arm64' ? 'arm64' : 'x64');
            const url = `https://nodejs.org/dist/v${selection.version}/node-v${selection.version}-${plat}-${arch}.tar.gz`;
            const tgz = path.join(eraRoot, `${selection.version}.tgz`);
            const dl = sh('curl', ['-fsSL', url, '-o', tgz]);
            if (dl.status === 0) sh('tar', ['-xzf', tgz, '-C', dir, '--strip-components=1']);
          }
          if (fs.existsSync(path.join(bin, 'node'))) eraBin = bin;
        }
        rec.eraPinned = eraBin ? selection.version : null;
        rec.eraStatus = eraBin ? `PINNED ${selection.version}`
          : `NOT-PINNED (${selection.pinnable === false ? 'engines unsatisfiable' : 'not provisionable'})`;

        const { armPath: ap } = armPath({ ambient: process.env.PATH ?? '', eraBin,
                                          fixtureBin: path.join(obs, 'node_modules', '.bin') });
        const py = pythonForEra(rec.eraMajor, pythonCandidates);
        const env = { ...env0, PATH: ap, ...(py.path ? { PYTHON: py.path } : {}) };
        rec.python = py.path;

        // ⛔ APPLY THE SCAFFOLD. Also imported-but-never-called in the first version, which is why
        // `@paypal/paypal-js@2.1.8` came back rc=127 (`husky: command not found`) after I had already
        // measured it going to rc=0 with `husky@^5.0.9` alone.
        const manifestPath = path.join(obs, 'node_modules', ...pkg.split('/'), 'package.json');
        let scaffold = { install: [] };
        try { scaffold = scriptScaffold(JSON.parse(fs.readFileSync(manifestPath, 'utf8'))); } catch { /* none */ }
        rec.scaffold = scaffold.install;
        if (scaffold.install.length) {
          const si = sh('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', ...scaffold.install],
                        { cwd: obs, env });
          rec.scaffoldRc = si.status ?? 1;
        }

        // ⛔ `runCapped` IS CALLED DIRECTLY, NOT SPAWNED AS A CHILD, AND THE OUTPUT GOES TO A FILE.
        // The first version did `spawnSync(node, ['arm-cap.mjs', …])`, which DEADLOCKS: spawnSync
        // drains the child's pipes to EOF, arm-cap spawns DETACHED with inherited stdio, and the
        // detached grandchild keeps those fds open in a process group spawnSync is not watching. The
        // cap fires, the grandchild dies, and the parent still waits on a pipe that never closes.
        // MEASURED: 24 minutes, ZERO rows written, no live child processes. Redirecting to a file
        // removes the pipe entirely, and calling runCapped in-process keeps the group kill.
        const logPath = path.join(root, 'rebuild.log');
        const fd = fs.openSync(logPath, 'w');
        const npmBin = eraBin ? path.join(eraBin, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js') : null;
        const useEra = npmBin && fs.existsSync(npmBin);
        const r = await runCapped(
          useEra ? path.join(eraBin, 'node') : 'npm',
          useEra ? [npmBin, 'rebuild', '--no-audit', '--no-fund', pkg]
                 : ['rebuild', '--no-audit', '--no-fund', pkg],
          { ms: capSecs * 1000, cwd: obs, env, stdio: ['ignore', fd, fd] });
        fs.closeSync(fd);
        rec.rebuildRc = r.code;
        rec.capped = r.timedOut;
        const log = fs.readFileSync(logPath, 'utf8');
        rec.firstError = log.split('\n').find((l) => /npm error|ERR!|SyntaxError|command not found/.test(l))?.trim().slice(0, 160) ?? null;
      } else {
        rec.rebuildRc = null; rec.capped = false;
        rec.firstError = fs.readFileSync(fetchLog, 'utf8').split('\n')
          .find((l) => /npm error|ERR!/.test(l))?.trim().slice(0, 160) ?? null;
      }
      rec.verdict = observeVerdict(rec);
      rec.disposition = prevVerdict ? disposition(prevVerdict, rec.verdict) : null;
    } catch (e) { rec.verdict = 'HARNESS-ERROR'; rec.firstError = String(e?.message ?? e).slice(0, 160); }
    fs.rmSync(root, { recursive: true, force: true });
    ledger.write(`${JSON.stringify(rec)}\n`);
    n++;
    if (n % 10 === 0) process.stderr.write(`  ${n}/${specs.length}\n`);
  }
  ledger.end();
  process.stderr.write(`done: ${n} rows -> ${out}\n`);
}
