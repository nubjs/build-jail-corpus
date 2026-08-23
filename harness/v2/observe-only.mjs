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
import { pythonForEra, PROBE_NAMES } from './era-python.mjs';
import { runCapped } from './arm-cap.mjs';
import { npmInvocation } from './npm-cli.mjs';
import { namesMissingDependency } from './missing-dep.mjs';
import { provisionEraNode, eraRootDir } from './era-provision.mjs';

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
/** npm lines that name no cause: a bare exit code, or the OS/argv banner npm prints before the
 *  real error.
 *
 *  ⛔ MEASURED ON MY OWN LEDGER, WHICH IS WHY THIS EXISTS. Taking the FIRST line matching
 *  /npm error|ERR!/ captured a useless line on 240 of 625 rows — `npm error code 1`, or
 *  `npm ERR! Linux 6.11.0-azure`. The ledger looked attributed and was not: the honest count was
 *  385 of 959, not 625. The informative line is usually two or three lines further down. */
const UNINFORMATIVE = new RegExp([
  // Any error CODE is a category, never a cause, and npm always prints a more specific sibling:
  // EBADPLATFORM is followed by `notsup Unsupported platform for x@y: wanted {...}`, ERESOLVE by
  // `While resolving: ...`, ELIFECYCLE by the line naming the script that exited. The first cut of
  // this pattern only skipped NUMERIC codes, which left 98 rows on `code ELIFECYCLE` and 64 on
  // `code EBADPLATFORM` — attributed-looking rows carrying nothing package-specific.
  String.raw`^npm (error|ERR!) code \S+$`,
  // The environment preamble. `path` is the one that mattered: it was absent from the first cut and
  // it is the SECOND line of every npm 10 error block, so it won 284 of 284 win32 rows outright.
  String.raw`^npm (error|ERR!) (Linux|Darwin|Windows|path|argv|node|npm|cwd|System|errno|syscall|file|A complete log)\b`,
  // npm's own boilerplate tail.
  String.raw`^npm (error|ERR!) (Exit status \d+|not ok\b|This is probably not a problem with npm|Failed at the\b)`,
  // ⛔ `gyp` AND `command` ARE NOT BLANKET-NOISE, and treating them as such is how a node-gyp row
  // ends up attributed to `code 1`. Under npm 10 the whole gyp transcript is re-prefixed with
  // `npm error`, so the ONLY line naming the cause is `npm error gyp ERR! stack Error: ...`.
  // Skip gyp's progress chatter and npm's bare `command failed`; keep everything else.
  String.raw`^(npm (error|ERR!) )?gyp (info|http|verb|WARN)\b`,
  // gyp's own stage markers and preamble. `gyp ERR! configure error` says only WHICH PHASE
  // died; the line under it (`gyp ERR! stack Error: Can't find Python executable "python"`)
  // is the reason, and heapdump@0.3.9 was attributed to the marker until this was added.
  String.raw`^(npm (error|ERR!) )?gyp ERR! (configure|build|install) error$`,
  String.raw`^(npm (error|ERR!) )?gyp ERR! (System|command|cwd|node -v|node-gyp -v|not ok)\b`,
  String.raw`^npm (error|ERR!) command failed$`,
].join('|'));

/** Lines that name WHY, as opposed to what npm was doing when it happened. `npm error command sh -c
 *  node-gyp rebuild` is a true statement about the failure and still not the cause; two lines below
 *  it sits `gyp ERR! find Python Python is not set from command line or npm configuration`, which
 *  is. Ranking beats first-match here because npm prints the block outside-in: category, then
 *  context, then cause. */
const NAMES_A_CAUSE = /gyp ERR! (stack|find)|ERR! stack |SyntaxError|Error:|command not found|is not recognized|\bnotsup |No such file|Permission denied|cannot find|not supported|Unsupported/;

/** Three tiers, and the last one is what keeps this from ever being a regression: a row is never
 *  made LESS informative than the naive "first line matching /npm error/" it replaced. */
export function firstCause(log) {
  const lines = String(log ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
  const errish = lines.filter((l) => /npm error|npm ERR!|ERR!|SyntaxError|Error:|command not found|is not recognized/.test(l));
  return errish.find((l) => NAMES_A_CAUSE.test(l))
      ?? errish.find((l) => !UNINFORMATIVE.test(l))
      ?? errish[0]
      ?? null;
}

/** The last lines of a failing log, capped so a ledger of thousands of rows stays a text file.
 *  Stored on every measured row so any later change to the cause extractor can be evaluated against
 *  what the run actually saw, rather than re-run against a registry that has moved on. */
export function errorTail(log, { lines = 40, chars = 8000 } = {}) {
  const kept = String(log ?? '').split('\n').map((l) => l.trimEnd()).filter((l) => l.trim());
  if (!kept.length) return null;
  return kept.slice(-lines).join('\n').slice(-chars);
}

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

  // ⛔ `npm.cmd` ON WINDOWS. npm ships as a `.cmd` shim there, and `spawnSync` without a shell
  // CANNOT execute one — it returns 127, "command not found". MEASURED: all 570 win32 rows came back
  // fetchRc=127, every one dispositioned CONFIRMED with no era pin and no error text. A 100% verdict
  // with zero evidence is a broken instrument, not a finding, and it would have reported the entire
  // win32 population as confirmed-broken on the strength of npm never having run.
  // ⛔ RUN npm's JS ENTRY WITH THIS NODE — never the `npm` / `npm.cmd` shim.
  //
  // Two measured failures got us here. A bare `npm` on Windows returns 127 (npm is a `.cmd` shim and
  // spawnSync without a shell cannot execute one): all 570 win32 rows came back fetchRc=127 and were
  // dispositioned CONFIRMED with no era pin and no error text. Switching to `npm.cmd` then failed
  // EARLIER, with `status=null` — Node refuses to spawn a `.cmd` at all without `shell: true`, which
  // is the CVE-2024-27980 fix. `shell: true` would work and would also re-introduce quoting hazards
  // on every spec containing a scope or a caret.
  //
  // npm's own entry point is plain JS and is laid out predictably next to the interpreter: POSIX puts
  // it under `lib/node_modules`, Windows directly under the install root. Running it with
  // `process.execPath` sidesteps the shim, the shell and the quoting.
  // One implementation, shared with era-node.mjs — see npm-cli.mjs for why the shim is unusable and
  // for what leaving a second copy unconverted cost.
  const { cmd: NPM, prefix: npmPrefix } = npmInvocation();
  const npmCli = npmPrefix[0] ?? null;
  const npmArgs = (args) => [...npmPrefix, ...args];
  const sh = (cmd, args, opts = {}) => spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 1 << 28, ...opts });

  // ⛔ PREFLIGHT, SO A MISSING TOOL FAILS LOUD INSTEAD OF BECOMING 570 PACKAGE VERDICTS. The whole
  // sweep is worthless if npm cannot be invoked, and the failure mode is silent: every row simply
  // "confirms" the record it was meant to re-test.
  {
    const probe = sh(NPM, npmArgs(['--version']));
    if (probe.status !== 0) {
      process.stderr.write(`FATAL: cannot invoke ${NPM} (status=${probe.status}) — refusing to measure.\n`);
      process.exit(2);
    }
    process.stderr.write(`npm ${String(probe.stdout).trim()} via ${npmCli ?? NPM}\n`);
  }
  const eraRoot = eraRootDir();
  fs.mkdirSync(eraRoot, { recursive: true });
  // Discovered ONCE: probing per row would run `command -v` thousands of times for one answer.
  //
  // ⛔ NOT VIA `/bin/sh`, WHICH WINDOWS DOES NOT HAVE. Every probe returned nothing there, so
  // `pythonCandidates` was EMPTY on win32 and 53 rows carry `python: null` — the era Python never
  // had a chance to apply. Resolving each name against PATH in-process works on all three.
  //
  // ⛔ AND AN INJECTED PATH WINS. A legacy era needs a Python no newer than 3.9 (see
  // era-python.mjs), and a runner's default is 3.12+. The workflow provisions one and passes it in
  // ERA_PYTHON_LEGACY, because setup-python exposes its interpreter as `python3`, not `python3.9` —
  // probing by versioned name alone would never find it.
  const resolveOnPath = (name) => {
    const exts = process.platform === 'win32' ? ['.exe', '.cmd', '.bat', ''] : [''];
    for (const dir of (process.env.PATH ?? '').split(path.delimiter).filter(Boolean)) {
      for (const ext of exts) {
        const cand = path.join(dir, name + ext);
        try { fs.accessSync(cand, fs.constants.X_OK); return cand; } catch { /* keep looking */ }
      }
    }
    return null;
  };
  const describePython = (pth) => {
    if (!pth) return null;
    // Python 2 writes --version to stderr, Python 3 to stdout. Read both or every 2.x reads blank.
    const v = spawnSync(pth, ['--version'], { encoding: 'utf8' });
    const text = `${v.stdout ?? ''}${v.stderr ?? ''}`.trim();
    return text ? { path: pth, version: text } : null;
  };
  const pythonCandidates = [];
  const seenPython = new Set();
  // ERA_PYTHON2 is the Windows MSI's interpreter: a TARGETDIR install is not on PATH, so the only
  // way the probe finds it is to be handed the path. Both injected paths are tried before the
  // name probe, and `pythonForEra` still picks by FAMILY, so a modern era is unaffected.
  for (const cand of [process.env.ERA_PYTHON2 ?? null,
                      process.env.ERA_PYTHON_LEGACY ?? null,
                      ...PROBE_NAMES.map(resolveOnPath)]) {
    const found = describePython(cand);
    if (!found || seenPython.has(found.path)) continue;
    seenPython.add(found.path);
    pythonCandidates.push(found);
  }
  process.stderr.write(`python candidates: ${pythonCandidates.map((c) => `${c.path} (${c.version})`).join(', ') || 'NONE'}\n`);
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
      // ⛔ AN ERA THAT COULD NOT BE CHOSEN IS NOT AN ERA. When the packument lookup fails, the
      // selector falls back to the harness's own Node and the row would otherwise read a confident
      // `PINNED 22.23.2` — which is the DEFAULT, not the package's era. All 570 win32 rows of two
      // sweeps carried eraMajor null and before null while reporting exactly that pin. The reason
      // now rides on the record.
      rec.eraLookupFailure = selection.lookupFailure ?? (sel.status !== 0
        ? `era-node.mjs exited ${sel.status}` : null);
      // ⛔ SHARE THE NODE-GYP HEADER CACHE, AND DO IT BY LINKING $HOME/.node-gyp — NOT with
      // `npm_config_devdir`, WHICH THE ERA NODES DO NOT READ. HOME is deliberately fresh per record,
      // and node-gyp 3.x resolves its devDir from HOME with no override at all:
      //   lib/node-gyp.js:59   this.devDir = path.resolve(homeDir, '.node-gyp')
      //   lib/node-gyp.js:50   // TODO: make this *more* configurable?
      // (`--devdir` arrived in node-gyp 4.) So every native build re-downloaded the Node headers
      // over TLS from a 2016 Node, and that download FLAKES: heapdump@0.3.9 measured rc=0,0,124,0,1
      // across five identical runs on era 6.17.1, failing inside request.js with
      // "is related to network connectivity" and once blowing the 300s cap outright. A flaky fetch
      // inside the arm is indistinguishable in the ledger from a package that genuinely does not
      // build, so it manufactures false CONFIRMED and false HARNESS-TIMEOUT rows on exactly the
      // native builds this corpus is about. A junction is used rather than a symlink so this works
      // unprivileged on Windows too.
      const gypCache = path.join(eraRoot, '..', 'gyp-headers');
      fs.mkdirSync(gypCache, { recursive: true });
      try { fs.symlinkSync(gypCache, path.join(home, '.node-gyp'), 'junction'); }
      catch { /* a link we cannot make costs a re-download, never a wrong verdict */ }
      const env0 = { ...process.env, HOME: home, npm_config_cache: path.join(root, 'npmcache') };
      // ⛔ THE FETCH IS CAPPED TOO. Only the rebuild was wrapped before, so a hanging
      // `npm install --before=…` bounded nothing and one row could stall an entire sweep.
      const fetchLog = path.join(root, 'fetch.log');
      const ffd = fs.openSync(fetchLog, 'w');
      const f = await runCapped(NPM, npmArgs([...fa.args, '--no-audit', '--no-fund'].filter((a, i, all) => all.indexOf(a) === i)),
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
        // ⛔ THE PROVISIONER IS PER-PLATFORM AND IT VERIFIES. The inline version here hardcoded
        // `darwin ? 'darwin' : 'linux'`, so a win32 runner fetched a LINUX tarball and then tested
        // for `bin/node` — a path the Windows layout never has. All 333 win32 rows of the
        // 2026-08-21 sweep came back `NOT-PINNED (not provisionable)` with era pins 0, silently
        // confirming failures an era Node might well have fixed. era-provision.mjs owns the layout,
        // runs the binary to prove it is the version asked for, and names the stage that failed.
        let eraBin = null;
        let eraNpmCli = null;
        if (selection.version && selection.pinnable !== false) {
          const p = provisionEraNode(selection.version, { root: eraRoot, exec: sh });
          eraBin = p.binDir;
          eraNpmCli = p.npmCli;
          rec.eraStatus = p.status;
        } else {
          rec.eraStatus = `NOT-PINNED (${selection.version ? 'engines unsatisfiable' : 'no era selected'})`;
        }
        rec.eraPinned = eraBin ? selection.version : null;
        if (rec.eraLookupFailure) {
          rec.eraStatus = `NOT-AN-ERA (${rec.eraLookupFailure}); ran on ${selection.version ?? 'the harness Node'}`;
        }

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
          // ⛔ THE SCAFFOLD IS DATED TOO. Without `--before` this pulled TODAY's `typings`,
          // `flow-typed` and `webdriver-manager` into a tree pinned to 2016, and the era Node then
          // could not parse them. The fetch had carried the date since F2; this second install
          // never did.
          const si = sh(NPM, npmArgs(['install', '--no-audit', '--no-fund', '--ignore-scripts',
                                      ...(fa.before ? [`--before=${fa.before}`] : []),
                                      ...scaffold.install]),
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
        // ⛔ ASK THE PROVISIONER, DO NOT REBUILD THE PATH HERE. This was
        // `<eraBin>/../lib/node_modules/npm/bin/npm-cli.js` — the POSIX layout — so on Windows it
        // never existed, `useEra` was always false, and the HARNESS npm ran its node-gyp under the
        // era Node reached through the arm PATH: `TypeError: name.replaceAll is not a function`
        // out of node 22's bundled node-gyp. 78 of the 96 rows in that family were win32.
        const npmBin = eraNpmCli;
        const useEra = Boolean(npmBin);
        const rebuildOnce = async (outFd) => runCapped(
          useEra ? path.join(eraBin, 'node') : NPM,
          // The era path already runs a JS entry with the era node; the fallback needs npmArgs so it
          // does not reach for the shim on Windows.
          useEra ? [npmBin, 'rebuild', '--no-audit', '--no-fund', pkg]
                 : npmArgs(['rebuild', '--no-audit', '--no-fund', pkg]),
          { ms: capSecs * 1000, cwd: obs, env, stdio: ['ignore', outFd, outFd] });

        let r = await rebuildOnce(fd);
        fs.closeSync(fd);
        let log = fs.readFileSync(logPath, 'utf8');

        // ⛔ ASK THE FAILURE WHAT IT NEEDS, THEN RETRY. The scaffold reads the manifest's script
        // STRING, so it provides what `postinstall: "tsc -p ."` names and nothing a script reaches
        // for at RUNTIME — `node build.js` whose build.js requires `rollup`, or shells out to
        // `bower`. Measured on the 2026-08-22 ledger: of the 130 rows that died naming a missing
        // module or binary, the scaffold had produced anything at all for only 20, and 60 of them
        // name a package that npm can simply install.
        //
        // Bounded at MAX_RETRIES because each pass must name something NEW to continue, and the
        // same install is never attempted twice — a script that keeps naming the same absent thing
        // stops rather than looping. Everything added is recorded on the row, so a record can never
        // claim an environment it did not have.
        const MAX_RETRIES = 3;
        const added = [];
        for (let attempt = 0; attempt < MAX_RETRIES && r.code !== 0 && !r.timedOut; attempt++) {
          const need = namesMissingDependency(log);
          if (!need || added.includes(need.install)) break;
          // Dated like every other install in this arm: an undated retry pulls TODAY's package into
          // a tree pinned to the target's publish date, which is the leak that cost 96 rows before.
          const add = sh(NPM, npmArgs(['install', '--no-audit', '--no-fund', '--ignore-scripts',
                                       ...(fa.before ? [`--before=${fa.before}`] : []),
                                       need.install]), { cwd: obs, env });
          added.push(need.install);
          if ((add.status ?? 1) !== 0) break;      // could not supply it — keep the failure we have
          const rfd = fs.openSync(logPath, 'w');
          r = await rebuildOnce(rfd);
          fs.closeSync(rfd);
          log = fs.readFileSync(logPath, 'utf8');
        }
        if (added.length) rec.retryInstalled = added;
        // ⛔ SET FROM THE FINAL ATTEMPT, and these were briefly LOST when the retry loop replaced the
        // single call: the row came back `rebuildRc: undefined`, which `observeVerdict` read as a
        // failure, so a package the retry had just FIXED still recorded BROKEN-WITHOUT-JAIL-TOO.
        rec.rebuildRc = r.code;
        rec.capped = r.timedOut;
        rec.firstError = firstCause(log)?.slice(0, 200) ?? null;
        // ⛔ KEEP THE TAIL. Auditing the extractor against the 2026-08-21 ledger was impossible
        // because only `firstError` was stored: when 284 of 284 win32 rows came back on the same
        // useless line, nothing on disk could say whether a better line had existed. A ~20-line
        // tail makes every attribution re-checkable without re-running the sweep.
        rec.tail = errorTail(log);
      } else {
        rec.rebuildRc = null; rec.capped = false;
        // ⛔ READ THE FETCH LOG, NOT `f.stdout`. `runCapped` returns only {code, timedOut} — it never
        // captures output, and the fetch's stdio is a FILE descriptor. So this branch was reading a
        // property that is always undefined, and EVERY row npm could not even install recorded no
        // reason at all: `@ffmpeg-installer/darwin-x64@4.1.0` came back fetchRc=1 with firstError
        // null. A row that cannot say why the install failed cannot be told from one that was never
        // measured.
        const ftext = fs.existsSync(fetchLog) ? fs.readFileSync(fetchLog, 'utf8') : '';
        rec.firstError = firstCause(ftext)?.slice(0, 200) ?? null;
        rec.tail = errorTail(ftext);
      }
      rec.verdict = observeVerdict(rec);
      rec.disposition = prevVerdict ? disposition(prevVerdict, rec.verdict) : null;
    } catch (e) { rec.verdict = 'HARNESS-ERROR'; rec.firstError = String(e?.message ?? e).slice(0, 160); }
    // ⛔ CLEANUP CANNOT BE FATAL. On Windows a native build leaves a DLL mapped, so rmSync throws
    //   Error: EBUSY: resource busy or locked, rmdir '...\\node_modules\\lzma-native'
    // and the throw escaped the loop: three of four win32 shards died mid-sweep, each losing every
    // row behind the one that happened to build a native module. A leaked temp directory on an
    // ephemeral runner costs nothing; a truncated shard costs the whole tail of the worklist.
    try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 }); }
    catch (e) { process.stderr.write(`  cleanup skipped for ${spec}: ${e?.code ?? e}\n`); }
    ledger.write(`${JSON.stringify(rec)}\n`);
    n++;
    if (n % 10 === 0) process.stderr.write(`  ${n}/${specs.length}\n`);
  }
  ledger.end();
  process.stderr.write(`done: ${n} rows -> ${out}\n`);
}
