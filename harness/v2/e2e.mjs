// One package, the whole loop, one summary: measure -> record -> collate -> INSTALL FOR REAL.
//
// The stages this drives all existed; running them meant four commands, three of which take flags
// nobody remembers, and the fourth — whether the grant the pipeline just produced actually installs
// the package — did not exist at all. A grant that measures clean and does not install is the one
// failure nobody would currently see, because every step before it is the harness checking itself.
//
//   usage: node e2e.mjs <pkg> <version> [options]
//
//     --nub <path>            binary under test (default: the driver's own default)
//     --at-grant '<json>'     DIRECT mode: does it install under EXACTLY this grant? No synthesis,
//                             so no catalog and no install stage — a different question (see below)
//     --install-grant '<json>'  ⛔ NEGATIVE CONTROL: install under this grant instead of the
//                             collated one. Feed a grant you know is too narrow to prove the
//                             install stage can FAIL
//     --catalog <file>        install against this catalog file rather than collating one
//     --skip-install          stop after the catalog
//     --falsify               also run the batch runner's six-arm falsification control (~55s)
//     --publish               publish the record to the corpus (default: no — see PUBLISH below)
//     --no-publish            the default, statable
//     --keep                  keep every fixture root and log instead of sweeping them
//     --json                  emit the summary as JSON on stdout
//     --runs <dir>            where the record lands (default: a private temp dir)
//     --budget <seconds>      per-driver budget, passed to the batch runner
//
//   exit codes:
//     0  the install stage RAN and the package installed under the pipeline's own catalog
//     1  a stage failed (or the negative control passed, which is a failure of this tool)
//     2  usage
//     4  ⛔ every stage that COULD run passed, but the install stage did not run — either this
//        platform cannot run it, or `--skip-install` asked for that. The product is UNVERIFIED.
//
// ⛔ 4 EXISTS BECAUSE 0 WOULD BE A LIE WHEREVER THE INSTALL STAGE CANNOT RUN, AND IT IS THE LIE THIS
// TOOL WAS BUILT TO REMOVE. Every OTHER stage is the harness reading its own output back, so a plain
// 0 there would certify a pipeline against itself and say nothing whatever about whether the grant
// installs. A caller gating on `rc === 0` gets that distinction for free; one gating on `rc !== 1`
// opts out of it deliberately.
//
// ⛔⛔ AND WHICH PLATFORMS THOSE ARE IS NO LONGER ASSERTED FROM A SEARCH — IT IS ASKED OF THE RUN.
// This comment used to say `--at-catalog` "is implemented in `measure.sh` only, verified by search".
// That was true when written, went false when `measure-macos.sh` gained the flag, and the METHOD was
// unsound either way: a driver commit landed with the flag's PARSER and no dispatch, so `--at-catalog`
// was accepted, silently ignored, and every arm ran the same catalog — which would have published an
// empty grant as a measured minimum. A search for the flag name matches the parser, not the feature.
//
// So the stage now requires the driver to PROVE the mode engaged, by printing its `── DIRECT:` banner.
// No banner means the mode did not run, whatever the exit code said, and the stage reports
// `unavailable` rather than a pass. That is the one check a parser-without-a-dispatch cannot satisfy.
//
// ⛔ THE MEASUREMENT IS NOT REIMPLEMENTED HERE — IT SHELLS OUT TO `run-batch-v2.mjs` WITH A
// ONE-LINE WORKLIST. That is deliberate and it is the whole answer to "could this tool and the
// batch runner disagree about a package?". They cannot: the verdict comes from the batch runner
// itself, including its driver dispatch, its `rc=124` timeout convention, its retained-event-log
// variables and its `record.mjs` invocation. A second copy of that dispatch would be a copy that
// can drift, and the drift would be invisible — two verdicts for one package, both plausible.
//
// The one thing the batch runner could not express is a driver FLAG, so it gained a two-line seam
// (`NUB_V2_DRIVER_ARGS`) rather than being forked.
//
// ⛔ PUBLISH IS OPT-IN, INVERTING THE PHRASING OF THE ASK, AND THE REASON IS MECHANICAL:
// `publish-record-v2.sh` runs `git fetch` + `git reset` in the corpus checkout it is pointed at. A
// debugging tool that does that to a shared tree by default would, on any box where someone else
// has work in progress, reset it out from under them. `--no-publish` is accepted so the default can
// be stated rather than assumed.
//
// ⛔ AND IT ALWAYS MEASURES: the batch runner is invoked with `--force`, so an existing record for
// this spec is REPLACED, never skipped. Resume is right for a sweep and wrong for a debugging loop,
// where "already recorded" is the answer you are trying to change. With `--publish` the record
// lands in the corpus tree, so a re-measure of a spec that already holds a record overwrites it —
// which is what re-measuring means, and why it is not the default destination.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const PLATFORM = `${process.platform}-${process.arch}`;

// ── argv ──────────────────────────────────────────────────────────────────────
// ⛔ AN UNRECOGNISED FLAG IS REFUSED, NOT IGNORED — the lesson `collate.mjs` records in its own
// header, where `--records` instead of `--runs` read the default path, collated zero records, wrote
// an empty catalog and exited 0. Every option here has a default, so the same silence is available.
const argv = process.argv.slice(2);
const FLAGS = new Set(['--nub', '--at-grant', '--install-grant', '--catalog', '--runs', '--budget']);
const BOOLS = new Set(['--keep', '--json', '--publish', '--no-publish', '--skip-install',
  '--falsify', '--no-falsify']);
{
  const unknown = argv.filter((a, i) => a.startsWith('--') && !FLAGS.has(a) && !BOOLS.has(a)
    && !(i > 0 && FLAGS.has(argv[i - 1])));
  if (unknown.length) {
    console.error(`e2e REFUSED: unknown flag(s): ${unknown.join(', ')}`);
    console.error(`  known: ${[...FLAGS, ...BOOLS].join(' ')}`);
    process.exit(2);
  }
}
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const has = (n) => argv.includes(n);
const positional = argv.filter((a, i) => !a.startsWith('--') && !(i > 0 && FLAGS.has(argv[i - 1])));
const [PKG, VER] = positional;
if (!PKG || !VER) {
  console.error('usage: node e2e.mjs <pkg> <version> [options]   (see the header for options)');
  process.exit(2);
}

const JSON_OUT = has('--json');
// ⛔ A DIRECT-MODE RECORD MUST NOT REACH THE CORPUS. `record.mjs` has no verdict for `=> SUFFICIENT`
// / `=> INSUFFICIENT`, so a `--at-grant` run records as `HARNESS-ERROR` — and published under
// `--force` that would overwrite a good `MINIMUM` record for the same spec with an instrument
// failure that never happened.
if (has('--at-grant') && has('--publish')) {
  console.error('e2e REFUSED: --at-grant with --publish. DIRECT mode produces no MINIMUM verdict, so '
    + 'the record would land in the corpus as HARNESS-ERROR and overwrite whatever is there.');
  process.exit(2);
}
const KEEP = has('--keep');
const PUBLISH = has('--publish');
const AT_GRANT = opt('--at-grant', '');
const INSTALL_GRANT = opt('--install-grant', '');
const CATALOG_IN = opt('--catalog', '');
const SKIP_INSTALL = has('--skip-install');
const BUDGET = opt('--budget', '');
const NUB = path.resolve(opt('--nub', path.join(os.homedir(), 'nub', 'target', 'fast', 'nub')));

// Everything this run writes that is not a record: driver logs, the collated catalog, the isolated
// one-record tree collate reads. One directory so `--keep` retains a coherent set and the default
// sweep cannot miss half of it.
const WORK = fs.mkdtempSync(path.join(os.homedir(), `e2e-${PKG.replace(/[^a-z0-9]/gi, '-')}-`));
const RUNS = path.resolve(opt('--runs', PUBLISH ? path.join(REPO, 'records-v2', 'runs')
  : path.join(WORK, 'runs')));

// ── stage bookkeeping ─────────────────────────────────────────────────────────
// A failure has to be attributable to a stage or this tool is worth nothing: "it failed" is what
// the four-command sequence already told you.
const stages = [];
const stage = (name) => {
  const s = { name, status: 'running', why: null, ms: 0, log: null, t0: Date.now() };
  stages.push(s);
  return s;
};
const done = (s, status, why, log) => {
  s.status = status; s.why = why ?? null; s.log = log ?? s.log; s.ms = Date.now() - s.t0;
  return s;
};
const sh = (cmd, args, o = {}) => spawnSync(cmd, args, {
  encoding: 'utf8', maxBuffer: 1 << 28, ...o,
});
const secs = (ms) => `${(ms / 1000).toFixed(1)}s`;
const j = (v) => (v === undefined ? '(absent)' : JSON.stringify(v));

const summary = {
  pkg: PKG, version: VER, platform: PLATFORM, at: new Date().toISOString(),
  work: WORK, binary: null, record: null, catalog: null, install: null, stages,
};

let exitCode = 0;
const finish = (code) => {
  summary.ok = code === 0;
  summary.exitCode = code;
  // A JSON consumer must be able to ask "did the product check run?" without pattern-matching the
  // stage table. `ok` alone cannot answer it: `ok:false` covers both "the grant does not install"
  // and "nobody checked", and those call for opposite reactions.
  summary.productChecked = stages.some((s) => s.name === 'install' && (s.status === 'ok' || s.status === 'fail'));
  // ⛔ RE-HASHED AT THE END, AND THIS IS NOT BELT-AND-BRACES. The binary path is shared mutable
  // state: `~/nub/target/release/nub` was rebuilt mid-sweep without the override feature and every
  // measurement after that point went VOID, with `nubGitSha` IDENTICAL across the good and the bad
  // binary because the commit had not moved. Provenance could not tell them apart; the content hash
  // can, and a run whose binary changed underneath it measured two different programs.
  if (summary.binary) {
    const after = hashBinary(NUB);
    summary.binary.sha256After = after.sha256;
    summary.binary.changedDuringRun = after.sha256 !== summary.binary.sha256;
  }
  // ⛔ A FAILED RUN KEEPS EVERYTHING, WHATEVER `--keep` SAYS. This tool exists to be debugged
  // through, and the first version swept the driver log of the run that had just failed — leaving a
  // summary that named the stage, named the log, and had deleted it. Sweeping is for the SUCCESS
  // path, where the fixture roots are large and there is nothing left to read.
  summary.retained = code !== 0 || KEEP;
  if (!summary.retained) sweep();
  render();
  process.exit(code);
};

// The driver's fixture roots are `mktemp -d "$HOME/v2-XXXXXX"` and it does not remove them. Eight
// abandoned ones took the corpus VM's root filesystem to 100% full, which presents as a dead box:
// `scp: write remote: Failure`, zero-byte outputs from commands that "succeeded". A tool that runs
// the driver twice per invocation cleans up after itself, and `--keep` is how you inspect instead.
const roots = [];
function sweep() {
  for (const r of roots) { try { fs.rmSync(r, { recursive: true, force: true }); } catch { /* best effort */ } }
  if (!PUBLISH && !opt('--runs', null)) { try { fs.rmSync(WORK, { recursive: true, force: true }); } catch { /* ignore */ } }
}

// ── stage 1: is the binary fit? ───────────────────────────────────────────────
function hashBinary(p) {
  try {
    const buf = fs.readFileSync(p);
    const st = fs.statSync(p);
    return { sha256: crypto.createHash('sha256').update(buf).digest('hex'), size: st.size, mtime: st.mtime.toISOString() };
  } catch (e) { return { sha256: null, size: null, mtime: null, error: e.message }; }
}

function stageBinary() {
  const s = stage('binary');
  if (!fs.existsSync(NUB)) return done(s, 'fail', `no such binary: ${NUB}`);
  const h = hashBinary(NUB);
  // ⛔ FITNESS IS ASKED OF THE RUNNING BINARY, BEFORE ANY WORK, AND `nubGitSha` CANNOT SUBSTITUTE
  // FOR IT. A nub built without `build-jail-catalog-override` REFUSES `NUB_BUILD_JAIL_CATALOG`, so
  // every arm measures the compiled-in catalog and the run ends VOID — an hour of installs to learn
  // a fact available in one second. Two binaries from ONE commit differ here, which is why the
  // record needs the CONTENT hash beside the commit sha: `nubGitSha` was identical across the good
  // and the bad binary during the incident that motivated this check.
  //
  // ⛔⛔ AND IT IS NOT A GREP FOR THE FEATURE NAME. That predicate is exactly INVERTED: the literal
  // reaches a binary only through the refusal message inside
  // `if !cfg!(feature = "build-jail-catalog-override")`, so a fit build has the branch — and the
  // string — optimised away, while an unfit build carries it. MEASURED 2026-08-06 on three binaries
  // across two profiles, all built with the feature: every one failed the grep and every one printed
  // the banner. The banner IS the artifact; the byte pattern is adjacent to it.
  const probeCat = path.join(WORK, 'preflight-cat.json');
  fs.writeFileSync(probeCat, '{"packages":{"__override_preflight__":{"default":{"network":true}}}}');
  const v = sh(NUB, ['--version'], { timeout: 60_000, env: { ...process.env, NUB_BUILD_JAIL_CATALOG: probeCat } });
  const out = `${v.stdout ?? ''}${v.stderr ?? ''}`;
  const fit = /catalog OVERRIDDEN/.test(out);
  const version = (v.stdout ?? '').trim().split('\n').filter((l) => /^v?\d/.test(l)).pop()
    ?? (v.stdout ?? '').trim().split('\n').pop() ?? '';
  summary.binary = { path: NUB, version, ...h, honoursOverride: fit };
  if (!fit) {
    return done(s, 'fail', `${NUB} does not honour NUB_BUILD_JAIL_CATALOG — every arm would be VOID. `
      + 'Rebuild:\n'
      + '    cargo build -p nub-cli --profile fast --features nub-cli/build-jail-catalog-override\n'
      + `  it said: ${out.trim().split('\n').slice(0, 3).join(' / ').slice(0, 300)}`);
  }
  if (v.status !== 0) return done(s, 'fail', `${NUB} --version exited ${v.status}: ${(v.stderr ?? '').trim().slice(0, 200)}`);
  return done(s, 'ok', `${version}  sha256:${h.sha256.slice(0, 12)}  honours NUB_BUILD_JAIL_CATALOG`);
}

// ── stage 2: measure, through the batch runner ────────────────────────────────
function stageMeasure() {
  const s = stage('measure');
  const worklist = path.join(WORK, 'worklist.txt');
  fs.writeFileSync(worklist, `${PKG}@${VER}\n`);
  const env = { ...process.env };
  // R6 — apparatus only. Nothing here is an environment variable an install script or nub can read:
  // `NUB_V2_DRIVER_ARGS` is the batch runner's own passthrough and `NUB_CORPUS_*` are the corpus
  // tooling's. `CI`, `HOME`, `PATH`, `NODE_ENV` and TTY-ness are left exactly as inherited, which is
  // the rule in VENUE-PORTABILITY.md: the harness may normalise its instrument, never its subject.
  if (AT_GRANT) env.NUB_V2_DRIVER_ARGS = JSON.stringify(['--at-grant', AT_GRANT]);
  if (PUBLISH) {
    env.NUB_CORPUS_REPO = REPO;
    env.NUB_CORPUS_ON_RECORD = path.join(HERE, 'publish-record-v2.sh');
  } else {
    delete env.NUB_CORPUS_ON_RECORD;
  }
  // ⛔ THE BATCH RUNNER'S FALSIFICATION PRE-FLIGHT IS OFF BY DEFAULT HERE, AND THAT IS A REAL
  // TRADE-OFF RATHER THAN A CONVENIENCE. `falsify.mjs` runs six real install arms on two unrelated
  // packages (~55s, measured) before the batch starts. That is proportionate to a sweep and
  // disproportionate to a single-package debugging loop this tool exists to shorten — it would more
  // than double the round-trip and re-prove the same thing every iteration. What is NOT given up:
  // this run has its own per-package falsification available (`--install-grant`, which forces a
  // grant chosen to be too narrow and requires the install to be refused), and the binary-fitness
  // gate that motivates falsify's INCONCLUSIVE case already ran above. `--falsify` opts back in.
  //
  // ⛔ AND THE SKIP IS PRINTED. Their gate's own rule: a control that can be silently absent is not
  // a control, because "it passed" and "it never ran" read identically in a log.
  const falsify = has('--falsify');
  summary.falsify = falsify ? 'run' : 'skipped';
  const args = [path.join(HERE, 'run-batch-v2.mjs'), '--file', worklist, '--runs', RUNS, '--force',
    ...(falsify ? [] : ['--no-falsify']),
    ...(NUB ? ['--nub', NUB] : []), ...(BUDGET ? ['--budget', BUDGET] : [])];
  const r = sh(process.execPath, args, { env });
  const log = path.join(WORK, 'measure.out');
  fs.writeFileSync(log, `$ node ${args.join(' ')}\n\n${r.stdout ?? ''}${r.stderr ?? ''}`);
  s.log = log;
  if (r.status !== 0) return done(s, 'fail', `run-batch-v2.mjs exited ${r.status}`, log);

  const dir = path.join(RUNS, PLATFORM, PKG.replace(/\//g, '+'), VER);
  const rj = path.join(dir, 'results.json');
  if (!fs.existsSync(rj)) return done(s, 'fail', `no record written at ${rj}`, log);
  const rec = JSON.parse(fs.readFileSync(rj, 'utf8'));
  summary.record = { dir, ...rec };
  // The driver announces its fixture root on its first line: `### pkg@ver   (/home/nub/v2-XXXXXX)`.
  // Retained so the sweep can find it, and so `--keep` points somewhere real.
  const driverOut = path.join(dir, 'driver.out');
  if (fs.existsSync(driverOut)) {
    const m = /^### .*\((.+)\)\s*$/m.exec(fs.readFileSync(driverOut, 'utf8'));
    if (m) { summary.record.fixtureRoot = m[1]; roots.push(m[1]); }
  }
  // ⛔ THE BINARY THIS TOOL PROBED AND THE BINARY THE DRIVER MEASURED WITH ARE TWO CLAIMS, AND ON A
  // SHARED BOX THEY CAN DIFFER. `measure.sh` records its own `VENUE-NUB-BINARY` content hash; a
  // mismatch against the hash taken seconds earlier here means a lane rebuilt the artifact mid-run
  // — the failure that produced a batch of VOID cells with an entirely unchanged `nubGitSha`.
  const drvSha = rec.provenance?.nubBinary?.sha256 ?? null;
  summary.binary.sha256AtDriver = drvSha;
  summary.binary.driverAgrees = drvSha === null ? null : drvSha === summary.binary.sha256;
  if (summary.binary.driverAgrees === false) {
    return done(s, 'fail', 'the binary CHANGED between this tool\'s preflight and the driver\'s run — '
      + `probed ${summary.binary.sha256.slice(0, 12)}, driver measured with ${drvSha.slice(0, 12)}. `
      + 'Two programs were measured, so the record is attributable to neither.', log);
  }
  // ⛔ DIRECT MODE'S VOCABULARY IS NOT IN `record.mjs`'S VERDICT TABLE, AND THE RECORD IS THEREFORE
  // WRONG RATHER THAN MISSING. `measure.sh --at-grant` terminates on `=> SUFFICIENT` / `=>
  // INSUFFICIENT`; `VERDICTS` models neither, so `parseDriverLog` finds no terminal line and the CLI
  // falls through to `HARNESS-ERROR` — the instrument reporting its own failure for a run that
  // answered its question perfectly. Left alone rather than added to their table: `claim-slice.mjs`
  // closes a queue row on a non-`HARNESS-*` verdict, so teaching the table two new words would make
  // a DIRECT probe close a row it never measured a minimum for. The driver's own terminal line is
  // read instead, and the misleading record stays out of the corpus (`--publish` is refused above).
  if (AT_GRANT) {
    const term = fs.existsSync(driverOut)
      ? (fs.readFileSync(driverOut, 'utf8').match(/^\s*=>.*$/m) ?? [''])[0].trim() : '';
    summary.direct = { grant: AT_GRANT, rc: rec.driverRc, terminal: term };
    if (rec.driverRc === 3) return done(s, 'void', `the override did not engage — nothing was measured. ${term}`, log);
    if (rec.driverRc === 0) return done(s, 'ok', `SUFFICIENT — ${PKG}@${VER} installs under exactly ${AT_GRANT}. ${term}`, log);
    return done(s, 'fail', `INSUFFICIENT — ${PKG}@${VER} needs MORE than ${AT_GRANT}. ${term}`, log);
  }
  // ⛔ A `HARNESS-*` VERDICT IS THE INSTRUMENT SAYING IT COULD NOT MEASURE, NOT A RESULT. It must
  // stop the pipeline: collating it yields no entry, and an install stage run against no entry would
  // report on the base profile while looking like it had checked this package's grant.
  if (String(rec.verdict).startsWith('HARNESS-')) {
    return done(s, 'fail', `${rec.verdict} — the harness could not measure this package `
      + `(driver rc=${rec.driverRc}). Read ${driverOut}`, log);
  }
  return done(s, 'ok', `${rec.verdict}${rec.grant ? ` ${JSON.stringify(rec.grant)}` : ''}`, log);
}

// ── stage 3: the catalog entry the record implies ─────────────────────────────
function stageCatalog() {
  const s = stage('catalog');
  const out = path.join(WORK, 'catalog.json');
  if (CATALOG_IN) {
    fs.copyFileSync(path.resolve(CATALOG_IN), out);
    summary.catalog = { file: out, source: `--catalog ${CATALOG_IN}`, entry: readEntry(out) };
    return done(s, 'ok', `taken from ${CATALOG_IN}`);
  }
  // ⛔ COLLATED FROM AN ISOLATED TREE HOLDING THIS ONE RECORD, NOT FROM THE CORPUS. `collate.mjs`
  // groups by package and each entry is derived from that package's records alone, so the entry is
  // identical either way — and pointing it at the corpus would spend seconds walking thousands of
  // records to produce one line. The repo's `overrides/` IS still read, because a hand-authored
  // override REPLACES the measured entry in production and a check that skipped it would validate a
  // catalog nobody ships.
  //
  // VERIFIED rather than assumed: collating `kerberos@7.0.0` alone and collating the whole
  // `records-v2/runs` tree produce a byte-identical entry — `{"default":{"network":true,"notes":
  // "latest measured 7.0.0"}}` — with identical `baseline` and `env` blocks.
  //
  // ⛔ ONE THING THIS CATALOG GENUINELY LACKS, AND ITS DIRECTION IS THE SAFE ONE. The override
  // REPLACES the compiled-in table rather than merging into it, so a DEPENDENCY of the package under
  // test that has its own catalog entry in the shipped catalog has none here and runs its lifecycle
  // scripts at the base profile. That can make the install stage FAIL where the shipped catalog
  // would have succeeded — a false FAILURE, never a false pass, so it cannot launder an under-grant
  // through as green. When an install stage failure is not explained by this package's own grant,
  // that is the first thing to check: `--catalog <shipped-catalog.json>` reruns the same arm against
  // the real table.
  const solo = path.join(WORK, 'solo-runs');
  const dst = path.join(solo, PLATFORM, PKG.replace(/\//g, '+'), VER);
  fs.mkdirSync(dst, { recursive: true });
  fs.copyFileSync(path.join(summary.record.dir, 'results.json'), path.join(dst, 'results.json'));
  const args = [path.join(REPO, 'harness', 'collate.mjs'), '--runs', solo, '--out', out,
    '--baseline', path.join(REPO, 'harness', 'baseline.json'),
    '--overrides', path.join(REPO, 'harness', 'overrides'), '--only-platform', PLATFORM];
  const r = sh(process.execPath, args);
  const log = path.join(WORK, 'collate.out');
  fs.writeFileSync(log, `$ node ${args.join(' ')}\n\n${r.stdout ?? ''}${r.stderr ?? ''}`);
  s.log = log;
  if (r.status !== 0) return done(s, 'fail', `collate.mjs exited ${r.status}`, log);
  if (!fs.existsSync(out)) return done(s, 'fail', 'collate.mjs wrote no catalog', log);

  const entry = readEntry(out);
  summary.catalog = { file: out, source: 'collate.mjs', entry, absent: entry === undefined };
  // ⛔ AN ABSENT ENTRY IS THE CORRECT ENCODING OF "NEEDS NOTHING", NOT A COLLATION FAILURE. nub
  // REJECTS an entry that widens nothing and then falls back to the compiled-in table silently, so
  // `collate.mjs` drops the package instead; the override REPLACES that table, so an absent package
  // runs at the base profile — exactly what the record said. Worth stating in the summary because
  // "no entry" and "collate lost the record" read identically otherwise.
  return done(s, 'ok', entry === undefined
    ? 'no entry — the package needs nothing, and absence IS that grant'
    : `entry: ${JSON.stringify(stripNotes(entry))}`, log);
}

const readEntry = (file) => JSON.parse(fs.readFileSync(file, 'utf8')).packages?.[PKG];
const stripNotes = (e) => {
  const c = JSON.parse(JSON.stringify(e));
  delete c.default?.notes;
  for (const v of Object.values(c.versions ?? {})) delete v.notes;
  return c;
};

// ── stage 4: does it ACTUALLY install under that catalog? ─────────────────────
//
// ⛔ THIS IS THE ONLY STAGE THAT CHECKS THE PRODUCT RATHER THAN THE HARNESS. Everything above is the
// pipeline reading its own output back: OBSERVE feeds synthesis, synthesis feeds a verify arm built
// from the same grant, and the record feeds a collator that re-serialises it. A defect anywhere in
// that chain — a grant the collator encodes in a shape nub's parser reads differently, a band that
// resolves to the wrong version, a `baseline`/`env` block the arm catalogs never carried — survives
// all of it and shows up only when nub is handed the collated file and told to install.
//
// It runs through `measure.sh --at-catalog`, not through a hand-rolled `nub install` here, so it
// inherits the four replay guards, the explicit `buildJail`, the override assertion and the artifact
// gate. An install that exits 0 having produced nothing is the normal failure shape in a jail, and
// only the artifact manifest catches it.
// ⛔ THE PER-PLATFORM DRIVER, SPELLED THE SAME WAY `run-batch-v2.mjs` AND `falsify.mjs` SPELL IT.
// A fourth copy of this map would be a fourth thing to go stale; there are already three, and the
// batch runner's second copy of a *capability* list is exactly what silently skipped win32's
// falsification control. Kept here only because the drivers take different argv shapes, which is the
// same reason `run-batch-v2.mjs` keeps its own dispatch.
// ⛔ DARWIN NEEDS ROOT AND `bash` ALONE DOES NOT GIVE IT ANY. dtrace requires uid 0, so
// `bash measure-macos.sh …` unprivileged dies before it traces anything — MEASURED locally: rc=1 in
// 3s, ZERO verdict lines, `dtrace: DTrace requires additional privileges`. `falsify.mjs` had the
// identical omission and reported `UNPARSED … detectors=none`, i.e. an instrument failure wearing
// the costume of the finding it exists to make. Here it would have been quieter but no better: no
// `── DIRECT:` banner, so the stage reports `unavailable` forever and darwin's collated-catalog
// round trip silently never runs — which is what wiring darwin was meant to fix.
//
// `-E` is load-bearing, per `run-batch-v2.mjs:198`: the driver reads `SUDO_USER` to drop every
// measured process back to the invoking user (R7), and needs the ambient PATH to find npm, which a
// bare `sudo` strips.
const DRIVER_FOR_PLATFORM = {
  linux: { file: 'measure.sh', run: 'bash', pre: [] },
  darwin: { file: 'measure-macos.sh', run: 'sudo', pre: ['-E', 'bash'] },
};

function stageInstall() {
  const s = stage('install');
  const driver = DRIVER_FOR_PLATFORM[process.platform];
  if (!driver) {
    return done(s, 'unavailable', `no direct-mode driver is wired for ${process.platform} — `
      + '`measure-windows.mjs` has no `--at-catalog`. Not skipped quietly: the stage is MISSING here, '
      + 'so nothing has checked that the collated catalog actually installs on this platform.');
  }
  let cat = summary.catalog.file;
  if (INSTALL_GRANT) {
    // ⛔ A NEGATIVE CONTROL, LABELLED AS ONE EVERYWHERE IT APPEARS. Its result is not a verdict about
    // the package; it is a verdict about whether this stage can fail at all. A run that only ever
    // reports success has not been shown able to detect a failure.
    let g;
    try { g = JSON.parse(INSTALL_GRANT); } catch (e) { return done(s, 'fail', `--install-grant is not JSON: ${e.message}`); }
    // nub rejects an entry that widens nothing and falls back to the compiled-in catalog, which
    // reads as VOID rather than as a refused install — so an empty control would prove nothing.
    if (!Object.keys(g).length) {
      return done(s, 'fail', '--install-grant {} widens nothing, so nub REJECTS the entry and falls '
        + 'back to the compiled-in catalog; the arm would be VOID, not insufficient. Use a '
        + 'non-empty grant that is narrower than the measured one.');
    }
    const doc = JSON.parse(fs.readFileSync(summary.catalog.file, 'utf8'));
    doc.packages[PKG] = { default: { ...g, notes: 'NEGATIVE CONTROL injected by e2e.mjs --install-grant' } };
    cat = path.join(WORK, 'catalog-control.json');
    fs.writeFileSync(cat, `${JSON.stringify(doc, null, 2)}\n`);
    summary.install = { negativeControl: g };
  }
  const args = [...(driver.pre ?? []), path.join(HERE, driver.file), PKG, VER, NUB, '--at-catalog', cat];
  const r = sh(driver.run, args);
  const log = path.join(WORK, 'install.out');
  const text = `$ ${driver.run} ${args.join(' ')}\n\n${r.stdout ?? ''}${r.stderr ?? ''}`;
  fs.writeFileSync(log, text);
  s.log = log;
  const m = /^### .*\((.+)\)\s*$/m.exec(text);
  if (m) roots.push(m[1]);
  const terminal = (text.match(/^\s*=>.*$/m) ?? [''])[0].trim();
  // ⛔ THE MODE MUST PROVE IT ENGAGED, BEFORE ANY EXIT CODE IS INTERPRETED. Both direct-mode drivers
  // announce themselves with `── DIRECT:` before running the arm; a driver that ACCEPTED `--at-catalog`
  // and ignored it prints no such line and then exits 0 off the ordinary ladder — which this stage
  // would otherwise read as "the grant installs". That is not hypothetical: a driver commit landed
  // carrying the flag's parser and no dispatch, and the failure mode was every arm running the same
  // catalog with every narrowing "verified" — an empty grant published as a measured minimum.
  //
  // Checking the BANNER rather than the flag is the whole point: a parser can satisfy a search for
  // the flag name, and cannot satisfy this.
  const engaged = /^\s*──\s*DIRECT:/m.test(text);
  summary.install = { ...(summary.install ?? {}), catalog: cat, rc: r.status, terminal, engaged };
  if (!engaged) {
    return done(s, 'unavailable', `${driver.file} printed no \`── DIRECT:\` banner, so --at-catalog did `
      + `NOT engage (it exited ${r.status}). The flag was accepted and ignored, or this driver's direct `
      + 'mode is absent — either way NOTHING about the collated catalog was checked, and this is not '
      + 'an install failure. Read the log before believing any exit code from it.', log);
  }
  // measure.sh's DIRECT vocabulary: 0 SUFFICIENT, 1 INSUFFICIENT, 3 VOID. VOID is neither — the
  // override did not engage, so nothing was measured and it must not be read as a refusal.
  if (r.status === 3) {
    return done(s, 'void', 'the catalog override did NOT engage — nothing was measured. This is not '
      + `an install failure, and it must not be read as one. ${terminal}`, log);
  }
  // ⛔ THE CONTROL'S PASS/FAIL IS INVERTED AND ITS WORDING MUST SAY SO. A control that FAILS is the
  // intended outcome and says this stage can detect an under-grant; a control that SUCCEEDS is the
  // alarming one — it means the stage would report green on a grant that does not install, which is
  // the entire failure this tool was built to catch. Naming the failing grant as "the grant the
  // pipeline produced" here would be a lie: the pipeline's grant is in the catalog line above.
  if (INSTALL_GRANT) {
    if (r.status === 1) {
      return done(s, 'control-failed-as-intended', 'the forced too-narrow grant did NOT install — '
        + `this stage can detect an under-grant. ${terminal}`, log);
    }
    if (r.status === 0) {
      return done(s, 'fail', '⛔ THE CONTROL PASSED. A grant chosen to be insufficient still '
        + 'installed, so this stage cannot currently falsify a grant and its green results mean '
        + `nothing. ${terminal}`, log);
    }
  }
  if (r.status === 0) return done(s, 'ok', `real \`nub install\` SUCCEEDED under this catalog — ${terminal}`, log);
  if (r.status === 1) {
    return done(s, 'fail', 'real `nub install` FAILED under this catalog — the grant the pipeline '
      + `produced does not install the package. ${terminal}`, log);
  }
  return done(s, 'fail', `measure.sh --at-catalog exited ${r.status}: ${terminal || '(no => line)'}`, log);
}

// ── render ────────────────────────────────────────────────────────────────────
const ICON = {
  ok: '✓', fail: '⛔', void: '⛔', skip: '·', unavailable: '·', running: '…',
  // A control that failed did its job, so it is not marked as a defect — but the run still exits
  // non-zero, because "the install failed" is what happened and a caller must not read it as green.
  'control-failed-as-intended': '✓',
};

function render() {
  if (JSON_OUT) { process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`); return; }
  const L = [];
  const b = summary.binary;
  const control = stages.some((s) => s.status === 'control-failed-as-intended');
  // Three outcomes, not two. "PIPELINE OK, PRODUCT UNCHECKED" is the honest name for a run whose
  // install stage could not execute: neither a pass to quote nor a failure to debug.
  //
  // Keyed on the EXIT CODE rather than on the stage's status, because `skip` is overloaded — DIRECT
  // mode also marks the install stage `skip`, and there the real install genuinely ran and IS the
  // verdict. Only the paths that chose 4 are unchecked.
  const unchecked = summary.exitCode === 4;
  const banner = control ? 'CONTROL REFUSED AS INTENDED'
    : unchecked ? '⛔ PIPELINE OK, PRODUCT UNCHECKED'
      : summary.ok ? 'OK' : 'FAILED';
  L.push(`═══ e2e  ${PKG}@${VER}  ${PLATFORM}  ${banner} ═══`);
  if (b) {
    L.push(`binary    ${b.path}`);
    L.push(`          ${b.version || '(no --version)'}  sha256:${(b.sha256 ?? '').slice(0, 16)}  `
      + `${b.size} B  mtime ${b.mtime}`);
    L.push(`          honours NUB_BUILD_JAIL_CATALOG: ${b.honoursOverride ? 'YES (banner seen)' : '⛔ NO'}`
      + `${b.driverAgrees === false ? '   ⛔ the driver measured a DIFFERENT binary'
        : b.driverAgrees ? '   driver measured the same bytes' : ''}`
      + `${b.changedDuringRun ? '   ⛔ THE BINARY CHANGED DURING THIS RUN — two programs were measured'
        : b.sha256After ? '   unchanged end-to-end' : ''}`);
  }
  const rec = summary.record;
  if (rec) {
    L.push(`measure   ${summary.direct ? 'DIRECT' : rec.verdict}   `
      + `driver=${rec.provenance?.harness} rc=${rec.driverRc}  via run-batch-v2.mjs`);
    if (summary.direct) {
      // The whole minimum-search block below is about a search DIRECT mode did not run, so printing
      // it would offer a grant nothing measured. One line, plus why the record's verdict is wrong.
      L.push(`  at grant     ${summary.direct.grant}`);
      L.push(`  → ${summary.direct.terminal}`);
      L.push(`  record says  ${rec.verdict} — an artifact, not a failure: record.mjs models no DIRECT`);
      L.push('               vocabulary, which is why this record is never published');
    } else {
      L.push(`  synthesized  ${j(rec.synthesized ?? undefined)}`);
      L.push(`  descended    ${rec.descendedGrant ? j(rec.descendedGrant) : '(the grant-source rule did not run)'}`
        + `${rec.overPredictedBy?.length ? `   dropped: ${rec.overPredictedBy.join(', ')}`
          : '   (nothing was droppable, so it equals the synthesized grant)'}`);
      L.push(`  → grant      ${j(rec.grant ?? undefined)}   source=${rec.grantSource ?? '(rule did not run)'}`);
      if (rec.grantSourceReason) L.push(`     why       ${rec.grantSourceReason}`);
      L.push(`  minimality   ${rec.minimality ?? '(none)'}`);
      L.push(`  verifiedBy   ${rec.verifiedBy ?? '(none)'}`);
      L.push(`  notes        ${rec.notes?.length ? rec.notes.join(', ') : '(none)'}`);
    }
    L.push(`  venue        ${rec.provenance?.venue} ci=${rec.provenance?.ciEnvSet} `
      + `store=${rec.provenance?.storeLayout} observeUser=${rec.provenance?.observeUser}`);
    L.push(`  record       ${rec.dir}`);
  }
  if (summary.catalog) {
    const e = summary.catalog.entry;
    L.push(`catalog   ${summary.catalog.absent ? 'NO ENTRY (needs nothing — absence is the grant)'
      : JSON.stringify(stripNotes(e))}`);
    L.push(`          ${summary.catalog.file}`);
    if (summary.catalog.source === 'collate.mjs') {
      L.push('          this package only — a dependency with its own shipped entry runs at the base');
      L.push('          profile here, which can fail an install the real catalog would pass');
    }
  }
  if (summary.install) {
    if (summary.install.negativeControl) {
      L.push(`install   ⛔ NEGATIVE CONTROL: forced grant ${JSON.stringify(summary.install.negativeControl)} `
        + '— not a verdict about this package');
    }
    L.push(`install   rc=${summary.install.rc}  ${summary.install.terminal}`);
  }
  L.push('');
  for (const s of stages) {
    L.push(`${ICON[s.status] ?? '?'} ${s.name.padEnd(9)} ${s.status.padEnd(12)} ${secs(s.ms).padStart(8)}  ${s.why ?? ''}`);
    if (s.log && s.status !== 'ok') L.push(`             log: ${s.log}`);
  }
  const ctl = stages.find((s) => s.status === 'control-failed-as-intended');
  if (ctl) {
    L.push('');
    L.push('⛔ NEGATIVE CONTROL, NOT A VERDICT — the install stage was fed a grant chosen to be too');
    L.push('   narrow and refused it. That is the intended outcome: it shows this stage can FAIL,');
    L.push('   which is what makes its green results worth anything. Exit is non-zero regardless.');
  }
  const bad = stages.find((s) => s.status === 'fail' || s.status === 'void');
  if (bad) {
    L.push('');
    L.push(`⛔ FAILED AT STAGE: ${bad.name}`);
    L.push(`   ${bad.why}`);
    if (bad.log) L.push(`   log: ${bad.log}`);
  }
  if (summary.retained) {
    L.push(`\nkept${KEEP ? '' : ' (a failed run is never swept)'}: ${WORK}`
      + `${roots.length ? `\n      fixtures: ${roots.join('  ')}` : ''}`);
  } else L.push(`\nswept ${roots.length} fixture root(s) and ${WORK}; --keep to retain them`);
  if (summary.falsify === 'skipped') {
    L.push("falsification pre-flight SKIPPED (--falsify to run the batch runner's six-arm control; "
      + '--install-grant is the per-package equivalent)');
  } else if (summary.falsify === 'run') L.push('falsification pre-flight RAN and passed');
  if (!PUBLISH) L.push('record NOT published (--publish to write it to the corpus)');
  process.stdout.write(`${L.join('\n')}\n`);
}

// ── drive ─────────────────────────────────────────────────────────────────────
if (stageBinary().status !== 'ok') finish(1);
if (stageMeasure().status !== 'ok') finish(1);

// ⛔ `--at-grant` ANSWERS A DIFFERENT QUESTION AND THE REMAINING STAGES DO NOT APPLY TO IT. It runs
// one arm at a stated grant and reports SUFFICIENT / INSUFFICIENT; `collate.mjs` only ever emits an
// entry from a `MINIMUM` record, so there is nothing to collate and an install stage would be
// checking a catalog with no entry for this package. Named as inapplicable rather than skipped.
if (AT_GRANT) {
  done(stage('catalog'), 'skip', 'DIRECT mode produces no MINIMUM record, so there is nothing to collate');
  done(stage('install'), 'skip', 'DIRECT mode already ran the real install — that IS its verdict');
  finish(0);
}
if (summary.record.verdict !== 'MINIMUM') {
  // A real verdict, just not one that collates: NO-STATE-PASSED, BROKEN-*, ARTIFACT-GATE-SUSPECT.
  done(stage('catalog'), 'skip', `verdict ${summary.record.verdict} — collate.mjs emits entries from MINIMUM records only`);
  done(stage('install'), 'skip', `verdict ${summary.record.verdict} — no grant to install under`);
  finish(1);
}
if (stageCatalog().status !== 'ok') finish(1);
if (SKIP_INSTALL) {
  // Also 4, not 0. The exit code describes WHAT HAPPENED, not whether the caller consented to it:
  // "you asked me to skip the product check" and "this platform cannot run it" leave the caller in
  // exactly the same position — holding a result that attests to the pipeline and nothing else.
  done(stage('install'), 'skip', '--skip-install');
  finish(4);
}
const inst = stageInstall();
// `unavailable` is NOT success — see the exit-code table in the header. It means the one stage that
// checks the PRODUCT never ran, so it gets its own code rather than borrowing the one that means
// "the grant installs".
exitCode = inst.status === 'ok' ? 0 : inst.status === 'unavailable' ? 4 : 1;
finish(exitCode);

