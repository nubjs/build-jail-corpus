// What do the jail-BLAMING records actually die of?
//
// ⛔⛔ THE POPULATION AND WHY IT DECIDES THE SHIP. 209 records carry a verdict that says the jail is the
// difference — `UNDER-PREDICTED` (97, darwin) and `NO-STATE-PASSED` (112, linux+win). Those verdicts mean
// "no state the harness can express installed this package", i.e. every rung up to `write:"disk"` plus
// network failed. If they are real, the jail breaks 209 packages and default-on is not shippable as is.
// If they are something else, the ship argument is intact. Nothing in the records answers it: 136 of the
// 138 rc-invariant ones carry NO installer error anywhere, because they predate
// `a46d96bbf harness: make a failing arm say WHY it failed, on all three drivers`.
//
// ⛔ THIS IS NOT THE FULL DRIVER, DELIBERATELY. The macOS driver needs dtrace (uid 0) for its OBSERVE
// pass, which cannot run unattended here — and OBSERVE is not what the question needs. The question is
// "does it install when NOTHING is withheld, and if not, what does the installer say?" That needs one
// install at the widest grant, which needs no tracer and no privilege.
//
// ⛔ THE GRANT IS DELIVERED THROUGH THE SHIPPED CATALOG-UPDATE READER, not a patched binary. A catalog
// naming the package with `read/write: "disk"` and `network: true` is placed under XDG_DATA_HOME, and the
// reader's own banner is checked PER ROW — without that check a row that silently fell back to the
// compiled catalog is indistinguishable from a row where the widest grant genuinely failed. That exact
// mistake happened while measuring electron: the stamp went to the top level instead of under
// `provenance`, so three rows reported the compiled grant while claiming to be overrides.
//
// Usage: node widest-grant-probe.mjs --nub <path> --list <file.json> [--out <tsv>] [--limit N]
//   --list is [{plat,pkg,ver,verdict}, …]; rows whose plat is not this platform are skipped.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i === -1 ? dflt : args[i + 1];
};
const NUB = opt('--nub');
const LIST = opt('--list');
const OUT = opt('--out', '/tmp/widest-grant-probe.tsv');
const LIMIT = Number(opt('--limit', '0'));
const CATALOG = opt(
  '--catalog',
  path.join(os.homedir(), '.cache/nub/worktrees/integ/crates/nub-sandbox/data/build-jail-catalog-v2.json'),
);
if (!NUB || !LIST) {
  console.error('usage: widest-grant-probe.mjs --nub <path> --list <file.json> [--out <tsv>] [--limit N]');
  process.exit(2);
}

const PLAT = process.platform === 'darwin' ? 'darwin-arm64' : process.platform === 'win32' ? 'win32-x64' : 'linux-x64';
let rows = JSON.parse(fs.readFileSync(LIST, 'utf8')).filter((r) => r.plat === PLAT);
// ⛔⛔ A `+` IN A PACKAGE NAME MEANS THE WORKLIST WAS BUILT FROM DIRECTORY NAMES, AND EVERY SUCH ROW IS A
// LIE. A record for a scoped package lives at `<plat>/@scope+name/<ver>/`, because `/` cannot be a path
// component — so reading the name off the directory yields `@pulumi+gcp`, which does not exist on the
// registry. The first run of this probe did exactly that: 45 rows carried a `+`, ALL 45 "failed at the
// widest grant", and the perfect correlation is the tell. The record's own `pkg` field is the name.
// Refusing outright rather than warning, because a run that reports 45 false failures is worse than none.
const mangled = rows.filter((r) => r.pkg.includes('+'));
if (mangled.length > 0) {
  console.error(
    `refusing: ${mangled.length} rows have '+' in the package name (e.g. ${mangled[0].pkg}), which means the ` +
      `worklist was built from directory names rather than each record's own pkg field`,
  );
  process.exit(2);
}
if (LIMIT > 0) rows = rows.slice(0, LIMIT);
console.log(`widest-grant-probe: ${PLAT}, ${rows.length} rows`);

const baseCatalog = JSON.parse(fs.readFileSync(CATALOG, 'utf8'));

// The installer's OWN first error line. Ordered most-specific first: a gyp/compiler line beats the
// `npm error` wrapper that quotes it, and the wrapper beats a bare non-zero exit. A generic matcher would
// return `gyp ERR! not ok`, which is the outer shell of every native failure and says nothing.
const ERROR_PATTERNS = [
  /^.*\b(?:fatal error|error):\s+'?[^']*\.h'? file not found.*$/im,
  /^.*\bimplicit declaration of function\b.*$/im,
  /^.*\btoo many errors emitted\b.*$/im,
  /^.*\b(?:sh|bash|cmd):\s*\S+:\s*(?:command not found|not found)\b.*$/im,
  /^.*\bcommand not found\b.*$/im,
  /^.*\b(?:ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|ECONNRESET)\b.*$/im,
  /^.*\b(?:EACCES|EPERM|operation not permitted|permission denied)\b.*$/im,
  /^.*\bunsupported (?:platform|engine)\b.*$/im,
  /^.*\bnode-pre-gyp\b.*\b(?:404|403|failed)\b.*$/im,
  /^.*`make`\s+failed with exit code.*$/im,
  /^.*\bnpm error\b(?!\s*$).*$/im,
];
const firstError = (log) => {
  for (const re of ERROR_PATTERNS) {
    const m = log.match(re);
    if (m) return m[0].trim().slice(0, 240);
  }
  return '';
};

const mktemp = (tag) => fs.mkdtempSync(path.join(os.homedir(), `wgp-${tag}-`));

function probe(pkg, ver) {
  const xdg = mktemp('x');
  const home = mktemp('h');
  const fx = mktemp('f');
  try {
    // The widest grant the vocabulary can express, for THIS package only. Everything else keeps whatever
    // the shipped catalog says, so a row cannot pass because some dependency was widened too.
    const cat = JSON.parse(JSON.stringify(baseCatalog));
    // ⛔ NO `read` KEY. `write: "disk"` ALREADY GRANTS EVERY READ, and naming both is a validation ERROR:
    // "`write: \"disk\"` already grants every read; remove `read`". The first version of this set both, so
    // the reader refused the whole catalog and every row measured the compiled grant — caught only by the
    // per-row banner control, which is the entire reason that control exists. The 35 whole-disk entries in
    // the shipped catalog are all spelled `{write: "disk", network: true}`, which I had printed and not read.
    cat.packages[pkg] = { default: { write: 'disk', network: true, notes: 'widest-grant probe' } };
    (cat.provenance ??= {}).generatedAt = '2099-01-01T00:00:00Z';
    fs.mkdirSync(path.join(xdg, 'nub/catalog'), { recursive: true });
    fs.writeFileSync(path.join(xdg, 'nub/catalog/build-jail-catalog-v2.json'), JSON.stringify(cat));

    fs.writeFileSync(
      path.join(fx, 'package.json'),
      JSON.stringify({ name: 'wgp', version: '1.0.0', dependencies: { [pkg]: ver }, allowBuilds: { [pkg]: true } }),
    );
    fs.writeFileSync(path.join(fx, '.npmrc'), 'side-effects-cache=false\n');

    // ⛔ spawnSync, NOT execFileSync, and the difference voided every row of the first control run.
    // execFileSync RETURNS stdout only; on success stderr is discarded even with `stdio: 'pipe'`. The
    // reader's catalog banner goes to stderr, so every rc=0 row reported `VOID-override-not-loaded` —
    // the instrument declaring itself broken when it was merely deaf. spawnSync hands back both streams
    // for success and failure alike.
    const run = spawnSync(NUB, ['install'], {
      cwd: fx,
      encoding: 'utf8',
      timeout: 300_000,
      env: { ...process.env, XDG_DATA_HOME: xdg, HOME: home, NUB_CACHE_DIR: path.join(home, 'nc') },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const rc = run.status ?? -1;
    const log = `${run.stdout ?? ''}\n${run.stderr ?? ''}`;
    // ⛔ THE PER-ROW INSTRUMENT CONTROL. No banner means the override was not in force and this row
    // measured the COMPILED grant, so it says nothing about the widest one.
    const loaded = /build-jail catalog updated from/.test(log);
    return { rc, loaded, error: firstError(log), bytes: log.length };
  } finally {
    for (const d of [xdg, home, fx]) fs.rmSync(d, { recursive: true, force: true });
  }
}

const out = [];
let installs = 0;
let stillFails = 0;
let void_ = 0;
for (const [i, r] of rows.entries()) {
  const res = probe(r.pkg, r.ver);
  let verdict;
  if (!res.loaded) {
    verdict = 'VOID-override-not-loaded';
    void_ += 1;
  } else if (res.rc === 0) {
    verdict = 'INSTALLS-AT-WIDEST';
    installs += 1;
  } else {
    verdict = 'FAILS-AT-WIDEST';
    stillFails += 1;
  }
  // ⛔ AN ERROR ON A ROW THAT EXITED 0 IS A RECOVERED ONE, AND SAYING SO MATTERS. lzma-native logs a
  // node-pre-gyp 404 for its prebuilt and then installs anyway from source — the Goal's own caveat that an
  // exit code cannot judge a narrowing because a package may fall back to a source build. Printing that
  // line unlabelled next to a FAILS row invites a reader to treat it as a cause.
  const err = res.error ? `${res.rc === 0 ? 'recovered: ' : ''}${res.error}` : '(no installer error found)';
  const line = [r.pkg, r.ver, r.verdict, verdict, `rc=${res.rc}`, err].join('\t');
  out.push(line);
  fs.writeFileSync(OUT, `${out.join('\n')}\n`);
  if ((i + 1) % 10 === 0) console.log(`  ${i + 1}/${rows.length} …`);
}
console.log(`installs-at-widest=${installs}  fails-at-widest=${stillFails}  void=${void_}`);
console.log(`rows -> ${OUT}`);
