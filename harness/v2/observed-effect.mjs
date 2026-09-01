// Did the lifecycle script DO ANYTHING in this venue, or did the run measure the venue instead of
// the package?
//
// ⛔⛔ THIS IS THE TERM THAT SEPARATES "NEEDS NOTHING" FROM "DID NOTHING", AND EVERY OTHER DETECTOR IN
// THIS HARNESS RETURNS THE SAME ANSWER FOR BOTH.
//
// A grant of `{}` is produced by two states that no arm can tell apart:
//
//   (a) the script ran, did its work, and that work needed no capability the base profile withholds.
//       `{}` is a MEASUREMENT and narrowing to it is correct.
//   (b) the script ran and did NOTHING — a precondition it silently depends on was absent on this
//       runner. `{}` is a measurement OF THE RUNNER, and narrowing to it is an under-grant.
//
// In state (b) every signal this harness owns reads green, by construction:
//
//   the artifact gate     vacuous — the package ships its output prebuilt, so it passes in an arm
//                         where nothing ran (`arm-falsifiability.mjs`).
//   the exit code         0 — and `arm-falsifiability.mjs`'s `rc-vacuous` cannot see why, because it
//                         matches a SHELL-level trailing swallow and this swallow is in the PAYLOAD.
//   the descent           ZERO arms. `descent-terms.mjs` yields no term for `{}`, so `minimality`
//                         comes back `MINIMAL` "by construction" and `descentRedArm` is false.
//   the denial witness    CLEAN. `denial-witness.mjs` asks whether the script ATTEMPTED a refused
//                         access inside the dropped scope; a script that attempted nothing attempted
//                         no refused thing. ⛔ THIS IS THE TRAP THIS FILE EXISTS FOR: a witness
//                         scored on the VERIFY arm of a `{}` record returns CLEAN for state (b) as
//                         reliably as for state (a), so wiring it as a licence publishes (b).
//
// MEASURED on the 2026-09-01 win32-x64 re-measure of 30 whole-home packages. Twelve records collapsed
// to `{}` and are withheld; TEN of those twelve are state (b), and the mechanism is in the payload:
//
//   @pulumi/{azuread,cloudflare,datadog,docker,docker-build,gcp,kubernetes,postgresql,tls}
//       `scripts/install-pulumi-plugin.js` is `spawnSync("pulumi", ["plugin","install",…])` followed
//       by an UNCONDITIONAL `process.exit(0)`. With no `pulumi` on the runner the spawn ENOENTs, the
//       script prints a sentence and exits 0 having written nothing and opened no socket. On a
//       machine that HAS the CLI the same script downloads into `~/.pulumi/plugins/` over the
//       network — `write.userHome` + `network`, which is exactly the grant these records would drop.
//       The corpus already holds the other half of that pair: the committed linux
//       `@pulumi/gcp@0.16.9` record, whose install script is the same shape, is cited in
//       `record.mjs` as downloading `~/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp`.
//       Same package family, same script, opposite measurement, decided by an unrelated binary's
//       presence on PATH.
//   backport@12.0.4
//       `test -f ./dist/… && node ./dist/… || echo 'Dist folder missing'` — rc 0 unconditionally,
//       and `arm-falsifiability.mjs`'s `SWALLOWS` alternation is `true|:|exit 0`, so `echo` is not
//       matched and the record claims a live exit code it does not have.
//
// All ten record `== WRITES ==` with no bucket beneath it: zero writes attributed to the lifecycle
// subtree in the UNJAILED observe run, base-covered buckets included.
//
// ⛔ THE OTHER TWO OF THE TWELVE ARE STATE (a) AND THIS FILE MUST NOT TOUCH THEM.
// `@azure-devops/mcp@2.8.0` (`npmCache 1 jailHome 1 jailTmp 2`, from `preinstall: npm config set
// registry …`) and `@depot/cli@0.0.1-cli.2.99.1` (`jailHome 2`) both did real work whose writes
// landed inside a base-granted root, because `compile_build_jail` redirects HOME/USERPROFILE/APPDATA
// at a per-package private home. Their `{}` is a real measurement. A detector that refused them too
// would be the blanket refusal `measure.sh`'s attribution branch already learned not to be: of 134
// linux attribution failures, 97 were correct MINIMUMs and refusing all of them to fix ~37 was the
// wrong trade.
//
// ⛔ ADDS A REFUSAL, NEVER A LICENCE. `NONE` can only move a record from publish to WITHHELD;
// no verdict this file returns can license a narrowing that was not already licensed. That is what
// keeps it on the safe side of the guard's asymmetry — the falsifiability rule is not relaxed by a
// term that can only ever say "no".

import fs from 'node:fs';
import path from 'node:path';

// The npm lifecycle scripts an install ACTUALLY runs. `prepare` is deliberately absent: the OBSERVE
// arm is `npm rebuild`, which runs preinstall/install/postinstall and not prepare, so counting it
// would call a run "should have done work" over a script the arm never executes. Same list, same
// reason, as the DECLARES probe in `measure.sh`'s attribution branch.
export const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'];

// ⛔ THE INSTALLED TREE, NEVER `npm view`. The registry's `versions[v].scripts` is the DEVELOPMENT
// manifest captured at publish time; the tarball carries whatever `npm pack` produced, and
// publishing pipelines routinely strip an install script before packing. Only the tarball's copy can
// execute. `declares-reads-the-installed-tree.test.mjs` pins the drivers to that rule for the
// neighbouring attribution probe and the reason does not change here.
//
// ⛔ `binding.gyp` COUNTS. npm runs `node-gyp rebuild` for a package that ships one even with NO
// explicit install script, so the native builds — the packages whose grants matter most — would
// otherwise be scored as "runs nothing" and exempted from the very check they most need.
export const declaresInstallWork = (pkgRoot) => {
  if (typeof pkgRoot !== 'string' || pkgRoot === '') return null;
  let scripts = {};
  try {
    scripts = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8')).scripts ?? {};
  } catch { return null; }        // unreadable manifest — unknown, never "declares nothing"
  const named = INSTALL_SCRIPTS.filter((k) => typeof scripts[k] === 'string' && scripts[k].trim() !== '');
  const gyp = fs.existsSync(path.join(pkgRoot, 'binding.gyp'));
  return { scripts: named, gyp, declares: named.length > 0 || gyp };
};

// ⛔⛔ WHAT COUNTS AS EFFECT, AND THE ONE SIGNAL DELIBERATELY EXCLUDED.
//
//   writes   every bucket, base-covered ones INCLUDED. A write into `jailHome` is the script doing
//            its work; that the jail happens to grant that root for free is a fact about the grant,
//            not about whether anything happened. Excluding base-covered buckets would score
//            `@azure-devops/mcp@2.8.0` — which really did write its `.npmrc` — as having done
//            nothing, and refuse a correct narrowing.
//   peers    a network peer the script reached. Distinct-peer count, matching what each classifier
//            already prints.
//
//   execs    ⛔ NOT COUNTED, AND THIS IS THE LOAD-BEARING EXCLUSION. A `spawnSync` that ENOENTs IS an
//            attempted exec, so counting execs scores `@pulumi/*` as WORK — the exact ten records
//            this term exists to catch, waved through by the signal that most looks like activity.
//            An exec that produced no write and no packet produced no effect a grant can describe.
//   reads    NOT COUNTED, for the mirror reason: a read earns no write scope, so a run that only
//            read has still not exercised anything a `write.*` grant is about.

// ⛔⛔ THE WRITES THE INSTRUMENT ITSELF CAUSES, WHICH ARE NOT THE SCRIPT DOING ANYTHING.
//
// "Every bucket, base-covered ones INCLUDED" is right about the JAIL granting a root for free. It is
// wrong about a path that exists only because tracing is switched on: that write is not evidence the
// package did work, it is evidence the tracer attached. Counting it means the census answers "was
// this run traced?", and the answer is always yes.
//
// MEASURED over all 6,887 committed records. `/dev/dtracehelper` — the DTrace helper device
// `libdtrace` opens in every process running under the macOS driver — appears in 1,383 of the 1,912
// darwin records and in ZERO linux or win32 records. In 424 of them it is the ONLY write in the run,
// so the census reads 1 and `observedEffect` returns WORK for a script that did nothing at all. Every
// one of those 424 is a record this term exists to catch and would have waved through, on darwin,
// silently. `records-v2/runs/darwin-arm64/@pulumi+gcp/6.9.0` is one of them and is COMMITTED as
// `MINIMUM {}`.
//
// ⛔ IT IS A LIST, NOT A REGEX, AND IT STAYS SHORT. Each entry has to be a path the instrument opens
// in EVERY traced process on its platform — provable by counting it across the corpus — never merely
// a write that looks uninteresting. Two near misses that are deliberately NOT here, both measured:
// `/dev/null` is the sole write in 42 records and is the SCRIPT redirecting output, and the win32
// `…dll:wofcompresseddata` alternate data streams are the sole write in 4 and are the OS
// decompressing a system DLL for the interpreter. Neither is caused by tracing, so excluding either
// would start scoring real behaviour as no-effect — the direction that suppresses a true grant.
export const INSTRUMENT_OWNED_WRITES = [
  '/dev/dtracehelper',
];

export const isInstrumentOwnedWrite = (p) => typeof p === 'string' && INSTRUMENT_OWNED_WRITES.includes(p);

// The census the three classifiers feed to `marker()`. Takes the same `{scope: [path, …]}` bucket map
// each of them already prints, so the number in the marker and the numbers in `== WRITES ==` are
// derived from one object rather than counted twice in three files.
export const effectWrites = (buckets) => {
  if (!buckets || typeof buckets !== 'object') return 0;
  let n = 0;
  for (const paths of Object.values(buckets)) {
    if (!Array.isArray(paths)) continue;
    for (const p of paths) if (!isInstrumentOwnedWrite(p)) n++;
  }
  return n;
};

export const observedEffect = ({
  lifecyclePids = null, writes = null, peers = null, declares = null,
} = {}) => {
  // ⛔ ZERO PIDS IS SOMEONE ELSE'S FINDING. The drivers already resolve it — `observe.mjs` emits
  // `UNKNOWN-ATTRIBUTION-FAILED` and the driver asks the manifest — and a second, differently-worded
  // verdict for the same state is how two rules come to disagree about one record.
  if (lifecyclePids === 0) {
    return { verdict: 'UNATTRIBUTED', writes, peers, declares,
      reason: 'no lifecycle process was attributed, which the attribution branch already adjudicates' };
  }
  if (!Number.isInteger(lifecyclePids) || !Number.isInteger(writes) || !Number.isInteger(peers)) {
    return { verdict: 'UNKNOWN', writes, peers, declares,
      reason: 'the classifier emitted no effect counts, so whether the script did anything is unknown' };
  }
  if (writes > 0 || peers > 0) {
    return { verdict: 'WORK', writes, peers, declares,
      reason: `the lifecycle subtree performed ${writes} write(s) and reached ${peers} peer(s), so the run exercised the script` };
  }
  // ⛔ A PACKAGE THAT RUNS NOTHING AT INSTALL IS NOT A FAILED MEASUREMENT. `npm rebuild` executes no
  // script for it, so zero effect is the honest answer and `{}` is real. Refusing it would be the
  // blanket refusal the attribution branch already reverted.
  if (declares === false) {
    return { verdict: 'NO-INSTALL-WORK', writes, peers, declares,
      reason: 'the installed tree declares no install-time script and ships no binding.gyp, so npm ran nothing and the empty effect is the answer' };
  }
  if (declares !== true) {
    return { verdict: 'UNKNOWN', writes, peers, declares,
      reason: 'the lifecycle subtree produced no write and no peer, but whether the package declares an install-time script could not be read, so this cannot be told from a package that runs nothing' };
  }
  return { verdict: 'NONE', writes, peers, declares,
    reason: 'the package DECLARES an install-time script, a lifecycle process WAS attributed, and the '
      + 'script produced no write and reached no peer — it ran and did nothing, so this run measured '
      + 'the venue rather than the package' };
};

// True when this verdict must veto a narrowing. Exported so `publish-guard.mjs` and any future
// consumer ask the same question of the same word rather than re-deriving it from the string.
export const vetoesNarrowing = (rec) => rec?.observedEffect?.verdict === 'NONE';

// One line, JSON payload, the same shape as every other marker `record.mjs` consumes. The classifier
// emits the counts half; `declares` is filled in from the `ARM-FALSIFIABILITY` payload, which is the
// only stage that already reads the installed tree on all three platforms.
export const marker = (counts) => `OBSERVED-EFFECT ${JSON.stringify({
  lifecyclePids: counts.lifecyclePids ?? null,
  writes: counts.writes ?? null,
  peers: counts.peers ?? null,
})}`;

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const argv = process.argv.slice(2);
  const one = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  const n = (f) => (one(f) === undefined ? null : Number(one(f)));
  const d = one('--pkg-root') ? declaresInstallWork(one('--pkg-root')) : null;
  const r = observedEffect({
    lifecyclePids: n('--lifecycle-pids'), writes: n('--writes'), peers: n('--peers'),
    declares: d ? d.declares : null,
  });
  console.log(marker({ lifecyclePids: n('--lifecycle-pids'), writes: n('--writes'), peers: n('--peers') }));
  console.log(`     ${r.verdict} — ${r.reason}`);
}
