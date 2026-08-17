// The JAIL-OFF CONTROL: does nub install this package when the jail is not in the way?
//
// It answers the one question that decides whether a ladder of failures is a JAIL finding at all. A
// package that fails at every rung looks identical to a package the jail blocks — until you run it
// unjailed and find it fails there too, at which point the whole ladder said nothing about
// capabilities. Measured on this stage's first live record: `@aws-amplify/cli@2.0.0` came back
// "nub cannot install it" while plain `npm install` failed too (gyp rejects Python 3.12), so the
// verdict was true about nub and still misleading.
//
// ⛔⛔ ONE COPY, THREE DRIVERS. This exists as a module because the control was Linux-only and the
// macOS and Windows drivers had no equivalent — so every ladder failure on those platforms was filed
// against the jail with nothing having asked whether the jail was the difference. Re-implementing it
// per driver would put the verdict vocabulary and the off-switch assertion in three places, which is
// the drift `driver-invocation.mjs` and `override-probe.mjs` were both written to stop.
//
// What stays with the CALLER, because it is genuinely per-platform and this module must not guess:
// the SPAWN STRATEGY (plain on Linux/Windows; `sudo -u $RUNUSER -H env PATH=$PATH` plus a pre-chown
// on macOS) and STORE INDEPENDENCE (eviction on POSIX, its own XDG_CACHE_HOME on Windows). Both are
// injected. Precedent: `driver-invocation.mjs` refuses to own capability, only invocation.
//
//   usage: node harness/v2/unjailed-nub.mjs --pkg <name> --version <v> --nub <path> --dir <dir>
//   exit 0 = nub installs it unjailed;  1 = it does not;  2 = the control itself is unsound
import fs from 'node:fs';
import path from 'node:path';

/// The clause nub prints when it declines to confine a script.
///
/// ⛔⛔ THIS IS THE OFF-SWITCH ASSERTION AND IT IS THE POINT OF THE MODULE. Do not take the flag's
/// word for it. An off-switch that silently stops working does not produce an error — it produces
/// UNANIMOUS AGREEMENT, which reads as a confident exoneration. That is not hypothetical: v1's
/// fixture set `dependenciesMeta.<pkg>.sandbox: false` for months after the commit that deleted
/// every path reading it, so every "jail off" cell ran JAILED and every failing package was filed as
/// NOT-THE-JAIL. Re-measuring the affected macOS records with a working switch flipped 2 of the
/// first 5 to real jail defects the broken control had buried.
///
/// Verified present in nub's source and in a live install's output, for BOTH gates that can
/// unconfine a script (the global `install.buildJail: false` and a per-package `allowBuilds`
/// opt-out) — the clause is shared and only the parenthetical reason differs, and a nub-side test
/// pins that. Asserting on a string that never appears would fail closed into blanket
/// HARNESS-ERROR, so this was grounded before it was written rather than after.
export const OFF_SWITCH_CLAIM = 'build scripts are running without the build sandbox';

/// Verdicts this control can produce. Held in one place so three drivers cannot spell them
/// differently — `record.mjs` matches these exactly.
export const VERDICT = {
  /// nub installs it unjailed, so the jail IS the difference. A real finding.
  noStatePassed: 'NO-STATE-PASSED',
  /// npm installs it, nub does not, jail OFF. A nub install defect — NOT a jail finding and NOT an
  /// under-grant. Do not widen the catalog for it.
  brokenUnjailedNub: 'BROKEN-UNJAILED-NUB',
  /// Nothing installs it unjailed. There is nothing to measure.
  brokenWithoutJailToo: 'BROKEN-WITHOUT-JAIL-TOO',
  /// The control itself is unsound, so it has no verdict to offer.
  ///
  /// ⛔ AN ERROR, DELIBERATELY NOT A WARNING. A warning scrolls past in a sweep of thousands, which
  /// is precisely how the broken v1 off-switch went unnoticed for months. `claim-slice.mjs` returns
  /// a HARNESS-* row to `pending` rather than closing it, so a re-run off a fixed harness answers
  /// the question — exactly the right disposition for "ask me again later".
  harnessError: 'HARNESS-ERROR',
  /// The control ran out of time. Distinct from failure: a timeout says nothing about whether nub
  /// can install the package, and calling it a failure would file a nub defect for a slow build.
  harnessTimeout: 'HARNESS-TIMEOUT',
};

/// The decision tree, as a pure function of the two arms' outcomes.
///
/// Separated from the IO so it can be tested without a nub binary, a registry, or a package that
/// takes four minutes to compile — the tree is where the reasoning lives, and it is what a driver
/// gets wrong. `nub` is this control's own arm; `npm` is consulted ONLY when nub failed.
///
/// ⛔ THE ORDER OF THESE CLAUSES IS THE CONTRACT. Soundness is checked BEFORE any verdict, because
/// an unsound control's rc is not evidence of anything: a cell whose off-switch never engaged ran
/// jailed, so its rc describes the jail rather than its absence.
export function classify({ nub, npm }) {
  if (nub.timedOut) {
    return { verdict: VERDICT.harnessTimeout, why: 'the jail-off control did not finish in time' };
  }
  if (nub.engaged === false) {
    return {
      verdict: VERDICT.harnessError,
      why: `the jail-off control ran with the jail still ENGAGED — no "${OFF_SWITCH_CLAIM}" in its logs`,
    };
  }
  if (nub.rc === 0) {
    return {
      verdict: VERDICT.noStatePassed,
      why: 'nub installs this package unjailed (rc=0), so the jail IS the difference',
    };
  }
  // nub failed with the jail off. That is not yet "nub is at fault" — ask npm before naming a
  // culprit, or the record asserts a nub defect for a package NOTHING installs and sends the next
  // reader chasing a bug that is not there.
  if (npm?.rc === 0) {
    return {
      verdict: VERDICT.brokenUnjailedNub,
      why: 'npm installs this package but nub cannot, even with the jail OFF — a nub install defect, not an under-grant',
    };
  }
  return {
    verdict: VERDICT.brokenWithoutJailToo,
    why: 'neither nub nor npm installs this unjailed; nothing to measure',
  };
}

/// What nub prints when there was no lifecycle script to approve at all.
///
/// ⛔ THE ASSERTION IS ONLY MEANINGFUL WHEN A SCRIPT COULD HAVE PRINTED THE CLAIM. nub announces the
/// decision not to confine at SPAWN time, so a package with no lifecycle script never prints it —
/// and treating that silence as "the off-switch is broken" turns every script-less cell into a
/// HARNESS-ERROR, a flood that hides the real ones. Grounded in a live run rather than guessed.
export const NO_SCRIPTS_CLAIM = 'No ignored builds to approve';

/// Did the off-switch engage? THREE states, and collapsing any pair of them causes a wrong verdict:
///   `true`  — the claim is present, so the control really ran unjailed
///   `false` — a script ran and the claim is ABSENT, which is the broken off-switch
///   `null`  — unknowable here, so the caller must fall through to the rc rather than erroring
///
/// `null` covers two genuinely different unknowns, and neither is disproof: no log to read (a
/// harness problem of its own), and no script in play (nothing was ever going to print it).
export function offSwitchEngaged(logs) {
  const text = Object.values(logs ?? {}).filter((v) => typeof v === 'string').join('\n');
  if (!text.trim()) return null;
  if (text.includes(OFF_SWITCH_CLAIM)) return true;
  // A tree with nothing to approve cannot testify either way.
  if (text.includes(NO_SCRIPTS_CLAIM)) return null;
  return false;
}

/// A unique root package name, so the fixture cannot replay a previous arm.
///
/// ⛔ NOT A FIXED NAME. nub memoises a lifecycle outcome keyed on package identity, so a reused root
/// name REPLAYS the earlier arm's result with every precondition still green. The Linux control used
/// a fixed `"nsp"` while `verify()` two hundred lines above it carefully computed a unique one — and
/// the direction of that error is the dangerous one: the control runs AFTER every verify arm has
/// materialised this closure into the machine-global store, so a relink returns rc=0 without running
/// the lifecycle script at all. That is a false control PASS, which files a jail finding against a
/// package the jail never touched.
export const uniqueRootName = (seed) => `nsp${String(seed).replace(/[^a-z0-9]/gi, '').toLowerCase()}`;

/// Write the jail-OFF fixture. Returns the directory.
///
/// Three replay guards, closing three different paths — dropping any one reopens its own:
///   unique root name      — nub memoises a lifecycle outcome keyed on package identity
///   side-effects-cache=no — the memo says "this script already ran, skip it"
///   store eviction        — the store says "this package is already materialised, relink it"
/// The third is the caller's, because POSIX and Windows achieve it differently.
export function writeFixture({ dir, pkg, version, seed, write = fs.writeFileSync, mkdir = fs.mkdirSync }) {
  mkdir(dir, { recursive: true });
  const name = uniqueRootName(seed ?? path.basename(dir));
  write(
    path.join(dir, 'package.json'),
    `${JSON.stringify({ name, version: '1.0.0', dependencies: { [pkg]: version } })}\n`,
  );
  // STATE THE SWITCH EXPLICITLY rather than inheriting a default — the whole cell is a claim about
  // this one setting, so reading it from ambient config would make the claim unfalsifiable.
  write(path.join(dir, 'nub.jsonc'), '{"install":{"buildJail":false}}\n');
  write(path.join(dir, '.npmrc'), 'side-effects-cache=false\n');
  return { dir, name };
}

/// Run the control: three nub invocations in order, capturing a log per step.
///
/// `run({ cmd, args, cwd })` must resolve `{ rc, out, timedOut }`. It is injected so the caller owns
/// the platform's spawn strategy and its timeout, and so the tests need no nub binary.
/// `screen` is the caller's security screen over the RESOLVED tree, injected for the same reason the
/// spawn strategy is: each driver already has one and they are not interchangeable. It runs after the
/// `--ignore-scripts` step and before anything executes, which is the only window where the tree is
/// materialised but no script has touched it — screening later would be screening the aftermath.
export async function unjailedNubOk({ nub, pkg, version, dir, seed, run, evictStore, screen }) {
  const { name } = writeFixture({ dir, pkg, version, seed });
  if (evictStore) await evictStore({ pkg, version, dir });

  const logs = {};
  // `--ignore-scripts` first: this resolves and materialises WITHOUT running anything, so a failure
  // here is a fetch/resolve problem and the screen below sees the tree before any script touched it.
  const steps = [
    { key: 'security-resolve.log', args: ['install', '--ignore-scripts'] },
    { key: 'i.log', args: ['install'] },
    { key: 'a.log', args: ['approve-builds', '--all'] },
  ];
  for (const step of steps) {
    const r = await run({ cmd: nub, args: step.args, cwd: dir });
    logs[step.key] = r.out ?? '';
    // ⛔ WHICH STEP FAILED DECIDES WHETHER THE OFF-SWITCH IS JUDGEABLE AT ALL, and it is not
    // symmetric. nub IGNORES build scripts pending approval, so neither the resolve step nor the
    // plain install spawns one for an unapproved package — nothing could have printed the claim, and
    // reporting `false` there would file HARNESS-ERROR for what is really a fetch or install failure
    // whose verdict the npm arm decides. `approve-builds` is different: that is the step that
    // actually runs the scripts, so if it failed WITHOUT the claim appearing, the off-switch really
    // did not engage and the whole cell is unsound.
    const judged = step.key === 'a.log' ? offSwitchEngaged({ i: logs['i.log'], a: logs['a.log'] }) : null;
    if (r.timedOut) return { rc: null, timedOut: true, engaged: judged, logs, name, step: step.key };
    if (r.rc !== 0) return { rc: r.rc, timedOut: false, engaged: judged, logs, name, step: step.key };
    // Screen the resolved tree in the one window where it is materialised and nothing has run yet.
    if (step.key === 'security-resolve.log' && screen) {
      await screen({ dir, label: 'nub-unjailed-resolved' });
    }
  }
  // ⛔ THE ASSERTION IS OVER THE STEPS THAT CAN RUN SCRIPTS, WHICH EXCLUDES THE RESOLVE STEP. nub
  // announces the decision not to confine ONCE PER PACKAGE, at spawn time. For an unapproved package
  // that is `approve-builds`; for a project whose manifest already approves it, the plain install.
  // Both are read, and `security-resolve.log` deliberately is not — it spawns nothing, so including
  // it would dilute the claim with a log that can never carry it.
  return {
    rc: 0,
    timedOut: false,
    engaged: offSwitchEngaged({ i: logs['i.log'], a: logs['a.log'] }),
    logs,
    name,
    step: null,
  };
}

/// Rewrite a command to run as another user, as EXPLICIT ARGV.
///
/// macOS measurement runs under `sudo`, and every arm it measures is re-dropped to the invoking user
/// with `sudo -u <user> -H env PATH=<path>` — `-H` sets HOME to that user's REAL home from the
/// directory service, which is what the traced installer must see. Without this the control would run
/// as root while every verify arm ran as the user, and a permission difference between the two would
/// read as a jail finding.
///
/// ⛔ ARGV, NOT A SHELL PREFIX STRING. A free-form prefix has to be re-split by somebody, and a path
/// with a space in it then becomes two arguments silently. Returning the vector leaves nothing to
/// re-parse. Pure, so the shape is testable without sudo or a second user account.
export function asIdentity({ cmd, args, user, path: pathValue }) {
  if (!user) return [cmd, args];
  return ['sudo', ['-u', user, '-H', 'env', `PATH=${pathValue ?? process.env.PATH ?? ''}`, cmd, ...args]];
}

/// The npm reference arm, consulted only when nub failed. Identical on all three platforms.
///
/// `npm install --ignore-scripts` then `npm rebuild` over the WHOLE tree: an ordinary `npm install`
/// runs dependency lifecycle scripts as well as the target's, so rebuilding only the target would
/// change the reference arm.
///
/// ⛔ A FRESH `npm install` IS A DIFFERENT QUESTION FROM `npm rebuild` ON A WARM TREE, and the
/// harness's older top-of-file control asked the second one. `npm rebuild <pkg>` on a tree where the
/// package is not installed is a NO-OP that exits 0 — a false success. That is why this arm installs
/// first, into its own directory.
export async function npmOk({ pkg, version, dir, run, mkdir = fs.mkdirSync, write = fs.writeFileSync }) {
  mkdir(dir, { recursive: true });
  write(path.join(dir, 'package.json'), '{"name":"nspnpm","version":"1.0.0"}\n');
  const fetch = await run({
    cmd: 'npm',
    args: ['install', '--no-audit', '--no-fund', '--ignore-scripts', `${pkg}@${version}`],
    cwd: dir,
  });
  if (fetch.timedOut) return { rc: null, timedOut: true, logs: { 'fetch.log': fetch.out ?? '' } };
  if (fetch.rc !== 0) return { rc: fetch.rc, timedOut: false, logs: { 'fetch.log': fetch.out ?? '' } };
  const rebuild = await run({ cmd: 'npm', args: ['rebuild', '--no-audit', '--no-fund'], cwd: dir });
  return {
    rc: rebuild.timedOut ? null : rebuild.rc,
    timedOut: !!rebuild.timedOut,
    logs: { 'fetch.log': fetch.out ?? '', 'n.log': rebuild.out ?? '' },
  };
}

/// The whole control: run nub unjailed, consult npm only if it failed, and classify.
export async function control({ nub, pkg, version, dir, run, evictStore, npmDir }) {
  const nubArm = await unjailedNubOk({ nub, pkg, version, dir: path.join(dir, 'nub-unjailed'), run, evictStore });
  // Soundness and rc=0 both settle it without npm — and NOT calling npm matters, because the arm
  // costs a full install of a package that may take minutes to compile.
  let npmArm;
  if (!nubArm.timedOut && nubArm.engaged !== false && nubArm.rc !== 0) {
    npmArm = await npmOk({ pkg, version, dir: npmDir ?? path.join(dir, 'npm-reference'), run });
  }
  return { ...classify({ nub: nubArm, npm: npmArm }), nub: nubArm, npm: npmArm };
}

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────────
//
// ⛔ `pathToFileURL(process.argv[1])`, GUARDED, AND NOT A STRING COMPARISON. A physical-vs-logical
// path mismatch makes this block silently not fire — the CLI prints nothing and exits 0, which a
// shell driver reads as success. macOS is where it bites first, because `/tmp` is a symlink to
// `/private/tmp`, so a fixture path resolves differently than it was spelled.
if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const arg = (k) => (argv.includes(k) ? argv[argv.indexOf(k) + 1] : undefined);
  const [pkg, version, nub, dir] = [arg('--pkg'), arg('--version'), arg('--nub'), arg('--dir')];
  // ⛔⛔ WHY A SHELL DRIVER GETS TWO PHASES INSTEAD OF THE `screen` HOOK. A JS caller injects `screen`
  // directly. A shell driver cannot: its screen is a sourced FUNCTION whose contract includes exiting
  // the whole driver — rc 42 means "malicious, the verdict line is already printed, stop now" and it
  // does that at exit 0, which is indistinguishable from success to any wrapper spawned as a child.
  // Reimplementing that in JS would put a malicious-package refusal behind a code path where a wrong
  // guess silently converts a refusal into an ordinary measurement, so the semantics stay in the
  // shell where they already work. `resolve` stops after the tree is materialised, the driver screens
  // it with its own function, then `run` continues in the same directory — state passes through the
  // directory and its logs, so there is nothing to serialise between the two.
  const phase = arg('--phase') ?? 'all';
  if (!['resolve', 'run', 'verdict', 'all'].includes(phase)) {
    console.error(`unknown --phase ${phase}; expected resolve, run, verdict or all`);
    process.exit(2);
  }
  // ⛔ REQUIRED ARGUMENTS ARE PER-PHASE, AND VALIDATING THEM UP FRONT BROKE THE `verdict` PHASE
  // SILENTLY. That phase is pure classification — it takes only npm's answer and needs no package,
  // binary or directory — so a blanket check rejected it with the usage line on STDERR and exit 2. The
  // driver captures stdout, so the cell simply carried NO verdict at all: green tests, empty log, and
  // nothing to indicate the stage had gone inert.
  if (phase !== 'verdict' && (!pkg || !version || !nub || !dir)) {
    console.error('usage: unjailed-nub.mjs [--phase resolve|run|all] --pkg <name> --version <v> --nub <path> --dir <dir>');
    console.error('       unjailed-nub.mjs --phase verdict --npm ok|fail');
    process.exit(2);
  }
  // Appended to the `=>` line after the shared verdict TOKEN. The token is what `record.mjs` matches,
  // so each driver can keep the context its own ladder earned — "even at write:disk" states that the
  // ladder climbed every rung, which is a Linux-ladder fact the other drivers have no business
  // asserting — without three copies of the vocabulary.
  const context = arg('--context') ?? '';
  const timeoutMs = Number(arg('--timeout-ms') ?? 900000);
  const { spawn } = await import('node:child_process');
  const run = ({ cmd, args, cwd }) =>
    new Promise((resolve) => {
      const [c, a] = asIdentity({ cmd, args, user: arg('--spawn-as'), path: arg('--spawn-path') });
      const child = spawn(c, a, { cwd, env: process.env });
      let out = '';
      let timedOut = false;
      const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
      child.stdout.on('data', (d) => { out += d; });
      child.stderr.on('data', (d) => { out += d; });
      child.on('close', (rc) => { clearTimeout(timer); resolve({ rc, out, timedOut }); });
      child.on('error', (e) => { clearTimeout(timer); resolve({ rc: 127, out: `${out}${e.message}`, timedOut }); });
    });

  const writeLogs = (logs) => {
    for (const [file, body] of Object.entries(logs ?? {})) {
      try { fs.writeFileSync(path.join(dir, file), body); } catch { /* the verdict still stands */ }
    }
  };

  /// Exit code meaning "the nub arm failed soundly; the CALLER must consult npm and come back".
  ///
  /// ⛔ THE npm ARM CANNOT LIVE IN HERE FOR A SHELL DRIVER, for the same reason the screen cannot: it
  /// screens its own fetched tree, and that screen's refusal path exits the driver. So this phase
  /// settles every case it can alone — timeout, broken off-switch, and nub succeeding — and hands back
  /// the one case that needs a second opinion. No verdict is printed on this path, because the verdict
  /// depends on an answer this process does not have.
  const CONSULT_NPM = 3;

  if (phase === 'verdict') {
    // The caller ran its own npm arm and is reporting the result. The nub arm's state is known from
    // having reached CONSULT_NPM at all: it failed, it did not time out, and its off-switch engaged.
    const npmVerdict = arg('--npm');
    if (!['ok', 'fail'].includes(npmVerdict)) {
      console.error('--phase verdict requires --npm ok|fail');
      process.exit(2);
    }
    const r = classify({ nub: { rc: 1, engaged: true }, npm: { rc: npmVerdict === 'ok' ? 0 : 1 } });
    console.log(`  jail-off control: ${r.why}`);
    console.log(`  => ${r.verdict}${context ? ` ${context}` : ""}`);
    process.exit(1);
  }

  if (phase === 'resolve') {
    // Materialise the tree and stop. NO verdict is printed here: the driver has not screened yet, and
    // a `=>` line emitted before the screen could be overwritten by the screen's own — `record.mjs`
    // takes the LAST match, so two verdicts from one cell means the earlier one silently vanishes.
    const { name } = writeFixture({ dir, pkg, version });
    const r = await run({ cmd: nub, args: ['install', '--ignore-scripts'], cwd: dir });
    writeLogs({ 'security-resolve.log': r.out ?? '' });
    console.log(`  jail-off control: resolved as ${name} (rc=${r.rc}${r.timedOut ? ', timed out' : ''})`);
    process.exit(r.timedOut || r.rc !== 0 ? 1 : 0);
  }

  const result = phase === 'run'
    // The fixture and the resolved tree are already on disk from the `resolve` phase, so this reuses
    // them rather than rewriting the manifest — rewriting it would reset the guards mid-cell.
    ? await (async () => {
      const logs = {};
      for (const step of [{ key: 'i.log', args: ['install'] }, { key: 'a.log', args: ['approve-builds', '--all'] }]) {
        const r = await run({ cmd: nub, args: step.args, cwd: dir });
        logs[step.key] = r.out ?? '';
        if (r.timedOut || r.rc !== 0) {
          const engaged = step.key === 'a.log' ? offSwitchEngaged({ i: logs['i.log'], a: logs['a.log'] }) : null;
          const nub_ = { rc: r.timedOut ? null : r.rc, timedOut: !!r.timedOut, engaged, logs };
          // A timeout or a broken off-switch is settled here; anything else needs npm's answer, which
          // only the caller can get with its own screen in place.
          if (!nub_.timedOut && engaged !== false) return { consultNpm: true, nub: nub_ };
          return { ...classify({ nub: nub_ }), nub: nub_ };
        }
      }
      const nub_ = { rc: 0, timedOut: false, engaged: offSwitchEngaged({ i: logs['i.log'], a: logs['a.log'] }), logs };
      return { ...classify({ nub: nub_ }), nub: nub_ };
    })()
    : await control({ nub, pkg, version, dir, run });

  writeLogs(result.nub.logs);
  if (result.consultNpm) {
    // NO verdict line here — it depends on npm's answer, which this process cannot get soundly.
    console.log('  jail-off control: nub failed with the jail OFF; asking npm before naming a culprit');
    process.exit(CONSULT_NPM);
  }
  // ONE `=>` line: `record.mjs` walks the log and the LAST match wins, so a second verdict from this
  // cell would silently overwrite this one and the stage would be inert.
  console.log(`  jail-off control: ${result.why}`);
  console.log(`  => ${result.verdict}${context ? ` ${context}` : ""}`);
  process.exit(result.verdict === VERDICT.noStatePassed ? 0 : 1);
}
