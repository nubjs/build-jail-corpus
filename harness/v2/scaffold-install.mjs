// Apply an arm's scaffold to the observe tree, resiliently, from ONE implementation the three drivers share.
//
// ⛔⛔ WHY THIS IS A SHARED MODULE AND NOT THREE COPIES — the same reason `dep-scaffold.mjs` gives at
// length, and it has now happened twice. A v2 fix that lands in `measure.sh` alone stays live as a
// DEFECT on macOS and Windows for as long as it takes someone to notice, because the two shell drivers
// and the JS driver spell everything differently. They cannot share a function, but they CAN share a
// process. `arm-prepare.test.mjs` asserts all three call this file, and that guard is what makes
// "landed" mean landed.
//
// ⛔ THE DEFECT THIS FIXES. The drivers installed the scaffold with ONE `npm install` carrying every
// spec. npm's install is atomic, so a single spec that will not resolve loses the whole batch and the
// arm is left exactly as badly off as it was — with `ARM-SCAFFOLD-INSTALL rc=1` as the only trace, and
// no way for a reader to tell WHICH spec was fatal or whether the rest would have been fine.
//
// The old conclusion drawn from that was to install LESS (only the binaries a script names). It is the
// wrong lever: `script-scaffold.mjs`'s header carries the 2026-09-01 measurement showing the failure is
// `ERESOLVE` under npm 7+'s strict peer resolution, not an inherent limit. The right lever is to stop
// letting one bad resolution be fatal.
//
// ⛔ BISECT, NOT PER-PACKAGE. A per-spec loop is n installs for n specs and it also RESOLVES each spec
// in isolation, which is a different (and more permissive) question than resolving them together — the
// arm would get a tree npm would never have produced. Bisecting keeps the whole-batch resolution in the
// common case, costs one extra install per boundary, and converges to per-spec only around the specs
// that actually fail. A 29-package closure that resolves clean is still ONE install.
//
// ⛔ `--legacy-peer-deps` IS UNCONDITIONAL AND IT IS SAFE ON BOTH ERAS. It is what takes paypal-js's
// 29-package closure from rc=1/`.bin` empty to rc=0/48 bins. npm 6 has no such flag and needs none — it
// never enforced peers — and accepts it as an unknown option rather than failing (measured: era npm
// 6.14.18 from the Node 14.21.3 tarball, `install --legacy-peer-deps rimraf@2.6.3`, rc=0).
//
// ⛔ IT DOES NOT RE-INSTALL THE SUBJECT AND MUST NOT START. Every driver already does that immediately
// after this call, guarded by its own ARM-SUBJECT-EVICTED refusal, and each reads the tree back in the
// layout-aware way its platform needs. Two owners for that repair is how it drifts.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { installedManifest, installedFileReader } from './arm-prepare.mjs';
import { scriptScaffold } from './script-scaffold.mjs';
import { SELF_DOWNLOADING, prestageLauncher, prestageMarker } from './prestage-launcher.mjs';

/** One npm install. Injected in tests; the real one is below.
 *
 *  ⛔ `prefix` IS A NAMED OPTION AND NOT PART OF `specs`. Folding `--prefix <dir>` into the spec list
 *  would make it count toward the batch LENGTH the bisect slices on, so a failing batch would split on
 *  a boundary that includes two flag words and hand npm a `--prefix` with no value. The bisect may only
 *  ever see package specs. */
export function npmInstall({ specs, cwd, before, npmArgv, env, dated = true, prefix = null }) {
  const [cmd, ...pre] = npmArgv;
  const r = spawnSync(cmd, [...pre, 'install', '--no-audit', '--no-fund', '--ignore-scripts',
    '--legacy-peer-deps', ...(prefix ? ['--prefix', prefix] : []),
    ...(dated && before ? [`--before=${before}`] : []), ...specs],
  { cwd, env, encoding: 'utf8', maxBuffer: 1 << 26 });
  return { status: r.status ?? 1, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

/** npm's own one-line diagnosis for a failed spec, so a record can say WHY rather than only rc. */
export function whyFailed(out) {
  const lines = String(out).split('\n').map((l) => l.trim()).filter(Boolean);
  const code = lines.find((l) => /^npm (ERR!|error) code /.test(l));
  const first = lines.find((l) => /^npm (ERR!|error) /.test(l) && !/^npm (ERR!|error) code /.test(l)
    && !/A complete log|report see|_logs/.test(l));
  return [code, first].filter(Boolean).join(' ').replace(/^npm (ERR!|error) /, '').slice(0, 200)
    || 'no npm diagnosis in the log';
}

/**
 * Install `specs`, keeping everything that resolves.
 *
 * Whole batch first; on failure split in half and recurse, so a bad spec costs O(log n) extra installs
 * and isolates itself. At size 1 the failure is RECORDED and the walk continues — that record is the
 * difference between "the scaffold was not applied" and "it was applied and did not help", which the
 * drivers' existing rc reporting already treats as the distinction worth preserving.
 *
 * @returns {{requested:number, installed:string[], failed:{spec:string,why:string}[], installs:number}}
 */
export function installResiliently(specs, run, state = { installs: 0 }) {
  const installed = [], failed = [];
  const walk = (batch) => {
    if (!batch.length) return;
    state.installs++;
    const r = run(batch);
    if (r.status === 0) { installed.push(...batch); return; }
    if (batch.length === 1) { failed.push({ spec: batch[0], why: whyFailed(r.out) }); return; }
    const mid = Math.floor(batch.length / 2);
    walk(batch.slice(0, mid));
    walk(batch.slice(mid));
  };
  walk(specs);
  return { requested: specs.length, installed, failed, installs: state.installs };
}

/** Apply a whole scaffold plan in the order the tiers are meant to land. */
export function applyScaffold(plan, { runDated, runUndated }) {
  const tiers = {};
  // ⛔ TOOLS FIRST, THEN THE NAMED BINARIES, THEN THE CLOSURE — least to most likely to disturb the
  // tree. The closure is much the largest and the only best-effort tier, so it goes last: an npm
  // install re-resolves the whole tree, and the tier whose absence actually breaks the arm should not
  // be the one a later install gets to reconsider.
  tiers.tools = plan.tools?.length ? installResiliently(plan.tools, runUndated) : null;
  tiers.install = plan.install?.length ? installResiliently(plan.install, runDated) : null;
  tiers.closure = plan.closure?.length ? installResiliently(plan.closure, runDated) : null;
  const done = (t) => (t ? t.installed.length : 0);
  return {
    tiers,
    requested: (plan.tools?.length ?? 0) + (plan.install?.length ?? 0) + (plan.closure?.length ?? 0),
    installed: done(tiers.tools) + done(tiers.install) + done(tiers.closure),
    failed: [...(tiers.tools?.failed ?? []), ...(tiers.install?.failed ?? []), ...(tiers.closure?.failed ?? [])],
    // ⛔ THE REQUIRED TIERS ARE REPORTED SEPARATELY FROM THE BEST-EFFORT ONE. A closure spec that will
    // not resolve is expected and uninteresting; a script-NAMED binary that will not resolve is the
    // arm missing something its lifecycle script is about to invoke, and those two must never be
    // summed into one number a reader then has to disambiguate.
    requiredFailed: [...(tiers.tools?.failed ?? []), ...(tiers.install?.failed ?? [])],
  };
}

/** The `driver.out` lines. One per line — `driver.out` is parsed line-wise. */
export function scaffoldMarkers(result) {
  const t = (name, tier) => (tier
    ? `ARM-SCAFFOLD-${name} ${tier.installed.length}/${tier.requested} installed in ${tier.installs} install(s)`
      + (tier.failed.length ? `; failed: ${tier.failed.map((f) => `${f.spec} (${f.why})`).join(' | ')}` : '')
    : `ARM-SCAFFOLD-${name} none`);
  return [
    t('TOOLS', result.tiers.tools),
    t('NAMED', result.tiers.install),
    t('CLOSURE', result.tiers.closure),
    result.requiredFailed.length
      ? `ARM-SCAFFOLD-REQUIRED-INCOMPLETE ${result.requiredFailed.length} script-named provider(s) could not be installed`
      : 'ARM-SCAFFOLD-REQUIRED-INCOMPLETE none',
  ].map((l) => l.replace(/\s*\n\s*/g, ' '));
}

// ── CLI ───────────────────────────────────────────────────────────────────────
//
//   node scaffold-install.mjs --observe <dir> --pkg <name> [--before <iso>] [--prefix <dir>]
//
// The plan is re-derived here from the INSTALLED manifest rather than passed in as argv. Two reasons,
// and the second was paid for: it is the same `scriptScaffold()` call `arm-prepare.mjs` makes on the
// same file, so the two cannot drift; and a 29-spec argv threaded through a shell variable is a word-
// splitting hazard that silently produced `husky@file:^5.0.9 @babel/core@…` as ONE package name when
// it was tried, with rc=0 and one package installed to show for it.
//
// Exit status is 0 whenever the tree was left usable, INCLUDING when best-effort specs failed. A
// scaffold that cannot resolve leaves the arm no worse than it was, so it must never convert a
// measurable package into a harness error — the drivers have always treated it that way and the
// markers carry the detail.
// ⛔ REALPATH, AND `fileURLToPath` RATHER THAN `.pathname` — the pair `dep-scaffold.mjs` already had to
// get right. On macOS `/tmp` is a symlink to `/private/tmp`, so a plain string compare silently skips
// this branch when the script is reached through one; and `new URL(...).pathname` yields `/C:/…` on
// Windows, which matches nothing.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const arg = (n) => { const i = process.argv.indexOf(`--${n}`); return i === -1 ? undefined : process.argv[i + 1]; };
  const observeDir = arg('observe'); const pkg = arg('pkg');
  if (!observeDir || !pkg) {
    process.stderr.write('usage: scaffold-install.mjs --observe <dir> --pkg <name> [--before <iso>] [--prefix <dir>]\n');
    process.exit(2);
  }
  // ⛔ BOTH SPELLINGS ACCEPTED, BECAUSE THE SHELL DRIVERS ALREADY HOLD THE FLAG FORM. `era-resolution.mjs`
  // prints line 1 as the whole `--before=<iso>` ARGUMENT, and both shell drivers carry it in `$ERA_BEFORE`
  // that way. Requiring the bare instant here would mean each driver stripping the prefix in its own
  // `sed`, which is three chances to get one regex wrong for no gain.
  const before = (arg('before') || '').replace(/^--before=/, '') || null;
  const prefix = arg('prefix') || null;
  const { npmArgv } = await import('./npm-cli.mjs');
  // ⛔ NOT A BARE `npm`. npm ships on Windows as a `.cmd` shim that `spawnSync` cannot execute, and
  // `npm-cli.mjs` records two separate sweeps lost to exactly that.
  const argv = npmArgv();
  const manifest = installedManifest(observeDir, pkg);
  if (!manifest) {
    process.stdout.write('ARM-SCAFFOLD-PLAN none (the subject is not in the observe tree)\n');
    process.exit(0);
  }
  const plan = scriptScaffold(manifest, { readFile: installedFileReader(observeDir, pkg) });
  const base = { cwd: observeDir, before, npmArgv: argv, env: process.env, prefix };
  const result = applyScaffold(plan, {
    runDated: (specs) => npmInstall({ ...base, specs, dated: true }),
    runUndated: (specs) => npmInstall({ ...base, specs, dated: false }),
  });
  for (const m of scaffoldMarkers(result)) process.stdout.write(`${m}\n`);

  // ⛔ AFTER THE TOOLS TIER, AND ONLY FOR A TOOL THAT ACTUALLY INSTALLED. A self-downloading launcher
  // would otherwise fetch its payload into the arm's HOME on first use, which is the scope being
  // measured — see `prestage-launcher.mjs` for the 291 MB this keeps out of it. The staging dir is a
  // sibling of the observe tree rather than a child: a child would be inside the very directory the
  // artifact gate diffs, and 100 MB of tool would read as files the script produced.
  const installedTools = new Set(result.tiers.tools?.installed ?? []);
  for (const tool of Object.keys(SELF_DOWNLOADING)) {
    if (!installedTools.has(tool)) continue;
    const stageDir = path.join(path.dirname(observeDir), `.prestage-${tool}`);
    let r;
    try { r = prestageLauncher(tool, { observeDir, stageDir }); }
    catch (e) { r = { tool, staged: false, why: `threw: ${e.message}`, binaries: [] }; }
    process.stdout.write(`${prestageMarker(r)}\n`);
  }
}
