// THREE-DRIVER PARITY: a soundness guard wired into one driver must be wired into all three, or the
// exemption must be written down here with a reason.
//
// ⛔ THE DEFECT CLASS, AND WHY IT NEEDS A GENERATIVE GUARD RATHER THAN A FOURTH NAMED TEST. The
// harness measures the same question on three drivers (`measure.sh`, `measure-macos.sh`,
// `measure-windows.mjs`) feeding three classifiers (`observe.mjs`, `observe-macos.mjs`,
// `classify.mjs`). Every time a measurement-soundness bug is fixed, it is fixed in ONE of them and
// the other two keep producing unsound records — silently, because a driver that never asks a
// question never prints an answer that looks wrong. Four measured recurrences in one week:
//
//   1. THE ARTIFACT EXCUSAL. The toolchain excusal lived inside `artifact-gate.mjs`, which the two
//      POSIX drivers invoke as a CLI. `measure-windows.mjs` cannot, so it carried a hand-copied
//      `missingArtifacts` with no excusal at all. Fixed by hoisting `artifact-excusal.mjs`.
//   2. THE HOST-ASKED PLATFORM. `descentTerms(grant, platform = process.platform)` defaulted to the
//      HOST. Asked `linux`/`darwin`, the win32 driver GAINS a `no-network` arm that cannot go red —
//      a vacuous pass published as an UNDER-GRANT. All three drivers now name their own platform.
//   3. THE `observedEffect` WRITE SUM. `observe-macos.mjs` summed every write bucket including
//      `systemfs`, so the tracer's own `/dev/dtracehelper` read as work; `observe.mjs` fed the
//      marker an UNATTRIBUTED peer count where the other two fed the ATTRIBUTED one. One field
//      name, three quantities, 44% of the class blind.
//   4. THE FOURTH REPLAY PATH. `measure.sh` purged the machine-global artefact caches between
//      descent arms; the other two did not, so a warm arm passed for free and 44 darwin records
//      narrowed to an empty grant off arms that did no work. Fixed by `arm-artifact-cache.mjs`.
//
// Each was found by a separate investigation, after the unsound records had already shipped. A list
// of those four tokens would prevent nothing: they are all fixed. So this file asserts a RULE over
// the drivers' own reference graph, and the rule fires on a guard nobody has thought of yet — the
// author of the fifth recurrence sees it red at authoring time, and must either wire the other two
// drivers or write down here why not.
//
// ⛔ WHAT THIS FILE DOES **NOT** COVER, NAMED SO NOBODY READS IT AS TOTAL COVERAGE. Recurrence 3 was
// two identically-named fields carrying DIFFERENT QUANTITIES. No source-level rule can decide that
// `sum(writes)` in one classifier and `sum(writes) - systemfs` in another are the same number, so
// this file checks that a marker is REACHABLE from all three pipelines and never what it holds. The
// quantity question needs a differential fixture, not a lint.
//
// ⛔ ITS RELATIONSHIP TO `marker-contract.test.mjs`, which is adjacent and not the same. That file
// asserts the BIDIRECTIONAL contract — every emitted marker has a parser, every parsed marker has at
// least ONE emitter — over the `VENUE`/`RAWLOG`/`EVENTLOG` families. "At least one" is exactly the
// state recurrences 1–4 lived in. This file asserts the PER-DRIVER extension: all three, over every
// marker `record.mjs` parses.
//
// ⛔ EVERY EXTRACTOR IS VALIDATED AGAINST A KNOWN POSITIVE AND A KNOWN NEGATIVE BEFORE ANY CONTRACT
// ASSERTION RUNS. An extractor that silently matches nothing turns this whole file into a vacuous
// pass, which is the failure it exists to catch one level up. The `INSTRUMENT` cases are that check.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const V2 = path.dirname(fileURLToPath(import.meta.url));
const HARNESS = path.resolve(V2, '..');

/**
 * The three drivers, keyed by the platform each one MEASURES — which is a property of the driver and
 * not of the host executing it (recurrence 2). Paths are relative to `harness/` because the drivers
 * reach `../osv-screen.mjs`, which lives one level up and is shared by all three.
 */
const DRIVERS = {
  linux: { file: 'v2/measure.sh', platform: 'linux' },
  macos: { file: 'v2/measure-macos.sh', platform: 'darwin' },
  windows: { file: 'v2/measure-windows.mjs', platform: 'win32' },
};
const DRIVER_KEYS = Object.keys(DRIVERS);
const named = (keys) => keys.map((k) => DRIVERS[k].file).join(', ') || '(none)';

// ── SOURCE INDEX ──────────────────────────────────────────────────────────────────────────────────

const SOURCE_EXT = new Set(['.mjs', '.sh', '.cjs', '.ps1', '.d', '.js']);
// `results`/`overrides` are data, and `fixtures` are inputs to tests rather than harness code.
const SKIP_DIR = new Set(['node_modules', 'results', 'overrides', 'fixtures']);

const walk = (dir, acc = []) => {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIR.has(e.name)) walk(p, acc); }
    else if (SOURCE_EXT.has(path.extname(e.name))) acc.push(path.relative(HARNESS, p).split(path.sep).join('/'));
  }
  return acc;
};
const FILES = new Set(walk(HARNESS));

/**
 * A file's source with every COMMENT-ONLY line blanked, line count preserved.
 *
 * ⛔ BLANKED IN PLACE RATHER THAN DELETED, so every line-number-based window below still lines up
 * with the real file. And comment-ONLY rather than trailing-comment: stripping a `#` that follows
 * code would also eat a `#` inside a quoted string, and a lost reference reads as a MISSING guard —
 * a false failure. Over-keeping can only lose a detection; over-stripping invents one.
 *
 * This is what makes a module NAMED IN A COMMENT not count as wired up. Recurrence 1 is exactly that
 * shape: `measure-windows.mjs` discussed `artifact-gate.mjs` in prose while carrying its own copy.
 */
const blankComments = (src, isShell) => src.split('\n').map((l) => {
  const t = l.trimStart();
  if (isShell) return t.startsWith('#') ? '' : l;
  return (t.startsWith('//') || t.startsWith('/*') || t.startsWith('*')) ? '' : l;
}).join('\n');

const rawCache = new Map();
const codeOf = (rel) => {
  if (!rawCache.has(rel)) {
    const src = fs.readFileSync(path.join(HARNESS, rel), 'utf8');
    rawCache.set(rel, blankComments(src, rel.endsWith('.sh')));
  }
  return rawCache.get(rel);
};

/**
 * The harness files one file references. Shell keys on `$HERE/…` — the only form the drivers use to
 * INVOKE something, and one that never appears in their prose, which spells a module in backticks.
 * Node keys on a quoted relative path, covering both `import … from './x.mjs'` and a spawn argument.
 */
const refsOf = (rel) => {
  const code = codeOf(rel);
  const dir = path.dirname(rel);
  const out = new Set();
  const add = (spec) => {
    for (const c of [path.posix.normalize(path.posix.join(dir, spec)), path.posix.normalize(spec)]) {
      if (FILES.has(c)) { out.add(c); return; }
    }
  };
  const pat = rel.endsWith('.sh')
    ? /\$\{?(?:HERE|here|V2)\}?\/([A-Za-z0-9_./-]+\.(?:mjs|sh|cjs|ps1|d|js))/g
    : /['"](\.{0,2}[A-Za-z0-9_./-]*\.(?:mjs|sh|cjs|ps1|d|js))['"]/g;
  for (const m of code.matchAll(pat)) add(m[1]);
  out.delete(rel);
  return out;
};

const refCache = new Map();
const refs = (rel) => { if (!refCache.has(rel)) refCache.set(rel, refsOf(rel)); return refCache.get(rel); };

/** Everything a driver can reach, directly or through a module or CLI it invokes. */
const reachOf = (root) => {
  const seen = new Set([root]);
  const stack = [root];
  while (stack.length) for (const r of refs(stack.pop())) if (!seen.has(r)) { seen.add(r); stack.push(r); }
  return seen;
};

const REACH = Object.fromEntries(DRIVER_KEYS.map((k) => [k, reachOf(DRIVERS[k].file)]));
const isHarnessCode = (f) => !f.endsWith('.test.mjs');
/** The modules under audit: everything at least one driver reaches, tests excluded. */
const MODULE_UNIVERSE = [...new Set(DRIVER_KEYS.flatMap((k) => [...REACH[k]]))]
  .filter((f) => isHarnessCode(f) && !Object.values(DRIVERS).some((d) => d.file === f))
  .sort();
const modReachedBy = (m) => DRIVER_KEYS.filter((k) => REACH[k].has(m));

// ── THE MODULE REGISTRY ───────────────────────────────────────────────────────────────────────────
//
// ⛔ AN ENTRY HERE IS A CLAIM A HUMAN MADE, NOT A WAY TO GET GREEN. Every field is asserted below:
// the module must still exist, must still be partial (a fixed gap deletes its entry rather than
// keeping a stale one), the reason must be substantive, and a `mirrored` entry must name the test
// that holds the copies together — because a mirror with no test is the recurrence, not an exemption.
//
//   kind: 'platform'      the module implements a per-OS mechanism. The other drivers have their own
//                         counterpart, or the mechanism does not exist on their platform.
//   kind: 'mirrored'      one shared decision, duplicated because a driver cannot consume the shared
//                         form (shell cannot import JS; win32 cannot source a shell file). REQUIRES
//                         `boundBy`: the test that fails when the copies drift.
//   kind: 'not-soundness' absence cannot change a published record. Cost or ergonomics only.
//   kind: 'open'          A REAL, UNFIXED DIVERGENCE. Not an exemption — a finding parked here so the
//                         suite stays green while it is priced. Reported as a diagnostic on each run.
const MODULE_REGISTRY = new Map([
  ['v2/adapters/linux.mjs', { kind: 'platform', why:
    'The strace decoder. Landlock denials arrive as ordinary syscall failures in a strace stream; ' +
    'darwin reads the same facts out of DTrace and win32 out of ETW, each through its own adapter.' }],
  ['v2/adapters/macos-eventlog.mjs', { kind: 'platform', why:
    'The darwin DTrace event decoder, counterpart to adapters/linux.mjs and adapters/windows.mjs. ' +
    'It normalizes the DTrace OPEN return probe errno to the same symbolic names the others use.' }],
  ['v2/adapters/macos-observe.d', { kind: 'platform', why:
    'The DTrace script itself. There is no such artefact on a platform that is not traced by DTrace, ' +
    'and no other driver can consume a .d file at all.' }],
  ['v2/adapters/windows.mjs', { kind: 'platform', why:
    'The ETW capture adapter, counterpart to adapters/linux.mjs and adapters/macos-eventlog.mjs. ' +
    'Each driver wires exactly one tracer adapter and it is the one its kernel can produce.' }],
  ['v2/adapters/windows.ps1', { kind: 'platform', why:
    'The PowerShell half of the ETW capture. No POSIX driver has a PowerShell host to run it in, and ' +
    'the events it collects have no equivalent producer on either POSIX tracer.' }],
  ['v2/adapters/windows-retain.mjs', { kind: 'platform', why:
    'Retention of the ETW trace artefact. The POSIX drivers retain their traces through the ' +
    'RAWLOG/EVENTLOG file markers instead, which is the same fact in each platform tracer vocabulary.' }],
  ['v2/adapters/windows-shortnames.mjs', { kind: 'platform', why:
    'Resolves Windows 8.3 short names so a captured path can be compared with a long one. Neither ' +
    'POSIX filesystem has short names, so there is nothing for the other drivers to resolve.' }],
  ['v2/observe.mjs', { kind: 'platform', why:
    'One of the three per-platform classifiers. Each driver wires exactly one, and which one is the ' +
    'platform decision itself; observe-macos.mjs and classify.mjs are its darwin and win32 peers.' }],
  ['v2/observe-macos.mjs', { kind: 'platform', why:
    'The darwin classifier, peer of observe.mjs and classify.mjs. A separate implementation rather ' +
    'than a wrapper, which is precisely why its record fields are audited by the marker rule below.' }],
  ['v2/classify.mjs', { kind: 'platform', why:
    'The win32 classifier, peer of observe.mjs and observe-macos.mjs. Same one-per-driver rule: the ' +
    'choice of classifier is the platform decision, not a guard one driver happens to have.' }],
  ['v2/arm-cap.mjs', { kind: 'platform', why:
    'A POSIX process-group wall-clock cap. Its own header records the split: "measure.sh and ' +
    'measure-macos.sh enforce NOTHING ... Only measure-windows.mjs caps its arms", which it does ' +
    'through spawnSync\'s --arm-timeout. The cap exists on all three; only its mechanism differs.' }],
  ['v2/artifact-gate.mjs', { kind: 'mirrored', boundBy: 'artifact-excusal.test.mjs', why:
    'RECURRENCE 1 ITSELF, in its fixed state. The POSIX drivers invoke this as a CLI; ' +
    'measure-windows.mjs cannot, so it carries its own missingArtifacts. The DECISION they used to ' +
    'diverge on — which shortfalls the toolchain excuses — was hoisted into artifact-excusal.mjs, ' +
    'which all three reach. The gate wrapper stays split; the excusal must not.' }],
  ['v2/ci-env-scrub.sh', { kind: 'mirrored', boundBy: 'ci-env-scrub.test.mjs', why:
    'The POSIX drivers source this shell file; Windows cannot, so measure-windows.mjs mirrors CI_KEYS ' +
    'in JS. The named test reads both lists and fails when they drift, which is the only thing that ' +
    'makes a mirror safe rather than a second copy waiting to go stale.' }],
  ['v2/security-screen.sh', { kind: 'mirrored', boundBy: 'security-screen.test.mjs', why:
    'A POSIX shell wrapper over ../osv-screen.mjs, which all three drivers reach; measure-windows.mjs ' +
    'open-codes the same three outcomes in JS. The named test reads all three drivers and pins the ' +
    'fail-closed contract, so the wrapper is a calling convention rather than a policy that can drift.' }],
  ['v2/xdg-scrub.sh', { kind: 'platform', why:
    'The file documents its own exemption at xdg-scrub.sh:65: "NOT MIRRORED IN measure-windows.mjs, ' +
    'AND THAT IS A MEASURED DECISION RATHER THAN A GAP" — across 1,688 committed win32 captures, ' +
    'ZERO carry an XDG name in observeEnv, and every win32 real-home write is USERPROFILE-derived.' }],
  ['v2/override-probe.mjs', { kind: 'mirrored', boundBy: 'override-probe-parity.test.mjs', why:
    'The predicate deciding whether a nub binary honours NUB_BUILD_JAIL_CATALOG. The shell drivers ' +
    'cannot import JS, so they carry the two markers as grep arguments; the named test asserts the ' +
    'three spellings agree, and its CROSS-DRIVER case is what keeps this exemption honest.' }],
  ['v2/provision-node-matrix.mjs', { kind: 'not-soundness', why:
    'A per-box pre-provisioning fast path. The shell drivers open-code the same <root>/node/<version>/' +
    'bin layout and fall back to era-provision.mjs when it is absent, which is the same interpreter at ' +
    'the cost of a re-download. A stale layout here costs bandwidth; it cannot change a published grant.' }],
  ['v2/stamp-waiver.mjs', { kind: 'platform', why:
    'Scoped to falsify\'s win32 network case, which asserts a refusal TEXT emitted by nub\'s net-gate ' +
    'shim. That shim reaches a confined Node only as a NODE_OPTIONS --import term, so an era Node ' +
    'below 20.6 cannot print it. The POSIX jails deny at the kernel layer and assert no such text.' }],
  ['v2/denial-witness.mjs', { kind: 'open', why:
    'OPEN DIVERGENCE on win32 ONLY — darwin was wired at epoch 68, so this is now a two-of-three ' +
    'entry rather than one-of-three. The win32 half is BLOCKED, not merely unwired: measured over ' +
    'six committed win32 streams, zero rows carry an `r` or a `w`, and write INTENT is structurally ' +
    'absent because Create (event 12) carries no DesiredAccess while AppContainer denies AT Create, ' +
    'so event 16 never arrives to evidence the write. Capturing it needs a schema change, not a ' +
    'driver line. ⛔ THE DANGEROUS FIX IS STAMPING `jailed` WITHOUT MAPPING st->r: that makes every ' +
    'win32 stream score CLEAN, which is a blanket licence to narrow. VOID today is fail-closed and ' +
    'correct. (An earlier version of this note cited "223 committed darwin diagnose traces" as ' +
    'evidence; DIAGNOSE greps its trace into driver.out and DISCARDS it, so every committed darwin ' +
    'trace is an OBSERVE trace whose header reads jailed:false.)' }],
]);

// ── MARKERS ───────────────────────────────────────────────────────────────────────────────────────

/**
 * The marker vocabulary `record.mjs` PARSES, read off its parse sites — the lines that match a
 * regex against a driver log line. Keying on the parse site rather than on any uppercase token is
 * what keeps the harness's dense hyphenated PROSE (`LEAVE-ONE-OUT`, `BROKEN-WITHOUT-JAIL-TOO`) out
 * of a vocabulary it was never part of.
 */
const parsedMarkers = (src) => {
  const found = new Set();
  for (const line of src.split('\n')) {
    if (!/\.(?:exec|test)\(l\)/.test(line)) continue;
    for (const m of line.matchAll(/([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)/g)) found.add(m[1]);
  }
  return found;
};

const RECORD_SRC = fs.readFileSync(path.join(V2, 'record.mjs'), 'utf8');
const MARKERS = [...parsedMarkers(RECORD_SRC)].sort();

/**
 * Whether a driver's reach can PRODUCE a marker. Presence of the literal token in non-comment source
 * is the test, because emission forms vary irreducibly across the harness — `echo "  MARKER …"`,
 * ``console.log(`  ${CONFINED_WIDE_MARKER} …`)`` off an exported constant, and
 * ``export const marker = (r) => `DENIAL-WITNESS …` `` are all live. A form-matching extractor would
 * miss the last two and report a fictional gap; the token itself is distinctive enough.
 */
const markerReachedBy = (marker) => {
  const re = new RegExp(`${marker}(?![A-Z0-9-])`);
  return DRIVER_KEYS.filter((k) => [...REACH[k]].some((f) => isHarnessCode(f) && re.test(codeOf(f))));
};

// ⛔ SAME RULES AS THE MODULE REGISTRY: still parsed, still partial, substantive reason, and 'open'
// means a real gap rather than a decision.
const MARKER_REGISTRY = new Map([
  ['RAWLOG-FILE', { kind: 'platform', why:
    'Retention of the raw POSIX tracer stream (strace / DTrace). The win32 driver retains its ETW ' +
    'capture through adapters/windows-retain.mjs instead, so the artefact exists on all three and ' +
    'only the marker naming it is per-tracer.' }],
  ['EVENTLOG-FILE', { kind: 'platform', why:
    'Names the decoded per-event log the POSIX adapters write. The ETW pipeline keeps its events in ' +
    'the capture the win32 retention adapter preserves, so there is no second file to name.' }],
  ['EVENTLOG-STATS', { kind: 'platform', why:
    'Loss accounting for the POSIX event decoders, whose drop modes (a lost clone edge, a full DTrace ' +
    'principal buffer) are properties of those tracers. The win32 loss signal is its own and is ' +
    'already covered by the bidirectional contract in marker-contract.test.mjs.' }],
  ['VENUE-CI-CHILD', { kind: 'platform', why:
    'Asserts what the TRACED CHILD saw, and only the darwin chain can lose the scrub: measure-macos.sh ' +
    'reaches the traced npm through `sudo -u <user> -H env`, whose env_reset builds a fresh environment ' +
    'from sudo\'s own env_keep rather than inheriting the driver\'s. Linux traces the target directly ' +
    'in the driver environment, and Windows mutates process.env before spawning, so on both the plain ' +
    'unset IS the proof. Reasoned in place at measure-macos.sh:564.' }],
  ['VENUE-XDG-CHILD', { kind: 'platform', why:
    'The XDG half of the same darwin-only sudo assertion (measure-macos.sh:612): `env -u` runs on the ' +
    'far side of sudo, so whether a name survives is a property of env_keep as much as of the flag. ' +
    'Windows has no XDG names to scrub at all (xdg-scrub.sh:65); Linux unsets in its own shell and ' +
    'traces the child there.' }],
  ['SELF-CHECK', { kind: 'platform', why:
    'Not an independent marker: it is the failure branch INSIDE VENUE-CI-CHILD and VENUE-XDG-CHILD, ' +
    'which record.mjs matches on its own to note ci-scrub-unverified / xdg-scrub-unverified. It ' +
    'follows those two exactly, and exempting it separately would be double-counting them.' }],
  ['VENUE-JAIL-ROOT', { kind: 'platform', why:
    'Records where the win32 jail rooted the measurement, which the AppContainer profile needs and ' +
    'the POSIX backends do not have as a distinct fact — their root is the project directory the ' +
    'other VENUE markers already carry.' }],
  ['CWD-UNOBSERVED', { kind: 'platform', why:
    'The ambiguity it reports cannot arise on win32. Both POSIX tracers see a relative path and must ' +
    'resolve it against a cwd they may not have observed; ETW file events carry the resolved NT path, ' +
    'and the ONE relative case — a rename destination leaf under a RootDirectory handle — is anchored ' +
    'to the source directory or dropped outright by adapters/windows.mjs destPathOf().' }],
  ['DENIAL-WITNESS', { kind: 'open', why:
    'OPEN DIVERGENCE on win32 ONLY — the marker half of the denial-witness.mjs entry in ' +
    'MODULE_REGISTRY, which carries the measurement showing why win32 needs an event-schema change ' +
    'rather than a driver line. measure.sh and measure-macos.sh both emit this marker as of epoch 68.' }],
  ['CWD-RESOLVED', { kind: 'open', why:
    'OPEN DIVERGENCE on LINUX; platform-justified on win32. Only observe-macos.mjs emits it, so ' +
    'record.mjs\'s cwdResolved count is absent on every linux record even though observe.mjs ' +
    'documents the SAME hazard reaching linux through a lost clone edge and emits CWD-UNOBSERVED for ' +
    'it without the resolved-count companion. win32 is exempt for the reason CWD-UNOBSERVED records: ' +
    'ETW carries resolved paths, so there is no cwd to resolve against. Parked to keep the suite green.' }],
  ['CWD-UNPLACEABLE-WRITES', { kind: 'open', why:
    'OPEN DIVERGENCE on LINUX; platform-justified on win32, and the same gap as CWD-RESOLVED. ' +
    'observe-macos.mjs lists the writes it could not place so a future catalog fix does not need a ' +
    're-measure; observe.mjs reaches the identical state through a lost clone edge and lists nothing, ' +
    'so a linux record in doubt names those paths only in prose. Parked to keep the suite green.' }],
]);

// ── PLATFORM ARGUMENTS (recurrence 2) ─────────────────────────────────────────────────────────────

/** Modules whose CLI reads a `--platform` flag, so an invocation that omits it asks the HOST. */
const PLATFORM_FLAG_MODULES = MODULE_UNIVERSE.filter((m) =>
  m.endsWith('.mjs') && /['"]--platform['"]/.test(codeOf(m)));

/**
 * Modes of a `--platform`-capable CLI that genuinely take no platform. Each entry is a claim that the
 * code path behind the flag ignores the platform entirely; the assertion below re-checks that the
 * mode is still a real mode of that module, so a renamed mode cannot leave a hole behind.
 */
const PLATFORM_FREE_MODES = new Map([
  ['v2/descent-terms.mjs --narrow', 'narrow(grant, names) takes no platform parameter at all — it ' +
    'applies a named drop to a grant and throws when the drop cannot genuinely be applied.'],
  ['v2/promotion-probe.mjs --entries', '--entries lists the writePaths entries in the grant. The ' +
    'platform enters only at --score, which is where every driver passes it.'],
]);

/** Logical lines of a shell file: continuations joined, so a flag on the next line still counts. */
const logicalShellLines = (code) => {
  const out = [];
  let buf = null;
  for (const line of code.split('\n')) {
    const acc = buf === null ? line : `${buf} ${line.trim()}`;
    if (/\\\s*$/.test(line)) buf = acc.replace(/\\\s*$/, '');
    else { out.push(acc); buf = null; }
  }
  if (buf !== null) out.push(buf);
  return out;
};

/**
 * Every CLI invocation a driver makes of a `--platform`-capable module, as the text of the
 * invocation. Shell: one logical line. Node: the spawn call the reference sits inside, from the
 * nearest `run(`/`spawnSync(`/`execFileSync(` at most three lines above to the closing `]);`.
 *
 * ⛔ THE SPAWN ANCHOR IS WHAT KEEPS `decoderSha('classify.mjs')` OUT. That line names the classifier
 * to hash it, not to run it, and demanding a --platform beside it would be a false failure.
 */
const platformInvocations = (driverKey) => {
  const { file } = DRIVERS[driverKey];
  const code = codeOf(file);
  const found = [];
  const wanted = PLATFORM_FLAG_MODULES.map((m) => [m, path.posix.basename(m)]);
  if (file.endsWith('.sh')) {
    for (const line of logicalShellLines(code)) {
      for (const [mod, base] of wanted) if (new RegExp(`\\$\\{?(?:HERE|here|V2)\\}?/${base}`).test(line)) found.push({ mod, text: line });
    }
    return found;
  }
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const [mod, base] of wanted) {
      if (!new RegExp(`['"](?:\\./)?${base.replace('.', '\\.')}['"]`).test(lines[i])) continue;
      let start = -1;
      for (let j = i; j >= Math.max(0, i - 3); j--) if (/\b(?:run|spawnSync|execFileSync|spawn)\s*\(/.test(lines[j])) { start = j; break; }
      if (start === -1) continue; // named, not invoked
      let end = i;
      while (end < lines.length - 1 && !/\]\s*\)\s*;?/.test(lines[end])) end++;
      found.push({ mod, text: lines.slice(start, end + 1).join(' ') });
    }
  }
  return found;
};

/**
 * Exported functions whose FIRST parameter defaults to `process.platform`, so calling them with NO
 * arguments hands the question to the host. Restricted to the first parameter on purpose: a later
 * positional would need real argument-position parsing, which a regex cannot do soundly, and a
 * wrong answer there is a false failure. Named in the notes as a deliberate gap.
 */
const hostDefaultedExports = (mod) => {
  const found = new Set();
  const code = codeOf(mod);
  for (const m of code.matchAll(/export\s+(?:async\s+)?function\s+(\w+)\s*\(\s*platform\s*=\s*process\.platform/g)) found.add(m[1]);
  for (const m of code.matchAll(/export\s+const\s+(\w+)\s*=\s*\(\s*platform\s*=\s*process\.platform/g)) found.add(m[1]);
  return found;
};

/** Local names a driver binds an import to, so an aliased call is still checked. */
const importedAs = (driverCode, exportName) => {
  const names = new Set();
  for (const m of driverCode.matchAll(new RegExp(`\\b${exportName}\\s+as\\s+(\\w+)`, 'g'))) names.add(m[1]);
  if (new RegExp(`\\b${exportName}\\b(?!\\s+as\\b)`).test(driverCode)) names.add(exportName);
  return names;
};

// ⛔ SAME REGISTRY RULES. 'open' is a real gap parked to keep the suite green.
const HOST_DEFAULT_REGISTRY = new Map([
  ['v2/measure-windows.mjs confinedWideBaseline', { kind: 'open', why:
    'OPEN DIVERGENCE, not an exemption. The call takes no argument, so confined-wide.mjs answers from ' +
    'process.platform — right on a Windows runner and silently wrong anywhere else, which is the exact ' +
    'shape recurrence 2 fixed for descent-terms.mjs. The driver already names its own platform as ' +
    'WIN32 and its own comment says "All three drivers now name their own rather than asking the ' +
    'host". No published record is wrong today because the driver only runs on win32. Parked here.' }],
  ['v2/measure-windows.mjs interpretation', { kind: 'open', why:
    'OPEN DIVERGENCE, not an exemption, and the same call site family as confinedWideBaseline: the ' +
    'baseline and the sentence describing it are read from the host rather than from the driver\'s own ' +
    'WIN32 constant. Harmless while the driver only ever runs on win32, and one edit from not being. ' +
    'Parked here to keep the suite green.' }],
]);

// ── INSTRUMENT CHECKS — nothing below them is worth anything if these fail ────────────────────────

test('INSTRUMENT: the reference extractor finds each driver\'s known wiring', () => {
  // arm-artifact-cache.mjs is recurrence 4 in its fixed state: all three drivers reference it.
  for (const k of DRIVER_KEYS) {
    assert.ok(REACH[k].has('v2/arm-artifact-cache.mjs'),
      `the reference extractor cannot see ${DRIVERS[k].file} -> arm-artifact-cache.mjs, so it is broken`);
    assert.ok(REACH[k].size > 15, `the reference extractor found only ${REACH[k].size} files from ${DRIVERS[k].file}`);
  }
  // Transitive: no driver imports artifact-excusal.mjs on POSIX; they reach it through artifact-gate.mjs.
  assert.ok(REACH.linux.has('artifact-excusal.mjs') || REACH.linux.has('v2/artifact-excusal.mjs'),
    'the reference extractor does not follow measure.sh -> artifact-gate.mjs -> artifact-excusal.mjs');
  // One level up, through a `../` specifier the two POSIX drivers reach only via security-screen.sh.
  assert.ok(DRIVER_KEYS.every((k) => REACH[k].has('osv-screen.mjs')),
    'the reference extractor does not resolve ../osv-screen.mjs, so it under-reports every driver');
});

test('INSTRUMENT: a module named only in a COMMENT does not count as wired up', () => {
  // The negative control, and the one that decides whether this file can detect anything at all.
  // Recurrence 1 lived exactly here: measure-windows.mjs discussed artifact-gate.mjs in prose.
  assert.equal(blankComments('# see $HERE/foo.mjs for why\ncode "$HERE/bar.mjs"\n', true).includes('foo.mjs'), false,
    'the shell comment blanker keeps a commented reference, so a prose mention would read as wiring');
  assert.ok(blankComments('# see $HERE/foo.mjs\ncode "$HERE/bar.mjs"\n', true).includes('bar.mjs'),
    'the shell comment blanker eats real code');
  assert.equal(blankComments("// see './foo.mjs'\nrun('./bar.mjs');\n", false).includes('foo.mjs'), false,
    'the node comment blanker keeps a commented reference');
  assert.ok(blankComments("// see './foo.mjs'\nrun('./bar.mjs');\n", false).includes('bar.mjs'),
    'the node comment blanker eats real code');
  // And the live case: artifact-gate.mjs appears in measure-windows.mjs prose only.
  assert.match(fs.readFileSync(path.join(V2, 'measure-windows.mjs'), 'utf8'), /artifact-gate\.mjs/,
    'ANCHOR DRIFT: measure-windows.mjs no longer mentions artifact-gate.mjs, so this control is stale');
  assert.equal(REACH.windows.has('v2/artifact-gate.mjs'), false,
    'the reference extractor counts a prose mention of artifact-gate.mjs as wiring — it cannot detect recurrence 1');
});

test('INSTRUMENT: the marker extractor finds record.mjs\'s known vocabulary', () => {
  assert.ok(MARKERS.length >= 20, `the marker extractor found only ${MARKERS.length} markers — it is broken`);
  for (const known of ['OBSERVED-EFFECT', 'DENIAL-WITNESS', 'CONFINED-WIDE', 'ARM-FALSIFIABILITY', 'VENUE-STORE-LAYOUT']) {
    assert.ok(MARKERS.includes(known), `the marker extractor missed ${known}:\n${MARKERS.join(' ')}`);
  }
  // Prose is dense with hyphenated uppercase; none of it may enter the vocabulary.
  assert.equal(parsedMarkers('// LEAVE-ONE-OUT is the method\nconst x = 1;\n').size, 0,
    'the marker extractor harvests prose, so it would invent markers no driver could ever emit');
  // A marker every driver produces, as the positive control for the reach half.
  assert.deepEqual(markerReachedBy('VENUE-STORE-LAYOUT'), DRIVER_KEYS,
    'the marker reach test cannot see a marker all three drivers emit');
  assert.deepEqual(markerReachedBy('NO-SUCH-MARKER-ANYWHERE'), [],
    'the marker reach test reports a marker nothing emits');
  // ⛔ THE ONE WAY THE MARKER INVARIANT COULD GO VACUOUS. `record.mjs` names every marker in the
  // vocabulary, so the day a driver references it — even only to digest it — every marker becomes
  // "producible" from every driver and the rule below passes while measuring nothing at all.
  for (const k of DRIVER_KEYS) {
    assert.equal(REACH[k].has('v2/record.mjs'), false,
      `${DRIVERS[k].file} now reaches record.mjs, which names every marker; the marker rule is vacuous until record.mjs is excluded from the reach`);
  }
});

test('INSTRUMENT: the platform-invocation extractor sees the real invocations and not the mentions', () => {
  assert.ok(PLATFORM_FLAG_MODULES.includes('v2/descent-terms.mjs'),
    `descent-terms.mjs is not detected as --platform-capable: ${PLATFORM_FLAG_MODULES.join(' ')}`);
  const linux = platformInvocations('linux');
  assert.ok(linux.length >= 4, `only ${linux.length} platform-capable invocations found in measure.sh`);
  assert.ok(linux.some((i) => /--terms/.test(i.text) && /--platform linux/.test(i.text)),
    'the extractor cannot see measure.sh\'s `--terms … --platform linux` invocation');
  // The continuation-join control: measure.sh puts --score and --platform on different physical lines.
  assert.ok(linux.some((i) => /--score/.test(i.text) && /--platform linux/.test(i.text)),
    'the extractor does not join shell continuation lines, so a wrapped invocation reads as platform-less');
  const win = platformInvocations('windows');
  assert.ok(win.some((i) => i.mod === 'v2/classify.mjs' && /--platform', 'win32'/.test(i.text)),
    'the extractor cannot see measure-windows.mjs\'s classify.mjs spawn');
  assert.equal(win.filter((i) => i.mod === 'v2/classify.mjs').length, 1,
    'the extractor counts a non-spawn mention of classify.mjs (decoderSha) as an invocation');
});

test('INSTRUMENT: the host-defaulted-export extractor finds a known signature', () => {
  const cw = hostDefaultedExports('v2/confined-wide.mjs');
  assert.ok(cw.has('confinedWideBaseline'),
    `confinedWideBaseline(platform = process.platform) not detected: ${[...cw]}`);
  assert.equal(hostDefaultedExports('v2/arm-make.mjs').size, 0,
    'the extractor reports a host default in a module that has none');
  // marker(result, platform = process.platform) is a SECOND positional and deliberately out of scope.
  assert.equal(cw.has('marker'), false,
    'the extractor claims a non-first platform parameter, which it cannot decide soundly');
});

// ── THE INVARIANTS ────────────────────────────────────────────────────────────────────────────────

test('every shared module a driver reaches is reached by all three, or registered here', () => {
  const gaps = [];
  for (const m of MODULE_UNIVERSE) {
    const have = modReachedBy(m);
    if (have.length === DRIVER_KEYS.length || MODULE_REGISTRY.has(m)) continue;
    const missing = DRIVER_KEYS.filter((k) => !have.includes(k));
    gaps.push(`${m}\n      wired into: ${named(have)}\n      MISSING from: ${named(missing)}`);
  }
  assert.deepEqual(gaps, [],
    'A measurement guard is wired into some drivers and not others. This is the defect class that has\n'
    + 'recurred four times in one week (artifact excusal, host-asked platform, observedEffect write sum,\n'
    + 'the fourth replay path); each time the unwired drivers kept publishing unsound records until a\n'
    + 'separate investigation found it. Wire the missing drivers, or add an entry to MODULE_REGISTRY in\n'
    + `three-driver-parity.test.mjs saying why not.\n\n    ${gaps.join('\n    ')}`);
});

test('every marker record.mjs parses can be produced by all three drivers, or is registered here', () => {
  const gaps = [];
  for (const mk of MARKERS) {
    const have = markerReachedBy(mk);
    if (have.length === DRIVER_KEYS.length || MARKER_REGISTRY.has(mk)) continue;
    const missing = DRIVER_KEYS.filter((k) => !have.includes(k));
    gaps.push(`${mk}\n      producible by: ${named(have)}\n      NOT producible by: ${named(missing)}`);
  }
  assert.deepEqual(gaps, [],
    'record.mjs parses a marker some drivers can never emit, so the field it fills is silently empty on\n'
    + 'those platforms and reads as "the driver measured nothing" rather than "nobody wired it up".\n'
    + 'marker-contract.test.mjs only requires ONE emitter, which is the state every recurrence lived in.\n'
    + `Wire the missing drivers, or add an entry to MARKER_REGISTRY.\n\n    ${gaps.join('\n    ')}`);
});

test('a driver invoking a --platform CLI names its own platform, never the host', () => {
  const gaps = [];
  for (const k of DRIVER_KEYS) {
    const { file, platform } = DRIVERS[k];
    for (const { mod, text } of platformInvocations(k)) {
      const free = [...PLATFORM_FREE_MODES.keys()]
        .filter((key) => key.startsWith(`${mod} `))
        .some((key) => text.includes(key.slice(mod.length + 1)));
      if (free) continue;
      if (new RegExp(`--platform['"\\s,]+${platform}`).test(text)) continue;
      gaps.push(`${file} invokes ${mod} without --platform ${platform}:\n      ${text.trim().slice(0, 160)}`);
    }
  }
  assert.deepEqual(gaps, [],
    'RECURRENCE 2. A --platform-capable CLI invoked without one falls back to process.platform, i.e. to\n'
    + 'the HOST. The platform is a property of the driver, not of the machine running it: the win32\n'
    + 'driver asked linux or darwin GAINS a no-network arm that cannot go red, passes it vacuously, and\n'
    + 'publishes an UNDER-GRANT. Pass the platform, or register the mode in PLATFORM_FREE_MODES.\n\n    '
    + gaps.join('\n    '));
});

test('no driver calls a host-defaulted shared API with an empty argument list', () => {
  const gaps = [];
  for (const k of DRIVER_KEYS) {
    const { file } = DRIVERS[k];
    if (!file.endsWith('.mjs')) continue; // a shell driver reaches these through the CLI rule above
    const code = codeOf(file);
    for (const mod of MODULE_UNIVERSE.filter((m) => m.endsWith('.mjs'))) {
      if (!refs(file).has(mod)) continue;
      for (const fn of hostDefaultedExports(mod)) {
        for (const local of importedAs(code, fn)) {
          if (!new RegExp(`\\b${local}\\s*\\(\\s*\\)`).test(code)) continue;
          const key = `${file} ${fn}`;
          if (HOST_DEFAULT_REGISTRY.has(key)) continue;
          gaps.push(`${file} calls ${local}() with no argument — ${mod} then answers from process.platform`);
        }
      }
    }
  }
  assert.deepEqual(gaps, [],
    'RECURRENCE 2, in its JS form. The first parameter of each of these defaults to process.platform, so\n'
    + 'an empty call asks the HOST what platform is being measured. Pass the driver\'s own platform\n'
    + `constant, or register the call site in HOST_DEFAULT_REGISTRY.\n\n    ${gaps.join('\n    ')}`);
});

// ── REGISTRY HYGIENE — an allowlist nobody re-checks is the defect with a rubber stamp on it ──────

test('every registered exemption is still real, still needed, and reasoned', (t) => {
  const problems = [];
  const check = (label, key, entry, exists, stillPartial) => {
    if (!exists) problems.push(`${label} names ${key}, which no driver reaches any more — delete the entry`);
    else if (!stillPartial) problems.push(`${label} names ${key}, which all three drivers now have — delete the entry`);
    if (!entry.why || entry.why.length < 80) problems.push(`${label}'s entry for ${key} has no substantive reason`);
    if (entry.kind === 'mirrored') {
      if (!entry.boundBy) problems.push(`${label} calls ${key} 'mirrored' but names no test holding the copies together`);
      else if (!fs.existsSync(path.join(V2, entry.boundBy))) {
        problems.push(`${label}'s ${key} is bound by ${entry.boundBy}, which does not exist — the mirror is unguarded`);
      }
    }
    if (entry.kind === 'open') t.diagnostic(`OPEN CROSS-DRIVER DIVERGENCE — ${key}: ${entry.why.split('.')[0]}.`);
  };
  for (const [m, e] of MODULE_REGISTRY) check('MODULE_REGISTRY', m, e, MODULE_UNIVERSE.includes(m), modReachedBy(m).length < DRIVER_KEYS.length);
  for (const [mk, e] of MARKER_REGISTRY) check('MARKER_REGISTRY', mk, e, MARKERS.includes(mk), markerReachedBy(mk).length < DRIVER_KEYS.length);
  for (const [key, e] of HOST_DEFAULT_REGISTRY) {
    const [file, fn] = key.split(' ');
    const code = codeOf(file);
    const live = [...importedAs(code, fn)].some((l) => new RegExp(`\\b${l}\\s*\\(\\s*\\)`).test(code));
    check('HOST_DEFAULT_REGISTRY', key, e, live, true);
  }
  for (const [key, why] of PLATFORM_FREE_MODES) {
    const [mod, mode] = key.split(' ');
    // Both spellings, because a CLI declares its modes either bare (`MODES = ['narrow', …]`) or with
    // the dashes (`process.argv.includes('--entries')`), and either one proves the mode is still real.
    const declared = codeOf(mod).includes(`'${mode}'`) || codeOf(mod).includes(`'${mode.replace(/^--/, '')}'`);
    if (!MODULE_UNIVERSE.includes(mod)) problems.push(`PLATFORM_FREE_MODES names ${mod}, which no driver reaches`);
    else if (!declared) {
      problems.push(`PLATFORM_FREE_MODES names ${key}, but ${mod} no longer has that mode — the exemption is a hole`);
    }
    if (why.length < 80) problems.push(`PLATFORM_FREE_MODES' entry for ${key} has no substantive reason`);
  }
  assert.deepEqual(problems, [],
    `stale or unreasoned exemptions mask the next recurrence:\n    ${problems.join('\n    ')}`);
});
