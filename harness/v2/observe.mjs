// Read a god-mode strace and say what a lifecycle script ACTUALLY needs.
//
// THE METHOD THIS REPLACES. The 55-state ascending ladder exists because pass/fail was the only
// signal available: run a grant, see if the package survives, widen, repeat. That is ~13 min per
// package and it answers "how WIDE a grant does this need" while never answering "WHAT does it
// touch". Under a root-privileged harness we do not have to infer any of it — the trace says so.
//
// THE SPLIT THIS BELONGS TO. Generation runs on our boxes, may use root/ptrace/eBPF freely, and
// assumes the script is well-behaved. The shipped jail runs unprivileged on a stranger's machine
// and assumes the script is hostile. This file lives entirely on the generation side; nothing it
// needs is available to — or required by — the jail.
//
// ⛔ THE STRACE DECODING LIVES IN `adapters/linux.mjs` AND IS IMPORTED, NOT REIMPLEMENTED HERE.
// This file used to carry its own regex decoder, and the two drifted: measured against the
// known-answer fixture `probes/syscall-coverage.c` on 2026-08-06, the local decoder retained 18 of
// the 26 writes that actually executed, invented one path no process touched, and truncated another
// — while `adapters/linux.mjs`, written later for log retention, retained all 26. Every one of the
// eight losses was in the UNDER-GRANT direction, which is the one direction this system may not
// take. Duplication is what produced that gap, so the duplication is gone: `decode()` is the single
// strace surface and this file is the CLASSIFIER + SYNTHESIZER on top of it.
//
// WHAT THE SHARED DECODER FIXES, each measured on the fixture (see `adapters/linux.mjs`'s header for
// the mechanism of each):
//   · `rename`/`link` DESTINATIONS — the old matcher took the first quoted argument, the SOURCE.
//   · a `*at` syscall with a REAL dirfd (`openat(3,"B")`, `mkdirat`, `unlinkat`, `renameat2`) — the
//     old matcher required `AT_FDCWD` or a quoted first argument and failed the line WHOLE.
//   · `fchmodat`/`fchownat`/`mknodat` — glibc rewrites `chmod()`/`chown()` to the `*at` forms, and
//     the old anchored filter listed `chmod`/`chown` and so matched NEITHER. `mknod` was absent
//     entirely. Measured live: 725 `fchmodat` + 728 `fchownat` in one `sharp@0.32.6` install.
//   · `symlinkat(target, dirfd, linkpath)` — the old code resolved `linkpath` against the cwd and
//     INVENTED a path no process touched, which is worse than missing one: a fabricated path can
//     widen a grant on evidence that does not exist.
//   · a path containing a `"` — `"([^"]*)"` stopped at the C escape and truncated it mid-path.
//
// ⛔ WHAT IS NOT SHARED, DELIBERATELY: the RETENTION STEP. `measure.sh` still invokes
// `adapters/linux.mjs` as a separate process AFTER this one, and that invocation still feeds nothing
// back — a failure there still cannot move a verdict. Sharing a pure `decode()` function is not the
// same as sharing a step, and it is what stops the two from drifting again.
//
// ⛔ EVERY ROOT COMES FROM `capture.json`, AND NOTHING ELSE MAY SUPPLY ONE (VENUE-PORTABILITY R2).
// Not the ambient environment, not a hardcoded `~/.cache/nub` pattern, not a root derived from the
// path being classified. The roots are what turn a machine-specific path into a scope, so a
// classifier that can obtain one from its surroundings produces a plausible answer on the machine
// that happens to match and a wrong one everywhere else — and says nothing either way.
//
// ⛔ A NEEDED ROOT THAT `capture.json` DOES NOT DECLARE IS A HARD ERROR, NEVER A FALLBACK. A
// fallback is precisely the mechanism that makes a venue difference SILENT: it keeps running and
// emits a grant, so the failure surfaces as a wrong catalog entry rather than as a crash. Exiting
// here costs one run; a silent wrong root costs a corpus nobody knows is wrong.
//
// ⛔ ABSENT AND `null` ARE DIFFERENT AND ARE TREATED DIFFERENTLY. `null` is the capture SAYING this
// platform has no such root, which is an answer; an absent key is the capture failing to say, which
// is not. Only the latter is fatal — collapsing them would let a stale writer silently opt out.
//
//   usage: node observe.mjs <trace-file> --capture <capture.json>
import fs from 'node:fs';
import { decode } from './adapters/linux.mjs';
import { deriveWritePaths, refuseUserHome, relativizeUnder } from './write-paths.mjs';

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const file = argv.find((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const capturePath = flag('--capture');
if (!file || !capturePath) {
  console.error('usage: observe.mjs <trace> --capture <capture.json>');
  process.exit(2);
}

// Every root this classifier keys on. The list is HERE rather than in the driver because this file
// is what would misclassify without one, so it is the file that must refuse to run.
const REQUIRED_ROOTS = ['project', 'home', 'jailHome', 'globalStore', 'projectStore',
                        'interpreter', 'toolsDir', 'temp', 'npmPrefix', 'ownPkg'];
let capture;
try { capture = JSON.parse(fs.readFileSync(capturePath, 'utf8')); }
catch (e) { console.error(`⛔ cannot read capture.json at ${capturePath}: ${e.message}`); process.exit(3); }
const roots = capture.roots ?? {};
const undeclared = REQUIRED_ROOTS.filter((k) => !(k in roots));
if (undeclared.length) {
  console.error(`⛔ capture.json does not DECLARE these roots: ${undeclared.join(', ')}`);
  console.error('   Classification would fall back to ambient state and silently differ by venue.');
  console.error('   Declare each one, or `null` where this platform genuinely has no such root.');
  process.exit(3);
}
const { project: proj, home, jailHome, temp: jailTmp, npmPrefix: jailNpmPrefix,
        globalStore, projectStore, interpreter, toolsDir, ownPkg: ownPkgDir } = roots;
const pkgName = capture.pkg ?? null;
// The MEASURED version, used for one thing only: saying whether a derived `writePaths` entry
// embeds it and therefore stops matching on the next release. Never used to guess a path.
const pkgVersion = capture.version ?? null;
const text = fs.readFileSync(file, 'utf8');
const decoded = decode(text, { project: proj });

// ⛔ ONLY `= -1 EACCES` IS A REFUSAL. A bare `grep EACCES` also matches the FLAG NAME `AT_EACCESS`
// in faccessat calls, which are ordinary successful probes. Measured on a real trace: the naive
// pattern reported 26 denials where 11 were real. The shared decoder hands us the errno as a field,
// so the distinction is structural here rather than a pattern that has to be got right.
const DENIED = /^(EACCES|EPERM|EROFS)$/;

const writes = new Set(), reads = new Set(), denials = new Set(), hosts = new Set();
let sockets = 0;
// Everything the WHOLE traced tree did, package manager included. Kept only so the
// over-attribution can be reported as a number instead of asserted.
const allWrites = new Set();
let allSockets = 0;

// ⛔ ATTRIBUTION IS NOT OPTIONAL, AND ITS ABSENCE IS A SILENT 100% OVER-PREDICTION. The trace
// contains the package manager's own syscalls as well as the lifecycle script's, and path text
// cannot tell them apart — npm writes `~/.npm/_logs` and opens TLS sockets on every single run.
// Without a subtree filter EVERY package synthesizes `write:userHome` + `network:true` regardless
// of what its script does, which also makes the per-path question unanswerable. A lifecycle script
// is always reached through a shell (`npm run-script` execs `sh -c "<script>"`), so the attributed
// set is the union of the subtrees rooted at those shells.
//
// The rule lives in the shared decoder and is applied there identically; `decode()` returns it
// per-process rather than stamped on each event, so it stays recomputable. What is new is that the
// shared decoder rejoins `<unfinished ...>` clone lines, so a subtree whose fork edge was split
// across a context switch is now attributed instead of silently dropped.
const lifecycle = new Set(decoded.procs.filter((p) => p.life).map((p) => p.pid));

// ⛔ AN UNRESOLVABLE dirfd YIELDS "UNKNOWN", NEVER A GUESS, AND NEVER A SCOPE. When a `*at` syscall
// names a dirfd the decoder never saw opened (inherited across an exec it did not witness, or passed
// over `SCM_RIGHTS`), the only honest output is the raw relative path plus the fact that its base is
// unknown. The old decoder resolved such a path against the project root, which is how a file
// created somewhere else entirely became `<project>/H-symlinkat-dirfd` — a FABRICATED path that
// still classified into a scope and could still widen a grant on evidence that does not exist.
// These are counted, reported, and excluded from classification. A non-empty count is a decoding
// gap to close, not a capability to grant.
const unknownWrites = new Set();

// ⛔ WHICH OF A TWO-PATH CALL'S ENDS IS ACTUALLY MUTATED. The three disagree, and the disagreement
// is deliberate — each is pinned by its own test so the asymmetry reads as intentional rather than
// as an oversight someone should tidy up:
//
//   rename(old, new)   BOTH. It creates `new` AND unlinks `old`; each needs the grant on its own.
//   link(old, new)     `new` only. `old` is READ — its link count changes, its contents do not — so
//                      billing it as a write over-predicts by exactly one scope, and the scope it
//                      over-predicts into is whatever the source happened to live in.
//   mount(src, target) `target` only, on the same reasoning as link.
//
// `symlink` is absent because the shared decoder already resolves it correctly: `f` is the LINKPATH
// it creates and `g` is opaque link CONTENT the kernel stores verbatim and never resolves. Anything
// not listed here bills `f` and ignores `g` entirely, which is what keeps that content out.
// (Measured on `vanilla-cookieconsent@3.0.0-rc.9`: billing `symlink("../only-allow/bin.js", …)`'s
// first argument resolved the CONTENT against the cwd and kept `write:{userHome}` alive by itself.)
const TWO_PATH_ROLES = {
  rename: { f: 'w', g: 'w' },
  link: { f: 'r', g: 'w' },
  mount: { f: 'r', g: 'w' },
};

for (const e of decoded.events) {
  if (e.o === 'connect') continue;                     // peers are collected below
  if (DENIED.test(e.r)) denials.add(`${e.s} ${e.f}${e.u ? ` (dirfd ${e.u}, UNRESOLVED)` : ''}`);
  if (e.r !== 0) continue;                             // failed calls are not a need
  const roles = TWO_PATH_ROLES[e.o];
  const parts = [];
  if (e.f != null) parts.push([e.f, e.u != null, roles ? roles.f === 'w' : e.w === 1]);
  if (roles && e.g != null) parts.push([e.g, e.u2 != null, roles.g === 'w']);
  for (const [path, unresolved, isWrite] of parts) {
    if (unresolved) { if (isWrite) unknownWrites.add(`${e.s} ${path} (dirfd ${e.u ?? e.u2})`); continue; }
    if (isWrite) allWrites.add(path);
    if (lifecycle.has(e.p)) (isWrite ? writes : reads).add(path);
  }
}

// ⛔ THE NETWORK SIGNAL IS COUNTED FROM THE RAW TEXT, NOT FROM THE EVENT STREAM, and deliberately so.
// The grant's `network` axis keys on `socket(AF_INET…)`, which the shared decoder does not emit —
// it retains `connect` peers only. Deriving `network` from connects instead would NARROW the signal
// (a socket opened but never connected, or a connect the decoder failed to rejoin, would stop
// earning the grant), and narrowing is the direction that breaks installs. So this stays byte-for-
// byte the predicate it has always been, over the same attributed pid set.
for (const m of text.matchAll(/^(\d+)?\s*socket\(AF_INET/gm)) {
  allSockets++;
  if (lifecycle.has(m[1] ? Number(m[1]) : 0)) sockets++;
}
// Peers are REPORT-ONLY and stay unattributed, as they have always been. The shared decoder captures
// the address and port independently, which is what stops strace's differing sockaddr member order
// between `sin_port`/`sin6_port` from silently reporting every peer on port 0.
for (const e of decoded.events) {
  if (e.o === 'connect' && e.h) hosts.add(`${e.h}:${e.pt ?? '?'}`);
}

// Classify a path against the scopes the CATALOG can express, so the output maps onto a grant
// rather than onto a pile of strings.
// ⛔ TWO SCOPES THE JAIL ALREADY GRANTS, WHICH THE NAIVE CLASSIFIER BILLED AS A CAPABILITY.
// Measured over the 9-package v2 agreement run: 4 of 9 over-predicted, every one of them here,
// and 3 of the 3 packages in the `network`-only band. Over-granting is safe but it defeats the
// point of a MINIMUM catalog, so these fall out of the grant entirely rather than being
// attributed to a scope. Each corresponds to a real base-profile grant in
// `crates/nub-sandbox/src/compiler/preset.rs`:
//
//   `jailHome`  — the jail REDIRECTS `HOME`/`USERPROFILE` to a per-package private home
//                 (`NUB_JAIL_HOME_ROOT_PATTERN` = `$cache/nub/jail-home`, resolved by
//                 `private_home_dir`, exported through `jail_private_home`, and RW-granted by
//                 `push_rw_path`). So a HOME-anchored write moves WITH `$HOME` and lands inside
//                 a directory the base profile already owns. `measure.sh` reproduces that
//                 redirect for the traced `npm rebuild`, so this bucket is exactly the set of
//                 writes that follow `$HOME` — the classifier no longer has to GUESS provenance.
//                 A write to the REAL user home survives as `userHome` and still earns a grant,
//                 which is what keeps this from becoming an UNDER-prediction.
//
//   `ownPkg`    — `store_entry_write_root` grants RW on the package's own store entry
//                 (`enclosing_node_modules(package_dir).parent()`, gated on its parent being the
//                 global store or the project-local `.store`). Under the isolated layout
//                 `<project>/node_modules/<pkg>` is a SYMLINK into that entry, so a write to the
//                 package's own directory resolves into granted space. A write to a SIBLING
//                 dependency does NOT, and stays `deps`.
//
//   `npmPrefix` — the ONE read-write carve-out inside nub's own tool cache.
//                 `grant_build_jail_dependency_reads` grants `$cache/nub/pm/tools` READ-ONLY and
//                 then `push_rw_path`s `$cache/nub/pm/tools/npm-prefix` on top, because
//                 `redirect_npm_prefix` points `npm_config_prefix` there and a prefix is a
//                 directory npm CREATES. ⛔ THE DISTINCTION IS NOT PEDANTRY, IT IS THE DIFFERENCE
//                 BETWEEN THE TWO REDIRECTS: `ms-playwright` and `electron-cache` sit under the
//                 read-only `tools` grant, so a write there is genuinely refused and genuinely
//                 needs `userHome`; `npm-prefix` is granted, so billing it would manufacture a
//                 `userHome` grant for a directory the jail hands the script for free. The scope is
//                 the exact leaf, never `tools` — a write grant over the whole directory would
//                 reach the node-gyp nub bootstraps for itself and executes on later installs.
//
//   `jailTmp`   — `TmpMode::Private`. `backend/mod.rs::make_private_tmp` creates a fresh per-run
//                 dir under the OS temp root, `backend/linux_landlock.rs` grants it READ-WRITE, and
//                 `backend/linux.rs::apply_landlock` points the child's `TMPDIR` at it. `measure.sh`
//                 reproduces both halves, so this bucket is the set of writes that follow `TMPDIR`.
//                 ⛔ IT IS NOT "anything under /tmp". The shared `/tmp` is NOT granted on the
//                 Landlock arm — there is no mount namespace to rebind it — so a script that
//                 HARDCODES `/tmp/foo` is refused in the jail and must stay in `outside`, where it
//                 is reported rather than silently absorbed. Only the per-run dir this driver
//                 created and exported is free, which is exactly the jail's own rule.
//
// ⛔ PYTHON BYTECODE IS DROPPED WHEREVER IT LANDS, AND THIS IS THE ONLY UNCONDITIONAL DROP HERE.
// It is tested FIRST, ahead of every root, because the bucket a `.pyc` would otherwise fall into is
// an accident of where the user's Node happens to be installed — under `$HOME` (`~/.nvm`, and this
// corpus VM until today) it bills `userHome`; under `/opt` or `/usr/local` it bills `outside`. The
// same package would then carry a different grant on two machines running identical code.
//
// ⛔ THE JUSTIFICATION IS TWO INDEPENDENT GROUNDS AND IT NEEDS BOTH. Either alone would be a bad
// reason to discard an observed write, because dropping a write a scope COULD have satisfied is an
// under-prediction — the one direction this system may not take.
//
//   1. MEASURED, on this corpus, `lmdb-store@2.0.0-alpha2` under a real Landlock jail with the
//      bytecode caches cleared in both node-gyp trees first (a warm cache makes the observation
//      vacuous — every `.pyc` is then a READ that succeeds, which is consistent with the write
//      being suppressed AND with it never being attempted):
//        mkdir attempts for a __pycache__ dir   total: 10   refused: 10   (= -1 EACCES)
//        .pyc files created on disk after the run: 0
//        install rc=0
//      Controls in the same trace: python execve 5, gyp/pylib source reads 40, and 344 EACCES/EPERM
//      overall, so the tracer was live and refusals were observable. A capability whose absence does
//      not change the outcome is not a capability the package needs.
//
//   2. LANGUAGE-LEVEL, which is what makes generalizing from that one measurement sound. CPython
//      compiles to bytecode in memory when it cannot write the cache; the import simply proceeds.
//      That is a property of the interpreter, not a per-package accident, so it holds for every
//      package whose build shells out to Python — which on this corpus means every node-gyp build.
//
// ⛔ WHAT THIS DELIBERATELY IS NOT: a general "the preset already covers it, so drop it" rule. That
// broader bucket was proposed and is WRONG, because the scopes do not compile to what it assumes.
// `Scope::Deps` (`compiler/curated.rs`) resolves each DECLARED dependency through the store and
// `push_rw`s it, explicitly UNclamped to the project — so for a package that declares `node-gyp`,
// `deps` really does grant rw over the tree these writes target. `Scope::UserHome` expands to
// `home_minus_secrets_allows(..., ReadWrite)`, which covers the interpreter closure whenever Node
// lives under `$HOME`. And the compiled policy is a pure allowlist with the deny floor stripped
// (`enforce_pure_allowlist`), so grants UNION: a read-only preset rule does not veto an rw scope
// rule over the same path. A blanket drop would therefore discard writes a scope could have
// satisfied. Bytecode is exempt only because ground 2 says the write is never load-bearing at all.
// ⇒ Any further drop class needs its own "refused, and rc=0 anyway" measurement with a control.
const isBytecode = (p) => /(^|\/)__pycache__(\/|$)/.test(p) || /\.py[co]$/.test(p);

// Ordered before the `proj` test on purpose: `ownPkgDir` is a subtree of the project.
const scope = (p) => {
  if (isBytecode(p)) return 'bytecode';
  if (ownPkgDir && (p === ownPkgDir || p.startsWith(`${ownPkgDir}/`))) return 'ownPkg';
  if (jailHome && (p === jailHome || p.startsWith(`${jailHome}/`))) return 'jailHome';
  if (jailTmp && (p === jailTmp || p.startsWith(`${jailTmp}/`))) return 'jailTmp';
  // Before the `tools`-wide answer below it would ever be reached, and before `home`: the leaf is
  // nested inside both, and only the leaf is writable.
  if (jailNpmPrefix && (p === jailNpmPrefix || p.startsWith(`${jailNpmPrefix}/`))) return 'npmPrefix';
  // ⛔ THE `/node_modules/` TEST RUNS ON THE SUFFIX AFTER `proj`, NEVER ON THE WHOLE PATH, and
  // MAPPING.md rule 2 names this exact anti-pattern: "A rule like 'contains `/node_modules/`' is
  // not deterministic: it depends on where the fixture happened to live." Testing `p` whole is
  // that bug — a fixture root that itself contains `/node_modules/` bills every project SOURCE
  // file as `deps`. PROVEN with the two roots side by side: under `/tmp/v2m-abc/fx` a source file
  // classifies `project`, under `/tmp/x/node_modules/fx` the same file classifies `deps`, and on
  // the suffix both give `project` while a real dependency still gives `deps`.
  //
  // The direction is what makes it worth a line rather than a note: `deps` costs 3 and `project`
  // costs 5, so the misclassification synthesizes the CHEAPER grant — an UNDER-grant, the one
  // direction this system may not take. Inert as measured today only because the driver roots
  // fixtures at `$HOME/v2-XXXXXX`; that is an accident of the driver, not a property of this file.
  if (proj && p.startsWith(proj)) {
    return p.slice(proj.length).includes('/node_modules/') ? 'deps' : 'project';
  }
  if (home && p.startsWith(home)) return 'userHome';
  if (p.startsWith('/proc') || p.startsWith('/sys') || p.startsWith('/dev')) return 'kernelfs';
  return 'outside';
};
// The buckets a base-profile grant already covers. Named once so the report and the synthesized
// grant cannot disagree about which writes are free.
const BASE_COVERED = ['ownPkg', 'jailHome', 'jailTmp', 'npmPrefix'];
// ⛔ `bytecode` IS NOT IN `BASE_COVERED`, AND THE DISTINCTION IS THE POINT. A base-covered write is
// one the jail GRANTS; a bytecode write is one the jail REFUSES and the build survives without.
// Collapsing them into one list would make the report claim the jail hands these paths over, which
// is the opposite of what was measured. They are excluded from the grant for different reasons, so
// they are named separately and reported with different words.
const NOT_BILLED = [...BASE_COVERED, 'bytecode'];
const bucket = (set) => {
  const out = {};
  for (const p of set) (out[scope(p)] ??= []).push(p);
  return out;
};

const w = bucket(writes);
console.log(`== ATTRIBUTION == attributed pids: ${lifecycle.size}`);
console.log(`  writes  script ${writes.size}  /  whole traced tree ${allWrites.size}`);
console.log(`  sockets script ${sockets}  /  whole traced tree ${allSockets}`);
// ⛔ THE DECODER'S OWN SHORTFALLS, PRINTED. A line the decoder could not parse, a syscall it does
// not map, or an argument strace truncated is a path that may be MISSING from the grant below — and
// a missing path is an under-grant. These are the numbers that say how much to trust the answer.
const ds = decoded.stats;
if (ds.unparsed) console.log(`  ⛔ ${ds.unparsed} trace lines the decoder could not parse`);
// ⛔ SAME MARKER NAME AS THE macOS DRIVER, DELIBERATELY, so `record.mjs` needs ONE parser rather than
// a second spelling of the same fact — the divergence the marker-contract test now guards against.
// The two lanes reach it for different reasons: macOS because `posix_spawn addchdir_np` changes
// directory in-kernel and emits no chdir syscall at all, Linux because a LOST CLONE EDGE leaves a
// child re-anchored on the project it was never observed to reach. The consequence is identical — a
// relative path resolved against a base we did not see — and so is the direction: billing it under
// the project reads cheaper than the truth, which is an under-grant.
if (ds.cwdUnobserved) {
  console.log(`  ⛔ CWD-UNOBSERVED ${ds.cwdUnobserved} relative path(s) (${ds.cwdUnobservedWrites} write(s)) came from a`);
  console.log('     process whose own cwd was never observed. The paths are KEPT and marked rather');
  console.log('     than dropped or guessed silently, but they are not evidence of WHERE a write');
  console.log('     landed, so a grant resting on one is not measured.');
}
if (ds.truncatedArg) console.log(`  ⛔ ${ds.truncatedArg} arguments strace TRUNCATED — those paths are incomplete`);
if (unknownWrites.size) {
  console.log(`  ⛔ ${unknownWrites.size} WRITES with an UNRESOLVED dirfd — base unknown, so NOT classified`);
  console.log('     and NOT granted. They are a decoding gap, not a capability. Never guessed:');
  [...unknownWrites].slice(0, 10).forEach((p) => console.log(`      ${p}`));
}
if (lifecycle.size === 0) {
  // Not a package with no needs — a parse failure. Saying so beats emitting an empty grant that
  // looks like a confident "needs nothing".
  console.log('  ⛔ NO LIFECYCLE SHELL FOUND — the subtree filter matched nothing, so the grant');
  console.log('     below is EMPTY BY DEFAULT rather than by measurement. Treat it as UNKNOWN.');
}
// ⛔ ECHO THE ROOTS THE GRANT WAS COMPUTED AGAINST. Two jobs, and the second is the reason it is
// printed rather than merely held: it makes R2 auditable from `driver.out` alone — a reader can see
// that every root came from the capture, and can tell a `null` (this platform has no such root)
// from a path. A venue difference then shows up as different ROOTS in the log rather than as an
// unexplained difference in the grant.
//
// ⛔ `globalStore`, `projectStore` and `interpreter` are DECLARED AND REPORTED BUT NOT YET KEYED ON,
// and saying so is deliberate. R1 requires them declared; changing which bucket a write lands in is
// a grant-semantics change and needs its own evidence, exactly as the bytecode drop did. The
// OBSERVE arm is `npm rebuild` in a plain hoisted layout, so it does not touch nub's store at all —
// inventing a bucket for a path this arm never produces would be policy with no measurement under
// it. They are here so the next person has the roots without re-deriving them from ambient state.
console.log('== ROOTS (from capture.json — R2: no ambient reads) ==');
for (const k of REQUIRED_ROOTS) {
  const keyed = ['project', 'home', 'jailHome', 'temp', 'npmPrefix', 'ownPkg'].includes(k);
  console.log(`  ${k.padEnd(13)} ${roots[k] ?? '(null)'}${keyed ? '' : '   [declared, not keyed on]'}`);
}
console.log('== WRITES the script actually performed ==');
for (const [k, v] of Object.entries(w)) {
  const free = BASE_COVERED.includes(k) ? '  (base profile already grants this — NOT billed)'
    : k === 'bytecode' ? '  (jail REFUSES these and the build succeeds anyway — NOT billed)' : '';
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}${free}`);
  // Dump a sample of every bucket that is either unclassifiable or excluded from the grant. The
  // excluded ones are the evidence that the exclusion is honest: a reader can see the paths and
  // check them against the base profile instead of taking the classifier's word for it.
  if (k === 'outside' || k === 'kernelfs' || NOT_BILLED.includes(k)) {
    v.slice(0, 10).forEach((p) => console.log(`      ${p}`));
    if (v.length > 10) console.log(`      … and ${v.length - 10} more`);
  }
}
console.log('== NETWORK ==');
console.log(`  AF_INET sockets: ${sockets}   distinct peers: ${hosts.size}`);
[...hosts].slice(0, 10).forEach((h) => console.log(`      ${h}`));
console.log('== REFUSALS (only `= -1 EACCES/EPERM/EROFS`) ==');
console.log(`  distinct: ${denials.size}`);
[...denials].slice(0, 15).forEach((d) => console.log(`      ${d}`));

// The synthesized grant: the NARROWEST catalog entry covering everything observed.
const g = {};
if (w.deps) g.write = { ...(g.write ?? {}), deps: true };
if (w.project) g.write = { ...(g.write ?? {}), project: true };
if (w.userHome) g.write = { ...(g.write ?? {}), userHome: true };
if (sockets > 0) g.network = true;

// ── `writePaths`, DERIVED FROM THE PRIVATE HOME AND FROM NOTHING ELSE ──────────────────────────
//
// ⛔ THIS IS NOT A NARROWER SPELLING OF `write:{userHome}`, AND READING IT AS ONE SHIPS AN
// UNDER-GRANT. nub's `persist_declared_home_writes` grants nothing: after the lifecycle scripts
// finish it renames `private_jail_home/<rel>` to `real_home/<rel>` for each declared entry. So an
// entry can only ever move something that ALREADY LANDED in the throwaway home — which is the
// `jailHome` bucket above, and only that bucket.
//
// The two home buckets therefore have opposite answers, and the classifier already tells them apart
// because this driver redirects `HOME` for the traced run exactly as the jail does:
//
//   jailHome  the write FOLLOWED `$HOME`. It succeeds in the jail and is then DISCARDED with the
//             throwaway home, so nothing is refused and no scope is earned — what is lost is the
//             artefact. Declaring it here is the only thing that keeps it. ⇒ the input below.
//   userHome  the write named the REAL home by ABSOLUTE path. In the jail it is REFUSED unless
//             `write:{userHome}` is granted, and promotion cannot help because there is nothing of
//             its in the private home. ⇒ the scope STAYS, and `refuseUserHome` says so in the log.
//
// MEASURED, both halves, on this corpus: `@pulumi/gcp@0.16.9` wrote `/home/runner/.pulumi/...` with
// `HOME` pointed at the jail home (so it resolves the home some way other than `$HOME`), and the two
// playwright packages write into `$HOME/.cache/nub/pm/tools/ms-playwright` because nub itself sets
// `PLAYWRIGHT_BROWSERS_PATH` to that absolute path. Both are `userHome`, and a `writePaths` entry
// naming those directories would move nothing while removing the grant that makes the write legal.
//
// ⛔ AND THE DESCENT NEVER TESTS THIS FIELD, DELIBERATELY. `measure.sh`'s `descend` enumerates
// `no-network` and `no-write-<scope>` only, so `writePaths` rides through every arm unchanged. That
// is correct rather than an omission: a missing promotion does not fail the INSTALL — it fails the
// package at RUN time, long after any arm has exited — so an arm could not detect its absence and a
// `no-writePaths` arm would report "droppable" for every package on earth.
const privateHomeRels = (w.jailHome ?? [])
  .map((p) => relativizeUnder(p, jailHome))
  .filter(Boolean);
const wp = deriveWritePaths(privateHomeRels, { version: pkgVersion });
if (wp.paths.length) g.writePaths = wp.paths;

console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
console.log('  ' + JSON.stringify(g));
if (w.outside) console.log(`  ⛔ ${w.outside.length} writes OUTSIDE project/home — no scope covers these; inspect before granting`);
if (w.kernelfs) console.log(`  NOTE ${w.kernelfs.length} kernel-fs touches (/proc,/sys,/dev) — a READ floor question, not a write grant`);

// ⛔ THE DERIVATION SHOWS ITS WORK, INCLUDING WHEN IT DECLARES NOTHING. A silent empty is
// indistinguishable from "this file does not derive writePaths at all", which is the state this
// section replaced — and a reader auditing a `write:{userHome}` entry has to be able to see that the
// question was asked and how it was answered.
console.log('== writePaths (DERIVED — promotion out of the package\'s PRIVATE home) ==');
console.log(`  private-home writes observed: ${privateHomeRels.length}`);
if (wp.paths.length) {
  wp.paths.forEach((p) => console.log(`      ${p}`));
  if (wp.pinned.length) {
    console.log(`  ⛔ VERSION-PINNED: ${wp.pinned.join(', ')} embed the measured version ${pkgVersion}`);
    console.log('     — the directory MOVES on the next release; the collator records a re-measure note.');
    console.log(`  WRITEPATHS-VERSION-PINNED ${JSON.stringify(wp.pinned)}`);
  }
} else {
  console.log(`  none declared — ${wp.refused}`);
}
if (w.userHome) {
  console.log(`  ${refuseUserHome(w.userHome.length).refused}`);
}

// The RAW candidate listing, kept as it was. It answers a different question from the derivation
// above — "what did this package touch outside project/deps at all", including the `outside` writes
// that no scope covers and no promotion can reach — and it is the listing a human reads when the
// derivation declines. A version- or PID-stamped directory name is far easier to spot here than by
// any heuristic, so the paths stay printed rather than being summarised away.
const enumerable = [...(w.userHome ?? []), ...(w.outside ?? [])];
console.log('== writePaths FEASIBILITY (distinct writes outside project/deps) ==');
console.log(`  count: ${enumerable.length}`);
enumerable.slice(0, 40).forEach((p) => console.log(`      ${p.startsWith(home) ? p.slice(home.length + 1) : p}`));
if (enumerable.length > 40) console.log(`      … and ${enumerable.length - 40} more`);

// The FULL attributed write set, one `WRITE\t<scope>\t<path>` line each, behind an env flag. Off by
// default because the human-readable report above is what a driver log wants — but the report prints
// a COUNT plus ten examples per bucket, which is exactly why the question "did this decoder change
// lose a path?" could not be answered against a real package without re-measuring it. With this,
// two decoders can be diffed on one trace. It is the instrument the 18-of-26 defect was measured
// with; committing it means the next such question costs a re-run of this script, not a re-install.
if (process.env.NUB_V2_DUMP_WRITES) {
  for (const p of [...writes].sort()) console.log(`WRITE\t${scope(p)}\t${p}`);
}
