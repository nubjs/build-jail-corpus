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
//   usage: node observe.mjs <trace-file> <project-root> <home> [jail-home] [package-name] [jail-tmp]
//                           [jail-npm-prefix]
import fs from 'node:fs';
import { decode } from './adapters/linux.mjs';

const [file, proj, home, jailHome, pkgName, jailTmp, jailNpmPrefix] = process.argv.slice(2);
if (!file) { console.error('usage: observe.mjs <trace> <projectRoot> <home> [jailHome] [pkgName] [jailTmp] [jailNpmPrefix]'); process.exit(2); }
// The rebuilt package's OWN directory in the observation layout (plain hoisted `node_modules`).
// Its jail counterpart is the store entry, which the base profile already grants RW.
const ownPkgDir = proj && pkgName ? `${proj}/node_modules/${pkgName}` : null;
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
// Ordered before the `proj` test on purpose: `ownPkgDir` is a subtree of the project.
const scope = (p) => {
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
console.log('== WRITES the script actually performed ==');
for (const [k, v] of Object.entries(w)) {
  const free = BASE_COVERED.includes(k) ? '  (base profile already grants this — NOT billed)' : '';
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}${free}`);
  // Dump a sample of every bucket that is either unclassifiable or excluded from the grant. The
  // excluded ones are the evidence that the exclusion is honest: a reader can see the paths and
  // check them against the base profile instead of taking the classifier's word for it.
  if (k === 'outside' || k === 'kernelfs' || BASE_COVERED.includes(k)) {
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
console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
console.log('  ' + JSON.stringify(g));
if (w.outside) console.log(`  ⛔ ${w.outside.length} writes OUTSIDE project/home — no scope covers these; inspect before granting`);
if (w.kernelfs) console.log(`  NOTE ${w.kernelfs.length} kernel-fs touches (/proc,/sys,/dev) — a READ floor question, not a write grant`);

// Could an ENUMERATION replace a scope grant? Only if the set outside project/deps is small AND
// stable run to run. A version- or PID-stamped directory name makes it neither, so print the
// candidate paths — a human reading them can tell a fixed `~/.cache/foo` from a random temp name
// far more reliably than any heuristic here.
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
