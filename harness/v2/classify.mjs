// EVENT stream -> grant. The shared half of the mapping, per MAPPING.md.
//
// observe.mjs is the Linux adapter AND classifier fused together, because on Linux the trace
// format and the classifier arrived at the same time. Windows cannot reuse it: its adapter
// (adapters/windows.mjs) already emits the normalized EVENT contract, so what is missing is the
// half after the arrow. This file is that half, written against EVENT alone -- it never looks at
// a trace format, so the Linux adapter can be pointed at it later without changing a line here.
//
//   usage: node classify.mjs <events.ndjson> --capture <capture.json> [--platform win32]
//                            [--json out.json]
//
// Determinism rules 1-5 (MAPPING.md) are the whole specification. Where this file departs from
// observe.mjs the departure is a rule, not a preference:
//
//  * rule 1  normalize BEFORE classifying. Windows and macOS case-fold, Linux does not; the
//            kernel emits both `C:\d` and `C:\d\` for one directory. Both are handled once, here.
//  * rule 2  scope is LONGEST-PREFIX against roots taken from `capture.json`, never a substring
//            like "contains node_modules". Roots are ordered longest-first so the package dir
//            nested inside the project resolves the same way every time.
//  * rule 3  a path that maps to no scope is REPORTED, never rounded up to write:"disk".
//
// ⛔ EVERY ROOT COMES FROM `capture.json`, AND NOTHING ELSE MAY SUPPLY ONE (VENUE-PORTABILITY R2).
// This used to take `--project`/`--home` as arguments, and the Windows driver filled `--home` from
// `process.env.USERPROFILE` — an AMBIENT read of whatever machine happened to be classifying. Two
// records produced on different venues were then indistinguishable in the record AND classified
// against different roots, so a divergence between them could be neither detected nor attributed.
//
// ⛔ A NEEDED ROOT THAT `capture.json` DOES NOT DECLARE IS A HARD ERROR, NEVER A FALLBACK. A
// fallback is exactly what makes a venue difference silent: it keeps running and emits a grant, so
// the failure surfaces as a wrong catalog entry rather than as a crash. Absent and `null` are
// different and are treated differently — `null` is the capture SAYING this platform has no such
// root, which is an answer; an absent key is the capture failing to say, which is not.
import fs from 'node:fs';
import { deriveWritePaths, refuseUserHome, relativizeUnder } from './write-paths.mjs';
import { marker as observedEffectMarker, effectWrites } from './observed-effect.mjs';

const args = process.argv.slice(2);
const val = (f, d) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : d; };
const file = args.filter((a, i) => !a.startsWith('--') && !(i > 0 && args[i - 1].startsWith('--')))[0];
const capturePath = val('--capture');
const platform = val('--platform', process.platform);
const jsonOut = val('--json');
if (!file || !capturePath) {
  console.error('usage: classify.mjs <events.ndjson> --capture <capture.json> [--platform p] [--json f]');
  process.exit(2);
}

// The list lives HERE, not in the driver: this file is what would misclassify without a root, so
// this is the file that must refuse to run. Eleven roots are REQUIRED; five are keyed on below.
// That is deliberate and matches the Linux and macOS classifiers — a root re-derived later is a
// root re-derived from ambient state, and changing which bucket a path lands in is a grant-semantics
// change that needs its own evidence rather than arriving as a side effect of declaring a root.
//
// ⛔ `npmCache` JOINED THIS LIST BECAUSE THE DRIVER WAS ALREADY REDIRECTING THERE. A directory the
// driver POINTS THE MEASURED INSTALL AT and does not DECLARE is the one shape this file cannot
// recover from: the redirect target matches no root, so the classifier bills its own apparatus as a
// write it cannot account for. `measure-windows.mjs` has set `npm_config_cache` to `<run-root>\
// npm-cache` since the arm was given a cold cache, and that path is a SIBLING of `observe`, `tmp`
// and `jailhome` — so every write npm made under it could only ever land in `outside`.
const REQUIRED_ROOTS = ['project', 'home', 'jailHome', 'globalStore', 'projectStore',
                        'interpreter', 'toolsDir', 'temp', 'npmPrefix', 'npmCache', 'ownPkg'];
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
const project = roots.project;
const home = roots.home;
// The MEASURED version, used for one thing only: saying whether a derived `writePaths` entry embeds
// it and therefore stops matching on the next release. Never used to guess a path. Same field, same
// single purpose, as `observe.mjs` and `observe-macos.mjs`.
const pkgVersion = capture.version ?? null;
// The two that ARE keyed on must be real paths, not `null`. A `null` reaching `startsWith` below
// would match the literal string "null" and silently misclassify — the failure mode the macOS
// classifier documents and guards the same way.
for (const k of ['project', 'home']) {
  if (typeof roots[k] !== 'string' || !roots[k]) {
    console.error(`⛔ capture.json declares \`${k}\` as ${JSON.stringify(roots[k])}; this classifier keys on it and cannot proceed`);
    process.exit(3);
  }
}

const WIN = platform === 'win32';
const FOLD = WIN || platform === 'darwin';

// Rule 1. One normalizer, applied to every path before anything else looks at it.
const norm = (p) => {
  if (!p) return p;
  let s = WIN ? p.replace(/\//g, '\\') : p;
  const sep = WIN ? '\\' : '/';
  // The kernel emits a directory both with and without its trailing separator. Same path.
  if (s.length > 3 && s.endsWith(sep)) s = s.slice(0, -1);
  const parts = s.split(sep);
  const out = [];
  for (const seg of parts) {
    if (seg === '.') continue;
    if (seg === '..') { if (out.length > 1) out.pop(); continue; }
    out.push(seg);
  }
  s = out.join(sep);
  return FOLD ? s.toLowerCase() : s;
};

// Non-filesystem namespaces the classifier must NOT round into a write grant (rule 3). On Linux
// this is /proc,/sys,/dev; on Windows it is the NTFS metadata files the filesystem writes in the
// requesting thread's context, plus unmapped NT device paths.
const isKernelFs = (p) => WIN
  ? /^[a-z]:\\\$(mft|logfile|extend|bitmap|secure|volume)/i.test(p) || p.startsWith('\\device\\') || p.startsWith('\\??\\')
  : /^\/(proc|sys|dev)(\/|$)/.test(p);

const isSystemFs = (p) => WIN
  ? /^[a-z]:\\(windows|program files|program files \(x86\)|programdata)(\\|$)/i.test(p)
  : /^\/(usr|bin|sbin|lib|lib64|etc|opt)(\/|$)/.test(p);

// Rule 2. Roots come IN, longest-first, first match wins. `deps` must precede `project` because
// it is nested inside it; a longest-first sort gets that right without special-casing.
//
// ⛔ `jailTmp` IS KEYED ON THE PATH `capture.json` DECLARES, NEVER ON "looks like temp", AND THAT IS
// THE WHOLE SAFETY OF THIS BUCKET. The build-jail preset sets `fs["$tmp"] = "rw"` unconditionally
// (`compiler/preset.rs`), so `TmpMode::Private` gives every confined script a fresh per-run temp
// directory and `backend/mod.rs::set_tmp_env` points `TMP`/`TEMP`/`TMPDIR` at it. A write that
// FOLLOWS that variable therefore needs no capability at all, and billing it is pure noise — on
// Windows especially, where `%TEMP%` sits INSIDE `%USERPROFILE%` and so billed `write.userHome` for
// every package that touched temp.
//
// ⛔ BUT A SCRIPT THAT HARDCODES A TEMP PATH IS A DIFFERENT CASE AND MUST STILL BILL. `C:\Windows\Temp\foo`
// (or `/tmp/foo` on POSIX) is not the jail's private temp; the jail hides the shared one, so that
// write is genuinely refused and is a genuine capability need. A heuristic that dropped anything
// temp-shaped would silently under-grant exactly those packages. Only the exact declared root is
// free, which is the jail's own rule rather than an approximation of it. Same reasoning, same
// spelling and the same hazard note as `observe.mjs` and `observe-macos.mjs`.
//
// ⛔ `jailHome` IS THE SAME CONSTRUCTION AND CARRIES THE SAME HAZARD, ONE SCOPE UP. The jail gives a
// confined script a private per-package home (`compiler/preset.rs::private_home_dir`) and repoints
// `HOME`/`USERPROFILE`/`APPDATA` at it, so a write that FOLLOWED one of those variables lands in
// space the base profile already grants read-write. Keyed on the path `capture.json` declares and
// never on "looks like a home": a script that spells the REAL home out absolutely is writing
// somewhere the jail does not grant, so that write still bills `userHome` and still earns the scope.
// The two buckets then have OPPOSITE answers for `writePaths` — see the derivation below.
//
// ⛔ `npmCache` IS THE THIRD OF THE SAME CONSTRUCTION, AND IT WAS THE ONE THE DRIVER REDIRECTED
// WITHOUT DECLARING. `measure-windows.mjs` sets `npm_config_cache` to a per-run directory so the
// OBSERVE arm gets the COLD npm cache a real user has — without it a lifecycle script that fetches
// its payload finds it already staged, the trace records no `connect`, and the grant omits
// `network`, which is the under-grant direction. That redirect target is a sibling of `observe`,
// `tmp` and `jailhome`, so with no root declared for it EVERY write npm made under it fell through
// to `outside` — the classifier billing its own apparatus. Keyed on the declared path and never on
// "looks like a cache": a script that hardcodes some other cache directory is writing somewhere the
// jail does not grant, and must keep billing what it really costs.
const ROOTS = [
  ...(roots.temp ? [{ name: 'jailTmp', path: norm(roots.temp) }] : []),
  ...(roots.jailHome ? [{ name: 'jailHome', path: norm(roots.jailHome) }] : []),
  ...(roots.npmCache ? [{ name: 'npmCache', path: norm(roots.npmCache) }] : []),
  { name: 'deps', path: norm(project + (WIN ? '\\node_modules' : '/node_modules')) },
  { name: 'project', path: norm(project) },
  { name: 'userHome', path: norm(home) },
].sort((a, b) => b.path.length - a.path.length);
const jailHomeRoot = roots.jailHome ? norm(roots.jailHome) : null;

// The buckets a base-profile grant already covers. Named once so the report and the synthesized
// grant cannot disagree about which writes are free.
//
// ⛔ NO `toolsRw` BUCKET HERE, AND THE ABSENCE IS MEASURED RATHER THAN ASSUMED. Both POSIX
// classifiers carve the three tool-cache read-write leaves — `$cache/nub/pm/tools/{npm-prefix,
// ms-playwright,electron-cache}`, `push_rw_path`ed together in `preset.rs` — out of `userHome`,
// because their drivers reproduce the three redirects that send a package there and a write that
// lands in one is free. THIS DRIVER REPRODUCES NONE OF THEM: `measure-windows.mjs` sets no
// `PLAYWRIGHT_BROWSERS_PATH`, no `ELECTRON_CACHE`/`electron_config_cache` and no
// `npm_config_prefix`, and says so where it declares `npmPrefix: null`. A package cannot reach
// those directories without the redirect — the paths are nub's own and no package hardcodes them —
// so there is nothing to carve out and adding a bucket would be policy with no path under it.
//
// CHECKED against the committed corpus: 0 of the win32-x64 `driver.out` files carry a tool-cache
// WRITES row, against 7 on POSIX. Restore this bucket if and when the Windows driver starts
// reproducing the redirects — at which point `toolsDir`, already declared and unkeyed, is the root
// to derive the leaves from, exactly as `observe.mjs` does.
//
// ⛔ `npmCache` IS IN THIS LIST, AND THE GROUND IS NUB'S SOURCE RATHER THAN THE SHAPE OF THE PATH.
// The question a `BASE_COVERED` entry answers is not "did the harness redirect it" — that only says
// where the OBSERVE arm wrote — but "does the jail hand a confined script the corresponding
// directory for free". For npm's cache the answer is yes, in three steps, none of them inferred:
//
//   1. nub sets no `npm_config_cache`, ever. `build_jail.rs` redirects `npm_config_prefix` and sets
//      `npm_config_nodedir` / `npm_config_python`; the cache key appears in neither
//      `compiler/preset.rs` nor `build_jail.rs`. So a confined script resolves its cache the way
//      npm resolves it by default.
//   2. npm's default resolves INTO the private jail home. `preset.rs` repoints `HOME`,
//      `USERPROFILE` **and** `APPDATA` at `private_home_dir()`, `APPDATA` at the `AppData\Roaming`
//      leaf — and its own comment gives npm's cache as the whole reason for the third: "npm on
//      Windows resolves its cache to `%APPDATA%\npm-cache`, not to `$HOME/.npm` as on POSIX …
//      every lifecycle script shelling out to npm or prebuild-install takes `EPERM: mkdir
//      …\AppData\Roaming\npm-cache`. That was 14 of 63 Windows corpus breaks."
//   3. That destination is READ-WRITE at the base profile: `preset.rs` does
//      `if let Some(dir) = private_home { fs.insert(dir, "rw") }`, and `AppData\Roaming` sits
//      inside it, so it rides that grant rather than emitting a rule of its own.
//
// ⇒ the write npm makes here costs no catalog scope in the jail, exactly as `jailTmp` and
// `jailHome` do, and the harness's `npm_config_cache` redirect is apparatus standing in front of a
// directory the jail already grants.
//
// ⛔ AND THE PERMISSIVE DIRECTION CANNOT COST ANYTHING HERE, WHICH IS WHY THIS ENTRY IS SAFE TO MAKE
// RATHER THAN MERELY DEFENSIBLE. The synthesized grant below is built from `w.deps`, `w.project`
// and `w.userHome` and from nothing else, so `outside` — where every one of these writes lands
// today — already contributes zero. Moving them into a bucket cannot make any grant NARROWER in
// either direction of this decision; what the list membership changes is what the REPORT claims,
// and claiming the jail covers a path it did not would be the lie worth avoiding. The measurement
// backing that: re-classifying every archived win32 record that carries an `outside` write row,
// before and after, moves no grant at all.
const BASE_COVERED = ['jailTmp', 'jailHome', 'npmCache'];

const under = (p, root) => p === root || p.startsWith(root + (WIN ? '\\' : '/'));

const scopeOf = (p) => {
  for (const r of ROOTS) if (under(p, r.path)) return r.name;
  if (isKernelFs(p)) return 'kernelfs';
  if (isSystemFs(p)) return 'systemfs';
  return 'outside';
};

// ⛔ ATTRIBUTION IS NOT OPTIONAL, AND ITS ABSENCE IS A SILENT 100% OVER-PREDICTION. The trace
// carries the package manager's own work as well as the lifecycle script's, and path text cannot
// tell them apart -- npm opens registry TLS sockets and writes its cache and logs under the user
// profile on every run. Without a subtree filter EVERY package synthesizes `write:userHome` +
// `network:true` regardless of what its script does, which also makes the per-path question
// (can `writePaths` replace a disk grant?) unanswerable.
//
// The Linux extractor keys on `sh -c`. Windows has no `-c` to key on, because the EVENT contract
// carries no command line -- so the equivalent is structural: npm reaches a lifecycle script
// through `cmd.exe`, and the traced ROOT is itself a cmd.exe (the launcher). The lifecycle shells
// are therefore every cmd.exe exec that is NOT the root, and the attributed set is the union of
// the subtrees rooted at them. Verified against the dprint trace in README-windows.md, where this
// admits the install.js/powershell/download subtree and excludes npm's own registry connection.
const rootPid = Number(val('--root-pid', '0'));
const SHELL = /(^|\\)cmd\.exe$/i;

const parsed = [];
let n = 0, bad = 0;
for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  let e;
  try { e = JSON.parse(line); } catch { bad++; continue; }
  n++;
  parsed.push(e);
}

// Build the process tree first: an event's attribution depends on an exec that may appear later
// in the stream, so a single streaming pass would mis-attribute whatever preceded it.
const parentOf = new Map(), imageOf = new Map();
for (const e of parsed) {
  if (e.op !== 'exec') continue;
  if (!parentOf.has(e.pid)) parentOf.set(e.pid, e.ppid);
  imageOf.set(e.pid, norm(e.path));
}
const lifecycle = new Set();
for (const [pid, img] of imageOf) if (SHELL.test(img) && pid !== rootPid) lifecycle.add(pid);
// Descendants of a lifecycle shell are lifecycle. Iterate to a fixed point rather than assuming
// the exec stream is topologically ordered.
for (let changed = true; changed;) {
  changed = false;
  for (const [pid, ppid] of parentOf) {
    if (!lifecycle.has(pid) && lifecycle.has(ppid)) { lifecycle.add(pid); changed = true; }
  }
}

const writes = new Map(), reads = new Map(), denials = [], peers = new Set(), execs = [];
const allWrites = new Set(), allPeers = new Set();
for (const e of parsed) {
  const mine = lifecycle.has(e.pid);
  if (e.op === 'connect') { allPeers.add(`${e.host}:${e.port}`); if (mine) peers.add(`${e.host}:${e.port}`); continue; }
  if (e.op === 'exec') { execs.push({ path: e.path, pid: e.pid, ppid: e.ppid }); continue; }
  const p = norm(e.path);
  if (!p) continue;
  // Rule 4. Only a genuine refusal is a refusal; the adapter already applied its own predicate,
  // so a `denied` result here is authoritative and is NOT counted as a need. A refusal outside the
  // subtree is still recorded -- it is evidence about the environment, not about the package.
  if (e.result === 'denied') { denials.push({ op: e.op, path: p, scope: scopeOf(p), mine }); continue; }
  if (e.op === 'write') allWrites.add(p);
  if (!mine) continue;
  const t = e.op === 'write' ? writes : reads;
  t.set(p, (t.get(p) ?? 0) + 1);
}

const bucket = (m) => {
  const out = {};
  for (const p of m.keys()) (out[scopeOf(p)] ??= []).push(p);
  return out;
};
const w = bucket(writes), r = bucket(reads);

// The synthesized grant: the NARROWEST catalog entry covering everything observed.
//
// `write` implies `read` at its own scope and stating the redundant `read` is a PARSE ERROR, so a
// read scope is only emitted where the same scope has no write.
//
// ⛔ A BASE-COVERED BUCKET CONTRIBUTES NOTHING. `w.jailTmp` and `w.jailHome` are deliberately absent
// below: the jail grants both directories unconditionally, so there is no catalog scope to widen for
// them. They are still COUNTED and REPORTED, because "this package wrote 40 files into temp" is a
// fact a reader wants — they are only excluded from the grant.
const grant = {};
const wr = {};
if (w.deps) wr.deps = true;
if (w.project) wr.project = true;
if (w.userHome) wr.userHome = true;
if (Object.keys(wr).length) grant.write = wr;
if (peers.size > 0) grant.network = true;

// ── `writePaths`, DERIVED FROM THE PRIVATE HOME AND FROM NOTHING ELSE ──────────────────────────
//
// ⛔ THIS IS NOT A NARROWER SPELLING OF `write:{userHome}`, AND READING IT AS ONE SHIPS AN
// UNDER-GRANT. `build_jail.rs::persist_declared_home_writes` grants nothing: after the lifecycle
// scripts finish it renames `private_jail_home/<rel>` to `real_home/<rel>` for each declared entry,
// and its own header says Windows promotes through that same body. So an entry can only ever move
// something that ALREADY LANDED in the throwaway home — the `jailHome` bucket above, and only it.
//
//   jailHome  the write FOLLOWED `%USERPROFILE%`/`%APPDATA%`/`$HOME`. It succeeds in the jail and is
//             then DISCARDED with the throwaway home, so nothing is refused and no scope is earned —
//             what is lost is the artefact. Declaring it here is the only thing that keeps it.
//   userHome  the write named the REAL home by ABSOLUTE path. In the jail it is REFUSED unless
//             `write:{userHome}` is granted, and promotion cannot help because there is nothing of
//             its in the private home. ⇒ the scope STAYS, and `refuseUserHome` says so in the log.
//
// ⛔ THE ENTRIES THIS EMITS ON WIN32 ARE CASE-FOLDED, BECAUSE RULE 1 FOLDS EVERY PATH BEFORE ANYTHING
// LOOKS AT IT. `appdata/roaming/foo` rather than `AppData/Roaming/foo`. That is correct for the mover
// (NTFS is case-insensitive, and `deriveWritePaths` matches `sharedHomeRoots` case-insensitively too)
// and it is the SAME text a re-decode of the same archive produces, which is what R2 asks for.
// Un-folding would need a second, unfolded path vocabulary running beside the classified one — two
// spellings of every path, which is the drift this file is built to prevent.
const privateHomeRels = (w.jailHome ?? [])
  .map((p) => relativizeUnder(p, jailHomeRoot))
  .filter(Boolean);
const wp = deriveWritePaths(privateHomeRels, { version: pkgVersion });
if (wp.paths.length) grant.writePaths = wp.paths;

const report = {
  events: n, malformed: bad,
  // ⛔ THE RECORD SAYS WHAT IT WAS CLASSIFIED AGAINST. A grant is only interpretable against the
  // roots that produced it, and comparing two venues' grants means being able to see that they were
  // classified against correspondingly-shaped roots (the absolute paths necessarily differ).
  // Without this the acceptance test can tell you two grants disagree and never why.
  rootsFrom: capturePath,
  roots: Object.fromEntries(REQUIRED_ROOTS.map((k) => [k, roots[k] ?? null])),
  keyedOn: ROOTS.map((r) => r.name),
  // Which buckets were excluded from the grant because the base profile already covers them. A
  // reader comparing two records has to be able to tell a package that needed nothing from one whose
  // writes were all free, and the grant alone says `{}` for both.
  baseCovered: BASE_COVERED,
  // ⛔ THE DERIVATION SHOWS ITS WORK IN THE STRUCTURED OUTPUT TOO, AND THE REFUSAL IS THE PART THAT
  // MATTERS. `grant.writePaths` alone cannot tell "the question was asked and the answer was none"
  // from "this decoder does not derive writePaths at all" — which is exactly the state win32 was in.
  writePathsRefused: wp.refused,
  writePathsVersionPinned: wp.pinned,
  privateHomeWrites: privateHomeRels.length,
  lifecyclePids: lifecycle.size,
  attributedWrites: writes.size, allTreeWrites: allWrites.size,
  attributedPeers: peers.size, allTreePeers: allPeers.size,
  writes: Object.fromEntries(Object.entries(w).map(([k, v]) => [k, v.length])),
  reads: Object.fromEntries(Object.entries(r).map(([k, v]) => [k, v.length])),
  outsideWrites: (w.outside ?? []).slice().sort(),
  systemWrites: (w.systemfs ?? []).slice().sort(),
  kernelfsWrites: (w.kernelfs ?? []).length,
  peers: [...peers].sort(),
  denials,
  execDepth: (() => {
    const byPid = new Map(execs.map((e) => [e.pid, e]));
    let max = 0;
    for (const e of execs) { let d = 0, c = e; while (c && d < 20) { c = byPid.get(c.ppid); d++; } max = Math.max(max, d); }
    return max;
  })(),
  grant,
};

console.log('== ROOTS (from capture.json — R2: no ambient reads) ==');
for (const k of REQUIRED_ROOTS) {
  const keyed = ROOTS.some((r) => r.path === norm(roots[k] ?? '\0'));
  console.log(`  ${k.padEnd(13)} ${roots[k] ?? '(null — declared inapplicable)'}${keyed ? '   [keyed on]' : ''}`);
}
console.log(`== ATTRIBUTION == lifecycle pids: ${lifecycle.size} (root ${rootPid || 'UNSET'})`);
console.log(`  writes  script ${writes.size}  /  whole traced tree ${allWrites.size}`);
console.log(`  peers   script ${peers.size}  /  whole traced tree ${allPeers.size}`);
if (lifecycle.size === 0) {
  // Not a package with no needs -- a filter that matched nothing. Saying so beats emitting an
  // empty grant that reads as a confident "needs nothing".
  console.log('  !! NO LIFECYCLE SHELL FOUND -- the subtree filter matched nothing, so the grant');
  console.log('     below is EMPTY BY DEFAULT rather than by measurement. Treat it as UNKNOWN.');
}
console.log('== WRITES ==');
for (const [k, v] of Object.entries(w)) {
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
  if (k === 'outside' || k === 'systemfs') v.slice(0, 12).forEach((p) => console.log(`      ${p}`));
}
console.log('== READS ==');
for (const [k, v] of Object.entries(r)) console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
// ⛔ THE EFFECT CENSUS, OVER THE BUCKETS PRINTED ABOVE — BASE-COVERED ONES INCLUDED.
// `observed-effect.mjs` decides whether an empty grant measures the PACKAGE or the RUNNER, and a
// write into a free bucket is still the script doing its work. Counting only billed buckets would
// score a package whose whole product lands in the redirected private home as having done nothing,
// and would refuse a correct narrowing.
//
// ⛔ IT IS NOT THE PLAIN SUM: `effectWrites` drops the handful of paths the INSTRUMENT opens in every
// traced process, which are evidence that tracing is on rather than that the package did anything.
// The list and the measurement behind each entry live in `observed-effect.mjs`; it is shared so the
// three classifiers cannot come to disagree about what counts as an effect.
console.log(observedEffectMarker({
  lifecyclePids: lifecycle.size,
  writes: effectWrites(w),
  peers: peers.size,
}));
console.log('== NETWORK ==');
console.log(`  distinct peers: ${peers.size}`);
[...peers].slice(0, 12).forEach((h) => console.log(`      ${h}`));
console.log('== REFUSALS (adapter-classified) ==');
console.log(`  distinct: ${denials.length}`);
denials.slice(0, 15).forEach((d) => console.log(`      ${d.op} [${d.scope}] ${d.path}`));
console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
console.log('  ' + JSON.stringify(grant));
if (w.jailTmp) {
  console.log(`  NOTE ${w.jailTmp.length} writes into the DECLARED private temp -- the base profile grants`);
  console.log('       that directory unconditionally (preset.rs `$tmp`=rw), so they widen nothing.');
}
if (w.jailHome) {
  console.log(`  NOTE ${w.jailHome.length} writes into the DECLARED private home -- the base profile grants`);
  console.log('       that directory unconditionally (preset.rs `private_home_dir`), so they widen nothing.');
  console.log('       What they earn instead is a `writePaths` declaration; see the section below.');
}
if (w.npmCache) {
  console.log(`  NOTE ${w.npmCache.length} writes into the DECLARED per-run npm cache -- this driver sets`);
  console.log('       `npm_config_cache` there for a cold arm, and the jail resolves the same cache into');
  console.log('       the RW private home (preset.rs redirects APPDATA at it), so they widen nothing.');
  console.log('       No `writePaths` either: this is a CACHE, and the jail re-fills its own.');
}
if (w.outside) console.log(`  !! ${w.outside.length} writes OUTSIDE project/home -- no scope covers these; inspect before granting`);
if (w.systemfs) console.log(`  !! ${w.systemfs.length} writes into system dirs -- an unprivileged user would be refused these`);
if (w.kernelfs) console.log(`  NOTE ${w.kernelfs.length} kernel/metadata writes -- not a write-grant question (rule 3)`);

// ⛔ THE DERIVATION SHOWS ITS WORK, INCLUDING WHEN IT DECLARES NOTHING. A silent empty is
// indistinguishable from "this file does not derive writePaths at all", which is the state win32 was
// in for 2,270 records — and a reader auditing a `write:{userHome}` entry has to be able to see that
// the question was asked and how it was answered.
console.log('== writePaths (DERIVED -- promotion out of the package\'s PRIVATE home) ==');
console.log(`  private-home writes observed: ${privateHomeRels.length}`);
if (wp.paths.length) {
  wp.paths.forEach((p) => console.log(`      ${p}`));
  if (wp.pinned.length) {
    console.log(`  ⛔ VERSION-PINNED: ${wp.pinned.join(', ')} embed the measured version ${pkgVersion}`);
    console.log('     -- the directory MOVES on the next release; the collator records a re-measure note.');
    // The marker `record.mjs` parses off the driver log. One spelling, because there is one reader.
    console.log(`  WRITEPATHS-VERSION-PINNED ${JSON.stringify(wp.pinned)}`);
  }
} else {
  console.log(`  none declared -- ${wp.refused}`);
}
if (w.userHome) console.log(`  ${refuseUserHome(w.userHome.length).refused}`);

if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(report, null, 2));
