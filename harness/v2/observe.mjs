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
//   usage: node observe.mjs <trace-file> <project-root> <home> [jail-home] [package-name]
import fs from 'node:fs';

const [file, proj, home, jailHome, pkgName] = process.argv.slice(2);
if (!file) { console.error('usage: observe.mjs <trace> <projectRoot> <home> [jailHome] [pkgName]'); process.exit(2); }
// The rebuilt package's OWN directory in the observation layout (plain hoisted `node_modules`).
// Its jail counterpart is the store entry, which the base profile already grants RW.
const ownPkgDir = proj && pkgName ? `${proj}/node_modules/${pkgName}` : null;
const lines = fs.readFileSync(file, 'utf8').split('\n');

// ⛔ ONLY `= -1 EACCES` IS A REFUSAL. A bare `grep EACCES` also matches the FLAG NAME `AT_EACCESS`
// in faccessat calls, which are ordinary successful probes. Measured on a real trace: the naive
// pattern reported 26 denials where 11 were real.
const DENIED = /=\s*-1\s+(EACCES|EPERM|EROFS)\b/;
// A write intent is visible in the OPEN FLAGS, not in a later write() — by then the fd hides the
// path. Creating, truncating or appending all count; O_RDONLY does not.
const WRITE_FLAGS = /O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)/;

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
const lifecycle = new Set();
const toolPids = new Set();
let started = false;
const SHELL_EXEC = /^execve\("[^"]*\/(?:sh|bash|dash)"[^)]*"-c"/;

// ⛔ RESOLVE RELATIVE PATHS OR THEY MATCH NO SCOPE. strace prints the path exactly as the syscall
// received it, so a script that chdir's into its own package dir and opens "../dist/app.js" yields
// a string that cannot be prefix-matched against ANY root. MEASURED on dotnet-2.0.0@1.4.4's first
// real run: four writes landed in the unclassifiable "outside" bucket for this reason alone, and
// the synthesized grant was wrong as a result. Determinism rule 1 — normalize BEFORE classifying —
// requires per-pid cwd tracking, inherited across fork.
const cwds = new Map();
const abs = (pid, p) => {
  if (!p) return p;
  if (p.startsWith('/')) return p;
  const parts = ((cwds.get(pid) ?? proj ?? '') + '/' + p).split('/');
  const out = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
};

// ⛔ `symlink`/`link`'s FIRST ARGUMENT IS NOT THE PATH BEING WRITTEN, AND BILLING IT AS ONE
// INVENTS A PATH THAT NO PROCESS EVER TOUCHED. `symlink(target, linkpath)` creates `linkpath`;
// `target` is opaque link CONTENT the kernel stores verbatim and never resolves at creation time.
// The generic `syscall("<first-quoted-arg>"` matcher above cannot tell the two apart, so it took
// the target.
//
// MEASURED on `vanilla-cookieconsent@3.0.0-rc.9`, and this single line was the whole residual that
// kept `write:{userHome}` alive after the `jailHome` redirect reclassified the other 51 writes:
//
//   symlink("../only-allow/bin.js", "<jailhome>/.npm/_npx/<hash>/node_modules/.bin/only-allow") = 0
//
// `../only-allow/bin.js` is relative, so `abs()` resolved it against the cwd fallback (`$OBS`) and
// produced `$ROOT/only-allow/bin.js` — a path under `$HOME`, outside `$OBS` and outside `$JAIL_HOME`,
// so it classified as `userHome` and earned a grant. The file the process actually created is the
// LINKPATH, which is inside the jail's private HOME and already RW-granted (`preset.rs`
// `private_home_dir` / `NUB_JAIL_HOME_ROOT_PATTERN`, granted through `push_rw_path`).
//
// THIS IS A PARSE CORRECTION, NOT AN EXCLUSION. Nothing is filtered by path shape: the linkpath is
// classified by the same scope function as every other write, so a script that symlinks into the
// REAL user home still lands in `userHome` and still earns the grant. `only-allow` is `npx
// only-allow <pm>`, a very common preinstall guard, so this reaches a whole family of packages.
//
// `rename(old, new)` is deliberately NOT in here: it UNLINKS `old` as well as creating `new`, so
// both arguments are genuine writes and taking the first is correct.
const LINK_TARGET_IS_CONTENT = /^(?:symlink|symlinkat|link|linkat)$/;
const linkTarget = (call, line) => {
  if (!LINK_TARGET_IS_CONTENT.test(call)) return null;
  // Take the LAST quoted argument: `symlink(t, l)`, `symlinkat(t, dirfd, l)`,
  // `linkat(olddirfd, o, newdirfd, n, flags)` all put the created path last.
  const quoted = [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((q) => q[1]);
  return quoted.length >= 2 ? quoted[quoted.length - 1] : null;
};

for (const raw of lines) {
  if (!raw) continue;
  // Keep the pid: cwd is per-process, so stripping it first loses the only key we have.
  const pidM = raw.match(/^(\d+)\s+/);
  const pid = pidM ? Number(pidM[1]) : 0;
  const line = raw.replace(/^\d+\s+/, '');

  const cd = line.match(/^f?chdir\("([^"]+)"\)\s*=\s*0/);
  if (cd) cwds.set(pid, abs(pid, cd[1]));
  // A child inherits the parent's cwd at fork; without this every grandchild resolves against the
  // wrong base, which is the common case since the interesting syscall is usually a grandchild.
  const cl = line.match(/^(?:clone3?|v?fork)\(.*\)\s*=\s*(\d+)/);
  if (cl) {
    if (cwds.has(pid)) cwds.set(Number(cl[1]), cwds.get(pid));
    // A child of the lifecycle shell IS lifecycle. The clone returns in the parent before the
    // child's first syscall is emitted, so propagating here is ordering-safe.
    if (lifecycle.has(pid)) lifecycle.add(Number(cl[1]));
  }
  if (SHELL_EXEC.test(line) && !line.includes('= -1')) { lifecycle.add(pid); started = true; }
  // ⛔ THE clone EDGE IS NOT ALWAYS IN THE TRACE, so a pure parent->child walk under-attributes to
  // exactly the shell and nothing below it. MEASURED on @nuxt/components@2.1.0: the lifecycle shell
  // was found, its `yarn` descendants were not, and the parser emitted `{}` — a confident "this
  // package needs nothing" for a package that does not even install at three grants above that.
  // glibc's posix_spawn issues CLONE_VM|CLONE_VFORK and libuv takes several spawn paths, so the
  // edge is missing rather than mis-parsed. FALLBACK, and it is a heuristic, not a derivation: once
  // the lifecycle shell has exec'd, attribute every pid not already seen as the package manager's.
  // Sound because npm's own pids all appear during the fetch/link phase that precedes the script.
  if (!started) toolPids.add(pid);
  const mine = lifecycle.has(pid) || (started && !toolPids.has(pid));

  const m = line.match(/^([a-z_0-9]+)\((?:AT_FDCWD,\s*)?"([^"]*)"/);

  if (DENIED.test(line) && m) denials.add(`${m[1]} ${abs(pid, linkTarget(m[1], line) ?? m[2])}`);

  if (m && /^(open|openat|creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate|chmod|utimensat)/.test(m[1])) {
    if (line.includes('= -1')) continue;               // failed calls are not a need
    const path = abs(pid, linkTarget(m[1], line) ?? m[2]);
    const isWrite = /^(creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate)/.test(m[1])
      || WRITE_FLAGS.test(line);
    if (isWrite) allWrites.add(path);
    if (mine) (isWrite ? writes : reads).add(path);
  }

  if (/^socket\(AF_INET/.test(line)) { allSockets++; if (mine) sockets++; }
  // ⛔ THE PORT AND ADDRESS ORDER IS NOT FIXED. strace prints sockaddr members in struct order,
  // which differs between sin_port/sin_addr and sin6_port/sin6_flowinfo/sin6_addr — and a single
  // regex assuming one order silently yields port 0 for the other. MEASURED: a real run reported
  // fifteen peers as `104.16.x.34:0`. Capture the two fields INDEPENDENTLY.
  if (/^connect\(/.test(line)) {
    const port = line.match(/sin6?_port=htons\((\d+)\)/);
    const addr = line.match(/inet6?_addr\("([^"]+)"/);
    if (addr) hosts.add(`${addr[1]}:${port ? port[1] : '?'}`);
  }
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
// Ordered before the `proj` test on purpose: `ownPkgDir` is a subtree of the project.
const scope = (p) => {
  if (ownPkgDir && (p === ownPkgDir || p.startsWith(`${ownPkgDir}/`))) return 'ownPkg';
  if (jailHome && (p === jailHome || p.startsWith(`${jailHome}/`))) return 'jailHome';
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
const BASE_COVERED = ['ownPkg', 'jailHome'];
const bucket = (set) => {
  const out = {};
  for (const p of set) (out[scope(p)] ??= []).push(p);
  return out;
};

const w = bucket(writes);
console.log(`== ATTRIBUTION == lifecycle pids: ${lifecycle.size}`);
console.log(`  writes  script ${writes.size}  /  whole traced tree ${allWrites.size}`);
console.log(`  sockets script ${sockets}  /  whole traced tree ${allSockets}`);
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
