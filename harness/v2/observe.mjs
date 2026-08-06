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
//   usage: node observe.mjs <trace-file> <project-root> <home> [store-root]
import fs from 'node:fs';

const [file, proj, home, store] = process.argv.slice(2);
if (!file) { console.error('usage: observe.mjs <trace> <projectRoot> <home> [storeRoot]'); process.exit(2); }
const lines = fs.readFileSync(file, 'utf8').split('\n');

// ⛔ ONLY `= -1 EACCES` IS A REFUSAL. A bare `grep EACCES` also matches the FLAG NAME `AT_EACCESS`
// in faccessat calls, which are ordinary successful probes. Measured on a real trace: the naive
// pattern reported 26 denials where 11 were real.
const DENIED = /=\s*-1\s+(EACCES|EPERM|EROFS)\b/;
// A write intent is visible in the OPEN FLAGS, not in a later write() — by then the fd hides the
// path. Creating, truncating or appending all count; O_RDONLY does not.
const WRITE_FLAGS = /O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)/;
const PATH_SYSCALL = /^(open|openat|creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate|chmod|utimensat)/;
const MUTATOR = /^(creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate)/;

const writes = new Set(), reads = new Set(), denials = new Set(), hosts = new Set();
let sockets = 0;

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

// ⛔ THE TRACE MUST CARRY `%process` OR NEITHER CWD INHERITANCE NOR SUBTREE ATTRIBUTION CAN WORK.
//
// The driver used to run `strace -f -e trace=file,network`. `%file` and `%network` do not include
// clone/fork/execve, so the fork-inheritance branch below matched ZERO lines and the attribution
// pass had no parentage to walk. MEASURED on @airbnb/node-memwatch@3.0.0's trace: 133,793 lines,
// 0 matching `^<pid> (clone|fork|vfork)` and 0 `Process N attached`. Every child therefore
// resolved its relative paths against the project root instead of its own cwd, silently.
// The driver now passes `-e trace=file,network,process`; this asserts the caller did.
let sawClone = false;

// ⛔ ATTRIBUTE ONLY THE LIFECYCLE SUBTREE. THE PACKAGE MANAGER IS NOT THE PACKAGE.
//
// The trace covers the whole install, so without this every event the PACKAGE MANAGER performs is
// charged to the package: its registry fetches become `network: true` and its cache writes become
// `write.userHome`. MEASURED on @airbnb/node-memwatch@3.0.0, whose true minimum is `null`: 3,370
// userHome writes (126 of them under `.npm/_cacache`) and 17 peers on 104.16.x.34 — all of them
// npm's, none of them the package's — synthesizing
// `{"write":{"deps":true,"project":true,"userHome":true},"network":true}` for a package that needs
// nothing at all. The jail confines the lifecycle script and nothing else, so the observation has
// to be scoped the same way.
//
// The root is the shell the manager spawns the script in (`sh -c "<script>"`); everything cloned
// beneath it inherits the flag, which is what catches the grandchild case (`dotnet-2.0.0@1.4.4`'s
// whole story is one syscall in a bundled yarn, three processes down).
const lifecycle = new Set();
const SHELL_C = /execve\("[^"]*\/(sh|bash|dash|zsh)",\s*\[[^\]]*"-c"/;
let lifecycleFound = false;

// ⛔ AN `<unfinished ...>` LINE CARRIES THE PATH BUT NO RESULT; ITS `<... resumed>` HALF CARRIES THE
// RESULT BUT NO PATH. Neither half is usable alone, and reading them as-is fails in BOTH directions:
// an interrupted `openat(..., O_WRONLY) <unfinished ...>` that ultimately returns -1 was counted as
// a successful write, and a `<... openat resumed>) = -1 EACCES` was dropped from the refusal set
// because the denial branch requires a path on the same line. MEASURED on @airbnb/node-memwatch@3.0.0:
// 7,768 unfinished / 7,768 resumed pairs in a 133,793-line trace — 11.6% of all syscalls split.
// strace guarantees at most one outstanding call per pid, so a per-pid slot is sufficient.
const pending = new Map();

const record = (pid, call, path, line) => {
  if (!lifecycle.has(pid)) return;
  if (DENIED.test(line)) { denials.add(`${call} ${path}`); return; }
  if (line.includes('= -1')) return;                   // failed calls are not a need
  const isWrite = MUTATOR.test(call) || WRITE_FLAGS.test(line);
  (isWrite ? writes : reads).add(path);
};

// ⛔ THE SPLIT HALVES MUST BE REJOINED AND THEN PROCESSED IDENTICALLY TO A WHOLE LINE — NOT
// HANDLED ON A SIDE PATH. A first cut returned early on every `<unfinished ...>` line and only
// rejoined path syscalls, which dropped execve and clone on the floor. MEASURED: the ONE line that
// identifies the lifecycle root is itself split —
//     49767 execve("/usr/bin/sh", ["sh", "-c", "node-gyp rebuild"], … <unfinished ...>
// so nothing was ever attributed and @airbnb/node-memwatch@3.0.0 synthesized an empty grant for a
// reason that had nothing to do with the package. Rejoin first, dispatch second.
const handle = (pid, line) => {
  const cd = line.match(/^f?chdir\("([^"]+)"\)\s*=\s*0/);
  if (cd) cwds.set(pid, abs(pid, cd[1]));
  // A child inherits the parent's cwd at fork; without this every grandchild resolves against the
  // wrong base, which is the common case since the interesting syscall is usually a grandchild.
  const cl = line.match(/^(?:clone3?|v?fork)\(.*\)\s*=\s*(\d+)/);
  if (cl) {
    sawClone = true;
    const kid = Number(cl[1]);
    if (cwds.has(pid)) cwds.set(kid, cwds.get(pid));
    if (lifecycle.has(pid)) lifecycle.add(kid);
  }
  if (SHELL_C.test(line) && !line.includes('= -1')) { lifecycle.add(pid); lifecycleFound = true; }

  const m = line.match(/^([a-z_0-9]+)\((?:AT_FDCWD,\s*)?"([^"]*)"/);
  if (m && PATH_SYSCALL.test(m[1])) record(pid, m[1], abs(pid, m[2]), line);

  if (/^socket\(AF_INET/.test(line) && lifecycle.has(pid)) sockets++;
  // ⛔ THE PORT AND ADDRESS ORDER IS NOT FIXED. strace prints sockaddr members in struct order,
  // which differs between sin_port/sin_addr and sin6_port/sin6_flowinfo/sin6_addr — and a single
  // regex assuming one order silently yields port 0 for the other. MEASURED: a real run reported
  // fifteen peers as `104.16.x.34:0`. Capture the two fields INDEPENDENTLY.
  if (/^connect\(/.test(line) && lifecycle.has(pid)) {
    const port = line.match(/sin6?_port=htons\((\d+)\)/);
    const addr = line.match(/inet6?_addr\("([^"]+)"/);
    if (addr) hosts.add(`${addr[1]}:${port ? port[1] : '?'}`);
  }
};

for (const raw of lines) {
  if (!raw) continue;
  // Keep the pid: cwd is per-process, so stripping it first loses the only key we have.
  const pidM = raw.match(/^(\d+)\s+/);
  const pid = pidM ? Number(pidM[1]) : 0;
  const line = raw.replace(/^\d+\s+/, '');

  const res = line.match(/^<\.\.\.\s+([a-z_0-9]+)\s+resumed>(.*)$/);
  if (res) {
    const head = pending.get(pid);
    pending.delete(pid);
    // strace guarantees at most one outstanding call per pid, so the slot is unambiguous.
    if (head && head.call === res[1]) handle(pid, head.line.replace(/\s*<unfinished \.\.\.>\s*$/, '') + res[2]);
    continue;
  }
  if (line.includes('<unfinished ...>')) {
    const um = line.match(/^([a-z_0-9]+)\(/);
    if (um) pending.set(pid, { call: um[1], line });
    continue;
  }
  handle(pid, line);
}

// ⛔ A BASELINE DEVICE IS NOT A GRANT. `/dev/null` was landing in an unclassified "kernelfs" bucket
// with no policy, which invites exactly the rounding determinism rule 3 forbids. These nodes carry
// no user data, every backend already permits them (verified against the jail: a script that opens
// `/dev/null` for write survives the narrowest representable grant), and there is no catalog
// vocabulary that could express needing them. They are dropped rather than reported so the
// "unclassifiable" bucket keeps meaning "a human must look at this".
const BASELINE_DEV = /^\/dev\/(null|zero|full|random|urandom|tty|ptmx|pts\/|fd\/|stdin|stdout|stderr)/;

// Classify a path against the scopes the CATALOG can express, so the output maps onto a grant
// rather than onto a pile of strings.
// ⛔ ROOTS ARE ORDERED LONGEST-FIRST (determinism rule 2). The store lives INSIDE the redirected
// home and the project lives inside the fixture, so a home-first test would swallow both.
const scope = (p) => {
  if (store && p.startsWith(store)) return 'deps';   // a dep's own files live in the store under nub
  if (proj && p.startsWith(proj)) return p.includes('/node_modules/') ? 'deps' : 'project';
  if (home && p.startsWith(home)) return 'userHome';
  if (BASELINE_DEV.test(p)) return 'baseline-dev';
  if (p.startsWith('/proc') || p.startsWith('/sys') || p.startsWith('/dev')) return 'kernelfs';
  return 'outside';
};
const bucket = (set) => {
  const out = {};
  for (const p of set) (out[scope(p)] ??= []).push(p);
  return out;
};

const w = bucket(writes), r = bucket(reads);
if (!sawClone) console.log('  ⛔ NO clone/fork LINES IN TRACE — rerun with `-e trace=file,network,process`');
if (!lifecycleFound) console.log('  ⛔ NO LIFECYCLE SHELL FOUND — nothing attributed; grant below is EMPTY BY DEFAULT, not by evidence');
console.log('== WRITES the lifecycle subtree actually performed ==');
for (const [k, v] of Object.entries(w)) {
  console.log(`  ${k.padEnd(12)} ${String(v.length).padStart(5)}`);
  if (k === 'outside' || k === 'kernelfs') v.slice(0, 10).forEach((p) => console.log(`      ${p}`));
}
console.log('== READS (kernelfs/outside only — the rest are implied by the write scopes) ==');
for (const [k, v] of Object.entries(r)) {
  if (k !== 'outside' && k !== 'kernelfs') continue;
  console.log(`  ${k.padEnd(12)} ${String(v.length).padStart(5)}`);
  v.slice(0, 12).forEach((p) => console.log(`      ${p}`));
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
// ⛔ AN EMPTY `default` BLOCK IS REJECTED BY THE PARSER, and a rejected override falls back to the
// COMPILED-IN catalog with a warning the driver would otherwise read as a passing arm. The
// narrowest REPRESENTABLE nothing is an explicit `network:false`.
console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
console.log('  ' + JSON.stringify(Object.keys(g).length ? g : { network: false }));
if (w.outside) console.log(`  ⛔ ${w.outside.length} writes OUTSIDE project/home — no scope covers these; inspect before granting`);
if (w.kernelfs || r.kernelfs) console.log(`  NOTE ${(w.kernelfs ?? []).length} kernel-fs writes / ${(r.kernelfs ?? []).length} reads (/proc,/sys) — a READ floor question, not a write grant`);
