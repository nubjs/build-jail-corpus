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
//   usage: node observe.mjs <trace-file> <project-root> <home>
import fs from 'node:fs';

const [file, proj, home] = process.argv.slice(2);
if (!file) { console.error('usage: observe.mjs <trace> <projectRoot> <home>'); process.exit(2); }
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
  if (cl && cwds.has(pid)) cwds.set(Number(cl[1]), cwds.get(pid));

  const m = line.match(/^([a-z_0-9]+)\((?:AT_FDCWD,\s*)?"([^"]*)"/);

  if (DENIED.test(line) && m) denials.add(`${m[1]} ${abs(pid, m[2])}`);

  if (m && /^(open|openat|creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate|chmod|utimensat)/.test(m[1])) {
    if (line.includes('= -1')) continue;               // failed calls are not a need
    const path = abs(pid, m[2]);
    const isWrite = /^(creat|mkdir|mkdirat|unlink|unlinkat|rename|renameat2?|link|symlink|truncate)/.test(m[1])
      || WRITE_FLAGS.test(line);
    (isWrite ? writes : reads).add(path);
  }

  if (/^socket\(AF_INET/.test(line)) sockets++;
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
const scope = (p) => {
  if (proj && p.startsWith(proj)) return p.includes('/node_modules/') ? 'deps' : 'project';
  if (home && p.startsWith(home)) return 'userHome';
  if (p.startsWith('/proc') || p.startsWith('/sys') || p.startsWith('/dev')) return 'kernelfs';
  return 'outside';
};
const bucket = (set) => {
  const out = {};
  for (const p of set) (out[scope(p)] ??= []).push(p);
  return out;
};

const w = bucket(writes);
console.log('== WRITES the script actually performed ==');
for (const [k, v] of Object.entries(w)) {
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
  if (k === 'outside' || k === 'kernelfs') v.slice(0, 10).forEach((p) => console.log(`      ${p}`));
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
