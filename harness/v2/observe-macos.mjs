// Decode a macOS dtrace OBSERVE stream and say what a lifecycle script ACTUALLY needs.
//
// The macOS twin of observe.mjs. Same output contract (an `== SYNTHESIZED GRANT ==` block whose
// next line is the JSON the driver feeds to VERIFY), same classification scopes, same attribution
// discipline. What differs is only the input format: dtrace emits one structured record per event
// with pid AND ppid already on it, where strace emits pid-prefixed C syntax.
//
// ⛔ THE ATTRIBUTION FILTER IS NOT OPTIONAL. The traced subtree is `npm rebuild`, which is npm's
// own process as well as the lifecycle script's. MEASURED on Linux: without the subtree filter
// EVERY package synthesizes `network:true` + `write:userHome` regardless of what its script does,
// because npm writes `~/.npm/_logs` and opens TLS sockets on every run. dtrace's `progenyof()`
// already narrowed the stream to the npm subtree; this narrows it to the lifecycle shell's.
//
//   usage: node observe-macos.mjs <dtrace-log> <project-root> <home>
import fs from 'node:fs';

const [file, proj, home] = process.argv.slice(2);
if (!file) { console.error('usage: observe-macos.mjs <log> <projectRoot> <home>'); process.exit(2); }
const lines = fs.readFileSync(file, 'utf8').split('\n');

// Darwin open(2) flags. Any of these means the fd may be written through; O_RDONLY is 0x0 and so
// is the absence of all of them. A write intent is only visible HERE — by the time write(2) runs,
// the fd has hidden the path.
const O_WRONLY = 0x1, O_RDWR = 0x2, O_APPEND = 0x8, O_CREAT = 0x200, O_TRUNC = 0x400;
const isWriteFlags = (fl) => (fl & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC)) !== 0;

// EACCES 13, EPERM 1, EROFS 30 on Darwin. A refusal is these and nothing else: ENOENT is a probe
// that missed, not a denial, and counting it inflates the refusal census with ordinary lookups.
const REFUSAL_ERRNO = new Set([1, 13, 30]);

const cwds = new Map();      // pid -> cwd
const parent = new Map();    // pid -> ppid, rebuilt from the events themselves
const psargs = new Map();    // pid -> exec argv text
const execname = new Map();
const lifecycle = new Set(); // pids whose subtree IS the package's script

const writes = new Set(), reads = new Set(), denials = new Set(), hosts = new Set();
const allWrites = new Set();
let sockets = 0, allSockets = 0, live = false, events = 0;

const abs = (pid, p) => {
  if (!p) return p;
  const base = p.startsWith('/') ? p : ((cwds.get(pid) ?? proj ?? '') + '/' + p);
  const out = [];
  for (const seg of base.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return '/' + out.join('/');
};

// A pid is the package's if it or any ancestor is a lifecycle shell. Walking the chain per event
// is O(depth) and depth is ~5; memoising it would have to be invalidated as the tree grows.
const mine = (pid) => {
  for (let p = pid, i = 0; p && i < 64; p = parent.get(p), i++) if (lifecycle.has(p)) return true;
  return false;
};

// npm runs a lifecycle script by exec'ing `sh -c "<the script>"`. That is the ONLY `-c` shell in a
// `npm rebuild` subtree — npm's own work is done in-process in node. The driver's own wrapper is
// `bash <file>`, with no `-c`, so it cannot match.
//
// ⛔ THIS READS EXECARGV, NOT THE EXEC RECORD'S psargs. On macOS `curpsinfo->pr_psargs` carries only
// the COMMAND NAME — MEASURED on run 31087159355, where 0 of 9 EXEC records from a real
// `npm rebuild` contained a space at all: `sudo -u runner -H env PATH=<400 chars> …` came out as
// the four characters `sudo`, and the lifecycle shell came out as `sh`. A ` -c ` test against
// psargs therefore can never match on this platform, which is why every macOS arm reported
// `lifecycle pids: 0`. EXECARGV carries the caller's real argv[]; EXEC still builds the tree.
//
// argv[0] is matched on its BASENAME: npm execs a bare `sh`, but an absolute path is legal too.
const basename = (p) => (p ?? '').split('/').pop();
const isLifecycleShell = (argv0, argv1) =>
  /^(sh|bash|dash|zsh)$/.test(basename(argv0)) && argv1 === '-c';

for (const raw of lines) {
  if (!raw) continue;
  if (raw.startsWith('DTRACE-LIVE|')) { live = true; continue; }
  const f = raw.split('|');
  const kind = f[0];
  if (kind !== 'EXEC' && kind !== 'EXECARGV' && kind !== 'OPEN' && kind !== 'PATHOP'
      && kind !== 'CHDIR' && kind !== 'CONN' && kind !== 'CONN-OTHERFAMILY') continue;
  const pid = Number(f[1]), ppid = Number(f[2]);
  if (!Number.isFinite(pid)) continue;
  events++;
  if (Number.isFinite(ppid) && ppid > 0) parent.set(pid, ppid);
  if (f[3]) execname.set(pid, f[3]);

  // Fires at execve ENTRY, i.e. BEFORE the exec-success record for the same pid, so a lifecycle
  // shell is already marked by the time any of its own or its children's events arrive.
  if (kind === 'EXECARGV') {
    const argv0 = f[3] ?? '', argv1 = f[4] ?? '';
    const argv2 = f.slice(5).join('|');   // free-form script body; may itself contain `|`
    if (!cwds.has(pid) && cwds.has(ppid)) cwds.set(pid, cwds.get(ppid));
    if (isLifecycleShell(argv0, argv1)) {
      lifecycle.add(pid);
      psargs.set(pid, `${argv0} ${argv1} ${argv2}`);
    }
    continue;
  }

  if (kind === 'EXEC') {
    const args = f.slice(4).join('|');
    if (!psargs.has(pid)) psargs.set(pid, args);
    // A child inherits the parent's cwd; the exec record is the first time we see the pid, so this
    // is where the inheritance has to be applied or every grandchild resolves against the wrong base.
    if (!cwds.has(pid) && cwds.has(ppid)) cwds.set(pid, cwds.get(ppid));
    continue;
  }
  if (!cwds.has(pid) && cwds.has(ppid)) cwds.set(pid, cwds.get(ppid));

  if (kind === 'CHDIR') {
    const ret = Number((f[4] ?? '').replace('ret=', ''));
    if (ret === 0) cwds.set(pid, abs(pid, f.slice(5).join('|')));
    continue;
  }

  if (kind === 'CONN' || kind === 'CONN-OTHERFAMILY') {
    // ⛔ A NON-BLOCKING connect() RETURNS EINPROGRESS (36) ON EVERY ARM, INCLUDING A CLOSED PORT.
    // A connect refusal is therefore NOT readable from this return value at all — it needs the
    // later getsockopt(SO_ERROR). So: never classify a negative connect return as denied here.
    // What the record IS good for is the peer and the fact that an AF_INET connect was attempted,
    // which is exactly what the `network` capability is about.
    if (kind !== 'CONN') continue;   // gate on af == 2; the other families carry no host
    allSockets++;
    if (!mine(pid)) continue;
    sockets++;
    const port = (f[6] ?? '').replace('port=', '');
    hosts.add(`${f[5]}:${port}`);
    continue;
  }

  // OPEN | PATHOP
  const isOpen = kind === 'OPEN';
  const flags = isOpen ? Number((f[4] ?? '0').replace('flags=', '')) : 0;
  const op = isOpen ? 'open' : f[4];
  const ret = Number((f[isOpen ? 5 : 5] ?? '').replace('ret=', ''));
  const errno = Number((f[6] ?? '').replace('errno=', ''));
  const path = abs(pid, f.slice(7).join('|'));
  if (!path) continue;

  if (ret < 0) {
    if (REFUSAL_ERRNO.has(errno) && mine(pid)) denials.add(`${op} errno=${errno} ${path}`);
    continue;   // a call that failed is not a need
  }
  const w = isOpen ? isWriteFlags(flags)
    : /^(mkdir|rmdir|unlink|rename|link|symlink|truncate|chmod)$/.test(op);
  if (w) allWrites.add(path);
  if (mine(pid)) (w ? writes : reads).add(path);
}

const scope = (p) => {
  if (proj && p.startsWith(proj)) return p.includes('/node_modules/') ? 'deps' : 'project';
  if (home && p.startsWith(home)) return 'userHome';
  // macOS has no /proc. The nearest equivalent read floor is the shared cache and the system
  // frameworks, which every process touches and no grant has to name.
  if (/^\/(dev|System|usr\/lib|usr\/share|Library)\b/.test(p)) return 'systemfs';
  return 'outside';
};
const bucket = (set) => {
  const out = {};
  for (const p of set) (out[scope(p)] ??= []).push(p);
  return out;
};
const w = bucket(writes), r = bucket(reads);

console.log(`== TRACER == live=${live} decodable-events=${events}`);
if (!live) console.log('  ⛔ NO DTRACE-LIVE MARKER — the tracer never started. Nothing below is a measurement.');
console.log(`== ATTRIBUTION == lifecycle pids: ${lifecycle.size}`);
console.log(`  writes  script ${writes.size}  /  whole traced subtree ${allWrites.size}`);
console.log(`  sockets script ${sockets}  /  whole traced subtree ${allSockets}`);
if (lifecycle.size === 0) {
  // Not a package with no needs — an attribution failure. Saying so beats emitting an empty grant
  // that reads as a confident "this package needs nothing".
  console.log('  ⛔ NO LIFECYCLE SHELL FOUND — the subtree filter matched nothing, so the grant');
  console.log('     below is EMPTY BY DEFAULT rather than by measurement. Treat it as UNKNOWN.');
}
console.log('== WRITES the script actually performed ==');
for (const [k, v] of Object.entries(w)) {
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
  if (k === 'outside' || k === 'systemfs') v.slice(0, 10).forEach((p) => console.log(`      ${p}`));
}
console.log('== READS the script performed, by scope ==');
for (const [k, v] of Object.entries(r)) console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}`);
if (r.outside) r.outside.slice(0, 10).forEach((p) => console.log(`      outside: ${p}`));
console.log('== NETWORK ==');
console.log(`  AF_INET connects: ${sockets}   distinct peers: ${hosts.size}`);
[...hosts].slice(0, 10).forEach((h) => console.log(`      ${h}`));
console.log('== REFUSALS (errno EPERM/EACCES/EROFS only; ENOENT is a miss, not a denial) ==');
console.log(`  distinct: ${denials.size}`);
[...denials].slice(0, 15).forEach((d) => console.log(`      ${d}`));

// The synthesized grant: the narrowest catalog entry covering everything observed.
//
// READ SCOPES ARE DELIBERATELY NOT SYNTHESIZED FROM THE READ CENSUS. Every process reads dyld's
// shared cache and its own binary, so a read-derived grant would be `read:"disk"` for every package
// on the platform — which is the widest grant available and would make the read axis meaningless.
// The driver instead starts from the write+network grant and, if it fails to verify, escalates the
// read axis explicitly. What the census above is for is telling a human WHY that escalation was
// needed, and whether the reads were project-local or genuinely disk-wide.
const g = {};
if (w.deps) g.write = { ...(g.write ?? {}), deps: true };
if (w.project) g.write = { ...(g.write ?? {}), project: true };
if (w.userHome) g.write = { ...(g.write ?? {}), userHome: true };
if (sockets > 0) g.network = true;
console.log('== SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==');
// ⛔ `{}` IS A REAL, VERIFIABLE ANSWER — a package whose script genuinely needs nothing. It has been
// verified as such on another platform (Windows, husky@4.3.8). So it must NEVER double as the
// failure value: a decoder that emits `{}` when attribution failed is indistinguishable from one
// that emits it on success, and the difference is a confident empty grant in the corpus. When the
// subtree filter matched nothing, emit a token that is not valid JSON and that no downstream step
// can mistake for a measurement.
console.log('  ' + (lifecycle.size === 0 ? 'UNKNOWN-ATTRIBUTION-FAILED' : JSON.stringify(g)));
if (w.outside) console.log(`  ⛔ ${w.outside.length} writes OUTSIDE project/home — no scope covers these; inspect before granting`);

const enumerable = [...(w.userHome ?? []), ...(w.outside ?? [])];
console.log('== writePaths FEASIBILITY (distinct writes outside project/deps) ==');
console.log(`  count: ${enumerable.length}`);
enumerable.slice(0, 40).forEach((p) => console.log(`      ${home && p.startsWith(home) ? p.slice(home.length + 1) : p}`));
if (enumerable.length > 40) console.log(`      … and ${enumerable.length - 40} more`);
