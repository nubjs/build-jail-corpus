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
// ⛔ EVERY ROOT COMES FROM `capture.json`, AND NOTHING ELSE MAY SUPPLY ONE (VENUE-PORTABILITY R2).
// Not the ambient environment, not a hardcoded `~/.cache/nub` pattern, not a root derived from the
// path being classified. Roots are what turn a machine-specific path into a scope, so a classifier
// that can obtain one from its surroundings produces a plausible answer on the machine that happens
// to match and a wrong one everywhere else — and says nothing either way.
//
// ⛔ A NEEDED ROOT THAT `capture.json` DOES NOT DECLARE IS A HARD ERROR, NEVER A FALLBACK. A
// fallback is exactly the mechanism that makes a venue difference SILENT: it keeps running and
// emits a grant, so the failure surfaces as a wrong catalog entry rather than as a crash.
//
// ⛔ ABSENT AND `null` ARE DIFFERENT AND ARE TREATED DIFFERENTLY. `null` is the capture SAYING this
// platform has no such root, which is an answer; an absent key is the capture failing to say, which
// is not. Only the latter is fatal — collapsing them would let a stale writer silently opt out.
//
// ⛔ `cwd` IS DECLARED LIKE ANY OTHER ROOT, AND ON THIS PLATFORM IT IS ALWAYS `null` — THE NULL IS
// THE POINT. It is per-process and time-varying rather than one path, but the same rule binds it:
// observed or declared, never inferred. macOS cannot observe it (posix_spawn `addchdir_np`, see
// `cwdTrusted` below) and the driver cannot truthfully declare it, because npm chooses it. So the
// capture says `null`, which is the honest statement that the root is unavailable, and the cwd guard
// is what stops an unavailable root from being silently guessed anyway.
//
//   usage: node observe-macos.mjs <dtrace-log> --capture <capture.json>
import fs from 'node:fs';

const argv = process.argv.slice(2);
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };
const file = argv.find((a, i) => !a.startsWith('--') && !(i > 0 && argv[i - 1].startsWith('--')));
const capturePath = flag('--capture');
if (!file || !capturePath) {
  console.error('usage: observe-macos.mjs <log> --capture <capture.json>');
  process.exit(2);
}
// The list lives HERE, not in the driver: this file is what would misclassify without a root, so
// this is the file that must refuse to run.
const REQUIRED_ROOTS = ['project', 'home', 'jailHome', 'globalStore', 'projectStore',
                        'interpreter', 'toolsDir', 'temp', 'npmPrefix', 'ownPkg', 'cwd'];
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
// ⛔ ELEVEN ROOTS ARE REQUIRED; THREE ARE KEYED ON. That is deliberate and not an oversight.
// R1 requires every root the classifier COULD key on to be DECLARED, because a root re-derived
// later is a root re-derived from ambient state — the exact failure R2 exists to stop. Changing
// which bucket a path lands in is a grant-semantics change and needs its own evidence, exactly as
// the bytecode drop did. The OBSERVE arm is `npm rebuild` in a plain hoisted layout and never
// touches nub's store, so inventing a bucket for a path this arm cannot produce would be policy
// with no measurement under it.
//
// Only these three are destructured, and every use below is null-guarded — a `null` root must never
// reach `startsWith`, which would match the literal string "null" and silently misclassify.
const { project: proj, home, ownPkg: ownPkgDir } = roots;
const pkgName = capture.pkg ?? null;
const lines = fs.readFileSync(file, 'utf8').split('\n');

// Darwin open(2) flags. Any of these means the fd may be written through; O_RDONLY is 0x0 and so
// is the absence of all of them. A write intent is only visible HERE — by the time write(2) runs,
// the fd has hidden the path.
const O_WRONLY = 0x1, O_RDWR = 0x2, O_APPEND = 0x8, O_CREAT = 0x200, O_TRUNC = 0x400;
const isWriteFlags = (fl) => (fl & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC)) !== 0;

// EACCES 13, EPERM 1, EROFS 30 on Darwin. A refusal is these and nothing else: ENOENT is a probe
// that missed, not a denial, and counting it inflates the refusal census with ordinary lookups.
const REFUSAL_ERRNO = new Set([1, 13, 30]);

// The adapter's `key=value` tokens, recognised by NAME so a free-form path can never be read as
// one. Adding a key here is what makes a new adapter field visible; omitting it makes the scan stop
// at that field and treat it as the start of the path, which is the safe direction.
// `cwd` carries dtrace's built-in, which on Darwin is a BASENAME rather than a path — see the
// `cwdTrusted` note. Recognised here so the adapter can start emitting it without shifting the
// path field; absent from every archive taken before that, which the guard handles as "unproven".
const META_KEYS = new Set(['ret', 'errno', 'flags', 'ev', 'dirfd', 'role', 'mode', 'cwd']);
const AT_FDCWD = -2;   // Darwin
let unresolvableDirfd = 0;
// ⛔ THE LIFECYCLE SCRIPT'S CWD IS NOT OBSERVABLE ON THIS PLATFORM, AND THE DECODER USED TO INVENT
// ONE. npm runs a lifecycle script with the cwd set to the package directory. On Linux libuv does
// that with fork(2) + chdir(2) — a real syscall, which is why `observe.mjs` resolves these paths
// correctly. On macOS libuv takes the posix_spawn path and calls
// `posix_spawn_file_actions_addchdir_np` (`deps/uv/src/unix/process.c:565`, resolved by `dlsym` at
// `:436`); the directory change happens INSIDE the kernel as part of the spawn, so no `chdir`
// syscall ever fires. MEASURED: across BOTH darwin-arm64 archives ever taken, the only `CHDIR`
// records belong to this driver's own wrapper — never to a lifecycle shell.
//
// The consequence was silent and it ran in both directions. `ttf2woff2@1.2.3` opens `builderror.log`
// relative; the decoder resolved it against the INHERITED wrapper cwd and produced
// `<project>/builderror.log`, a path no process touched, billing `write.project`. The real file is
// `<project>/node_modules/ttf2woff2/builderror.log`, which Linux recorded and which the `ownPkg`
// bucket grants for free. Over-prediction there — but a script that chdirs into a temp or home
// directory and writes relatively would have had those writes attributed to the project root, which
// HIDES a real capability. That is an under-grant, the one direction this project forbids.
//
// ⛔ "CATCH THE CHDIR" CANNOT WORK — there is no chdir to catch. And dtrace's built-in `cwd` does not
// close it either: `/usr/lib/dtrace/darwin.d:339` defines it as `curproc->p_fd.fd_cdir->v_name`,
// the vnode's NAME — a single path COMPONENT, not a path. Apple's comment on the line above says
// they want `vn_getpath()` and cannot have it because it takes `namecache_rw_lock`. So `cwd` can
// tell us our belief is STALE (basename mismatch) but cannot tell us the truth.
//
// ⇒ So the rule here is the same one the dirfd guard already applies: a path we cannot resolve is
// never given a fabricated absolute form. It is counted, reported with its RAW text, and — because
// a write really did happen and we do not know where — the grant is WIDENED to cover anywhere it
// could have landed. Over-granting is safe; a silent attribution to the wrong scope is not.
//
// ⛔ THE `cwd=` DETECTOR SETS SEVERITY, NEVER BILLING, AND THE ASYMMETRY IS THE WHOLE POINT. When the
// adapter supplies dtrace's `cwd` (a BASENAME — see above), a MISMATCH against the basename we
// believe proves our resolution wrong. A MATCH proves nothing: `/a/observe` and `/b/observe` share a
// basename, so a match is consistent with a resolution that is still wrong, and that error runs in
// the under-grant direction. So a match downgrades the flag to "not disproven" and NEVER upgrades it
// to "verified" — both severities still bill the widest scope. Over-firing costs extra jailed arms;
// under-firing breaks installs.
//
// The one collision we can eliminate outright, we do: `measure-macos.sh` names its observation
// directory with an UPPERCASE letter and asserts it. npm package names may not contain uppercase
// (npm has refused them since 2017), and the actual cwd of a lifecycle script is overwhelmingly a
// package directory — so a basename collision between our fixture and the real cwd is not merely
// unlikely, it is unrepresentable.
// ⛔ TRUST IS INHERITED, AND THE LIFECYCLE SHELL IS WHERE IT IS BROKEN — NOT EVERY PROCESS THAT DID
// NOT chdir ITSELF. An ordinary fork/exec child (`mkdir`, `mv`, `ln` under the script) inherits its
// parent's cwd through a path this tracer CAN see, so its belief is as good as the parent's.
// Requiring an own chdir instead flagged all of those and broke five existing cases — the tell that
// the rule was wrong, caught by the suite rather than in production. What npm actually does
// invisibly is set the cwd of the lifecycle SHELL, so trust is cleared exactly there and restored
// the moment that shell performs a chdir this tracer can observe.
const cwdTrusted = new Set();      // pids whose cwd belief traces back to an OBSERVED chdir
const cwdName = new Map();         // pid -> basename of the cwd dtrace observed, when the adapter emits it
const cwdUnresolved = [];          // { pid, raw, write, severity } for the report
let cwdUnobservedWrite = false;    // any WRITE we could not place ⇒ widen the grant
let cwdProvenStale = false;        // a basename mismatch: our belief is DISPROVEN, not merely unproven

// ⛔ EVERY PATH-MUTATING CALL THE ADAPTER SUBSCRIBES TO MUST BE HERE, OR ITS PATH IS BILLED AS A
// READ. The `*at` family and the Darwin-specific forms were added to the adapter after a census
// measured 53% of path-mutating syscalls invisible to it (run 31116027627); a decoder that did not
// learn the names alongside would have turned a fixed under-grant into a different one.
const PATH_MUTATOR = /^(mkdir|mkdirat|rmdir|unlink|unlinkat|rename|renameat|renameatx_np|link|linkat|symlink|symlinkat|clonefileat|fclonefileat|copyfile|truncate|chmod|fchmodat|chown|lchown|fchownat|mknod|mkfifo|undelete|exchangedata|setattrlist|setattrlistat|setxattr|removexattr|utimes)$/;

const cwds = new Map();      // pid -> cwd
const parent = new Map();    // pid -> ppid, rebuilt from the events themselves
const psargs = new Map();    // pid -> exec argv text
const execname = new Map();
const lifecycle = new Set(); // pids whose subtree IS the package's script

const writes = new Set(), reads = new Set(), denials = new Set(), hosts = new Set();
const allWrites = new Set();
let sockets = 0, allSockets = 0, live = false, events = 0;

// ⛔ DROPPED EVENTS, COUNTED. A copyin/copyinstr fault aborts the whole clause, so the record is
// never emitted — and a record never emitted is a path never seen, which is a capability never
// granted. That is an UNDER-prediction, the one direction that breaks real installs, and until the
// adapter grew its `dtrace:::ERROR` clause it happened in total silence: dtrace complains on its own
// STDERR, which lands in `dtrace.log` and is read by nobody, while `trace.txt` shows no gap at all.
// MEASURED on run 31109041194: 26 of 26 rename DESTINATION paths were lost this way, and the run
// still printed a confident grant. The count below is what makes the next such loss visible.
const lost = new Map();   // "epid=N action=M fault=F addr=A" -> count
let lostTotal = null;     // the adapter's own END-time tally, independent of the per-event records

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
  if (raw.startsWith('TRACER-ERROR-TOTAL|')) {
    const n = Number(raw.split('|')[1]);
    if (Number.isFinite(n)) lostTotal = n;
    continue;
  }
  if (raw.startsWith('TRACER-ERROR|')) {
    const g = raw.split('|');
    const key = `${g[4] ?? 'epid=?'} ${g[5] ?? 'action=?'} ${g[6] ?? 'fault=?'} ${g[7] ?? 'addr=?'}`;
    lost.set(key, (lost.get(key) ?? 0) + 1);
    continue;
  }
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
    if (!cwds.has(pid) && cwds.has(ppid)) { cwds.set(pid, cwds.get(ppid)); if (cwdTrusted.has(ppid)) cwdTrusted.add(pid); }
    if (isLifecycleShell(argv0, argv1)) {
      lifecycle.add(pid);
      cwdTrusted.delete(pid);   // npm set this shell's cwd in-kernel; the inherited belief is stale
      psargs.set(pid, `${argv0} ${argv1} ${argv2}`);
    }
    continue;
  }

  if (kind === 'EXEC') {
    const args = f.slice(4).join('|');
    if (!psargs.has(pid)) psargs.set(pid, args);
    // A child inherits the parent's cwd; the exec record is the first time we see the pid, so this
    // is where the inheritance has to be applied or every grandchild resolves against the wrong base.
    if (!cwds.has(pid) && cwds.has(ppid)) { cwds.set(pid, cwds.get(ppid)); if (cwdTrusted.has(ppid)) cwdTrusted.add(pid); }
    continue;
  }
  if (!cwds.has(pid) && cwds.has(ppid)) { cwds.set(pid, cwds.get(ppid)); if (cwdTrusted.has(ppid)) cwdTrusted.add(pid); }

  if (kind === 'CHDIR') {
    const ret = Number((f[4] ?? '').replace('ret=', ''));
    // ⛔ ONLY A SUCCESSFUL chdir BY THIS PID MAKES ITS CWD *OBSERVED*. Inheritance — the three
    // `cwds.set` lines above — propagates a BELIEF, and on macOS that belief is exactly what
    // posix_spawn's in-kernel addchdir_np invalidates without a trace. Conflating the two is the
    // defect this guard exists for, so the two are tracked in different structures.
    if (ret === 0) { cwds.set(pid, abs(pid, f.slice(5).join('|'))); cwdTrusted.add(pid); }
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
  //
  // ⛔ THE TRAILING FIELDS ARE PARSED BY KEY, NOT BY POSITION, and that is what lets the adapter
  // gain a field without breaking this reader. The previous version read `ret` at index 5, `errno`
  // at 6 and the path at 7+, so the adapter's new `ev`/`dirfd`/`role` tokens would have shifted the
  // PATH into the metadata and left a decoder happily treating `ev=173…` as a filename. A path is
  // never mistaken for a token because only the keys in META_KEYS are recognised, and the scan
  // stops at the first field that is not one.
  const isOpen = kind === 'OPEN';
  const meta = {};
  let i = isOpen ? 4 : 5;
  for (; i < f.length; i++) {
    const eq = f[i].indexOf('=');
    if (eq < 0) break;
    const k = f[i].slice(0, eq);
    if (!META_KEYS.has(k)) break;
    const raw = f[i].slice(eq + 1);
    meta[k] = /^0x/.test(raw) ? parseInt(raw, 16) : (/^-?\d+$/.test(raw) ? Number(raw) : raw);
  }
  const rawPath = f.slice(i).join('|');
  if (meta.cwd !== undefined) cwdName.set(pid, String(meta.cwd));
  const flags = isOpen ? (meta.flags ?? 0) : 0;
  const op = isOpen ? 'open' : f[4];
  const ret = meta.ret ?? NaN;
  const errno = meta.errno ?? 0;
  if (!rawPath) continue;
  // ⛔ A RELATIVE PATH UNDER A REAL dirfd IS NOT RESOLVABLE HERE, AND RESOLVING IT ANYWAY INVENTS A
  // PATH NO PROCESS TOUCHED. `abs()` resolves against the process CWD, which is correct only when
  // the dirfd is AT_FDCWD; every other dirfd names an open directory this tracer cannot map back to
  // a path. Such a record is COUNTED and dropped rather than scope-assigned — a phantom path in a
  // write bucket keeps a whole capability alive on its own, which is the defect the symlink-target
  // fix already paid for once.
  if (meta.dirfd !== undefined && meta.dirfd !== AT_FDCWD && !rawPath.startsWith('/')) {
    unresolvableDirfd++;
    continue;
  }
  const path = abs(pid, rawPath);
  if (!path) continue;

  if (ret < 0) {
    if (REFUSAL_ERRNO.has(errno) && mine(pid)) denials.add(`${op} errno=${errno} ${path}`);
    continue;   // a call that failed is not a need
  }
  const w = isOpen ? isWriteFlags(flags) : PATH_MUTATOR.test(op);
  // ⛔ THE CWD GUARD. See the long note on `cwdTrusted`. A relative path from a lifecycle process
  // whose OWN cwd was never observed cannot be placed, so it is never given the fabricated absolute
  // form `abs()` just computed. Restricted to `mine(pid)` because only the lifecycle subtree is
  // spawned by npm with a cwd override, and only its paths reach the grant.
  if (!rawPath.startsWith('/') && mine(pid) && !cwdTrusted.has(pid)) {
    // The detector, when the adapter supplies it. Severity ONLY — see the note: a match is "not
    // disproven", never "verified", and both severities bill the same.
    const believed = (cwds.get(pid) ?? proj ?? '').split('/').pop();
    const seen = cwdName.get(pid);
    const severity = seen && seen !== '<unknown>' && seen !== believed ? 'stale' : 'unproven';
    if (severity === 'stale') cwdProvenStale = true;
    if (w) cwdUnobservedWrite = true;
    cwdUnresolved.push({ pid, raw: rawPath, write: w, severity });
    continue;
  }
  if (w) allWrites.add(path);
  if (mine(pid)) (w ? writes : reads).add(path);
}

// ⛔ `ownPkg` IS A SCOPE THE JAIL ALREADY GRANTS, AND BILLING IT MANUFACTURES A CAPABILITY.
// `store_entry_write_root` grants RW on the package's own store entry, and under the isolated
// layout `<project>/node_modules/<pkg>` is a SYMLINK into that entry — so a script writing into its
// own directory is writing into space the base profile handed it. A write to a SIBLING dependency
// does NOT resolve there and stays `deps`. Ported from `observe.mjs:162,193`, where it has shipped
// across 45 Linux records; the long derivation from `preset.rs` lives there and is not duplicated.
//
// MEASURED, and it is why this is not a cosmetic tidy-up: `hugo-extended@0.141.0` is the only
// darwin-arm64 record taken without this bucket, and all four of its billed writes are
// `node_modules/hugo-extended/vendor/*` — its own directory. It synthesized
// `{"write":{"deps":true},"network":true}` where Linux synthesized `{"network":true}` for the same
// package, and the NARROW arm then spent a second jailed run rediscovering that `write.deps` was
// never needed. Re-parsing that record's retained `trace.txt.gz` through this bucket yields
// `{"network":true}` at synthesis. Since most install scripts write into their own directory
// (native builds, downloaded binaries, generated shims), the old behaviour was a systematic
// over-grant on every macOS record plus a redundant arm on the platform with the scarcest runners.
//
// Ordered before the `proj` test on purpose: `ownPkgDir` is a subtree of the project.
const scope = (p) => {
  if (ownPkgDir && (p === ownPkgDir || p.startsWith(`${ownPkgDir}/`))) return 'ownPkg';
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

const lostEvents = [...lost.values()].reduce((a, b) => a + b, 0);
console.log(`== TRACER == live=${live} decodable-events=${events} dropped-events=${lostTotal ?? lostEvents}`);
if (unresolvableDirfd > 0) {
  // Not a drop and not an error: the record arrived intact and its path is genuinely not resolvable
  // without an fd->path table. Reported because the alternative — resolving it against the cwd —
  // is a confidently wrong path, and because a rising count is the signal that the table is worth
  // building.
  console.log(`  NOTE ${unresolvableDirfd} relative path(s) under a non-AT_FDCWD dirfd were not`);
  console.log('     scope-assigned: resolving them against the cwd would invent a path.');
}
if (cwdUnresolved.length > 0) {
  // The marker string is the contract with `record.mjs`, which turns it into a record note. Printed
  // with the RAW relative text and the pid, because the whole point is that no absolute form of
  // these paths is trustworthy — showing a resolved one would re-commit the error being reported.
  const nw = cwdUnresolved.filter((c) => c.write).length;
  console.log(`  ⛔ CWD-UNOBSERVED ${cwdUnresolved.length} relative path(s) (${nw} write(s)) came from a lifecycle`);
  console.log(`     process whose own cwd was never observed${cwdProvenStale ? ' — AND A BASENAME MISMATCH PROVES' : ''}`);
  if (cwdProvenStale) console.log('     THE INHERITED CWD WRONG. Severity: STALE.');
  console.log('     macOS spawns with posix_spawn addchdir_np, which changes directory in-kernel and');
  console.log('     emits no chdir syscall, so the inherited cwd cannot be trusted. These are NOT');
  console.log('     scope-assigned; the grant below is WIDENED instead so it covers wherever they landed.');
  for (const c of cwdUnresolved.slice(0, 10)) {
    console.log(`       pid=${c.pid} ${c.write ? 'WRITE' : 'read '} ${c.severity.padEnd(8)} ${c.raw}`);
  }
  if (cwdUnresolved.length > 10) console.log(`       … and ${cwdUnresolved.length - 10} more`);
}
if (!live) console.log('  ⛔ NO DTRACE-LIVE MARKER — the tracer never started. Nothing below is a measurement.');
// The two counters come from different places on purpose — per-event records vs the adapter's own
// END-time aggregation — so a disagreement means records were lost on the way OUT (a full principal
// buffer), which is its own reason to distrust the census rather than to average the two.
if (lostTotal !== null && lostTotal !== lostEvents) {
  console.log(`  ⛔ LOSS LEDGER DISAGREES: END says ${lostTotal}, ${lostEvents} per-event records survived`);
}
if (lostEvents > 0 || (lostTotal ?? 0) > 0) {
  console.log(`  ⛔ THE TRACER DROPPED ${lostTotal ?? lostEvents} EVENT(S). A dropped event is a path never`);
  console.log('     seen, so the grant below can only be too NARROW — the direction that breaks installs.');
  console.log('     Treat it as a FLOOR, not a measurement, until the adapter fault is fixed:');
  for (const [k, n] of [...lost.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)) {
    console.log(`       ${String(n).padStart(5)} x  ${k}`);
  }
}
console.log(`== ATTRIBUTION == lifecycle pids: ${lifecycle.size}`);
console.log(`  writes  script ${writes.size}  /  whole traced subtree ${allWrites.size}`);
console.log(`  sockets script ${sockets}  /  whole traced subtree ${allSockets}`);
if (lifecycle.size === 0) {
  // Not a package with no needs — an attribution failure. Saying so beats emitting an empty grant
  // that reads as a confident "this package needs nothing".
  console.log('  ⛔ NO LIFECYCLE SHELL FOUND — the subtree filter matched nothing, so the grant');
  console.log('     below is EMPTY BY DEFAULT rather than by measurement. Treat it as UNKNOWN.');
}
// ⛔ ECHO THE ROOTS THE GRANT WAS COMPUTED AGAINST. Two jobs, and the second is why it is printed
// rather than merely held: it makes R2 auditable from `driver.out` alone — a reader can see that
// every root came from the capture, and can tell a `null` (this platform has no such root) from a
// path. A venue difference then shows up as different ROOTS in the log rather than as an unexplained
// difference in the grant.
console.log(`== ROOTS (from ${capturePath}; the classifier reads no other source) ==`);
for (const k of REQUIRED_ROOTS) {
  const v = roots[k];
  console.log(`  ${k.padEnd(13)} ${v === null ? '(null — this platform has no such root)' : v}`);
}
console.log('== WRITES the script actually performed ==');
for (const [k, v] of Object.entries(w)) {
  // Naming the free scopes in the log is what stops a reader reconciling a bucket against the grant
  // and concluding the synthesis dropped a write it deliberately did not bill.
  const free = k === 'ownPkg' ? '  (base profile already grants this — NOT billed)' : '';
  console.log(`  ${k.padEnd(9)} ${String(v.length).padStart(5)}${free}`);
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
// ⛔ AN UNPLACEABLE WRITE WIDENS THE GRANT TO EVERY WRITE SCOPE. We know a write happened and we do
// not know where, so the only sound grant is one covering everywhere it could have been. This is
// deliberately NOT `write:"disk"` — `classify.mjs` rule 3 is that an unmappable path is reported,
// never rounded up to disk — and it is not a drop either: dropping it would be an under-grant, the
// direction that breaks installs. The union of the three real scopes is the widest thing the v2
// vocabulary can express, and the NARROW arms then descend from it with real jailed runs, which is
// what recovers the true minimum. The cost is one extra arm per scope on affected packages.
if (cwdUnobservedWrite) g.write = { ...(g.write ?? {}), deps: true, project: true, userHome: true };
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
