// Cases for the denial witness. `node --test harness/v2/denial-witness.test.mjs`.
//
// ⛔ THE VOID CASES CARRY THE WEIGHT. A detector that returns CLEAN whenever it cannot read its
// evidence hands out a blanket licence to narrow — an under-grant produced by pointing the instrument
// at the wrong file — and every "this witnesses" assertion would still pass. So each way the input can
// be useless is asserted to land on VOID, and CLEAN is asserted only where a live, jailed, attributed
// stream genuinely contains no refusal.
//
// ⛔ THE EVENT FIXTURES ARE THE REAL NORMALIZED SHAPE, taken from a committed record rather than
// invented: `records-v2/runs/linux-x64/@pulumi+gcp/0.16.9/events.ndjson.gz` holds
// `{"k":"e","p":16315,"o":"open-w","s":"openat","f":"/home/runner/.pulumi/.cachedVersionInfo","r":0,
// "fl":"O_RDWR|O_CREAT|O_TRUNC|O_CLOEXEC","w":1,"n":1}` and a `k:"p"` row carrying `life`. A fixture
// in a different shape would test this file against a stream no adapter emits.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { witness, scopeMatcher, marker, axisFor, REFUSAL_ERRNO } from './denial-witness.mjs';

// ⛔ `import.meta.dirname`, never `new URL(...).pathname` — see the note in arm-falsifiability.test.mjs.
const HERE = import.meta.dirname;
const TOOL = join(HERE, 'denial-witness.mjs');

const ROOTS = {
  project: '/home/runner/v2-uyXXxI/verify-drop-nowriteuserHome',
  home: '/home/runner',
  jailHome: '/home/runner/v2-uyXXxI/jailhome',
  jailTmp: '/tmp/nub-tmp-obs7gIdVg',
  ownPkg: '/home/runner/v2-uyXXxI/verify-drop-nowriteuserHome/node_modules/@pulumi/gcp',
};

const header = (over = {}) => ({ k: 'h', v: 1, platform: 'linux-x64', jailed: true, roots: ROOTS, ...over });
const proc = (pid, life = 1) => ({ k: 'p', pid, ppid: null, exe: null, argv: null, cwd: null, life });
// Filler so a stream clears MIN_EVENTS without any of it being in scope.
const filler = (n, pid = 16315) => Array.from({ length: n }, (_, i) => ({
  k: 'e', p: pid, o: 'open-w', s: 'openat', f: `/tmp/nub-tmp-obs7gIdVg/f${i}`, r: 0, w: 1, n: 1 }));
const refusedHomeWrite = (pid = 16315) => ({
  k: 'e', p: pid, o: 'open-w', s: 'openat',
  f: '/home/runner/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp',
  r: 'EACCES', fl: 'O_WRONLY|O_CREAT|O_TRUNC', w: 1, n: 1 });

const stream = (extra = [], { life = 1, over = {} } = {}) =>
  [header(over), proc(16315, life), ...filler(250), ...extra];

const CAP = 'no-write-userHome';

test('a refused home write in the lifecycle subtree is WITNESSED — the script asked and was denied', () => {
  // RED ON REVERT: change the `hits` filter to ignore `REFUSAL_ERRNO` (accept any `r`), or drop the
  // `w === 1` term, and this still passes — so the negative controls below are what pin it. The real
  // instance is @pulumi/gcp@0.16.9, whose OBSERVE trace writes
  // `.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp` into the REAL home by absolute path
  // (it resolves the home through getpwuid, not $HOME) and whose drop-no-write-userHome arm still
  // reported rc=0 artifacts=697/697.
  const r = witness(stream([refusedHomeWrite()]), { cap: CAP });
  assert.equal(r.verdict, 'WITNESSED');
  assert.equal(r.scope, 'userHome');
  assert.equal(r.refusalsInScope, 1);
  assert.match(r.sample[0], /pulumi-resource-gcp = -1 EACCES/);
});

test('a live jailed stream with no in-scope refusal is CLEAN — the green arm is evidence', () => {
  const r = witness(stream(), { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', `expected CLEAN, got ${r.verdict}: ${r.reason}`);
  assert.equal(r.refusalsInScope, 0);
});

test('a refusal OUTSIDE the lifecycle subtree does not witness — attribution is the adapter\'s', () => {
  // The refusal is real and in scope, but it belongs to a pid the adapter marked life:0 — nub's own
  // resolver, npm, a tool. Billing it against the package is the exact mistake that produced three
  // wrong hand-rolled trace scans on this effort.
  const rows = [header(), proc(16315, 1), proc(999, 0), ...filler(250), refusedHomeWrite(999)];
  const r = witness(rows, { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', `expected CLEAN, got ${r.verdict}: ${r.reason}`);
  assert.equal(r.refusalsInScope, 0);
});

test('a refused READ under the home does not witness a WRITE scope', () => {
  const read = { ...refusedHomeWrite(), o: 'open-r', w: 0, f: '/home/runner/.npmrc' };
  const r = witness(stream([read]), { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', `expected CLEAN, got ${r.verdict}: ${r.reason}`);
});

test('ENOENT is not a refusal — a jail that hides a path and a file that never existed look alike', () => {
  const enoent = { ...refusedHomeWrite(), r: 'ENOENT' };
  const r = witness(stream([enoent]), { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', `expected CLEAN, got ${r.verdict}: ${r.reason}`);
  assert.ok(!REFUSAL_ERRNO.has('ENOENT'));
});

test('a SUCCESSFUL home write does not witness — r=0 means the write happened', () => {
  const ok = { ...refusedHomeWrite(), r: 0 };
  const r = witness(stream([ok]), { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', `expected CLEAN, got ${r.verdict}: ${r.reason}`);
});

test('a refusal under a declared NON-home root is out of scope', () => {
  // The jail home and the arm project both sit under /home/runner on this venue. Counting them as
  // `userHome` would witness on every arm that touched its own throwaway home — CLEAN would become
  // unreachable and the detector would keep every grant wide forever, which looks safe and is inert.
  for (const f of [`${ROOTS.jailHome}/.config/x`, `${ROOTS.project}/build/x`, `${ROOTS.ownPkg}/x`]) {
    const r = witness(stream([{ ...refusedHomeWrite(), f }]), { cap: CAP });
    assert.equal(r.verdict, 'CLEAN', `${f} should be out of scope, got ${r.verdict}`);
  }
});

test('--exclude subtracts a directory the header does not declare', () => {
  const f = '/home/runner/v2-uyXXxI/scratch/x';
  assert.equal(witness(stream([{ ...refusedHomeWrite(), f }]), { cap: CAP }).verdict, 'WITNESSED');
  assert.equal(
    witness(stream([{ ...refusedHomeWrite(), f }]), { cap: CAP, exclude: ['/home/runner/v2-uyXXxI'] }).verdict,
    'CLEAN');
});

test('a prefix that is not a path boundary does not subtract — /home/runner-2 is not the home', () => {
  const r = witness(stream([{ ...refusedHomeWrite(), f: '/home/runner-2/.pulumi/x' }]), { cap: CAP });
  assert.equal(r.verdict, 'CLEAN', 'a sibling directory sharing a prefix is not under the home');
});

// ── VOID: every way the evidence can be unreadable ────────────────────────────────────────────

test('an UNJAILED stream is VOID, never CLEAN — scoring OBSERVE would license everything', () => {
  // The single most dangerous input. OBSERVE is unjailed, so it contains no jail refusal at all;
  // read as a drop arm it says CLEAN for every package on earth.
  const r = witness(stream([refusedHomeWrite()], { over: { jailed: false } }), { cap: CAP });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /not marked `jailed`/);
});

test('a stream with no header is VOID — without roots a path means nothing', () => {
  const r = witness([proc(16315), ...filler(250)], { cap: CAP });
  assert.equal(r.verdict, 'VOID');
});

test('a stream with no attributed lifecycle process is VOID, never CLEAN', () => {
  // The subtree filter matching nothing is precisely when "no refusal was attributed" says nothing.
  const r = witness(stream([], { life: 0 }), { cap: CAP });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /no lifecycle process/);
});

test('a short stream is VOID — the tracer did not observe an install', () => {
  const r = witness([header(), proc(16315), ...filler(3)], { cap: CAP });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /decoded events/);
});

test('a header with no home root is VOID rather than matching nothing', () => {
  const r = witness(stream([refusedHomeWrite()], { over: { roots: { project: '/p' } } }), { cap: CAP });
  assert.equal(r.verdict, 'UNSUPPORTED');
  assert.equal(scopeMatcher(CAP, { project: '/p' }), null);
});

test('a capability this scorer expresses no axis for is UNSUPPORTED, not CLEAN', () => {
  // `no-network` is in the list on purpose even though it now HAS an axis: `stream()`'s header
  // carries no `netRefusals`, which is exactly the shape of a stream decoded before the adapter
  // retained socket outcomes, and of every darwin stream. The axis must refuse it.
  for (const cap of ['no-network', 'no-write-deps', 'no-write-project', 'no-read']) {
    const r = witness(stream(), { cap });
    assert.equal(r.verdict, 'UNSUPPORTED', `${cap} must not be scored`);
  }
});

// ── the network axis ──────────────────────────────────────────────────────────────────────────
//
// ⛔ WHY THIS AXIS EXISTS AND WHY IT WAS RIGHT TO REFUSE IT UNTIL NOW. `record.mjs` licenses a
// narrowing only when EVERY dropped capability comes back CLEAN, and MEASURED over the 6887
// committed records, 153 of the blocked set dropped `no-network` beside `no-write-userHome` — so a
// perfect answer on the home arm moved none of them. The refusal was not conservatism for its own
// sake: both POSIX adapters classified `connect` alone, and nub's filter
// (`vendor/aube/crates/aube-scripts/src/linux_jail.rs`) refuses at `socket`/`socketpair`, so a
// refused network attempt produced NO EVENT and its absence was not evidence of absence.
const NET = 'no-network';
// A header from a decoder that retains socket-family outcomes. Without this flag the axis refuses.
const netHeader = (over = {}) => ({ netRefusals: true, ...over });
const sock = (r, pid = 16315, s = 'socket') => ({ k: 'e', p: pid, o: 'net', s, r, n: 1 });
// The scorer's positive control: an arm runs a real `nub install`, so the tool processes open
// registry sockets whether or not the script does. A stream with none did not capture the syscall.
const toolSocket = () => sock(0, 999);
const netStream = (extra = [], { life = 1 } = {}) =>
  [header(netHeader()), proc(16315, life), proc(999, 0), ...filler(250), toolSocket(), ...extra];

test('a refused socket() in the lifecycle subtree is WITNESSED — the script asked for the network', () => {
  const r = witness(netStream([sock('EPERM')]), { cap: NET });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
  assert.equal(r.scope, 'network');
  assert.equal(r.refusalsInScope, 1);
  assert.match(r.sample[0], /^socket = -1 EPERM$/, 'a path axis names the path; this one has none to name');
});

test('socketpair, bind, sendto and a refused connect all witness the same axis', () => {
  for (const e of [sock('EPERM', 16315, 'socketpair'), sock('EPERM', 16315, 'bind'),
    sock('EPERM', 16315, 'sendto'),
    { k: 'e', p: 16315, o: 'connect', s: 'connect', h: '104.16.1.34', pt: 443, r: 'EPERM', n: 1 }]) {
    const r = witness(netStream([e]), { cap: NET });
    assert.equal(r.verdict, 'WITNESSED', `${e.s} must witness: ${r.reason}`);
  }
});

test('a live jailed stream whose script opened no socket is CLEAN — the green arm is evidence', () => {
  const r = witness(netStream(), { cap: NET });
  assert.equal(r.verdict, 'CLEAN', r.reason);
  assert.equal(r.refusalsInScope, 0);
});

test('a SUCCESSFUL socket() does not witness — r=0 means the jail let it through', () => {
  const r = witness(netStream([sock(0)]), { cap: NET });
  assert.equal(r.verdict, 'CLEAN', r.reason);
});

test('a socket refusal outside the lifecycle subtree does not witness', () => {
  // nub's own resolver opens registry sockets in the same traced tree and is life:0. Billing one of
  // its failures against the package is the attribution mistake the adapter exists to prevent.
  const r = witness(netStream([sock('EPERM', 999)]), { cap: NET });
  assert.equal(r.verdict, 'CLEAN', r.reason);
});

test('a filesystem refusal does not witness the network axis, and vice versa', () => {
  // The two axes must not leak into each other: a home EACCES is not a network need, and a socket
  // EPERM is not a home write. Both directions, because either leak licenses the wrong thing.
  assert.equal(witness(netStream([refusedHomeWrite()]), { cap: NET }).verdict, 'CLEAN');
  const fsStream = [header(netHeader()), proc(16315, 1), ...filler(250), sock('EPERM')];
  assert.equal(witness(fsStream, { cap: CAP }).verdict, 'CLEAN');
});

// ⛔⛔ THE DANGEROUS DIRECTION. Every case below is a stream in which a refusal COULD NOT have been
// recorded. Reading any of them as CLEAN publishes an under-grant on a package that needs the
// network — the one direction this project forbids — and every "this witnesses" assertion above
// would still pass while it happened.

test('⛔ a stream whose decoder cannot see socket outcomes is UNSUPPORTED, never CLEAN', () => {
  // RED ON REVERT: delete the `header?.netRefusals !== true` guard from `axisFor`. Every darwin
  // stream — whose dtrace probe has no `socket` clause at all — and every stream decoded before the
  // adapter retained the family then reads CLEAN, because it contains no socket event to refuse.
  const r = witness(stream(), { cap: NET });
  assert.equal(r.verdict, 'UNSUPPORTED', r.reason);
  assert.match(r.reason, /netRefusals/);
  assert.equal(axisFor(NET, { netRefusals: false }), null, 'and the axis refuses to be built at all');
});

test('⛔ a stream declaring the flag but holding NO socket outcome at all is VOID, never CLEAN', () => {
  // RED ON REVERT: delete the network axis's `control`; this stream then reads CLEAN and licenses a
  // narrowing. That is the case a header flag cannot catch — the decoder declares the capability but
  // the TRACER never captured a socket call, which is exactly what an `strace -e trace=` filter
  // omitting the network class produces. An arm runs a real `nub install`, so the absence of even a
  // TOOL-process socket is proof the instrument was blind rather than proof the script was quiet.
  const blind = [header(netHeader()), proc(16315, 1), ...filler(250)];
  const r = witness(blind, { cap: NET });
  assert.equal(r.verdict, 'VOID', r.reason);
  assert.match(r.reason, /no socket\(\)\/socketpair\(\) outcome/);
  // And the same stream WITH the census present is the positive control for this control: it must
  // reach a real verdict, or the guard would be indistinguishable from one that voids everything.
  assert.equal(witness([...blind, toolSocket()], { cap: NET }).verdict, 'CLEAN');
});

test('⛔ an UNJAILED stream is VOID on the network axis too — scoring OBSERVE licenses everything', () => {
  const r = witness([header({ ...netHeader(), jailed: false }), proc(16315, 1), ...filler(250),
    toolSocket()], { cap: NET });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /not marked `jailed`/);
});

test('⛔ a network stream with no attributed lifecycle process is VOID, never CLEAN', () => {
  const r = witness(netStream([], { life: 0 }), { cap: NET });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /no lifecycle process/);
});

// ── CLI ───────────────────────────────────────────────────────────────────────────────────────

const writeStream = (rows, gz = false) => {
  const p = join(mkdtempSync(join(tmpdir(), 'dw-')), gz ? 'events.ndjson.gz' : 'events.ndjson');
  const text = rows.map((r) => JSON.stringify(r)).join('\n') + '\n';
  writeFileSync(p, gz ? gzipSync(Buffer.from(text)) : text);
  return p;
};
const cli = (a) => execFileSync(process.execPath, [TOOL, ...a], { encoding: 'utf8' });
const payload = (out) => JSON.parse(/DENIAL-WITNESS (\{.*\})/.exec(out)[1]);

test('the CLI prints one machine-readable marker line', () => {
  const p = writeStream(stream([refusedHomeWrite()]));
  const j = payload(cli(['--cap', CAP, '--events', p]));
  assert.equal(j.verdict, 'WITNESSED');
  assert.equal(j.cap, CAP);
  assert.equal(j.scope, 'userHome');
});

test('the CLI reads a gzipped stream — an adapter --out ending in .gz is normal', () => {
  // RED ON REVERT: drop the magic-number branch in readEvents. A gzipped file then decodes to binary,
  // yields zero parseable rows, and the arm reports VOID for a stream that was perfectly good — or,
  // with a laxer VOID rule, CLEAN.
  const p = writeStream(stream([refusedHomeWrite()]), true);
  assert.equal(payload(cli(['--cap', CAP, '--events', p])).verdict, 'WITNESSED');
});

test('the CLI unions several arm traces — an arm runs install AND approve-builds', () => {
  const a = writeStream(stream());
  const b = writeStream([header(), proc(16315), refusedHomeWrite()]);
  assert.equal(payload(cli(['--cap', CAP, '--events', a, '--events', b])).verdict, 'WITNESSED');
});

test('an unreadable events file is VOID and names the file, never a silent CLEAN', () => {
  const out = cli(['--cap', CAP, '--events', '/definitely/not/here.ndjson']);
  const j = payload(out);
  assert.equal(j.verdict, 'VOID');
  assert.match(out, /ENOENT|no event stream could be read/);
});

test('the marker survives a round trip through the recorder\'s parse', () => {
  const line = marker(witness(stream([refusedHomeWrite()]), { cap: CAP }));
  const m = /^DENIAL-WITNESS\s+(\{.*\})\s*$/.exec(line);
  assert.ok(m, 'the recorder anchors its regex at both ends of the line');
  assert.equal(JSON.parse(m[1]).verdict, 'WITNESSED');
});
