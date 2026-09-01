// The win32 path axis of the denial witness. `node --test harness/v2/denial-witness-win32.test.mjs`.
//
// ⛔⛔ THIS FILE'S JOB IS TO PROVE ONE NEGATIVE: THAT THE WIN32 AXIS CANNOT RETURN A FALSE `CLEAN`.
// Everything else it asserts is secondary. A `CLEAN` licenses `record.mjs` to drop `write.userHome` —
// authority over the entire user home — and an under-grant breaks real installs, which is the one
// direction this project forbids. There are 131 win32-only whole-home specs whose grant no verified
// descent reached, so a scorer that answered CLEAN by accident would narrow them all on no evidence.
//
// ⛔ SO THE CASES ARE WRITTEN AS A MUTATION TABLE, NOT AS A HAPPY PATH. For each way the mapping or
// the gating could be wrong, there is a case that goes RED under that mutation — and each one names
// the mutation in as many words, because a test whose failure mode is not written down gets "fixed"
// by loosening the assertion. The mutations, and the case that catches each:
//
//   MUTATION                                                          CAUGHT BY
//   reuse the POSIX `under` (appends `/`) for win32 paths             separator
//   compare paths case-sensitively                                    case fold
//   read only `f`, not the 8.3 expansion `fx`                         short spelling
//   read only the source path, not the rename destination `g`/`gx`    rename destination
//   keep the POSIX `e.w === 1` write-intent term                      open-r refusal
//   loosen the control to any refusal status, not ACCESS_DENIED       privilege-only control
//   loosen the control to any event, not a Create                     rename-only control
//   infer `jailed`/`winRefusals` from `platform` instead of the flag  the two archive cases
//   let a root subtraction swallow the whole scope                    jailHome === home
//
// ⛔ AND THE POSITIVE CONTROL RUNS IN THE OTHER DIRECTION TOO. A stream that genuinely should be
// WITNESSED must not come back CLEAN, or the whole table above is satisfied by a scorer that answers
// VOID to everything and is therefore useless rather than merely safe.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { witness, axisFor } from './denial-witness.mjs';
import { REFUSAL_ACCESS_DENIED } from './adapters/windows-status.mjs';

const HERE = import.meta.dirname;
const REPO = path.resolve(HERE, '..', '..');
const CAP = 'no-write-userHome';

// ⛔ THE ROOTS ARE COPIED FROM A COMMITTED HEADER, NOT INVENTED — `records-v2/runs/win32-x64/
// victory-voronoi/0.0.5/events.ndjson.gz`. A fixture with a plausible-looking roots block would test
// this axis against a stream no adapter emits, and `toolsDir` living UNDER `home` is exactly the
// subtraction that has to keep working.
const ROOTS = {
  project: 'D:\\jail\\m-victoryvoronoi-msjz41t0\\observe',
  home: 'C:\\Users\\runneradmin',
  jailHome: null,
  globalStore: 'C:\\Users\\runneradmin\\AppData\\Local\\nub\\pm\\store',
  projectStore: 'D:\\jail\\m-victoryvoronoi-msjz41t0\\observe\\node_modules\\.store',
  interpreter: 'C:\\hostedtoolcache\\windows\\node\\22.23.2\\x64\\node.exe',
  toolsDir: 'C:\\Users\\runneradmin\\AppData\\Local\\nub\\pm\\tools',
  temp: 'D:\\jail\\m-victoryvoronoi-msjz41t0\\tmp',
  npmPrefix: null,
  ownPkg: 'D:\\jail\\m-victoryvoronoi-msjz41t0\\observe\\node_modules\\victory-voronoi',
  cwd: null,
};

const header = (over = {}) => ({
  k: 'h', v: 1, platform: 'win32-x64', jailed: true, winRefusals: true, roots: ROOTS, ...over });
const proc = (pid = 8736, life = 1) => ({ k: 'p', pid, ppid: 5116, ts: null, life, data: {} });

// Event shape copied from the committed stream: `{"k":"e","p":…,"o":"open-r","s":"Create","f":…,
// "st":"0x00000000","d":1,"n":1}`. No `w`, no `r` — that absence is the whole reason this axis exists.
const ev = (over) => ({ k: 'e', p: 8736, o: 'open-r', s: 'Create', f: null, st: '0x00000000', n: 1, ...over });
// Filler so a stream clears MIN_EVENTS with nothing in scope and nothing refused.
const filler = (n) => Array.from({ length: n }, (_, i) =>
  ev({ f: `D:\\jail\\m-victoryvoronoi-msjz41t0\\tmp\\f${i}` }));

// ⛔ THE CONTROL EVENT, PRESENT IN EVERY STREAM THAT IS MEANT TO BE SCOREABLE. A Create refused with
// ACCESS_DENIED, OUT of scope — under an allowlist jail a real arm denies hundreds of these outside
// the grant. Its absence is what makes a stream VOID, so a case that omits it is testing the control
// rather than the axis.
const control = () => ev({ s: 'Create', f: 'C:\\Windows\\System32\\config\\SAM', st: REFUSAL_ACCESS_DENIED });

const stream = (extra = [], { over = {}, withControl = true, life = 1 } = {}) => [
  header(over), proc(8736, life), ...filler(250), ...(withControl ? [control()] : []), ...extra];

// ── THE POSITIVE CONTROL, IN BOTH DIRECTIONS ────────────────────────────────────────────────────

test('a refused home access in the traced subtree is WITNESSED, and a live clean stream is CLEAN', () => {
  // Both halves in one case on purpose: a scorer that answered VOID to everything would satisfy every
  // safety assertion below while being useless, and a scorer that answered WITNESSED to everything
  // would be safe and equally useless. Only the pair pins that the axis discriminates at all.
  const hit = witness(stream([ev({ o: 'open-w', d: 5, f: 'C:\\Users\\runneradmin\\.foo', st: REFUSAL_ACCESS_DENIED })]), { cap: CAP });
  assert.equal(hit.verdict, 'WITNESSED', hit.reason);
  assert.equal(hit.scope, 'userHome');
  assert.equal(hit.refusalsInScope, 1);
  assert.match(hit.sample[0], /0xc0000022/, 'the sample must name the NTSTATUS, never `-1 undefined`');

  const clean = witness(stream(), { cap: CAP });
  assert.equal(clean.verdict, 'CLEAN', clean.reason);
  assert.equal(clean.refusalsInScope, 0);
});

// ── THE ARCHIVE CASES: THE EXACT CATASTROPHE, RUN AGAINST REAL COMMITTED DATA ────────────────────

const committedWin32 = () => {
  const dir = path.join(REPO, 'records-v2', 'runs', 'win32-x64');
  const found = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name === 'events.ndjson.gz') found.push(p);
    }
  };
  walk(dir);
  return found;
};

test('EVERY committed win32 stream is an OBSERVE capture and none of them carries `jailed`', () => {
  // ⛔ THE GUARD THIS PINS IS THE FIRST OF THE TWO. `windows-retain.mjs` sets `jailed` only from its
  // own `--jailed`, which no caller passes today; if a driver ever started passing it against an
  // OBSERVE capture, every one of these streams would become a candidate for scoring.
  const files = committedWin32();
  assert.ok(files.length > 1000, `expected the full win32 archive, found ${files.length} streams`);
  for (const f of files) {
    const h = JSON.parse(zlib.gunzipSync(fs.readFileSync(f)).toString('utf8').split('\n', 1)[0]);
    assert.notEqual(h.jailed, true, `${f} is marked jailed — an OBSERVE capture must never be`);
  }
});

test('⛔ THE CATASTROPHE: force `jailed` + `winRefusals` onto a real OBSERVE stream and it is VOID, never CLEAN', () => {
  // ⛔⛔ THIS IS THE CASE THE WHOLE AXIS EXISTS TO PASS, AND IT IS RUN AGAINST REAL DATA RATHER THAN A
  // FIXTURE. Stamping `jailed` without correctly gating the vocabulary is the named dangerous version
  // of this change: an OBSERVE arm is UNJAILED, so it contains no jail refusal at all, and a scorer
  // that read its silence as CLEAN would license narrowing every win32 whole-home grant on nothing.
  //
  // MEASURED over all 1,688 committed win32 streams: ZERO carry a Create refused with
  // STATUS_ACCESS_DENIED, so the axis's positive control cannot be satisfied by any of them and the
  // verdict is VOID. 19 of them DO carry a refused Create — every one `0xc0000061`
  // STATUS_PRIVILEGE_NOT_HELD from the harness's own SeBackup drop — which is exactly why the control
  // names one status rather than "a refusal".
  //
  // RED ON MUTATION: loosen the control to any refusal status, or to any event class, and the 19
  // privilege-refused streams start scoring and this goes red.
  const files = committedWin32();
  let scored = 0;
  for (const f of files) {
    const rows = zlib.gunzipSync(fs.readFileSync(f)).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
    rows[0].jailed = true;
    rows[0].winRefusals = true;
    const r = witness(rows, { cap: CAP });
    assert.notEqual(r.verdict, 'CLEAN', `${f} scored CLEAN — that is a blanket licence to narrow`);
    assert.equal(r.verdict, 'VOID', `${f} scored ${r.verdict}; the control must refuse an observe stream`);
    scored++;
  }
  assert.ok(scored > 1000, `only ${scored} streams checked`);
});

test('an unmodified committed win32 stream is VOID on the `jailed` guard, before the axis is even chosen', () => {
  const f = committedWin32()[0];
  const rows = zlib.gunzipSync(fs.readFileSync(f)).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  const r = witness(rows, { cap: CAP });
  assert.equal(r.verdict, 'VOID');
  assert.match(r.reason, /not marked `jailed`/);
});

// ── THE TWO FLAG GATES ──────────────────────────────────────────────────────────────────────────

test('a win32 stream without `winRefusals` is UNSUPPORTED — the platform name must not select the axis', () => {
  // RED ON MUTATION: key the axis on `header.platform === 'win32-x64'` instead of the flag, and this
  // stream — which is what every adapter before this change emitted — starts being scored.
  const rows = stream([ev({ o: 'open-w', f: 'C:\\Users\\runneradmin\\.foo', st: REFUSAL_ACCESS_DENIED })],
    { over: { winRefusals: undefined } });
  const r = witness(rows, { cap: CAP });
  assert.equal(r.verdict, 'UNSUPPORTED', r.reason);
});

test('⛔ THE LATENT HOLE: `jailed` alone on a real win32 stream is UNSUPPORTED, and used to be CLEAN', () => {
  // ⛔⛔ THIS CASE FOUND A LIVE FALSE `CLEAN` IN THE FILE AS IT SHIPPED, and it is the one the brief
  // for this change had already measured without identifying its cause. Stamping ONLY `jailed` sends
  // the stream down the POSIX path axis, whose `under` appends `/` — so against
  // `C:\Users\runneradmin` the scope is EMPTY, nothing is ever in it, and the axis (correctly, for a
  // namespace it can read) applies no control and answers CLEAN.
  //
  // MEASURED before the namespace guard: `victory-voronoi@0.0.5` returned
  // `CLEAN, events 12525, refusalsInScope 0`. Note the cause is NOT a missing `st` -> `r` mapping —
  // no mapping runs at all, because the matcher matches nothing. A fix that only added the mapping
  // would have left this exactly as it was.
  //
  // RED ON MUTATION: delete the `ns` check from `scopeMatcher`.
  const f = committedWin32().find((p) => p.includes(`${path.sep}victory-voronoi${path.sep}`))
    ?? committedWin32()[0];
  const rows = zlib.gunzipSync(fs.readFileSync(f)).toString('utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  rows[0].jailed = true;
  const r = witness(rows, { cap: CAP });
  assert.notEqual(r.verdict, 'CLEAN', `${f} scored CLEAN on a Windows path through the POSIX matcher`);
  assert.equal(r.verdict, 'UNSUPPORTED', r.reason);
});

test('`no-network` stays UNSUPPORTED on win32 — the decoder writes `st: null` on every network event', () => {
  const r = witness(stream(), { cap: 'no-network' });
  assert.equal(r.verdict, 'UNSUPPORTED', r.reason);
});

// ── THE CONTROL ─────────────────────────────────────────────────────────────────────────────────

test('a stream whose only refused Create is PRIVILEGE_NOT_HELD is VOID — that is the wrong access check', () => {
  // ⛔ THE 19-STREAM CASE, AS A FIXTURE. `0xc0000061` comes from the privilege check; the AppContainer
  // DACL refusal this axis reads is `0xc0000022` from `SeAccessCheck`. A control satisfied by the
  // former proves nothing about whether the latter is visible.
  // RED ON MUTATION: change the control to `REFUSAL_STATUS.has(e.st)` and this scores CLEAN.
  const rows = stream([], { withControl: false }).concat([
    ev({ s: 'Create', f: 'C:\\Users\\runneradmin\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations\\x.customDestinations-ms', st: '0xc0000061' }),
  ]);
  // That event is itself in scope, so it is a HIT — which is safe. Drop it from scope to isolate the
  // control: the same status, outside the home.
  const isolated = stream([], { withControl: false }).concat([
    ev({ s: 'Create', f: 'C:\\Windows\\System32\\config\\SAM', st: '0xc0000061' })]);
  assert.equal(witness(isolated, { cap: CAP }).verdict, 'VOID');
  assert.match(witness(isolated, { cap: CAP }).reason, /STATUS_ACCESS_DENIED/);
  // And the in-scope one still keeps the grant rather than narrowing it.
  assert.equal(witness(rows, { cap: CAP }).verdict, 'VOID');
});

test('a stream whose only ACCESS_DENIED is on a Rename is VOID — the control must validate the Create path', () => {
  // RED ON MUTATION: drop the `CREATE_EVENTS.has(e.s)` term from the control. The 3 committed streams
  // carrying an ACCESS_DENIED do so on Rename/SetDelete, so that mutation makes them scoreable.
  const rows = stream([], { withControl: false }).concat([
    ev({ o: 'setinfo', s: 'Rename', f: 'D:\\jail\\x\\npm-cache\\_cacache\\tmp\\abc', st: REFUSAL_ACCESS_DENIED })]);
  const r = witness(rows, { cap: CAP });
  assert.equal(r.verdict, 'VOID', r.reason);
});

test('a stream with no refusal at all is VOID, not CLEAN — silence is not evidence', () => {
  const r = witness(stream([], { withControl: false }), { cap: CAP });
  assert.equal(r.verdict, 'VOID', r.reason);
});

// ── THE SCOPE MATCHER: FOUR MUTATIONS, FOUR CASES ───────────────────────────────────────────────

const hitsOn = (over) => witness(stream([ev({ st: REFUSAL_ACCESS_DENIED, ...over })]), { cap: CAP });

test('MUTATION separator: a `\\`-spelled home path is in scope', () => {
  // ⛔ THE SINGLE MOST DANGEROUS LINE IN THE AXIS. The POSIX `under` appends `/`, so against
  // `C:\Users\runneradmin` it matches NOTHING on Windows — every stream would find zero refusals and
  // score CLEAN. RED ON MUTATION: swap `underWin` for `under`.
  const r = hitsOn({ f: 'C:\\Users\\runneradmin\\.cache\\thing' });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
});

test('MUTATION case fold: an upper-cased home path is in scope — NTFS is case-insensitive', () => {
  // RED ON MUTATION: drop the `.toLowerCase()` from `winKey`. The kernel reports whichever spelling
  // the caller used, so a case-sensitive compare drops real refusals — the CLEAN direction.
  const r = hitsOn({ f: 'C:\\USERS\\RUNNERADMIN\\.cache\\thing' });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
});

test('MUTATION short spelling: a refusal whose 8.3 `f` expands into the home via `fx` is in scope', () => {
  // ⛔ On a GitHub runner `%TEMP%` is literally `C:\Users\RUNNER~1\…`, so a package resolving through
  // the environment produces short-spelled paths that do not prefix-match the long `home` root.
  // RED ON MUTATION: read only `e.f`.
  const r = hitsOn({ f: 'C:\\Users\\RUNNER~1\\.cache\\thing', fx: 'C:\\Users\\runneradmin\\.cache\\thing' });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
});

test('MUTATION rename destination: a refused rename INTO the home is in scope via `g`', () => {
  // RED ON MUTATION: read only the source path. A rename into the home is a write to the home, and
  // `windows-retain.mjs` puts the destination on `g` with the source on `f`.
  const r = hitsOn({ o: 'dest', s: 'RenamePath', kind: 'rename',
    f: 'D:\\jail\\x\\tmp\\staged', g: 'C:\\Users\\runneradmin\\.config\\thing' });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
});

test('MUTATION write-intent: an `open-r` refusal in the home is a HIT — win32 has no write-intent term', () => {
  // ⛔ THE TERM THE REGISTRY ENTRY CALLED STRUCTURAL. Create carries no DesiredAccess, so a script
  // opening an EXISTING home file for write emits disposition FILE_OPEN, i.e. `open-r`. Requiring
  // `w === 1` would miss exactly that and read CLEAN. RED ON MUTATION: re-add `e.w === 1`.
  const r = hitsOn({ o: 'open-r', d: 1, f: 'C:\\Users\\runneradmin\\.npmrc' });
  assert.equal(r.verdict, 'WITNESSED', r.reason);
});

test('a declared root nested under the home is still SUBTRACTED — the tool cache is not a home write', () => {
  // The other direction of the matcher: `toolsDir` lives under `home` and the jail grants it, so a
  // refusal there is not a home write. This is the one place a NARROWER answer is correct.
  const r = hitsOn({ o: 'open-w', f: 'C:\\Users\\runneradmin\\AppData\\Local\\nub\\pm\\tools\\ms-playwright\\x' });
  assert.equal(r.verdict, 'CLEAN', r.reason);
});

test('a subtraction that swallows the whole scope is UNSUPPORTED, never CLEAN', () => {
  // ⛔ RED ON MUTATION: delete the empty-scope guard. A `capture.json` declaring `jailHome === home`
  // would leave a scope in which no refusal can ever be found, and the axis would answer CLEAN for
  // every package while looking perfectly healthy.
  const rows = stream([ev({ o: 'open-w', f: 'C:\\Users\\runneradmin\\.foo', st: REFUSAL_ACCESS_DENIED })],
    { over: { roots: { ...ROOTS, jailHome: 'C:\\Users\\runneradmin' } } });
  const r = witness(rows, { cap: CAP });
  assert.equal(r.verdict, 'UNSUPPORTED', r.reason);
});

// ── THE GUARDS THE AXIS INHERITS ────────────────────────────────────────────────────────────────

test('the shared guards still fire on a win32 stream: not jailed, too few events, no lifecycle proc', () => {
  const inScope = ev({ o: 'open-w', f: 'C:\\Users\\runneradmin\\.foo', st: REFUSAL_ACCESS_DENIED });
  assert.equal(witness(stream([inScope], { over: { jailed: false } }), { cap: CAP }).verdict, 'VOID');
  assert.equal(witness([header(), proc(), control(), inScope], { cap: CAP }).verdict, 'VOID');
  assert.equal(witness(stream([inScope], { life: 0 }), { cap: CAP }).verdict, 'VOID');
});

// ── NO POSIX VERDICT MOVES ──────────────────────────────────────────────────────────────────────

test('a linux stream is scored exactly as before — the win32 branch is unreachable without the flag', () => {
  // ⛔ THE REGRESSION THAT WOULD BE INVISIBLE. `scopeMatcher` gained a comparator parameter and
  // `axisFor` gained a branch; either could have moved a committed linux or darwin verdict. The POSIX
  // comparator is the default and the branch is gated on a flag no POSIX adapter sets, so neither can.
  const linuxRoots = { project: '/home/runner/p', home: '/home/runner', jailHome: '/home/runner/p/jh' };
  const h = { k: 'h', v: 1, platform: 'linux-x64', jailed: true, netRefusals: true, roots: linuxRoots };
  const p = { k: 'p', pid: 1, life: 1 };
  const fill = Array.from({ length: 250 }, (_, i) => ({ k: 'e', p: 1, o: 'open-w', s: 'openat', f: `/tmp/f${i}`, r: 0, w: 1, n: 1 }));
  const refused = { k: 'e', p: 1, o: 'open-w', s: 'openat', f: '/home/runner/.pulumi/x', r: 'EACCES', w: 1, n: 1 };
  assert.equal(witness([h, p, ...fill, refused], { cap: CAP }).verdict, 'WITNESSED');
  assert.equal(witness([h, p, ...fill], { cap: CAP }).verdict, 'CLEAN');
  // And a read-only refusal in the home still does NOT witness on POSIX, where `w` is real evidence.
  const readRefusal = { k: 'e', p: 1, o: 'open-r', s: 'openat', f: '/home/runner/.pulumi/x', r: 'EACCES', n: 1 };
  assert.equal(witness([h, p, ...fill, readRefusal], { cap: CAP }).verdict, 'CLEAN');
  // The axis object itself is the POSIX one.
  assert.equal(typeof axisFor(CAP, h).hit, 'function');
  assert.equal(axisFor(CAP, h).control([]), null, 'the POSIX path axis needs no control');
});
