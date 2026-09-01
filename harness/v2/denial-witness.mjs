// Did the DROP ARM's script actually ASK for the capability the arm removed?
//
// ⛔ THIS IS THE MACHINERY `record.mjs` NAMES AS MISSING. Its `applyGrantSourceRule` says, verbatim:
// "a script that writes its essential output into the home and swallows the EACCES in a try/catch —
// a swallow no shell-level `SWALLOWS` regex can see — would still narrow wrongly. Closing that needs
// an arm that traces the DENIED write and asserts it was attempted-and-refused, which is machinery
// this harness does not have." This is that arm's SCORER.
//
// THE PROBLEM IT SOLVES, IN ONE PARAGRAPH. `arm-falsifiability.mjs` flags a package whose artifact
// gate is vacuous — it ships its build output prebuilt, so the gate passes in every arm including a
// broken one. For 213 records the gate is vacuous AND no descent arm ever went red, so nothing in the
// run could have failed and a green `no-write-userHome` arm is not evidence. MEASURED on the
// committed corpus 2026-08-31: 202 of those 213 carry `userHome` as the ONLY write scope in the
// grant, so no widening of the artifact gate can help — the home write IS the script's only
// observable product and the drop arm denies exactly it.
//
// THE DISCRIMINANT. In the drop arm the jail refuses the write, and on both POSIX platforms that
// refusal is an ORDINARY SYSCALL FAILURE the tracer already decodes:
//
//   linux    Landlock is an LSM. `openat()` enters the kernel, the hook denies, the syscall returns
//            `-EACCES` to userspace. `adapters/linux.mjs` records it as `r: "EACCES"`.
//   darwin   Seatbelt denies at the MAC layer and the syscall likewise returns with an errno.
//            `adapters/macos-observe.d`'s OPEN return probe reads `errno` and `macos-eventlog.mjs`
//            normalizes it to the same symbolic name.
//
// ⛔ THAT IS MEASURED, NOT ASSUMED, AND THE EVIDENCE IS IN THIS REPOSITORY. `measure-macos.sh`'s
// DIAGNOSE arm has re-run failing grants JAILED under dtrace for 223 committed darwin records; ZERO
// of them printed "no diagnose trace produced", the median trace is 6737 lines, and 19 of them
// decoded at least one refusal on a path under the REAL user home — `gentype@4.5.0` records
// `/Users/runner/.CFUserTextEncoding`, others `/Users/runner/Library/Android/sdk`. A Seatbelt denial
// inside the jail therefore reaches the tracer. On linux the same shape is `measure.sh`'s
// `diagnose()`, which calls `verify "$GRANT" "diag" "strace -f -o …"` — a jailed arm under strace —
// and ran on 244 committed records with zero "DIAGNOSE skipped (no strace)".
//
// ⛔⛔ THE THREE VERDICTS, AND WHICH DIRECTION EACH FAILS IN.
//
//   WITNESSED  a refusal inside the dropped scope, in the lifecycle subtree. The script WANTED the
//              capability and was refused; the arm's green means the refusal was SWALLOWED, not that
//              the capability was unnecessary. ⇒ KEEP THE WIDE GRANT. This is the only verdict that
//              can move a record toward a wider grant, and it is the whole point.
//   CLEAN      the trace is live, the lifecycle subtree is attributed, and NOTHING inside the
//              dropped scope was refused. The script never asked. ⇒ the green arm is evidence.
//   VOID       the trace is unusable — absent, empty, not a jailed decode, no lifecycle process
//              identified, or the axis's own positive control failed (the network axis: not one
//              socket-family outcome anywhere in the stream, so the syscall the jail refuses was
//              never captured). ⇒ NO LICENCE EITHER WAY. `record.mjs` falls back to the rule it had.
//
// VOID IS THE DEFAULT AND EVERY UNCERTAIN PATH LANDS ON IT. Under-granting breaks real installs and
// is the one direction this project forbids, so a detector that cannot read its own evidence must
// never license a narrowing.
//
// ⛔ SCOPE MATCHING IS DELIBERATELY GENEROUS, AND THE ASYMMETRY IS THE SAFETY ARGUMENT. `userHome`
// means "under `roots.home`, minus every OTHER root the header declares" (project, jailHome, jailTmp,
// ownPkg, plus any `--exclude`). That is WIDER than `observe.mjs`'s classifier, which additionally
// carves the `toolsRw` leaves out of the home. Being wider can only ever turn a CLEAN into a
// WITNESSED, i.e. keep a grant that might have been droppable — the safe direction. Being narrower
// could turn a WITNESSED into a CLEAN and publish an under-grant, which is why this file does not
// re-implement the classifier and does not try to be exact. In practice the difference is empty: the
// tool-cache leaves are granted by the base profile, so a write there is not refused at all.
//
// ⛔ TWO CAPABILITIES ARE SUPPORTED: `no-write-userHome` and `no-network`. Every other one returns
// `UNSUPPORTED`, which `record.mjs` treats exactly like an absent marker. The remaining write scopes
// cannot be expressed against the header roots without re-deriving `observe.mjs`'s bucket order,
// which is the thing the paragraph above refuses to do. Adding one is a scope matcher plus its
// tests, not a redesign.
//
// ⛔⛔ THE NETWORK AXIS, AND WHY IT WAS THE LARGER HALF OF THE PROBLEM. `no-write-userHome` alone
// unblocks a record only when it is the ONLY capability the descent dropped, because `record.mjs`
// licenses a narrowing on `every` dropped capability being CLEAN. MEASURED over the 6887 committed
// records: of the blocked set, exactly 153 dropped `no-network` ALONGSIDE `no-write-userHome`
// (linux-x64 95, win32-x64 57, darwin-arm64 1) — so for those the home arm could answer perfectly
// and the record still could not move, because nothing had ever been pointed at the network axis.
//
// ⛔ IT WAS UNSUPPORTED FOR A CORRECT REASON, AND THE FIX IS IN THE DECODER RATHER THAN HERE. Both
// POSIX adapters classified `connect` ONLY, and the jail does not refuse at `connect`: nub's filter
// (`vendor/aube/crates/aube-scripts/src/linux_jail.rs`) attaches its denied-family rules to
// `SYS_socket` and `SYS_socketpair` alone, with `match_action = Errno(EPERM)`. A refused network
// attempt therefore emitted NO EVENT AT ALL, and an absence of `connect` refusals is not evidence of
// absence — scoring it would have shipped an under-grant. `adapters/linux.mjs` now retains the
// outcome of the whole socket family and declares `netRefusals: true` on the stream header; this
// file scores `no-network` against a stream carrying that flag and against no other.
//
// ⛔ THE FLAG IS A POSITIVE DECLARATION, WHICH IS WHAT MAKES THE AXIS FAIL CLOSED ON A PLATFORM THAT
// CANNOT SEE THE REFUSAL. `macos-eventlog.mjs` streams carry no such flag, because
// `adapters/macos-observe.d` has `connect:entry`/`connect:return` clauses and NO `socket` clause at
// all — a Seatbelt network denial on darwin is invisible to the probe as it stands. Absence of the
// flag is UNSUPPORTED, which licenses nothing. A darwin probe that grows a `socket` clause sets its
// own flag and inherits the whole scorer.
//
// ⛔⛔ WINDOWS: THE SCORER EXISTS, THE CAPTURE DOES NOT, AND NO WIN32 STREAM IN THE CORPUS CAN BE
// SCORED. `win32PathAxis` below reads a `windows-retain.mjs` stream, and `record.mjs` needs no change
// to consume its marker. What is still missing is the half that has to run on Windows:
// `measure-windows.mjs` has no DIAGNOSE arm and has never taken a jailed trace — its `verify()` takes
// no tracer parameter, and ETW capture lives in `adapters/windows.ps1`, which wraps ONE command in a
// system-wide `logman` session. Wiring that is a driver change that must be validated on a real
// runner; until it lands, a win32 arm emits no marker and `record.mjs` behaves exactly as before.
//
// ⛔ WHAT MAKES IT SAFE TO LAND THE SCORER FIRST, AHEAD OF ANY EVIDENCE. Two independent gates, and
// EVERY committed win32 stream fails BOTH:
//
//   jailed        all 1,688 are OBSERVE captures. `windows-retain.mjs` sets the flag only from its
//                 own `--jailed`, which no caller passes, so all 1,688 carry `jailed: false`.
//   the control   the axis requires a Create refused with STATUS_ACCESS_DENIED somewhere in the
//                 stream before it will read an absence of in-scope refusals as evidence. ZERO of
//                 the 1,688 carry one. So even a stream force-stamped `jailed` scores VOID, never
//                 CLEAN — which is the exact catastrophe this axis is built to be unable to cause,
//                 and `denial-witness-win32.test.mjs` runs that mutation as a test.
//
// ⛔ THE `no-network` AXIS STAYS UNSUPPORTED ON WIN32, DELIBERATELY. `windows-retain.mjs` writes
// `st: null` on every Kernel-Network event unconditionally, so a refused socket leaves no outcome in
// the stream and the absence of one is not evidence. The stream sets no `netRefusals`, so the network
// branch returns UNSUPPORTED before this axis is reached. A win32 record whose descent dropped
// `no-network` alongside `no-write-userHome` therefore still cannot move.
//
//   usage: node denial-witness.mjs --cap no-write-userHome|no-network --events A.ndjson[.gz]
//                                  [--events B…] [--exclude DIR]… [--min-events N]
import fs from 'node:fs';
import zlib from 'node:zlib';
// ⛔ ONE DEFINITION OF THE TWO SYSCALLS THE JAIL GUARDS, SHARED WITH THE DECODER THAT EMITS THEM.
// A second copy here is the drift that produced the descent-vocabulary defect: `measure.sh` emitted
// `network` where `record.mjs` matched `no-network`, both sides had passing tests, and the
// recomputation silently deleted NOTHING while the record still claimed it had narrowed.
import { SOCKET_SYSCALLS } from './adapters/linux.mjs';
// The same rule for the win32 outcome vocabulary. ⛔ IT COMES FROM A LEAF, NOT FROM THE RETAIN
// ADAPTER, and `three-driver-parity.test.mjs` is what forced that: this module is reached by
// `measure.sh` and `measure-macos.sh`, so importing `windows-retain.mjs` for a constant dragged that
// adapter, `windows-shortnames.mjs` and `windows.ps1` into both POSIX drivers' closure and staled
// three platform exemptions in one move. `windows-status.mjs` imports nothing.
import { CREATE_EVENTS, REFUSAL_ACCESS_DENIED, REFUSAL_STATUS } from './adapters/windows-status.mjs';

// The errno symbols a confinement refusal produces. Deliberately NOT `ENOENT`: a jail that hides a
// path reports it missing, and so does an ordinary probe for a file that was never there, so counting
// ENOENT would bury every real refusal under thousands of module-resolution misses. Same three
// symbols `observe.mjs`'s REFUSALS section and both drivers' DIAGNOSE arms already use.
export const REFUSAL_ERRNO = new Set(['EACCES', 'EPERM', 'EROFS']);

// A trace with fewer decoded events than this did not observe an install. The number is a floor on
// "the tracer produced something", not a tuning knob: a jailed `nub install` arm that ran a lifecycle
// script emits events in the thousands (the committed darwin DIAGNOSE traces median 6737 raw lines).
export const MIN_EVENTS = 200;

const under = (p, root) => typeof p === 'string' && typeof root === 'string' && root !== ''
  && (p === root || p.startsWith(root.endsWith('/') ? root : `${root}/`));

// ⛔⛔ THE WINDOWS COMPARATOR IS A SEPARATE FUNCTION AND IT IS THE SINGLE MOST DANGEROUS LINE IN THIS
// FILE. `under` above is POSIX: it appends `/`. Run against `C:\Users\runneradmin` it asks whether the
// path starts with `C:\Users\runneradmin/`, which NOTHING on Windows does — so every win32 path would
// fall OUT of scope, every stream would find zero refusals, and every one would score CLEAN. That is
// precisely the blanket licence to narrow this whole axis exists to prevent, and it would arrive
// through a helper that looks platform-neutral and is not. `denial-witness-win32.test.mjs` breaks the
// separator, the case fold and the drive letter one at a time and requires each mutation to go red.
//
// Two things it must do that the POSIX one need not:
//   * accept BOTH separators. ETW hands back `\`, but a `capture.json` root is whatever the driver
//     wrote and node's own `path.join` on win32 emits `\` while a hand-built literal may not.
//   * fold case. NTFS is case-insensitive, the kernel reports whichever spelling the caller used, and
//     `C:\Users\RUNNERADMIN\x` is the same file as `C:\Users\runneradmin\x`. Comparing case-sensitively
//     would drop a real refusal, which is the CLEAN direction — the forbidden one.
const winKey = (s) => s.replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
const underWin = (p, root) => {
  if (typeof p !== 'string' || typeof root !== 'string' || root === '') return false;
  const a = winKey(p);
  const b = winKey(root);
  return b !== '' && (a === b || a.startsWith(`${b}\\`));
};

// ⛔ THE READER TOLERATES A GZIPPED STREAM BECAUSE THE ADAPTERS WRITE ONE WHENEVER `--out` ENDS IN
// `.gz`, AND A DRIVER THAT FORGOT WOULD OTHERWISE SCORE BINARY AS ZERO EVENTS AND REPORT CLEAN.
export const readEvents = (file) => {
  const buf = fs.readFileSync(file);
  const text = (buf[0] === 0x1f && buf[1] === 0x8b) ? zlib.gunzipSync(buf).toString('utf8') : buf.toString('utf8');
  return text.split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
};

// The scope a dropped capability names, as a predicate over an absolute path. `null` means this file
// cannot express the capability — the caller turns that into UNSUPPORTED rather than guessing.
// ⛔⛔ A COMPARATOR ONLY WORKS INSIDE ITS OWN PATH NAMESPACE, AND SAYING SO IS NOT PEDANTRY — IT IS
// THE FIX FOR A LIVE FALSE-`CLEAN` THIS FILE SHIPPED WITH. `under` appends `/`. Handed the win32 home
// root `C:\Users\runneradmin` it asks whether a path starts with `C:\Users\runneradmin/`, which
// nothing on Windows does — so the scope is EMPTY, every stream finds zero refusals, and the POSIX
// path axis (whose `control` is `() => null`, correct for a namespace it can actually read) reports
// CLEAN. MEASURED before this guard existed: stamping `jailed: true` onto the committed
// `victory-voronoi@0.0.5` win32 stream and scoring it returned `CLEAN, 12525 events, 0 refusals` —
// a blanket licence to narrow, produced with no mapping error anywhere and nothing in the output
// hinting that the matcher had matched nothing.
//
// So expressibility is now asserted POSITIVELY rather than assumed from the caller's good manners: a
// matcher is built only when the home root is in the namespace `cmp` understands, and a root that is
// not returns `null`, which the caller turns into UNSUPPORTED. That licenses nothing, and it holds
// whether or not a future stream carries the right flags.
//
// It moves no committed verdict. MEASURED over all 4,048 committed POSIX streams: every linux home is
// `/home/runner` or `/home/nub` and every darwin home is `/Users/runner`, so zero fail the check.
const POSIX_ABS = (p) => p.startsWith('/');
const WIN_ABS = (p) => /^[A-Za-z]:[\\/]/.test(p) || p.startsWith('\\\\');

// ⛔ `cmp`/`ns` DEFAULT TO THE POSIX PAIR SO EVERY EXISTING CALLER IS BYTE-IDENTICAL. The win32 axis
// passes the Windows pair; nothing else does, so no linux or darwin verdict can move because of it.
export function scopeMatcher(cap, roots, extraExcludes = [], cmp = under, ns = POSIX_ABS) {
  if (cap !== 'no-write-userHome') return null;
  const home = roots?.home;
  if (typeof home !== 'string' || home === '' || !ns(home)) return null;
  // Every OTHER declared root, plus whatever the driver excluded. `home` itself is obviously not a
  // subtraction, and a null root (this platform has no such thing) contributes nothing.
  const subtract = [
    ...Object.entries(roots).filter(([k]) => k !== 'home').map(([, v]) => v),
    ...extraExcludes,
  ].filter((v) => typeof v === 'string' && v !== '');
  return {
    scope: 'userHome',
    subtract,
    inScope: (p) => cmp(p, home) && !subtract.some((s) => cmp(p, s)),
  };
}

export const NET_CAP = 'no-network';

// Every socket-family event the decoder emits. `connect` keeps its own `o` because `observe.mjs`
// prints peers off it; the rest share `o:"net"`. Both are in scope, and the generosity is the same
// safety argument the userHome matcher makes above — counting a refusal the jail did not cause can
// only turn a CLEAN into a WITNESSED, which KEEPS a grant. Missing one would publish an under-grant.
const NET_OPS = new Set(['net', 'connect']);

// ⛔ WHAT COULD BE A REFUSAL OF THIS CAPABILITY, AND WHAT MUST BE TRUE BEFORE AN ABSENCE OF ONE IS
// EVIDENCE. Two members, and the second is the one that keeps a blind platform from reading CLEAN:
//
//   hit        the predicate over a decoded event. Path axes additionally require `w === 1` — the
//              write-intent flag — because a `write:{scope}` grant governs writes and a denied READ
//              is a different arm's business. The network axis has no such flag and needs none: any
//              socket-family call is network intent by construction.
//   control    a POSITIVE control over the whole stream, returning a reason when the stream could
//              not have carried the refusal in the first place. `null` means the stream is fit to
//              score. The path axes need none — a refused `openat` is the same event as a successful
//              one and the decoder has retained it since it existed.
//
// ⛔⛔⛔ THE WIN32 PATH AXIS. Read the four notes before changing a character of it; each one is the
// difference between this file keeping a grant and this file handing out a blanket licence to narrow
// 131 whole-home grants on no evidence, which is the worst outcome available in this whole effort.
//
// ⛔ 1. WHY THERE IS A SECOND AXIS AT ALL, RATHER THAN AN `st -> r` TRANSLATION IN THE ADAPTER. The
// POSIX hit predicate is `e.w === 1 && REFUSAL_ERRNO.has(e.r) && inScope(e.f)`, and win32 diverges on
// all three terms, not on `r` alone:
//
//   r   `windows-retain.mjs` writes the raw NTSTATUS into `st` ("0xc0000022"), never an errno symbol.
//       Translating it is mechanical and the map is imported from that adapter, not copied.
//   w   THERE IS NO SOURCE FOR IT, and this is the term the registry entry correctly called
//       structural. The header says so in its own `limits`: "Create (12) carries no DesiredAccess;
//       `d` is the CreateDisposition, not the requested access", so `open-r` means disposition
//       FILE_OPEN and is NOT proof of read-only intent — a FILE_OPEN handle can be written through.
//       Event 16 (Write) would evidence a write, and under an allowlist jail it never arrives,
//       because the refusal happens AT Create and no handle is ever returned. An adapter that
//       synthesized a `w` would be writing a fabricated fact into an archive whose whole design
//       refuses that; so the archive keeps `st` and the GENEROSITY lives here, in the scorer, where
//       the safety argument for it can be stated.
//   f   the path needs the Windows comparator, and there are two spellings of it (see note 3).
//
// ⛔ 2. THE HIT PREDICATE DROPS THE WRITE-INTENT TERM ENTIRELY, AND THAT IS SAFE BY DIRECTION. Any
// refusal inside the scope counts, read or write. This file's own scope-matching note already makes
// the argument: being WIDER can only ever turn a CLEAN into a WITNESSED — keep a grant that might
// have been droppable — while being narrower turns a WITNESSED into a CLEAN and publishes an
// under-grant. Dropping `w` is the widest possible reading, so it is the safest. It is also close to
// exact here: nub's win32 backend is an ALLOWLIST (`crates/nub-sandbox/src/backend/windows.rs` — "a
// LowBox token can reach an object ONLY where the object's ACL grants its AppContainer SID … every
// other path fails closed with no per-file deny-ACE"), so in a `no-write-userHome` drop arm the real
// home carries no ACE for the run's SID at all and EVERY home access is refused. A refusal there is
// evidence the script reached for the home; whether it wanted to read or write it, keeping the wide
// grant is the answer this file is allowed to give.
//
// The cost is precision, and it is real and measured: 19 of the 1,688 committed streams carry a
// refused Create on `…\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\…` that is
// Explorer's jump-list, refused because `windows.ps1` strips SeBackup — in scope, not the script's,
// and it would read WITNESSED. That keeps a wide grant on harness noise. Wrong in the harmless
// direction, and the alternative is wrong in the forbidden one.
//
// ⛔ 3. BOTH PATH SPELLINGS, AND THE DESTINATION END TOO. `f` is the kernel's spelling and `fx` the
// 8.3 expansion; the archive keeps both because the expansion is perishable. On a GitHub runner
// `%TEMP%` is literally `C:\Users\RUNNER~1\…`, so a package that resolves through the environment
// produces short-spelled paths — and a short spelling does not prefix-match the long `home` root.
// Checking only one spelling would silently drop those refusals, i.e. read CLEAN. `g`/`gx` are the
// rename/hardlink DESTINATION: a rename INTO the home is a write to the home, and the source end
// alone would miss it.
//
// ⛔ 4. THE POSITIVE CONTROL, WHICH IS THE ONLY REASON THIS AXIS MAY EXIST BEFORE ANYONE HAS SEEN A
// JAILED WIN32 TRACE. One empirical premise carries the whole axis: that a Create refused by the
// AppContainer DACL check surfaces as a Kernel-File event carrying STATUS_ACCESS_DENIED. It has never
// been measured — no jailed ETW capture has ever been taken on this platform — so instead of
// ASSUMING it, the axis CHECKS it per stream and refuses the stream when it cannot. If the premise is
// false, no stream ever satisfies the control, every win32 verdict is VOID, and nothing narrows.
//
// It must be ACCESS_DENIED specifically, and it must be on a CREATE. Both halves were paid for:
// keying on "any refusal" or on "a refused Create of any status" would have passed on the 19 streams
// in note 2, whose refusals come from the PRIVILEGE check rather than the DACL check and therefore
// say nothing about whether a LowBox denial is visible. ZERO of the 1,688 committed streams carry
// `0xc0000022` on a Create, so this control is a real discriminant. See `windows-retain.mjs`, which
// owns the split.
function win32PathAxis(cap, header, extraExcludes) {
  const m = scopeMatcher(cap, header?.roots ?? {}, extraExcludes, underWin, WIN_ABS);
  if (!m) return null;
  // ⛔ A SUBTRACTION THAT SWALLOWS THE SCOPE MAKES EVERY STREAM CLEAN, SILENTLY. `scopeMatcher`
  // subtracts every other declared root from the home, so a `capture.json` that declared
  // `jailHome === home` — or any root at or above it — would leave an EMPTY scope in which no refusal
  // can ever be found, and the axis would answer CLEAN for every package while looking healthy.
  // win32 has no jail home today (`provenance.overrides.notRedirected.USERPROFILE` records that
  // `build_jail.rs` passes the ambient value through), so this cannot fire now; it is here because a
  // driver that ever introduced one would otherwise turn this axis into the blanket licence.
  // Deliberately NOT added to the POSIX path, where it would change committed verdicts.
  if (m.subtract.some((s) => underWin(header.roots.home, s))) return null;
  return {
    scope: m.scope,
    hit: (e) => REFUSAL_STATUS.has(e.st)
      && (m.inScope(e.f) || m.inScope(e.fx) || m.inScope(e.g) || m.inScope(e.gx)),
    control: (events) => (events.some((e) => CREATE_EVENTS.has(e.s) && e.st === REFUSAL_ACCESS_DENIED)
      ? null
      : 'the decoder recorded no Create refused with STATUS_ACCESS_DENIED anywhere in this stream — '
        + 'that is the event an AppContainer DACL refusal produces, and under an allowlist jail a '
        + 'real arm denies hundreds of them outside the grant, so this trace either was not taken '
        + 'inside the jail or cannot see the refusal at all, and an absence of refusals is not '
        + 'evidence'),
  };
}

// `null` from this function means the capability is not expressible against THIS stream, which the
// caller turns into UNSUPPORTED rather than guessing.
export function axisFor(cap, header, extraExcludes = []) {
  if (cap === NET_CAP) {
    // ⛔ THE FLAG, NOT THE PLATFORM NAME. A stream decoded before the adapter retained socket-family
    // outcomes carries `platform: "linux-x64"` and cannot answer this question; keying on the
    // platform would score it and read its silence as CLEAN.
    if (header?.netRefusals !== true) return null;
    return {
      scope: 'network',
      hit: (e) => NET_OPS.has(e.o) && REFUSAL_ERRNO.has(e.r),
      // ⛔⛔ THE INSTRUMENT IS VALIDATED AGAINST A CASE WHOSE ANSWER IS ALREADY KNOWN, ON EVERY RUN.
      // An arm runs a real `nub install`, and nub's own resolver and npm open registry sockets
      // UNJAILED in the same traced tree — so a stream in which the decoder saw not one
      // `socket`/`socketpair` outcome from ANY process did not capture the syscall the jail refuses.
      // Without this, a tracer invoked with a filter that omits the network class, or a decoder
      // regression, would produce a clean-looking stream and license a narrowing off it.
      control: (events) => (events.some((e) => e.o === 'net' && SOCKET_SYSCALLS.has(e.s))
        ? null
        : 'the decoder recorded no socket()/socketpair() outcome anywhere in this stream — not even '
          + 'from the tool processes, which open registry sockets on every arm — so the syscall the '
          + 'jail refuses was never captured and an absence of refusals is not evidence'),
    };
  }
  // ⛔ THE FLAG, NOT THE PLATFORM NAME — same rule as the network axis one branch up, and for the same
  // reason. Every one of the 1,688 win32 streams committed before this line existed carries
  // `platform: "win32-x64"` and no `winRefusals`, and keying on the platform would score them.
  if (header?.winRefusals === true) return win32PathAxis(cap, header, extraExcludes);
  const m = scopeMatcher(cap, header?.roots ?? {}, extraExcludes);
  if (!m) return null;
  return {
    scope: m.scope,
    hit: (e) => e.w === 1 && REFUSAL_ERRNO.has(e.r) && m.inScope(e.f),
    control: () => null,
  };
}

// ⛔ ATTRIBUTION IS THE ADAPTER'S, NOT THIS FILE'S. Both POSIX adapters emit a `k:"p"` row per
// process carrying `life: 1|0`, computed from their own subtree filter — the same one `observe.mjs`
// uses to decide which writes earn a grant. Re-deriving it here from pids and argv is exactly the
// hand-rolled scan that has produced three wrong answers on this effort, each time by ignoring
// process attribution. A stream with ZERO life-1 processes is VOID, never CLEAN: it means the filter
// matched nothing, so "no refusal was attributed" says nothing about what the script did.
export function witness(rows, { cap, exclude = [], minEvents = MIN_EVENTS } = {}) {
  const header = rows.find((r) => r.k === 'h') ?? null;
  const base = { cap, scope: null, events: 0, lifecyclePids: 0, refusalsInScope: 0, sample: [] };
  if (!header) return { ...base, verdict: 'VOID', reason: 'the event stream carries no header row, so its roots are unknown' };
  // ⛔ THE JAILED FLAG IS A GUARD, NOT A LABEL. Scoring an OBSERVE stream would be catastrophic and
  // silent: OBSERVE is UNJAILED, so it contains no jail refusals at all and every arm would read
  // CLEAN — a blanket licence to narrow, produced by pointing the detector at the wrong file. Both
  // adapters stamp `jailed` into the header from their own `--jailed` flag.
  if (header.jailed !== true) {
    return { ...base, verdict: 'VOID', reason: 'the event stream is not marked `jailed` — decode the arm trace with the adapter\'s --jailed flag' };
  }
  const ax = axisFor(cap, header, exclude);
  if (!ax) {
    return { ...base, verdict: 'UNSUPPORTED', reason: cap === NET_CAP
      ? 'this event stream does not declare `netRefusals`, so its decoder does not retain '
        + 'socket-family outcomes — a refused socket() leaves no event in it and the absence of one '
        + 'is not evidence'
      : `this scorer expresses no scope for '${cap}'` };
  }
  const life = new Set(rows.filter((r) => r.k === 'p' && r.life === 1).map((r) => r.pid));
  const events = rows.filter((r) => r.k === 'e');
  const out = { ...base, scope: ax.scope, events: events.length, lifecyclePids: life.size };
  if (events.length < minEvents) {
    return { ...out, verdict: 'VOID', reason: `only ${events.length} decoded events (< ${minEvents}) — the tracer did not observe an install` };
  }
  if (life.size === 0) {
    return { ...out, verdict: 'VOID', reason: 'no lifecycle process was attributed in this stream — the subtree filter matched nothing, so an absence of refusals is not evidence' };
  }
  // The axis's own positive control, and it is tested LAST of the three because it is the most
  // specific: a stream that fails the two above is unusable for every capability, and saying so in
  // the general terms is more use to a human reading `driver.out`.
  const blind = ax.control(events);
  if (blind) return { ...out, verdict: 'VOID', reason: blind };
  const hits = events.filter((e) => life.has(e.p) && ax.hit(e));
  out.refusalsInScope = hits.reduce((a, e) => a + (e.n ?? 1), 0);
  // A path axis names the path; the network axis has none, so it names the peer when the decoder
  // captured one and the bare syscall otherwise. `undefined` in a sample line is what a human reads
  // as a broken detector.
  // A win32 stream carries the raw NTSTATUS in `st` and no `r` at all; rendering `= -1 undefined`
  // for it is precisely what a human reads as a broken detector, which is the thing this line's
  // original note warns about.
  out.sample = [...new Set(hits.map((e) => `${e.s ?? e.o}`
    + (e.f ? ` ${e.f}` : e.h ? ` ${e.h}:${e.pt ?? '?'}` : '')
    + (e.st ? ` = ${e.st}` : ` = -1 ${e.r}`)))].slice(0, 6);
  // ⛔ "access" ON THE WIN32 PATH AXIS, NOT "write", BECAUSE THAT AXIS DOES NOT ESTABLISH WRITE
  // INTENT — it counts any refusal in scope. Saying "write" there would state in the record a fact
  // the evidence does not carry, and the first question anyone auditing a kept whole-home grant asks
  // is what the trace actually showed.
  const what = cap === NET_CAP ? 'socket-family call'
    : header.winRefusals === true ? 'access' : 'write';
  return hits.length
    ? { ...out, verdict: 'WITNESSED', reason: `${out.refusalsInScope} ${what}(s) inside ${ax.scope} were attempted by the lifecycle subtree and REFUSED` }
    : { ...out, verdict: 'CLEAN', reason: `the lifecycle subtree attempted no ${what} inside ${ax.scope} that the jail refused` };
}

// One line, JSON payload, same shape as every other marker `record.mjs` consumes. The prose beneath
// it is for a human reading `driver.out`; the recorder reads the JSON.
export const marker = (r) => `DENIAL-WITNESS ${JSON.stringify({
  cap: r.cap, scope: r.scope, verdict: r.verdict, refusalsInScope: r.refusalsInScope,
  lifecyclePids: r.lifecyclePids, events: r.events, sample: r.sample,
})}`;

if (import.meta.filename === process.argv[1]) {
  const argv = process.argv.slice(2);
  const one = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : undefined);
  const many = (f) => argv.reduce((a, v, i) => (v === f && argv[i + 1] ? [...a, argv[i + 1]] : a), []);
  const cap = one('--cap');
  const files = many('--events');
  if (!cap || files.length === 0) {
    console.error('usage: denial-witness.mjs --cap no-write-userHome|no-network --events A.ndjson [--events B…] [--exclude DIR]…');
    process.exit(2);
  }
  // ⛔ AN UNREADABLE INPUT IS VOID, NEVER A SKIP. A driver that mistypes a path must not get a silent
  // CLEAN out of an empty array; it gets a VOID marker naming the file, which keeps the wide grant
  // and says why in the log.
  let rows = [];
  const bad = [];
  for (const f of files) { try { rows = rows.concat(readEvents(f)); } catch (e) { bad.push(`${f}: ${e.code ?? e.message}`); } }
  const r = bad.length && !rows.length
    ? { cap, scope: null, verdict: 'VOID', refusalsInScope: 0, lifecyclePids: 0, events: 0, sample: [],
      reason: `no event stream could be read (${bad.join('; ')})` }
    : witness(rows, { cap, exclude: many('--exclude'), minEvents: Number(one('--min-events') ?? MIN_EVENTS) });
  console.log(marker(r));
  console.log(`     ${r.verdict} — ${r.reason}`);
  for (const s of r.sample) console.log(`       ${s}`);
  process.exit(0);
}
