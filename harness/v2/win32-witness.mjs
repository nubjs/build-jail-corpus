// The win32 denial-witness CAPTURE half: everything about it that can be decided WITHOUT Windows.
//
// ⛔⛔ WHY THIS IS A MODULE AND NOT SIXTY LINES INSIDE `measure-windows.mjs`. The driver is a 2,600
// line top-level script that spawns PowerShell and cannot be imported, so nothing inside it can be
// exercised anywhere but a Windows runner. The half that DECIDES — is this capture fit to score, what
// rc did the arm return, which roots does the witness declare, is the script text safe to hand to
// cmd.exe — is ordinary data-in/data-out and belongs where a test on any host can break it. What is
// left in the driver is spawn-and-print glue, and the list of its untestable lines is short enough to
// write down (see `WITNESS-OFF-WINDOWS` in the driver).
//
// ⛔ THE ONLY FAILURE MODE THAT MATTERS IS A `CLEAN` VERDICT ON EVIDENCE NOBODY READ. A witness that
// crashes costs a measurement; a witness that answers CLEAN off a truncated, unjailed, privileged or
// mis-spelled trace licenses `record.mjs` to drop `write.userHome` — authority over the whole user
// home — for a package that needed it, which breaks that package's install for every real user. So
// every predicate here is written to answer "NOT scoreable" when it cannot answer, and every one of
// them is a mutation target in `win32-witness.test.mjs`.
import path from 'node:path';
// ⛔ THE MARKER IS THE SCORER'S OWN, NOT A SECOND COPY OF ITS JSON. `measure.sh` and
// `measure-macos.sh` hand-write their VOID marker as a shell string literal because they cannot
// import JS; this driver can, so it does. A hand-written copy is how the descent vocabulary came to
// be spelled `network` on one side and `no-network` on the other with both sides' tests green.
import { marker } from './denial-witness.mjs';

/** The one capability this witness is wired for. `denial-witness.mjs` expresses no other win32 scope. */
export const WITNESS_CAP = 'no-write-userHome';

/**
 * The `-MaxMB` handed to `windows.ps1`, and the number the truncation gate compares against.
 *
 * ⛔ ONE LITERAL FOR THE SESSION AND FOR THE CHECK, which is the same rule `windows.ps1` states for
 * its own knobs: two copies would let the gate pass while the session used a different cap. It equals
 * that script's default, so a witness session has exactly the OBSERVE session's geometry.
 */
export const WITNESS_MAX_MB = 8192;

/** The capture-schema string `windows.ps1` stamps into `meta.json`. A capture that does not carry it
 *  was produced by something else, and nothing here knows what its fields mean. */
export const CAPTURE_SCHEMA = 'nub-obs-win/1';

/** `windows.ps1` reports one of these per privilege it was asked to remove. Anything else is a drop
 *  that silently failed. */
const PRIV_OK = new Set(['removed', 'already-absent']);

// ── The batch file the ETW session wraps ─────────────────────────────────────────────────────────

// ⛔ CHARACTERS THAT WOULD MAKE cmd.exe READ SOMETHING OTHER THAN THE PATH WE WROTE. A `"` ends the
// quoted argument; `%` is an environment expansion; a newline is a second command. All three are
// legal in an NTFS path, so this is a real input rather than a defensive flourish — and a path that
// carries one must REFUSE to produce a script, never produce one that runs a different command.
const UNSAFE_FOR_CMD = /["%\r\n]/;

/**
 * The batch file that runs the arm's two nub commands inside the traced session.
 *
 * ⛔⛔ THE SAME TWO COMMANDS AS THE UNTRACED ARM, IN THE SAME ORDER, WITH THE SAME REDIRECTIONS. A
 * traced arm that ran only `install` would be a DIFFERENT EXPERIMENT from every other arm for any
 * package whose build is deferred to `approve-builds` — and `measure-macos.sh` shipped exactly that
 * bug, which is why `denial-witness-decode.test.mjs` named the repair in as many words before darwin
 * was allowed to have a witness at all. The rc the driver reports is composed from the two
 * `%ERRORLEVEL%` captures below by `armRc`, which reproduces `i.status === 0 ? a.status : i.status`.
 *
 * ⛔ A SPACE BEFORE EVERY `>`, AND IT IS LOAD-BEARING. `echo %ERRORLEVEL%> f` is cmd's oldest
 * footgun: a digit written immediately before a redirection operator is parsed as a FILE HANDLE, so
 * an rc of 1 would redirect handle 1 and write an empty line — an unreadable rc that reads exactly
 * like a crash. With the space, `1` is an argument and the file gets `1 `, which `armRc` trims.
 *
 * ⛔ `%ERRORLEVEL%` EXPANDS PER LINE, WHICH IS WHY THERE IS NO `setlocal enabledelayedexpansion` AND
 * NO PARENTHESISED BLOCK. cmd parses a batch file one line at a time outside a block, so each capture
 * line is parsed AFTER the command above it has finished. Putting these lines inside `( … )` is the
 * classic way to break that and would freeze both captures at the value before the first command.
 */
export function jailScript({ nub, dir, iLog, aLog, iRc, aRc }) {
  const parts = { nub, dir, iLog, aLog, iRc, aRc };
  for (const [k, v] of Object.entries(parts)) {
    if (typeof v !== 'string' || v === '') throw new Error(`jailScript: ${k} is not a path`);
    if (UNSAFE_FOR_CMD.test(v)) throw new Error(`jailScript: ${k} contains a character cmd.exe would reparse`);
  }
  return [
    '@echo off',
    `cd /d "${dir}"`,
    `"${nub}" install > "${iLog}" 2>&1`,
    `echo %ERRORLEVEL% > "${iRc}"`,
    `"${nub}" approve-builds --all > "${aLog}" 2>&1`,
    `echo %ERRORLEVEL% > "${aRc}"`,
    '',
  ].join('\r\n');
}

/**
 * The arm's exit code, composed from the two captured `%ERRORLEVEL%` values.
 *
 * ⛔ THE UNTRACED ARM'S RULE, REPRODUCED EXACTLY: `i.status === 0 ? (a.status ?? 0) : i.status`. A
 * traced arm that scored its rc any other way would not be comparable with the arms around it, and
 * the descent compares them directly.
 *
 * ⛔ AN UNREADABLE rc IS `null`, WHICH THE DRIVER TURNS INTO A VOID ARM, NEVER INTO A ZERO. A missing
 * or garbled capture means the batch did not finish; scoring that as rc 0 would report a PASS for an
 * arm that never ran, and a passing drop arm is what narrows a grant.
 */
export function armRc(iText, aText) {
  // A negative rc is real on Windows (`-1073741819` is an access violation), so the pattern is signed.
  const num = (t) => {
    if (typeof t !== 'string') return null;
    const s = t.trim();
    return /^-?\d+$/.test(s) ? Number(s) : null;
  };
  const i = num(iText);
  const a = num(aText);
  if (i === null) return { rc: null, reason: 'the traced arm wrote no readable `install` exit code' };
  if (a === null) return { rc: null, reason: 'the traced arm wrote no readable `approve-builds` exit code' };
  return { rc: i === 0 ? a : i, reason: null };
}

// ── The roots the witness capture declares ───────────────────────────────────────────────────────

/**
 * The `roots` block for a drop arm's own `capture.json`.
 *
 * ⛔⛔ EVERY DECLARED ROOT IS SUBTRACTED FROM THE `userHome` SCOPE, SO DECLARING ONE IS THE DANGEROUS
 * DIRECTION AND SILENCE IS THE SAFE ONE. `denial-witness.mjs`'s `scopeMatcher` builds the scope as
 * "under `roots.home`, minus every OTHER root the header declares" — so a root that happens to sit
 * inside the home CARVES A HOLE in the scope, and a refusal in that hole stops counting. Being wider
 * can only turn a CLEAN into a WITNESSED (keep a grant that might have been droppable); being
 * narrower turns a WITNESSED into a CLEAN and publishes an under-grant.
 *
 * So this declares the two roots that are certainly true of a drop arm and writes `null` for every
 * other key rather than copying OBSERVE's block:
 *
 *   project   the arm directory. It is a sibling of OBSERVE under the driver's `--root` (`C:\jail` by
 *             default), not under the home, so subtracting it removes nothing from the scope — it is
 *             declared because it is the truth about this run, not to change the scope.
 *   home      `%USERPROFILE%`. THE SCOPE ITSELF: under a `no-write-userHome` drop arm this is the
 *             directory the grant no longer covers.
 *   jailHome  `null`. The driver does not create one for a verify arm — nub derives its own private
 *             home from the arm's `XDG_CACHE_HOME`, which lives under the arm directory. Declaring
 *             `null` cannot cause a false CLEAN in either reading of nub's Windows home handling: if
 *             nub redirects HOME for the confined child then the script's home writes go to a granted
 *             directory and are never refused, and if it does not then the writes land in the REAL
 *             home and must be counted. Both are served by not carving anything out.
 *   temp      `null`, for the same reason and with more force: the jail hands the script a private
 *             temp, so a refusal under the AMBIENT `%TEMP%` — which on a runner lives inside the home
 *             — is a real reach for the user's home and must not be subtracted away.
 *
 * ⛔ `ownPkg` IS DECLARED BECAUSE `scopeMatcher` EXPECTS THE KEY, and it points inside the arm
 * directory, so like `project` it subtracts nothing from the home.
 */
export function witnessRoots({ project, home, pkg }) {
  if (typeof project !== 'string' || project === '') throw new Error('witnessRoots: no project root');
  if (typeof home !== 'string' || home === '') throw new Error('witnessRoots: no home root');
  return {
    project,
    home,
    jailHome: null,
    globalStore: null,
    projectStore: null,
    interpreter: null,
    toolsDir: null,
    temp: null,
    npmPrefix: null,
    npmCache: null,
    ownPkg: typeof pkg === 'string' && pkg !== ''
      ? path.win32.join(project, 'node_modules', ...pkg.split('/'))
      : null,
    cwd: null,
  };
}

// ── The gate: is this capture fit to be scored at all? ───────────────────────────────────────────

/**
 * Every reason a win32 witness capture must NOT reach the scorer, in the order a human would want to
 * read them. Returns `{ ok: true }` or `{ ok: false, reason }`; the driver turns a refusal into a
 * VOID marker, which licenses nothing.
 *
 * ⛔ THE SCORER CANNOT MAKE THESE CHECKS AND IS NOT SUPPOSED TO. `denial-witness.mjs` reads a decoded
 * event stream; the facts below live in the CAPTURE — how the session was configured, whether it lost
 * events, what privileges the traced token held. A stream from a lossy or privileged capture decodes
 * perfectly and looks healthy, which is exactly why it has to be refused here.
 *
 * The individual reasons, and the direction each one fails in if it is missing:
 *
 *   schema / meta      A capture directory with no `meta.json`, or one written by something other
 *                      than `windows.ps1`, has no known field meanings. Reading `eventsLost` off it
 *                      would be reading a field that may not exist, i.e. `undefined`, i.e. "no loss".
 *   elevated           ETW kernel providers are administrator-only. An unelevated capture produces
 *                      no events, and no events is silence, and silence read as CLEAN is the
 *                      catastrophe.
 *   privDropped        ⛔ THE ONE THAT LOOKS LIKE PARANOIA AND IS THE SHARPEST. `windows.ps1` removes
 *                      SeBackup/SeRestore/SeTakeOwnership because libuv sets FILE_FLAG_BACKUP_SEMANTICS
 *                      on every open, and those privileges then BYPASS THE DACL OUTRIGHT — measured on
 *                      nub-win3, where a write into a directory carrying an explicit Deny ACE
 *                      SUCCEEDED with them and was refused without them. Under an AppContainer jail
 *                      the refusal IS a DACL check, so a retained SeBackupPrivilege turns every home
 *                      write into a success: no refusals in the trace, a green arm, and a CLEAN
 *                      verdict produced by an instrument that was structurally unable to observe a
 *                      denial. Same assertion the OBSERVE arm makes for its own reasons.
 *   tracerptExit       The XML the decoder reads is tracerpt's output. A non-zero conversion is a
 *                      partial or empty XML that still parses.
 *   eventsLost         ⛔ A LOSSY TRACE CANNOT SUPPORT AN ABSENCE CLAIM, WHICH IS THE ONLY CLAIM A
 *                      CLEAN VERDICT MAKES. `windows.ps1` reads this from tracerpt's summary and
 *                      writes `-1` when it could not parse one, so anything other than an exact 0 is
 *                      refused. The scorer has no equivalent check: `MIN_EVENTS` is a floor on "the
 *                      tracer produced something", and a trace that dropped 60% of its events sails
 *                      past it.
 *   truncation         The session runs in SEQUENTIAL mode, so reaching `-max` stops the writing
 *                      SILENTLY — with `eventsLost` still 0, because nothing was lost, it was never
 *                      recorded. The tell is the `.etl` sitting at its cap, and a trace cut off part
 *                      way is missing exactly the late writes a postinstall makes.
 *   rootPid            `windows-retain.mjs` attributes events by subtree of this pid. Without it the
 *                      stream has no `life:1` process and the scorer VOIDs anyway — refused here so
 *                      the log says why.
 *   xml                An absent or empty XML decodes to zero events.
 *   shortNames         ⛔ 8.3 EXPANSION IS A CORRECTNESS TERM ON THIS AXIS, NOT AN ORNAMENT. The
 *                      kernel reports whichever spelling the caller used, and a GitHub runner's
 *                      `%TEMP%` is literally `C:\Users\RUNNER~1\…` — a spelling that does NOT
 *                      prefix-match the long home root. The scorer checks `f` and its expansion `fx`,
 *                      so with expansion OFF a short-spelled home refusal is invisible and the stream
 *                      reads CLEAN. Passing `--resolve-shortnames` is what turns it on; this asserts
 *                      it took effect rather than assuming the flag was honoured.
 */
export function captureIsScoreable({ meta, etlBytes, xmlBytes, shortNameMode, maxMB = WITNESS_MAX_MB }) {
  if (!meta || typeof meta !== 'object') {
    return { ok: false, reason: 'the traced arm produced no meta.json, so the capture cannot be described at all' };
  }
  if (meta.schema !== CAPTURE_SCHEMA) {
    return { ok: false, reason: `the capture declares schema ${JSON.stringify(meta.schema ?? null)} rather than `
      + `${CAPTURE_SCHEMA}, so its fields have no known meaning here` };
  }
  if (meta.elevated !== true) {
    return { ok: false, reason: 'the capture was not taken from an elevated token — ETW kernel providers are '
      + 'administrator-only, so the session recorded nothing and its silence is not evidence' };
  }
  const priv = meta.privDropped;
  if (!priv || typeof priv !== 'object') {
    return { ok: false, reason: 'the capture records no privilege drop, so the traced token may have held '
      + 'SeBackupPrivilege — which bypasses the DACL the jail refuses through, making a denial unobservable' };
  }
  const bad = Object.entries(priv).filter(([, v]) => !PRIV_OK.has(v));
  if (bad.length) {
    return { ok: false, reason: `the privilege drop failed (${bad.map(([k, v]) => `${k}=${v}`).join(', ')}) — libuv `
      + 'opens every file with FILE_FLAG_BACKUP_SEMANTICS, so a retained SeBackupPrivilege bypasses the DACL '
      + 'and the home write the jail should refuse would SUCCEED, leaving no refusal to witness' };
  }
  if (meta.tracerptExit !== 0) {
    return { ok: false, reason: `tracerpt exited ${JSON.stringify(meta.tracerptExit ?? null)}, so the XML the `
      + 'decoder reads is partial or absent' };
  }
  if (meta.eventsLost !== 0) {
    return { ok: false, reason: `the session lost ${JSON.stringify(meta.eventsLost ?? null)} events — a lossy trace `
      + 'cannot support "nothing was refused", which is the only claim a CLEAN verdict makes' };
  }
  if (typeof etlBytes !== 'number' || etlBytes < 0) {
    return { ok: false, reason: 'the capture left no readable trace.etl, so it cannot be checked for truncation' };
  }
  if (etlBytes >= maxMB * 1024 * 1024) {
    return { ok: false, reason: `the trace reached its ${maxMB} MB cap (${etlBytes} bytes) — a sequential session `
      + 'stops writing SILENTLY at the cap with eventsLost still 0, so the end of the arm is simply missing' };
  }
  if (typeof xmlBytes !== 'number' || xmlBytes <= 0) {
    return { ok: false, reason: 'tracerpt produced no trace.xml content, so there is nothing to decode' };
  }
  if (!Number.isInteger(meta.rootPid) || meta.rootPid <= 0) {
    return { ok: false, reason: `the capture records no usable rootPid (${JSON.stringify(meta.rootPid ?? null)}), `
      + 'so the decoder cannot attribute a lifecycle subtree and an absence of refusals means nothing' };
  }
  if (shortNameMode === 'off') {
    return { ok: false, reason: 'the decoder could not resolve 8.3 short names, so a refusal the kernel spelled '
      + '`C:\\Users\\RUNNER~1\\…` would not prefix-match the long home root and would be silently out of scope' };
  }
  return { ok: true, reason: null };
}

/**
 * The decoded stream's own header, checked before it is handed to the scorer.
 *
 * ⛔ THE SCORER ALREADY REFUSES A STREAM MISSING EITHER FLAG, so this is not a second gate on the
 * verdict — it is a gate on the WIRING. `--jailed` not reaching the header, or a retain adapter that
 * stopped declaring `winRefusals`, both produce a permanently VOID witness that looks like a package
 * property rather than a broken driver; saying so here is the difference between a fixed bug and a
 * silently inert feature.
 */
export function headerIsScoreable(row) {
  if (!row || row.k !== 'h') return { ok: false, reason: 'the decoded stream has no header row' };
  if (row.jailed !== true) {
    return { ok: false, reason: 'the decoded stream is not marked `jailed` — the retain adapter did not receive '
      + '--jailed, so the scorer would refuse it' };
  }
  if (row.winRefusals !== true) {
    return { ok: false, reason: 'the decoded stream does not declare `winRefusals`, so the scorer cannot tell '
      + 'that its decoder retains NTSTATUS outcomes and would answer UNSUPPORTED' };
  }
  if (typeof row.roots?.home !== 'string' || row.roots.home === '') {
    return { ok: false, reason: 'the decoded stream declares no home root, so `userHome` has no scope' };
  }
  return { ok: true, reason: null };
}

/**
 * The marker a refused capture emits: the scorer's own VOID payload, with the reason on the line
 * beneath it for a human reading `driver.out`.
 *
 * ⛔ THE MARKER IS EMITTED ON EVERY PATH, INCLUDING THE ONES WHERE NOTHING WAS TRACED. `record.mjs`
 * treats an ABSENT marker and a VOID one identically, so this is not needed for correctness — it is
 * needed so a reader can tell "the witness ran and could not answer" from "the witness never ran",
 * which is the difference between a package property and a broken lane.
 */
export function voidWitness(cap, reason) {
  return [
    `     ${marker({ cap, scope: null, verdict: 'VOID', refusalsInScope: 0, lifecyclePids: 0, events: 0, sample: [] })}`,
    `     VOID — ${reason}`,
  ];
}
