// THE FIXTURE. Runs identically jailed and unjailed and prints ONE machine-readable record, so a
// diff between two arms is a diff between two JSON objects and not between two prose logs.
//
// ⛔ EVERY PATH THIS PROBES ARRIVES ON argv, NEVER FROM ITS OWN ENVIRONMENT. The whole question is
// what the jailed child's environment says, so a fixture that derived its own targets from
// `%USERPROFILE%` / `%LOCALAPPDATA%` would silently probe a DIFFERENT target in the jailed arm than
// in the unjailed one -- and the negative control, which only means something when both arms aim at
// the same file, would be aiming at two. The env is DATA here, reported and never consumed.
//
// Output framing: the record is wrapped in sentinels because a jailed run's stdout also carries
// nub's own warnings, and a driver that JSON.parse'd the whole stream would fail on a healthy run.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const flag = (n, d = '') => {
  const i = process.argv.indexOf(n);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : d;
};

const LABEL = flag('--label', 'anon');
const MARKER = flag('--marker', `nubtmp-${LABEL}-${Math.random().toString(36).slice(2, 10)}`);
// The negative control's target. Handed in so both arms write to the same absolute path.
const NEGCTL = flag('--negctl', '');
// Roots to hunt the marker in from INSIDE the jail. The interesting one is the host's
// `%LOCALAPPDATA%\Packages`, where an AppContainer's virtualized TEMP is said to land.
const HUNT = flag('--hunt', '').split(';').filter(Boolean);

const attempt = (fn) => {
  try {
    return { ok: true, value: fn() };
  } catch (e) {
    return { ok: false, code: e.code ?? null, errno: e.errno ?? null, message: String(e.message) };
  }
};

// A write is only evidence if the bytes come back: on Windows a create can succeed against a path
// that is then redirected elsewhere, and read-back is what proves the file the process believes it
// wrote is the file it can reach.
//
// ⛔ IT DELIBERATELY DOES NOT CREATE THE PARENT. Every target here has a parent that exists before
// the run (the mkdtemp dir, `C:\Windows\Temp`, the `C:\Temp` the driver makes outside the jail, the
// user profile), and a `mkdirSync(..., {recursive:true})` would fold a directory-creation refusal
// into the file-write result -- reporting a parent the jail would not let us make as though the
// WRITE had failed. `parentExists` is reported instead so an ENOENT is never read as a denial.
const writeRead = (p) =>
  attempt(() => {
    const parentExists = fs.existsSync(path.dirname(p));
    fs.writeFileSync(p, MARKER);
    const back = fs.readFileSync(p, 'utf8');
    return { path: p, parentExists, roundTrip: back === MARKER, realpath: attempt(() => fs.realpathSync.native(p)) };
  });

// Bounded walk. The AppContainer profile is nearly empty, so a small cap finds the marker if it is
// there; the cap exists so a mis-aimed root (a real user profile) cannot turn this into a disk scan.
const hunt = (root, token, maxDepth = 6, cap = 20000) => {
  const hits = [];
  let seen = 0;
  let truncated = false;
  const walk = (dir, depth) => {
    if (depth > maxDepth || seen > cap) {
      truncated = truncated || seen > cap;
      return;
    }
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (seen++ > cap) {
        truncated = true;
        return;
      }
      const full = path.join(dir, e.name);
      if (e.name.includes(token)) hits.push(full);
      if (e.isDirectory()) walk(full, depth + 1);
    }
  };
  walk(root, 0);
  return { root, exists: fs.existsSync(root), hits, scanned: seen, truncated };
};

const env = process.env;
const tmpdir = os.tmpdir();

// ⛔ WHICH VARIABLE NODE ACTUALLY USED, decided by replaying Node's own Windows algorithm
// (`lib/os.js`: `TEMP || TMP || <SystemRoot|windir>\temp`, trailing separator trimmed) against the
// env this process was handed, and then CHECKING the replay reproduces `os.tmpdir()`. Reporting the
// source without that check would be an assertion about Node's source, not a measurement.
const trim = (s) => (s && s.length > 1 && /[\\/]$/.test(s) && !/^[a-zA-Z]:[\\/]$/.test(s) ? s.slice(0, -1) : s);
let tmpdirSource = 'SystemRoot|windir + \\temp';
let replay = `${env.SystemRoot || env.windir}\\temp`;
if (env.TEMP) {
  tmpdirSource = 'TEMP';
  replay = env.TEMP;
} else if (env.TMP) {
  tmpdirSource = 'TMP';
  replay = env.TMP;
}

const mk = attempt(() => {
  const d = fs.mkdtempSync(path.join(tmpdir, `${MARKER}-`));
  return {
    dir: d,
    realpathNative: attempt(() => fs.realpathSync.native(d)),
    realpath: attempt(() => fs.realpathSync(d)),
    write: writeRead(path.join(d, 'inside.txt')),
    // Can the dir be reached again through the literal env TEMP string? If a redirection is
    // happening beneath us this still resolves; the hunt below says where the bytes are.
    reReadDir: attempt(() => fs.readdirSync(d)),
  };
});

const record = {
  label: LABEL,
  marker: MARKER,
  pid: process.pid,
  nodeVersion: process.version,
  cwd: process.cwd(),
  osTmpdir: tmpdir,
  osHomedir: attempt(() => os.homedir()),
  osUserInfo: attempt(() => os.userInfo().username),
  tmpdirSource,
  tmpdirReplayMatches: trim(replay) === tmpdir,
  tmpdirReplayValue: trim(replay),
  env: {
    TEMP: env.TEMP ?? null,
    TMP: env.TMP ?? null,
    TMPDIR: env.TMPDIR ?? null,
    USERPROFILE: env.USERPROFILE ?? null,
    LOCALAPPDATA: env.LOCALAPPDATA ?? null,
    APPDATA: env.APPDATA ?? null,
    HOME: env.HOME ?? null,
    HOMEDRIVE: env.HOMEDRIVE ?? null,
    HOMEPATH: env.HOMEPATH ?? null,
    SystemRoot: env.SystemRoot ?? null,
    SystemDrive: env.SystemDrive ?? null,
    USERNAME: env.USERNAME ?? null,
  },
  envKeys: Object.keys(env).sort(),
  envCount: Object.keys(env).length,
  mkdtemp: mk,
  // ── Q6: the Windows analogue of the POSIX hardcoded-`/tmp` split. ────────────────────────────
  hardcoded: {
    windowsTemp: writeRead(`C:\\Windows\\Temp\\${MARKER}-winroot.txt`),
    cTemp: writeRead(`C:\\Temp\\${MARKER}-ctemp.txt`),
    // mkdtemp against the hardcoded root too: `bin-wrapper`-shaped installers make a dir, not a file.
    windowsTempMkdtemp: attempt(() => fs.mkdtempSync(`C:\\Windows\\Temp\\${MARKER}-`)),
  },
  // ── The negative control. MUST fail jailed and MUST succeed unjailed. ───────────────────────
  negativeControl: NEGCTL ? { target: NEGCTL, write: writeRead(NEGCTL) } : { target: null, skipped: true },
  // Informational, and deliberately separate from the control: on Windows the jail is documented to
  // leave the user profile READABLE, so a successful read here is expected and is NOT a breach.
  homeReadable: NEGCTL ? attempt(() => fs.readdirSync(path.dirname(NEGCTL)).length) : { ok: false, skipped: true },
  hunts: HUNT.map((r) => hunt(r, MARKER)),
};

// ⛔ THE SENTINELS ARE ASSEMBLED AT RUNTIME, NEVER WRITTEN WHOLE. Arm A hands this file to `node
// -e` as a command-line ARGUMENT, so any error path that echoes the command line would reproduce a
// literal `@@PROBE@@ ... @@END@@` pair in the output -- and a driver scanning for that pair would
// then extract the fixture's own SOURCE and report it as a result. Splitting the literals means the
// only way the pair appears intact is if this line ran.
process.stdout.write(`@@PRO${'BE'}@@${JSON.stringify(record)}@@E${'ND'}@@\n`);
