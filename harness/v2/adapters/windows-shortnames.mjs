// The 8.3 short-name map: a CAPTURE-HOST fact, resolved once and archived.
//
// ⛔ THIS FILE EXISTS BECAUSE THE DECODER USED TO ANSWER DIFFERENTLY DEPENDING ON THE MACHINE IT RAN
// ON. Both Windows decoders gated 8.3 expansion on
// `(meta.host ?? '').toLowerCase() === (process.env.COMPUTERNAME ?? '').toLowerCase()` —
// an AMBIENT read of the DECODING host (`windows.mjs:100`, `windows-retain.mjs:693`). Decoding one
// archive on the capture VM and on a CI runner therefore produced two DIFFERENT views of the same
// bytes: on the capture host `C:\Users\RUNNER~1\...` expands and lands in the `userHome` scope, and
// anywhere else it stays short and falls to `outside`, which is reported and never granted. That is
// an under-grant, and it is invisible. It also broke the venue-portability acceptance test at the
// root, because that test's whole method is decoding and comparing two archives — the instrument
// disagreed with itself exactly where it was being used to detect disagreement. (VENUE-PORTABILITY
// R2: the classifier reads roots ONLY from the capture; no ambient environment reads.)
//
// ⛔ THE RESOLUTION GENUINELY NEEDS A LIVE FILESYSTEM, and that is not a reason to keep the ambient
// read — it is the reason for this file. `RUNNER~1` names whatever THAT machine had, and expanding
// it is a `realpathSync.native` against a directory that exists only there and only then. So the fix
// is not to make every decoder resolve; it is to resolve ONCE, on the capture host, at capture time,
// and ARCHIVE the answer. Every later decode reads the map and touches no filesystem at all, so its
// output is a pure function of (archive, explicit flags) and is identical on any machine.
//
// ⛔ A MISSING MAP IS NOT A LICENCE TO GUESS. An archive with no map decodes with expansion OFF — on
// every machine, INCLUDING the one that captured it. Expansion-off is then a property of the
// ARCHIVE, which is stable and inspectable; the old behaviour made it a property of the OBSERVER,
// which is what made it silent.
//
// ⛔ AND A MAP THAT DOES NOT COVER A PATH IS COUNTED, NOT FILLED IN. `entries` records `null` for a
// component the capture host itself could not resolve (deleted temp file, junction crossing) — an
// ANSWER. A key that is absent from the map is a DIFFERENT state: the map is incomplete, which means
// it was written by an older or partial resolution pass. Those get `shortUnmapped`, kept short, so
// an incomplete archive is visible rather than silently topped up from ambient state.
import fs from 'node:fs';
import path from 'node:path';

export const SHORT_NAMES_SCHEMA = 'nub-obs-win-shortnames/1';
export const SHORT_NAMES_FILE = 'shortnames.json';

// DELIBERATELY LOOSE, and tightening it would be the wrong repair. This only decides whether a
// component is worth RESOLVING; the filesystem is the authority. A false positive (`a~b~1`, a
// legitimate long name) resolves to itself and nothing changes. A false NEGATIVE silently keeps a
// path in the wrong scope, so the pattern errs toward asking.
export const SHORT_COMPONENT = /^[^\\/.]{1,8}~\d+(\.[^\\/.]{1,3})?$/;

// Keys are lowercased FULL short paths (`parent\comp`), not bare components: `PROGRA~1` means
// different things under `C:\` and under `C:\Users\nub\`, and a component-only key would collide.
export const shortKey = (parent, comp) => `${parent}\\${comp}`.toLowerCase();

// A distinguished return meaning "this map does not say". `null` is reserved for the map SAYING
// there is no long name, which is an answer and must not be confused with the map not covering it.
export const UNMAPPED = Symbol('unmapped');

export function loadShortNames(file) {
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return null; }
  if (parsed?.schema !== SHORT_NAMES_SCHEMA || typeof parsed.entries !== 'object' || !parsed.entries) {
    throw new Error(`${file}: not a ${SHORT_NAMES_SCHEMA} map`);
  }
  return parsed;
}

// The one place a decoder is allowed to touch the filesystem, and only when the caller has said in
// so many words that it is the capture host. Accepts ONLY a same-parent rename: a junction or
// symlink resolves elsewhere, and rewriting the path to its target would silently move the operation
// into a different scope.
function resolveAgainstFilesystem(parent, comp) {
  try {
    const real = fs.realpathSync.native(`${parent}\\${comp}`);
    const leaf = path.win32.basename(real);
    if (leaf && path.win32.dirname(real).toLowerCase() === parent.toLowerCase()) return leaf;
  } catch { /* gone, or unreachable: there is no long name to be had */ }
  return null;
}

// Returns `(parent, comp) -> long | null | UNMAPPED`.
//
//   mode 'map'     read a recorded map; NEVER touches the filesystem. UNMAPPED for an absent key.
//   mode 'resolve' capture-host only: resolve against the filesystem and RECORD every answer, so the
//                  archive carries what this pass learned and no later decode has to re-derive it.
export function componentResolver({ mode, entries = null, record = null }) {
  if (mode === 'map') {
    return (parent, comp) => {
      const k = shortKey(parent, comp);
      return Object.hasOwn(entries, k) ? entries[k] : UNMAPPED;
    };
  }
  if (mode === 'resolve') {
    return (parent, comp) => {
      const k = shortKey(parent, comp);
      if (Object.hasOwn(record, k)) return record[k];
      const long = resolveAgainstFilesystem(parent, comp);
      record[k] = long;
      return long;
    };
  }
  throw new Error(`componentResolver: unknown mode ${mode}`);
}

// ⛔ THE MODE IS DECIDED BY THE ARCHIVE AND BY EXPLICIT FLAGS, NEVER BY THE HOST. `reason` is what
// the decoders print, so an expansion-off run says WHICH of these it was rather than naming two
// machines whose relationship the reader cannot check.
//
// `--resolve-shortnames` is the capture-time pass. The driver passes it because the driver knows it
// is on the capture host with the traced tree still on disk; nothing infers that. Running it
// anywhere else would record a map of that machine's names, which is why it is opt-in and loud
// rather than a default that happens to be right on one box.
export function shortNameMode({ dir, args, val }) {
  if (args.includes('--no-longpath')) return { mode: 'off', reason: '--no-longpath' };
  if (args.includes('--resolve-shortnames')) {
    if (process.platform !== 'win32') {
      return { mode: 'off', reason: '--resolve-shortnames given off Windows; refusing to invent a map' };
    }
    return { mode: 'resolve', reason: 'resolving on the capture host', record: {} };
  }
  const file = val('--shortnames') ?? path.join(dir, SHORT_NAMES_FILE);
  const loaded = loadShortNames(file);
  if (!loaded) {
    return { mode: 'off', reason: `no recorded 8.3 map at ${path.basename(file)} — a property of this ARCHIVE, identical on every machine` };
  }
  return { mode: 'map', reason: `recorded 8.3 map (${Object.keys(loaded.entries).length} components, resolved on ${loaded.host ?? 'an unnamed host'})`, entries: loaded.entries, file, loaded };
}

export function writeShortNames(file, record, meta) {
  const payload = {
    schema: SHORT_NAMES_SCHEMA,
    // The host is recorded so a reader can see WHERE these names came from. It is provenance and
    // nothing reads it to make a decision — that is the whole difference from the mechanism this
    // file replaced.
    host: meta?.host ?? null,
    resolvedAt: new Date().toISOString(),
    entries: record,
  };
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`);
  return payload;
}
