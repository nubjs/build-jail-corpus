// The win32 driver's PRIVATE HOME: that it exists, that it is declared as the `jailHome` root, and
// that every environment vector reaching the measured install carries the redirect.
//
// ⛔ WHY THIS IS A SEPARATE FILE FROM `write-paths.test.mjs`. That file pins the CLASSIFIER half —
// given a declared `jailHome` root, which bucket a path lands in and what it earns. This one pins the
// DRIVER half, and the two fail differently. A classifier that reads the right bucket against a root
// nothing ever wrote to produces an EMPTY bucket, which is byte-identical to a package that wrote
// nothing into its home: the record then says `writePaths: []` and reads as a measured zero rather
// than as a lane that never asked the question. That is exactly the state win32 was in for 2,270
// records, and it is invisible from the classifier's side.
//
// ⛔ AND THE DRIVER CANNOT BE RUN HERE. It is Windows-only end to end — ETW, powershell, cmd.exe — so
// these assert against its SOURCE. Two of the three do it by EXECUTING the extracted region against a
// synthetic environment rather than by matching a regex over it, which is what makes them able to
// fail for the right reason: a regex guard passes on code that has stopped working.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const DRIVER = path.join(import.meta.dirname, 'measure-windows.mjs');
const src = fs.readFileSync(DRIVER, 'utf8');

/** The source text from `decl` up to and including the first line equal to `close` at column zero.
 *  The same extraction idiom `rebuild-spec-is-versioned.test.mjs` and `win-control-era-env.test.mjs`
 *  use, so a region that moves does not silently stop being tested — it fails to be found. */
function region(decl, close) {
  const lines = src.split('\n');
  const start = lines.findIndex((l) => l.startsWith(decl));
  assert.notEqual(start, -1, `measure-windows.mjs no longer declares \`${decl}\``);
  const end = lines.findIndex((l, i) => i > start && l === close);
  assert.notEqual(end, -1, `could not find the end of \`${decl}\``);
  return lines.slice(start, end + 1).join('\n');
}

test('the driver declares its own private home as the `jailHome` root', () => {
  // ⛔ THE ROOT IS THE WHOLE MECHANISM. `classify.mjs` keys the free-and-promotable bucket on the
  // path `capture.json` declares and on nothing else, so a `null` here is not a missing decoration —
  // it removes the bucket, and with it every `writePaths` this lane could ever derive.
  assert.match(src, /^\s*jailHome: OBS_HOME,$/m,
    'the capture must declare the private home this driver created and exported');
  assert.doesNotMatch(src, /^\s*jailHome: null,$/m,
    'a null jailHome deletes the promotable bucket — 0 writePaths on every win32 record');
  // And the directory has to exist before anything writes into it: a redirect onto a path that is
  // not there trades one failure for another, which is why `preset.rs` materializes its own leaf.
  assert.match(src, /const OBS_HOME = path\.join\(ROOT, 'jailhome'\);/);
  assert.match(src, /fs\.mkdirSync\(OBS_APPDATA, \{ recursive: true \}\);/,
    'creating the AppData leaf creates the home root with it — both must exist before the fetch');
  // ⛔ APPDATA IS THE `AppData\Roaming` LEAF INSIDE THE PRIVATE HOME, NOT THE HOME ROOT, because that
  // is what `preset.rs` builds: npm on Windows resolves its cache to `%APPDATA%\npm-cache` rather
  // than to `$HOME/.npm`, and a package walking relative to `%APPDATA%` expects the real layout. It
  // is asserted HERE, against the source, because the value is decided outside the region the next
  // test executes — where an assertion on it would compare an argument against itself and pass on a
  // driver that had collapsed the two.
  assert.match(src, /const OBS_APPDATA = path\.join\(OBS_HOME, 'AppData', 'Roaming'\);/,
    'collapsing APPDATA onto the home root changes the directory layout a script sees');
});

test('the home redirect is presence-gated and keeps the ambient spelling', () => {
  // Executed, not matched. `compile_build_jail` only REPLACES a home variable the environment already
  // carried and compares case-insensitively on Windows, and OBSERVE has to reproduce both: inventing
  // a variable the jailed child would not have is a second divergence where the contract allows
  // exactly one, and adding `HOME:` beside an ambient `Home:` hands the child BOTH spellings.
  const build = new Function('process', 'OBS_HOME', 'OBS_APPDATA',
    `${region('const OBS_HOME_ENV = Object.fromEntries(', ');')}\nreturn OBS_HOME_ENV;`);
  const H = 'C:\\jail\\m-x\\jailhome';
  const A = `${H}\\AppData\\Roaming`;

  // A Windows ambient: USERPROFILE and APPDATA are redirected, LOCALAPPDATA is deliberately not —
  // the LowBox launch resolves its AppContainer profile directory from it.
  const win = build({ env: { USERPROFILE: 'C:\\Users\\nub', APPDATA: 'C:\\Users\\nub\\AppData\\Roaming', LOCALAPPDATA: 'C:\\Users\\nub\\AppData\\Local' } }, H, A);
  // The two values are distinct, so this also pins the MAPPING: `APPDATA` takes the AppData leaf and
  // the two home variables take the home root, never the other way round.
  assert.deepEqual(win, { USERPROFILE: H, APPDATA: A });

  // The odd-cased ambient. The value must land on the key that is ALREADY there.
  const odd = build({ env: { Userprofile: 'C:\\Users\\nub' } }, H, A);
  assert.deepEqual(odd, { Userprofile: H },
    'a second, differently-cased key would hand the child both the real home and the private one');

  // A POSIX-shaped ambient carries no USERPROFILE, so none is introduced.
  assert.deepEqual(build({ env: { HOME: '/home/u' } }, H, A), { HOME: H });
});

test('⭑ every OBSERVE environment vector carries the redirect, because there is exactly one', () => {
  // ⛔ THE FOUR VECTORS. The rewrites reach the measured install through the untraced fetch and npm
  // reference arm (`obsEnv`), the two scaffold installs, and the `rebuild.cmd` wrapper — the only one
  // in scope for the TRACED rebuild. A redirect present in three of the four declares a `jailHome`
  // root the traced run never wrote to, and the empty bucket reads as a measured zero. The guard is
  // therefore not "each site mentions HOME" but "no site can spell the environment for itself".
  const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l));
  const defs = code.filter((l) => l.includes('npm_config_cache'));
  assert.equal(defs.length, 1,
    `the OBSERVE environment must have ONE definition; found ${defs.length}:\n  ${defs.map((l) => l.trim()).join('\n  ')}`);
  assert.equal(code.filter((l) => l.includes('TMP: OBS_TMP')).length, 1,
    'a second hand-written temp redirect is a second spelling that will drift from the declared root');

  // CONTROL: the scan is reading real code, and the consumers are really there. Without this the
  // assertions above are satisfied by a file that sets no environment at all.
  const consumers = code.filter((l) => /\.\.\.OBS_ENV|Object\.entries\(OBS_ENV\)|set: OBS_ENV/.test(l));
  assert.ok(consumers.length >= 6,
    `expected the four env vectors plus the two provenance emissions, found ${consumers.length}`);
  assert.match(src, /const WRAP_SETS = Object\.entries\(OBS_ENV\)/,
    'the traced rebuild\'s cmd wrapper must be GENERATED from the same object, not retyped');
  assert.match(src, /observeEnv: \{ set: OBS_ENV, unset: \[\] \}/,
    'R6: the archive\'s account of what the driver set must be the object it set, not a list beside it');
});

test('the generated cmd wrapper exports the redirect into the traced shell', () => {
  // Executed for the same reason as the presence gate: the wrapper is a STRING, so a change that
  // stops emitting `set` lines is invisible to any assertion about the code that builds it. `cmd`
  // resolves `set` names case-insensitively, so the ambient spelling costs nothing here.
  const line = src.split('\n').find((l) => l.startsWith('const WRAP_SETS = '));
  assert.ok(line, 'measure-windows.mjs no longer builds the wrapper from a single WRAP_SETS line');
  const build = new Function('OBS_ENV', `${line}\nreturn WRAP_SETS;`);
  const text = build({ npm_config_cache: 'C:\\r\\npm-cache', TMP: 'C:\\r\\tmp', USERPROFILE: 'C:\\r\\jailhome' });
  assert.equal(text,
    'set "npm_config_cache=C:\\r\\npm-cache"\r\nset "TMP=C:\\r\\tmp"\r\nset "USERPROFILE=C:\\r\\jailhome"\r\n');
  // The `rebuild` line still follows the sets in the file itself; a wrapper that set the environment
  // after invoking npm would be worse than one that never set it, because it would read as fixed.
  assert.match(src, /\$\{WRAP_SETS\}"\$\{NODE\}" "\$\{NPM\}" rebuild/,
    'the sets must precede the traced command in the wrapper');
});
