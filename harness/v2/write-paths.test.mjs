// The `writePaths` derivation, and the one rule that may never be relaxed: a REAL-home write is not
// promotable.
//
// SCOPE. Two layers, because they fail differently. The unit cases pin the COLLAPSE — which entry a
// pile of observed paths becomes, and when the answer is "none" — since a wrong entry there is a
// plausible-looking string that ships. The end-to-end cases drive `observe.mjs` itself, because the
// bug this whole file guards against is a WIRING one: reading the `userHome` bucket instead of the
// `jailHome` bucket produces a perfectly well-formed `writePaths` list that swaps a needed grant for
// a no-op, and no unit test of the collapse can see that.
//
//   node --test harness/v2/write-paths.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { deriveWritePaths, refuseUserHome, relativizeUnder, MAX_ENTRIES } from './write-paths.mjs';
import { parseDriverLog } from './record.mjs';

// ⛔ `import.meta.dirname`, never `new URL(...).pathname` — the doubled-drive-letter trap
// `observe.test.mjs` carries the scar for.
const HERE = import.meta.dirname;
const PROJ = '/home/u/root/observe';
const HOME = '/home/u';
const JAIL = '/home/u/root/jailhome';
const SHELL = '100 execve("/usr/bin/sh", ["sh", "-c", "postinstall"], 0x1 /* 1 vars */) = 0\n';

const CAPTURE_ROOTS = {
  project: PROJ, home: HOME, jailHome: JAIL, temp: null, npmPrefix: null,
  ownPkg: `${PROJ}/node_modules/p`, globalStore: null,
  projectStore: `${PROJ}/node_modules/.store`, interpreter: null, toolsDir: null,
};

/** Drive the real `observe.mjs` over a synthetic strace body and return its parsed grant plus the
 *  raw report — the report matters because the DERIVATION'S REFUSAL is only visible there, and a
 *  refusal that prints nothing is indistinguishable from a classifier that never asked. */
const observe = (body, version = '1.0.0') => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-test-'));
  const f = path.join(dir, 'trace.txt');
  fs.writeFileSync(f, SHELL + body);
  const cap = path.join(dir, 'capture.json');
  fs.writeFileSync(cap, JSON.stringify({ v: 1, kind: 'capture', pkg: 'p', version, roots: CAPTURE_ROOTS }));
  const out = execFileSync('node', [path.join(HERE, 'observe.mjs'), f, '--capture', cap], { encoding: 'utf8' });
  return { out, grant: JSON.parse(out.split('SYNTHESIZED GRANT')[1].split('\n')[1].trim()) };
};

/** One successful `openat` creating `abs`. The syscall shape the Linux decoder bills as a write. */
const wrote = (abs) => `200 openat(AT_FDCWD, "${abs}", O_WRONLY|O_CREAT, 0644) = 3\n`;

// ── the collapse ──────────────────────────────────────────────────────────────────────────────

test('many paths under one vendor directory collapse to ONE entry, and two vendors never to their shared root', () => {
  // The puppeteer shape: 355 paths, one answer. `.cache` is a `sharedHomeRoots` entry, so the entry
  // is the root PLUS ONE segment — the first directory the package itself owns.
  const one = deriveWritePaths([
    '.cache/puppeteer/chrome/linux-151/chrome',
    '.cache/puppeteer/chrome/linux-151/locales/en.pak',
    '.cache/puppeteer/.metadata',
  ]);
  assert.deepEqual(one.paths, ['.cache/puppeteer']);
  assert.equal(one.refused, null);

  // ⛔ THE HALF THAT CATCHES AN UNBOUNDED COLLAPSE. Walking up to the shared ancestor answers
  // `.cache` here — the cache root of every tool on the machine — and it gets WIDER the more a
  // package writes, which is backwards. Two vendors must give two entries.
  const two = deriveWritePaths(['.cache/alpha/x/y', '.cache/beta/x/y']);
  assert.deepEqual(two.paths, ['.cache/alpha', '.cache/beta']);
  assert.ok(!two.paths.includes('.cache'), 'collapsing two vendors to their shared root hands over every tool cache');
});

test('a directory NOT under a shared root keeps its own top segment', () => {
  // `.pulumi` is nobody else's root, so the entry is the first segment itself — the measured shape
  // for `@pulumi/gcp@0.16.9`, whose writes were `.pulumi/logs/...` and `.pulumi/plugins/...`.
  const r = deriveWritePaths(['.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp', '.pulumi/logs/x.log']);
  assert.deepEqual(r.paths, ['.pulumi']);
});

test('a shallower entry subsumes a deeper one, so nub is never asked to move a directory twice', () => {
  // ⛔ THIS CASE INJECTS A NON-PREFIX-CLOSED ROOT LIST, AND THE FIRST VERSION OF IT WAS A NO-OP.
  // Written against the shipped `sharedHomeRoots` it asserted `.electron/a/b` + `.electron/zip/c/d`
  // collapse to `.electron` — which they do, at the Set, because neither path matches a root and
  // both take one segment. The subsumption filter never ran, and BREAK 7 (deleting that filter)
  // left the whole file GREEN. The shipped list cannot reach the filter at all: every multi-segment
  // root has its parent in the list too, so a bare `Library` never appears beside a
  // `Library/Caches/V`. With `x/y` a root and `x` NOT, one path takes three segments and the other
  // takes one, and the pair is nested.
  const r = deriveWritePaths(['x/y/deep/file', 'x/other/file'], { sharedRoots: ['x/y'] });
  assert.deepEqual(r.paths, ['x'], 'the shallower entry must absorb the deeper one');
});

test('writes that SCATTER produce NO entry — the derivation declines rather than promoting a long tail', () => {
  // ⛔ THE NEGATIVE CONTROL FOR THE WHOLE FEATURE. Without it, "v2 emits writePaths" is satisfied by
  // emitting it always, and every package would ship a per-directory copy into the user's real home.
  // Promotion is AUTHORITY, so over-declaring is not the safe direction it is everywhere else here.
  const scattered = Array.from({ length: MAX_ENTRIES + 3 }, (_, i) => `.vendor${i}/sub/file`);
  const r = deriveWritePaths(scattered);
  assert.deepEqual(r.paths, [], 'a scattered write set must declare nothing');
  assert.match(r.refused, /SCATTER/, 'and must SAY it declined, not silently return empty');

  // The paired positive: exactly at the cap it still emits, so the refusal is a threshold and not a
  // blanket "never emit" that would pass this test while doing nothing.
  const atCap = Array.from({ length: MAX_ENTRIES }, (_, i) => `.vendor${i}/sub/file`);
  assert.equal(deriveWritePaths(atCap).paths.length, MAX_ENTRIES);
});

test('a FILE at the top of the private home yields no entry — an entry names a directory to move', () => {
  const r = deriveWritePaths(['.npmrc', '.bashrc']);
  assert.deepEqual(r.paths, []);
  assert.match(r.refused, /FILE at the top/);
});

test('a TOOLCHAIN-owned directory is never promoted, and a package directory beside it still is', () => {
  // ⛔ THE CASE THE EXISTING SUITE FOUND. The first version of this derivation had no denylist and
  // turned npm's own npx bootstrap — a symlink under `<jailhome>/.npm/_npx/...`, created inside the
  // lifecycle subtree by npm rather than by the package — into `writePaths: [".npm/_npx"]`, which
  // would copy an npx cache entry into the user's real `~/.npm`. `observe.test.mjs`'s two symlink
  // cases went red and were right to.
  //
  // Asserted with a legitimate sibling in the SAME input, so the denylist cannot pass this by
  // refusing everything.
  const r = deriveWritePaths(['.npm/_npx/abc/node_modules/.bin/x', '.cache/vendor/chrome/bin']);
  assert.deepEqual(r.paths, ['.cache/vendor']);

  const only = deriveWritePaths(['.cache/node-gyp/22.0.0/include/node/node.h']);
  assert.deepEqual(only.paths, [], 'node-gyp\'s shared header cache is the toolchain\'s, not the package\'s');
});

test('an observed path that could not become a legal catalog entry is DROPPED, not shipped', () => {
  // `catalog_v2.rs::parse_write_paths` refuses an absolute entry, a `~` entry and anything containing
  // `..` — and a REJECTED override does not fail loudly, it makes nub fall back to the COMPILED-IN
  // catalog while every other precondition still reads green. So the illegal shapes must never leave
  // this function. Asserted alongside a legal sibling so the case cannot pass by returning nothing.
  const r = deriveWritePaths(['../escape/x', '/abs/x', '~/tilde/x', '.cache/ok/x/y']);
  assert.deepEqual(r.paths, ['.cache/ok']);
});

test('an entry embedding the measured version is reported as version-pinned, not silently shipped', () => {
  const r = deriveWritePaths(['.cache/tool-1.2.3/bin/tool'], { version: '1.2.3' });
  assert.deepEqual(r.paths, ['.cache/tool-1.2.3']);
  assert.deepEqual(r.pinned, ['.cache/tool-1.2.3'], 'the collator turns this into a re-measure note');
  // CONTROL: the same entry measured at a version it does not contain is not pinned, so the field
  // cannot be a constant that happens to look right.
  assert.deepEqual(deriveWritePaths(['.cache/tool-1.2.3/bin/tool'], { version: '9.9.9' }).pinned, []);
});

test('relativizeUnder requires a separator boundary, so a sibling directory is not swallowed', () => {
  assert.equal(relativizeUnder('/a/jailhome/.cache/x', '/a/jailhome'), '.cache/x');
  assert.equal(relativizeUnder('/a/jailhome-backup/.cache/x', '/a/jailhome'), null);
  assert.equal(relativizeUnder('/a/jailhome', '/a/jailhome'), null, 'the home itself is not a subpath');
});

// ── the rule that may not be relaxed ──────────────────────────────────────────────────────────

test('a REAL-home write is never promotable, and refuseUserHome says why', () => {
  const r = refuseUserHome(617);
  assert.deepEqual(r.paths, []);
  assert.match(r.refused, /UNDER-GRANT/);
});

test('observe: a write into the PRIVATE home earns a writePaths entry and no write scope', () => {
  // The jailHome bucket is already base-covered, so no scope is earned — and before this change the
  // artefact was simply discarded with the throwaway home. The entry is what keeps it.
  const { grant, out } = observe(
    wrote(`${JAIL}/.cache/vendor/chrome/bin`) + wrote(`${JAIL}/.cache/vendor/chrome/lib.so`),
  );
  assert.deepEqual(grant.writePaths, ['.cache/vendor']);
  assert.equal(grant.write, undefined, 'a private-home write must not earn a write scope');
  assert.match(out, /writePaths \(DERIVED/);
});

test('observe: a REAL-home write keeps write.userHome and adds NO writePaths', () => {
  // ⛔ THE WIRING BUG THIS FILE EXISTS FOR. Sourcing the derivation from the `userHome` bucket
  // produces a perfectly well-formed `[".cache/vendor"]` here — and it would be a no-op, because
  // nub's mover only ever moves OUT of the private home and nothing of this package's is in it. The
  // install would then be refused at the write it needs. Both halves are asserted: the scope must
  // survive AND the field must be absent.
  const { grant, out } = observe(
    wrote(`${HOME}/.cache/vendor/chrome/bin`) + wrote(`${HOME}/.cache/vendor/chrome/lib.so`),
  );
  assert.equal(grant.write?.userHome, true, 'a real-home write still earns the scope');
  assert.equal(grant.writePaths, undefined, 'and must NOT be promoted — promotion cannot reach it');
  assert.match(out, /UNDER-GRANT/, 'the report must state why the scope was kept');
});

test('observe: scattered private-home writes emit no writePaths, and the report says it declined', () => {
  const body = Array.from({ length: MAX_ENTRIES + 3 }, (_, i) => wrote(`${JAIL}/.vendor${i}/sub/f`)).join('');
  const { grant, out } = observe(body);
  assert.equal(grant.writePaths, undefined);
  assert.match(out, /none declared — the writes SCATTER/);
});

test('observe: a version-pinned entry prints the marker record.mjs parses', () => {
  const { out } = observe(wrote(`${JAIL}/.cache/tool-4.5.6/bin/x`), '4.5.6');
  assert.match(out, /WRITEPATHS-VERSION-PINNED \["\.cache\/tool-4\.5\.6"\]/);
});

// ── the record hop ────────────────────────────────────────────────────────────────────────────

test('record: a grant carrying writePaths reaches the record, and the pinned marker with it', () => {
  // ⛔ THE HOP THAT WAS DEAD FOR EVERY v2 RECORD. `collate.mjs` has read `writePathsVersionPinned`
  // and `writePaths` off a record since v1 and turned the first into a re-measure note — inert,
  // because no v2 driver emitted either. Asserted end-to-end from a driver log rather than by
  // reading the parser, since the parse and the record assembly are separate steps and only the
  // second is what a collator sees.
  const p = parseDriverLog([
    '  == SYNTHESIZED GRANT (verify this in the real unprivileged jail) ==',
    '  {"network":true,"writePaths":[".cache/tool-4.5.6"]}',
    '  WRITEPATHS-VERSION-PINNED [".cache/tool-4.5.6"]',
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"network":true,"writePaths":[".cache/tool-4.5.6"]}   (observed, then verified)',
  ].join('\n'));
  assert.equal(p.verdict, 'MINIMUM');
  assert.deepEqual(p.grant.writePaths, ['.cache/tool-4.5.6'], 'the field must survive into the verified grant');
  assert.deepEqual(p.writePathsVersionPinned, ['.cache/tool-4.5.6']);
});

test('record: a descent that drops every scope leaves writePaths standing', () => {
  // The descent enumerates `no-network` / `no-write-<scope>` only, so `writePaths` must ride through
  // the recomputation untouched. If it did not, a package whose ONLY need is persistence would have
  // its declaration deleted by an arm that never tested it — silently, in the losing direction.
  const p = parseDriverLog([
    '  ARM-FALSIFIABILITY {"reasons":[]}',
    '  => VERIFIED {"write":{"deps":true},"writePaths":[".cache/v"]}   (observed, then verified)',
    '  => OVER-PREDICTED by: no-write-deps  (synthesized …)',
  ].join('\n'));
  assert.equal(p.grantSource, 'descended');
  assert.deepEqual(p.grant, { writePaths: ['.cache/v'] });
});

test('record: a log with NO writePaths yields an empty list, never undefined', () => {
  // CONTROL. `collate.mjs` does `r.writePaths ?? []`, so an absent field is survivable — but the
  // record must state that the question was ASKED and answered "none", which is the distinction this
  // corpus draws everywhere between an absent value and a measured zero.
  const p = parseDriverLog('  => VERIFIED {"network":true}   (observed, then verified)\n');
  assert.deepEqual(p.writePathsVersionPinned, []);
  assert.equal(p.grant.writePaths, undefined);
});
