// The arm PATH must be built, not inherited — and the tests that matter are the ones proving it
// does NOT over-drop. An over-broad rule would fail thousands of currently-passing records, which is
// a far worse outcome than leaving one contaminated.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { armPath, isContaminating, armPathMarker, ambientTools, ambientToolsMarker, LEAKABLE } from './arm-path.mjs';

test('drops the directories that actually leaked on the machine this was written on', () => {
  // Both measured, not imagined: `tsc` resolved from the first and `rimraf` from the second, which
  // is what made a local control pass the very step the corpus records as failing.
  assert.ok(isContaminating('/Users/x/Library/pnpm'));
  assert.ok(isContaminating('/Users/x/.config/yarn/global/node_modules/.bin'));
});

test('keeps every system directory a native build legitimately needs', () => {
  // ⛔ THE TEST THAT GUARDS THE 4,917 PASSING RECORDS. Homebrew is where a modern GNU Make comes
  // from, hostedtoolcache is how CI supplies compilers, and Xcode lives under /usr/bin.
  for (const dir of ['/usr/bin', '/bin', '/usr/sbin', '/sbin', '/usr/local/bin', '/opt/homebrew/bin',
                     '/opt/hostedtoolcache/Python/3.12.0/x64/bin', '/Library/Developer/CommandLineTools/usr/bin',
                     '/usr/local/go/bin', '/Users/x/.cargo/bin'])
    assert.ok(!isContaminating(dir), `${dir} must survive — dropping it breaks real builds`);
});

test('the fixture bin leads, then the era Node, then what survived', () => {
  const r = armPath({ ambient: '/usr/bin:/Users/x/Library/pnpm:/bin', eraBin: '/era/18/bin',
                      fixtureBin: '/fix/node_modules/.bin', sep: ':' });
  assert.equal(r.armPath, '/fix/node_modules/.bin:/era/18/bin:/usr/bin:/bin');
  assert.deepEqual(r.dropped, ['/Users/x/Library/pnpm']);
});

test('works with no era pin and no fixture — the unpinned path must still be sanitised', () => {
  const r = armPath({ ambient: '/usr/bin:/Users/x/.nvm/versions/node/v20/bin', sep: ':' });
  assert.equal(r.armPath, '/usr/bin');
});

test('an npm global prefix is dropped but /usr/local/bin beside it is not', () => {
  const r = armPath({ ambient: '/usr/local/lib/node_modules:/usr/local/bin', sep: ':' });
  assert.deepEqual(r.dropped, ['/usr/local/lib/node_modules']);
  assert.deepEqual(r.kept, ['/usr/local/bin']);
});

test('a stray node_modules/.bin never survives — only the fixture bin we place ourselves', () => {
  const r = armPath({ ambient: '/somewhere/node_modules/.bin:/usr/bin', fixtureBin: '/fix/node_modules/.bin', sep: ':' });
  assert.equal(r.armPath, '/fix/node_modules/.bin:/usr/bin');
});

test('Windows separators and backslashes classify the same', () => {
  assert.ok(isContaminating('C:\\Users\\x\\AppData\\Roaming\\npm\\lib\\node_modules'));
  const r = armPath({ ambient: 'C:\\Windows\\system32;C:\\Users\\x\\.bun\\bin', sep: ';' });
  assert.equal(r.armPath, 'C:\\Windows\\system32');
});

test('the marker states what was removed, so the record can be read back', () => {
  assert.match(armPathMarker({ dropped: ['/a', '/b'] }), /^ARM-PATH SANITISED \(dropped 2: \/a, \/b\)$/);
  assert.match(armPathMarker({ dropped: [] }), /nothing to drop/);
});

test('empty ambient PATH does not synthesise an empty entry', () => {
  assert.equal(armPath({ ambient: '', eraBin: '/era/bin', sep: ':' }).armPath, '/era/bin');
});

test('the probe reports a tool that survived the directory filter', () => {
  // ⛔ THE CASE THAT KILLED THE FILTER-ONLY DESIGN, pinned so it cannot silently come back. After
  // dropping every package-manager directory, `tsc` still resolved from /usr/local/bin — a system
  // directory a native build needs. No directory rule separates them, so the record must SAY so.
  const found = ambientTools('/usr/local/bin:/usr/bin', {
    resolve: (n, dirs) => (n === 'tsc' ? dirs.find((d) => d === '/usr/local/bin') + '/tsc' : null),
    sep: ':',
  });
  assert.deepEqual(found, { tsc: '/usr/local/bin/tsc' });
  assert.match(ambientToolsMarker(found), /^ARM-AMBIENT-TOOLS 1 leaked: tsc=\/usr\/local\/bin\/tsc$/);
});

test('a clean box reports none, so the marker is never ambiguous', () => {
  assert.equal(ambientToolsMarker(ambientTools('/usr/bin', { resolve: () => null, sep: ':' })), 'ARM-AMBIENT-TOOLS none');
});

test('the probe list covers the binaries the corpus actually died on', () => {
  // Measured distribution over the 105 `command not found` records; the top names must all be probed
  // or the marker understates the contamination on exactly the records that matter most.
  for (const n of ['tsc', 'husky', 'patch-package', 'rimraf', 'typings', 'pnpm', 'pulumi'])
    assert.ok(LEAKABLE.includes(n), `${n} is a measured failure cause and must be probed`);
});
