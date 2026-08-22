// The cause extractor decides what a CONFIRMED row is worth. A row whose `firstError` is
// `npm error code 1` looks attributed and tells nobody anything, and the failure is invisible in
// aggregate — every row has a non-null field. These fixtures are the npm error blocks the sweep
// actually meets, each with the one line a human would have picked.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firstCause } from './observe-only.mjs';

test('an unsupported-platform block resolves to the notsup line, not the code', () => {
  // `code EBADPLATFORM` was the answer on 64 rows of the 2026-08-21 ledger. It names the category;
  // the very next line names the package and both platforms.
  const log = `
npm error code EBADPLATFORM
npm error notsup Unsupported platform for fsevents@1.2.13: wanted {"os":"darwin"} (current: {"os":"linux"})
npm error notsup Valid os:  darwin
npm error A complete log of this run can be found in: /root/.npm/_logs/x.log`;
  assert.match(firstCause(log), /notsup Unsupported platform for fsevents@1\.2\.13/);
});

test('a node-gyp block resolves to the gyp stack error, not to `code 1` or the path', () => {
  // ⛔ THE WIN32 REGRESSION IN ONE FIXTURE. `npm error path C:\\...` is the second line of every
  // npm 10 error block, and it won 284 of 284 win32 rows. Under npm 10 the whole gyp transcript is
  // re-prefixed with `npm error`, so skipping `gyp` wholesale would leave `code 1` as the answer.
  const log = String.raw`
npm error code 1
npm error path C:\Users\RUNNER~1\AppData\Local\Temp\obs-qwdm99\observe\node_modules\heapdump
npm error command failed
npm error command sh -c node-gyp rebuild
npm error gyp info it worked if it ends with ok
npm error gyp info using node-gyp@10.0.1
npm error gyp ERR! find Python Python is not set from command line or npm configuration
npm error gyp ERR! stack Error: Could not find any Python installation to use
npm error A complete log of this run can be found in: /root/.npm/_logs/x.log`;
  assert.match(firstCause(log), /gyp ERR! find Python/);
});

test('an old-npm lifecycle block resolves to the line naming the package and the script', () => {
  // npm 2/3 shape, which the era pin reintroduces on every record older than ~2016. The OS banner
  // and `code ELIFECYCLE` are both category lines; the useful one names the failing script.
  const log = `
npm ERR! Linux 6.17.0-1022-azure
npm ERR! argv "/x/bin/node" "/x/bin/npm" "rebuild"
npm ERR! node v4.9.1
npm ERR! npm  v2.15.11
npm ERR! code ELIFECYCLE
npm ERR! heapdump@0.3.9 install: \`node-gyp rebuild\`
npm ERR! Exit status 1
npm ERR! Failed at the heapdump@0.3.9 install script 'node-gyp rebuild'.`;
  assert.match(firstCause(log), /heapdump@0\.3\.9 install/);
});

test('a log with nothing but category lines still yields its first error line', () => {
  // The fallback is what keeps a row from becoming LESS informative than before. Tightening the
  // pattern must never turn an attributed row into a null one.
  const log = `
npm error code 1
npm error path /tmp/x
npm error A complete log of this run can be found in: /root/.npm/_logs/x.log`;
  assert.equal(firstCause(log), 'npm error code 1');
});

test('a log with no error lines at all yields null', () => {
  assert.equal(firstCause('added 12 packages in 3s\n'), null);
  assert.equal(firstCause(''), null);
});

test('a raw (un-prefixed) toolchain failure is still the answer', () => {
  // Not every failure goes through npm's error block: a lifecycle script's own stderr reaches the
  // log unprefixed. 132 rows of the ledger were attributed this way and must stay that way.
  // `gyp ERR! configure error` names the PHASE that died, never why. heapdump@0.3.9 was attributed
  // to exactly that marker until the phase lines were demoted.
  assert.match(firstCause('gyp ERR! configure error\ngyp ERR! stack Error: not found: make\n'),
               /stack Error: not found: make/);
  assert.match(firstCause('sh: 1: node-pre-gyp: command not found\n'), /node-pre-gyp: command not found/);
});

test('a fetch that never installed the package still records why', () => {
  // ⛔ THE FAIL-OPEN THIS CLOSED. `runCapped` returns only {code, timedOut} and the fetch's stdio is
  // a file descriptor, so the failure branch was reading `f.stdout` — always undefined. Every row
  // npm could not even install carried firstError: null, which is indistinguishable from a row that
  // was never measured. The runner now reads fetch.log; this pins the shape it must handle.
  const log = `npm error code EBADPLATFORM
npm error notsup Unsupported platform for @ffmpeg-installer/darwin-x64@4.1.0: wanted {"arch":"x64"} (current: {"arch":"arm64"})`;
  assert.match(firstCause(log), /notsup Unsupported platform for @ffmpeg-installer/);
});
