import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyReference, firstErrorFrom } from './reference-classify.mjs';

const arm = (outcome, error = '') => ({
  quorum: { outcome, fingerprint: error ? `fp-${outcome}` : null },
  lifecycle: { provenCount: outcome === 'pass' ? 1 : 0 },
  attempts: error ? [{ stages: { install: { error: firstErrorFrom(error) } } }] : [],
});
const record = (nub, npm, extra = {}) => ({
  status: 'complete',
  arms: { nubUnjailed: nub, npmUnjailed: npm },
  lifecycle: { expectedCount: 1 },
  provenance: { runtime: { node: { version: 'v22.23.2' }, os: { platform: 'linux', arch: 'x64' } } },
  ...extra,
});

test('the classifier preserves package-manager differentials instead of blaming the jail', () => {
  assert.equal(classifyReference(record(arm('consistent-failure', 'Error: failed'), arm('pass'))).code,
    'NUB_PM_DIVERGENCE');
  assert.equal(classifyReference(record(arm('pass'), arm('consistent-failure', 'Error: failed'))).code,
    'NPM_PM_DIVERGENCE');
});

test('a timed-out arm remains incomplete instead of becoming a package-manager verdict', () => {
  const classified = classifyReference(record(arm('timeout', 'REFERENCE-DEADLINE-REACHED'), arm('pass')));
  assert.equal(classified.code, 'REFERENCE_TIMEOUT');
  assert.equal(classified.status, 'incomplete');
});

test('a recovered clean retry is transient evidence, not a package-manager divergence', () => {
  assert.equal(classifyReference(record(arm('pass-after-failure'), arm('pass'))).code,
    'TRANSIENT_EXTERNAL_DOWNLOAD');
  assert.equal(classifyReference(record(arm('pass'), arm('pass-after-failure'))).code,
    'TRANSIENT_EXTERNAL_DOWNLOAD');
});

test('an incompatible Nub binary or contaminated fixture is an instrument failure, not a package differential', () => {
  for (const message of ['Error: unknown key `buildJail` in install', 'Error: ERR_NUB_LOCKFILE_AMBIGUOUS']) {
    const classified = classifyReference(record(arm('consistent-failure', message), arm('pass')));
    assert.equal(classified.code, 'HARNESS_INTERNAL');
    assert.equal(classified.status, 'incomplete');
  }
});

test('metadata classes outrank failure signatures when both managers fail', () => {
  const both = record(arm('consistent-failure', 'gyp ERR! build error'), arm('consistent-failure', 'gyp ERR! build error'), {
    packageMetadata: { engines: { node: '<=16' } },
  });
  assert.equal(classifyReference(both).code, 'INCOMPATIBLE_NODE');
});

test('a package libc constraint excludes the wrong Linux runtime cell', () => {
  const both = record(arm('consistent-failure', 'Error: unsupported runtime'),
    arm('consistent-failure', 'Error: unsupported runtime'), {
      packageMetadata: { libc: ['glibc'] },
    });
  both.provenance.runtime.os.libc = { family: 'musl', version: '1.2.5' };
  assert.equal(classifyReference(both).code, 'OS_CPU_MISMATCH');
});

test('toolchain, transient, permanent and unknown failures stay mutually exclusive', () => {
  const cases = [
    ['gyp ERR! find Python Could not find any Python installation', 'TOOLCHAIN_PREREQUISITE'],
    ['deps/readies/mk/main:6: *** GNU Make version is too old. Aborting.', 'TOOLCHAIN_PREREQUISITE'],
    ['./autogen.sh: line 18: aclocal: command not found', 'TOOLCHAIN_PREREQUISITE'],
    ["Makefile.am:161: error: Libtool library used but 'LIBTOOL' is undefined", 'TOOLCHAIN_PREREQUISITE'],
    ['npm ERR! code ECONNRESET', 'TRANSIENT_EXTERNAL_DOWNLOAD'],
    ['npm ERR! code ETARGET No matching version found', 'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ['Error: surprising opaque failure', 'UNCLASSIFIED'],
  ];
  for (const [message, expected] of cases) {
    const classified = classifyReference(record(arm('consistent-failure', message), arm('consistent-failure', message)));
    assert.equal(classified.code, expected, message);
  }
});

test('a green exit without lifecycle evidence remains incomplete', () => {
  const green = record(arm('pass'), arm('pass'));
  green.arms.nubUnjailed.lifecycle.provenCount = 0;
  green.arms.npmUnjailed.lifecycle.provenCount = 0;
  assert.deepEqual(classifyReference(green), {
    status: 'incomplete',
    code: 'LIFECYCLE_NOT_PROVEN',
    confidence: 'deterministic',
    summary: 'both package managers exited successfully but exact package lifecycle hooks were not proven in both arms',
    evidence: ['expectedLifecyclePackages=1', 'incompleteArms=2'],
  });
});

test('failure excerpts remove credentials and machine roots before fingerprinting', () => {
  const error = firstErrorFrom('Error: /tmp/run failed at https://u:secret@example.test/x', { project: '/tmp/run' });
  assert.doesNotMatch(JSON.stringify(error), /secret|\/tmp\/run/);
  assert.match(error.summary, /<PROJECT>/);
});

test('Windows short-path aliases and attempt ids do not destabilize failure fingerprints', () => {
  const first = firstErrorFrom(
    String.raw`C:\Users\runneradmin\AppData\Local\Temp\nub-reference-ABC123\attempts\nub-1\project\src\addon.cc(4,2): error C2665: no overload`,
    { project: String.raw`C:\Users\RUNNER~1\AppData\Local\Temp\nub-reference-ABC123\attempts\nub-1\project` },
  );
  const second = firstErrorFrom(
    String.raw`C:\Users\runneradmin\AppData\Local\Temp\nub-reference-ZYX987\attempts\nub-3\project\src\addon.cc(4,2): error C2665: no overload`,
    { project: String.raw`C:\Users\RUNNER~1\AppData\Local\Temp\nub-reference-ZYX987\attempts\nub-3\project` },
  );
  assert.equal(first.summary, String.raw`<PROJECT>\src\addon.cc(4,2): error C2665: no overload`);
  assert.equal(first.fingerprint, second.fingerprint);
  assert.doesNotMatch(JSON.stringify(first), /runneradmin|nub-reference|nub-1/i);
});

test('incidental codes outside the causal excerpt do not make identical failures unstable', () => {
  const clean = firstErrorFrom("Error: spawn EINVAL\nnpm error command failed");
  const cleanupNoise = firstErrorFrom("npm warn cleanup EPERM unlink cache\nError: spawn EINVAL\nnpm error command failed");
  assert.equal(clean.fingerprint, cleanupNoise.fingerprint);
  assert.deepEqual(clean.codes, cleanupNoise.codes);
});

test('causal diagnostics outrank package-manager wrappers and remain in the compact record', () => {
  const error = firstErrorFrom(`npm error code 2
npm error command failed
gyp ERR! configure error
Package pixman-1 was not found in the pkg-config search path.
Package 'pixman-1', required by 'virtual:world', not found`);
  assert.equal(error.summary, "Package 'pixman-1', required by 'virtual:world', not found");
  assert.ok(error.excerpts.includes('gyp ERR! configure error'));
  assert.ok(error.excerpts.some((line) => /pkg-config search path/.test(line)));

  const make = firstErrorFrom(`failed to download/install Redis binaries. The error: Error: Command failed: make
deps/readies/mk/main:6: *** GNU Make version is too old. Aborting.. Stop.
make: *** [build] Error 1`);
  assert.match(make.summary, /GNU Make version is too old/);
  assert.equal(classifyReference(record(arm('consistent-failure', make.summary),
    arm('consistent-failure', make.summary))).code, 'TOOLCHAIN_PREREQUISITE');

  const libtool = firstErrorFrom(`failed to download/install Redis binaries
Makefile.am:161: error: Libtool library used but 'LIBTOOL' is undefined
autoreconf: error: automake failed with exit status: 1`);
  assert.equal(libtool.summary, "Makefile.am:161: error: Libtool library used but 'LIBTOOL' is undefined");
  assert.equal(classifyReference(record(arm('consistent-failure', libtool.summary),
    arm('consistent-failure', libtool.summary))).code, 'TOOLCHAIN_PREREQUISITE');
});

test('current stratified failures resolve to durable remediation classes from causal excerpts', () => {
  const cases = [
    ["npm error code 127\nsh: 1: husky: not found", { devDependencies: ['husky'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ["error TS5083: Cannot read file '/work/node_modules/tsconfig.json'", {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ['ReferenceError: primordials is not defined', { engines: { node: '>=0.10.0' } },
      'OBSOLETE_NATIVE_ASSUMPTION'],
    ["gyp ERR! configure error\nPackage 'pixman-1', required by 'virtual:world', not found", {},
      'SYSTEM_LIBRARY_PREREQUISITE'],
    [String.raw`C:\work\canvas\Backend.h(3,10): error C1083: Cannot open include file: 'cairo.h': No such file or directory`, {},
      'SYSTEM_LIBRARY_PREREQUISITE'],
    ['failed to download/install Redis binaries. The error: Error: Status Code is 404', {},
      'EXTERNAL_ARTIFACT_UNAVAILABLE'],
    ["make: *** No rule to make target 'Release/obj.target/addon/src/bindings/addon.o'", {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    [String.raw`C:\work\node-liblzma.cpp(1,1): error C1083: Cannot open source file: '..\src\bindings\node-liblzma.cpp': No such file or directory`, {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ["gyp ERR! stack SyntaxError: Missing parentheses in call to 'print'", {},
      'OBSOLETE_PYTHON_ASSUMPTION'],
    ['sh: tsc: command not found', {}, 'UNDECLARED_EXTERNAL_TOOL_REQUIRED'],
    ["'tsc' is not recognized as an internal or external command", {},
      'UNDECLARED_EXTERNAL_TOOL_REQUIRED'],
    ["'husky' is not recognized as an internal or external command", { devDependencies: ['husky'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ["TypeError: 'process.env' only accepts a configurable, writable, and enumerable data descriptor", {},
      'OBSOLETE_NATIVE_ASSUMPTION'],
    ['Error: spawn EINVAL\nat build (node_modules/fibers/build.js:62:5)', {},
      'OBSOLETE_NATIVE_ASSUMPTION'],
  ];
  for (const [message, metadata, code] of cases) {
    const classified = classifyReference(record(arm('consistent-failure', message),
      arm('consistent-failure', message), { packageMetadata: metadata }));
    assert.equal(classified.code, code, message);
  }
});

test('compiler errors outrank warnings and classify native ABI incompatibility', () => {
  const message = `./src/addon.cc:12:3: warning: incompatible function type
./src/addon.cc:27:65: error: no member named 'kFinalizer' in 'v8::WeakCallbackType'
gyp ERR! build error`;
  const error = firstErrorFrom(message);
  assert.match(error.summary, /error: no member named/);
  assert.equal(classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message))).code, 'OBSOLETE_NATIVE_ASSUMPTION');
});

test('MSVC compiler diagnostics in stdout outrank a generic node-gyp stderr wrapper', () => {
  const message = String.raw`C:\work\src\util\macros.lzz(150,35): error C2665: 'v8::ObjectTemplate::SetAccessor': no overloaded function could convert all the argument types
Previous IPDB not found, fall back to full compilation.
gyp ERR! build error
gyp ERR! stack Error: MSBuild.exe failed with exit code: 1`;
  const error = firstErrorFrom(message);
  assert.match(error.summary, /macros\.lzz\(150,35\): error C2665/);
  assert.equal(classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message))).code, 'OBSOLETE_NATIVE_ASSUMPTION');
});

test('a causal failure in one arm outranks the other arm generic toolchain wrapper', () => {
  const generic = arm('consistent-failure', 'gyp ERR! find VS could not find Visual Studio');
  const cases = [
    [String.raw`Backend.h(3,10): error C1083: Cannot open include file: 'cairo.h': No such file or directory`,
      'SYSTEM_LIBRARY_PREREQUISITE'],
    [String.raw`addon.cpp(1,1): error C1083: Cannot open source file: '..\src\addon.cpp': No such file or directory`,
      'PUBLISHED_SOURCE_PREREQUISITE'],
    [String.raw`conversions.cc(31,48): error C2661: 'v8::ArrayBuffer::New': no overloaded function takes 3 arguments`,
      'OBSOLETE_NATIVE_ASSUMPTION'],
  ];
  for (const [message, code] of cases) {
    assert.equal(classifyReference(record(arm('consistent-failure', message), generic)).code, code, message);
  }
});

test('generated-source compiler errors against V8 are native ABI incompatibilities', () => {
  const message = `./src/util/macros.lzz:150:35: error: no matching member function for call to 'SetAccessor'
recv->InstanceTemplate()->SetAccessor(
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/node/v8-template.h:1049:8: note: candidate function not viable`;
  assert.match(firstErrorFrom(message).excerpts.join('\n'), /v8-template/);
  assert.equal(classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message))).code, 'OBSOLETE_NATIVE_ASSUMPTION');
});

test('generic native-build wrappers remain unclassified without a causal diagnostic', () => {
  const classified = classifyReference(record(arm('consistent-failure', 'gyp ERR! build error'),
    arm('consistent-failure', 'gyp ERR! build error')));
  assert.equal(classified.code, 'UNCLASSIFIED');
});

test('Nub accepting a required npm-rejected platform constraint is an expected pnpm policy differential', () => {
  const classified = classifyReference(record(arm('pass'),
    arm('consistent-failure', 'npm error code EBADPLATFORM'), {
      packageMetadata: { os: ['linux'], cpu: ['arm64'] },
    }));
  assert.equal(classified.code, 'REQUIRED_PLATFORM_POLICY_DIFFERENTIAL');
  assert.match(classified.summary, /follows pnpm/);
});

test('Node module errors outrank deprecation warnings and source snippets', () => {
  const error = firstErrorFrom(`npm warn deprecated old package\n  throw err;\nError: Cannot find module '/project/node_modules/a/scripts/install.js'\n  code: 'MODULE_NOT_FOUND'`,
    { project: '/project' });
  assert.equal(error.summary, "Error: Cannot find module '<PROJECT>/node_modules/a/scripts/install.js'");
  assert.ok(error.codes.includes('MODULE_NOT_FOUND'));
});

test('both managers missing a package lifecycle file is a permanent package failure', () => {
  const message = "Error: Cannot find module '/project/node_modules/a/scripts/install.js' MODULE_NOT_FOUND";
  assert.equal(classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message))).code, 'PACKAGE_BROKEN_OR_UNAVAILABLE');
});

test('a passing resolved tree with no install hooks is a terminal population exclusion', () => {
  const green = record(arm('pass'), arm('pass'));
  green.lifecycle.expectedCount = 0;
  green.arms.nubUnjailed.lifecycle.expectedCount = 0;
  green.arms.npmUnjailed.lifecycle.expectedCount = 0;
  assert.equal(classifyReference(green).code, 'NO_LIFECYCLE_SCRIPT');
  assert.equal(classifyReference(green).status, 'classified');
});
