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

  const resolverThenTimeout = classifyReference(record(
    arm('consistent-failure', 'ERR_NUB_PEER_CONTEXT_NOT_CONVERGED'),
    arm('timeout', 'REFERENCE-DEADLINE-REACHED'),
  ));
  assert.equal(resolverThenTimeout.code, 'REFERENCE_TIMEOUT');
  assert.equal(resolverThenTimeout.status, 'incomplete');
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
    ['make[2]: *** [Makefile:255: verify-deps] Error 1', 'TOOLCHAIN_PREREQUISITE'],
    ['RangeError [ERR_CHILD_PROCESS_STDIO_MAXBUFFER]: stderr maxBuffer length exceeded',
      'PUBLISHED_INSTALLER_OUTPUT_LIMIT'],
    ["error: rustup could not choose a version of cargo to run, because one wasn't specified explicitly, and no default is configured.",
      'TOOLCHAIN_PREREQUISITE'],
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

test('clock prefixes written by build tools do not manufacture unstable fingerprints', () => {
  const first = firstErrorFrom('[12:02:55] Local modules not found in <PROJECT>/node_modules/pkg');
  const second = firstErrorFrom('[12:03:19] Local modules not found in <PROJECT>/node_modules/pkg');
  assert.equal(first.summary, 'Local modules not found in <PROJECT>/node_modules/pkg');
  assert.equal(first.fingerprint, second.fingerprint);
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

  const dependencyCheck = firstErrorFrom(`failed to download/install Redis binaries
make[2]: *** [Makefile:255: verify-deps] Error 1
make: *** [Makefile:109: build] Error 1`);
  assert.equal(dependencyCheck.summary, 'make[2]: *** [Makefile:255: verify-deps] Error 1');
  assert.equal(classifyReference(record(arm('consistent-failure', dependencyCheck.summary),
    arm('consistent-failure', dependencyCheck.summary))).code, 'TOOLCHAIN_PREREQUISITE');

  const sourcePinnedRust = firstErrorFrom(`info: syncing channel updates for '1.94.0-x86_64-unknown-linux-gnu'
info: downloading 6 components
make[2]: *** [Makefile:251: build] Error 1
make[1]: *** [modules/common.mk:80: /tmp/redisearch.so] Error 2
make: *** [Makefile:109: build] Error 1`);
  assert.equal(sourcePinnedRust.summary, 'make[2]: *** [Makefile:251: build] Error 1');
  assert.match(sourcePinnedRust.excerpts.join('\n'), /syncing channel updates/);
  const rustEvidence = sourcePinnedRust.excerpts.join('\n');
  const classifiedRust = classifyReference(record(arm('consistent-failure', rustEvidence),
    arm('consistent-failure', rustEvidence)));
  assert.equal(classifiedRust.code, 'TOOLCHAIN_PREREQUISITE');
  assert.match(classifiedRust.summary, /source-pinned Rust toolchain/);

  const compiler = firstErrorFrom(`<CACHE>/node-gyp/include/node/v8.h:123:25: error: obsolete native API
gyp ERR! stack Error: make failed`);
  assert.match(compiler.summary, /v8\.h:123:25: error/);

  const minified = `esm/esm.js:1\n${'const TypeErrorAlias=global.TypeError;'.repeat(300)}\nnpm error command failed`;
  const compacted = firstErrorFrom(minified);
  assert.equal(compacted.summary, 'esm/esm.js:1');
  assert.ok(compacted.excerpts.every((line) => line.length <= 800));
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
    ['Error: spawn node-waf ENOENT', {}, 'OBSOLETE_NATIVE_ASSUMPTION'],
    ['Error: spawn runhaskell ENOENT', {}, 'UNDECLARED_EXTERNAL_TOOL_REQUIRED'],
    ['Error: unsupported target win32-x64', {}, 'OS_CPU_MISMATCH'],
    ['Error: Failed to find Electron v8.0.0 for darwin-arm64', {}, 'OS_CPU_MISMATCH'],
    ["error: SWIFT_VERSION '3.0' is unsupported, supported versions are: 4.0, 5.0, 6.0.", {},
      'OBSOLETE_XCODE_ASSUMPTION'],
    ["clang: error: SDK does not contain 'libarclite'; try increasing the minimum deployment target", {},
      'OBSOLETE_XCODE_ASSUMPTION'],
    ["error: Could not delete '/tmp/build' because it was not created by the build system.", {},
      'OBSOLETE_XCODE_ASSUMPTION'],
    ["source.c:398:20: error: size of array element isn't a multiple of its alignment", {},
      'OBSOLETE_NATIVE_ASSUMPTION'],
    ['Error: The git reference could not be found\nerror: pathspec 4.0 did not match', {},
      'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ['TypeError: DOMParser.parseFromString: the provided mimeType undefined is not valid.', {},
      'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ["Cannot find curl's header file.", {}, 'SYSTEM_LIBRARY_PREREQUISITE'],
    ["fatal error: 'lzma.h' file not found", {}, 'SYSTEM_LIBRARY_PREREQUISITE'],
    ["libtool is required, but wasn't found on this system", {}, 'TOOLCHAIN_PREREQUISITE'],
    ['CMake Error at CMakeLists.txt:1 (cmake_minimum_required):\nCompatibility with CMake < 3.5 has been removed from CMake.', {},
      'TOOLCHAIN_PREREQUISITE'],
    ['This project defines "packageManager": "yarn@4.10.3". The current global version of Yarn is 1.22.22.\nCorepack must currently be enabled.', {},
      'TOOLCHAIN_PREREQUISITE'],
    ['Cannot find cypress folder. Please scaffold Cypress folder by opening Cypress once.', {},
      'PROJECT_FIXTURE_PREREQUISITE'],
    ['if [ -z ${PUPPETEER_SKIP_CHROMIUM_DOWNLOAD+x} ]; then exit 1; fi', {},
      'ENVIRONMENT_PREREQUISITE'],
    ['403 status code downloading tarball https://example.test/addon.tar.gz', {},
      'EXTERNAL_ARTIFACT_UNAVAILABLE'],
    ['M1 Chip system with arm64 architecture is not supported. Please install x64 version of node.js.', {},
      'OS_CPU_MISMATCH'],
    ['node: bad option: --harmony_destructuring', {}, 'OBSOLETE_NODE_ASSUMPTION'],
    ["ENOENT: no such file or directory, open './package-lock.json'", {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ['sh: cd: docs: No such file or directory', {}, 'PUBLISHED_SOURCE_PREREQUISITE'],
    ['You can learn about all of the compiler options at https://aka.ms/tsc',
      { scripts: { postinstall: 'tsc -b' } }, 'PUBLISHED_SOURCE_PREREQUISITE'],
    ['Fatal error: Unable to find local grunt.', { devDependencies: ['grunt'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['/work/node_modules/.bin/gulp: not found', { devDependencies: ['gulp'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['@lavamoat/preinstall-always-fail refuses lifecycle execution', {},
      'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ['Error: figma-js must be installed with Yarn: https://yarnpkg.com/', {},
      'TOOLCHAIN_PREREQUISITE'],
    ['Error: Unsupported architecture arm64. Only x64 binaries are available.', {},
      'OS_CPU_MISMATCH'],
    ['dotnet-2.0.0-osx@1.0.5: The CPU architecture "arm64" is incompatible with this module.', {},
      'OS_CPU_MISMATCH'],
    ['Error: Playwright does not support chromium on mac15.7', {}, 'OS_CPU_MISMATCH'],
    ['Error: Request failed with status code 404', {}, 'EXTERNAL_ARTIFACT_UNAVAILABLE'],
    ['./build.sh: line 3: node-waf: command not found', {}, 'OBSOLETE_NATIVE_ASSUMPTION'],
    ["tsconfig.json(5,27): error TS5108: Option 'moduleResolution=node10' has been removed.", {},
      'OBSOLETE_TYPESCRIPT_ASSUMPTION'],
    ['Error: Patch file found for package hashes which is not present at node_modules/@noble/hashes', {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ["make: *** No rule to make target 'clean_closure'. Stop.", {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ["../src/liblzma-node.hpp:36:10: fatal error: lzma.h: No such file or directory", {},
      'SYSTEM_LIBRARY_PREREQUISITE'],
    ["gyp: Call to 'node /work/node-libcurl/tools/curl-config.js --cflags' returned exit status 1", {},
      'SYSTEM_LIBRARY_PREREQUISITE'],
    ['src/cdf.c:299:6: error: call to undeclared function lseek', {},
      'OBSOLETE_NATIVE_ASSUMPTION'],
    ["code: 'ERR_DLOPEN_FAILED'", {}, 'OBSOLETE_NATIVE_ASSUMPTION'],
    ['oracledb ERR! a pre-built node-oracledb binary was not found for darwin arm64', {},
      'OS_CPU_MISMATCH'],
    ['/work/node_modules/typings/dist/bin.js: not found', { devDependencies: ['typings'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['Installation failed: TypeError [ERR_INVALID_ARG_TYPE]: The "paths[0]" argument must be of type string. Received undefined', {},
      'PACKAGE_BROKEN_OR_UNAVAILABLE'],
    ['Unfortunately, there are currently no Elm Platform binaries available for your operating system and architecture.', {},
      'OS_CPU_MISMATCH'],
    ['Unsupported (?) architecture: `arm64`', {}, 'OS_CPU_MISMATCH'],
    [String.raw`File: C:\work\node_modules\node-libcurl\deps\curl-for-windows\libssh2.gyp not found.`, {},
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ["sh: 1: cd: can't cd to docs/storybook", {}, 'PUBLISHED_SOURCE_PREREQUISITE'],
    ['bash: ./scripts/postinstall.sh: No such file or directory', {}, 'PUBLISHED_SOURCE_PREREQUISITE'],
    ['tsc: The TypeScript Compiler - Version 7.0.2', { devDependencies: ['typescript'] },
      'PUBLISHED_SOURCE_PREREQUISITE'],
    ['sh: ./node_modules/.bin/bower: No such file or directory', { devDependencies: ['bower'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['Local modules not found in <PROJECT>/node_modules/pkg', { devDependencies: ['gulp'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['sh: scripts/postinstall.mts: Permission denied', {}, 'PUBLISHED_SCRIPT_NOT_EXECUTABLE'],
    ['ERR! bootstrap The "bootstrap" command was removed by default in v7', { devDependencies: ['lerna'] },
      'PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY'],
    ['Error: Refusing to load formula facebook/fb/fbsimctl from untrusted tap facebook/fb.', {},
      'TOOLCHAIN_PREREQUISITE'],
    ['`git-win` not support this platform, please install from Windows.', {}, 'OS_CPU_MISMATCH'],
    ['/work/node_modules/esm/esm.js:1', { dependencies: ['esm'] }, 'OBSOLETE_NODE_ASSUMPTION'],
    ['ERROR peer-context hit MAX_ITERATIONS=16 without convergence code=ERR_NUB_PEER_CONTEXT_NOT_CONVERGED', {},
      'NUB_PM_RESOLVER_DEFECT'],
  ];
  for (const [message, metadata, code] of cases) {
    const classified = classifyReference(record(arm('consistent-failure', message),
      arm('consistent-failure', message), { packageMetadata: metadata }));
    assert.equal(classified.code, code, message);
  }
});

test('an unstable retry with one durable cause is classified before the instability fallback', () => {
  const unstable = arm('unstable', "ENOENT: no such file or directory, open './package-lock.json'");
  assert.equal(classifyReference(record(unstable, structuredClone(unstable))).code,
    'PUBLISHED_SOURCE_PREREQUISITE');
  const opaque = arm('unstable', 'Error: varying opaque wrapper');
  const classification = classifyReference(record(opaque, structuredClone(opaque)));
  assert.equal(classification.code, 'UNSTABLE_REFERENCE');
  assert.equal(classification.status, 'incomplete');
});

test('published lifecycle mistakes are separated from missing host tools', () => {
  const windows = record(
    arm('consistent-failure', '-f was unexpected at this time.'),
    arm('consistent-failure', '-f was unexpected at this time.'),
  );
  windows.provenance.runtime.os.platform = 'win32';
  assert.equal(classifyReference(windows).code, 'PUBLISHED_SCRIPT_PLATFORM_ASSUMPTION');

  const recursion = record(arm('consistent-failure', 'error Command failed with exit code 1.'),
    arm('consistent-failure', 'error Command failed with exit code 1.'), {
      packageMetadata: { scripts: { install: 'yarn install' } },
    });
  assert.equal(classifyReference(recursion).code, 'PUBLISHED_SCRIPT_RECURSION');

  const chromedriver = record(
    arm('consistent-failure', "Download failed: ENOENT: no such file or directory, chmod '/work/chromedriver'"),
    arm('consistent-failure', "Download failed: ENOENT: no such file or directory, chmod '/work/chromedriver'"),
    { pkg: 'electron-chromedriver' },
  );
  chromedriver.provenance.runtime.os.platform = 'darwin';
  chromedriver.provenance.runtime.os.arch = 'arm64';
  assert.equal(classifyReference(chromedriver).code, 'OS_CPU_MISMATCH');
});

test('causal compaction retains prefixed runtime errors and Visual Studio discovery failures', () => {
  const parser = firstErrorFrom('ERR! CDInstaller TypeError: DOMParser.parseFromString: invalid mime type\nnpm error command failed');
  assert.match(parser.summary, /TypeError: DOMParser/);
  const visualStudio = firstErrorFrom('Error: Command failed: node-gyp\ngyp ERR! find VS Could not find any Visual Studio installation to use');
  assert.match(visualStudio.summary, /Could not find any Visual Studio/);
  assert.match(firstErrorFrom('npm error command failed\n* * THIS PACKAGE WAS RENAMED! * *').summary,
    /PACKAGE WAS RENAMED/);
  assert.match(firstErrorFrom('source.c:434:5: error: size of array element is not a multiple of its alignment\nmake[3]: *** [target] Error 1').summary,
    /size of array element/);
  const xcodeA = firstErrorFrom("error: Could not delete '/tmp/one/EarlGrey/build' because it was not created by the build system.");
  const xcodeB = firstErrorFrom('error: Could not delete `/tmp/two/SocketRocket/build` because it was not created by the build system.');
  assert.equal(xcodeA.summary, 'error: Could not delete <BUILD_DIR> because it was not created by the build system.');
  assert.equal(xcodeA.fingerprint, xcodeB.fingerprint);
});

test('classifier evidence includes bounded auxiliary logs written outside process stdio', () => {
  const both = record(arm('consistent-failure', 'Error: opaque lifecycle wrapper'),
    arm('consistent-failure', 'Error: opaque lifecycle wrapper'));
  for (const attempt of [both.arms.nubUnjailed.attempts[0], both.arms.npmUnjailed.attempts[0]]) {
    attempt.auxiliaryLogs = { files: [{ error: firstErrorFrom(
      "src/addon.cc:4:2: error: no member named 'OldApi' in namespace 'v8'",
    ) }] };
  }
  assert.equal(classifyReference(both).code, 'OBSOLETE_NATIVE_ASSUMPTION');

  const cacheOnly = record(arm('consistent-failure', 'Error: opaque lifecycle wrapper'),
    arm('consistent-failure', 'Error: opaque lifecycle wrapper'));
  for (const attempt of [cacheOnly.arms.nubUnjailed.attempts[0], cacheOnly.arms.npmUnjailed.attempts[0]]) {
    attempt.auxiliaryLogs = { files: [{ sourceRoot: 'npmCache', error: firstErrorFrom(
      'npm error code E404\nnpm error package not found',
    ) }] };
  }
  assert.equal(classifyReference(cacheOnly).code, 'UNCLASSIFIED');
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

test('interleaved configure probes expose a published native build race instead of a missing host tool', () => {
  const message = `configure:7321: checking for a sed that does not truncate output
configure:7385: result: /usr/bin/sed
configure:7378: error: no acceptable sed could be found in $PATH`;
  const error = firstErrorFrom(message);
  assert.match(error.summary, /no acceptable sed/);
  assert.match(error.excerpts.join('\n'), /result: \/usr\/bin\/sed/);
  const classified = classifyReference(record(arm('consistent-failure', message),
    arm('consistent-failure', message)));
  assert.equal(classified.code, 'OBSOLETE_NATIVE_ASSUMPTION');
  assert.match(classified.summary, /concurrent native configure probes/);
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
