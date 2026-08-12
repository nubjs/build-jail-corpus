import crypto from 'node:crypto';
import fs from 'node:fs';
import { satisfiesNodeRange } from './node-range.mjs';

const stripAnsi = (value) => String(value ?? '').replace(/\x1b\[[0-9;]*m/g, '');
const regexEscape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function sanitizeFailureText(value, roots = {}) {
  let text = stripAnsi(value).replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/g, 'https://<credentials>@');
  for (const [name, root] of Object.entries(roots)) {
    if (!root) continue;
    const aliases = new Set([String(root)]);
    try { aliases.add(fs.realpathSync(String(root))); } catch { /* path may no longer exist */ }
    for (const alias of [...aliases].sort((a, b) => b.length - a.length)) {
      const flags = /^[A-Za-z]:[\\/]/.test(alias) ? 'gi' : 'g';
      const placeholder = name.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();
      text = text.replace(new RegExp(regexEscape(alias), flags), `<${placeholder}>`);
    }
  }
  const scratchNames = {
    project: 'PROJECT', home: 'HOME', tmp: 'TEMP', cache: 'CACHE', config: 'CONFIG', 'npm-cache': 'NPM_CACHE',
  };
  text = text.replace(
    /[A-Za-z]:[\\/][^\r\n]*?[\\/]nub-reference-[A-Za-z0-9_-]+[\\/]attempts[\\/](?:nub|npm)-\d+[\\/](project|home|tmp|cache|config|npm-cache)/gi,
    (_, name) => `<${scratchNames[name.toLowerCase()]}>`,
  );
  text = text.replace(
    /(error: Could not delete )[`'"]?[^\r\n]+?[`'"]?( because it was not created by the build system\.?)/gi,
    '$1<BUILD_DIR>$2',
  );
  text = text.replace(/^\[\d{2}:\d{2}:\d{2}\]\s*/gm, '');
  return text;
}

export function firstErrorFrom(output, roots = {}) {
  const text = sanitizeFailureText(output, roots);
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const useful = lines.filter((line) => !/^(?:npm )?warn(?:ing)?\b|^throw err;?$|^\^$|complete log of this run/i.test(line));
  const rank = (line) => {
    if (/\bwarning:/i.test(line)) return 0;
    if (line.length > 4096 && !/^(?:Error|TypeError|RangeError|ReferenceError|SyntaxError):\s+/i.test(line)) return 0;
    if (/^configure:\d+: error: no acceptable sed could be found in \$PATH/i.test(line)) return 101;
    if (/^configure:\d+: result: \/usr\/bin\/sed\b/i.test(line)
      || /^sed: conftest\.c: No such file or directory$/i.test(line)) return 100;
    if (/\b(?:TypeError|RangeError|ReferenceError|SyntaxError):\s+/i.test(line)
      || /^Error: Cannot (?:find module|read file)/i.test(line)) return 100;
    if (/^(?:CMake|configure) Error\b|^configure: error:|\b(?:is not supported|not supported on|no .*binaries?.*available|unsupported architecture|installation is not supported|cannot install).*(?:arm64|x64|platform|architecture)?/i.test(line)) return 99;
    if (/^(?:(?:clang|swiftc|xcodebuild): (?:fatal )?error:|error: (?:SWIFT_VERSION|Could not delete))\s+/i.test(line)) return 99;
    if (/\b(?:error TS\d+|fatal error:|MODULE_NOT_FOUND|Missing parentheses in call to ['"]print['"])/i.test(line)
      || /\(\d+(?:,\d+)?\):\s+(?:fatal )?error\s+[A-Z]+\d*:/i.test(line)) return 98;
    if (/THIS PACKAGE WAS RENAMED/i.test(line)) return 98;
    if (/GNU Make version is too old/i.test(line)
      || /^make(?:\[\d+\])?: \*\*\* \[[^\]]*verify-deps[^\]]*\] Error/i.test(line)) return 97;
    if (/Could not find any Visual Studio|gyp ERR! find VS/i.test(line)) return 97;
    if (/\b(?:Cannot read file|Cannot find module|Cannot find .+ folder|Package ['"].+['"].*not found|No rule to make target|command not found|not found: command|No such file|Permission denied|can't cd to|Local modules not found|Status Code is 4\d\d|libtool is required|must be installed with Yarn|incorrect header check)\b/i.test(line)
      || /^The system cannot find the path specified\.?$/i.test(line)
      || /^tsc: The TypeScript Compiler\b/i.test(line)) return 96;
    if (/^[A-Za-z0-9_.@+-]+(?:[/\\][^:\r\n]+)*:\d+(?::\d+)?:\s+(?:fatal )?error:/i.test(line)) return 98;
    if (/^(?:<[^>]+>|\.{0,2}[/\\]|[/\\]).*:\d+(?::\d+)?:\s+(?:fatal )?error:/i.test(line)) return 98;
    if (/(?:^|[/\\])esm[/\\]esm\.js:1$/i.test(line)) return 97;
    if (/^make\[\d+\]: \*\*\* \[[^\]]+\] Error/i.test(line)) return 95;
    if (/^(?:make: \*\*\*|gyp: Call to|failed to download\/install)\b/i.test(line)) return 92;
    if (/^Error:\s+/i.test(line)) return 90;
    if (/\b(?:ERR_[A-Z0-9_]+|EACCES|ENOENT|ETIMEDOUT|ECONNRESET|EAI_AGAIN|EBADPLATFORM)\b/.test(line)) return 85;
    if (/(?:failed|exception|not found|unsupported|incompatible|403|404|410)\b/i.test(line)) return 75;
    if (/^(?:npm (?:error|ERR!)|gyp ERR!|node-pre-gyp ERR!|fatal:)\s+/i.test(line)) return 40;
    return 0;
  };
  const ranked = useful.map((line, index) => ({ line, index, rank: rank(line) }))
    .filter((entry) => entry.rank > 0)
    .sort((a, b) => b.rank - a.rank || a.index - b.index);
  const summary = (ranked[0]?.line ?? useful.at(-1) ?? 'process exited without diagnostic output').slice(0, 800);
  const selected = new Set([summary]);
  for (const entry of ranked) {
    if (selected.size >= 12) break;
    for (let index = Math.max(0, entry.index - 3); index <= Math.min(useful.length - 1, entry.index + 3); index += 1) {
      selected.add(useful[index].slice(0, 800));
      if (selected.size >= 12) break;
    }
  }
  const excerpts = useful.filter((line) => selected.has(line.slice(0, 800)))
    .map((line) => line.slice(0, 800)).filter((line, index, all) => all.indexOf(line) === index);
  const causalText = [summary, ...excerpts].join('\n');
  const codes = [...new Set(causalText.match(/\b(?:ERR_[A-Z0-9_]+|MODULE_NOT_FOUND|E(?:ACCES|AI_AGAIN|CONNREFUSED|CONNRESET|HOSTUNREACH|NETUNREACH|NOENT|NOTFOUND|PERM|PIPE|PROTO|TIMEDOUT|TARGET|BADPLATFORM)|HTTP\s+[45]\d\d)\b/gi) ?? [])]
    .map((code) => code.toUpperCase()).sort();
  return {
    summary,
    excerpts,
    codes,
    fingerprint: crypto.createHash('sha256').update(`${summary}\n${codes.join(',')}\n`).digest('hex'),
  };
}

const listAllows = (value, list) => {
  if (list == null) return null;
  const entries = (Array.isArray(list) ? list : [list]).filter((entry) => typeof entry === 'string');
  if (!entries.length) return null;
  const denied = new Set(entries.filter((entry) => entry.startsWith('!')).map((entry) => entry.slice(1)));
  if (denied.has(value)) return false;
  const allowed = entries.filter((entry) => !entry.startsWith('!'));
  return allowed.length ? allowed.includes(value) : true;
};

const allFailureText = (record) => Object.values(record.arms ?? {}).flatMap((arm) => arm.attempts ?? [])
  .flatMap((attempt) => [...Object.values(attempt.stages ?? {}),
    ...(attempt.auxiliaryLogs?.files ?? []).filter((file) => file.sourceRoot !== 'npmCache')])
  .flatMap((source) => [source?.error?.summary, ...(source?.error?.excerpts ?? [])])
  .filter(Boolean).join('\n');

const eventuallyPassed = (arm) => ['pass', 'pass-after-failure'].includes(arm?.quorum?.outcome);
const refused = (arm) => arm?.quorum?.outcome === 'refused-malicious';
const harnessFailed = (arm) => arm?.quorum?.outcome === 'harness-error';

const result = (code, confidence, summary, evidence = [], status = 'classified') => ({
  status, code, confidence, summary, evidence,
});

export function classifyReference(record) {
  const nub = record.arms?.nubUnjailed;
  const npm = record.arms?.npmUnjailed;
  const metadata = record.packageMetadata ?? nub?.packageMetadata ?? npm?.packageMetadata ?? {};
  const nodeVersion = record.provenance?.runtime?.node?.version ?? process.version;
  const platform = record.provenance?.runtime?.os?.platform ?? process.platform;
  const arch = record.provenance?.runtime?.os?.arch ?? process.arch;
  const libc = record.provenance?.runtime?.os?.libc?.family ?? null;
  const text = allFailureText(record);
  const osAllowed = listAllows(platform, metadata.os);
  const cpuAllowed = listAllows(arch, metadata.cpu);
  const libcAllowed = libc ? listAllows(libc, metadata.libc) : null;
  const platformMismatch = osAllowed === false || cpuAllowed === false || libcAllowed === false;

  if (record.security?.status === 'refused-malicious' || refused(nub) || refused(npm)) {
    return result('REFUSED_MALICIOUS', 'deterministic', 'OSV refused the direct package or a resolved dependency tree',
      ['security.status=refused-malicious']);
  }
  if (record.status === 'harness-error' || harnessFailed(nub) || harnessFailed(npm)) {
    return result('HARNESS_INTERNAL', 'deterministic', 'the probe did not produce two terminal reference outcomes',
      [nub?.quorum?.outcome, npm?.quorum?.outcome].filter(Boolean), 'incomplete');
  }

  if ([nub?.quorum?.outcome, npm?.quorum?.outcome].includes('timeout')) {
    return result('REFERENCE_TIMEOUT', 'bounded',
      'a reference arm did not finish within the recorded process or batch deadline',
      [nub?.quorum?.outcome, npm?.quorum?.outcome].filter(Boolean), 'incomplete');
  }
  if (/ERR_NUB_PEER_CONTEXT_NOT_CONVERGED/i.test(text)) {
    return result('NUB_PM_RESOLVER_DEFECT', 'deterministic',
      'Nub exhausted its peer-context resolver before it could run the package lifecycle',
      ['ERR_NUB_PEER_CONTEXT_NOT_CONVERGED']);
  }

  if (/unknown key `buildJail`|ERR_NUB_LOCKFILE_AMBIGUOUS/i.test(text)) {
    return result('HARNESS_INTERNAL', 'deterministic',
      'the selected Nub binary or fixture root cannot engage the declared reference configuration',
      [/buildJail/i.test(text) ? 'unsupported Nub binary' : 'ambient lockfile contamination'], 'incomplete');
  }

  if (nub?.quorum?.outcome === 'invalid-tree' && npm?.quorum?.outcome === 'invalid-tree') {
    return result('HARNESS_INTERNAL', 'deterministic',
      'neither clean preflight installed the exact requested package version',
      [nub.quorum.fingerprint, npm.quorum.fingerprint].filter(Boolean), 'incomplete');
  }

  const quorumOutcomes = [nub?.quorum?.outcome, npm?.quorum?.outcome];
  const recovered = quorumOutcomes.includes('pass-after-failure');
  const transientSignature = /ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket hang up|network timeout|HTTP\s+429|HTTP\s+5\d\d|TLS handshake|invalid central directory file header|incorrect header check/i.test(text);
  if (eventuallyPassed(nub) && eventuallyPassed(npm)) {
    if (recovered) {
      return result('TRANSIENT_EXTERNAL_DOWNLOAD', 'retry',
        'an external download failed transiently or changed outcome across clean retries',
        quorumOutcomes.filter(Boolean));
    }
    const expected = record.lifecycle?.expectedCount ?? 0;
    const incompleteArms = [nub, npm].filter((arm) => (arm.lifecycle?.expectedCount ?? 0) === 0
      || (arm.lifecycle?.provenCount ?? 0) !== arm.lifecycle?.expectedCount);
    if (expected === 0) {
      return result('NO_LIFECYCLE_SCRIPT', 'deterministic',
        'ordinary installs pass and neither resolved tree contains an install lifecycle hook',
        ['expectedLifecyclePackages=0']);
    }
    if (incompleteArms.length) {
      return result('LIFECYCLE_NOT_PROVEN', 'deterministic',
        'both package managers exited successfully but exact package lifecycle hooks were not proven in both arms',
        [`expectedLifecyclePackages=${expected}`, `incompleteArms=${incompleteArms.length}`], 'incomplete');
    }
    return result('REFERENCE_PASSES', 'deterministic', 'ordinary unjailed installs pass through both Nub and npm',
      ['nub=pass', 'npm=pass']);
  }
  if (eventuallyPassed(npm) && !eventuallyPassed(nub)) {
    if (/uses exotic specifier[\s\S]*blocked by\s*blockExoticSubdeps|blocked exotic transitive dependency|ERR_(?:NUB|AUBE)_BLOCKED_EXOTIC_SUBDEP/i.test(text)) {
      return result('EXOTIC_SUBDEP_POLICY_DIFFERENTIAL', 'differential',
        'Nub follows pnpm by blocking an exotic transitive dependency that npm permits',
        ['blockExoticSubdeps=true', 'npm=pass']);
    }
    if (platform === 'win32'
      && /paths\[0\].*must be of type string[\s\S]*Received (?:null|undefined)/i.test(text)
      && /(?:getInstallationPath[\s\S]*go-ios|go-npm[\\/]bin[\\/]index\.js)/i.test(text)) {
      return result('NPM_GLOBAL_PREFIX_ASSUMPTION', 'signature',
        'the published Windows lifecycle requires npm\'s user-global prefix, which pnpm-compatible managers do not export',
        ['platform=win32', 'npm_config_prefix=required', 'npm=pass']);
    }
    if ((/POSTINSTALL FAILED: If using npm v2, please upgrade to npm v3/i.test(text)
      && /(?:Cannot find module|not found|can't cd to).*(?:node_modules|\blib\b)/i.test(text))
      || /\[builder:local-detect\] Error importing local builder: Cannot find module .*node_modules[/\\][^\r\n]+[/\\]node_modules[/\\]builder[/\\]bin[/\\]builder-core\.js/i.test(text)) {
      return result('NPM_FLAT_TREE_ASSUMPTION', 'signature',
        'the published lifecycle requires npm-era flattened dependency layout that pnpm-compatible managers do not provide',
        ['package-script=npm-v3-layout', 'npm=pass']);
    }
    if (transientSignature) {
      return result('TRANSIENT_EXTERNAL_DOWNLOAD', 'retry',
        'an external download failed transiently or changed outcome across clean retries',
        quorumOutcomes.filter(Boolean));
    }
    return result('NUB_PM_DIVERGENCE', 'differential', 'npm passes while unjailed Nub fails on the same fixture and runtime',
      [nub?.quorum?.fingerprint, 'npm=pass'].filter(Boolean));
  }
  if (eventuallyPassed(nub) && !eventuallyPassed(npm)) {
    if (platformMismatch && /EBADPLATFORM|not compatible with your operating system|Unsupported platform/i.test(text)) {
      return result('REQUIRED_PLATFORM_POLICY_DIFFERENTIAL', 'differential',
        'Nub follows pnpm by accepting a required package that npm rejects under its published platform constraints',
        [`os=${platform}`, `cpu=${arch}`, `package.os=${JSON.stringify(metadata.os ?? null)}`,
          `package.cpu=${JSON.stringify(metadata.cpu ?? null)}`, `libc=${libc}`,
          `package.libc=${JSON.stringify(metadata.libc ?? null)}`]);
    }
    return result('NPM_PM_DIVERGENCE', 'differential', 'unjailed Nub passes while npm fails on the same fixture and runtime',
      ['nub=pass', npm?.quorum?.fingerprint].filter(Boolean));
  }

  if (quorumOutcomes.includes('transient') || transientSignature) {
    return result('TRANSIENT_EXTERNAL_DOWNLOAD', 'retry', 'an external download failed transiently or changed outcome across clean retries',
      quorumOutcomes.filter(Boolean));
  }

  const engineRange = metadata.engines?.node;
  const engineMatch = typeof engineRange === 'string' ? satisfiesNodeRange(nodeVersion, engineRange) : null;
  if (engineMatch === false) {
    return result('INCOMPATIBLE_NODE', 'metadata', `the package declares Node ${engineRange}, not ${nodeVersion}`,
      [`engines.node=${engineRange}`, `node=${nodeVersion}`]);
  }
  if (platformMismatch
    || /EBADPLATFORM|not compatible with your operating system|Unsupported platform|unsupported target (?:win32|darwin|linux)-/i.test(text)
    || /Failed to find Electron .+ for darwin-arm64|(?:M1 Chip system with )?arm64 architecture is not supported|The CPU architecture .+ is incompatible with this module|Unsupported \(\?\) architecture: [`'"]?arm64|Unsupported architecture arm64|Installation is not supported for this architecture|(?:no|unable to find) .*binaries?.*(?:platform|operating system|architecture|darwin|arm64)|cannot install.*(?:arm64|architecture)|Only x64 binaries are available|does not support chromium on mac|pre-built .+ binary was not found for darwin arm64|RELATIVE_EXECUTABLE_PATHS\[browser\]\[platform\].*undefined|`git-win` not support this platform/i.test(text)
    || (arch === 'arm64' && record.pkg === 'electron-chromedriver'
      && /Download failed: ENOENT: no such file or directory, chmod .*chromedriver/i.test(text))) {
    return result('OS_CPU_MISMATCH', osAllowed === false || cpuAllowed === false || libcAllowed === false
      ? 'metadata' : 'signature',
      'the package excludes this operating-system, CPU, or libc cell',
      [`os=${platform}`, `cpu=${arch}`, `package.os=${JSON.stringify(metadata.os ?? null)}`,
        `package.cpu=${JSON.stringify(metadata.cpu ?? null)}`, `libc=${libc}`,
        `package.libc=${JSON.stringify(metadata.libc ?? null)}`]);
  }

  if (/invalid mode: ['"]rU['"]|Missing parentheses in call to ['"]print['"]/i.test(text)) {
    return result('OBSOLETE_PYTHON_ASSUMPTION', 'signature',
      'the package build chain requires Python 2 behavior that is obsolete in the supported toolchain profile',
      ['python=obsolete-behavior']);
  }
  if (/ERR_CHILD_PROCESS_STDIO_MAXBUFFER|(?:stdout|stderr) maxBuffer length exceeded/i.test(text)) {
    return result('PUBLISHED_INSTALLER_OUTPUT_LIMIT', 'signature',
      'the published lifecycle wrapper exceeded its child-process output buffer',
      ['node.child_process=maxBuffer']);
  }
  if (/GNU Make version is too old/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the build requires a newer GNU Make than the selected toolchain profile provides',
      ['tool=make', 'version=too-old']);
  }
  if (/make(?:\[\d+\])?: \*\*\* \[[^\]]*verify-deps[^\]]*\] Error/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the build dependency verification target rejected the selected toolchain profile',
      ['build-target=verify-deps']);
  }
  if (/info: syncing channel updates for ['"]?\d+\.\d+\.\d+/i.test(text)
    && /info: downloading \d+ components/i.test(text)
    && /make\[\d+\]: \*\*\* \[[^\]]*:\s*build\] Error/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the build attempted to provision a source-pinned Rust toolchain during the lifecycle and could not complete the module build',
      ['tool=rustup', 'source-pinned-toolchain=true']);
  }
  if (/Libtool library used but ['"]LIBTOOL['"] is undefined/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the Autotools build requires Libtool macros absent from the selected toolchain profile',
      ['tool=libtool']);
  }
  if (/libtool is required, but (?:it )?wasn't found/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the native build requires Libtool absent from the selected toolchain profile',
      ['tool=libtool']);
  }
  if (/Compatibility with CMake < [\d.]+ has been removed from CMake/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the published build requires a CMake compatibility policy absent from this profile',
      ['tool=cmake', 'compatibility-policy=required']);
  }
  if (/Corepack must currently be enabled/i.test(text)
    || (/packageManager['"]?:?\s*['"]?yarn@\d+|defines ['"]packageManager['"]: ['"]yarn@\d+/i.test(text)
      && /current global version of Yarn is/i.test(text))) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the lifecycle requires its declared modern Yarn release through Corepack',
      ['tool=corepack', 'package-manager=yarn']);
  }
  if (/must be installed with Yarn/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the lifecycle explicitly requires Yarn instead of the selected project tool profile',
      ['tool=yarn']);
  }
  if (/Refusing to load formula .+ from untrusted tap/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the lifecycle requires an explicitly trusted Homebrew tap absent from the selected profile',
      ['tool=homebrew', 'tap-trust=required']);
  }
  if (/rustup could not choose a version of cargo to run.*no default is configured/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature',
      'the native build requires a configured Rust toolchain absent from this profile',
      ['tool=rustup', 'default-toolchain=missing']);
  }
  if (/pkg-config.*(?:not found|exit status)|Package ['"].+['"].*not found|not found in the pkg-config search path|Cannot open include file: ['"](?:cairo\.h|pango(?:\/|\\)|pixman(?:\.h|-1)|jpeglib\.h|gif_lib\.h|librsvg(?:\/|\\)|lzma\.h|curl(?:\/|\\)|curl\.h)|fatal error: ['"]?(?:lzma\.h|curl(?:\/|\\)[^'"\s]+|curl\.h)['"]?\s*:?\s*(?:(?:file )?not found|No such file or directory)|Cannot find curl['’]s header file|node-libcurl[/\\]tools[/\\]curl-config\.js.*returned exit status 1|(?:cairo|pango|pixman|libjpeg|libgif|librsvg|libcurl|liblzma|xz).*development (?:files|package)/i.test(text)) {
    return result('SYSTEM_LIBRARY_PREREQUISITE', 'signature',
      'the native build expects a system development library absent from this profile',
      ['profile experiment required']);
  }
  const lifecycleScripts = Object.values(metadata.scripts ?? {}).filter((value) => typeof value === 'string').join('\n');
  if (/Cannot read file .*node_modules.*(?:tsconfig|lerna|rush|angular)\.json|error TS\d+: Cannot read file .*node_modules|No rule to make target .*node_modules.*(?:src|source)|No rule to make target .*[/\\](?:src|source)[/\\]|No rule to make target ['"`]clean_closure|Cannot open source file:.*(?:^|[/\\])(?:src|source)[/\\]|fatal error: ['"]config\.h['"] file not found|cannot find input file: [`'"]Doxyfile\.in|Patch file found for package .+ which is not present at node_modules|File:\s+.*node_modules.*(?:\.gyp|config\.h)\s+not found|ENOENT.*(?:node_modules.*)?(?:package-lock\.json|postinstall\.sh)|postinstall\.sh: not found|(?:^|\n).*cd:.*can't cd to|(?:^|\n).*(?:cd:|cp: cannot stat).*No such file|(?:^|\n).*(?:bash|sh): .*scripts[/\\][^\r\n]+: No such file|cp: node_modules[/\\][^\r\n]+: No such file/im.test(text)
    || (platform === 'win32' && /The system cannot find the path specified/i.test(text)
      && /(?:^|\n)>\s*cd\s+[^\r\n]+?\s*&&/im.test(text))
    || ((/\btsc(?:\s|$)/m.test(lifecycleScripts) || (metadata.devDependencies ?? []).includes('typescript'))
      && /(?:aka\.ms\/tsc|^tsc: The TypeScript Compiler\b)/im.test(text))) {
    return result('PUBLISHED_SOURCE_PREREQUISITE', 'signature',
      'the published lifecycle script expects source-tree configuration that is absent from the package tarball',
      ['published source/configuration missing']);
  }
  if (/SWIFT_VERSION ['"]?3\.0['"]? is unsupported|SDK does not contain ['"]libarclite['"]|Could not delete .+ because it was not created by the build system/i.test(text)) {
    return result('OBSOLETE_XCODE_ASSUMPTION', 'signature',
      'the published Apple build requires behavior removed from the supported Xcode toolchain',
      ['tool=xcode', 'package-build=obsolete']);
  }
  if (/configure:\d+: result: \/usr\/bin\/sed\b/i.test(text)
    && /configure:\d+: error: no acceptable sed could be found in \$PATH/i.test(text)) {
    return result('OBSOLETE_NATIVE_ASSUMPTION', 'signature',
      'concurrent native configure probes clobbered their shared work files after finding the required host tool',
      ['configure found /usr/bin/sed and concurrently reported no acceptable sed']);
  }
  if (/NODE_MODULE_VERSION|ERR_DLOPEN_FAILED|V8.*(?:has no member|was not declared)|error(?::|\s+[A-Z]+\d*:).*(?:\bv8::|SetAccessor|WeakCallbackType)|nan\.h.*(?:not found|error)|primordials is not defined|ERR_INVALID_OBJECT_DEFINE_PROPERTY|process\.env.*only accepts a configurable, writable, and enumerable data descriptor|Error: spawn EINVAL|spawn node-waf ENOENT|node-waf: (?:command )?not found|size of array element .*(?:is not|isn't) a multiple of its alignment|C\+\+.*error:|(?:^|\n).*(?:\.c|\.cc|\.cpp|\.h|\.lzz)(?::\d+(?::\d+)?|\(\d+(?:,\d+)?\)): (?:fatal )?error(?:\s+[A-Z]+\d*)?:/i.test(text)) {
    return result('OBSOLETE_NATIVE_ASSUMPTION', 'signature', 'the native build reached its toolchain but does not compile or match this Node ABI',
      [engineRange ? `engines.node=${engineRange}` : 'engines.node=undeclared']);
  }
  if (/node: bad option: --harmony_|Function\.prototype\.apply was called on undefined|(?:^|[/\\])esm[/\\]esm\.js:1/im.test(text)) {
    return result('OBSOLETE_NODE_ASSUMPTION', 'signature',
      'the published lifecycle requires Node runtime behavior removed from this runtime cell',
      [engineRange ? `engines.node=${engineRange}` : 'engines.node=undeclared']);
  }
  if (/error TS(?:5011|5108):|error TS\d+:.*(?:not assignable|has no initializer)/i.test(text)) {
    return result('OBSOLETE_TYPESCRIPT_ASSUMPTION', 'signature',
      'the published source or configuration is incompatible with the resolved TypeScript toolchain',
      ['tool=typescript', 'package-source=obsolete']);
  }
  if (/Could not find any Python|find Python|python(?:3)?(?:\.exe)?: (?:not found|No such file)|No module named (?:distutils|setuptools)|gyp ERR!.*python/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a Python installation or Python behavior absent from this profile',
      ['tool=python']);
  }
  if (/not found: (?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja|aclocal|autoconf|automake|libtoolize)|(?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja|aclocal|autoconf|automake|libtoolize): (?:command )?not found|could not find (?:Visual Studio|MSBuild)|gyp ERR! find VS|No CMAKE_C_COMPILER|C compiler cannot create executables/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a compiler or native build tool absent from this profile',
      ['tool=native-build-chain']);
  }
  const directPosixScriptOnWindows = /['"]\.['"] is not recognized as an internal or external command/i.test(text)
    && (/(?:^|\n)>\s*\.\/\S+/m.test(text) || /(?:^|\s)\.\/[^\s]+/.test(lifecycleScripts));
  if (platform === 'win32' && (/was unexpected at this time/i.test(text) || directPosixScriptOnWindows
    || /ENOENT: no such file or directory, (?:chmod|rename).*(?:chromedriver|binary[\\/]rover)/i.test(text))) {
    return result('PUBLISHED_SCRIPT_PLATFORM_ASSUMPTION', 'signature',
      'the published lifecycle script uses a POSIX-only path or command on Windows',
      ['platform=win32']);
  }
  if (metadata.scripts?.install && /^(?:npm|pnpm|yarn|nub) install\s*$/i.test(metadata.scripts.install)) {
    return result('PUBLISHED_SCRIPT_RECURSION', 'metadata',
      'the published install lifecycle recursively invokes a package-manager install',
      [`scripts.install=${metadata.scripts.install}`]);
  }
  if (/Permission denied/i.test(text) && /(?:^|[ /\\])scripts?[/\\][^\r\n]+/i.test(text)) {
    return result('PUBLISHED_SCRIPT_NOT_EXECUTABLE', 'signature',
      'the published lifecycle script is present but lacks an executable file mode',
      ['published script mode invalid']);
  }
  if (/The ['"]bootstrap['"] command was removed by default/i.test(text)
    && (metadata.devDependencies ?? []).includes('lerna')) {
    return result('PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY', 'metadata',
      'the published lifecycle resolved an incompatible host Lerna because its required version is only a development dependency',
      ['missingCommand=lerna', 'devDependency=lerna']);
  }
  if (/Local modules not found in /i.test(text) && (metadata.devDependencies ?? []).length > 0) {
    return result('PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY', 'metadata',
      'the published build lifecycle requires local modules declared only as development dependencies',
      ['local build modules missing']);
  }
  const missingBinCommand = text.match(/(?:^|[/\\])\.bin[/\\]([@A-Za-z0-9_.-]+)(?::|\s).*(?:not found|No such file)\b/im)?.[1];
  const missingCommandRaw = missingBinCommand
    ?? text.match(/(?:^|\n)(?:(?:\/bin\/)?sh: (?:(?:line )?\d+: )?)?([@A-Za-z0-9_.-]+): (?:command )?not found\b/im)?.[1]
    ?? text.match(/\bspawn ([A-Za-z0-9_.-]+) ENOENT\b/i)?.[1]
    ?? text.match(/(?:^|\n)['"]?([@A-Za-z0-9_.-]+)['"]? is not recognized as an internal or external command\b/im)?.[1]
    ?? text.match(/node_modules[/\\]([@A-Za-z0-9_.-]+)[/\\][^\r\n:]+: (?:not found|No such file)\b/im)?.[1]
    ?? text.match(/\bCommand ['"]([@A-Za-z0-9_.-]+)['"] not found\b/i)?.[1]
    ?? text.match(/Unable to find local ([A-Za-z0-9_.-]+)/i)?.[1];
  const missingCommand = missingCommandRaw?.replace(/\.+$/, '');
  if (platform === 'win32' && missingBinCommand
    && (metadata.dependencies ?? []).includes(missingCommand)) {
    return result('PUBLISHED_SCRIPT_PLATFORM_ASSUMPTION', 'metadata',
      'the published Windows lifecycle invokes a dependency through a POSIX-only .bin path',
      [`missingCommand=${missingCommand}`, `dependency=${missingCommand}`, 'platform=win32']);
  }
  if (missingCommand && (metadata.devDependencies ?? []).includes(missingCommand)) {
    return result('PUBLISHED_SCRIPT_REQUIRES_DEV_DEPENDENCY', 'metadata',
      'the published lifecycle script invokes a tool declared only as a development dependency',
      [`missingCommand=${missingCommand}`, `devDependency=${missingCommand}`]);
  }
  if (missingCommand) {
    return result('UNDECLARED_EXTERNAL_TOOL_REQUIRED', 'signature',
      'the published lifecycle script invokes a tool that is not installed by the package dependency tree',
      [`missingCommand=${missingCommand}`, 'profile experiment required']);
  }
  if (/Cannot find cypress folder|scaffold Cypress folder|not a git repository|Cannot find.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)|ENOENT.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)/i.test(text)) {
    return result('PROJECT_FIXTURE_PREREQUISITE', 'signature', 'the lifecycle script expects additional project shape',
      ['profile experiment required']);
  }
  if (/(?:failed to download\/install|download|binary|artifact|tarball)[\s\S]{0,1200}(?:Status Code is )?(?:403|404|410)|(?:403|404|410)[\s\S]{0,1200}(?:download|binary|artifact|tarball)|Request failed with status code 404|Failed to download .+, caused by|incorrect header check|Download failed: ENOENT: no such file or directory, chmod/i.test(text)) {
    return result('EXTERNAL_ARTIFACT_UNAVAILABLE', 'signature',
      'the lifecycle script points at an external artifact that is consistently unavailable',
      ['consistent HTTP 403/404/410']);
  }
  if (/PUPPETEER_SKIP_CHROMIUM_DOWNLOAD|(?:environment variable|env var)\s+[A-Z][A-Z0-9_]+.*(?:required|missing|not set)|(?:Please|must) set [A-Z][A-Z0-9_]+/i.test(text)) {
    return result('ENVIRONMENT_PREREQUISITE', 'signature', 'the lifecycle script requires an environment value not supplied by this profile',
      ['profile experiment required']);
  }
  if (/No matching version found|ERR_NUB_NO_MATCHING_VERSION|ETARGET|E404|404 Not Found|410 Gone|checksum (?:failed|mismatch)|integrity checksum failed|unsupported URL type|Cannot find module .*node_modules.*(?:scripts|bin|install|postinstall)|MODULE_NOT_FOUND|THIS PACKAGE WAS RENAMED|The git reference could not be found|pathspec .+ did not match|provided mimeType .+ is not valid|blockExoticSubdeps|Error downloading binary; invalid response status code: 400|preinstall-always-fail|Cannot read properties of undefined \(reading ['"]has['"]\)|ERR_INVALID_ARG_TYPE.*(?:path|paths\[0\]).*(?:Object|undefined)/i.test(text)) {
    return result('PACKAGE_BROKEN_OR_UNAVAILABLE', 'signature', 'a pinned package or external artifact is unavailable or permanently invalid',
      ['consistent reference failure']);
  }

  if (quorumOutcomes.some((outcome) => outcome === 'unstable')) {
    return result('UNSTABLE_REFERENCE', 'retry', 'clean retries produced different failure fingerprints',
      [nub?.quorum?.fingerprint, npm?.quorum?.fingerprint].filter(Boolean), 'incomplete');
  }

  return result('UNCLASSIFIED', 'none', 'the retained evidence does not yet support one root-cause class',
    [nub?.quorum?.fingerprint, npm?.quorum?.fingerprint].filter(Boolean), 'incomplete');
}
