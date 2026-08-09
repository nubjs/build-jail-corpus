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
  return text;
}

export function firstErrorFrom(output, roots = {}) {
  const text = sanitizeFailureText(output, roots);
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const useful = lines.filter((line) => !/^(?:npm )?warn(?:ing)?\b|^throw err;?$|^\^$|complete log of this run/i.test(line));
  const rank = (line) => {
    if (/\bwarning:/i.test(line)) return 0;
    if (/^(?:TypeError|RangeError|ReferenceError|SyntaxError):\s+/i.test(line)
      || /^Error: Cannot (?:find module|read file)/i.test(line)) return 100;
    if (/\b(?:error TS\d+|fatal error:|MODULE_NOT_FOUND|Missing parentheses in call to ['"]print['"])/i.test(line)
      || /\(\d+(?:,\d+)?\):\s+(?:fatal )?error\s+[A-Z]+\d*:/i.test(line)) return 98;
    if (/GNU Make version is too old/i.test(line)
      || /^make(?:\[\d+\])?: \*\*\* \[[^\]]*verify-deps[^\]]*\] Error/i.test(line)) return 97;
    if (/\b(?:Cannot read file|Cannot find module|Package ['"].+['"].*not found|No rule to make target|command not found|not found: command|Status Code is 4\d\d)\b/i.test(line)) return 96;
    if (/^[A-Za-z0-9_.@+-]+(?:[/\\][^:\r\n]+)*:\d+(?::\d+)?:\s+(?:fatal )?error:/i.test(line)) return 94;
    if (/^(?:<[^>]+>|\.{0,2}[/\\].*|[/\\].*):\d+(?::\d+)?:\s+(?:fatal )?error:/i.test(line)) return 94;
    if (/^make\[\d+\]: \*\*\* \[[^\]]+\] Error/i.test(line)) return 95;
    if (/^(?:make: \*\*\*|gyp: Call to|failed to download\/install)\b/i.test(line)) return 92;
    if (/^Error:\s+/i.test(line)) return 90;
    if (/\b(?:ERR_[A-Z0-9_]+|EACCES|ENOENT|ETIMEDOUT|ECONNRESET|EAI_AGAIN|EBADPLATFORM)\b/.test(line)) return 85;
    if (/(?:failed|exception|not found|unsupported|incompatible|404|410)\b/i.test(line)) return 75;
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
  .flatMap((attempt) => Object.values(attempt.stages ?? {}))
  .flatMap((stage) => [stage?.error?.summary, ...(stage?.error?.excerpts ?? [])])
  .filter(Boolean).join('\n');

const passed = (arm) => arm?.quorum?.outcome === 'pass';
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
  if (quorumOutcomes.some((outcome) => outcome === 'pass-after-failure' || outcome === 'transient')
    || /ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|socket hang up|network timeout|HTTP\s+429|HTTP\s+5\d\d|TLS handshake/i.test(text)) {
    return result('TRANSIENT_EXTERNAL_DOWNLOAD', 'retry', 'an external download failed transiently or changed outcome across clean retries',
      quorumOutcomes.filter(Boolean));
  }
  if (quorumOutcomes.some((outcome) => outcome === 'unstable')) {
    return result('UNSTABLE_REFERENCE', 'retry', 'clean retries produced different failure fingerprints',
      [nub?.quorum?.fingerprint, npm?.quorum?.fingerprint].filter(Boolean), 'incomplete');
  }

  if (passed(nub) && passed(npm)) {
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
  if (passed(npm) && !passed(nub)) {
    return result('NUB_PM_DIVERGENCE', 'differential', 'npm passes while unjailed Nub fails on the same fixture and runtime',
      [nub?.quorum?.fingerprint, 'npm=pass'].filter(Boolean));
  }
  if (passed(nub) && !passed(npm)) {
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

  const engineRange = metadata.engines?.node;
  const engineMatch = typeof engineRange === 'string' ? satisfiesNodeRange(nodeVersion, engineRange) : null;
  if (engineMatch === false) {
    return result('INCOMPATIBLE_NODE', 'metadata', `the package declares Node ${engineRange}, not ${nodeVersion}`,
      [`engines.node=${engineRange}`, `node=${nodeVersion}`]);
  }
  if (platformMismatch
    || /EBADPLATFORM|not compatible with your operating system|Unsupported platform/i.test(text)) {
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
  if (/pkg-config.*(?:not found|exit status)|Package ['"].+['"].*not found|not found in the pkg-config search path|Cannot open include file: ['"](?:cairo\.h|pango(?:\/|\\)|pixman(?:\.h|-1)|jpeglib\.h|gif_lib\.h|librsvg(?:\/|\\))|(?:cairo|pango|pixman|libjpeg|libgif|librsvg).*development (?:files|package)/i.test(text)) {
    return result('SYSTEM_LIBRARY_PREREQUISITE', 'signature',
      'the native build expects a system development library absent from this profile',
      ['profile experiment required']);
  }
  if (/Cannot read file .*node_modules.*(?:tsconfig|lerna|rush|angular)\.json|error TS\d+: Cannot read file .*node_modules|No rule to make target .*node_modules.*(?:src|source)|No rule to make target .*[/\\](?:src|source)[/\\]|Cannot open source file:.*(?:^|[/\\])(?:src|source)[/\\]/im.test(text)) {
    return result('PUBLISHED_SOURCE_PREREQUISITE', 'signature',
      'the published lifecycle script expects source-tree configuration that is absent from the package tarball',
      ['published source/configuration missing']);
  }
  if (/NODE_MODULE_VERSION|V8.*(?:has no member|was not declared)|error(?::|\s+[A-Z]+\d*:).*(?:\bv8::|SetAccessor|WeakCallbackType)|nan\.h.*(?:not found|error)|primordials is not defined|ERR_INVALID_OBJECT_DEFINE_PROPERTY|process\.env.*only accepts a configurable, writable, and enumerable data descriptor|Error: spawn EINVAL|C\+\+.*error:|(?:^|\n).*(?:\.cc|\.cpp|\.h|\.lzz)(?::\d+(?::\d+)?|\(\d+(?:,\d+)?\)): (?:fatal )?error(?:\s+[A-Z]+\d*)?:/i.test(text)) {
    return result('OBSOLETE_NATIVE_ASSUMPTION', 'signature', 'the native build reached its toolchain but does not compile or match this Node ABI',
      [engineRange ? `engines.node=${engineRange}` : 'engines.node=undeclared']);
  }
  if (/Could not find any Python|find Python|python(?:3)?(?:\.exe)?: (?:not found|No such file)|No module named (?:distutils|setuptools)|gyp ERR!.*python/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a Python installation or Python behavior absent from this profile',
      ['tool=python']);
  }
  if (/not found: (?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja|aclocal|autoconf|automake|libtoolize)|(?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja|aclocal|autoconf|automake|libtoolize): (?:command )?not found|could not find (?:Visual Studio|MSBuild)|gyp ERR! find VS|No CMAKE_C_COMPILER|C compiler cannot create executables/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a compiler or native build tool absent from this profile',
      ['tool=native-build-chain']);
  }
  const missingCommand = text.match(/(?:^|\n)(?:(?:\/bin\/)?sh: (?:\d+: )?)?([@A-Za-z0-9_.-]+): (?:command )?not found\b/im)?.[1]
    ?? text.match(/(?:^|\n)['"]?([@A-Za-z0-9_.-]+)['"]? is not recognized as an internal or external command\b/im)?.[1];
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
  if (/not a git repository|Cannot find.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)|ENOENT.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)/i.test(text)) {
    return result('PROJECT_FIXTURE_PREREQUISITE', 'signature', 'the lifecycle script expects additional project shape',
      ['profile experiment required']);
  }
  if (/(?:failed to download\/install|download|binary|artifact).*(?:Status Code is )?(?:404|410)|(?:404|410).*(?:download|binary|artifact)/i.test(text)) {
    return result('EXTERNAL_ARTIFACT_UNAVAILABLE', 'signature',
      'the lifecycle script points at an external artifact that is consistently unavailable',
      ['consistent HTTP 404/410']);
  }
  if (/(?:environment variable|env var)\s+[A-Z][A-Z0-9_]+.*(?:required|missing|not set)|(?:Please|must) set [A-Z][A-Z0-9_]+/i.test(text)) {
    return result('ENVIRONMENT_PREREQUISITE', 'signature', 'the lifecycle script requires an environment value not supplied by this profile',
      ['profile experiment required']);
  }
  if (/No matching version found|ETARGET|E404|404 Not Found|410 Gone|checksum (?:failed|mismatch)|integrity checksum failed|unsupported URL type|Cannot find module .*node_modules.*(?:scripts|bin|install|postinstall)|MODULE_NOT_FOUND/i.test(text)) {
    return result('PACKAGE_BROKEN_OR_UNAVAILABLE', 'signature', 'a pinned package or external artifact is unavailable or permanently invalid',
      ['consistent reference failure']);
  }

  return result('UNCLASSIFIED', 'none', 'the retained evidence does not yet support one root-cause class',
    [nub?.quorum?.fingerprint, npm?.quorum?.fingerprint].filter(Boolean), 'incomplete');
}
