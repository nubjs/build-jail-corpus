import crypto from 'node:crypto';
import fs from 'node:fs';
import { satisfiesNodeRange } from './node-range.mjs';

const stripAnsi = (value) => String(value ?? '').replace(/\x1b\[[0-9;]*m/g, '');

export function sanitizeFailureText(value, roots = {}) {
  let text = stripAnsi(value).replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/g, 'https://<credentials>@');
  for (const [name, root] of Object.entries(roots)) {
    if (!root) continue;
    const aliases = new Set([String(root)]);
    try { aliases.add(fs.realpathSync(String(root))); } catch { /* path may no longer exist */ }
    for (const alias of [...aliases].sort((a, b) => b.length - a.length)) {
      text = text.split(alias).join(`<${name.toUpperCase()}>`);
    }
  }
  return text;
}

export function firstErrorFrom(output, roots = {}) {
  const text = sanitizeFailureText(output, roots);
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const useful = lines.filter((line) => !/^(?:npm )?warn(?:ing)?\b|^throw err;?$|^\^$|complete log of this run/i.test(line));
  const ranked = [
    /^(?:Error|TypeError|RangeError|SyntaxError):\s+/i,
    /^(?:<[^>]+>|[/\\].*):\d+(?::\d+)?:\s+(?:fatal )?error:/i,
    /^(?:npm (?:error|ERR!)|gyp ERR!|fatal:)\s+/i,
    /\b(?:ERR_[A-Z0-9_]+|MODULE_NOT_FOUND|EACCES|ENOENT|ETIMEDOUT|ECONNRESET|EAI_AGAIN)\b/,
    /(?:failed|exception)\b/i,
  ];
  const summary = (ranked.map((pattern) => useful.find((line) => pattern.test(line))).find(Boolean)
    ?? useful.at(-1) ?? 'process exited without diagnostic output').slice(0, 800);
  const codes = [...new Set(text.match(/\b(?:ERR_[A-Z0-9_]+|MODULE_NOT_FOUND|E(?:ACCES|AI_AGAIN|CONNREFUSED|CONNRESET|HOSTUNREACH|NETUNREACH|NOENT|NOTFOUND|PERM|PIPE|PROTO|TIMEDOUT|TARGET|BADPLATFORM)|HTTP\s+[45]\d\d)\b/gi) ?? [])]
    .map((code) => code.toUpperCase()).sort();
  return {
    summary,
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
  .map((stage) => stage?.error?.summary ?? '').filter(Boolean).join('\n');

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
    return result('NPM_PM_DIVERGENCE', 'differential', 'unjailed Nub passes while npm fails on the same fixture and runtime',
      ['nub=pass', npm?.quorum?.fingerprint].filter(Boolean));
  }

  const engineRange = metadata.engines?.node;
  const engineMatch = typeof engineRange === 'string' ? satisfiesNodeRange(nodeVersion, engineRange) : null;
  if (engineMatch === false) {
    return result('INCOMPATIBLE_NODE', 'metadata', `the package declares Node ${engineRange}, not ${nodeVersion}`,
      [`engines.node=${engineRange}`, `node=${nodeVersion}`]);
  }
  const osAllowed = listAllows(platform, metadata.os);
  const cpuAllowed = listAllows(arch, metadata.cpu);
  const libcAllowed = libc ? listAllows(libc, metadata.libc) : null;
  if (osAllowed === false || cpuAllowed === false || libcAllowed === false
    || /EBADPLATFORM|not compatible with your operating system|Unsupported platform/i.test(text)) {
    return result('OS_CPU_MISMATCH', osAllowed === false || cpuAllowed === false || libcAllowed === false
      ? 'metadata' : 'signature',
      'the package excludes this operating-system, CPU, or libc cell',
      [`os=${platform}`, `cpu=${arch}`, `package.os=${JSON.stringify(metadata.os ?? null)}`,
        `package.cpu=${JSON.stringify(metadata.cpu ?? null)}`, `libc=${libc}`,
        `package.libc=${JSON.stringify(metadata.libc ?? null)}`]);
  }

  if (/Could not find any Python|find Python|python(?:3)?(?:\.exe)?: (?:not found|No such file)|No module named (?:distutils|setuptools)|invalid mode: ['"]rU['"]|Missing parentheses in call to ['"]print['"]|gyp ERR!.*python/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a Python installation or Python behavior absent from this profile',
      ['tool=python']);
  }
  if (/not found: (?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja)|(?:make|gcc|g\+\+|cc|c\+\+|cmake|ninja): (?:command )?not found|could not find (?:Visual Studio|MSBuild)|gyp ERR! find VS|No CMAKE_C_COMPILER|C compiler cannot create executables/i.test(text)) {
    return result('TOOLCHAIN_PREREQUISITE', 'signature', 'the build expects a compiler or native build tool absent from this profile',
      ['tool=native-build-chain']);
  }
  if (/NODE_MODULE_VERSION|V8.*(?:has no member|was not declared)|nan\.h.*(?:not found|error)|node-gyp|gyp ERR! build error|C\+\+.*error:/i.test(text)) {
    return result('OBSOLETE_NATIVE_ASSUMPTION', 'signature', 'the native build reached its toolchain but does not compile or match this Node ABI',
      [engineRange ? `engines.node=${engineRange}` : 'engines.node=undeclared']);
  }
  if (/not a git repository|Cannot find.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)|ENOENT.*(?:README|lerna\.json|rush\.json|angular\.json|tsconfig\.json)/i.test(text)) {
    return result('PROJECT_FIXTURE_PREREQUISITE', 'signature', 'the lifecycle script expects additional project shape',
      ['profile experiment required']);
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
