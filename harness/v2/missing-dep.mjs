// What a failed lifecycle script SAYS it is missing.
//
// ⛔ THE SCAFFOLD CANNOT SEE THESE, AND THAT IS WHY THIS EXISTS. `script-scaffold.mjs` reads the
// manifest's script STRING and installs the binaries it names. That covers `postinstall: "tsc -p ."`
// and misses everything a script reaches for at RUNTIME — `node scripts/build.js` whose build.js
// does `require('rollup')`, or shells out to `bower`. Measured on the 2026-08-22 ledger: the
// scaffold was non-empty on only 20 of the 71 rows that died on a missing binary, and 34 more rows
// died on `Cannot find module '<bare>'` with a scaffold that had nothing to add.
//
// So the arm asks the FAILURE instead of the manifest. Installing what the log names, then
// retrying, is strictly better information than a static map: it needs no provider table for the
// module case, and it discovers runtime-only tools the manifest never mentions.
//
// ⛔ WHY NOT JUST INSTALL EVERY devDependency: measured, it is WORSE. `@paypal/paypal-js@2.1.8`
// declares 29 devDeps; installing all of them returns rc=1 with an EMPTY `.bin`, while installing
// the single one its script uses (`husky@^5.0.9`) returns rc=0. Targeted beats blanket.

/** Binaries whose npm package has a different name. Shared shape with script-scaffold's map, kept
 *  here too because a runtime-discovered binary never passes through that module. */
const BIN_PROVIDER = {
  tsc: 'typescript', 'run-p': 'npm-run-all', 'run-s': 'npm-run-all', grunt: 'grunt-cli',
  gulp: 'gulp-cli', webpack: 'webpack-cli', babel: 'babel-cli', ngcc: '@angular/compiler-cli',
  'node-pre-gyp': '@mapbox/node-pre-gyp', neon: 'neon-cli', remix: '@remix-run/dev',
};

/** Names no npm package supplies. A retry must not invent a provider for these. Note that the
 *  package MANAGERS are deliberately absent — see `installable` below. */
const NEVER = new Set([
  'nodejs', 'node-waf', 'pg_config', 'pulumi', 'node', 'npm', 'sh', 'bash', 'cmd',
  // ⛔ OTHER ECOSYSTEMS' TOOLS, AND THE TRAP IS THAT npm HAS PACKAGES BY THESE NAMES. A script that
  // shells out to `bundle` wants Ruby's bundler; npm's unrelated `bundle` package would install
  // cleanly and leave the record describing an environment that never existed. A missing name is a
  // cheap loss; a wrong one is a lie.
  'bundle', 'gem', 'ruby', 'rake', 'python', 'python3', 'pip', 'pip3', 'cargo', 'rustc', 'go',
  'git', 'make', 'cmake', 'gcc', 'clang', 'msbuild', 'dotnet', 'java', 'mvn', 'gradle', 'brew', 'apt-get',
]);

/** A bare specifier is installable; a path is the package's OWN missing file and no install fixes it. */
const isBare = (s) => Boolean(s) && !s.startsWith('.') && !s.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(s)
  // A relative path with no leading `./` still is not a specifier: `node_modules/typings/dist/bin.js`
  // reached the installer as a package name before this clause, which would have added a nonsense
  // dependency and made the record describe an environment that never existed. Note the test is the
  // PREFIX, not a file extension — `cypress/package.json` is a real subpath of a real package, and an
  // extension rule rejects it wrongly.
  && !s.startsWith('node_modules/');

/**
 * @returns {{kind: 'module'|'bin', name: string, install: string}|null}
 *   `install` is the package to add. null when the log names nothing installable — which includes
 *   the common case of a package whose own file is missing from its published tarball.
 */
export function namesMissingDependency(log) {
  const text = String(log ?? '');

  // A required module. `Cannot find module 'X'` — only the BARE form is actionable: an absolute
  // path means the package did not ship its own file, which no install can repair.
  const mod = /Cannot find module ['"]([^'"]+)['"]/.exec(text);
  if (mod && isBare(mod[1])) {
    // `typescript/lib/tsc` and `cypress/package.json` are subpaths — install the package, not the path.
    const name = mod[1].startsWith('@') ? mod[1].split('/').slice(0, 2).join('/') : mod[1].split('/')[0];
    if (!NEVER.has(name)) return { kind: 'module', name: mod[1], install: name };
  }

  // A binary the script shelled out to. Both dialects, and cmd.exe's is not a shell's.
  // ⛔ `npm error ` / `npm ERR! ` MAY PRECEDE THE SHELL'S OWN MESSAGE. npm re-prefixes a lifecycle
  // script's stderr, so anchoring `sh:` to line start missed `npm error sh: pnpm: command not found`
  // — 5 rows of the ledger, all of them actionable.
  const PRE = String.raw`(?:^|\n)\s*(?:npm (?:error|ERR!)\s+)?`;
  const bin = /['"]?([\w@/.+-]+)['"]? is not recognized as an internal or external/.exec(text)
           ?? new RegExp(`${PRE}(?:sh|bash):\\s*\\d*:?\\s*([\\w@/.+-]+):\\s*(?:command )?not found`).exec(text)
           ?? new RegExp(`${PRE}([\\w@/.+-]+):\\s*command not found`).exec(text);
  if (bin) {
    const raw = bin[1];
    // `.` and `scripts` come from a POSIX `./bin/x` invocation under cmd.exe. There is no package
    // called `.`, and the script genuinely does not run there — an install would be a lie.
    // ⛔ A BINARY NAME IS NOT A PATH, and the module branch's guard does not cover this one.
    // `sh: node_modules/typings/dist/bin.js: not found` reached the installer as a package name.
    // A scoped bin (`@scope/name`) is the only legitimate form carrying a slash.
    const looksLikePath = raw.includes('/') && !/^@[^/]+\/[^/]+$/.test(raw);
    if (!NEVER.has(raw) && !looksLikePath && /^[@a-z0-9][\w.@/-]*$/i.test(raw)
        && raw !== 'scripts' && raw !== 'node_modules') {
      return { kind: 'bin', name: raw, install: BIN_PROVIDER[raw] ?? raw };
    }
  }
  return null;
}
