// Which packages the OBSERVE arm must add so a lifecycle script can actually RUN.
//
// ⛔ THE DEFECT THIS FIXES. The observe arm is a CONSUMER install (`npm install <pkg>@<ver>`), and a
// consumer install never installs the dependency's devDependencies. So a package whose `postinstall`
// invokes a binary from its own devDependencies dies at `sh: <bin>: command not found` before it
// executes one line of its real work — and the corpus filed that as the PACKAGE being broken. It is
// not: it is the arm withholding the environment the script was written against. MEASURED across the
// 1,529 `BROKEN-*` records: 105 die exactly this way, on 34 distinct binaries.
//
// ⛔ WHOLESALE devDependency INSTALL IS THE WRONG FIX, AND IT WAS MEASURED WRONG BEFORE THIS SHAPE
// WAS WRITTEN. `@paypal/paypal-js@2.1.8` declares 29 devDependencies (puppeteer, jest, rollup, …).
// Installing them ALL returned exit 1 and left `node_modules/.bin` EMPTY — npm's install is atomic,
// so one bad resolution in a large closure loses the entire scaffold and the arm is no better off.
// Installing ONLY `husky@^5.0.9`, the one binary its `postinstall` names, took the same package from
// rc=127 to rc=0. Surgical, not wholesale.
//
// ⛔ THE VERSION COMES FROM THE PACKAGE'S OWN MANIFEST WHENEVER IT DECLARES ONE, AND THAT IS THE
// WHOLE POINT. `husky install` is husky 4/5 grammar; husky 9 removed it. Resolving the bare name
// `husky` would install 9 and fail differently while looking like the same class. The package's own
// `devDependencies` range is the era-correct answer, so it always wins over the fallback map.
//
// ⛔ WHAT THIS CANNOT DO, AND MUST NOT PRETEND TO. Scaffolding a binary does not make a package
// installable — it makes the NEXT failure attributable. `@antv/dom-util@2.0.0` goes from
// `sh: tsc: command not found` to `error TS5083: Cannot read file '<tree>/node_modules/tsconfig.json'`
// — its published tsconfig `extends` a monorepo root that was never published, so no environment can
// fix it. That is a far better record than the one it replaces: an UNATTRIBUTED environment gap
// becomes a quotable package defect. Both outcomes are wins; only the first is a recovery.

/** Lifecycle scripts an INSTALL of a dependency can run, in npm's own order. */
export const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare'];

/** Binaries whose providing package is NOT its own name.
 *
 *  ⛔ DELIBERATELY SMALL AND CURATED, and it is the FALLBACK — consulted only when the package's own
 *  `devDependencies` do not already name a provider. Every entry below was observed in the corpus,
 *  with its record count; this is not a speculative registry of build tools. Bin names that equal
 *  their package name (`husky`, `rimraf`, `patch-package`, `typings`, `bower`, `rollup`, …) need no
 *  entry and deliberately have none. */
export const BIN_TO_PACKAGE = {
  tsc: 'typescript',            // 10 records
  'run-p': 'npm-run-all',       // 4
  'run-s': 'npm-run-all',
  grunt: 'grunt-cli',           // 2
  ngcc: '@angular/compiler-cli', // 2
  gulp: 'gulp-cli',             // 1
  webpack: 'webpack-cli',       // 1
  babel: 'babel-cli',           // 1
  remix: '@remix-run/dev',      // 1
  'node-pre-gyp': '@mapbox/node-pre-gyp', // 1
  neon: 'neon-cli',             // 1
};

/** Binaries no npm package can supply, with the reason. A scaffold must not invent a provider for
 *  these — the honest outcome is an attributed refusal, not a guess that installs something unrelated.
 *
 *  ⛔ `nodejs` IS NOT A TYPO FOR `node`. One package's script really does invoke `nodejs`, the Debian
 *  binary name, which exists on no macOS or Windows box and on modern Debian only via a compat
 *  package. `node-waf` was REMOVED FROM NODE ITSELF in 0.8 (2012) — no era pin reaches it, because
 *  the eras that had it predate every Node this corpus can provision. */
export const UNPROVIDABLE = {
  nodejs: 'Debian-only binary name for node; not an npm package',
  'node-waf': 'removed from Node in 0.8 (2012); no provisionable era supplies it',
  pg_config: 'PostgreSQL system tool, not an npm package',
  pulumi: 'external CLI distributed outside npm',
  pnpm: 'a different package manager; a corpus policy call, not a package defect',
  bun: 'a different package manager; a corpus policy call, not a package defect',
};

/** Command names a shell script invokes, best-effort.
 *
 *  Deliberately conservative: it reads the FIRST word of each `&&` / `;` / `||` segment and nothing
 *  else. A parser that tried to be clever about quoting and substitution would silently mis-attribute,
 *  and a missed binary is cheap (the record keeps the failure it already had) while a wrong one is
 *  not (the arm installs an unrelated package and the record lies about its environment). */
export function commandsIn(script) {
  if (typeof script !== 'string') return [];
  const out = [];
  for (const segment of script.split(/&&|\|\||;|\|/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    // Step over env assignments (`FOO=bar cmd`) and `npx`, which name a command after themselves.
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
    if (i < words.length && (words[i] === 'npx' || words[i] === 'command')) i++;
    const cmd = words[i];
    if (cmd && !cmd.startsWith('-')) out.push(cmd);
  }
  return out;
}

/** Follow `npm run <x>` / `yarn <x>` chains so a `postinstall: "npm run build"` reaches `build`'s
 *  own commands. Cycles terminate on the `seen` set rather than recursion depth. */
export function resolveScriptCommands(scripts, entry, seen = new Set()) {
  if (!scripts || seen.has(entry) || !(entry in scripts)) return [];
  seen.add(entry);
  const found = [];
  const words = String(scripts[entry]).split(/\s+/);
  for (let i = 0; i < words.length - 1; i++) {
    if ((words[i] === 'run' && (words[i - 1] === 'npm' || words[i - 1] === 'yarn' || words[i - 1] === 'pnpm'))
        || (words[i] === 'yarn' && !words[i + 1].startsWith('-'))) {
      found.push(...resolveScriptCommands(scripts, words[i + 1], seen));
    }
  }
  for (const c of commandsIn(scripts[entry])) {
    if (c === 'npm' || c === 'yarn' || c === 'pnpm') continue;
    found.push(c);
  }
  return found;
}

/** Shell builtins and coreutils a lifecycle script may legitimately call. Never scaffolded. */
const AMBIENT = new Set([
  'rm', 'cp', 'mv', 'mkdir', 'cd', 'echo', 'cat', 'test', 'true', 'false', 'exit', 'set', 'sh',
  'bash', 'node', 'env', 'sed', 'awk', 'grep', 'find', 'chmod', 'ln', 'touch', 'tar', 'curl',
  'wget', 'git', 'make', 'python', 'python3', 'cmake', 'pwd', 'ls', 'if', 'then', 'else', 'fi',
  'for', 'do', 'done', 'while', 'case', 'esac', 'exec', 'printf', 'which', 'command',
]);

/** What the observe arm should install alongside `manifest`'s package so its lifecycle scripts can run.
 *
 *  Returns `{ install: [<spec>], unprovidable: [{bin, why}], ambient: [<bin>] }`. `install` is what
 *  the arm adds; the other two exist so the RECORD can state why a binary was left unsatisfied
 *  instead of leaving the reader to infer it from a failure. */
export function scriptScaffold(manifest, { has = () => false } = {}) {
  const scripts = manifest?.scripts ?? {};
  const declared = { ...(manifest?.devDependencies ?? {}), ...(manifest?.peerDependencies ?? {}) };
  const own = new Set([
    ...Object.keys(manifest?.dependencies ?? {}),
    ...Object.keys(manifest?.optionalDependencies ?? {}),
  ]);

  const wanted = new Set();
  for (const entry of LIFECYCLE) for (const c of resolveScriptCommands(scripts, entry)) wanted.add(c);

  const install = [], unprovidable = [], ambient = [];
  for (const bin of wanted) {
    if (AMBIENT.has(bin) || bin.startsWith('./') || bin.startsWith('/') || bin.includes('/')) { ambient.push(bin); continue; }
    if (own.has(bin) || has(bin)) continue;                       // already reachable in the tree
    if (bin in UNPROVIDABLE) { unprovidable.push({ bin, why: UNPROVIDABLE[bin] }); continue; }
    // The package's OWN declared range wins — it is the era-correct one. See the header note on husky.
    const provider = BIN_TO_PACKAGE[bin] ?? bin;
    if (declared[provider]) install.push(`${provider}@${declared[provider]}`);
    else if (declared[bin]) install.push(`${bin}@${declared[bin]}`);
    else if (BIN_TO_PACKAGE[bin] || /^[@a-z0-9][\w.@/-]*$/i.test(bin)) install.push(provider);
    else unprovidable.push({ bin, why: 'no provider known and the name is not a valid package name' });
  }
  return { install, unprovidable, ambient };
}
