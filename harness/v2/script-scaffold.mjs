// Which packages the OBSERVE arm must add so a lifecycle script can actually RUN.
//
// ⛔ THE DEFECT THIS FIXES. The observe arm is a CONSUMER install (`npm install <pkg>@<ver>`), and a
// consumer install never installs the dependency's devDependencies. So a package whose `postinstall`
// invokes a binary from its own devDependencies dies at `sh: <bin>: command not found` before it
// executes one line of its real work — and the corpus filed that as the PACKAGE being broken. It is
// not: it is the arm withholding the environment the script was written against. MEASURED across the
// 1,529 `BROKEN-*` records: 105 die exactly this way, on 34 distinct binaries.
//
// ⛔⛔ THE DECLARED CLOSURE IS INSTALLED TOO, AND THE ARGUMENT THAT SAID OTHERWISE RESTED ON A MISREAD
// CAUSE. This block used to read: "WHOLESALE devDependency INSTALL IS THE WRONG FIX … `@paypal/paypal-js@2.1.8`
// declares 29 devDependencies; installing them ALL returned exit 1 and left `node_modules/.bin` EMPTY —
// npm's install is atomic, so one bad resolution loses the entire scaffold." The OBSERVATION reproduces
// exactly. The CAUSE was wrong, and the conclusion drawn from it with it.
//
// MEASURED 2026-09-01 on that same package, same specs, same `--before`, with the instrument calibrated
// in BOTH directions first (no scaffold -> rc=127 `sh: husky: command not found`; surgical -> rc=0):
//
//   scaffold mode                       scaffold rc   .bin entries   rebuild rc
//   none                                     —          absent          127
//   surgical (what this module did)          0             1              0
//   full closure, as described above         1          absent          127
//   full closure + `--legacy-peer-deps`      0            48              0
//
// The failure is `ERESOLVE` — npm 7+'s STRICT PEER RESOLUTION, which npm 6 (the era npm for a 2021
// package) never had. Nothing was unresolvable, and nothing was lost to atomicity; the invocation was
// wrong for the era. One flag installs all 29.
//
// So the surgical set is no longer the ceiling, it is the FLOOR. `install` keeps exactly its old meaning
// and is applied first; `closure` carries the rest of the declared devDependencies. `scaffold-install.mjs`
// applies them RESILIENTLY — whole batch first, then bisect — so a genuinely unresolvable spec costs only
// itself. Atomicity was never the reason to install less; it is the reason to install in recoverable batches.
//
// ⛔ WHY THE CLOSURE EARNS ITS COST rather than merely being more. The surgical set is derived by PARSING
// the script string, so it reaches only what a script NAMES. It cannot reach what a script REQUIRES at
// runtime — `node build.js` whose build.js pulls in `rollup` — which is exactly the ceiling the note lower
// in this header calls unreachable by any static parser. The author already wrote that set down: it is the
// declared devDependency closure. `observe-only.mjs` chases the same thing one error at a time with a retry
// loop, and the three measurement drivers have no retry loop at all.
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

// ⛔ THE CEILING, MEASURED RATHER THAN GUESSED. Validated end to end against all 105 ground-truth
// records with their real published manifests: 76 get an installable provider, 26 are named
// unprovidable with a reason, and exactly 3 are missed. All 3 are RUNTIME-DISCOVERED and no static
// script parser can reach them — `libpq@0.2.5` and `libpq@1.9.0` need `pg_config`, which the gyp
// binding file invokes, and `wrtc@0.4.7` declares `install: "node scripts/download-prebuilt.js"` and
// calls node-pre-gyp from inside that file. Do not "fix" these by pattern-matching package names;
// the honest disposition is a system-dependency class, which is a different mechanism from this one.

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
  // ⛔ THE THREE BELOW ARE NOT CONVENIENCES — WITHOUT THEM THE FALLBACK INSTALLS THE WRONG PACKAGE.
  // The last branch of the resolver is `spec = provider` with `provider` defaulting to the BIN NAME,
  // so a bin whose real provider is scoped resolves to whatever squats the bare name. Checked on the
  // registry 2026-09-01, and each bare name is actively harmful rather than merely absent:
  //
  //   nuxt-module-build  -> "🚫 Placeholder to prevent dependency confusion."  (a real published stub)
  //   pkg-utils          -> "Run clientside project in the browser", and its bin is `pkg`, not `pkg-utils`
  //   kiota              -> "security holding package", no bin at all
  //
  // All three ARE declared by the packages that need them, under the scoped name — so with an entry
  // here the resolver's earlier `declared[provider]` branch wins and the era-correct range is used
  // (@nuxtjs/sitemap@5.3.1 declares @nuxt/module-builder 0.8.1; @sanity/json-match@1.0.3 declares
  // @sanity/pkg-utils ^7.8.4; @keycloak/keycloak-admin-client@26.6.0 declares @kiota-community/kiota-gen
  // ^1.0.2). Each provider was confirmed to publish the bin named on the left.
  'nuxt-module-build': '@nuxt/module-builder',      // 4 records
  'pkg-utils': '@sanity/pkg-utils',                 // 2
  kiota: '@kiota-community/kiota-gen',              // 2
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
};

// ⛔ THE PACKAGE MANAGERS CAME OFF THAT LIST (2026-08-23). They sat there as "a different package
// manager; a corpus policy call, not a package defect" — but pnpm, yarn and bun ARE npm packages,
// and a package whose postinstall shells out to `pnpm` genuinely needs pnpm on any machine that
// installs it. Withholding it does not measure the package, it measures our refusal: 18 rows of the
// 2026-08-22 ledger die on exactly this, and their capability profile is unknown as a result.
// The corpus records what a package NEEDS; supplying a tool it invokes is the same act as supplying
// its era Node or its era Python.
//
// ⛔ AND `pulumi` CAME OFF IT ON 2026-09-01, BECAUSE ITS REASON WAS FACTUALLY FALSE. The entry read
// "external CLI distributed outside npm". There IS an npm package named `pulumi` — `npm view pulumi
// bin` returns `{"pulumi":"run.js"}`, a launcher that fetches the real CLI on first use — and it is
// the single largest remaining `command not found` blocker in the corpus: 11 rows of the 2026-08-22
// ledger, out of 67 in that whole class. Refusing them cost 11 unmeasured packages for a premise
// nobody rechecked. Grep before writing "not an npm package" into this table.
export const PACKAGE_MANAGERS = { pnpm: 'pnpm', yarn: 'yarn', bun: 'bun' };

/** Providers that must be resolved UNDATED, even though every other install in the arm is dated.
 *
 *  ⛔ MEASURED, AND THE DATED FORM IS SILENTLY USELESS RATHER THAN LOUDLY WRONG. `@pulumi/kubernetes@0.12.0`
 *  declares `install: "pulumi plugin install resource kubernetes v0.12.0"`, publish date 2018-04-25:
 *
 *    no tool          -> rc=127, `sh: pulumi: command not found`      (the record learns nothing)
 *    DATED   pulumi   -> resolves `pulumi@0.0.1`, a deprecated stub with NO bin at all -> still rc=127
 *    UNDATED pulumi   -> resolves 3.260.0, `pulumi` lands in `.bin`, rc=127 -> 1, and the script RUNS:
 *                        it fetches the 100 MB CLI and then fails 403 on the 2018 darwin-arm64 plugin
 *                        tarball, which is an attributable result about the PACKAGE.
 *
 *  The split is the one `era-resolution.mjs` already draws for npm itself — "resolve with a MODERN npm,
 *  execute with the ERA Node". A package's DEPENDENCIES are era-dated because they are what the author
 *  shipped against. The TOOLS its script invokes are not dependencies; they are the environment, and an
 *  environment is wanted in working order, not in period costume.
 *
 *  Deliberately narrow: a provider belongs here only when it is a self-updating launcher or a package
 *  manager, where the old published artifact is a stub or a security-expired shim. `tsc`, `rimraf` and
 *  `husky` are NOT here — their era version is the whole point (see the husky note above). */
export const UNDATED_TOOLS = new Set([...Object.values(PACKAGE_MANAGERS), 'pulumi']);

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

/** Script-file arguments a script hands to `node`, so the scan below can follow them.
 *
 *  Only the FIRST non-flag word after a bare `node` counts, and only when it looks like a relative
 *  path to a JS file. Anything else — a `-e` body, an absolute path, a bin shim — is left alone. */
export function nodeScriptTargets(script) {
  if (typeof script !== 'string') return [];
  const out = [];
  for (const segment of script.split(/&&|\|\||;|\|/)) {
    const words = segment.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++;
    if (words[i] !== 'node') continue;
    i++;
    while (i < words.length && words[i].startsWith('-')) i++;
    const target = words[i];
    // Relative, inside the package, and a JS file. `..` is refused: a script may only pull in its own.
    if (target && /^[.\w][\w./-]*\.[cm]?js$/.test(target) && !target.startsWith('/') && !target.includes('..'))
      out.push(target.replace(/^\.\//, ''));
  }
  return out;
}

/** Command names a JS file SPAWNS at runtime, read from the file's own source.
 *
 *  ⛔⛔ THIS IS THE `node <file>` CASE, AND IT IS 86% OF THE PULUMI CORPUS RATHER THAN A CORNER.
 *  `commandsIn()` reads the first word of a script segment, so `install: "node scripts/install-pulumi-
 *  plugin.js resource awsx v2.9.0"` yields `node` — which is AMBIENT — and the real requirement is
 *  never seen. MEASURED 2026-09-01 over all 86 `@pulumi/*` cells in `records-v2/runs`, against their
 *  published registry manifests:
 *
 *    script shape                                     cells   reached WITHOUT this scan
 *    `pulumi plugin install …`                          12          12
 *    `node scripts/install-pulumi-plugin.js …`          74           0
 *
 *  So the routing that put `pulumi` in `UNDATED_TOOLS` reaches one cell in seven, and `@pulumi/awsx@2.9.0`
 *  — the package the change was made for — is in the missed 74. The header note above calls this class
 *  "RUNTIME-DISCOVERED and no static script parser can reach them". That is true of a parser that reads
 *  the script STRING; it is not true of one that opens the file the string names, which is what this does.
 *
 *  ⛔ LITERAL FIRST ARGUMENTS ONLY, AND THAT IS THE WHOLE SAFETY ARGUMENT. It matches a quoted string
 *  in argument one of `spawn`/`spawnSync`/`execFile`/`execFileSync`, plus the leading word of an
 *  `exec`/`execSync` command string. A computed name (`spawnSync(bin, …)`) is deliberately invisible:
 *  the module's standing rule is that a missed binary is cheap and a wrongly-guessed one is not, and
 *  guessing here would install an unrelated package and let the record lie about its environment.
 *  It does not follow `require()` into a second file — one hop is what the measurement showed is needed. */
export function spawnedCommandsIn(source) {
  if (typeof source !== 'string') return [];
  const out = new Set();
  const add = (name) => {
    // A bare command name only. A path is the caller's own file, not a PATH lookup.
    if (name && /^[@a-z0-9][\w.@-]*$/i.test(name) && !name.includes('/')) out.add(name);
  };
  for (const m of source.matchAll(/\b(?:spawnSync|spawn|execFileSync|execFile)\s*\(\s*(['"])([^'"]+)\1/g))
    add(m[2]);
  // `exec`/`execSync` take a whole command LINE, so only its first word is a binary.
  for (const m of source.matchAll(/\b(?:execSync|exec)\s*\(\s*(['"])([^'"]+)\1/g))
    add(m[2].trim().split(/\s+/)[0]);
  return [...out];
}

/** Follow the script graph the way npm actually executes it.
 *
 *  ⛔ TWO RULES, AND BOTH WERE MISSED BY THE FIRST VERSION — each cost real records in the
 *  end-to-end validation over the 105 ground-truth cases.
 *
 *  1. npm runs `pre<x>` and `post<x>` AROUND every `<x>`. `postcss-cssnext@3.0.1` declares
 *     `postinstall: "npm run babelify"` and `prebabelify: "rimraf lib"` — so `rimraf` is invoked by
 *     an install, and a resolver that follows only `babelify` never sees it. That package's record
 *     says `sh: rimraf: command not found`, so the miss was not theoretical.
 *  2. A package manager name at the head of a script is BOTH a chain to follow AND a binary the arm
 *     must supply. `@rspack/core@0.0.26` declares `postinstall: "pnpm precompile-schema"`: the chain
 *     leads to plain `node`, so the ONLY thing the script actually needs is `pnpm` itself. Dropping
 *     the PM name as noise loses the entire requirement — 6 of the 14 validation misses were this. */
export function resolveScriptCommands(scripts, entry, seen = new Set()) {
  if (!scripts || seen.has(entry) || !(entry in scripts)) return [];
  seen.add(entry);
  const found = [];
  // npm's own pre/post wrapping, before and after the script body.
  for (const sibling of [`pre${entry}`, `post${entry}`])
    if (sibling in scripts) found.push(...resolveScriptCommands(scripts, sibling, seen));

  const words = String(scripts[entry]).split(/\s+/);
  for (let i = 0; i < words.length - 1; i++) {
    const w = words[i], next = words[i + 1];
    if (next.startsWith('-')) continue;
    // `npm run x` / `yarn run x` / `pnpm run x`, and the bare `yarn x` / `pnpm x` forms.
    const isRunWord = w === 'run' && /^(npm|yarn|pnpm)$/.test(words[i - 1] ?? '');
    const isBareForm = /^(yarn|pnpm)$/.test(w) && next in scripts;
    if (isRunWord || isBareForm) found.push(...resolveScriptCommands(scripts, next, seen));
  }
  found.push(...commandsIn(scripts[entry]));
  return found;
}

/** Shell builtins and coreutils a lifecycle script may legitimately call. Never scaffolded. */
const AMBIENT = new Set([
  'rm', 'cp', 'mv', 'mkdir', 'cd', 'echo', 'cat', 'test', 'true', 'false', 'exit', 'set', 'sh',
  'bash', 'node', 'env', 'sed', 'awk', 'grep', 'find', 'chmod', 'ln', 'touch', 'tar', 'curl',
  'wget', 'git', 'make', 'python', 'python3', 'cmake', 'pwd', 'ls', 'if', 'then', 'else', 'fi',
  'for', 'do', 'done', 'while', 'case', 'esac', 'exec', 'printf', 'which', 'command',
  // Both ship with every arm: npm IS the installer running the script, and it bundles node-gyp.
  // The OTHER package managers are deliberately NOT here — see UNPROVIDABLE.
  'npm', 'node-gyp',
]);

/** What the observe arm should install alongside `manifest`'s package so its lifecycle scripts can run.
 *
 *  Returns `{ install, tools, closure, unprovidable, ambient }`. The three install lists are SEPARATE
 *  because they are applied differently, and collapsing them would lose exactly the distinctions that
 *  were measured into them:
 *
 *    install  — the binaries the lifecycle scripts NAME. Era-DATED, applied FIRST, and the one list
 *               whose failure is worth reporting loudly. Unchanged in meaning from before `closure`
 *               existed, so a record's old `ARM-SCAFFOLD` line still means what it always meant.
 *    tools    — the subset of the above whose provider is in `UNDATED_TOOLS`. Same specs, resolved
 *               without `--before`; see that constant for the pulumi measurement.
 *    closure  — the rest of the declared devDependencies and peerDependencies. Era-dated, BEST-EFFORT:
 *               this is the list that supplies what a script requires at RUNTIME rather than names.
 *
 *  `unprovidable` and `ambient` exist so the RECORD can state why a binary was left unsatisfied instead
 *  of leaving the reader to infer it from a failure. */
export function scriptScaffold(manifest, { has = () => false, readFile = () => null } = {}) {
  const scripts = manifest?.scripts ?? {};
  const declared = { ...(manifest?.devDependencies ?? {}), ...(manifest?.peerDependencies ?? {}) };
  const own = new Set([
    ...Object.keys(manifest?.dependencies ?? {}),
    ...Object.keys(manifest?.optionalDependencies ?? {}),
  ]);

  const wanted = new Set();
  for (const entry of LIFECYCLE) for (const c of resolveScriptCommands(scripts, entry)) wanted.add(c);

  // ⛔ ONE HOP INTO `node <file>`, AND ONLY WHEN THE CALLER SUPPLIED A READER. `readFile` defaults to
  // returning null so every existing caller — and every test that passes a bare manifest — keeps the
  // old plan exactly. The drivers reach the real files through `scaffold-install.mjs`, which is the
  // one place that already knows where the subject is unpacked.
  for (const entry of LIFECYCLE) {
    if (!(entry in scripts)) continue;
    for (const rel of nodeScriptTargets(String(scripts[entry]))) {
      let src = null;
      try { src = readFile(rel); } catch { src = null; }
      if (typeof src === 'string') for (const c of spawnedCommandsIn(src)) wanted.add(c);
    }
  }

  const install = [], tools = [], unprovidable = [], ambient = [];
  const named = new Set();     // providers already covered by `install`, so `closure` cannot duplicate them
  for (const bin of wanted) {
    if (AMBIENT.has(bin) || bin.startsWith('./') || bin.startsWith('/') || bin.includes('/')) { ambient.push(bin); continue; }
    if (own.has(bin) || has(bin)) continue;                       // already reachable in the tree
    if (bin in UNPROVIDABLE) { unprovidable.push({ bin, why: UNPROVIDABLE[bin] }); continue; }
    // The package's OWN declared range wins — it is the era-correct one. See the header note on husky.
    const provider = BIN_TO_PACKAGE[bin] ?? bin;
    let spec = null;
    if (declared[provider]) spec = `${provider}@${declared[provider]}`;
    else if (declared[bin]) spec = `${bin}@${declared[bin]}`;
    else if (BIN_TO_PACKAGE[bin] || /^[@a-z0-9][\w.@/-]*$/i.test(bin)) spec = provider;
    else { unprovidable.push({ bin, why: 'no provider known and the name is not a valid package name' }); continue; }
    named.add(provider);
    named.add(bin);
    // ⛔ AN UNDATED TOOL GOES IN `tools` BY BARE NAME AND NOT IN `install`, never both. It is listed
    // without the manifest's range on purpose: a package that declares `pnpm: "^6"` and also shells out
    // to it wants a WORKING pnpm, and carrying the range here would re-impose the era through the back
    // door and reproduce the `pulumi@0.0.1` stub result exactly. Putting it in only ONE list is what
    // keeps the two installs from racing to overwrite each other in an order nothing pins.
    if (UNDATED_TOOLS.has(provider)) tools.push(provider);
    else install.push(spec);
  }

  // Everything else the author declared. Ranges are kept — for a DEPENDENCY the era range is the point.
  const closure = [];
  for (const [name, range] of Object.entries(declared)) {
    if (named.has(name) || own.has(name)) continue;
    closure.push(typeof range === 'string' && range ? `${name}@${range}` : name);
  }

  return { install, tools, closure, unprovidable, ambient };
}
