// Turn a v2 driver's STDOUT into a corpus record.
//
// ⛔ THE THREE DRIVERS PRINT; NONE OF THEM WRITES A RECORD. `measure.sh`, `measure-macos.sh` and
// `measure-windows.mjs` were each built to be read by a human on a probe branch, so every v2 result
// so far has lived in a workflow log that expires. A queue-driven lane needs a durable artifact per
// (platform, pkg, version), and that artifact has to be shaped like a v1 record or nothing
// downstream can read it: `collate.mjs` keys on `rec.grant` / `rec.verdict` / `provenance.platform`
// and takes repeated `--runs <dir>`, and `claim-slice.mjs --reconcile` keys on the same three. So
// this parses the driver's own terminal vocabulary into that shape rather than inventing one.
//
// ⛔ THE THREE VOCABULARIES DIFFER AND ONE PAIR IS A FALSE FRIEND. The POSIX drivers print
// `=> VERIFIED <grant>` where the Windows driver prints `=> MINIMUM <grant>   (observed, then
// verified)` for the SAME outcome, and the Windows driver ALSO prints `=> MINIMUM <grant>
// (ladder fallback; ...)` for a materially different one — a grant OBSERVE under-predicted and the
// ladder repaired. Keying on the word `MINIMUM` alone therefore merges the arm that proves synthesis
// works with the arm that proves it failed. `verifiedBy` keeps them apart in the record; the verdict
// stays `MINIMUM` so a v2 record collates through the existing catalog builder unchanged.
//
// ⛔ A DRIVER THAT PRODUCES NO TERMINAL LINE IS AN INSTRUMENT FAILURE, NOT AN EMPTY GRANT. It gets a
// `HARNESS-*` verdict, which `claim-slice.mjs` deliberately refuses to close a queue row on — the
// row returns to `pending` so a later fix can reach it. Emitting `null` here instead would bake the
// harness's own failure into the corpus as a measurement, which is the thing this project exists to
// prevent.
//
//   usage: node record.mjs --log <driver-stdout> --pkg <p> --version <v> --out <dir> [--rc <n>]
//                          [--platform <p>] [--duration-ms <n>] [--nub-sha <sha>] ...

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { observedEffect } from './observed-effect.mjs';
import { execFileSync } from 'node:child_process';
import { computeHarnessIdentity, loadInstrumentConfig, REPO_ROOT } from './instrument.mjs';
import { collectRuntimeProvenance, fileIdentity } from './runtime-provenance.mjs';
import { digestSpecs } from '../osv-screen.mjs';
// ⛔ A LEAF, AND IT HAS TO BE ONE. `stale-adjudication.mjs` imports `parseDriverLog` from this file,
// so putting the write census there and importing it back is a CYCLE — and a cycle here does not
// throw, it hands the importer `undefined` from the temporal dead zone and the guard silently never
// fires. `write-census.mjs` imports nothing from the harness for exactly that reason.
import { CENSUS_REFUSE, homeDropVerdict } from './write-census.mjs';
// The same leaf discipline for the same reason, on the axis the artifact gate is blindest to. See
// the long note on the network override at the foot of `applyGrantSourceRule`.
import { NET_CLEAR, NET_UNKNOWN, networkDropVerdict } from './network-census.mjs';

// A grant is a JSON object with no string values containing braces, so brace-depth scanning is
// exact. `JSON.parse` on a regex-sliced tail is not: `(observed, then verified)` trails the object
// on every VERIFIED line and a greedy match swallows it.
export const firstObject = (line) => {
  const start = line.indexOf('{');
  if (start < 0) return null;
  let depth = 0;
  for (let i = start; i < line.length; i++) {
    if (line[i] === '{') depth++;
    else if (line[i] === '}' && --depth === 0) {
      try { return JSON.parse(line.slice(start, i + 1)); } catch { return null; }
    }
  }
  return null;
};

// ⛔ WHICH HARNESS MEASURED THIS — DERIVED, NOT ONLY DECLARED. `corpusGitSha` came exclusively from
// `--corpus-sha`, so any caller that forgot the flag silently produced a record that cannot say
// which harness produced it. That is mission property 4 ("nothing measured by a harness we have
// since fixed") failing quietly, and it failed for a hand-run re-measure on 2026-08-07: the record
// landed with `corpusGitSha: null` and nothing flagged it.
//
// The flag still WINS when passed — a caller that knows better (a CI job checking out a specific
// ref) is not second-guessed. This only fills the gap where the answer was `null`.
function corpusShaFromCheckout() {
  const git = (args) => execFileSync('git', ['-C', REPO_ROOT, ...args],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  try {
    // ⛔⛔ HEAD IS NOT THE HARNESS unless the harness matches it. A measuring box is updated with
    // `git checkout origin/main -- harness/`, a PATHSPEC checkout that deliberately does NOT move
    // HEAD — that is precisely what makes it safe to run on a box whose record tree must not be
    // touched. Reading HEAD there would name an OLDER commit than the code that actually ran, and a
    // wrong sha is worse than no sha: `null` says "I cannot tell you", a stale sha asserts something
    // false and nothing downstream can detect it. Caught 2026-08-07 on `nub-corpus-linux`, whose
    // HEAD said `e546d433` while its harness was `04ed4365`.
    // `git diff` ignores untracked files. A newly copied helper is still executable harness input,
    // so status (with untracked files expanded) is the only honest cleanliness check here.
    const status = git(['status', '--porcelain', '--untracked-files=all', '--',
      ...loadInstrumentConfig(REPO_ROOT).inputs]);
    if (status) return null;
    return git(['rev-parse', 'HEAD']) || null;
  } catch {
    // Either not a checkout / no git, or `diff --quiet` exited non-zero meaning the harness differs
    // from HEAD. Both are honestly "I cannot name the commit that produced this".
    return null;
  }
}

/** Load the exact spec list out of each per-screen clearance artifact and deduplicate identical
 * resolved trees. Absolute temporary paths never enter the record. */
export function hydrateResolvedTrees(screens, read = (file) => JSON.parse(fs.readFileSync(file, 'utf8'))) {
  const trees = new Map();
  for (const screen of screens) {
    if (!screen?.clearancePath) throw new Error(`OSV screen ${screen?.kind ?? '<unknown>'} has no clearance artifact`);
    const clearance = read(screen.clearancePath);
    if (!Array.isArray(clearance.specs) || digestSpecs(clearance.specs) !== screen.digest
      || clearance.specCount !== screen.specCount || clearance.kind !== screen.kind) {
      throw new Error(`OSV screen ${screen.kind} clearance artifact does not match its marker`);
    }
    const lockfiles = clearance.lockfiles ?? { digest: null, files: [] };
    const key = `${screen.digest}\0${lockfiles.digest ?? ''}`;
    const existing = trees.get(key);
    if (existing) {
      existing.kinds.push(screen.kind);
      continue;
    }
    trees.set(key, {
      digest: screen.digest,
      specCount: screen.specCount,
      specs: clearance.specs,
      lockfiles,
      kinds: [screen.kind],
      screenedAt: screen.screenedAt,
    });
  }
  return [...trees.values()].map((tree) => ({ ...tree, kinds: [...new Set(tree.kinds)].sort() }));
}

const VERDICTS = {
  'REFUSED-MALICIOUS': /=>\s*REFUSED-MALICIOUS/,
  'BROKEN-WITHOUT-JAIL-TOO': /=>\s*BROKEN-WITHOUT-JAIL-TOO/,
  'NO-STATE-PASSED': /=>\s*NO-STATE-PASSED/,
  // ⛔ nub cannot install the package even with the jail OFF, so the ladder's failures are not
  // capability evidence. Distinct from BROKEN-WITHOUT-JAIL-TOO, which keys on `npm rebuild`: this
  // one keys on the program the verify arms actually run. Neither collates.
  'BROKEN-UNJAILED-NUB': /=>\s*BROKEN-UNJAILED-NUB/,
  VOID: /=>\s*(?:⛔\s*)?VOID/,
  UNKNOWN: /=>\s*UNKNOWN\b/,
  'OBSERVE-ONLY': /=>\s*OBSERVE-ONLY/,
  'HARNESS-TIMEOUT': /=>\s*TIMED-OUT/,
  'HARNESS-ERROR': /=>\s*(?:HARNESS-ERROR|CAPTURE FAILED|PARSE FAILED)|SYNTHESIZE FAILED|DTRACE NEVER STARTED/,
};

// ⛔⛔ THE ARM RESOLVED TODAY'S DEPENDENCIES AND THEN RAN THEM ON AN ERA NODE THAT CANNOT PARSE THEM.
//
// The harness dates the npm arms with `--before` (`measure.sh:487`, applied at 489, 563 and 2054) so
// they resolve the dependency versions that existed when the package shipped. NO `nub install` is
// dated anywhere, and nub has no `--before` equivalent to pass -- `minimumReleaseAge` is a FLOOR on
// package age, not a ceiling on publish date. So every nub arm resolves TODAY's versions into a tree
// running an era Node, which is precisely the failure `measure.sh:2038` already describes for the npm
// reference arm: "Undated resolution alone pulls TODAY's dependency versions into a tree pinned to
// nothing, which is the exact failure `--before` was added at line 487 to stop."
//
// MEASURED on `electron-prebuilt@0.28.3` (run 33319235832, the first log epoch 38 preserved): the
// era-dated npm OBSERVE arm resolved 108 packages and installed cleanly on Node 4.9.1; every nub arm
// resolved 146 and every one failed, because `psl@1.15.0` throws `SyntaxError: Unexpected token ...`
// on a spread operator under Node 4. Nub warned about it itself -- `punycode@2.3.1: wanted node >=6,
// got 4.9.1` -- and nobody had ever seen the line, because withheld driver logs were deleted with the
// runner until epoch 38.
//
// ⛔ THIS DETECTOR CHANGES NO VERDICT, AND THAT IS DELIBERATE. The root fix is dated resolution in
// nub, which the corpus cannot validate because it PINS its subject binary. Rewriting verdicts on a
// heuristic, mid-drain, is the kind of change that is hard to undo -- so this makes the class
// COUNTABLE on every future measurement instead, which is what the macOS and windows lanes (3900 rows
// still ahead, and the same old-package population) actually need. Epoch 34's lesson: when a fix
// rests on an unknown mechanism, ship the instrument that measures it.
//
// It reads the RAW log on purpose. `parseDriverLog` strips `    | ` echoed lines because a package's
// own output must never be read as a verdict -- and those echoed lines are exactly where nub's warning
// and the dependency's stack trace live.
// ⛔⛔ THE FILE PATHS NODE PRINTS ABOVE A PARSE ERROR — SCANNED FORWARD FROM THE SUFFIX, NEVER WITH
// A GREEDY PREFIX. Epoch 40 wrote this as `/(\S*\/\S+\.(?:c|m)?js):\d+/g` and shipped a CUBIC
// blowup into the instrument: two unbounded `\S` quantifiers ahead of a literal suffix means that on
// any whitespace-free run WITHOUT a match, the engine tries every split of that run. Measured on that
// shape: 1,500 chars costs 228 ms, 2,000 costs 537 ms, 3,000 costs 1,805 ms, 4,000 costs 4,273 ms --
// doubling the token multiplies the cost by eight.
//
// MEASURED on `@vscode+windows-process-tree@0.8.0` (darwin, 25 KB log): the old pattern took
// **5,556 ms and returned ZERO matches**, while the warning regex beside it took 0.3 ms. The trigger
// is a 5,532-character token with no whitespace in it -- a node-gyp `.deps` line listing every
// include path -- and every native-build package emits one.
// Across 817 real logs the detector averaged 52 ms of pure backtracking each. `record.mjs` runs
// under a 120 s budget per record, and a token twice that long costs EIGHT times as much, so this
// was a live path from "a package uses node-gyp" to HARNESS-TIMEOUT on a measurement that was fine.
//
// Scanning from the `.js:<line>` suffix and walking back to whitespace is linear and has no
// quantifier ahead of a literal at all. The `/`-must-be-present test moved out of the pattern and
// into code for the same reason: it is a structural check, not something to make the engine search
// for. Caller short-circuits on `syntaxError` too -- the result is only ever read on that branch,
// so the common log now pays nothing here.
function loadPaths(log) {
  const out = [];
  for (const line of log.split('\n')) {
    for (const m of line.matchAll(/\.(?:c|m)?js:\d+/g)) {
      let i = m.index;
      while (i > 0 && !/\s/.test(line[i - 1])) i--;
      const p = line.slice(i, m.index) + m[0].slice(0, m[0].indexOf(':'));
      if (p.includes('/')) out.push(p);
    }
  }
  return out;
}

export function detectEraDepMismatch(log) {
  // Nub's own engine warning. Three shapes are observed and all three must match, which is why the
  // version is a full semver rather than a bare major: spacing varies (`node >=6` and `node >= 6`),
  // and the bound may be `>=6` OR `>=16.20.0`. Requiring `(\d+),` matched the first two and silently
  // dropped `eslint-plugin-functional@4.0.0-rc1`'s `wanted node >=16.20.0, got 14.21.3` — caught only
  // because a loose hand count said 18 and this said 17.
  const warned = [...log.matchAll(/^\s*\|?\s*warn:\s+(\S+):\s+wanted node\s*>=?\s*(\d+)(?:\.\d+)*\s*,\s*got\s+(\S+)/gm)]
    .map((m) => ({ spec: m[1], wantsMajor: Number(m[2]), got: m[3] }));
  // A parse failure raised while LOADING A FILE is Node printing `<path>:<line>` immediately before
  // the offending source and the `SyntaxError`. WHICH path it is separates two DIFFERENT defects,
  // and an early version of this conflated them — it matched any `node_modules/...js:N` anywhere in
  // the log and fired on 75 `MINIMUM` records against a hand count of 6, which is what a filter
  // producing a surprising split looks like.
  //
  //   dependency — the path is under the content-addressed package STORE. This is the finding above:
  //                an undated resolution put a modern dependency in a tree running an era Node.
  //   toolchain  — the path is the runner's own npm out of the hosted toolcache. A DIFFERENT defect,
  //                measured on `cldr-data@26.0.9` (darwin): era Node 4 execing Node 22's npm, which
  //                dies on `const { enableCompileCache } = require('node:module')`. Nothing to do
  //                with dependency dating; recorded separately rather than folded in, because a
  //                single number covering both would be actionable for neither.
  // ⛔ TWO SPELLINGS, AND THE SECOND IS THE ONE A MODERN DEPENDENCY PRODUCES. Top-level `await`
  // under an era Node raises `Unexpected reserved word`, not `Unexpected token`, so the original
  // single needle missed exactly the shape this classifier exists to find.
  //
  // MEASURED 2026-08-31 across all 6,880 driver logs: 3 name `Unexpected reserved word`. 2 of them
  // also name a store path and are real dependency mismatches (`spectron@11.1.0` and `@12.0.0`,
  // both `puppeteer@25.9.0/install.mjs`); the third names neither a store nor a harness path and
  // stays unclassified, which is the conservative answer.
  //
  // ⛔ THE HARNESS-SELF-FAILURE HAZARD IS REAL BUT EXTINCT, AND THE PATH TEST IS WHAT SEPARATES
  // THEM. `measure.sh:104` records that this same string was once produced by the harness's OWN
  // `arm-cap.mjs` running under an era Node with a rewritten PATH — fixed by resolving
  // `HARNESS_NODE` absolutely. Of the 3 logs above, **0** name a harness path. The separation does
  // not rest on that fix holding, though: a dependency is only reported when a STORE path is the
  // one that failed to load, and a harness self-failure names a harness path.
  const syntaxError = /SyntaxError: (?:Unexpected token|Unexpected reserved word)/.test(log);
  const loading = syntaxError ? loadPaths(log) : [];
  // ⛔ `[./]store/`, BECAUSE THERE ARE TWO STORE LAYOUTS AND ONLY ONE WAS MATCHED. The shared cache
  // is `…/pm/store/<slug>@<ver>-<hash>/…`; the PROJECT-LOCAL layout is
  // `…/node_modules/.store/<slug>@<ver>/…`, and `/store/` cannot match `/.store/` — the `.` sits
  // between the slash and the word. `storeLayout` is an observed field precisely because both occur.
  //
  // MEASURED 2026-08-31: 7 logs name a `.store` path beside a SyntaxError, and 5 of them name NO
  // shared-store path at all, so they were classified as having no dependency mismatch when they
  // plainly do — `@bazel/cypress@2.3.3` and `@3.8.0` and `subrequests@2.9.2` (`Unexpected token`),
  // `spectron@11.1.0` and `@12.0.0` (`Unexpected reserved word`).
  //
  // ⛔ EXCLUDE THE HARNESS'S OWN TOOLS DIR, WHICH THIS WIDENING NEWLY REACHES. nub provisions
  // node-gyp into `…/pm/tools/node-gyp/v<N>/node_modules/.store/node-gyp@<ver>/…`, which the old
  // `/store/` needle missed by accident and `[./]store/` would match. That is harness tooling, not
  // a package's dependency, and folding it in would report a defect against the wrong subject —
  // the same conflation the comment above says this split exists to prevent. `lzo@0.1.1` is the
  // observed case; it is unaffected today only because its error is Python's `invalid syntax`.
  const dependency = syntaxError
    ? loading.find((p) => /[./]store\//.test(p)
      && !/\/node_modules\/npm\//.test(p)
      && !/\/pm\/tools\//.test(p)) ?? null : null;
  const toolchain = syntaxError
    ? loading.find((p) => /hostedtoolcache|\/node_modules\/npm\//.test(p)) ?? null : null;
  if (!warned.length && !dependency && !toolchain) return null;
  return { warned, storeSyntaxError: dependency, toolchainSyntaxError: toolchain };
}

export function parseDriverLog(log) {
  // ⛔ A QUOTED LINE IS PACKAGE OUTPUT, NEVER A VERDICT. The jail-off control echoes what nub said
  // with a `    | ` prefix so a real nub defect and a harness asymmetry stop leaving byte-identical
  // records. But every verdict pattern below is UNANCHORED -- `/=>\s*VERIFIED\s/` and 16 siblings --
  // even though the drivers' own comments say the parser "keys every verdict on a LEADING `=>`".
  // Code and comment disagreed, so a `=>` ANYWHERE in a line an arbitrary package printed could be
  // read as a verdict, and the LAST match wins.
  //
  // Filtering here rather than anchoring 17 regexes: it states the intent once, and one of those
  // patterns carries alternatives that do NOT involve `=>` at all (SYNTHESIZE FAILED, DTRACE NEVER
  // STARTED), which a blanket `^\s*` would silently re-scope.
  //
  // MEASURED across all 6880 driver logs before landing: 2958 echoed lines in 135 files, of which
  // ZERO currently match any verdict pattern. So this changes no existing record and closes the hole
  // for every future one. (Anchoring instead was measured too: also 0 divergent lines.)
  const ECHOED_LINE = /^\s*\|\s/;
  const lines = log.split('\n').filter((l) => !ECHOED_LINE.test(l));
  const out = {
    // ⛔ COMPUTED FROM THE RAW `log`, NOT FROM `lines`. The evidence lives in the echoed lines the
    // filter above removes. Null when nothing was detected; never guessed.
    eraDepMismatch: detectEraDepMismatch(log),
    verdict: null,
    grant: null,
    synthesized: null,
    verifiedBy: null,
    minimality: null,
    overPredictedBy: [],
    // ⛔ NULL AND FALSE ARE BOTH "NOT ESTABLISHED", AND THE RULE BELOW TREATS THEM THAT WAY. A log
    // predating `arm-falsifiability.mjs` carries no marker, so `falsifiabilityReasons` stays null and
    // no narrowing is licensed off it — the same absent-is-not-empty direction the `checked` flag
    // already takes. `descentRedArm` starts false because "no arm was announced red" is exactly what
    // an absent announcement means.
    falsifiabilityReasons: null,
    // ⛔ SEPARATE FROM `falsifiabilityReasons` EVEN THOUGH BOTH ARRIVE ON THE SAME MARKER, because
    // they answer different questions and one is `null` far more often than the other. `reasons`
    // says which detector died; this says whether npm had anything to run at all, which is what
    // `observed-effect.mjs` needs to tell "the script did nothing" from "there was no script".
    declaresInstallWork: null,
    // ⛔⛔ WAS THE PACKAGE EVEN IN THE TREE THE ARMS RAN AGAINST? Every other field here asks how much
    // a green arm proves; this one asks the prior question, and when the answer is no, none of the
    // others is measuring the subject at all. The observe arm is `npm rebuild <pkg>`: run against a
    // tree that does not contain `<pkg>` it executes nothing, the decoder attributes zero lifecycle
    // pids, and the synthesized grant is `{}` — byte-identical to the grant of a package that
    // genuinely needs nothing, so the record lands MINIMUM off a run that never happened.
    // `subject-survives-scaffold.test.mjs` carries the measurement and the drivers' refusal branch.
    //
    // THREE STATES, and `false` is the only one that refuses anything:
    //
    //   true    the marker carried a numeric `manifestFiles` — `arm-falsifiability.mjs` resolved the
    //           package's directory in the observe tree and walked it.
    //   false   it carried `manifestFiles: null` — that file's `pkgDir()` found no layout for the
    //           subject at all, so the arms measured a tree without it.
    //   null    no marker, or a marker predating the field. NOT ESTABLISHED, and it has to stay
    //           distinguishable from `false` forever: 1,220 of the 6,887 committed logs carry no
    //           marker at all, so a consumer that read absent as absent-SUBJECT would floor the
    //           entire corpus.
    //
    // ⛔ A TRI-STATE BOOLEAN RATHER THAN THE RAW COUNT, AND THAT IS THE WHOLE SAFETY ARGUMENT. Carried
    // verbatim, the alarm value would be `manifestFiles === null` — one loose `== null` or `!x` at
    // any future consumer then turns "unknown" into "evicted" for every marker-less record. Here
    // `=== false` is the only refusal and no falsy-test can reach it by accident.
    subjectInObserveTree: null,
    // ⛔ THE COUNTS HALF, FROM THE `OBSERVED-EFFECT` MARKER ALL THREE CLASSIFIERS EMIT. Null means the
    // record predates the marker, and `observedEffect()` reads that as UNKNOWN — which vetoes
    // nothing, so every existing record keeps the behaviour it was measured under.
    observedCounts: null,
    descentRedArm: false,
    // ⛔ cap -> verdict, from the DENIAL-WITNESS markers the descent arms emit. An EMPTY map means no
    // arm was witnessed — which is what every record taken before `denial-witness.mjs` existed looks
    // like, and what every win32 record will look like until that platform grows a jailed trace — so
    // an empty map must license nothing and block nothing. Same absent-is-not-empty direction as
    // `falsifiabilityReasons` above.
    denialWitness: {},
    // ⛔⛔ THE ONE AXIS NO OTHER DETECTOR CAN SEE. `writePaths` grants nothing — `catalog_v2.rs` says
    // it "cannot decide whether a write SUCCEEDS, only whether the result is KEPT" — so `rc` cannot
    // fail for it, `artifact-gate.mjs` is scoped to the package's OWN directory and never looks in
    // the home, and `denial-witness.mjs` scores refusals where a dropped promotion produces none. A
    // grant that is `{"writePaths":[…]}` therefore flattens to ZERO capability tokens in
    // `publish-guard.mjs` and can never carry a red arm, which withholds every narrowing to it.
    //
    // `promotion-probe.mjs` runs the pair that fixes that — the grant WITH the declaration and the
    // same grant WITHOUT it, each against its own fresh real home — and this is where its verdict
    // lands. NULL is "not established": every record taken before the probe existed carries no
    // marker, and a null must license nothing. Same absent-is-not-empty direction as the three fields
    // above.
    promotionProbe: null,
    notes: [],
    rawLogPath: null,
    capturePath: null,
    eventLogPath: null,
    eventLog: null,
    // Venue-portability R3/R6. Null rather than guessed: a driver that does not report these has
    // not measured them, and inventing a value here would make an unmeasured field indistinguishable
    // from a measured one.
    storeLayout: null,
    interpreterPath: null,
    overrides: null,
    // ⛔ WHICH DERIVED `writePaths` ENTRIES EMBED THE MEASURED VERSION. `collate.mjs` already reads
    // `writePathsVersionPinned` off a record and turns it into a re-measure note — that reader has
    // existed since v1 and has been inert for every v2 record, because no v2 driver emitted the
    // marker. An entry like `.cache/foo-1.2.3` names a directory that MOVES on the next release, so
    // without this the catalog would ship an entry that silently stops matching. Empty ARRAY, not
    // null: the classifier always answers this question now, so "no pinned entries" is a measured
    // answer rather than an absence.
    writePathsVersionPinned: [],
    // ⛔⛔ DID A WIDE GRANT WORK WHILE THE SANDBOX WAS STILL ENGAGED? This is the field that separates
    // "this package needs a wide write scope" from "this package cannot run confined at all" — a
    // distinction the ladder could not draw, because its terminal rung `write:"disk"` is not a wider
    // sandbox but NO sandbox (`relax_fs_to_full_disk` clears `entries`, sets `default_effect = Allow`
    // and puts tmp back to Shared, and each backend then stands down). Every `write:"disk"` record in
    // this corpus was produced by that rung, so every one of them is currently ambiguous.
    //
    // ⛔ NULL IS "NOT ESTABLISHED" AND MUST LICENSE NOTHING. A record predating the probe carries no
    // marker; a record whose confined rungs PASSED never needed one, because the ladder stopped before
    // the probe. Both are null, and null must never be read as `fail` — that would publish "cannot run
    // confined" off an arm that was never run. Same absent-is-not-empty direction as
    // `falsifiabilityReasons` and `denialWitness`.
    //
    // ⛔ THE PROBE NEVER NARROWS A GRANT, BY CONSTRUCTION. Its widening is delivered through the
    // catalog's GLOBAL `baseline`, and the shipped per-package vocabulary (`catalog_v2::Reach` is
    // `None | Scopes | Disk`) has no spelling for one — so a grant it passed at is not publishable, and
    // the terminal rung still decides what the record ships. This field is diagnosis, never a licence.
    confinedWide: null,
    // ⛔ WHY THE DESCENT ASKED NOTHING, when it asked nothing. Null on every record whose descent had
    // terms to run and on every record taken before the marker existed — absent is "not established",
    // never "supported". Set only from the driver's own `DESCENT-UNSUPPORTED` payload, so a reader can
    // separate a venue that CANNOT test an axis from a run that merely did not.
    descentUnsupported: null,
    // Every completed direct/resolved-tree OSV screen prints one compact marker. The exact spec set
    // stays in the clearance artifact during the run; the record persists the digest/count and every
    // advisory that caused a terminal refusal.
    securityScreens: [],
    maliciousAdvisories: [],
    // ⛔ WHERE THE JAILED ARMS RAN. Two records from different venues can agree on every other field
    // and still have been measured under filesystem roots with different ACLs — and on Windows that
    // is not hypothetical: any jail root under `C:\Users\<user>` fails before a single script runs
    // with "could not evaluate ALL APPLICATION PACKAGES rights on …: The access control list (ACL)
    // structure is invalid. (os error 1336)", because that home carries seven inheritable
    // `S-1-15-2-…` AppContainer package SIDs. MEASURED: only the root path changed between the
    // failing and passing runs. So a record that does not name its jail root cannot distinguish
    // "this package needs a wider grant" from "this run was rooted somewhere the jail cannot build a
    // token", and a reader comparing two venues would attribute the second to the first.
    jailRoot: null,
    observeUser: null,
    ciChild: null,
    xdgChild: null,
    cwdUnplaceableWrites: null,
    cwdResolved: null,
    nubBinary: null,
    nodeSelection: null,
    // ⛔ NULL HERE MEANS "THE DRIVER EMITTED NO MARKER", AND IT NEVER REACHES THE RECORD AS NULL.
    // `venueProvenance` substitutes an explicit negative, because a null in a field whose entire job
    // is to say "nobody checked" is indistinguishable from the field not existing yet.
    netEnforcement: null,
  };

  let synthesizedNext = false;
  for (const l of lines) {
    const security = /^OSV-SCREEN\s+(\{.*\})\s*$/.exec(l);
    if (security) {
      try {
        const parsed = JSON.parse(security[1]);
        out.securityScreens.push(parsed);
        for (const finding of parsed.maliciousAdvisories ?? []) {
          if (finding?.spec && Array.isArray(finding.ids)) out.maliciousAdvisories.push(finding);
        }
      } catch { out.notes.push('osv-screen-marker-unparsable'); }
      continue;
    }
    // ⛔ THE RETAINED EVENT LOG. The driver writes the file and prints its PATH; this reader only
    // learns where it is. That keeps the contract at two stdout lines, so a platform adopts
    // retention by printing them and this file never learns a trace format.
    // ⛔ THE RAW TRACER OUTPUT IS THE ARTIFACT OF RECORD; the normalized event log below it is a
    // derived cache. A normalized stream bakes in today's DECODER the way a scope tag bakes in
    // today's classifier — and both of those decoders have already been measured losing events
    // silently. With the raw kept, a decoder bug is a re-parse; without it, a permanent hole.
    const rwf = /RAWLOG-FILE\s+(\S+)/.exec(l);
    if (rwf) { out.rawLogPath = rwf[1]; continue; }
    // A raw trace with unknown capture parameters is worth much less than it looks: "no `linkat`
    // records" means `linkat` never fired under one adapter revision and was never SUBSCRIBED under
    // another, and nothing in the byte stream tells them apart.
    const rwc = /RAWLOG-CAPTURE\s+(\S+)/.exec(l);
    if (rwc) { out.capturePath = rwc[1]; continue; }
    if (/RAW TRACE NOT RETAINED/.test(l)) out.notes.push('rawlog-missing');
    const evf = /EVENTLOG-FILE\s+(\S+)/.exec(l);
    if (evf) { out.eventLogPath = evf[1]; continue; }
    // Venue-portability R3/R6, same two-stdout-line contract as the retention markers above: the
    // driver measures, this file only learns. A platform adopts these by printing them.
    const sl = /VENUE-STORE-LAYOUT\s+(isolated|hoisted)/.exec(l);
    if (sl) { out.storeLayout = sl[1]; continue; }
    // ⛔ `(.+)$` AND NOT `(\S+)`, AND ON WINDOWS THAT IS THE DIFFERENCE BETWEEN A PATH AND A LIE.
    // The stock Windows Node is `C:\Program Files\nodejs\node.exe`, so `(\S+)` records
    // `C:\Program` — a path that does not exist, silently, in the field whose entire job is to say
    // where the interpreter lives. `interpreterInsideHome` is then computed against that truncation
    // too. Caught by a test, before any Windows record carried it: this marker is new on that lane.
    // The trailing `.trim()` is load-bearing for the same platform, because a driver writing CRLF
    // leaves a `\r` that `(.+)$` would otherwise take as part of the path.
    const ip = /VENUE-INTERPRETER\s+(.+)$/.exec(l);
    if (ip) { out.interpreterPath = ip[1].trim(); continue; }
    const jr = /VENUE-JAIL-ROOT\s+(.+)$/.exec(l);
    if (jr) { out.jailRoot = jr[1].trim(); continue; }
    // R7. The driver asserts it; this only learns what was asserted, so a reader can check the
    // claim rather than trust that the assertion was present in whatever driver revision ran.
    const ou = /VENUE-OBSERVE-USER\s+(.+)$/.exec(l);
    if (ou) { out.observeUser = ou[1].trim(); continue; }
    // ⛔ WHETHER THE CI SCRUB REACHED THE TRACED CHILD, as opposed to having been performed on the
    // driver. The distinction is platform-shaped: macOS reaches the child through `sudo … env`, whose
    // env_reset builds a fresh environment, so an `unset` in the driver proves nothing about what the
    // script saw. Recorded rather than left in the log because a record claiming a CI normalisation
    // in `overrides` should also carry the evidence that it took effect.
    const cc = /VENUE-CI-CHILD\s+(.+)$/.exec(l);
    if (cc) {
      out.ciChild = cc[1].trim();
      if (/^LEAKED/.test(out.ciChild)) out.notes.push('ci-env-leaked-to-child');
      if (/SELF-CHECK FAILED/.test(l)) out.notes.push('ci-scrub-unverified');
      continue;
    }
    // ⛔ WHETHER THE XDG BASE-DIRECTORY SCRUB REACHED THE TRACED CHILD. Same platform shape as the CI
    // check above and a sharper consequence: the removal is an `env -u` on the far side of `sudo`, so
    // survival is a property of sudo's env_keep as much as of the flag. A leak means the script
    // resolved its config dir from the venue rather than from `$HOME`, which is what bills a write
    // against the REAL home and synthesizes `write:{userHome}` — the whole home directory — for a
    // variable the jail never passes on. Recorded rather than left in the log for the same reason
    // `ciChild` is: `overrides.unsetForTracedChild` claims the removal, and this is the evidence.
    const xc = /VENUE-XDG-CHILD\s+(.+)$/.exec(l);
    if (xc) {
      out.xdgChild = xc[1].trim();
      if (/^LEAKED/.test(out.xdgChild)) out.notes.push('xdg-env-leaked-to-child');
      if (/SELF-CHECK FAILED/.test(l)) out.notes.push('xdg-scrub-unverified');
      continue;
    }
    // The binary's content hash and detected features. Same two-stdout-line contract as the markers
    // above: the driver measures, this file only learns.
    const nb = /VENUE-NUB-BINARY\s+(\{.*)/.exec(l);
    if (nb) {
      try { out.nubBinary = JSON.parse(nb[1]); }
      catch { out.notes.push('nub-binary-unparsable'); }
      continue;
    }
    // WHICH NODE THIS VERSION SHOULD RUN ON, and whether the arm actually got it. The driver decides
    // (`era-node.mjs`) and this file only learns, same contract as the markers above.
    //
    // ⛔ RECORDED EVEN WHILE THE PIN IS NOT YET BINDING, WHICH IS THE POINT. A record carrying the era
    // pick beside the Node the arm really used is what tells us how often the two DIFFER, and on
    // which packages, before the pin changes any verdict. Flipping it first would move every
    // measurement at once with nothing to attribute the movement to.
    const ns = /VENUE-NODE-SELECTION\s+(\{.*)/.exec(l);
    if (ns) {
      try { out.nodeSelection = JSON.parse(ns[1]); }
      catch { out.notes.push('node-selection-unparsable'); }
      continue;
    }
    // ⛔ FREE TEXT, NOT JSON, AND DELIBERATELY SO — the value is meant to be read by a human scanning
    // `provenance`, and its shape mirrors the era-node pin's `PINNED <v>` / `NOT-PINNED (<why>)`.
    // Taken as the LAST occurrence, like every marker here, so a driver that emits it upstream of an
    // early exit and again later cannot disagree with itself.
    const ne = /VENUE-NET-ENFORCEMENT\s+(\S.*?)\s*$/.exec(l);
    if (ne) { out.netEnforcement = ne[1]; continue; }
    const ov = /VENUE-OVERRIDES\s+(\{.*)/.exec(l);
    if (ov) {
      try { out.overrides = JSON.parse(ov[1]); }
      catch { out.notes.push('overrides-unparsable'); }
      continue;
    }
    const wvp = /WRITEPATHS-VERSION-PINNED\s+(\[.*\])\s*$/.exec(l);
    if (wvp) {
      try { out.writePathsVersionPinned = JSON.parse(wvp[1]); }
      catch { out.notes.push('writepaths-pinned-unparsable'); }
      continue;
    }
    const evs = /EVENTLOG-STATS\s+(\{.*)/.exec(l);
    if (evs) {
      try { out.eventLog = JSON.parse(evs[1]); }
      catch { out.notes.push('eventlog-stats-unparsable'); }
      continue;
    }
    // A record that carries a verdict and no evidence is the state this whole mechanism exists to
    // end, so it is NOTED rather than left to be inferred from an absent file.
    if (/EVENTLOG NOT WRITTEN/.test(l)) out.notes.push('eventlog-missing');
    // The synthesized grant is printed on the line AFTER the banner. macOS restates it on its
    // `### DONE` line, which is the only place it survives an OBSERVE-ONLY run.
    if (/SYNTHESIZED GRANT/.test(l)) { synthesizedNext = true; continue; }
    if (synthesizedNext) {
      synthesizedNext = false;
      const g = firstObject(l);
      if (g) out.synthesized = g;
      continue;
    }
    if (/###\s+DONE\s.*\ssynthesized=/.test(l)) {
      out.synthesized ??= firstObject(l.slice(l.indexOf('synthesized=')));
    }
    // ⛔ TWO DISTINCT STRENGTHS, AND ONLY ONE OF THEM WAS EVER RECORDED. This matched `REPLAY
    // SUSPECTED` alone — the wording the two HEURISTIC predicates print. `measure.sh` retired its
    // heuristic in favour of `side-effects-cache: restored`, which is the one predicate measured to
    // work, and announces it as `REPLAY CONFIRMED` — a spelling this line never matched. So the
    // STRONGEST replay signal available produced no note at all, while the weak ones did.
    //
    // They are kept as separate notes because they mean different things and a reader must be able
    // to tell them apart: CONFIRMED means the arm demonstrably replayed and its result is not a
    // measurement; SUSPECTED is a guess from an indirect log shape and has false-fired in
    // production (see the note at the Windows predicate).
    if (/REPLAY CONFIRMED/.test(l)) out.notes.push('replay-confirmed');
    else if (/REPLAY SUSPECTED/.test(l)) out.notes.push('replay-suspected');
    // ⛔ THE GRANT WAS WIDENED BECAUSE A WRITE COULD NOT BE PLACED, not because the package needed
    // the width. A reader comparing this record against another platform's has to be able to see
    // that from the record alone; the `STALE` variant additionally says the wrong resolution was
    // PROVEN, not merely suspected. macOS-only today — the cause is posix_spawn addchdir_np.
    if (/CWD-UNOBSERVED/.test(l)) out.notes.push('cwd-unobserved');
    if (/Severity: STALE/.test(l)) out.notes.push('cwd-stale');
    // ⛔ WHICH WRITES THE GUARD COULD NOT PLACE, BY NAME. The grant covers them with `deps`+`project`
    // — a calibrated guess, not a measurement. If a macOS install ever breaks because one landed
    // somewhere else, the fix is a single catalog line, but only if the record says WHICH paths were
    // in doubt; otherwise the next person must re-measure to learn it and the run is long gone.
    const up = /CWD-UNPLACEABLE-WRITES\s+(\[.*\])\s*$/.exec(l);
    if (up) { try { out.cwdUnplaceableWrites = JSON.parse(up[1]); } catch { out.notes.push('cwd-unplaceable-unparsable'); } continue; }
    const cr = /CWD-RESOLVED\s+(\d+)/.exec(l);
    if (cr) { out.cwdResolved = Number(cr[1]); continue; }
    // ⛔ DID THE DROP ARM'S SCRIPT ASK FOR THE CAPABILITY THE ARM REMOVED? `denial-witness.mjs` scores
    // the arm's own JAILED trace and answers WITNESSED (the write was attempted and refused), CLEAN
    // (the lifecycle subtree never touched the dropped scope), VOID (the trace could not be read) or
    // UNSUPPORTED (this scorer expresses no scope for that capability). Keyed by capability, because
    // the answer is per-arm: a witnessed `no-write-userHome` says nothing about `no-network`.
    //
    // ⛔ FAILS CLOSED IN BOTH DIRECTIONS. An unparsable payload is recorded as VOID rather than
    // dropped, so it licenses nothing; a verdict this recorder does not recognise is likewise VOID.
    // Only the two words below carry weight, and everything else keeps the rule that ran before.
    // ⛔ DID THE SCRIPT DO ANYTHING AT ALL? The counts half of `observed-effect.mjs`, emitted by each
    // of the three classifiers from its own bucket totals. Kept as raw counts rather than as a
    // verdict because the verdict also needs `declaresInstallWork`, which arrives on a different
    // marker — scoring here would fix the answer before both halves are in hand.
    //
    // ⛔ FAILS CLOSED: an unparsable payload leaves the counts null, which scores UNKNOWN, which
    // vetoes nothing and licenses nothing.
    const oe = /OBSERVED-EFFECT\s+(\{.*\})\s*$/.exec(l);
    if (oe) {
      try { out.observedCounts = JSON.parse(oe[1]); }
      catch { out.notes.push('observed-effect-marker-unparsable'); }
      continue;
    }
    const dw = /DENIAL-WITNESS\s+(\{.*\})\s*$/.exec(l);
    if (dw) {
      try {
        const p = JSON.parse(dw[1]);
        if (typeof p.cap === 'string') out.denialWitness[p.cap] = String(p.verdict ?? 'VOID');
      } catch { out.notes.push('denial-witness-unparsable'); }
      continue;
    }
    // ⛔ THE ARMS FOR THIS PACKAGE COULD NOT HAVE FAILED, so a green one is not evidence. Either the
    // package ships its build output prebuilt — making the artifact gate's manifest the tarball's own
    // file set, present in every arm before any script runs — or its script ends in a status swallow
    // (`|| true`, `|| (exit 0)`), so `rc` is 0 whatever happened. The GRANT may still be correct; what
    // is absent is a signal that could have gone red. Recorded because an unfalsifiable arm filed as a
    // clean MINIMAL is the shape that erodes trust in a whole corpus. See `arm-falsifiability.mjs`.
    // ⛔ THE PROMOTION PROBE'S ONE LINE, OWNED BY `promotion-probe.mjs` AND PRINTED BY ALL THREE
    // DRIVERS THROUGH IT. Same construction as the DENIAL-WITNESS and CONFINED-WIDE markers above and
    // for the same reason: three hand-written `printf`s of one marker is how a note came to be live on
    // one platform of three.
    //
    // ⛔ FAILS CLOSED. An unparsable payload, or a verdict this recorder does not recognise, leaves the
    // field null — which licenses nothing, so the guard keeps the behaviour it had. Only `PROVEN`
    // carries weight downstream, and `publish-guard.mjs` re-checks the whole payload rather than
    // trusting a word.
    const pp = /PROMOTION-PROBE\s+(\{.*\})\s*$/.exec(l);
    if (pp) {
      try {
        const p = JSON.parse(pp[1]);
        out.promotionProbe = typeof p?.verdict === 'string' ? p : null;
        if (out.promotionProbe === null) out.notes.push('promotion-probe-unparsable');
      } catch { out.notes.push('promotion-probe-unparsable'); }
      continue;
    }
    if (/ARMS-UNFALSIFIABLE/.test(l)) out.notes.push('arms-unfalsifiable');
    // ⛔ WHICH DETECTOR DIED, NOT MERELY THAT ONE DID. `arm-falsifiability.mjs` reports two
    // INDEPENDENT reasons and the note above collapses them: `gate-vacuous` kills the artifact gate,
    // `rc-vacuous` kills the exit code. `publish-guard.mjs` has acted on that distinction since it
    // was written; `applyGrantSourceRule` below could not, because the distinction never reached the
    // record. Read off the marker's JSON payload rather than the prose beneath it — that prose is
    // written for a human and has already been rewritten once.
    const afm = /ARM-FALSIFIABILITY\s+(\{.*\})\s*$/.exec(l);
    if (afm) {
      // Fails CLOSED: an unparsable marker leaves this null, and the rule below reads null as "both
      // detectors are dead", which keeps the wider grant.
      try {
        const af = JSON.parse(afm[1]);
        out.falsifiabilityReasons = af.reasons ?? null;
        // `?? null` rather than a boolean coercion: a marker predating this field is UNKNOWN, and
        // `false` there would mean "npm runs nothing", exempting the record from the veto.
        out.declaresInstallWork = typeof af.declaresInstallWork === 'boolean' ? af.declaresInstallWork : null;
        // ⛔⛔ `manifestFiles` WAS EMITTED FOR MONTHS AND READ BY NOTHING, WHICH IS THE DEFECT THIS
        // LINE CLOSES. `applyGrantSourceRule` gates the whole grant-source rule on the marker LINE
        // EXISTING — so a payload of `{"manifestFiles":null,…}` read as "asked and answered" while
        // the arm behind it had measured a tree the subject was never in. MEASURED over all 6,887
        // committed logs: 39 records (36 linux-x64, 3 darwin-arm64, 0 win32), 15 of them MINIMUM and
        // 13 of those at `grant: {}` — a published under-grant, and an under-grant breaks installs.
        //
        // ⛔ THE KEY'S PRESENCE IS WHAT SEPARATES "UNKNOWN" FROM "ABSENT", so it is tested rather than
        // inferred from the value. A marker predating the field yields `undefined`, which must score
        // exactly as no marker at all does; only an explicit `manifestFiles: null` is the alarm.
        // Any other type is folded into the alarm too — fail-closed, since a payload this recorder
        // cannot read is not evidence the subject was present.
        out.subjectInObserveTree = 'manifestFiles' in af ? typeof af.manifestFiles === 'number' : null;
        // A human-visible label beside the typed field. The gates below and in `publish-guard.mjs`
        // key on the field, never on this string — `notes` is an open vocabulary and a note is a
        // description, not a trust boundary.
        if (out.subjectInObserveTree === false) out.notes.push('subject-absent');
      } catch { out.notes.push('arm-falsifiability-marker-unparsable'); }
      continue;
    }
    // ⛔ THE POSITIVE CONTROL: A DESCENT ARM THAT DEMONSTRABLY WENT RED. The drivers announce it in
    // two spellings and BOTH are the `*)` default of a three-way `case`, i.e. `verify` returned 1 —
    // genuinely insufficient. Never 2, which is VOID and is announced as `INCONCLUSIVE for` on all
    // three platforms. That is what makes this signal sound where `minimality: MINIMAL` is not: an
    // `if verify …; else NECESSARY` two-way branch reads VOID as necessity, and `publish-guard.mjs`
    // carries a darwin carve-out for exactly that. The carve-out does not apply here — macOS printed
    // no such line AT ALL until c95f47d2e, the same commit that gave it the three-way `case`, so the
    // announcement has never existed in the unsound form. MEASURED across all 6887 committed
    // `driver.out` files: 2311 carry the announcement and ZERO of those contain a VOID descent arm.
    if (/(?:'[^']+' is NECESSARY — dropping it fails to verify|narrowing '[^']+' fails ⇒ that capability IS necessary)/.test(l)) {
      out.descentRedArm = true;
      continue;
    }
    // ⛔ THE WIDE-BUT-CONFINED PROBE'S ONE LINE. `confined-wide.mjs` owns both the spelling and the
    // payload, and all three drivers print it through that module rather than by hand — three
    // hand-written `printf`s of one marker is how the `events LOST` note ended up live on one platform
    // of three.
    //
    // ⛔ FAILS CLOSED. An unparsable payload, or a `result` this recorder does not recognise, leaves
    // the field NULL and adds a note. Null is "not established", so a package stays on whatever the
    // ladder concluded — never on a fabricated `pass`, which is the only direction that could make an
    // unconfinable package look confinable.
    //
    // ⛔ `interpretation` IS PART OF THE ANSWER, NOT DECORATION. On win32 it is `bounded`: an
    // unprivileged AppContainer can only be granted an ACE on what the caller owns (MECHANISM-FACTS
    // §5l), so the probe there grants barely more than the last confined rung, and a `fail` does not
    // separate a token problem from a path problem. A reader that took the win32 `fail` for the POSIX
    // one would conclude "no grant can fix this" from an experiment that could not have shown it.
    const cw = /CONFINED-WIDE\s+(\{.*\})\s*$/.exec(l);
    if (cw) {
      try {
        const p = JSON.parse(cw[1]);
        if (['pass', 'fail', 'void'].includes(p.result)) {
          out.confinedWide = {
            result: p.result,
            interpretation: typeof p.interpretation === 'string' ? p.interpretation : 'unknown',
            paths: Array.isArray(p.paths) ? p.paths : [],
          };
        } else out.notes.push('confined-wide-marker-unparsable');
      } catch { out.notes.push('confined-wide-marker-unparsable'); }
      continue;
    }
    // ⛔ EACH DRIVER SPELLS EVENT LOSS DIFFERENTLY, AND KEYING ON ONE SPELLING SILENTLY EXEMPTS THE
    // OTHERS. `events LOST` is the WINDOWS wording (`measure-windows.mjs`) and it is live there — so
    // this note was never dead, which is exactly what made the defect hard to see: it fired on the
    // one platform it was written against. macOS and Linux say it in their own words and were
    // therefore never noted at all. MEASURED: both darwin records dropped an event, `notes: []`.
    //
    //   windows  `!! N events LOST -- exact-set claims are not supported by this trace`
    //   macos    `⛔ THE TRACER DROPPED N EVENT(S).`  and  `⛔ LOSS LEDGER DISAGREES: …`
    //   linux    `⛔ N trace lines the decoder could not parse`
    //
    // A dropped event is a path never seen, which UNDER-predicts the grant — so this note is the
    // record's only warning that its own evidence is incomplete, and a note that fires on one venue
    // of three is worse than absent, because its silence reads as a clean trace. `out.notes` is
    // de-duplicated below, so a driver tripping two of these (macOS emits both) still yields one.
    if (/events LOST|THE TRACER DROPPED|LOSS LEDGER DISAGREES|trace lines the decoder could not parse/.test(l)) {
      out.notes.push('events-lost');
    }
    if (/INCONCLUSIVE for/.test(l)) out.notes.push('descent-inconclusive');
    if (/UNDER-PREDICTED/.test(l)) out.notes.push('under-predicted');
  }

  // ⛔ THE DRIVERS NARRATE THEIR WAY TO A VERDICT, so a later `=>` line is not automatically the
  // answer: a `=> VERIFIED` is followed by descent arms that print `=>` conclusions of their own,
  // and macOS's DIAGNOSE arm prints after that. A MINIMUM is therefore never downgraded once seen.
  for (const l of lines) {
    // ⛔ `=> VERIFIED <g>` (POSIX) and `=> MINIMUM <g> (observed, then verified)` (Windows) are the
    // SAME outcome under different words; `=> MINIMUM <g> (ladder fallback)` is a DIFFERENT one —
    // OBSERVE under-predicted and the ladder repaired it. Keying on the word MINIMUM alone would
    // merge the arm that proves synthesis works with the arm that proves it failed.
    const verified = /=>\s*VERIFIED\s/.test(l) || /=>\s*MINIMUM\s.*observed, then verified/.test(l);
    const ladder = /=>\s*MINIMUM\s.*ladder fallback/.test(l);
    if (verified || ladder) {
      out.verdict = 'MINIMUM';
      out.grant = firstObject(l) ?? {};
      out.verifiedBy = ladder ? 'ladder' : 'synth';
      continue;
    }
    // Linux prints one summary line naming every droppable capability; macOS prints one line PER
    // dropped capability, quoting the variant name. Both mean the synthesis over-predicted.
    if (/=>\s*OVER-PREDICTED by:/.test(l)) {
      out.minimality = 'OVER-PREDICTED';
      out.overPredictedBy = (/by:([^(]*)/.exec(l)?.[1] ?? '').trim().split(/\s+/).filter(Boolean);
      continue;
    }
    const narrowed = /OVER-PREDICTED\s+—.*'([^']+)'\s+was not needed/.exec(l);
    if (narrowed) {
      out.minimality = 'OVER-PREDICTED';
      out.overPredictedBy.push(narrowed[1]);
      continue;
    }
    if (/=>\s*MINIMAL\b/.test(l) || /grant is already empty/.test(l)) { out.minimality = 'MINIMAL'; continue; }
    if (/=>\s*DESCENT INCOMPLETE/.test(l)) { out.minimality = 'UNPROVEN'; continue; }
    // ⛔⛔ A GRANT WITH NO DROPPABLE TERM IS NOT AN EMPTY GRANT, AND UNTIL `descent-terms.mjs` THE
    // DRIVERS PRINTED THE SAME SENTENCE FOR BOTH. The clause above reads "grant is already empty" as
    // MINIMAL, which is honest when the grant holds nothing — there is nothing to narrow. Reaching it
    // with `{"write":"disk","network":true}` in hand would publish the WIDEST grant this corpus hands
    // out as PROVEN MINIMAL off a descent that ran zero arms. `UNPROVEN` is the value a VOID arm
    // already yields and it means the same thing here: the question was never put.
    if (/=>\s*DESCENT UNSUPPORTED/.test(l)) { out.minimality = 'UNPROVEN'; continue; }
    // ⛔ THE PER-AXIS REASON, ON THE RECORD RATHER THAN ONLY IN THE LOG. `minimality: 'UNPROVEN'`
    // alone cannot distinguish "an arm came back VOID" from "this venue cannot test this axis at
    // all", and the second is a permanent property of the platform rather than a re-runnable
    // failure — a re-measurement returns the identical answer, so a reader has to be able to tell
    // them apart without fetching a log. FAILS CLOSED like `confinedWide`: an unparsable payload
    // leaves the field null and notes it, so no reason is ever fabricated.
    const du = /DESCENT-UNSUPPORTED\s+(\{.*\})\s*$/.exec(l);
    if (du) {
      try {
        const p = JSON.parse(du[1]);
        if (Array.isArray(p.skipped) && p.skipped.length) {
          out.descentUnsupported = {
            platform: typeof p.platform === 'string' ? p.platform : 'unknown',
            skipped: p.skipped.map((s) => ({ axis: String(s.axis), reason: String(s.reason) })),
          };
        } else out.notes.push('descent-unsupported-marker-unparsable');
      } catch { out.notes.push('descent-unsupported-marker-unparsable'); }
      continue;
    }
    if (out.verdict === 'MINIMUM') continue;
    // ⛔ A SUSPECT GRANT IS RETAINED BUT IS NOT A MEASUREMENT, AND THE RECORD HAS TO SAY BOTH.
    // The driver reaches this when every ladder arm exited 0 and fell short by the SAME files at every
    // grant up to `write:"disk"` — a shortfall invariant under widening, so not a capability gap. The
    // grant is kept because discarding it is the defect this verdict exists to fix (3 of 45 linux
    // records, one of them with a correct narrow grant already in hand), but `verifiedBy` stays null
    // and no `minimality` is claimed: the leave-one-out descent never ran. `collate.mjs` keeps the
    // verdict out of the catalog on exactly that basis.
    if (/=>\s*ARTIFACT-GATE-SUSPECT/.test(l)) {
      out.verdict = 'ARTIFACT-GATE-SUSPECT';
      out.grant = firstObject(l);
      out.notes.push('artifact-shortfall-grant-independent');
      continue;
    }
    // ⛔ macOS's `=> UNDER-PREDICTED` IS A REAL FINDING, NOT AN INSTRUMENT FAILURE — and it has no
    // grant, because no state the harness can express installed the package. It gets its own verdict
    // so the collator excludes it from the catalog (there is no measured minimum) while the queue
    // still closes the row: re-running it would produce the same answer, and `HARNESS-*` would put it
    // in an endless retry loop.
    //
    // ⛔ THE `=>` IS THE WHOLE DISCRIMINATOR, AND IT USED TO MEAN SOMETHING WEAKER. Before macOS had
    // a ladder, this line fired the moment the SYNTHESIZED grant failed — so a package the ladder
    // would have repaired was filed as having no minimum, and `collate.mjs` gave it no catalog entry,
    // dropping it to the base profile at install time. `measure-macos.sh` now emits the bare
    // `!! OBSERVE UNDER-PREDICTED` for that intermediate state, which lands in `notes` here exactly
    // as the Linux and Windows spellings do, and reserves the `=>` form for "every rung up to
    // write:\"disk\" failed". All three drivers therefore now mean the same thing by it.
    if (/=>\s*UNDER-PREDICTED/.test(l)) { out.verdict = 'UNDER-PREDICTED'; continue; }
    for (const [v, re] of Object.entries(VERDICTS)) {
      if (re.test(l)) { out.verdict = v; break; }
    }
  }

  // `OBSERVE-ONLY` carries a grant on its own line and is NOT a measurement — the driver says so
  // itself ("this is a HYPOTHESIS"). Recording the hypothesis as `synthesized` and leaving `grant`
  // null is what stops the collator treating it as one.
  if (out.verdict === 'OBSERVE-ONLY' && !out.synthesized) {
    const l = lines.find((x) => /=>\s*OBSERVE-ONLY/.test(x));
    if (l) out.synthesized = firstObject(l);
  }
  out.notes = [...new Set(out.notes)];
  out.overPredictedBy = [...new Set(out.overPredictedBy)];
  out.maliciousAdvisories = [...new Map(out.maliciousAdvisories
    .map((finding) => [`${finding.spec}\0${finding.ids.join(',')}`, finding])).values()];
  applyGrantSourceRule(out, lines);
  return out;
}

/** The driver rcs that mean "killed at a budget/deadline", not "finished and failed". `124` is the
 *  GNU `timeout` convention `portable-timeout.sh` and `run-batch-v2.mjs` both spell; `137` is
 *  SIGKILL. */
export const isTruncatedRc = (rc) => rc === 124 || rc === 137;

/**
 * A descent that was KILLED must not report that it completed.
 *
 * ⛔ THE DEFECT, MEASURED on `mozjpeg@6.0.1` (win32): the driver ran for exactly `[2400s]` — the
 * `NUB_CORPUS_PKG_BUDGET` — finishing `no-network` and `no-write-deps` before the kill, so
 * `no-write-project`, `no-write-userHome` and the joint arm NEVER RAN. The record published
 * `grant: {"write":{"project":true,"userHome":true},"network":true}` with `grantSource: "descended"`
 * and `minimality: "OVER-PREDICTED"` — i.e. it claimed `write.userHome`, the persistence capability,
 * had been descended, when nothing ever tested it.
 *
 * ⛔ AND NOTHING DOWNSTREAM CAUGHT IT. `collate.mjs` excludes on VERDICT alone, and the verdict is
 * `MINIMUM` (see the note at the `!parsed.verdict` guard: the driver prints `=> MINIMUM` when the
 * SYNTH arm verifies, THEN descends, so a kill during the descent arrives with a verdict already
 * parsed and the `rc === 124` branch never runs). The `driver-timeout` note was honest and had no
 * consumer.
 *
 * ⛔ THIS IS SYSTEMATIC, NOT BAD LUCK: a ladder record costs ~3.4x a synth record (MEASURED,
 * `iedriver` 693s -> 2376s once the descent ran), so ladder records are exactly the ones that hit a
 * 2400s cap. A Windows sweep mints these.
 *
 * ⛔⛔ THE GRANT IS NOT TOUCHED, AND THAT IS THE SAFE DIRECTION RATHER THAN AN OVERSIGHT. Every drop
 * that was APPLIED had a verifying arm, so the narrowed grant is a real measurement; reverting to
 * the synthesized value would discard verified narrowing, and dropping the record would leave the
 * package running at the base profile — a BROKEN install, which is the one error this corpus may not
 * make. What is false is the CLAIM of completeness, so only the claim changes.
 *
 * Raising the budget is not the fix: it moves the cliff without removing it.
 */
export function applyTruncationClaim(parsed, rc) {
  if (!isTruncatedRc(rc)) return parsed;
  parsed.notes = [...new Set([...(parsed.notes ?? []), 'driver-timeout'])];

  // The vocabulary already exists: `=> DESCENT INCOMPLETE` (all three drivers) parses to
  // `minimality: 'UNPROVEN'` for the case where an arm was VOID so a capability was never measured.
  // A budget kill is the same class — capabilities never measured — reached the one way the driver
  // cannot announce, because it is dead. Unconditional: a descent that finished microseconds before
  // the kill is indistinguishable here, and understating our confidence is the safe direction.
  parsed.minimality = 'UNPROVEN';

  // ⛔ NOT `'synthesized'`. `applyGrantSourceRule` already moved the narrowed value into `grant`, so
  // relabelling it `synthesized` would put the descended grant beside a claim it was never
  // descended — the exact mirror of the defect the `descent-name-unparsed` guard exists to prevent.
  // A third value is what honestly describes a narrowing that is real but incomplete.
  if (parsed.grantSource === 'descended') {
    parsed.grantSource = 'descended-incomplete';
    parsed.grantSourceReason = `${parsed.grantSourceReason ?? 'the descent narrowed the grant'}`
      + ' — BUT THE DRIVER WAS KILLED AT ITS BUDGET (driver-timeout), so the descent did not run to '
      + 'completion: any capability whose arm had not yet run is still in this grant UNTESTED. The '
      + 'drops that were applied were each verified, so the grant is safe to use; its MINIMALITY is '
      + 'not established. Re-measure with a larger budget to settle it.';
  } else if (parsed.grantSource === 'synthesized') {
    parsed.grantSourceReason = `${parsed.grantSourceReason ?? 'the synthesized grant was kept'}`
      + ' — AND THE DRIVER WAS KILLED AT ITS BUDGET (driver-timeout), so this reason describes the '
      + 'descent only as far as it got. The grant is the wider synthesized value, which is the safe '
      + 'direction, but it was not shown to be minimal.';
  }
  return parsed;
}

// ⛔ WHICH VALUE THE CATALOG GETS, AND WHY IT IS NOT SIMPLY "THE NARROWEST ONE".
//
// `collate.mjs` keys on `grant`, and `grant` was the SYNTHESIZED value — so on every over-predicting
// record the descent's narrower, jail-VERIFIED minimum was computed and then thrown away. That
// contradicts the point of the catalog (grant the narrowest set that still installs), systematically
// and on every platform.
//
// The reason it was not simply changed to "always take the descended value" is a real tension: the
// descended value is narrower and therefore better, but it rests on ARMS PASSING — and an arm can
// pass for the wrong reason. The synthesized value is wider and dumber but cannot be flattered. So
// the rule uses the falsifiability instrument as its gate:
//
//   grant = the DESCENDED minimum when the arms that justified it COULD have failed,
//           the SYNTHESIZED value otherwise.
//
// ⛔⛔ AND A SECOND GUARD THE OBVIOUS IMPLEMENTATION GETS WRONG: THE DESCENT IS LEAVE-ONE-OUT, SO
// DROPPING TWO CAPABILITIES AT ONCE WAS NEVER MEASURED. `measure.sh:824` says so in its own summary —
// "each named capability drops on its own". Each of N over-predicted capabilities has an arm proving
// IT is droppable individually; nothing proves they are jointly droppable, and the joint grant is
// strictly narrower than any arm that ran. Narrowing to it would be an INFERENCE presented as a
// measurement, in the under-grant direction. With N >= 2 the record therefore keeps the synthesized
// value unless the driver ran an explicit JOINT-NARROW arm — and either way it says which.
const applyGrantSourceRule = (out, lines) => {
  if (out.verdict !== 'MINIMUM' || !out.grant) return;
  const n = out.overPredictedBy.length;
  // ⛔ ABSENCE OF THE FLAG IS NOT EVIDENCE OF FALSIFIABILITY — it is usually evidence the CHECK NEVER
  // RAN. Every record taken before `arm-falsifiability.mjs` existed has no flag and no check, and
  // treating those as falsifiable would retroactively narrow the whole existing corpus on the
  // strength of a test that was never performed. Same distinction as an absent vs a null root, and
  // the same direction of harm. The detector prints an `ARM-FALSIFIABILITY` line unconditionally, so
  // that line — not the absence of the flag — is what says the question was asked.
  const checked = lines.some((l) => /ARM-FALSIFIABILITY\s/.test(l));
  const unfalsifiable = out.notes.includes('arms-unfalsifiable');
  // ⛔⛔ THE THREE-TERM RULE, AND IT IS `publish-guard.mjs`'s, NOT A NEW ONE. That file has judged
  // this exact question since it was written — "may a record with `arms-unfalsifiable` narrow a
  // grant?" — and answers it with three terms rather than two, because a two-term rule refuses a
  // correct narrowing proven by red arms. This file answered it with ONE term and blocked
  // everything. The two disagreed, and this file is the coarse one.
  //
  // `gate-vacuous` kills the artifact gate. `rc-vacuous` kills the exit code. Both dead, nothing
  // could have gone red and no narrowing is licensed. `gate-vacuous` ALONE leaves rc live — which is
  // `arm-falsifiability.mjs`'s own closing sentence: "the EXIT CODE is still a live detector here,
  // so a descent arm that actually FAILED is evidence … do not read a green arm as proof ON ITS
  // OWN". A red descent arm in the same run is what makes a green sibling not on its own: it is the
  // positive control, proving the jail -> denial -> non-zero-rc -> driver chain is live for THIS
  // package in THIS venue rather than merely un-swallowed in the package.json.
  //
  // ⛔ WHAT THE RED ARM DOES NOT PROVE, AND WHAT NOW CLOSES IT. A red arm on capability X shows the
  // chain fires; it does not show it would fire for capability Y specifically, so a script that
  // writes its essential output into the home and swallows the EACCES in a try/catch — a swallow no
  // shell-level `SWALLOWS` regex can see — would still narrow wrongly. `denial-witness.mjs` is the
  // arm that closes it: it scores the DROP ARM'S OWN jailed trace and says whether the write was
  // attempted-and-refused. The red arm stays as the fallback for a record with no witness.
  //
  // MEASURED 2026-08-31 on the committed corpus, before the witness existed: all 80 records this
  // red-arm rule moved off `write.userHome` were LADDER-RUNG records — 55 of them have ZERO real-home
  // writes attributed by OBSERVE, the `userHome` in their grant coming from rung 0's
  // `{deps,project,userHome}` bundle rather than from anything the script did — so the residual risk
  // named above did not materialise on any of them. It is still real for the next one.
  const reasons = Array.isArray(out.falsifiabilityReasons) ? out.falsifiabilityReasons : null;
  const rcLive = reasons !== null && !reasons.includes('rc-vacuous');
  const redArmLicenses = rcLive && out.descentRedArm === true;
  // ⛔⛔ THE WITNESS IS PER-CAPABILITY AND IT OUTRANKS EVERY OTHER TERM IN BOTH DIRECTIONS.
  //
  //   WITNESSED on a dropped capability   the script ASKED for it and the jail REFUSED, so the arm's
  //                                       green means the refusal was swallowed rather than that the
  //                                       capability was unnecessary. Nothing licenses that drop —
  //                                       not a red sibling arm, not a live artifact gate. This is
  //                                       the only term here that can WIDEN a record relative to the
  //                                       rule that ran before it, and it is why the file exists.
  //   CLEAN on EVERY dropped capability   a live, jailed, subtree-attributed trace in which the
  //                                       script never touched any dropped scope. That is direct
  //                                       evidence, so it licenses the narrowing on its own — no red
  //                                       sibling arm required. This is what unblocks a record whose
  //                                       every arm was green.
  //
  // VOID / UNSUPPORTED / absent all mean "not established" and change nothing: the rule below then
  // runs exactly as it did before this term existed, which is what keeps every pre-witness record on
  // the behaviour it was measured under.
  //
  // ⛔ THAT SENTENCE USED TO NAME win32 AS A PLACE "WHERE NO JAILED TRACE IS TAKEN AT ALL", AND THAT
  // IS NO LONGER TRUE — `measure-windows.mjs` now wraps its `no-write-userHome` drop arm in an ETW
  // session and emits this marker. Every win32 record ALREADY COMMITTED still carries no marker and is
  // therefore unaffected, which is the property that sentence was really protecting; what changed is
  // that a FUTURE win32 record can carry one. The recorder needs no platform term either way — it
  // keys on `cap` and `verdict`, and the win32 axis is gated inside the scorer.
  const witnessOf = (cap) => out.denialWitness?.[cap];
  const witnessedCaps = out.overPredictedBy.filter((c) => witnessOf(c) === 'WITNESSED');
  const witnessLicenses = out.overPredictedBy.length > 0
    && out.overPredictedBy.every((c) => witnessOf(c) === 'CLEAN');
  // The synthesized grant minus every capability an arm proved droppable. Keyed on the driver's own
  // variant names, so this cannot drift from what was actually run.
  //
  // ⛔⛔ AN UNRECOGNISED NAME IS A FAILED RECOMPUTATION, AND IT USED TO BE INVISIBLE. This loop
  // silently ignored any name it could not match, so a driver spelling its variants differently
  // produced a `descended` grant IDENTICAL to the synthesized one — and the record then published
  // `grantSource: "descended"` beside the un-narrowed value, claiming a narrowing that never
  // happened. MEASURED: `measure.sh` emitted the bare `network` / `write.deps` for the whole life of
  // the Linux descent, so `descendedGrant === grant` in every linux-x64 record that over-predicted.
  //
  // The driver-side spelling is now `no-*` on all three platforms, which is the fix. This guard is
  // why the same defect cannot recur silently in a fourth: a name nobody can parse forces the wider
  // synthesized grant and SAYS SO, instead of dressing a no-op as a measurement. Deliberately NOT a
  // second vocabulary — the legacy Linux spelling is not accepted here, because accepting it is what
  // would let the two sides drift apart again.
  const descended = JSON.parse(JSON.stringify(out.grant));
  const unparsedNames = [];
  for (const name of out.overPredictedBy) {
    if (name === 'no-network') { delete descended.network; continue; }
    // `read` is a SCOPE, not a map of scopes, so the whole key goes — there is no `no-read-<scope>`
    // to mirror `no-write-<scope>`, and inventing one would be a second vocabulary of exactly the
    // kind the guard above exists to prevent. This case is what lets ladder rung 1 narrow at all:
    // that rung carries `read:"disk"`, and without a parse for the drop the record kept the WIDE
    // grant and recorded `descent-name-unparsed`. Safe by construction — the descent only ever
    // keeps a drop whose arm VERIFIED, so a dropped `read` is one the install provably did not need.
    if (name === 'no-read') { delete descended.read; continue; }
    const w = /^no-write-(.+)$/.exec(name);
    if (w) {
      // ⛔⛔ A `no-write-*` NAME AGAINST A STRING `write` IS A FAILED RECOMPUTATION DRESSED AS A
      // SUCCESSFUL ONE, AND IT IS THE ONE HOLE THE `no-*` VOCABULARY LEFT OPEN. `write` is the STRING
      // `"disk"` on the terminal ladder rung (`catalog_v2::Reach::Disk`), and `descended.write` is
      // truthy there — so the old body evaluated `delete "disk"["disk"]`, which JavaScript resolves
      // to `true` while changing nothing, and `Object.keys("disk").length` is 4, so the collapse
      // never fired either. The result: `descendedGrant` identical to the wide grant, published under
      // `grantSource: "descended"`. Exactly the defect `unparsedNames` exists to catch, reachable
      // through a name that HAPPENS to match the regex.
      //
      // `descent-terms.mjs` never emits such a name — the string reach yields no write term at all —
      // so this is the backstop for a fourth driver, not a live path. It routes to `unparsedNames`
      // because that branch already does the right thing: keep the wide grant and SAY the
      // recomputation failed, rather than dress a no-op as a measurement.
      if (typeof descended.write === 'string') { unparsedNames.push(name); continue; }
      if (descended.write) {
        delete descended.write[w[1]];
        if (!Object.keys(descended.write).length) delete descended.write;
      }
      continue;
    }
    unparsedNames.push(name);
  }
  const jointVerified = lines.some((l) => /JOINT-NARROW\s+VERIFIED/.test(l));
  out.descendedGrant = descended;

  // ⛔⛔ DOES THIS NARROWING TAKE THE HOME AWAY? Asked of the two GRANTS rather than of
  // `overPredictedBy`, because the arm name and the effect are different questions: a ladder-rung
  // record can name `no-write-userHome` over a grant that never carried the home, where deleting it
  // is a no-op and there is nothing to withhold. `write:"disk"` covers the home and is routed to
  // `unparsedNames` above before it can reach here, but the string form is handled anyway so that a
  // future rung cannot make the largest possible drop read as no drop at all.
  const homeInGrant = (g) => !!g?.write && (typeof g.write === 'string' || !!g.write.userHome);
  const dropsHome = homeInGrant(out.grant) && !homeInGrant(descended);
  // `lines` rather than the raw log, so every term in this function reads the same text. Not a
  // soundness dependency: `^\s*==` cannot get past a `    | ` prefix, so an echoed header opens no
  // census block in either form.
  const homeCensus = dropsHome
    ? homeDropVerdict({ log: lines, witness: witnessOf('no-write-userHome') })
    : null;
  // ⛔ THE SAME QUESTION ON THE NETWORK AXIS, ASKED OF THE TWO GRANTS FOR THE SAME REASON. A record
  // can name `no-network` over a grant that never carried it — 559 records name the arm and only 212
  // lose the capability — and deleting what was never there withholds nothing.
  //
  // Truthy rather than `=== true` so a future non-boolean reach (`write` is already the string
  // `"disk"` on the terminal ladder rung) cannot make the drop read as no drop. MEASURED over the
  // 6,887 committed records, `grant.network` is only ever `true` (2,767) or absent (4,120).
  const netInGrant = (g) => !!g?.network;
  const dropsNetwork = netInGrant(out.grant) && !netInGrant(descended);
  const netCensus = dropsNetwork
    ? networkDropVerdict({ log: lines, witness: witnessOf('no-network') })
    : null;

  let source, reason;
  // ⛔⛔ FIRST OF THE CHAIN, ABOVE EVEN `n === 0`, BECAUSE IT ANSWERS A PRIOR QUESTION. Every branch
  // below reasons about which detector could have gone red; this one says the arms were not looking
  // at the package. Placed first so the RECORD'S OWN SENTENCE is true as well as its source: with
  // `n === 0` the next branch would print "no capability was droppable — synthesized IS the minimum"
  // over a `{}` that was synthesized from a tree the subject was never in, which is the flattering
  // reading this whole file exists to refuse.
  //
  // ⛔ IT IS A REFUSAL, NEVER A LICENCE — the same asymmetry as the `denial-witnessed` branch below.
  // It can only ever hold a record on the wider synthesized grant; nothing here can narrow one.
  // MEASURED on the committed corpus: `p5@0.7.0` (linux-x64) is the one record this branch actually
  // moves — `grantSource: descended`, `{"write":{"userHome":true}}`, narrowed off an observe tree
  // with no `p5` in it.
  if (out.subjectInObserveTree === false) {
    source = 'synthesized';
    reason = 'the observe tree did not contain the subject at all (ARM-FALSIFIABILITY reported no '
      + 'package directory), so `npm rebuild` ran nothing and no arm here measured this package — '
      + 'the descent cannot be read as evidence and the wider synthesized grant is kept';
  } else if (n === 0) {
    source = 'synthesized'; reason = 'no capability was droppable — synthesized IS the minimum';
  } else if (unparsedNames.length) {
    // ⛔ TESTED BEFORE EVERY NARROWING BRANCH, because this is an INSTRUMENT failure and the branches
    // below would otherwise publish its no-op as a result. Deliberately louder than the other
    // `synthesized` outcomes: those are honest measurements of an uncertain package, this one says
    // the harness and the recorder disagree about their own vocabulary and the record cannot be
    // computed. The wide grant is the safe direction, so a record is still produced — but it must not
    // read as `descended`.
    source = 'synthesized';
    reason = `the descent named ${unparsedNames.length} capabilit${unparsedNames.length === 1 ? 'y' : 'ies'} `
      + `this recorder cannot parse (${unparsedNames.join(', ')}) — the descended grant could not be `
      + 'recomputed, so the wider synthesized value is kept rather than a narrowing that was never applied';
    out.notes.push('descent-name-unparsed');
  } else if (witnessedCaps.length) {
    // ⛔ BEFORE THE FALSIFIABILITY BRANCH, AND UNCONDITIONALLY — NOT ONLY FOR AN UNFALSIFIABLE RECORD.
    // A witnessed refusal is direct evidence the script wanted the capability, and that is true
    // whatever the artifact gate could or could not have seen. The gate only ever inspects files
    // under the package's OWN directory, so a package that writes its real product into the home —
    // `@pulumi/gcp@0.16.9` downloads `~/.pulumi/plugins/resource-gcp-v0.16.9/pulumi-resource-gcp`,
    // measured — can pass a perfectly live gate in an arm that lost the plugin entirely. Restricting
    // this to the unfalsifiable case would let exactly that record narrow.
    source = 'synthesized';
    reason = `the descent narrowed, but the drop arm's own jailed trace shows the script ATTEMPTED a `
      + `write inside ${witnessedCaps.join(', ')} and the jail REFUSED it — the arm passed by `
      + 'swallowing the refusal, not by not needing the capability, so the wider grant is kept';
    out.notes.push('denial-witnessed');
  } else if (unfalsifiable && !redArmLicenses && !witnessLicenses) {
    // Tested BEFORE `!checked`: the flag is itself positive evidence the check ran, so a log
    // carrying the flag must never be mistaken for one that predates the detector.
    source = 'synthesized';
    // ⛔ NAME THE DETECTOR THAT DIED, for the same reason `arm-falsifiability.mjs` stopped printing
    // the blanket sentence: "could not have failed" is FALSE for the common case, and two audit
    // passes were spent hunting the defect that phrasing implies. The three ways to reach this
    // branch are genuinely different findings and a reader has to be able to tell them apart.
    reason = reasons === null
      ? 'the descent narrowed, but the ARM-FALSIFIABILITY marker could not be read, so which '
        + 'detector survived is unknown — keeping the wider grant'
      : !rcLive
        ? 'the descent narrowed, but this package\'s arms could not have failed (arms-unfalsifiable: '
          + `${reasons.join(', ')}) — the exit code is swallowed and the artifact gate is vacuous, so a `
          + 'passing narrow arm is not evidence — keeping the wider grant'
        : 'the descent narrowed and the exit code was a live detector (arms-unfalsifiable: '
          + `${reasons.join(', ')}), but NO descent arm went red and no DENIAL-WITNESS came back CLEAN `
          + `for every dropped capability (${out.overPredictedBy
            .map((c) => `${c}=${witnessOf(c) ?? 'none'}`).join(', ')}), so nothing demonstrated the `
          + 'detector would have fired — a passing narrow arm on its own is not evidence — keeping the '
          + 'wider grant';
  } else if (!checked) {
    source = 'synthesized';
    reason = 'the descent narrowed, but this record predates the falsifiability check — no '
      + 'ARM-FALSIFIABILITY line, so whether a passing arm is evidence was never established';
  } else if (n === 1) {
    source = 'descended';
    reason = `one capability (${out.overPredictedBy[0]}) was dropped and the resulting grant was `
      + 'verified in the real jail by a single arm'
      // ⛔ SAY WHICH EVIDENCE CARRIED IT. Without this line a witness-licensed narrowing and an
      // ordinary one are indistinguishable in the record, and the first question anyone auditing a
      // dropped `write.userHome` asks is what made the passing arm count.
      + (witnessLicenses ? ', whose own jailed trace shows the lifecycle subtree never attempted a '
        + 'write inside the dropped scope (DENIAL-WITNESS CLEAN)' : '');
  } else if (jointVerified) {
    source = 'descended';
    reason = `${n} capabilities were dropped and the JOINT grant was explicitly verified`;
  } else {
    source = 'synthesized';
    // ⛔ "NEVER RUN" IS A CLAIM ABOUT THE RUN AND IT WAS ASSERTED WITHOUT LOOKING. The joint arm has
    // three outcomes and only one of them is absence; a record whose joint arm RAN and FAILED said
    // "never run" anyway, which points the next reader at a free win that does not exist —
    // `@pact-foundation/pact-node@10.18.0` is exactly that record, and it cost this investigation a
    // detour. The wider grant is right in all three cases; the REASON has to say which one.
    const jointRan = lines.some((l) => /JOINT-NARROW\s+(FAILED|INCONCLUSIVE)/.test(l));
    reason = `${n} capabilities each drop on their own, but the descent is leave-one-out and the `
      + (jointRan
        ? 'JOINT drop was measured and did NOT hold — they do not drop together, so the wider grant '
          + 'is the measured answer'
        : 'JOINT drop was never run — narrowing to it would be an inference, not a measurement');
  }
  // ⛔⛔ THE HOLE EVERY TERM ABOVE LEAVES OPEN, AND IT IS AN UNDER-GRANT — the one direction this
  // project forbids. `redArmLicenses` rests on a RED SIBLING arm — on `network`, say — which proves
  // the jail → denial → non-zero-rc → driver chain fires SOMEWHERE in this run. It cannot prove it
  // fires on the HOME write, because `artifact-gate.mjs` only ever walks the package's own directory
  // and a home write is by construction outside it. So a browser downloader whose entire product is
  // a home write passes its `no-write-userHome` arm with the browser missing, and the grant narrows
  // off an arm that measured nothing. The comment on `redArmLicenses` above conceded this residual
  // and said it "did not materialise on any of them. It is still real for the next one." It has:
  // MEASURED at `cf36b27f8` over the committed corpus, of the 425 records whose descent named
  // `no-write-userHome`, 348 have a POSITIVE real-home census and NOT ONE has a CLEAN witness —
  // `ibm_db@2.8.2` (win32) 3337 real-home writes, `playwright-chromium@1.9.2` (linux) 1185.
  //
  // ⛔ AN OVERRIDE ON THE DECIDED `source`, NOT A BRANCH IN THE CHAIN, AND THE DIFFERENCE IS
  // MEASURABLE RATHER THAN STYLISTIC. As a branch it also fired on records the chain was ALREADY
  // going to keep wide — the N>=2 leave-one-out case above, which reaches `synthesized` for a
  // completely different and more complete reason — replacing that reason on records whose grant does
  // not change. Keyed on `source === 'descended'` the term is withhold-ONLY by construction: it can
  // turn a narrowing into the wider grant and can never do the reverse, and every branch that already
  // decided to withhold keeps its own better-specified reason. That includes `witnessedCaps`, which
  // must keep outranking this — a WITNESSED refusal is direct evidence the script ASKED and the jail
  // REFUSED, strictly stronger than a count of what it wrote unjailed.
  //
  // ⛔ BEFORE THE `redArmLicenses` APPEND BELOW, so a withheld record does not also carry a sentence
  // explaining why a red arm let it through.
  //
  // ⛔ AN ABSENT CENSUS (`CENSUS_UNKNOWN`) DELIBERATELY DOES NOT FIRE THIS. The census is an OBSERVE
  // product, and this file's settled policy for an absent OBSERVE product is the one written on
  // `observedCounts`: null "vetoes nothing, so every existing record keeps the behaviour it was
  // measured under". Refusing on absence would re-adjudicate every log that never ran a census on the
  // strength of a check that was never performed. It costs nothing to scope it to a POSITIVE count:
  // all three classifiers print the block unconditionally, and MEASURED at `cf36b27f8` zero of the
  // 425 arm-carrying logs lack one. Nor is the absence case unguarded — `write-census.test.mjs` fails
  // at authoring time if a classifier stops emitting the header, and `stale-adjudication.mjs`'s G3
  // REFUSES on an absent census when re-adjudicating an ARCHIVED log, which no authoring-time guard
  // can reach.
  if (source === 'descended' && homeCensus?.verdict === CENSUS_REFUSE) {
    source = 'synthesized';
    reason = `the descent narrowed, but ${homeCensus.reason}`;
    out.notes.push('home-write-attributed');
  }
  // ⛔⛔ THE SAME HOLE ON THE NETWORK AXIS, AND IT IS THE ONE WITH A REPRODUCED BROKEN INSTALL.
  // `artifact-gate.mjs` walks the package's own directory and counts what is there; it cannot tell a
  // fetch that NEVER HAPPENED from one a WARM CACHE made unnecessary. Both leave every artefact
  // present and `rc=0`, and the recorder reads the second as proof the capability was never needed.
  //
  // ⛔ THE STORE EVICTION DOES NOT CLOSE THIS, AND BELIEVING IT DID IS WHY THE TERM WAS MISSING. The
  // per-arm `EVICT` clears `pm/store` only. nub redirects a confined script's downloads at
  // `pm/tools/{electron-cache,ms-playwright}` (`redirect_electron_cache`,
  // `redirect_playwright_browsers`) and `push_rw_path`s those leaves UNCONDITIONALLY, so they are
  // outside everything the eviction walks and outlive every arm.
  //
  // MEASURED on `electron-chromedriver@33.4.9` (darwin-arm64), whose committed log carries both
  // halves: OBSERVE reached `185.199.108.133:443` and `172.182.252.133:443` and wrote
  // `chromedriver-v33.4.9-darwin-arm64.zip` into `.cache/nub/pm/tools/electron-cache/<sha>/`, then
  // `EVICT[nar-no-network] 61 store entries removed … 2382 in store` left that zip untouched and
  // `VERIFY[nar-no-network] rc=0 artifacts=11/11` narrowed the grant to `{}` via a verified JOINT
  // arm. `harness/overrides/electron.json` records that same empty grant failing a real cold install
  // twice with `getaddrinfo ENOTFOUND github.com`. `arm-artifact-cache.mjs` purges those two leaves
  // for FUTURE arms; it cannot reach the 6,887 records already committed, and it can only ever cover
  // replay roots somebody has enumerated — `measure-macos.sh` names `~/.npm/_prebuilds` as another
  // that cost `kerberos@7.0.0` the same false pass. A recorder term is the backstop that does not
  // depend on that list being complete.
  //
  // ⛔ FAILS CLOSED, WHICH IS WHERE THIS DEPARTS FROM THE HOME TERM ABOVE. That one fires only on a
  // POSITIVE count and lets `CENSUS_UNKNOWN` through, on the settled `observedCounts` policy that an
  // absent OBSERVE product vetoes nothing. Here an absent census is refused: 1,228 committed records
  // carry no `== NETWORK` block at all, and reading "the question was never asked" as "the answer was
  // no" is precisely the under-grant this term exists to stop. It costs nothing to say so — MEASURED
  // over the committed corpus, ALL 212 records that actually drop `network` carry a census, so the
  // `NET_UNKNOWN` arm refuses zero of them today and is here for the log that stops printing one.
  //
  // ⛔ THE ARCHIVE'S LINUX PEER COUNT IS NOT SUBTREE-SCOPED, AND THE RULE IS SOUND ANYWAY — BOTH
  // HALVES MEASURED. In the committed era `observe.mjs` billed `distinct peers` from the whole traced
  // tree while `observe-macos.mjs` dropped an unattributed connect: 510 of the 2,059 linux logs print
  // `sockets script 0` beside a positive peer count, against 0 of 1,912 darwin. (`observe.mjs` now
  // prints `distinct peers: <attributed>  /  whole traced tree <all>`, which no committed log yet
  // carries — so this over-count is an ARCHIVE property that ages out, not a standing one.)
  //
  // An over-count is harmless in both arms. A whole-tree ZERO implies a subtree zero, so `CLEAR`
  // cannot over-clear; an over-counted POSITIVE can only withhold. And it cannot make this term fire
  // on npm's own traffic, because reaching here at all presupposes the synthesizer predicted
  // `network`, and the synthesizer keys on the ATTRIBUTED `sockets script` row — MEASURED, those two
  // agree on all 5,633 records carrying both, with zero disagreements either way, and all 211 records
  // this term refuses on the committed corpus have an attributed script socket AND a genuinely remote
  // peer, none refusing on a loopback resolver alone. A separate attribution guard here could
  // therefore never fire on any record that reaches it, so there is not one.
  //
  // ⛔ AFTER THE HOME TERM, AND THE ORDER IS CHOSEN RATHER THAN INCIDENTAL. Both are withhold-only
  // overrides on `source === 'descended'`, so which runs first cannot change a single grant — only
  // the REASON a withheld record carries. Going second means this term rewrites no existing record's
  // `grantSourceReason`, so every reason that changes is one this term newly withheld.
  if (source === 'descended' && netCensus && netCensus.verdict !== NET_CLEAR) {
    source = 'synthesized';
    reason = `the descent narrowed, but ${netCensus.reason}`;
    out.notes.push(netCensus.verdict === NET_UNKNOWN ? 'network-census-absent' : 'network-attributed');
  }
  // ⛔ SAY WHY THE FLAG DID NOT BLOCK, in the record rather than only here. A record carrying
  // `notes: ["arms-unfalsifiable"]` beside `grantSource: "descended"` reads as a contradiction
  // otherwise, and the whole point of the grant-source fields is that a narrowing never arrives
  // without the basis for it attached.
  //
  // Keyed on `redArmLicenses`, not on `unfalsifiable`: that is what the sentence actually claims, and
  // it is also what makes `reasons` non-null here, since `rcLive` is one of its terms.
  if (source === 'descended' && redArmLicenses) {
    reason += ` — the ${reasons.join(', ')} flag did not block it because a descent arm went RED, `
      + 'so the exit-code detector demonstrably fired for this package in this venue';
  }
  out.grantSource = source;
  out.grantSourceReason = reason;
  if (source === 'descended') out.grant = descended;
};

// ── CLI ───────────────────────────────────────────────────────────────────────
//
// ⛔⛔ `pathToFileURL`, NEVER `file://${process.argv[1]}` — AND THIS FILE IS WHERE THAT MISTAKE COSTS
// A WHOLE PLATFORM'S CORPUS. On Windows `process.argv[1]` is `D:\a\repo\harness\v2\record.mjs`
// while `import.meta.url` is `file:///D:/a/repo/harness/v2/record.mjs`: backslashes, and one slash
// versus three. The string form therefore NEVER matches on Windows, so everything below is skipped,
// the process prints nothing and EXITS 0.
//
// ⛔ AND THE CALLER CANNOT TELL. `run-batch-v2.mjs` checks `if (w.status !== 0)` and moves on, so a
// Windows batch would mark every row measured while writing no `results.json` at all — a silent
// total loss with a green log. `records-v2/runs/` holding `darwin-arm64` and `linux-x64` and no
// `win32-x64` is consistent with exactly this.
//
// `adapters/windows-retain.mjs` already carries this scar and its fix; `adapters/linux.mjs` uses the
// string form and is correct there and only there, because it never runs anywhere else.
// ⛔ `process.argv[1] &&` GUARDS THE IMPORT CASE, and it is not defensive padding.
// `pathToFileURL(undefined)` THROWS, so without it merely IMPORTING this module from a context
// with no `argv[1]` — `node -e`, a REPL, an embedder — dies before any caller runs. The naive
// string form this replaced was wrong on Windows but TOTAL: it just returned false. Swapping in a
// correct comparison therefore introduced a new failure mode, which is worth stating because the
// tests did not catch it: `node --test` always supplies `argv[1]`.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const argv = process.argv.slice(2);
  const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
  const log = fs.readFileSync(opt('--log'), 'utf8');
  const pkg = opt('--pkg');
  const version = opt('--version');
  const rc = Number(opt('--rc', '0'));
  const parsed = parseDriverLog(log);
  let harnessIdentity;
  let runtime;
  let resolvedTrees;
  let standing = null;
  try {
    harnessIdentity = computeHarnessIdentity();
    const expectedEpoch = opt('--expected-harness-epoch', '');
    const expectedSha = opt('--expected-harness-sha', '');
    if ((expectedEpoch && Number(expectedEpoch) !== harnessIdentity.harnessEpoch)
      || (expectedSha && expectedSha !== harnessIdentity.harnessSha256)) {
      throw new Error('the harness changed after this batch started; refusing a mixed-instrument record');
    }
    runtime = opt('--runtime-json', '')
      ? JSON.parse(opt('--runtime-json')) : collectRuntimeProvenance();
    standing = opt('--standing-json', '') ? JSON.parse(opt('--standing-json')) : null;
    if (expectedSha && (!standing?.observedAt || !standing?.latestVersion
      || !Number.isSafeInteger(standing?.weeklyDownloads))) {
      throw new Error('production record has incomplete package standing metadata');
    }
    resolvedTrees = hydrateResolvedTrees(parsed.securityScreens);
    const expectedNub = opt('--expected-nub-sha256', '');
    if (expectedNub && parsed.verdict !== 'REFUSED-MALICIOUS'
      && parsed.nubBinary?.sha256 !== expectedNub) {
      throw new Error('the Nub binary observed by the driver does not match the batch identity');
    }
    const recorderNode = { version: process.version, ...fileIdentity(process.execPath) };
    if (runtime?.node?.version !== recorderNode.version
      || runtime?.node?.sha256 !== recorderNode.sha256) {
      throw new Error('the Node runtime snapshot does not match the recorder executable');
    }
  } catch (error) {
    console.error(`record.mjs: REFUSED ${error.message}`);
    process.exit(2);
  }

  // ⛔ WHAT MACHINE, IN WHAT STATE (VENUE-PORTABILITY R3 + R6). Before this, two records produced on
  // different venues were INDISTINGUISHABLE in the record, so a divergence between them could not be
  // attributed without going back to the run — and the runs are ephemeral.
  //
  // ⛔ `ciEnvSet` AND `storeLayout` ARE SEPARATE FIELDS AND NEITHER IMPLIES THE OTHER. `is_ci()` is
  // `env::var_os("CI").is_some()` and `install_report.rs` returns the isolated layout when it is set,
  // so CI genuinely measures a DIFFERENT store layout. That difference is real and must be PRESERVED,
  // not normalised away; recording it is what turns a confound into a covered axis. Where the two
  // states disagree the catalog takes the UNION, because over-granting is safe and under-granting
  // breaks installs.
  //
  // ⛔ `storeLayout` IS OBSERVED, NOT INFERRED FROM `CI`. Deriving it from the env var would encode
  // the very rule this field exists to let us check, and would then agree with itself forever. The
  // driver reports what the arm tree actually contained; absent that, `null` — never a guess.
  // (MEASURED, and the reason this matters: a `CI`-unset install on the VM still produced a
  // `node_modules/.store`, so the "CI implies isolated" rule is not a biconditional.)
  // ⛔ CONTAINMENT IS PER-PLATFORM, AND THE POSIX-ONLY TEST WAS SILENTLY WRONG ON WINDOWS FOR EVERY
  // RECORD. The old form was `interpreterPath.startsWith(`${home}/`)` — a FORWARD slash, and a
  // case-SENSITIVE compare. On win32 the separator is `\` and the filesystem is case-insensitive, so
  // that expression is unsatisfiable there: `interpreterInsideHome` has been `false` on every win32
  // record regardless of where Node actually lives. `false` is a claim, not an absence, so nothing
  // downstream could tell it apart from a genuine measurement — which is exactly the failure R3
  // exists to prevent, arriving through the field meant to prevent it.
  //
  // The two POSIX-visible differences are both real: Windows folds case (`C:\Users\NUB` and
  // `c:\users\nub` are one directory) and separates with `\`. Both are normalised before comparing,
  // and the boundary check stays a SEPARATOR-terminated prefix on every platform so `/home/nubbins`
  // is never read as being inside `/home/nub`.
  const insideHome = (child, home, platform) => {
    if (!child || !home) return null;
    const win = platform.startsWith('win32');
    const fold = (s) => (win ? s.replace(/\//g, '\\').toLowerCase() : s).replace(/[\\/]+$/, '');
    const sep = win ? '\\' : '/';
    const c = fold(child), h = fold(home);
    return c === h || c.startsWith(h + sep);
  };

  // ⛔ AN UNDECLARED VENUE IS `unknown`, NEVER A PLAUSIBLE GUESS. This defaulted to `local`, so a run
  // on the corpus VM with `NUB_CORPUS_VENUE` unset recorded `venue: "local"` — a wrong value that
  // reads exactly like a right one. That is the same shape as every other "absent is not empty"
  // defect this harness has hit (the manifest, the falsifiability flag, the temp roots), and it is
  // worse in one way: venue is PROVENANCE, so a wrong value poisons the ability to re-examine the
  // record later rather than merely the current answer. `unknown` is non-breaking for consumers and
  // makes the gap visible IN THE DATA.
  //
  // ⛔ AND IT IS NEVER INFERRED — not from `CI`, not from the hostname, not from the interpreter
  // path. A cloud VM and a laptop are not distinguishable from inside; an inferred venue is a guess
  // wearing a fact's clothing, and the entire value of the field is that it is ASSERTED by whoever
  // knows. `GITHUB_ACTIONS` is the one exception and is not an inference: the runner sets it itself.
  const resolveVenue = (env) => {
    if (env.GITHUB_ACTIONS) return 'ci';
    const declared = env.NUB_CORPUS_VENUE;
    if (declared) return declared;
    // Loud, once per record, naming the variable and the value being written. An operator who sees
    // this once fixes it forever; a silent default is what let a mislabelled record exist at all.
    console.error('⛔ NUB_CORPUS_VENUE is not set, so this record is being written with '
      + 'venue: "unknown". Set NUB_CORPUS_VENUE=vm|local|ci to say where these arms actually ran — '
      + 'a venue comparison cannot attribute a difference between two records that both say unknown.');
    return 'unknown';
  };

  const venueProvenance = (p, platform) => {
    const env = process.env;
    const home = env.HOME ?? env.USERPROFILE ?? '';
    const interpreterPath = p.interpreterPath ?? null;
    return {
      venue: resolveVenue(env),
      ciEnvSet: env.CI !== undefined,
      storeLayout: p.storeLayout ?? null,
      interpreterPath,
      interpreterInsideHome: insideHome(interpreterPath, home, platform),
      // R3, and the reason is in `parseDriverLog`: a Windows jail root under `C:\Users\<user>` fails
      // to build a token at all, so a record has to name where its arms ran or a venue comparison
      // will read an environment failure as a capability finding.
      jailRoot: p.jailRoot ?? null,
      // R7. Null means the driver did not assert it — which is itself the finding, not a pass.
      observeUser: p.observeUser ?? null,
      // Whether the CI scrub reached the traced CHILD. Null means the driver never checked, which is
      // distinct from "clean" and must not be read as one.
      ciChild: p.ciChild ?? null,
      // Whether the XDG scrub reached the traced CHILD. Null means the driver never checked — which
      // is what every record measured before the scrub existed says, and it must not read as clean.
      xdgChild: p.xdgChild ?? null,
      // The cwd guard's own accounting: how many relative paths were PLACED against the package dir
      // and confirmed by an artifact, and which writes remain unplaceable. Null means the driver did
      // not report — distinct from zero, and must not be read as "none".
      cwdResolved: p.cwdResolved ?? null,
      cwdUnplaceableWrites: p.cwdUnplaceableWrites ?? null,
      // ⛔ WHICH BINARY, WHICH `nubGitSha` PROVABLY CANNOT ANSWER. Two binaries from the SAME commit
      // behave differently when their feature sets differ. MEASURED 2026-08-06: a `--release` build
      // of the right commit, missing only `build-jail-catalog-override`, VOIDed four measurement
      // cells while reporting a `nubGitSha` identical to the working binary's. The content hash is
      // also the only identity that survives a SHARED MUTABLE binary path — lanes on one box can
      // swap the artifact mid-batch, and the hash is what distinguishes a batch measured against one
      // binary from a batch measured against two.
      nubBinary: p.nubBinary ?? null,
      // The era pin, mirroring v1's `nodeSelection` field names so the two corpora are comparable.
      // v1 once shipped a whole Linux run whose every record said `pinnedTo: null` because the
      // selection silently fell through, and nothing in the record could tell that from a deliberate
      // no-pin — so the acceptance bar is POPULATED, not merely present.
      nodeSelection: p.nodeSelection ?? null,
      // ⛔⛔ WHETHER ANY CONTROL PROVED A DENIED NETWORK IS OBSERVABLE IN THIS VENUE — AND THE ABSENT
      // CASE RENDERS AS AN EXPLICIT NEGATIVE, NOT AS `null`. Every other field here uses `?? null`
      // and documents that null means "the driver did not assert it"; this one may not, because the
      // hole it reports on IS a missing assertion reading as a pass. A probe measured
      // `playwright-chromium@0.17.0` at the empty grant, downloaded 358 MB of Chromium at rc=0, and
      // recorded "needs no network" — and nothing in `results.json` could say that no falsification
      // control had ever established that egress denial is detectable there. Three routes reach that
      // state and none was visible: `--no-falsify` (which `corpus-v2-runner.yml` passes for a
      // targeted re-measure), a loud platform SKIP, and invoking a driver directly outside
      // `run-batch-v2.mjs`, which is what that probe did. `net-enforcement.mjs` composes the value.
      netEnforcement: p.netEnforcement
        ?? 'NOT-VERIFIED (the driver emitted no VENUE-NET-ENFORCEMENT marker, so this record predates '
          + 'the field or its driver died before the provenance block)',
      // R6. Normalisation that is RECORDED is a covered axis; normalisation that is invisible is a
      // silent bet that it did not matter. The driver names each variable it set, unset or
      // redirected, so a reader can tell whether `CI` was touched — the one override that would
      // invalidate the whole acceptance test — without trusting that it was not.
      overrides: p.overrides ?? null,
    };
  };

  // ⛔ NO TERMINAL LINE IS NOT AN EMPTY GRANT. A driver killed by a deadline, or dying before it
  // reaches a `=>`, must land in the `HARNESS-*` bucket so the queue reopens the row rather than
  // recording an absence as a result.
  if (!parsed.verdict) parsed.verdict = rc === 124 || rc === 137 ? 'HARNESS-TIMEOUT' : 'HARNESS-ERROR';

  // ⛔ AND THE `!parsed.verdict` GUARD ABOVE IS EXACTLY WHY A TIMEOUT CAN STILL LAND AS `MINIMUM`.
  // The driver prints its `=> MINIMUM` the moment the SYNTH arm verifies, then descends. A budget
  // kill during the descent therefore arrives with a verdict ALREADY parsed, the `rc === 124` branch
  // never runs, and a truncated run is recorded as a completed measurement.
  //
  // MEASURED on `duckdb@1.4.4`: `driverRc: 124`, `durationMs: 2400105` (the budget, exactly),
  // killed with its cwd in `verify-drop-no-network` — recorded `verdict: "MINIMUM"`,
  // `minimality: null`, with no capability yet dropped.
  //
  // ⛔ AND A KILL DOES NOT ALWAYS ARRIVE THAT EARLY — this comment used to say "a cut-off descent
  // narrows nothing and leaves the synthesized grant standing", and `mozjpeg@6.0.1` (win32) falsified
  // it: that descent COMPLETED `no-network` and `no-write-deps` before the kill, so `grant` was
  // genuinely narrowed and published `grantSource: "descended"` while `no-write-project`,
  // `no-write-userHome` and the joint arm never ran. The grant is still SAFE — every applied drop had
  // a verifying arm — but the record claimed a COMPLETENESS it never had, over `write.userHome`, the
  // persistence capability.
  //
  // The note is additive on purpose. Downgrading the verdict would drop the package from the catalog
  // (`collate.mjs` keeps only `MINIMUM`) and discard a grant its synth arm really did verify — the
  // same trade `ARTIFACT-GATE-SUSPECT` already settled the other way, for the same reason. What the
  // note alone could NOT do is stop the false claim, because nothing consumed it; `applyTruncationClaim`
  // is what now downgrades `minimality` and `grantSource` to match what actually ran.
  applyTruncationClaim(parsed, rc);

  // ⛔ RESOLVED ONCE, ABOVE THE RECORD, BECAUSE `interpreterInsideHome` NEEDS IT. Reading it out of
  // `rec.provenance` while `rec` is still being built would evaluate to `undefined`, and the
  // containment test would then silently take its POSIX branch on Windows — the same class of
  // silent-wrong-answer the test itself was written to end.
  const platform = opt('--platform', `${process.platform}-${process.arch}`);

  const rec = {
    pkg,
    version,
    // ⛔ THE RECORD SAYS WHICH HARNESS PRODUCED IT, IN ADDITION TO LIVING UNDER ITS OWN ROOT. The
    // root is the structural guarantee that v2 can never overwrite v1; this field is what survives a
    // record being copied, collated or reported out of that tree, where the path is gone.
    harnessVersion: 2,
    harnessEpoch: harnessIdentity.harnessEpoch,
    verdict: parsed.verdict,
    // ⛔ ON THE RECORD, NOT ONLY IN THE LOG, SO THE CLASS IS QUERYABLE WITHOUT ARTIFACT ARCHAEOLOGY.
    // Sizing this from logs took downloading a run artifact and grepping 733 files, and it could only
    // ever see the 733 records that KEEP a log -- 887 `BROKEN-WITHOUT-JAIL-TOO` records keep none, so
    // their cause is unknowable that way. A field on the record answers it for all 6880.
    eraDepMismatch: parsed.eraDepMismatch ?? null,
    grant: parsed.grant,
    synthesized: parsed.synthesized ?? null,
    verifiedBy: parsed.verifiedBy,
    minimality: parsed.minimality,
    overPredictedBy: parsed.overPredictedBy,
    // ⛔ MIRRORED OUT OF THE GRANT, NOT PARSED SEPARATELY, AND KEPT IN BOTH PLACES ON PURPOSE.
    // `writePaths` travels INSIDE the grant so the VERIFY arm actually builds a catalog carrying it
    // and exercises nub's mover — a field the driver never puts in a catalog is a field no arm ever
    // tests. But `collate.mjs` reads it from the RECORD's top level (`grantKey`, the `folded` union,
    // and the `byVersion` fold all key on `r.writePaths`), which is the v1 shape. Mirroring is what
    // lets an emitting v2 driver reach the existing collator with no change there; deriving it
    // separately would give two values that can disagree.
    writePaths: parsed.grant?.writePaths ?? [],
    writePathsVersionPinned: parsed.writePathsVersionPinned ?? [],
    securityScreens: (parsed.securityScreens ?? []).map(({ clearancePath: _, ...screen }) => screen),
    resolvedTrees,
    maliciousAdvisories: parsed.maliciousAdvisories ?? [],
    standing,
    // ⛔ WHICH VALUE `grant` ABOVE IS, AND WHY. `rec` is an explicit whitelist, so the first version
    // of the grant-source rule narrowed `grant` correctly and then dropped every field explaining it
    // — a record whose grant had been narrowed with nothing saying on what basis, which is the exact
    // silent-narrowing shape the rule exists to prevent. The parse-level tests all passed; only an
    // end-to-end run of this CLI shows it, which is why one now exists.
    grantSource: parsed.grantSource ?? null,
    grantSourceReason: parsed.grantSourceReason ?? null,
    descendedGrant: parsed.descendedGrant ?? null,
    // ⛔⛔ BOTH OF THESE WERE PARSED AND NEITHER REACHED THE RECORD. `rec` is an explicit whitelist, so
    // a field added to the parser and not to this list is computed on every run and then thrown away
    // — the same half-wired shape `marker-contract.test.mjs` exists to catch one level up, except
    // that guard only covers the VENUE/RAWLOG/EVENTLOG families and cannot see these two.
    // `confinedWide` shipped in that state: the wide-but-confined probe ran, printed its marker, was
    // parsed into a field, and vanished — so the one arm that adjudicates the WRITE axis of a
    // `write:"disk"` record left no trace in the corpus at all. `descentUnsupported` is its sibling
    // for the axes a descent could not test. Both are diagnosis and neither can narrow a grant.
    confinedWide: parsed.confinedWide ?? null,
    descentUnsupported: parsed.descentUnsupported ?? null,
    // ⛔ ON THE RECORD BECAUSE `publish-guard.mjs` HAS NO LOG. It decides whether a re-measure may
    // REPLACE a committed record, and it sees two `results.json` and nothing else — so the evidence
    // that licensed a narrowing has to travel IN the record or the guard withholds exactly the
    // records this rule just narrowed. `falsifiabilityReasons` rides along for the same reason it
    // exists above: `arms-unfalsifiable` alone cannot say which detector died.
    falsifiabilityReasons: parsed.falsifiabilityReasons ?? null,
    // ⛔⛔ AND THIS IS THE FIELD WHOSE ABSENCE FROM THIS WHITELIST WOULD REPEAT `confinedWide`'s
    // SCAR EXACTLY. `arm-falsifiability.mjs` has emitted `manifestFiles` since it was written and
    // nothing has ever read it; parsing it above and omitting it here would leave the fact stranded
    // one step further along, in a recorder that now knows the subject was missing and tells no
    // downstream consumer. `narrowingEvidence` in `publish-guard.mjs` is the consumer — used both by
    // `decide()` and by `collate.mjs`'s Gate 2 — and it reads records, never logs.
    //
    // `?? null` is the right collapse HERE and the wrong one in the parser: by this point the parser
    // has already separated "the key was absent" (null) from "the key said null" (false), so an
    // undefined arriving from an older `parsed` shape means not-established, which is what null is.
    subjectInObserveTree: parsed.subjectInObserveTree ?? null,
    descentRedArm: parsed.descentRedArm === true,
    // Same reason as the two fields above: `publish-guard.mjs` reads records, not logs, and a
    // WITNESSED capability is the strongest reason a re-measure must not be allowed to narrow.
    denialWitness: parsed.denialWitness ?? {},
    // ⛔⛔ ON THE RECORD FOR THE SAME REASON AS THE THREE FIELDS ABOVE, AND IT IS THE ONE THAT STOPS A
    // FUTURE LICENCE FROM PUBLISHING AN UNDER-GRANT. `publish-guard.mjs` reads records and never
    // logs, so the fact that the lifecycle script produced NOTHING in this venue reaches it here or
    // not at all — and that fact is what tells a `{}` that means "needs nothing" from a `{}` that
    // means "did nothing". `confinedWide` is the scar this list carries: parsed into a field and
    // dropped from the emitted object, so the arm ran for nothing on every package that had one.
    observedEffect: observedEffect({
      lifecyclePids: parsed.observedCounts?.lifecyclePids ?? null,
      writes: parsed.observedCounts?.writes ?? null,
      peers: parsed.observedCounts?.peers ?? null,
      declares: parsed.declaresInstallWork,
    }),
    // ⛔ AND IT MUST BE IN THIS LIST, WHICH IS THE HALF `confinedWide` GOT WRONG. The comment above
    // records what that cost: the probe ran, printed its marker, was parsed into a field, and was then
    // dropped from the emitted object — so the arm that adjudicates the write axis of a `write:"disk"`
    // record left no trace in any record. This field is the ONLY route by which a `writePaths`
    // narrowing's evidence reaches `publish-guard.mjs`, which reads records and never logs, so
    // omitting it here would leave the probe running for nothing on every package that has one.
    // `promotion-probe-round-trip` in `record.test.mjs` pins it.
    promotionProbe: parsed.promotionProbe ?? null,
    notes: [...new Set(parsed.notes)],
    // The event log's own census, inlined so `results.json` states how much evidence sits beside
    // it — event count, dropped-event count, the errno histogram — without opening the log.
    eventLog: parsed.eventLog,
    driverRc: rc,
    durationMs: Number(opt('--duration-ms', '0')) || null,
    provenance: {
      platform,
      harness: opt('--driver', ''),
      nubGitSha: opt('--nub-sha', '') || null,
      nubVersion: opt('--nub-version', '') || null,
      corpusGitSha: opt('--corpus-sha', '') || corpusShaFromCheckout(),
      harnessEpoch: harnessIdentity.harnessEpoch,
      harnessSha256: harnessIdentity.harnessSha256,
      harnessInputCount: harnessIdentity.inputCount,
      invalidationPolicySha256: harnessIdentity.invalidationPolicySha256,
      node: process.version,
      runtime,
      at: new Date().toISOString(),
      ...venueProvenance(parsed, platform),
    },
  };

  const dir = path.join(opt('--out'), rec.provenance.platform, pkg.replace(/\//g, '+'), version);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  // ⛔ `driver.out`, NOT `driver.log`. The repo's `.gitignore` carries a bare `*.log`, so the v1
  // corpus tracks results.json ALONE — every per-cell log it writes is silently dropped, and a
  // `.log` here would vanish the same way while looking committed on the runner's disk. MEASURED:
  // `git ls-files records | grep -c '\.log$'` is 0 against 6,750 records.
  //
  // Keeping the log is a deliberate trade, not an oversight. A v2 verdict summarises a multi-arm run
  // — synthesis, a verify arm, one descent arm per capability — so without it a surprising grant can
  // only be re-measured, never re-read, and "WHAT did the script touch" is the exact question v1
  // could never answer. Cost, sized from the captured fixtures: ~5 KB per record, ~35 MB across a
  // full three-platform corpus.
  fs.writeFileSync(path.join(dir, 'driver.out'), log);

  // ⛔ THE EVENT LOG IS COPIED INTO THE RECORD DIR, WHICH IS THE ONLY THING THE PUBLISHER COPIES.
  // `publish-record-v2.sh` does `cp -R "$REC_DIR/."` and stages the paths in its manifest — so a
  // file left in the driver's `mktemp -d` fixture root is not "somewhere else", it is GONE the
  // moment the runner ends. This copy is the whole difference between retention and a log message.
  //
  // ⛔ `events.ndjson.gz`, NOT `events.log`. The repo's `.gitignore` carries a bare `*.log`, so a
  // file named that vanishes at `git add` while looking perfectly present on the runner's disk —
  // measured on the v1 corpus, where `git ls-files records | grep -c '\.log$'` is 0 against 6,750
  // records. `driver.out` carries the same scar for the same reason.
  //
  // Gzipped rather than plain: the checkout cost is what bounds how long retention stays
  // affordable, and `gzcat`/`zgrep` keep the corpus-wide query the maintainer asked for ("what do
  // all the outside-writes look like?") a one-liner. Reversible — the driver writes both.
  //
  // ⛔ ORDER IS DELIBERATE: THE RAW TRACE AND ITS CAPTURE HEADER GO FIRST. They are the ARCHIVE —
  // the normalized `events.ndjson.gz` is a derived cache that can be rebuilt from them. If disk,
  // a size cap, or a publish policy ever forces one of the three out, the two that must survive are
  // `trace.txt.gz` and `capture.json`; the third is a re-parse away. Copying them first is what
  // makes that ordering true in practice rather than only in a comment.
  const copies = [
    [parsed.rawLogPath, 'trace.txt.gz', 'rawlog-copy-failed'],
    [parsed.capturePath, 'capture.json', 'capture-copy-failed'],
    [parsed.eventLogPath, 'events.ndjson.gz', 'eventlog-copy-failed'],
  ];
  let copyFailed = false;
  for (const [src, name, note] of copies) {
    if (!src) continue;
    try {
      fs.copyFileSync(src, path.join(dir, name));
    } catch (e) {
      // Loud, and recorded: retention is additive, so a copy failure must not cost a measured
      // package — but a record that silently lost its evidence is the state being fixed.
      rec.notes = [...new Set([...rec.notes, note])];
      copyFailed = true;
      console.error(`record.mjs: WARN could not copy ${src}: ${e.message}`);
    }
  }
  if (copyFailed) fs.writeFileSync(path.join(dir, 'results.json'), `${JSON.stringify(rec, null, 2)}\n`);
  console.log(dir);
}
