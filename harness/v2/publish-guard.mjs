// Decide whether a freshly-measured record may REPLACE the one already in the corpus.
//
// ⛔ THIS EXISTS BECAUSE `arm-falsifiability.mjs` IS "FLAG, NEVER FAIL" AND NOTHING ACTED ON THE FLAG.
// That policy is right for the case that motivated it — `ttf2woff2@1.2.3`, where the grant is
// substantively correct and only the MEASUREMENT proved nothing; refusing that record would lose a
// usable grant to buy nothing. But it has a hole it does not name: a vacuous record that would
// NARROW an existing grant. Narrowing on evidence that could not have gone red is an UNDER-GRANT
// published under a flag nobody is required to read, and under-granting is the one direction this
// project forbids.
//
// The rule, and it is deliberately asymmetric:
//
//   Flag-never-fail stands, EXCEPT where a vacuous record would narrow an existing grant.
//   Widening or confirming on a vacuous arm is fine — it cannot break an install.
//   Narrowing on one WITHHOLDS, with the flag and the prior grant recorded as the reason.
//
// ⛔ "NARROW" IS ABOUT THE EFFECTIVE GRANT, NOT ABOUT THE TOKEN SET. A FIRST measurement of `{}` drops
// no token — there is no prior grant to drop one from — and still reduces what nub grants, because an
// ABSENT catalog entry falls back to the baseline WITH its write-path promotion while an EMPTY entry
// disables promotion outright. `decide`'s `introducesEmptyEntry` term carries that case; the code
// there quotes the nub source that makes the two differ.
//
// ⛔ "VACUOUS" IS NOT THE SAME AS "CARRIES THE arms-unfalsifiable NOTE", AND CONFLATING THE TWO
// BLOCKS CORRECT RECORDS. `arm-falsifiability.mjs` reports INDEPENDENT reasons: `gate-vacuous` kills
// the artifact gate, `rc-vacuous` kills the exit code. A package flagged `gate-vacuous` ALONE still
// has rc as a live detector, and if its descent arms actually FAILED then the narrowing rests on a
// detector that demonstrably fired.
//
// MEASURED on the 2026-08-07 linux-x64 re-measure, and this pair is why the rule needs the third
// term rather than two:
//
//   playwright-chromium@0.17.0      gate-vacuous, both drop arms rc=1  -> narrowing IS evidence
//   @pulumi/gcp@0.16.9              gate-vacuous, ZERO drop arms       -> narrowing is NOT evidence
//
// ⛔ READ THE PULUMI FIGURES OFF THE RE-MEASURE, NOT OFF THE COMMITTED RECORD. The committed
// `@pulumi/gcp@0.16.9` is the 2026-08-06 one — `OVER-PREDICTED`, `notes: []`, two drop arms that
// both PASSED — because the re-measure was withheld by this very rule and never replaced it. The
// `arms-unfalsifiable` / zero-arm values cited here are from that withheld run, preserved in the
// record's `withheldRemeasure` block. An earlier revision of this comment said "the committed
// record", which pointed a reader at figures that contradict it.
//
// Both carry `arms-unfalsifiable`. A two-term rule refuses both, which would discard a correct
// narrowing proven by two red arms — a rule that blocks everything looks correct and is not.
//
//   usage: node publish-guard.mjs --prior <old results.json> --incoming <new results.json>
//          exit 0 = publish, 10 = withhold (any other non-zero = usage/IO error)

import fs from 'node:fs';
import { vetoesNarrowing } from './observed-effect.mjs';

// A grant's capabilities as flat tokens, so "narrower" is a set question rather than a shape one.
// `{"write":{"deps":true},"network":true}` -> {"write.deps", "network"}. A false-valued key is not a
// capability: `{"network":false}` grants nothing and must not read as covering `network`.
// ⛔ `write` AND `read` ARE EACH EITHER AN OBJECT OF SCOPES OR THE STRING `"disk"`, AND MISSING THE
// STRING FORM MAKES THE LARGEST POSSIBLE NARROWING READ AS A NO-OP. The ladder's top rungs in
// `measure.sh` are `{"write":{…},"read":"disk","network":true}` and `{"write":"disk","network":true}`.
// `write:"disk"` still reaches the record intact because that rung is never descended at all
// (`Object.keys("disk")` would fabricate arms). `read:"disk"` no longer does: all three drivers now
// enumerate `no-read`, so a rung-1 record can arrive having DROPPED the whole `read` axis — which is
// the single largest narrowing this guard will ever be asked to judge, and it is judged correctly
// only because `scopeTokens` gives the string form its own token. An earlier
// revision of this file gated on
// `typeof w === 'object'`, so `{"write":"disk","network":true}` flattened to `{"network"}` alone —
// and a re-measure narrowing that to `{"network":true}` reported "does not narrow" and would have
// published whole-disk-write → nothing as though it changed nothing. Caught in review before any v2
// ladder record existed, but not hypothetical: both PRIOR playwright records were
// `verifiedBy: "ladder"`, so only the top rung had never been reached.
//
// ⛔⛔ GIVING THE STRING FORM A TOKEN IS HALF THE JOB, AND THE MISSING HALF FAILS IN THE OPPOSITE
// DIRECTION. An OPAQUE `write:disk` token satisfies no per-scope token — which is right going DOWN,
// `"disk"` → `{deps}` — and is satisfied BY no per-scope token either, which is wrong going UP:
// `{deps,project}` → `"disk"` is the widest write grant that exists replacing a bounded one, and a
// set difference over opaque tokens reports it as `narrows (write.deps, write.project)`. `"disk"` is
// "the absence of confinement rather than a rule" (`crates/nub-sandbox/src/compiler/curated.rs`), so
// that is the largest widening the corpus can express, described as its opposite.
//
// The token set IS the order, so every implication the catalog's vocabulary carries has to be
// MATERIALISED here or the difference cannot see it. Two exist, both stated in
// `crates/nub-sandbox/src/catalog_v2.rs`, and both are materialised below:
//
//   `Reach::Disk` covers every scope        `covers()`: `Self::Disk => true`
//   `write` implies read at its own scope   `check_write_implies_read` REJECTS the redundant pair
//
// This is the same move `harness/states.mjs`'s `atomsOf` already makes, for the reason it states
// there: containment becomes plain set inclusion and never has to know the semantics.

// The scope vocabulary each axis accepts, mirroring the `allowed` argument `parse_reach` is called
// with. `read` has no `deps` — read on a declared dependency is part of the base profile, so there is
// no such capability to grant or to drop, and emitting the token would name one that cannot exist.
const AXIS_SCOPES = { write: ['deps', 'project', 'userHome'], read: ['project', 'userHome'] };

// The ONLY string `parse_reach` accepts on either axis: every other string is a parse error there.
const DISK = 'disk';

const scopeTokens = (out, axis, v) => {
  if (v === undefined || v === null || v === false) return;
  if (typeof v === 'object') {
    for (const [k, on] of Object.entries(v)) if (on === true) out.add(`${axis}.${k}`);
    return;
  }
  // The maximal form keeps its OWN token, so dropping to the full scope set is still the narrowing it
  // is, and additionally emits every per-scope token it covers, so widening TO it is not.
  if (v === DISK) {
    out.add(`${axis}:${DISK}`);
    for (const s of AXIS_SCOPES[axis]) out.add(`${axis}.${s}`);
    return;
  }
  // ⛔ EVERY OTHER NON-OBJECT REACH STAYS OPAQUE, AND THAT IS FAIL-CLOSED RATHER THAN UNFINISHED.
  // `parse_reach` accepts no other string and rejects `true` outright, so this shape can only reach
  // here from a record no catalog could hold. Expanding it would be a guess in the under-grant
  // direction: were such a form ever NARROWER than disk, expanding it would make a real narrowing
  // away from `"disk"` report as a no-op. One token and no scopes instead — which reads as a
  // narrowing in BOTH directions, so it can only ever withhold.
  out.add(`${axis}:${v === true ? '*' : v}`);
};

export const capsOf = (grant) => {
  const out = new Set();
  if (!grant || typeof grant !== 'object') return out;
  if (grant.network === true) out.add('network');
  scopeTokens(out, 'write', grant.write);
  scopeTokens(out, 'read', grant.read);
  // ⛔ THE IMPLIED READS EXIST IN NO GRANT'S TEXT, WHICH IS EXACTLY WHY THEY MUST BE ADDED HERE.
  // `check_write_implies_read` REJECTS a `read` beside `write:"disk"`, and rejects `read.<s>` wherever
  // `write` already covers `<s>` — "a grant whose author believed it was doing something is worse
  // than one that fails the build". So a legal grant never spells the implied half out, and without
  // this the ladder's own `{write:{…},read:"disk"}` → `{write:"disk"}` — a widening `measure.sh`
  // produces — reports as dropping the entire read axis.
  if (out.has(`write:${DISK}`)) out.add(`read:${DISK}`);
  for (const s of AXIS_SCOPES.read) if (out.has(`write.${s}`)) out.add(`read.${s}`);
  return out;
};

// NARROWS = the incoming record drops a capability the corpus currently grants. A record that only
// ADDS is widening (safe), and one that both adds and drops still narrows on the dropped term —
// which is the term that can break an install.
export const narrows = (priorGrant, incomingGrant) => {
  const a = capsOf(priorGrant); const b = capsOf(incomingGrant);
  return [...a].filter((c) => !b.has(c));
};

const notesOf = (rec) => (Array.isArray(rec?.notes) ? rec.notes : []);

// ⛔⛔ THE ARMS WERE NOT LOOKING AT THE PACKAGE. This is not a weaker detector — it is no detector,
// and it outranks every term in this file in the refusing direction.
//
// The observe arm is `npm rebuild <pkg>`. Run against a tree that does not contain `<pkg>` it
// executes nothing, the decoder attributes zero lifecycle pids, and the synthesized grant is `{}` —
// byte-identical to the grant of a package that genuinely needs nothing. Every detector this file
// weighs then answers about that empty run: the artifact gate passes (no artifact was expected), the
// exit code is 0 (nothing ran to fail), a denial witness comes back CLEAN (nothing was attempted to
// be refused), and `minimality` reads MINIMAL by construction. So the record arrives looking like the
// cleanest measurement in the corpus.
//
// MEASURED over all 6,887 committed `driver.out` files: `arm-falsifiability.mjs` reported
// `manifestFiles: null` — its `pkgDir()` resolved no layout for the subject — in 39 records, 36
// linux-x64 and 3 darwin-arm64. Every one carries an `ARM-SCAFFOLD` line and `reasons: []`, so NOT
// ONE of them is caught by the `arms-unfalsifiable` note this file's other terms key on. 15 are
// `MINIMUM` and 13 of those publish `grant: {}`.
//
// ⛔ THE DRIVER HALF IS ALREADY CLOSED AND THIS IS STILL NEEDED. All three drivers now re-install the
// subject after the scaffold and REFUSE (`ARM-SUBJECT-EVICTED` → `=> UNKNOWN`) rather than measure a
// tree without it — `subject-survives-scaffold.test.mjs` pins that on all three. But a rule only runs
// at measurement time, and those 39 records are frozen at the bad answer with their logs beside them.
// This is the reading half: the same fact, applied where records are SCORED.
//
// ⛔ `=== false` AND NOTHING LOOSER. `subjectInObserveTree` is a tri-state — `null`/absent means the
// marker predates the field or there is no marker at all, which describes 1,220 committed logs, and
// reading those as absent-subject would make `collate.mjs`'s Gate 2 floor the entire corpus.
export const subjectAbsent = (rec) => rec?.subjectInObserveTree === false;

// ⛔ A RED ARM IS THE WHOLE POINT, AND `MINIMAL` ALONE DOES NOT IMPLY ONE.
// `minimality: "MINIMAL"` means "no capability in the grant was droppable". With a NON-EMPTY grant
// that is the descent having run one arm per capability and every arm having FAILED — red arms, so a
// detector demonstrably fired. With an EMPTY grant it means the driver printed "grant is already
// empty — nothing to narrow; MINIMAL by construction" and ran NO arms at all. Same word, opposite
// evidentiary weight, and reading it as one is how `@pulumi/gcp@0.16.9` would have published `{}`.
//
// ⛔ AND THE `MINIMAL` INFERENCE IS UNSOUND ON DARWIN, WHICH IS WHY THE PLATFORM IS READ.
// `measure-macos.sh`'s descent USED TO BE `if verify …; then OVER-PREDICTED; else "IS necessary"` —
// a two-way branch, so a VOID arm (rc 2, the override not engaging) and an early `return 1` both
// collapsed into "necessary". `ANY_OVER` stayed empty and the driver printed `=> MINIMAL` having
// proven nothing. It has branched three ways since c95f47d2e (2026-08-28), so a FRESH darwin record
// is sound — but `minimality` does not say which driver produced it, and the corpus still holds
// darwin records measured under the two-way form. The carve-out therefore stays: on darwin `MINIMAL`
// alone cannot be read as "a detector fired", which withholds MORE there, the safe direction.
//
// ⛔⛔ THE SECOND TERM IS DIRECT AND NEEDS NO SUCH CARVE-OUT. `minimality: MINIMAL` is an INFERENCE
// about arms — "no capability dropped, so every arm must have failed" — and that inference is what
// the darwin branch above breaks. `descentRedArm` is the driver's own per-arm announcement of an
// rc=1 outcome, emitted only from the `*)` default of a three-way `case`; a VOID arm is announced as
// `INCONCLUSIVE for` instead and can never produce it. On darwin the announcement did not exist AT
// ALL before the three-way `case` landed, in the same commit, so it has never had an unsound form.
// MEASURED across all 6887 committed `driver.out` files: 2311 carry the announcement and ZERO of
// those contain a VOID descent arm.
//
// It also answers a case `MINIMAL` structurally cannot. `MINIMAL` requires EVERY arm red, so an
// OVER-PREDICTED record — some arms red, some green — has no red-arm evidence under the first term
// even when the descent plainly went red. Those are precisely the records `record.mjs` now narrows,
// and without this term the guard would withhold every one of them.
export const hasRedArm = (rec) => {
  if (rec?.descentRedArm === true) return true;
  if (String(rec?.provenance?.platform ?? '').startsWith('darwin')) return false;
  return rec?.minimality === 'MINIMAL' && capsOf(rec?.grant).size > 0;
};

// A verdict that is not a measurement. `collate.mjs` drops every non-`MINIMUM` verdict from the
// catalog, so replacing a measured `MINIMUM` with one of these does not merely change a grant — it
// removes the package from the catalog entirely, which is the widest possible under-grant and looks
// like housekeeping in a diff.
const isMeasurement = (rec) => rec?.verdict === 'MINIMUM';

// ⛔ THE THREE-TERM RULE, EXPORTED, BECAUSE A SECOND CONSUMER NOW ASKS THE IDENTICAL QUESTION.
// `collate.mjs` decides whether a catalog CELL may sit narrower than the shipped one, and the
// question "could the evidence behind this narrowing have gone red?" does not change with the unit
// it is asked about. Reimplementing it there is how the two would drift, and the naive two-term
// form — refuse anything carrying the note — is the exact drift to expect: it withholds
// `playwright-chromium@0.17.0`, a correct narrowing proven by two red arms, because a rule that
// blocks everything looks right and is not.
//
// ⛔⛔ THE THIRD TERM — THE PROMOTION PROBE — AND WHY IT IS NOT A WAIVER FOR `writePaths`.
//
// A `{"writePaths":[…]}` grant flattens to the EMPTY token set, so `hasRedArm`'s second clause
// (`minimality === 'MINIMAL' && capsOf(grant).size > 0`) is false by construction and no drop arm
// exists for the descent to announce red. Every narrowing to such a grant therefore reached the last
// branch below, and MEASURED on the committed corpus that is not a theoretical set:
// `records-v2/runs/darwin-arm64/@clerk+shared/2.9.2/results.json` is `grant:
// {"writePaths":["Library/Preferences/clerk"]}`, `minimality: "MINIMAL"`, `arms-unfalsifiable`,
// beside a win32 record for the same version still carrying `{"write":{"userHome":true}}`.
//
// The fix is NOT to exempt the shape. `promotion-probe.mjs` runs a real arm that removes the
// declaration and re-installs, scored by a detector the other three cannot supply — the declared
// entry's presence in the arm's OWN fresh real home — and a PROVEN pair means the control arm
// produced the entry and the drop arm did not. That is a detector that demonstrably fired, in this
// venue, on this package.
//
// ⛔ AND IT LICENSES ONE TOKEN, NOT A NARROWING. `licensedByPromotion` returns the capability set the
// pair actually speaks to, and `narrowingEvidence` requires EVERY dropped token to be in it — the same
// `every`-over-dropped-capabilities shape `record.mjs` uses for the denial witness. A pair that proves
// the home artefact travelled through the promotion says nothing about `network` or `read`, so a
// narrowing that also drops one of those still withholds.
//
// ⛔ THE PAYLOAD IS RE-CHECKED, NOT TRUSTED BY ITS VERDICT WORD. A record is a file this guard did not
// write, and `verdict: "PROVEN"` beside entries that say `drop: true` is exactly the shape a
// half-updated driver would emit. Re-deriving the verdict from the rows costs four lines and removes
// the word from the trust boundary.
const licensedByPromotion = (rec) => {
  const p = rec?.promotionProbe;
  if (!p || p.verdict !== 'PROVEN') return new Set();
  const rows = Array.isArray(p.entries) ? p.entries : [];
  if (!rows.length) return new Set();
  if (!rows.every((r) => r?.control === true && r?.drop === false)) return new Set();
  // ⛔ THE CONTROL ARM MUST NOT HAVE HELD A LIVE HANDLE ON THE REAL HOME, or its PRESENT is
  // unattributable — the script could have written the real home directly and the promotion moved
  // nothing. `probePlan` already declines that case, so this is the guard's own re-derivation of the
  // precondition rather than a second policy: a record whose grant carries `write.userHome` or
  // `write:"disk"` beside a PROVEN probe is an instrument disagreement, and the safe reading is that
  // the probe proves nothing.
  const caps = capsOf(rec?.grant);
  if (caps.has('write.userHome') || caps.has('write:disk')) return new Set();
  // ⛔ CLOSED UNDER THE IMPLICATION `capsOf` MATERIALISES, AND THAT IS NOT A WIDER LICENCE — IT IS THE
  // SAME ONE, SPELLED IN THE VOCABULARY THE DROP SET NOW USES. No grant ever authored `read.userHome`;
  // `capsOf` derives it from `write.userHome`, which is the token the probe speaks to. So a narrowing
  // that gives up the home write gives up both, and demanding separate evidence for the derived half
  // would demand evidence of a decision nobody made — the `costAtomsOf` distinction `states.mjs` draws
  // between authored atoms and free implied ones, applied to the licence instead of to cost.
  // It is still ONE capability: an INDEPENDENTLY-authored `read.project` is not implied by
  // `write.userHome`, is not in this set, and still withholds.
  return new Set(['write.userHome', 'read.userHome']);
};

// The `why` is returned rather than a bare boolean so a caller can say WHICH term carried it; the
// branches of `decide` below are now just this predicate plus their own prose.
//
// ⛔ `dropped` IS OPTIONAL AND ITS ABSENCE IS STRICTLY MORE CONSERVATIVE. `collate.mjs` calls this to
// gate a whole PLATFORM and has no per-cell drop set to hand over, so it cannot ask the scoped
// question the promotion term answers — and not being able to ask it means no licence, which keeps
// that consumer exactly as strict as it was before this term existed.
export const narrowingEvidence = (rec, dropped = null) => {
  // ⛔⛔ TESTED FIRST, ABOVE THE `arms-unfalsifiable` EARLY RETURN, AND BOTH HALVES OF THAT POSITION
  // ARE LOAD-BEARING. Above the early return, because not one of the 39 measured records carries the
  // note — they all report `reasons: []`, so a term placed below it is unreachable for every record
  // this exists to catch. Above `hasRedArm` and `licensedByPromotion`, because those are LICENCES and
  // a licence derived from the same empty tree is worth nothing: an arm that went red in a tree
  // without the subject proves the jail fires, not that this package needs the capability.
  if (subjectAbsent(rec)) {
    return {
      evidence: false,
      why: 'an observe tree that did not contain the subject at all (ARM-FALSIFIABILITY reported no '
        + 'package directory) — `npm rebuild` ran nothing, so no arm in this record measured this '
        + 'package and no detector here can speak to it',
    };
  }
  if (!notesOf(rec).includes('arms-unfalsifiable')) {
    return { evidence: true, why: 'falsifiable arms' };
  }
  if (hasRedArm(rec)) {
    return {
      evidence: true,
      why: 'arms that went red — the descent proved every remaining capability necessary, '
        + 'so a live detector fired',
    };
  }
  const licensed = licensedByPromotion(rec);
  if (Array.isArray(dropped) && dropped.length && dropped.every((c) => licensed.has(c))) {
    return {
      evidence: true,
      why: 'a PROMOTION PROBE that went red — the same grant with `writePaths` removed did NOT '
        + `deliver ${rec.promotionProbe.entries.map((r) => r.entry).join(', ')} into the arm's real `
        + 'home, while the grant with it did, so the declaration is what carries the artefact and the '
        + 'home write it replaces was never needed',
    };
  }
  return {
    evidence: false,
    why: `arms that could not have failed (${notesOf(rec).join(', ')}), and no descent arm went red`
      + (licensed.size
        ? `; the promotion probe is PROVEN but licenses only ${[...licensed].join(', ')}`
        : rec?.promotionProbe
          ? `; the promotion probe came back ${rec.promotionProbe.verdict}`
          : ''),
  };
};

export const decide = (prior, incoming) => {
  const dropped = narrows(prior?.grant, incoming?.grant);

  // ⛔ CHECKED BEFORE THE NARROWING TEST, because a degraded verdict carries `grant: null` and
  // `notes: []`, so it would otherwise fall through as "narrows on falsifiable arms" — a phrase that
  // is true and completely beside the point. A re-measure that could not measure is not evidence
  // that the prior measurement was wrong; the host may simply be missing a precondition, which is
  // exactly what @pulumi/kubernetes@0.14.0 turned out to be.
  if (isMeasurement(prior) && !isMeasurement(incoming) && capsOf(prior?.grant).size > 0) {
    return {
      publish: false,
      reason: `WITHHELD — would replace a measured MINIMUM `
        + `${JSON.stringify(prior?.grant ?? null)} with verdict ${incoming?.verdict ?? 'null'}, which `
        + 'collate.mjs drops from the catalog entirely. A re-measure that could not measure is not '
        + 'evidence the prior grant was wrong — check for a missing host precondition.',
    };
  }

  // ⛔⛔ AN EMPTY ENTRY IS TIGHTER THAN NO ENTRY, WHICH IS WHY THE VETO CANNOT SIT BELOW
  // `dropped.length === 0`.
  //
  // `narrows` is a set difference, so a FIRST measurement — no prior record at all — always yields an
  // empty `dropped`, for the opposite reason a confirming re-measure does: there was no grant to take
  // anything away from. Both reached the early return below and published.
  //
  // For a re-measure that is right, and the old comment's rationale holds: widening or confirming
  // cannot break an install. For a first measurement of `{}` it is FALSE, because nub does not treat
  // an absent catalog entry and an empty one alike (`crates/nub-cli/src/pm_engine/build_jail.rs`):
  //
  //     let caps = match catalog_override_v2_grant(name, version) {
  //         Some(grant) => grant.on(here),
  //         None => Cow::Owned(baseline_caps()),   // ABSENT -> baseline, WITH its write_paths
  //     };
  //     if caps.write_paths.is_empty() { return; } // EMPTY  -> promotion disabled entirely
  //
  // So publishing `{}` where the corpus held nothing REMOVES the baseline's promotion, silently,
  // while every grant still reads correctly. That is a narrowing in effect even though it drops no
  // token, and `records-v2/runs/darwin-arm64/@pulumi+gcp/6.9.0` is already committed in that state.
  //
  // The condition is therefore "would this record REDUCE what the catalog grants" — it narrows a
  // prior grant, OR it introduces an empty entry where no measured empty entry stands today. A
  // re-measure that merely CONFIRMS an existing `{}` changes nothing and is left alone, and a
  // no-effect run that WIDENS still publishes exactly as it did.
  const introducesEmptyEntry = isMeasurement(incoming)
    && capsOf(incoming?.grant).size === 0
    && !(isMeasurement(prior) && capsOf(prior?.grant).size === 0);

  // ⛔⛔ THE PRIOR-EST QUESTION OF ALL, AND IT SITS ABOVE THE `observed-effect` VETO BECAUSE IT
  // SUBSUMES IT. That one asks whether the script DID anything; this asks whether the package was
  // even in the tree. A subject-absent arm necessarily attempted nothing, so this is the more
  // specific finding of the two, and the reason text has to say so — "the script produced no
  // observable effect" sends a reader hunting for a missing host precondition, when the tree simply
  // had no package in it to rebuild.
  //
  // ⛔ SAME CONDITION AS THE VETO BELOW, AND THE `introducesEmptyEntry` HALF IS THE ONE THAT MATTERS
  // HERE. 13 of the 15 MINIMUM records in this population publish `grant: {}` with nothing prior, so
  // `dropped` is empty for every one of them — a term gated on `dropped.length > 0` alone would let
  // all 13 through. An empty entry is TIGHTER than no entry (see `introducesEmptyEntry` above), so
  // publishing one off an empty tree withdraws the baseline's write-path promotion.
  //
  // ⛔ AND IT IS A REFUSAL, NEVER A LICENCE, exactly like the veto below: it can only ever move a
  // record from publish to WITHHELD, and a widening or confirming record still publishes as it did.
  if (subjectAbsent(incoming) && (dropped.length > 0 || introducesEmptyEntry)) {
    const what = dropped.length
      ? `would drop ${dropped.join(', ')} from ${JSON.stringify(prior?.grant ?? null)} to `
        + `${JSON.stringify(incoming?.grant ?? null)}`
      : 'would publish an EMPTY entry where the corpus has none, which disables the baseline\'s '
        + 'write-path promotion rather than leaving it in place';
    return {
      publish: false,
      reason: `WITHHELD — ${what}, but ARM-FALSIFIABILITY reported no package directory in the `
        + 'observe tree, so `npm rebuild` ran nothing and this record measured a tree the subject '
        + 'was never in. Its `{}` means "did not run", not "needs nothing". Re-measure on a tree '
        + 'that holds the subject; do not narrow it.',
    };
  }

  // ⛔⛔ THE VETO, AND IT IS TESTED BEFORE `narrowingEvidence` SO THAT NO PRESENT OR FUTURE TERM CAN
  // OUTRANK IT. Every term below answers "could this arm have gone red?". This one answers a prior
  // question — "did the script DO anything in this venue?" — and when the answer is no, none of the
  // detectors below are measuring the package at all.
  //
  // ⛔ IT IS A REFUSAL, NEVER A LICENCE. `NONE` can only move a record from publish to WITHHELD; no
  // verdict `observed-effect.mjs` returns can license a narrowing. So this strengthens the
  // asymmetry rather than relaxing it, and a record measured before the marker existed scores
  // UNKNOWN and keeps exactly the behaviour it had.
  //
  // MEASURED on the 2026-09-01 win32-x64 re-measure: ten of the twelve withheld `{}` records are
  // this state, nine of them `@pulumi/*`, whose `install-pulumi-plugin.js` ends in an unconditional
  // `process.exit(0)` after a `spawnSync("pulumi", …)` that ENOENTs on a runner with no Pulumi CLI.
  // A denial witness scored on their VERIFY arm returns CLEAN — correctly, and uselessly, because
  // the script attempted nothing to be refused. That is the fix this term exists to pre-empt.
  if (vetoesNarrowing(incoming) && (dropped.length > 0 || introducesEmptyEntry)) {
    const e = incoming.observedEffect;
    const what = dropped.length
      ? `would drop ${dropped.join(', ')} from ${JSON.stringify(prior?.grant ?? null)} to `
        + `${JSON.stringify(incoming?.grant ?? null)}`
      : 'would publish an EMPTY entry where the corpus has none, which disables the baseline\'s '
        + 'write-path promotion rather than leaving it in place';
    return {
      publish: false,
      reason: `WITHHELD — ${what}, but `
        + `${e.reason}. Nothing here measured the PACKAGE, so no detector — a red arm, a live gate or `
        + 'a CLEAN denial witness — can speak to this record. Re-measure on a venue that supplies '
        + "whatever the script silently needs, or record it as unmeasurable; do not narrow it.",
    };
  }

  // Past the veto, a record that takes nothing away publishes as it always did. This return moved
  // BELOW the veto rather than away: everything under it reasons about DROPPED capabilities, so with
  // an empty `dropped` it has nothing to judge and `narrowingEvidence` would withhold on a question
  // this record does not ask.
  if (dropped.length === 0) {
    return { publish: true, reason: 'does not narrow the existing grant' };
  }
  // ⛔ `dropped` IS PASSED, AND THAT IS WHAT MAKES THE PROMOTION TERM REACHABLE AT ALL. The term is
  // scoped to the capability the probe actually speaks to, so a caller that does not say WHICH
  // capabilities are being dropped cannot get it — see `narrowingEvidence`'s own note.
  const { evidence, why } = narrowingEvidence(incoming, dropped);
  if (evidence) {
    return { publish: true, reason: `narrows (${dropped.join(', ')}) on ${why}` };
  }
  return {
    publish: false,
    reason: `WITHHELD — would drop ${dropped.join(', ')} from ${JSON.stringify(prior?.grant ?? null)} `
      + `to ${JSON.stringify(incoming?.grant ?? null)} on ${why}. A narrower grant with no `
      + 'falsifiable evidence behind it is an under-grant.',
  };
};

if (import.meta.filename === process.argv[1]) {
  const argv = process.argv.slice(2);
  const opt = (n) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : '');
  const read = (p) => (p && fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null);
  const priorPath = opt('--prior'); const incomingPath = opt('--incoming');
  if (!incomingPath) {
    console.error('usage: publish-guard.mjs --prior <results.json> --incoming <results.json>');
    process.exit(2);
  }
  const d = decide(read(priorPath), read(incomingPath));
  console.log(`${d.publish ? 'PUBLISH' : 'WITHHOLD'}: ${d.reason}`);
  process.exit(d.publish ? 0 : 10);
}
