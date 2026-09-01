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
const scopeTokens = (out, axis, v) => {
  if (v === undefined || v === null || v === false) return;
  // The string form is the WIDEST grant on its axis, so it gets one token that no per-scope token
  // can satisfy — `write:"disk"` → `write:{deps:true}` must therefore read as a narrowing.
  if (typeof v === 'string') { out.add(`${axis}:${v}`); return; }
  if (v === true) { out.add(`${axis}:*`); return; }
  if (typeof v === 'object') {
    for (const [k, on] of Object.entries(v)) if (on === true) out.add(`${axis}.${k}`);
  }
};

export const capsOf = (grant) => {
  const out = new Set();
  if (!grant || typeof grant !== 'object') return out;
  if (grant.network === true) out.add('network');
  scopeTokens(out, 'write', grant.write);
  scopeTokens(out, 'read', grant.read);
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
  return new Set(['write.userHome']);
};

// The `why` is returned rather than a bare boolean so a caller can say WHICH term carried it; the
// branches of `decide` below are now just this predicate plus their own prose.
//
// ⛔ `dropped` IS OPTIONAL AND ITS ABSENCE IS STRICTLY MORE CONSERVATIVE. `collate.mjs` calls this to
// gate a whole PLATFORM and has no per-cell drop set to hand over, so it cannot ask the scoped
// question the promotion term answers — and not being able to ask it means no licence, which keeps
// that consumer exactly as strict as it was before this term existed.
export const narrowingEvidence = (rec, dropped = null) => {
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
