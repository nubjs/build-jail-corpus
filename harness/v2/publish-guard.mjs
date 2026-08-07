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
// ⛔ AND IT IS UNSOUND ON DARWIN, WHICH IS WHY THE PLATFORM IS READ. `measure-macos.sh`'s descent is
// `if verify …; then OVER-PREDICTED; else "IS necessary"` — a two-way branch, so a VOID arm (rc 2,
// the override not engaging) and an early `return 1` both collapse into "necessary". `ANY_OVER`
// stays empty and the driver prints `=> MINIMAL` having proven nothing. `measure.sh` and
// `measure-windows.mjs` both keep three outcomes and are sound. So on darwin `MINIMAL` cannot be
// read as "a detector fired", and this returns false — which withholds MORE on darwin, the safe
// direction, until the macOS descent distinguishes VOID from a real failure.
export const hasRedArm = (rec) => {
  if (String(rec?.provenance?.platform ?? '').startsWith('darwin')) return false;
  return rec?.minimality === 'MINIMAL' && capsOf(rec?.grant).size > 0;
};

// A verdict that is not a measurement. `collate.mjs` drops every non-`MINIMUM` verdict from the
// catalog, so replacing a measured `MINIMUM` with one of these does not merely change a grant — it
// removes the package from the catalog entirely, which is the widest possible under-grant and looks
// like housekeeping in a diff.
const isMeasurement = (rec) => rec?.verdict === 'MINIMUM';

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

  if (dropped.length === 0) {
    return { publish: true, reason: 'does not narrow the existing grant' };
  }
  const unfalsifiable = notesOf(incoming).includes('arms-unfalsifiable');
  if (!unfalsifiable) {
    return { publish: true, reason: `narrows (${dropped.join(', ')}) on falsifiable arms` };
  }
  if (hasRedArm(incoming)) {
    return {
      publish: true,
      reason: `narrows (${dropped.join(', ')}) but the descent proved every remaining capability `
        + 'necessary with arms that went red, so a live detector fired',
    };
  }
  return {
    publish: false,
    reason: `WITHHELD — would drop ${dropped.join(', ')} from ${JSON.stringify(prior?.grant ?? null)} `
      + `to ${JSON.stringify(incoming?.grant ?? null)} on arms that could not have failed `
      + `(${notesOf(incoming).join(', ')}), and no descent arm went red. A narrower grant with no `
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
