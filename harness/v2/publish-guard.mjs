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
// MEASURED, and this pair is why the rule needs the third term rather than two:
//
//   playwright-chromium@0.17.0      gate-vacuous, both drop arms rc=1  -> narrowing IS evidence
//   @pulumi/gcp@0.16.9              gate-vacuous, ZERO drop arms       -> narrowing is NOT evidence
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
export const capsOf = (grant) => {
  const out = new Set();
  if (!grant || typeof grant !== 'object') return out;
  if (grant.network === true) out.add('network');
  const w = grant.write;
  if (w && typeof w === 'object') {
    for (const [k, v] of Object.entries(w)) if (v === true) out.add(`write.${k}`);
  }
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
export const hasRedArm = (rec) =>
  rec?.minimality === 'MINIMAL' && capsOf(rec?.grant).size > 0;

export const decide = (prior, incoming) => {
  const dropped = narrows(prior?.grant, incoming?.grant);
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
