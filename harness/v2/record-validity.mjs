// Decide whether an existing v2 record answers the exact measurement a batch is about to run.
// Exact identity is the default. Reuse across epochs is possible only through an explicit transition
// whose scope does not match the record; missing transitions and malformed selectors fail closed.

const recordInstrument = (record) => ({
  harnessEpoch: record?.harnessEpoch ?? record?.provenance?.harnessEpoch ?? null,
  harnessSha256: record?.provenance?.harnessSha256 ?? null,
});

const same = (a, b) => a?.harnessEpoch === b?.harnessEpoch
  && a?.harnessSha256 === b?.harnessSha256;

function scopeMatches(scope, record) {
  if (!scope || typeof scope !== 'object') throw new Error('invalidation scope must be an object');
  if (scope.all === true) return true;
  const known = new Set(['all', 'platforms', 'packages', 'verdicts']);
  const unknown = Object.keys(scope).filter((key) => !known.has(key));
  if (unknown.length) throw new Error(`unknown invalidation selector(s): ${unknown.join(', ')}`);
  const selectors = [
    ['platforms', record?.provenance?.platform],
    ['packages', record?.pkg],
    ['verdicts', record?.verdict],
  ].filter(([key]) => scope[key] !== undefined);
  if (!selectors.length) throw new Error('an invalidation scope must set all:true or a selector');
  return selectors.every(([key, value]) => Array.isArray(scope[key]) && scope[key].includes(value));
}

// ⛔⛔ A SETTLEMENT SURVIVES AN INSTRUMENT CHANGE THAT INVALIDATES NOTHING — AND WITHOUT THIS IT DID
// NOT, WHICH IS THE SINGLE MOST EXPENSIVE DEFECT IN THIS HARNESS.
//
// A row is SETTLED when re-measuring provably cannot change the outcome: the publish guard withheld
// its record and will withhold it again, so the queue stops re-running it. `claim-slice.mjs` used to
// hold that settlement only while `settledAtHash` equalled the CURRENT digest, compared raw. Any
// harness commit moves that digest, so EVERY settled row reopened on EVERY epoch bump — even a bump
// whose transition invalidates nothing at all.
//
// MEASURED 2026-08-30 by replaying the reopen pass over a copy of the live queue at epoch 42: **59
// linux rows reopened `done` -> `pending`, all 59 lost `settledAtHash`, and 5 lost their `attempts`
// counter.** 55 of them carry `priorHarnessEpoch: null` — records from the UNVERSIONED v2 instrument,
// which no transition chain can ever rescue — so they re-settle only by being re-measured and
// re-withheld, three times each, because `RETRY_LIMIT` is 3 TOTAL attempts and the reopen deletes the
// counter. That is three ~90-minute linux slices per bump, publishing nothing.
//
// It is also why the corpus looked stalled for twelve hours: epochs 37-41 each bought those rows
// three fresh attempts, `--claim` runs BEFORE `--next-os`, and one pending row is enough to stop the
// lane handing off. The cost falls on whichever lane is draining, and on windows an attempt costs
// ~30 minutes rather than ~1.5.
//
// THE SEMANTICS ARE THE POINT, NOT THE SAVING. "Re-measuring cannot change the outcome under
// instrument X" stays true when X changes in a way that invalidates nothing — that is precisely what
// a `{verdicts: []}` transition asserts. So the settlement is walked forward along the same chain a
// RECORD is walked along, and it is dropped the instant a transition's scope actually matches the
// row. A genuine harness change still reopens it; a measurement-neutral one no longer does.
//
// Fails CLOSED in every uncertain case — an unknown digest, a forked chain, a malformed scope — so a
// settlement is only ever preserved when the chain positively says it is safe.
export function settlementSurvives(settledAtHash, record, current, policy) {
  if (!settledAtHash) return { survives: false, reason: 'row is not settled' };
  if (settledAtHash === current?.harnessSha256) return { survives: true, via: 'exact-instrument' };
  if (policy?.currentEpoch !== current?.harnessEpoch) {
    return { survives: false, reason: 'invalidation policy does not name the current harness epoch' };
  }
  // Locate the settlement on the chain by the digest it settled AT. The row records only that hash,
  // never the epoch, so the transition that PRODUCED the hash is what places it.
  const origin = policy.transitions?.find((t) => t.toHarnessSha256 === settledAtHash);
  if (!origin) return { survives: false, reason: 'the digest this row settled at is not on the transition chain' };

  let hash = origin.toHarnessSha256;
  const seen = new Set();
  while (hash !== current.harnessSha256) {
    if (seen.has(hash)) return { survives: false, reason: 'invalidation transition cycle' };
    seen.add(hash);
    const candidates = policy.transitions.filter((t) => t.fromHarnessSha256 === hash);
    if (candidates.length !== 1) {
      return { survives: false, reason: `no unique transition from digest ${hash.slice(0, 16)}` };
    }
    const [transition] = candidates;
    let invalidated;
    try { invalidated = scopeMatches(transition.invalidate, record); }
    catch (error) { return { survives: false, reason: `invalid policy: ${error.message}` }; }
    if (invalidated) return { survives: false, reason: transition.reason || 'instrument transition invalidates record' };
    if (typeof transition.toHarnessSha256 !== 'string') {
      return { survives: false, reason: 'targeted transition lacks an exact forward target identity' };
    }
    hash = transition.toHarnessSha256;
  }
  return { survives: true, via: 'targeted-transition' };
}

export function instrumentCompatibility(record, current, policy) {
  if (policy?.currentEpoch !== current?.harnessEpoch) {
    return { reusable: false, reason: 'invalidation policy does not name the current harness epoch' };
  }
  let identity = recordInstrument(record);
  if (same(identity, current)) return { reusable: true, via: 'exact-instrument' };

  const seen = new Set();
  while (identity.harnessEpoch !== current.harnessEpoch) {
    const key = JSON.stringify(identity);
    if (seen.has(key)) return { reusable: false, reason: 'invalidation transition cycle' };
    seen.add(key);
    const candidates = policy.transitions.filter((transition) =>
      transition.fromEpoch === identity.harnessEpoch);
    if (candidates.length !== 1) {
      return { reusable: false, reason: `no unique transition from harness epoch ${identity.harnessEpoch}` };
    }
    const transition = candidates[0];
    if (transition.fromHarnessSha256 !== undefined
      && transition.fromHarnessSha256 !== identity.harnessSha256) {
      return { reusable: false, reason: 'record digest does not match transition source' };
    }
    let invalidated;
    try { invalidated = scopeMatches(transition.invalidate, record); }
    catch (error) { return { reusable: false, reason: `invalid policy: ${error.message}` }; }
    if (invalidated) return { reusable: false, reason: transition.reason || 'instrument transition invalidates record' };
    if (!Number.isInteger(transition.toEpoch) || transition.toEpoch <= (identity.harnessEpoch ?? -1)
      || typeof transition.toHarnessSha256 !== 'string') {
      return { reusable: false, reason: 'targeted transition lacks an exact forward target identity' };
    }
    identity = { harnessEpoch: transition.toEpoch, harnessSha256: transition.toHarnessSha256 };
  }
  return same(identity, current)
    ? { reusable: true, via: 'targeted-transition' }
    : { reusable: false, reason: 'transition target does not match current instrument' };
}

export function recordValidity(record, current, policy, runtime = {}) {
  if (!record || record.harnessVersion !== 2) return { reusable: false, reason: 'not a v2 record' };
  if (!record.verdict || String(record.verdict).startsWith('HARNESS-')) {
    return { reusable: false, reason: 'instrument failure is not a measurement' };
  }
  const instrument = instrumentCompatibility(record, current, policy);
  if (!instrument.reusable) return instrument;
  if (runtime.platform && record.provenance?.platform !== runtime.platform) {
    return { reusable: false, reason: 'platform identity changed' };
  }
  if (runtime.nodeVersion && record.provenance?.node !== runtime.nodeVersion) {
    return { reusable: false, reason: 'Node runtime changed' };
  }
  if (runtime.nodeSha256 && record.provenance?.runtime?.node?.sha256 !== runtime.nodeSha256) {
    return { reusable: false, reason: 'Node executable changed' };
  }
  // A malware refusal occurs before Nub executes. Its resolved npm tree still depends on the
  // platform and Node/npm environment above, but changing the unused subject binary cannot change
  // the refusal. Requiring a Nub hash here would reopen every refused row forever because the honest
  // record carries no driver-emitted Nub identity.
  if (record.verdict === 'REFUSED-MALICIOUS') return instrument;
  if (runtime.nubSha256 && record.provenance?.nubBinary?.sha256 !== runtime.nubSha256) {
    return { reusable: false, reason: 'Nub binary changed' };
  }
  if (runtime.nubGitSha && record.provenance?.nubGitSha !== runtime.nubGitSha) {
    return { reusable: false, reason: 'Nub commit changed' };
  }
  return instrument;
}
