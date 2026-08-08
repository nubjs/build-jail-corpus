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
