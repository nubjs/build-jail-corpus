// A cached lifecycle payload can legitimately make a narrow *warm* arm work. It must never be
// credited as evidence that the same grant works cold. This classifier admits that narrow outcome
// only for the one case with a functional and provenance oracle; every other sufficient warm arm
// remains the P0 falsification failure.

import { CJPEG_PATH } from './cjpeg-oracle.mjs';

export const requiresCjpegOracle = (kase, diagnostic = false) => diagnostic
  || kase.oracle === 'cjpeg';

const malformed = (message) => ({ kind: 'inconclusive', message });
const failure = (message) => ({ kind: 'fail', message });
const reused = (message) => ({ kind: 'warm-reused', message });
const normal = (message) => ({ kind: 'not-applicable', message });

const phases = ['before-right', 'after-right-before-wrong-warm', 'after-wrong-warm'];
const normalize = (value) => value.replaceAll('\\', '/').toLowerCase();
const artifactShape = (artifact) => artifact && artifact.status === 'present'
  && artifact.path === CJPEG_PATH
  && typeof artifact.realpath === 'string' && artifact.realpath.length > 0
  && Number.isInteger(artifact.bytes) && artifact.bytes >= 0
  && typeof artifact.sha256 === 'string' && /^[a-f0-9]{64}$/.test(artifact.sha256);
const sameArtifact = (a, b) => a.path === b.path && a.realpath === b.realpath
  && a.bytes === b.bytes && a.sha256 === b.sha256;
const underStore = (artifact, store) => {
  const normalizedArtifact = normalize(artifact.realpath);
  const normalizedStore = normalize(store).replace(/\/$/, '');
  return normalizedArtifact.startsWith(`${normalizedStore}/`);
};

const oracleRecord = (arm) => {
  const record = arm?.cjpegOracleRecord;
  if (!record || record.label !== 'at-grant') return null;
  if (!artifactShape(record.artifact)) return null;
  if (!record.execution || typeof record.execution.status !== 'number'
    || !Object.hasOwn(record.execution, 'error') || !Object.hasOwn(record.execution, 'signal')) return null;
  return record;
};

/**
 * Classify a sufficient `wrong-warm` arm without weakening cold grant inference.
 *
 * The return is deliberately tri-state: malformed/missing evidence is INCONCLUSIVE, while a
 * complete but contradictory control is a P0 FAIL. That distinction prevents a damaged capture
 * from becoming a green result while still surfacing a real post-right mutation.
 */
export const classifyWarmReuse = ({ kase, cold, right, warm, provenance }) => {
  if (warm?.verdict !== 'SUFFICIENT') return normal('warm arm was not sufficient');
  if (!requiresCjpegOracle(kase)) {
    return failure('the sufficient wrong-warm arm has no case-scoped functional/provenance oracle');
  }
  if (!cold || !right || !warm || cold.verdict !== 'INSUFFICIENT' || right.verdict !== 'SUFFICIENT') {
    return malformed('the cold/right/warm control verdicts are incomplete');
  }
  const booleanControls = ['storeShared', 'scriptRan', 'evidenceIsSound', 'refusalSeen', 'sideEffectsRestored'];
  if (booleanControls.some((key) => typeof warm[key] !== 'boolean')) {
    return malformed('the warm arm is missing structured control evidence');
  }
  if (!warm.storeShared || !warm.scriptRan || !warm.evidenceIsSound) {
    return failure('the sufficient warm arm did not prove a shared, executed lifecycle control');
  }
  if (!warm.refusalSeen) {
    return failure('the sufficient warm arm did not retain the expected denied-network control');
  }
  if (warm.sideEffectsRestored) {
    return failure('the sufficient warm arm restored a side-effects-cache result rather than exercising the store control');
  }
  if (!Array.isArray(provenance) || provenance.length !== phases.length
    || provenance.map((entry) => entry?.phase).join(',') !== phases.join(',')) {
    return malformed('the three GVS provenance snapshots are missing or malformed');
  }
  const [before, afterRight, afterWarm] = provenance.map((entry) => entry.artifact);
  if (!before || before.status !== 'missing' || typeof before.store !== 'string') {
    return failure('the shared GVS already contained the cjpeg payload before the sufficient control');
  }
  if (!afterRight || !afterWarm || typeof afterRight.store !== 'string' || afterRight.store.length === 0
    || afterRight.store !== afterWarm.store || typeof afterRight.entry !== 'string' || afterRight.entry.length === 0
    || afterRight.entry !== afterWarm.entry
    || !artifactShape(afterRight.artifact) || !artifactShape(afterWarm.artifact)) {
    return malformed('the post-control GVS provenance is incomplete or malformed');
  }
  if (!underStore(afterRight.artifact, afterRight.store) || !underStore(afterWarm.artifact, afterWarm.store)) {
    return failure('the cjpeg provenance escaped the shared GVS');
  }
  if (!sameArtifact(afterRight.artifact, afterWarm.artifact)) {
    return failure('the cjpeg payload changed during the narrowed warm arm');
  }
  const rightRecord = oracleRecord(right);
  const warmRecord = oracleRecord(warm);
  if (!rightRecord || !warmRecord) {
    return malformed('the per-arm cjpeg functional records are missing or malformed');
  }
  if (rightRecord.execution.status !== 0 || warmRecord.execution.status !== 0
    || rightRecord.execution.error !== null || warmRecord.execution.error !== null
    || rightRecord.execution.signal !== null || warmRecord.execution.signal !== null) {
    return failure('the cjpeg functional oracle did not succeed in both sufficient and warm arms');
  }
  if (!sameArtifact(afterRight.artifact, rightRecord.artifact)
    || !sameArtifact(afterWarm.artifact, warmRecord.artifact)) {
    return failure('the per-arm cjpeg artifact does not match the GVS provenance');
  }
  return reused('the warm arm reused the unchanged cjpeg payload created by the sufficient control; it is not cold-grant evidence');
};
