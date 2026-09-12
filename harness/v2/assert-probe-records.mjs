// Artifact-only campaigns require every requested record and exact runtime provenance.
// This gate checks measurement completeness, not whether a grant should be published.
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { validateCampaignSnapshot } from './campaign-provenance.mjs';

// `record.mjs` normalizes every driver spelling of a verified grant to MINIMUM.
// `verifiedBy` preserves whether VERIFY accepted the synthesized grant or a ladder repair.
const VERIFIED_BY = new Set(['synth', 'ladder']);

export function checkRecord(record, expected) {
  const errors = [];
  if (record.pkg !== expected.pkg || record.version !== expected.version) errors.push('package');
  if (record.harnessVersion !== 2 || record.driverRc !== 0) errors.push('driver');
  if (record.verdict !== 'MINIMUM' || !VERIFIED_BY.has(record.verifiedBy)
    || !record.grant || typeof record.grant !== 'object' || Array.isArray(record.grant)) {
    errors.push('verification');
  }
  for (const key of ['platform', 'nubGitSha', 'corpusGitSha', 'harnessSha256']) {
    if (!expected[key] || record.provenance?.[key] !== expected[key]) errors.push(key);
  }
  if (!expected.nubSha256 || record.provenance?.nubBinary?.sha256 !== expected.nubSha256) errors.push('nubSha256');
  if (expected.campaign) {
    try { validateCampaignSnapshot(expected.campaign); } catch { errors.push('campaignExpected'); }
    if (JSON.stringify(record.provenance?.runtime?.campaign) !== JSON.stringify(expected.campaign)) errors.push('campaign');
  }
  return errors;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const opt = (key) => args[args.indexOf(key) + 1];
  for (const key of ['--file', '--runs', '--expected', '--out']) {
    if (!args.includes(key) || !opt(key)) throw new Error(`missing ${key}`);
  }
  const specs = fs.readFileSync(opt('--file'), 'utf8').trim().split(/\s+/);
  if (!specs[0] || new Set(specs).size !== specs.length) throw new Error('empty or duplicate worklist');
  const expected = JSON.parse(fs.readFileSync(opt('--expected'), 'utf8'));
  const records = specs.map((spec) => {
    const at = spec.lastIndexOf('@');
    if (at <= 0 || at === spec.length - 1) throw new Error(`invalid spec ${spec}`);
    const pkg = spec.slice(0, at), version = spec.slice(at + 1);
    const file = path.join(opt('--runs'), expected.platform, pkg.replaceAll('/', '+'), version, 'results.json');
    try {
      const record = JSON.parse(fs.readFileSync(file, 'utf8'));
      return { spec, file, verdict: record.verdict, grant: record.grant, errors: checkRecord(record, { ...expected, pkg, version }) };
    } catch (error) {
      return { spec, file, errors: [error.message] };
    }
  });
  fs.writeFileSync(opt('--out'), `${JSON.stringify({ expected, records }, null, 2)}\n`);
  if (records.some((record) => record.errors.length)) process.exitCode = 1;
}
