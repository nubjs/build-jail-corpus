// Bind an artifact-only campaign's actual sidecar and inputs into each runtime snapshot.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyBundle } from './runtime-bundle.mjs';

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
export const hashFile = (file) => sha256(fs.readFileSync(file));
const digest = (value, key) => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/i.test(value)) throw new Error(`campaign ${key} is not a sha256`);
};
const required = ['runtimeBundleSha256', 'addonSha256', 'runtimeRecipeSha256', 'catalogSha256', 'worklistSha256', 'manifestSha256', 'runPlanSha256', 'workflowSha256'];

export function validateCampaignSnapshot(snapshot) {
  if (snapshot?.schemaVersion !== 1 || snapshot?.kind !== 'catalog-boundary-artifact') throw new Error('campaign snapshot has an unknown schema');
  for (const key of required) digest(snapshot[key], key);
  if (snapshot.busyboxSha256 !== null) digest(snapshot.busyboxSha256, 'busyboxSha256');
  return snapshot;
}

export function createCampaignContext({ bundleRoot, runtimeRecipeSha256, catalog, worklist, manifest, runPlan, workflow }) {
  const manifestFile = path.join(bundleRoot, 'runtime-bundle.json');
  const bundle = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  verifyBundle(bundleRoot, bundle.identity);
  const platform = bundle.identity.platform;
  const addon = path.join(bundleRoot, 'runtime', 'addons', 'nub-native.node');
  const busybox = platform === 'win32' ? path.join(bundleRoot, 'busybox.exe') : null;
  const campaign = validateCampaignSnapshot({
    schemaVersion: 1, kind: 'catalog-boundary-artifact', runtimeBundleSha256: hashFile(manifestFile),
    addonSha256: hashFile(addon), busyboxSha256: busybox ? hashFile(busybox) : null, runtimeRecipeSha256,
    catalogSha256: hashFile(catalog), worklistSha256: hashFile(worklist), manifestSha256: hashFile(manifest),
    runPlanSha256: hashFile(runPlan), workflowSha256: hashFile(workflow),
  });
  return { schemaVersion: 1, campaign, verification: { bundleRoot, identity: bundle.identity, files: { addon, busybox, catalog, worklist, manifest, runPlan, workflow } } };
}

export function verifyCampaignContext(context) {
  validateCampaignSnapshot(context?.campaign);
  if (context?.schemaVersion !== 1 || !context?.verification?.bundleRoot || !context?.verification?.identity) throw new Error('campaign context is incomplete');
  verifyBundle(context.verification.bundleRoot, context.verification.identity);
  const { files } = context.verification;
  const actual = createCampaignContext({ bundleRoot: context.verification.bundleRoot,
    runtimeRecipeSha256: context.campaign.runtimeRecipeSha256, ...files }).campaign;
  if (JSON.stringify(actual) !== JSON.stringify(context.campaign)) throw new Error('campaign input or sidecar digest changed');
  return context.campaign;
}

function cli(argv) {
  const option = (name) => argv.includes(name) ? argv[argv.indexOf(name) + 1] : null;
  if (argv.includes('--sha256')) { console.log(hashFile(option('--file'))); return; }
  if (argv.includes('--sha256-stdin')) { console.log(sha256(fs.readFileSync(0))); return; }
  const args = { bundleRoot: option('--runtime-bundle'), runtimeRecipeSha256: option('--runtime-recipe-sha256'),
    catalog: option('--catalog'), worklist: option('--worklist'), manifest: option('--manifest'), runPlan: option('--run-plan'), workflow: option('--workflow') };
  if (argv.includes('--create')) {
    const out = option('--out'); if (!out) throw new Error('--create requires --out');
    fs.writeFileSync(out, `${JSON.stringify(createCampaignContext(args), null, 2)}\n`); return;
  }
  if (argv.includes('--verify')) { verifyCampaignContext(JSON.parse(fs.readFileSync(option('--context'), 'utf8'))); return; }
  throw new Error('choose --create, --verify, --sha256, or --sha256-stdin');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { cli(process.argv.slice(2)); } catch (error) { console.error(`CAMPAIGN-PROVENANCE-ERROR ${error.message}`); process.exitCode = 2; }
}
