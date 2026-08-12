// recover-recent.mjs — generate a supplementary v2 queue that RECOVERS the broken high-download
// packages by measuring their CURRENT version.
//
// WHY: the v2 queue is derived spec-for-spec from v1 (make-queue-v2.mjs), which includes many OLD
// versions of popular packages. Old versions rot — deps unpublished from npm, prebuilt-binary URLs
// go 404, build files vanish from old tarballs — so they land BROKEN-WITHOUT-JAIL-TOO even unjailed.
// The PACKAGE is fine: measured on a sample, 86% of high-download broken packages install clean at
// latest with the enriched fixture (peers + build tools). This tool emits queue rows for the latest
// version of each high-download broken package so the corpus measures what users actually install.
//
//   usage: node recover-recent.mjs --platform linux-x64 [--min-downloads 10000] [--out recover-queue.ndjson]
//
// The OS token in each row mirrors the record's platform dir. Append the output to queue-v2.ndjson
// (or feed it to the runner) to schedule the recovery measurements. Rows whose latest version is
// already measured are skipped.

import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';

const argv = process.argv.slice(2);
const opt = (n, d) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : d);
const PLATFORM = opt('--platform', 'linux-x64');
const MIN_DL = Number(opt('--min-downloads', '10000'));
const OUT = opt('--out', '');
const RECORDS = path.join('records-v2', 'runs', PLATFORM);
const OS_TOKEN = PLATFORM.startsWith('win') ? 'win32' : PLATFORM.startsWith('darwin') ? 'darwin' : 'linux';

function walk(dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (e.name === 'results.json') acc.push(p);
  }
  return acc;
}
const get = (u, headers = {}) => new Promise((res) => {
  https.get(u, { headers }, (r) => { let d = ''; r.on('data', (c) => (d += c)); r.on('end', () => { try { res(JSON.parse(d)); } catch { res(null); } }); }).on('error', () => res(null));
});

// Broken names + the versions already measured (to skip dups)
const broken = new Map(); // name -> Set(versions measured, any verdict)
const measuredVer = new Map();
for (const f of walk(RECORDS)) {
  let r; try { r = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { continue; }
  if (!r.pkg || !r.version) continue;
  (measuredVer.get(r.pkg) || measuredVer.set(r.pkg, new Set()).get(r.pkg)).add(r.version);
  if (r.verdict === 'BROKEN-WITHOUT-JAIL-TOO') broken.set(r.pkg, true);
}
const names = [...broken.keys()];
process.stderr.write(`broken names on ${PLATFORM}: ${names.length}\n`);

const rows = [];
let skippedDl = 0, skippedDead = 0, skippedMeasured = 0;
for (let i = 0; i < names.length; i += 25) {
  await Promise.all(names.slice(i, i + 25).map(async (name) => {
    const dl = await get('https://api.npmjs.org/downloads/point/last-month/' + name.replace(/^@/, '%40'));
    if (!dl || (dl.downloads || 0) < MIN_DL) { skippedDl++; return; }
    const meta = await get('https://registry.npmjs.org/' + name.replace(/^@/, '%40'), { Accept: 'application/vnd.npm.install-v1+json' });
    const latest = meta && meta['dist-tags'] && meta['dist-tags'].latest;
    if (!latest) { skippedDead++; return; }
    if ((measuredVer.get(name) || new Set()).has(latest)) { skippedMeasured++; return; }
    rows.push({ pkg: name, version: latest, os: OS_TOKEN, status: 'pending', downloads: dl.downloads });
  }));
}
rows.sort((a, b) => b.downloads - a.downloads);
const ndjson = rows.map((r) => JSON.stringify({ pkg: r.pkg, version: r.version, os: r.os, status: 'pending' })).join('\n') + '\n';
if (OUT) fs.writeFileSync(OUT, ndjson);
process.stderr.write(`recovery rows (>=${MIN_DL}/mo, latest not yet measured): ${rows.length}  [skipped: ${skippedDl} low-dl, ${skippedDead} dead, ${skippedMeasured} latest-already-measured]\n`);
process.stderr.write('top 20:\n' + rows.slice(0, 20).map((r) => `  ${String(r.downloads).padStart(9)} ${r.pkg}@${r.version}`).join('\n') + '\n');
if (!OUT) process.stdout.write(ndjson);
