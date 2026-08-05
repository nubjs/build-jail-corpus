#!/usr/bin/env node
// Builds the adversarial fixture for the build-jail security probe.
//
// ⛔ THE REAL HOME IS BAKED IN AT GENERATION TIME, FROM OUTSIDE THE JAIL, AND THAT IS THE WHOLE
// POINT OF THE PROBE. An attacker's postinstall that calls `os.homedir()` learns only where the
// jail REDIRECTED it, so every access fails ENOENT and the jail looks like it worked — when all it
// did was move a path. Real credential-stealing malware hardcodes `/Users/<leaked-name>` or reads
// the username from a packument it already scraped. Baking the true path in here reproduces that,
// and turns the result from ENOENT (the target moved) into EPERM (the policy said no), which is the
// only outcome that demonstrates confinement.
//
// Measured on macOS 2026-08-04: round 1 used `os.homedir()` and returned ENOENT on every action.
// Reported alone it would have described a defeatable defence as a working one.
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const [, , outDir, realHome, mode] = process.argv;
if (!outDir || !realHome) {
  console.error('usage: make-probe.mjs <outDir> <realHome> [jail-off]');
  process.exit(2);
}

const attacker = join(outDir, 'attacker');
const proj = join(outDir, 'proj');
mkdirSync(attacker, { recursive: true });
mkdirSync(proj, { recursive: true });

const win = process.platform === 'win32';

// The credential files real supply-chain malware goes for. Each is probed as an ABSOLUTE path
// against the true home. A read that returns bytes is a successful credential steal.
const targets = win
  ? [
      ['read npmrc', `${realHome}\\.npmrc`],
      ['read gitconfig', `${realHome}\\.gitconfig`],
      ['read aws creds', `${realHome}\\.aws\\credentials`],
      ['read ssh key', `${realHome}\\.ssh\\id_rsa`],
    ]
  : [
      ['read npmrc', `${realHome}/.npmrc`],
      ['read gitconfig', `${realHome}/.gitconfig`],
      ['read aws creds', `${realHome}/.aws/credentials`],
      ['read ssh key', `${realHome}/.ssh/id_rsa`],
    ];

const probe = `// Adversarial probe. Benign: it reports whether each action was permitted and never
// transmits, encodes, or retains anything it reads. It exists to prove the jail denies these.
const fs = require('fs'), os = require('os');
const REAL = ${JSON.stringify(realHome)};
const results = [];
function t(name, fn) {
  let status, detail;
  try { detail = fn(); status = 'ALLOWED'; }
  catch (e) { status = 'BLOCKED'; detail = e.code || String(e).slice(0, 40); }
  results.push({ name, status, detail: String(detail) });
  console.log('  ' + status.padEnd(8) + ' ' + name.padEnd(34) + ' ' + detail);
}

console.log('=== BUILD JAIL SECURITY PROBE ===');
console.log('platform        : ' + process.platform);
console.log('redirected HOME : ' + os.homedir());
console.log('real HOME       : ' + REAL);
console.log('');

${targets
  .map(
    ([n, p]) =>
      `t(${JSON.stringify(n)}, () => fs.readFileSync(${JSON.stringify(p)}, 'utf8').length + ' bytes STOLEN');`,
  )
  .join('\n')}
t('list real home', () => fs.readdirSync(REAL).length + ' entries enumerated');
t('write persistence', () => { fs.writeFileSync(${JSON.stringify(win ? `${realHome}\\.nub-pwned` : `${realHome}/.nub-pwned`)}, 'x'); return 'persisted'; });

// Secrets in the environment are the other half of a Shai-Hulud steal.
const leaked = Object.keys(process.env).filter(k => /TOKEN|SECRET|KEY|PASSWORD|NPM_TOKEN|AWS_/i.test(k));
console.log('');
console.log('  env secrets visible : ' + (leaked.length ? leaked.join(',') : 'none present'));

const allowed = results.filter(r => r.status === 'ALLOWED').length;
console.log('');
console.log('PROBE_RESULT ' + JSON.stringify({ allowed, total: results.length, envLeaked: leaked.length, results }));
`;

writeFileSync(join(attacker, 'probe.js'), probe);
writeFileSync(
  join(attacker, 'package.json'),
  JSON.stringify(
    { name: 'evil-postinstall', version: '1.0.0', scripts: { postinstall: 'node probe.js' } },
    null,
    2,
  ),
);
writeFileSync(
  join(proj, 'package.json'),
  JSON.stringify(
    { name: 'victim', version: '1.0.0', dependencies: { 'evil-postinstall': 'file:../attacker' } },
    null,
    2,
  ),
);
// A warm side-effects cache replays a prior build, so the lifecycle script never spawns and the
// probe silently measures nothing.
writeFileSync(join(proj, '.npmrc'), 'side-effects-cache=false\n');

if (mode === 'jail-off') {
  // ⛔ THE CONTROL TURNS THE JAIL OFF VIA nub.jsonc — the ONLY global switch (#67). Without a
  // control showing all actions SUCCEED unjailed, a clean jailed run is unfalsifiable: a probe that
  // never ran reports exactly the same zeros.
  writeFileSync(join(proj, 'nub.jsonc'), JSON.stringify({ install: { buildJail: false } }, null, 2));
}

console.log(`fixture written to ${outDir} (mode=${mode || 'jailed'}, realHome=${realHome})`);
if (!existsSync(join(attacker, 'probe.js'))) process.exit(1);
