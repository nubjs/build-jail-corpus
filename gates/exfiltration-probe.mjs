// DOES A NETWORK-GRANTED PACKAGE STILL FAIL TO EXFILTRATE? The mission's central claim, tested.
//
// 43.2% of packages with a usable grant are granted `network` (measured, 874 of 2,025 on the fresh
// linux tree). Denying reads is only worth something if those packages ALSO cannot reach the
// credentials a Shai-Hulud-style worm wants. This probe grants `network: true` through the catalog --
// the single most common grant in the catalog -- and then tries to read the real credential set.
//
// ⛔ THE INSTRUMENT PROBLEM THIS FILE EXISTS TO AVOID: an ENOENT IS NOT A DENIAL. A probe that reads
// ~/.aws/credentials on a box that has no ~/.aws gets ENOENT and, read carelessly, looks exactly like
// enforcement. So the probe CREATES a decoy at every path it tests, in the REAL home, before running
// -- and it reports the errno, never a boolean, so ENOENT can never be scored as a block.
//
// Two arms, varying ONE thing (buildJail), because a denial under the jail proves nothing unless the
// same read SUCCEEDS without it.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const NUB = process.env.PROBE_NUB || process.env.CANARY_NUB;
if (!NUB) throw new Error('set PROBE_NUB (or CANARY_NUB) to a nub built with build-jail-catalog-override');
const CATALOG_SRC = process.env.PROBE_CATALOG_SRC;  // a real baked catalog, to borrow baseline+env from
const REAL_HOME = process.env.HOME || process.env.USERPROFILE;
if (!REAL_HOME) throw new Error('neither HOME nor USERPROFILE is set');
const ROOT = path.join(REAL_HOME, 'nub-spotcheck', '_exfil');
const DEP = 'exfil-probe-dep';

// The credential set, each with a decoy planted so a denial is distinguishable from absence.
const TARGETS = [
  ['npmrc', path.join(REAL_HOME, '.npmrc-exfilprobe'), '//registry.npmjs.org/:_authToken=DECOY-NPM-TOKEN'],
  ['awsCreds', path.join(REAL_HOME, '.aws-exfilprobe', 'credentials'), '[default]\naws_secret_access_key=DECOY'],
  ['sshKey', path.join(REAL_HOME, '.ssh-exfilprobe', 'id_rsa'), '-----BEGIN DECOY KEY-----'],
  ['ghToken', path.join(REAL_HOME, '.config-exfilprobe', 'gh', 'hosts.yml'), 'github.com:\n  oauth_token: DECOY'],
  ['plainSecret', path.join(REAL_HOME, '.exfilprobe-secret.txt'), 'DECOY-SECRET'],
];

for (const [, p, body] of TARGETS) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, body);
}
// Prove the decoys are readable by THIS process, so "unreadable in the arm" cannot be a setup bug.
for (const [name, p] of TARGETS) {
  try { fs.readFileSync(p, 'utf8'); } catch (e) { throw new Error(`decoy ${name} unreadable by the harness: ${e.code}`); }
}

const POSTINSTALL = [
  "const fs = require('fs'), net = require('net'), os = require('os');",
  'const out = { reads: {} };',
  'out.homedirSeen = os.homedir();',
  `const targets = ${JSON.stringify(TARGETS.map(([n, p]) => [n, p]))};`,
  'for (const [name, p] of targets) {',
  "  try { const s = fs.readFileSync(p, 'utf8');",
  "        out.reads[name] = 'READ:' + s.slice(0, 12); }",
  "  catch (e) { out.reads[name] = 'err:' + (e.code || 'unknown'); }",
  '}',
  // A base-profile system read. Expected to SUCCEED on both arms; it is here so a blanket
  // "everything failed" (a broken arm) is distinguishable from targeted credential denial.
  //
  // ⛔ PLATFORM-AWARE, BECAUSE A HARDCODED /etc/passwd MAKES THIS CONTROL VACUOUS ON WINDOWS. The
  // first run of this probe on win32 reported `err:ENOENT` on both arms — the path simply does not
  // exist there — so the one check that distinguishes targeted denial from a blanket-broken arm was
  // silently dead on the platform whose confinement is weakest. A control that cannot fire is not a
  // control. `win.ini` is the NT-era equivalent: present on every Windows install and readable.
  "const sysPath = process.platform === 'win32'",
  "  ? require('path').join(process.env.SystemRoot || 'C:\\\\Windows', 'win.ini')",
  "  : '/etc/passwd';",
  'out.sysPathTried = sysPath;',
  "try { fs.readFileSync(sysPath, 'utf8'); out.etcPasswd = 'READ'; }",
  "catch (e) { out.etcPasswd = 'err:' + (e.code || 'unknown'); }",
  // Env-carried credentials: the other half of the Shai-Hulud input set.
  "out.envNpm = process.env.NPM_TOKEN || '(absent)';",
  "out.envGh  = process.env.GITHUB_TOKEN || '(absent)';",
  "out.envAws = process.env.AWS_SECRET_ACCESS_KEY || '(absent)';",
  'const done = (v) => { out.net = v;',
  "  console.log('EXFIL ' + JSON.stringify(out)); };",
  "const s = net.connect({ host: '1.1.1.1', port: 443 });",
  's.setTimeout(5000);',
  "s.on('connect', () => { s.destroy(); done('SUCCEEDED'); });",
  "s.on('timeout', () => { s.destroy(); done('denied:timeout'); });",
  "s.on('error', (e) => { done('denied:' + (e.code || 'err')); });",
].join('\n');

// A catalog granting the probe package `network: true` -- and nothing else. baseline/env are borrowed
// from a real baked catalog so the shape is exactly what ships rather than a hand-guessed minimum.
function buildCatalog(dest) {
  let baseline = [], env = [];
  if (CATALOG_SRC && fs.existsSync(CATALOG_SRC)) {
    const src = JSON.parse(fs.readFileSync(CATALOG_SRC, 'utf8'));
    baseline = src.baseline ?? [];
    env = src.env ?? [];
  }
  fs.writeFileSync(dest, JSON.stringify({
    packages: { [DEP]: { default: { network: true, notes: 'exfiltration probe: network only' } } },
    baseline, env,
  }, null, 2));
}

function once(jailOn) {
  const dir = path.join(ROOT, jailOn ? 'on' : 'off');
  fs.rmSync(dir, { recursive: true, force: true });
  const dep = path.join(dir, 'dep');
  fs.mkdirSync(dep, { recursive: true });
  fs.mkdirSync(path.join(dir, 'home'), { recursive: true });
  fs.writeFileSync(path.join(dep, 'package.json'), JSON.stringify({
    name: DEP, version: '1.0.0', scripts: { postinstall: 'node postinstall.js' },
  }) + '\n');
  fs.writeFileSync(path.join(dep, 'postinstall.js'), POSTINSTALL);
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({
    name: 'exfilroot' + (jailOn ? 'on' : 'off'), version: '1.0.0', private: true,
    dependencies: { [DEP]: 'file:./dep' },
  }) + '\n');
  fs.writeFileSync(path.join(dir, 'nub.jsonc'), JSON.stringify({ install: { buildJail: jailOn } }) + '\n');
  fs.writeFileSync(path.join(dir, '.npmrc'), 'side-effects-cache=false\n');
  const cat = path.join(dir, 'catalog.json');
  buildCatalog(cat);

  // ⛔ HOME is NOT redirected here, unlike the canary. The point is to test reads of the REAL home,
  // which is where the decoys live; redirecting HOME would make every read an ENOENT and the probe
  // would "pass" while testing nothing. The jail's own homedir redirect still applies inside the arm.
  const env = { ...process.env, NUB_BUILD_JAIL_CATALOG: cat,
    NPM_TOKEN: 'DECOY-ENV-NPM', GITHUB_TOKEN: 'DECOY-ENV-GH', AWS_SECRET_ACCESS_KEY: 'DECOY-ENV-AWS' };
  delete env.XDG_CACHE_HOME;
  const r1 = spawnSync(NUB, ['install'], { cwd: dir, env, encoding: 'utf8', timeout: 300000 });
  const r2 = spawnSync(NUB, ['approve-builds', '--all'], { cwd: dir, env, encoding: 'utf8', timeout: 300000 });
  const log = (r1.stdout || '') + (r1.stderr || '') + (r2.stdout || '') + (r2.stderr || '');
  fs.writeFileSync(path.join(dir, 'run.log'), log);
  const m = /EXFIL (\{.*\})/.exec(log);
  return { jailOn, rc: r1.status, result: m ? JSON.parse(m[1]) : null,
    overridden: /catalog OVERRIDDEN/.test(log), rejected: /REJECTED/.test(log) };
}

const off = once(false);
const on = once(true);

console.log('\n=== exfiltration probe: a package granted `network: true` and nothing else ===');
for (const r of [off, on]) {
  console.log(`  jail ${r.jailOn ? 'ON ' : 'OFF'}: rc=${r.rc} overridden=${r.overridden} rejected=${r.rejected}` +
    `${r.result ? '' : '  (NO REPORT)'}`);
}
if (!off.result || !on.result) { console.log('\nINCONCLUSIVE: an arm never ran the script.'); process.exit(3); }
if (!on.overridden) { console.log('\nINCONCLUSIVE: the jailed arm did not load the probe catalog.'); process.exit(3); }
// ⛔ THE POSITIVE CONTROL. If network were denied in the jailed arm, "cannot exfiltrate" would be
// trivially true and would say NOTHING about the 43.2% of packages that DO hold a network grant.
if (on.result.net !== 'SUCCEEDED') {
  console.log(`\nINCONCLUSIVE: the jailed arm's network was ${on.result.net}, so the grant did not engage —` +
    ' this probe only means something while egress is ALLOWED.');
  process.exit(3);
}

console.log('\n  target                unjailed              ->  jailed (network GRANTED)');
for (const [name] of TARGETS) {
  console.log(`  ${name.padEnd(20)} ${String(off.result.reads[name]).padEnd(21)} ->  ${on.result.reads[name]}`);
}
const sysLabel = `sys read (${path.basename(off.result.sysPathTried || '?')})`;
console.log(`  ${sysLabel.padEnd(20)} ${String(off.result.etcPasswd).padEnd(21)} ->  ${on.result.etcPasswd}`);
console.log(`  ${'env NPM_TOKEN'.padEnd(20)} ${String(off.result.envNpm).padEnd(21)} ->  ${on.result.envNpm}`);
console.log(`  ${'env GITHUB_TOKEN'.padEnd(20)} ${String(off.result.envGh).padEnd(21)} ->  ${on.result.envGh}`);
console.log(`  ${'env AWS_SECRET'.padEnd(20)} ${String(off.result.envAws).padEnd(21)} ->  ${on.result.envAws}`);
console.log(`  ${'outbound socket'.padEnd(20)} ${String(off.result.net).padEnd(21)} ->  ${on.result.net}`);

// Score only targets the unjailed arm actually READ — anything it could not read is not evidence.
const capable = TARGETS.map(([n]) => n).filter((n) => String(off.result.reads[n]).startsWith('READ:'));
if (!capable.length) { console.log('\nINCONCLUSIVE: the unjailed arm read no decoy at all.'); process.exit(3); }
const blocked = capable.filter((n) => !String(on.result.reads[n]).startsWith('READ:'));
const leaked = capable.filter((n) => String(on.result.reads[n]).startsWith('READ:'));
// An ENOENT in the jailed arm is NOT a block — it would mean the path vanished, not that it was refused.
const enoent = capable.filter((n) => String(on.result.reads[n]) === 'err:ENOENT');

console.log('');
console.log(`  decoys the unjailed arm could read : ${capable.length}`);
console.log(`  of those, BLOCKED under the jail   : ${blocked.length}  ${blocked.join(', ')}`);
console.log(`  of those, still READABLE (leaked)  : ${leaked.length}  ${leaked.join(', ')}`);
if (enoent.length) console.log(`  ⚠ scored as blocked via ENOENT (weak): ${enoent.join(', ')}`);

const envLeaked = ['envNpm', 'envGh', 'envAws'].filter((k) => on.result[k] !== '(absent)');
console.log(`  env-carried credentials surviving  : ${envLeaked.length}  ${envLeaked.join(', ')}`);

// ⛔ THE BLANKET-DENIAL CONTROL MUST ACTUALLY FIRE, or "5 of 5 blocked" is indistinguishable from an
// arm in which every read fails for an unrelated reason. Reported loudly rather than failing the
// probe: the credential denials are still real refusals (EACCES/EPERM, not ENOENT), so the result is
// weakened, not void. This is here because the win32 run's control silently did not fire.
if (on.result.etcPasswd !== 'READ') {
  console.log(`  ⚠ WEAKENED: the system-read control did NOT succeed under the jail`
    + ` (${on.result.sysPathTried} -> ${on.result.etcPasswd}), so this run cannot rule out an arm in`
    + ' which every read fails. Treat the blocks as suggestive until a working control is in place.');
}

const verdict = leaked.length === 0;
console.log('\n' + (verdict
  ? 'A NETWORK-GRANTED PACKAGE STILL CANNOT READ THE CREDENTIAL SET — the read/exfiltrate pair is broken'
  : `LEAK: a network-granted package read ${leaked.length} credential file(s) — ${leaked.join(', ')}`));
process.exit(verdict ? 0 : 1);
