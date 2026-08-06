// KNOWN-ANSWER FIXTURE for 8.3 SHORT NAMES. Two modes, one file, because the expectation and the
// assertion must agree on the same two spellings and splitting them invites drift.
//
// ⛔ THE HAZARD IS A SCOPE DEFECT, NOT A COSMETIC ONE. NTFS keeps a legacy 8.3 spelling for a name
// that does not fit, and the kernel reports whichever spelling the CALLER used. On a GitHub runner
// `%TEMP%` is literally `C:\Users\RUNNER~1\AppData\Local\Temp` while `%USERPROFILE%` is
// `C:\Users\runneradmin`, so the same directory arrives under two names in one trace. The
// classifier assigns scope by longest-prefix against the roots it is handed, and
// `c:\users\runner~1\...` does not start with `c:\users\runneradmin\` -- so a real write under the
// user profile is bucketed `outside`, reported and never granted. Measured on the one real package
// the viability probe traced: 543 paths, 1 write and 542 reads, every one of them genuinely under
// the profile and every one classified `outside`.
//
// ⛔ THE FIXTURE MUST BE ABLE TO NOT APPLY, AND SAY SO. If `%TEMP%` on this runner carries no `~`
// there is no short name to expand and the assertion would pass while measuring nothing. That case
// reports SKIP explicitly rather than a green tick.
//
//   usage: node shortname-kaf.mjs write  <expect.json>   -- runs INSIDE the trace
//          node shortname-kaf.mjs assert <expect.json> <events.ndjson>
import fs from 'node:fs';
import path from 'node:path';

const [mode, expectPath, evPath] = process.argv.slice(2);
const LEAF = 'nub83probe.bin';

if (mode === 'write') {
  const short = process.env.TEMP ?? '';
  // realpathSync.native goes through GetFinalPathNameByHandle, which returns the LONG spelling --
  // this is the ground truth, taken from the OS rather than assembled from a guess.
  let long = null;
  try { long = fs.realpathSync.native(short); } catch { /* leave null; the assert reports it */ }
  const target = path.join(short, LEAF);
  fs.writeFileSync(target, Buffer.alloc(64, 0x83));
  fs.writeFileSync(expectPath, JSON.stringify({
    tempEnv: short,
    tempLong: long,
    shortPath: target,
    longPath: long ? path.join(long, LEAF) : null,
    applicable: short.includes('~') && !!long && long.toLowerCase() !== short.toLowerCase(),
  }, null, 2));
  console.log(`SHORTNAME wrote ${target}\n          long spelling ${long ? path.join(long, LEAF) : '(unresolved)'}`);
  process.exit(0);
}

if (mode !== 'assert') { console.error('usage: shortname-kaf.mjs write|assert <expect.json> [events.ndjson]'); process.exit(2); }

const exp = JSON.parse(fs.readFileSync(expectPath, 'utf8'));
const fold = (p) => String(p).replace(/\//g, '\\').toLowerCase();
const writes = new Set();
for (const line of fs.readFileSync(evPath, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  const e = JSON.parse(line);
  if (e.op === 'write' && e.result !== 'denied' && e.path) writes.add(fold(e.path));
}

console.log(`TEMP env      ${exp.tempEnv}`);
console.log(`TEMP long     ${exp.tempLong}`);
if (!exp.applicable) {
  console.log('SHORTNAME SKIP -- %TEMP% on this runner carries no 8.3 component, so there is nothing');
  console.log('                  to expand and a pass here would measure nothing.');
  process.exit(0);
}

const sawLong = writes.has(fold(exp.longPath));
const sawShort = writes.has(fold(exp.shortPath));
console.log(`  [${sawLong ? 'PASS' : 'FAIL'}] the write is reported under the LONG spelling   ${exp.longPath}`);
console.log(`  [${sawShort ? 'FAIL' : 'PASS'}] the SHORT spelling no longer appears            ${exp.shortPath}`);
// One file, one spelling. Both present is the dedup error the expansion exists to remove; only the
// short one present is the scope defect itself.
console.log(`\nSHORTNAME ${sawLong && !sawShort ? 'PASSED' : 'FAILED'}`);
