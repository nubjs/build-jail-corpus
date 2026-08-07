// Scores the jail security probe's JAILED arm. Exits 0 if the jail held, 1 if it leaked.
//
// ⛔ THIS LIVES IN A FILE BECAUSE AN INLINE `node -e '...'` IN THE WORKFLOW IS A LANDMINE.
// It was inline until 2026-08-07, when a single apostrophe in a prose comment ("the repo's most
// important gate") closed the shell string early, spilled the remaining JS into bash, and failed
// the job with `//: Is a directory` (exit 126) on BOTH POSIX platforms — while the jail itself was
// blocking 6 of 6 actions perfectly. A security gate that goes red for a quoting accident trains
// readers to ignore it, which is worse than having no gate. In a file there is no shell quoting to
// get wrong, and the tiers below are testable (score-jail-probe.test.mjs).
//
// ⛔⛔ TIERED, BECAUSE `allowed > 0` CANNOT TELL "read a secret" FROM "see a filename".
// Measured 2026-08-05 (run 30968614273): win32 denied all four credential READS and the persistence
// WRITE with EPERM, and was failed solely for enumerating the real home — which is DELIBERATE
// (`TRAVERSE_MASK` includes `FILE_LIST_DIRECTORY`, because traversal is required to reach granted
// paths at all). That one rule kept this repo's most important gate red for two days while the
// property it guards was in fact holding.
//
// ⛔ ENUMERATION IS STILL A REAL LEAK, just a far weaker one than reading `~/.aws/credentials` — it
// reveals which tools and accounts exist. So it is NOT ignored: it is its own tier, TOLERATED ONLY
// ON WINDOWS AND ONLY BECAUSE THE MECHANISM IS NAMED. On linux/macOS it stays a hard failure, so a
// POSIX regression into the same state is caught rather than excused.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const SECRET = /npmrc|gitconfig|aws creds|ssh key/i;
const PERSIST = /write persistence/i;
const ENUM = /list real home/i;

// Returns { code, lines } rather than exiting, so the tests can assert on every tier.
export function scoreProbe(log, probeOs) {
  const out = [];
  const m = log.match(/PROBE_RESULT (.*)/);

  if (!m) {
    // No probe output is the STRONGEST outcome, not a failure: nub default-denies an unapproved
    // lifecycle script, so the attacker code never executes at all. Accept it only when nub SAID
    // so — never as an unexplained absence, which is the "green step that did nothing" shape.
    if (/IGNORED_BUILD_SCRIPTS|approve-builds/.test(log)) {
      out.push('BLOCKED AT LAYER 0: the lifecycle script never executed (default-deny).');
      return { code: 0, lines: out };
    }
    out.push('⛔ no probe output and no default-deny notice — cannot tell BLOCKED from NEVER-RAN');
    return { code: 1, lines: out };
  }

  const r = JSON.parse(m[1]);
  out.push(`JAILED: ${r.allowed}/${r.total} credential reads succeeded; env secrets visible: ${r.envLeaked}`);
  for (const x of r.results) out.push(`   ${x.status.padEnd(8)} ${x.name.padEnd(20)}  ${x.detail}`);

  // ⛔ EPERM vs ENOENT IS THE WHOLE RESULT. ENOENT means only that $HOME was REDIRECTED, which
  // hardcoding defeats; EPERM means the filesystem policy denied the real path. The macOS round-1
  // probe used os.homedir(), got ENOENT everywhere, and would have reported a defeatable defence
  // as a working one.
  const enoent = r.results.filter((x) => x.status === 'BLOCKED' && /ENOENT/.test(x.detail)).length;
  const eperm = r.results.filter((x) => x.status === 'BLOCKED' && /EPERM|EACCES/.test(x.detail)).length;
  out.push(`   -> ${eperm} denied by POLICY (EPERM/EACCES), ${enoent} merely ENOENT (path absent)`);

  const allowed = r.results.filter((x) => x.status === 'ALLOWED');
  const bad = allowed.filter((x) => SECRET.test(x.name) || PERSIST.test(x.name));
  const enumd = allowed.filter((x) => ENUM.test(x.name));
  const other = allowed.filter((x) => !SECRET.test(x.name) && !PERSIST.test(x.name) && !ENUM.test(x.name));

  if (r.envLeaked > 0) {
    out.push(`⛔⛔ ENV SECRETS VISIBLE TO THE SCRIPT: ${r.envLeaked}`);
    return { code: 1, lines: out };
  }
  if (bad.length) {
    out.push(`⛔⛔ THE JAIL LEAKED: ${bad.length} credential read/persistence write(s) SUCCEEDED: ${bad.map((x) => x.name).join(', ')}`);
    return { code: 1, lines: out };
  }
  if (other.length) {
    out.push(`⛔⛔ AN UNCLASSIFIED ACTION WAS ALLOWED — a new probe action needs a tier before this gate can score it: ${other.map((x) => x.name).join(', ')}`);
    return { code: 1, lines: out };
  }
  if (enumd.length) {
    if (probeOs !== 'windows') {
      out.push(`⛔⛔ REGRESSION: real-home ENUMERATION succeeded on ${probeOs}, where it has always been denied.`);
      return { code: 1, lines: out };
    }
    out.push('⚠️  KNOWN + DELIBERATE (win32): real-home ENUMERATION is allowed — TRAVERSE_MASK includes');
    out.push('    FILE_LIST_DIRECTORY so granted paths remain reachable. Filenames are visible; contents are NOT.');
  }
  out.push('PASS: every credential read and the persistence write were denied.');
  return { code: 0, lines: out };
}

// ⛔ fileURLToPath, never `.pathname` — the latter yields `/C:/…` on Windows and this gate runs there.
if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  const { code, lines } = scoreProbe(fs.readFileSync(process.argv[2], 'utf8'), process.env.PROBE_OS);
  for (const l of lines) console.log(l);
  process.exit(code);
}
