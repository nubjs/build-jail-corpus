#!/usr/bin/env node
// Emits ONE NDJSON ledger row for the F9 nub-unjailed control, on stdout.
//
// ⛔ FOUR ATTEMPTS AT THIS FAILED BECAUSE THEY ALL READ THE WRONG FILE. The workflow captures the
// control's own stdout as out.log, and unjailed-nub.mjs writes nub's ACTUAL output somewhere else:
// writeLogs() puts it in the run directory as i.log / a.log / n.log / fetch.log /
// security-resolve.log. So out.log holds nothing but the control's verdict banner and its `=> ` lines
// — and every attempt to grep a cause out of it produced, in order: an empty capture, a printf JSON
// SyntaxError, `npm ERR! Linux 6.1` (the OS banner), and finally a null firstError on all 31 rows
// with an EMPTY tail, which is what finally made the missing file obvious. Read the run directory.
//
// The second reason it failed: firstCause() in observe-only.mjs filters for NPM's vocabulary
// (`npm error`, `npm ERR!`), and nub is not npm. Its PM output is rebranded aube — ERR_NUB_* /
// WARN_NUB_* — so an npm-shaped filter matches none of it.
//
// Usage: node f9-ledger-line.mjs <spec> <rc> <controlStdout> <runDir>
import fs from 'node:fs';
import path from 'node:path';
import { errorTail } from './observe-only.mjs';

// The control's own narration. It restates the exit code rather than naming a cause, and capturing
// it recorded the verdict on all 11 defects and nub's error on none.
const CONTROL_NOISE = /^\s*(jail-off control:|=> )/;

/** nub's failure vocabulary, which is aube's rebranded — plus npm's, because the control's npm arm
 *  writes into the same directory and its output is a legitimate cause for a fetch-side failure. */
const ERRISH = /ERR_NUB_|ERR_AUBE_|WARN_NUB_|npm error|npm ERR!|ERR!|error:|Error:|failed|refus|not found|is not recognized|panicked|No such file|Permission denied/i;

// Progress chatter and framing that names no cause. Same principle as the sweep's extractor: a line
// that carries no package-specific content is not an attribution.
const UNINFORMATIVE = /^\s*(npm (error|ERR!) (code \S+$|path |Linux|Darwin|Windows|argv|node |npm |cwd |A complete log)|Progress|Resolving|Downloading|Linking|\d+ packages? )/;

const [spec, rcRaw, controlStdout, runDir] = process.argv.slice(2);
if (!spec || rcRaw === undefined) {
  console.error('usage: f9-ledger-line.mjs <spec> <rc> <controlStdout> [runDir]');
  process.exit(2);
}
const rc = Number(rcRaw);

const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const control = read(controlStdout).split('\n').filter((l) => !CONTROL_NOISE.test(l)).join('\n');

// Every log the control may have written, in the order a reader would consult them: the install that
// failed first, then the approve step, then the fetch.
const NUB_LOGS = ['i.log', 'a.log', 'n.log', 'security-resolve.log', 'fetch.log'];
const logs = {};
for (const name of NUB_LOGS) {
  const body = runDir ? read(path.join(runDir, name)) : '';
  if (body.trim()) logs[name] = errorTail(body, { lines: 40, chars: 6000 });
}

const causeFrom = (text) => {
  const lines = String(text ?? '').split('\n').map((l) => l.trimEnd()).filter((l) => l.trim());
  const errish = lines.filter((l) => ERRISH.test(l));
  return errish.find((l) => !UNINFORMATIVE.test(l)) ?? errish[0] ?? null;
};

// Prefer a cause from nub's own logs; fall back to the control's stdout so a row is never blank when
// SOMETHING was said.
const firstError = NUB_LOGS.map((n) => logs[n]).filter(Boolean).map(causeFrom).find(Boolean)
                ?? causeFrom(control);

// ⛔ A REFUSAL IS A DECISION, NOT A DEFECT — and until the cause was captured, all eleven looked
// identical. With nub's own logs finally readable, 5 of the 11 "nub defects" turned out to be nub's
// security screen working exactly as designed: three ERR_NUB_MALICIOUS_PACKAGE and two
// ERR_NUB_TRUST_DOWNGRADE. That also explains the netlify-cli version boundary that read like a
// bisect target — 22.4.0 and 23.9.5 trip a trust downgrade, 26.2.0 and 27.0.1 do not. Filing a
// deliberate refusal as a bug to fix would be the worst possible outcome of this control.
const REFUSAL = /ERR_NUB_(MALICIOUS_PACKAGE|TRUST_DOWNGRADE|BLOCKED|POLICY)/;
const outcome = rc === 0 ? 'NUB-INSTALLS'
  : (firstError && REFUSAL.test(firstError) ? 'NUB-REFUSED' : 'NUB-DEFECT');

process.stdout.write(JSON.stringify({
  spec,
  unjailedNubRc: rc,
  outcome,
  // Kept for the earlier ledgers' shape, but it now means "nub failed for a reason that is not a
  // deliberate refusal" rather than the bare "rc !== 0" it used to.
  stillNubDefect: outcome === 'NUB-DEFECT',
  firstError: firstError ? firstError.slice(0, 300) : null,
  logs,                                   // per-file tails: the row is re-auditable without a re-run
  controlTail: errorTail(control, { lines: 15, chars: 2000 }),
}) + '\n');
