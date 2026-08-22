#!/usr/bin/env node
// Emits ONE NDJSON ledger row for the F9 nub-unjailed control, on stdout.
//
// This exists because the workflow built the row with printf and it died on real data:
// "SyntaxError: Expected ',' or '}' after property value in JSON at position 101" — nub's error
// text carries backslashes and quotes that printf cannot escape. Building the row in node also
// lets the cause come from firstCause(), the SAME extractor observe-only.mjs uses, instead of a
// second grep that drifts from it. A hand-rolled grep here captured "npm ERR! Linux 6.1" — the OS
// banner — on the very control that was meant to prove the capture worked.
//
// Usage: node f9-ledger-line.mjs <spec> <rc> <logfile>
import fs from 'node:fs';
import { firstCause } from './observe-only.mjs';

// The control prints its own verdict banner ("npm installs this package but nub cannot ...") and
// indented "=> " detail lines. Both restate the exit code rather than naming a cause, so they are
// dropped before anything reads the log.
const CONTROL_NOISE = /^\s*(jail-off control:|=> )/;

const [spec, rcRaw, logPath] = process.argv.slice(2);
if (!spec || rcRaw === undefined || !logPath) {
  console.error('usage: f9-ledger-line.mjs <spec> <rc> <logfile>');
  process.exit(2);
}
const rc = Number(rcRaw);
const clean = fs.readFileSync(logPath, 'utf8').split('\n').filter((l) => !CONTROL_NOISE.test(l));

process.stdout.write(JSON.stringify({
  spec,
  unjailedNubRc: rc,
  stillNubDefect: rc !== 0,
  firstError: firstCause(clean.join('\n')),
  tail: clean.filter((l) => l.trim()).slice(-30).join('\n'),
}) + '\n');
