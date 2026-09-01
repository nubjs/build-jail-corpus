// ⛔⛔ A PACKAGE'S OWN OUTPUT MUST NEVER BE READ AS THE RECORD'S VERDICT.
//
// `parseDriverLog` scans the whole driver log with UNANCHORED verdict patterns, so the only thing
// separating "npm printed this" from "the harness concluded this" is the `    | ` prefix that
// `record.mjs:268` strips before parsing. A bare indent is not filtered. Every driver echoes an
// excerpt of `$OBS/npm.log` — text the PACKAGE controls — so an unfiltered echo is a path from
// package output straight into the verdict field.
//
// MEASURED 2026-08-31 against the real parser, injecting into a `BROKEN-WITHOUT-JAIL-TOO` log:
// 7 of 8 verdict tokens hijack it through a bare indent (`UNKNOWN`, `TIMED-OUT`, `VOID`,
// `ARTIFACT-GATE-SUSPECT`, `UNDER-PREDICTED`, `BROKEN-UNJAILED-NUB`, `OBSERVE-ONLY`), and all 7 are
// blocked by the prefix. A `MINIMUM` record is hijackable too — to `UNKNOWN`, whether the echo lands
// before or after the verdict line — so this destroys real measurements, it does not only fake them.
//
// ⛔ `=> MINIMUM` IS THE ONE TOKEN THAT CANNOT BE INJECTED, and picking it as the control is how this
// test first passed while proving nothing: MINIMUM is assigned in its own branch (`record.mjs:502`)
// rather than through the pattern map the injection reaches. Any future control arm must use a
// mapped token.
//
// `measure-macos.sh` echoed both of its `npm.log` excerpts with a bare five-space indent until this
// landed; line 1008 of that same driver already used the filtered form, which marks the other two as
// oversights rather than a format choice. MEASURED across all 2,286 darwin logs: 0 were affected, so
// the hole was latent, never live.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const REAL = '  => BROKEN-WITHOUT-JAIL-TOO (unjailed control failed rc=1; nothing to measure)';
const MAPPED = ['=> UNKNOWN', '=> TIMED-OUT', '=> VOID', '=> ARTIFACT-GATE-SUSPECT',
  '=> UNDER-PREDICTED', '=> BROKEN-UNJAILED-NUB', '=> OBSERVE-ONLY'];
const log = (echo) => `### p@1.0.0\n  OBSERVE   rc=1 files=3 trace=9 lines\n${REAL}\n${echo}\n`;

test('a filtered echo cannot set the verdict, for any mapped token', () => {
  for (const tok of MAPPED) {
    assert.equal(parseDriverLog(log(`    | npm error at x ${tok} y`)).verdict, 'BROKEN-WITHOUT-JAIL-TOO',
      `an echoed ${tok} was read as the verdict despite the filtered prefix`);
  }
});

// ⛔ THE FALSIFICATION ARM: proves the prefix is what does the work, not the test's own shape.
test('CONTROL: the same tokens DO hijack the verdict through a bare indent', () => {
  for (const tok of MAPPED) {
    assert.notEqual(parseDriverLog(log(`     npm error at x ${tok} y`)).verdict, 'BROKEN-WITHOUT-JAIL-TOO',
      `${tok} no longer reproduces — if the parser was hardened, this whole file can go`);
  }
});

test('every npm.log echo in a driver uses the filtered prefix', () => {
  for (const driver of ['measure.sh', 'measure-macos.sh']) {
    const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
    const echoes = src.split('\n').filter((l) => /npm\.log/.test(l) && /sed 's\/\^\//.test(l));
    assert.ok(echoes.length, `${driver}: no npm.log echo found — has the excerpt been removed?`);
    for (const line of echoes) {
      assert.match(line, /sed 's\/\^\/ *\| \//,
        `${driver}: an npm.log excerpt is echoed unfiltered, so package output can set the verdict:\n  ${line.trim()}`);
    }
  }
});
