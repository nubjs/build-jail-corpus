// ⛔⛔ A COMMENT AFTER A `\` CONTINUATION SILENTLY EATS THE REST OF THE COMMAND, AND `bash -n` SAYS
// THE FILE IS FINE.
//
// Bash folds a backslash continuation BEFORE it honours `#`, so
//
//     cmd --flag \
//     # explanation
//       more-args
//
// joins line 1 and line 2 into `cmd --flag   # explanation`, a command with its tail commented out,
// and `more-args` then runs as its OWN command. It is a RUNTIME defect, not a syntax error, so
// `bash -n` reports the file clean and every existing gate passes.
//
// THIS HAS NOW BITTEN TWICE, and the second time was found only by going looking for the class:
//
//   epoch 18 — a comment between `--ref` and `-f os=` in the runner workflow broke the lane-handoff
//              dispatch. Caught then by EXECUTING the extracted command against a gh stub.
//   epoch 39 — `measure-macos.sh:488` put one between `sudo ... env "PATH=$ARM_PATH" ...` and its
//              `npm install`. The join produced a sudo with NO command, and npm then ran as ROOT on
//              the DRIVER's PATH instead of as $RUNUSER on the era $ARM_PATH -- the arm-toolchain
//              asymmetry that epochs 4, 13, 15 and 19 exist to close. It reported `rc=0` throughout,
//              because `$?` is npm's and npm succeeded, and the `chown -R "$RUNUSER"` on the next
//              line hid the ownership half. It had been live and unnoticed, in the driver about to
//              measure 1652 macOS rows.
//
// So this guards the CLASS across every shell driver and the workflow, rather than the two instances
// -- epoch 22's lesson, where fixing four unquoted paths and leaving four more cost a full CI round
// trip. A scanner is the right shape here precisely because the defect is invisible to execution
// unless you already suspect the exact line.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const here = import.meta.dirname;
const FILES = [
  'harness/v2/measure.sh',
  'harness/v2/measure-macos.sh',
  'harness/v2/publish-record-v2.sh',
  'harness/v2/security-screen.sh',
  '.github/workflows/corpus-v2-runner.yml',
];

/// Every line that ends in a continuation and is followed by a comment line.
function offenders(text) {
  const lines = text.split('\n');
  const out = [];
  for (let i = 0; i < lines.length - 1; i++) {
    if (/\\$/.test(lines[i]) && /^\s*#/.test(lines[i + 1])) out.push({ line: i + 1, text: lines[i].trim() });
  }
  return out;
}

test('the scanner fires on a planted case', () => {
  // ⛔ THE POSITIVE CONTROL, AND IT IS NOT OPTIONAL. A scanner that matches nothing passes every
  // file trivially, which is exactly how a "no offenders" result reads as a clean bill of health
  // when the instrument is broken. Assert it can FIND one before believing it found none.
  const found = offenders('echo a \\\n# swallowed\n  b\n');
  assert.equal(found.length, 1, 'the scanner cannot detect the defect it exists to detect');
  assert.equal(found[0].line, 1);
  // And that it does not fire on the CORRECT form, or every clean file would look broken.
  assert.equal(offenders('# explanation\necho a \\\n  b\n').length, 0,
    'the scanner flags a comment placed correctly ABOVE the command');
});

for (const rel of FILES) {
  test(`${rel} has no comment interrupting a line continuation`, () => {
    const file = path.join(here, '..', '..', rel);
    const text = fs.readFileSync(file, 'utf8');
    const found = offenders(text);
    assert.deepEqual(found, [],
      `${rel} joins a continuation onto a comment, so the rest of that command is commented out and `
      + `the following line runs on its own — invisible to bash -n:\n`
      + found.map((o) => `  ${rel}:${o.line}  ${o.text}`).join('\n'));
  });
}
