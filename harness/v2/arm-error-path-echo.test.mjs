// ⛔⛔ A `SyntaxError` WITH NO MODULE PATH IS UNCLASSIFIABLE, AND THE DRIVERS WERE THROWING THE PATH AWAY.
//
// Node prints the offending module on the line ABOVE the error:
//
//     /home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec.../node_modules/psl/dist/psl.cjs:1
//     SyntaxError: Unexpected token ...
//
// The failing-arm echo in both POSIX drivers filters the arm log by signature. The ERROR line always
// matched — `SyntaxError:` contains the substring `Error:` — while the PATH line matched no
// alternative at all, so `driver.out` recorded a bare `[synth/i] SyntaxError: Unexpected token ...`
// with its subject amputated.
//
// WHY THAT IS A CORRECTNESS BUG AND NOT A LEGIBILITY ONE: the path is the only thing separating two
// failures whose text is byte-identical and whose meanings are opposite —
//   * a DEPENDENCY the era Node is too old to parse — a real finding about the package, and the whole
//     era-mismatch class the corpus exists to measure; versus
//   * the HARNESS running its OWN `arm-cap.mjs` under an era Node after a PATH rewrite
//     (`measure.sh:104`), which is our bug and must never enter the corpus as a package verdict.
// `detectEraDepMismatch` in `record.mjs` classifies on exactly that path. With it stripped, the
// record cannot be classified at all, and classifying on the string alone would merge the two.
//
// MEASURED 2026-08-30 across all 6,880 committed `driver.out`: exactly 40 carry a path line, and ALL
// FORTY ARE `linux-x64`. Darwin has zero — not because darwin is clean, but because this echo
// amputated it; 18 darwin BROKEN-WITHOUT-JAIL-TOO records carry the identical stripped signature.
//
// ⛔ THE PATTERN IS EXTRACTED FROM THE DRIVERS, NOT PARAPHRASED HERE. A copy would drift from the
// thing it claims to guard and the drift would be invisible — the same reason `claim-cas.test.mjs`
// lifts its shell out of the workflow file rather than restating it.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DRIVERS = ['measure.sh', 'measure-macos.sh'];

/// The alternation the driver actually greps its failing arm logs with.
const armFilter = (driver) => {
  const src = fs.readFileSync(path.join(HERE, driver), 'utf8');
  const m = src.match(/grep -aE '(npm ERR![^']*)'/);
  assert.ok(m, `${driver}: the failing-arm echo's grep is gone or reshaped`);
  return m[1];
};

/// Run a pattern over a fixture through the REAL grep, exactly as the driver does.
const filter = (pattern, log) => {
  const res = execFileSync('grep', ['-aE', pattern], { input: log, encoding: 'utf8' })
    .split('\n').filter(Boolean);
  return res;
};

/// The epoch-41 alternation, verbatim — the control arm. Kept as a literal because its whole job is
/// to be the version that FAILS, so it must not track the file.
const BEFORE = 'npm ERR!|gyp ERR!|command not found|No such file or directory|Error:|EACCES|EPERM|ENOTFOUND|ETIMEDOUT';

/// Both real shapes, taken from committed logs: a CJS store path (linux-x64/jpeg-recompress-bin@0.2.2)
/// and the `file://` URL an ESM loader prints (linux-x64/spectron@11.1.0).
const CJS = '/home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec0a830a560da/node_modules/psl/dist/psl.cjs:1';
const ESM = 'file:///home/runner/v2-ywsPms/jail-off-control/node_modules/.store/puppeteer@25.9.0/node_modules/puppeteer/install.mjs:39';

const LOG = [
  'npm WARN deprecated something@1.0.0',
  CJS,
  'SyntaxError: Unexpected token ...',
  ESM,
  '  const {downloadBrowsers} = await importInstaller();',
  'SyntaxError: Unexpected reserved word',
  '    at require (/home/runner/.cache/nub/pm/store/x@1.0.0-abc/node_modules/x/index.mjs:7:3)',
  'gyp ERR! stack Error: not found',
].join('\n');

for (const driver of DRIVERS) {
  test(`${driver}: the failing-arm echo keeps Node's module path, not just the error line`, () => {
    const kept = filter(armFilter(driver), LOG);

    // ⛔ THE CONTROL FIRST. If the epoch-41 alternation ALSO keeps these lines then the fixture does
    // not exercise the defect and every assertion below is vacuous — so fail, and say so.
    const control = filter(BEFORE, LOG);
    assert.ok(!control.includes(CJS) && !control.includes(ESM),
      'the pre-fix alternation already kept the path lines, so this fixture proves nothing — '
      + 'it must use a path line that the old filter genuinely dropped');
    assert.ok(control.some((l) => l.includes('SyntaxError')),
      'the control did not even keep the error line, so the fixture is wrong in a second way');

    assert.ok(kept.includes(CJS), `${driver} dropped the CJS store path above the SyntaxError`);
    assert.ok(kept.includes(ESM), `${driver} dropped the ESM loader URL above the SyntaxError`);
  });

  test(`${driver}: a stack frame is still not a load path, so the echo stays bounded`, () => {
    // The echo is capped at 12 lines and a record is evidence, not an archive. A frame has text
    // before the path and a column after it; matching those would let one throw drown the four
    // signatures the filter exists to surface.
    const kept = filter(armFilter(driver), LOG);
    assert.ok(!kept.some((l) => l.trimStart().startsWith('at require (')),
      `${driver} now matches stack frames — the anchors on the path alternative have come loose`);
  });
}

test('both POSIX drivers filter arm logs identically', () => {
  // They diverged once already: linux kept its paths through a different, unfiltered echo while
  // darwin did not, and that accident is why the class looked linux-only for a day.
  const [a, b] = DRIVERS.map(armFilter);
  assert.equal(a, b, 'measure.sh and measure-macos.sh no longer agree on the failing-arm filter');
});
