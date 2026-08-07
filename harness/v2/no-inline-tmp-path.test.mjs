// No workflow may bake a POSIX temp path into a `node -e` program body.
//
// ⛔ THE DEFECT THIS GUARDS, AND WHY GREPPING FOR `/tmp` IS THE WRONG INSTRUMENT. Workflow steps run
// under Git-bash, whose msys2 runtime rewrites POSIX-looking ARGUMENTS and ENV-VAR VALUES into
// Windows paths when spawning a native child. MEASURED in run 31145732202: `--nub /tmp/nub/.../nub.exe`
// reached node.exe as `C:/Users/RUNNER~1/AppData/Local/Temp/nub/.../nub.exe`, and
// `NUB_BUILD_JAIL_CATALOG=/tmp/cat-good.json` reached nub.exe as the rewritten path it then printed.
// So nearly every `/tmp` in these files is CORRECT, and a blanket ban would be a false positive ~30
// times over in `corpus-v2-runner.yml` alone.
//
// What msys2 cannot rewrite is a path buried inside a longer string. A `node -e` program body is one
// argument that does not look like a path, so it arrives verbatim and Node resolves `/tmp/x`
// DRIVE-RELATIVE: `ENOENT ... open 'D:\tmp\verdicts.ndjson'`. That single line is what took the
// Windows lane down on the first run it was ever given.
//
// ⛔ AND THE CRASH WAS THE LUCKY OUTCOME. Had `D:\tmp` existed, a bash writer and a `node -e` reader
// of the identical `/tmp/x` spelling would have used two different files, silently.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const WORKFLOWS = path.join(import.meta.dirname, '..', '..', '.github', 'workflows');
const files = fs.readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));

/** The body of a `node -e '...'` / `node -e "..."` invocation, single- or multi-line. */
const NODE_E = /\bnode\s+(?:--[\w-]+(?:=\S+)?\s+)*-e\s+(['"])([\s\S]*?)\1/g;
const POSIX_TMP = /(?:^|[^\w.-])\/tmp\//;

const bodies = (text) => [...text.matchAll(NODE_E)].map((m) => m[2]);

// ⛔ CONTROL FIRST: a scan that matched no `node -e` at all would report every workflow clean, which
// is exactly the vacuous green this repo keeps getting caught by. Prove the extractor works on a
// string whose answer is known before believing any result it produces.
test('CONTROL: the `node -e` extractor finds a body, and flags a known-bad one', () => {
  const bad = `        run: |\n          node -e '\n            fs.writeFileSync("/tmp/verdicts.ndjson", x);\n          '\n`;
  const found = bodies(bad);
  assert.equal(found.length, 1, 'the extractor did not find the `node -e` body in a known sample');
  assert.ok(POSIX_TMP.test(found[0]), 'the extractor found the body but the /tmp pattern missed it');

  // …and the pattern must NOT fire on the spellings msys2 rewrites correctly, or the guard would
  // demand ~30 pointless edits and be turned off.
  const good = 'node harness/collect-verdicts.mjs --runs records-v2 --out /tmp/verdicts.ndjson';
  assert.equal(bodies(good).length, 0, 'a plain argument is not a `node -e` body and must not match');
});

test('⭑ no workflow embeds a /tmp path inside a `node -e` program', () => {
  const offenders = [];
  for (const f of files) {
    const text = fs.readFileSync(path.join(WORKFLOWS, f), 'utf8');
    for (const body of bodies(text)) {
      if (POSIX_TMP.test(body)) offenders.push(`${f}: ${body.trim().split('\n').find((l) => POSIX_TMP.test(l))?.trim()}`);
    }
  }
  assert.deepEqual(offenders, [],
    'these embed a POSIX temp path in a `node -e` body, which msys2 cannot rewrite — Node then '
    + 'resolves it drive-relative on Windows (`D:\\tmp\\...`) and the step dies, or worse, silently '
    + `uses a different file than the bash side does:\n  ${offenders.join('\n  ')}\n`
    + 'Pass the path as an ARGUMENT, or move the program into a real script under `harness/`.');
});

test('CONTROL: the workflow scan is actually reading files that contain `node` invocations', () => {
  // Guards against a wrong WORKFLOWS path making the assertion above pass over an empty set.
  assert.ok(files.length >= 2, `only ${files.length} workflow file(s) found — the path is wrong`);
  const withNode = files.filter((f) => /\bnode\s/.test(fs.readFileSync(path.join(WORKFLOWS, f), 'utf8')));
  assert.ok(withNode.length >= 1, 'no workflow contains a `node` invocation — the scan is not reading them');
});
