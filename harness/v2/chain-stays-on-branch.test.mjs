// A chaining runner must dispatch its successor against the branch it is RUNNING on, not against
// whatever GitHub considers the default branch.
//
// `gh workflow run <file>` with no `--ref` resolves to the repository's default branch. Both corpus
// runners chained that way, so a drain started on `probe/corpus-v2-lane` produced exactly one real
// slice and then walked onto `main` — a lane deliberately never merged, still carrying the epoch-3
// harness and no `records-v2/` at all.
//
// MEASURED 2026-08-28, four runs, no exceptions: 33187340541 and 33197089244 (dispatched by hand
// WITH --ref) reported `instrument: epoch 15` and `epoch 16` and measured their slices; their
// chained successors 33196045838 and 33201592660 reported `instrument: epoch 3 b21a24cef3e3ab8c`,
// claimed 60 rows off main's queue and died at the falsification gate. The alternating pass/fail
// was read for two slices as an intermittent gate flake. It was not: the gate correctly refused a
// harness thirteen epochs behind the binary it was handed, and that refusal is the only reason no
// epoch-3 measurement ever reached a corpus.
//
// The class-level assertion below is the point. Guarding only the v2 step would leave the next
// chain site free to repeat this, which is how BOTH runners came to carry it.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const WORKFLOWS = path.join(import.meta.dirname, '..', '..', '.github', 'workflows');

/// Every `gh workflow run` invocation in the workflow tree, as a single joined command string with
/// its file and line. Comment lines are excluded — the two `--ref` examples in the Windows probes'
/// headers are documentation, not dispatches — and backslash continuations are folded in, because
/// the flag under test sits on a different physical line from the command.
function dispatchSites() {
  const out = [];
  for (const name of fs.readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml'))) {
    const lines = fs.readFileSync(path.join(WORKFLOWS, name), 'utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith('#') || !lines[i].includes('gh workflow run')) continue;
      let cmd = lines[i];
      for (let j = i; lines[j]?.trimEnd().endsWith('\\') && j + 1 < lines.length; j++) cmd += `\n${lines[j + 1]}`;
      out.push({ file: name, line: i + 1, cmd });
    }
  }
  return out;
}

test('the workflow tree still contains chain dispatches to check', () => {
  // A known-answer control. Without it every assertion below passes vacuously the moment the
  // scanner breaks — and a scanner that silently matches nothing is precisely how a guard becomes
  // decoration.
  const sites = dispatchSites();
  assert.ok(sites.length >= 2, `expected at least 2 gh-workflow-run sites, found ${sites.length}`);
  const files = new Set(sites.map((s) => s.file));
  assert.ok(files.has('corpus-v2-runner.yml'), 'the v2 runner no longer dispatches anything');
  assert.ok(files.has('corpus-queue-runner.yml'), 'the v1 runner no longer dispatches anything');
});

test('every workflow dispatch names the ref it wants', () => {
  for (const { file, line, cmd } of dispatchSites()) {
    assert.ok(
      /--ref\s/.test(cmd),
      `${file}:${line}: a gh workflow run with no --ref dispatches the DEFAULT branch, which takes a `
        + 'chain off its own lane after one hop. Pass --ref "$GITHUB_REF_NAME".',
    );
  }
});

test('a chain dispatch follows its own branch rather than a hardcoded one', () => {
  for (const { file, line, cmd } of dispatchSites()) {
    if (!/-f\s+chain=true/.test(cmd)) continue;
    assert.match(
      cmd,
      /--ref\s+"\$GITHUB_REF_NAME"/,
      `${file}:${line}: a chaining dispatch must ride $GITHUB_REF_NAME so the drain stays on the `
        + 'branch it was started on — a literal branch name pins the chain to one lane forever.',
    );
  }
});
