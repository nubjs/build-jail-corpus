// Golden tests for the shared classifier. MAPPING.md rule 5 says the mapping is a pure function and
// is TESTED as one — same event stream in, same grant out, on every platform and every run.
//
//   node harness/v2/classify.test.mjs
//
// Each case is a hand-written EVENT stream with a known answer, chosen so that a plausible wrong
// implementation fails it. These exist because there were briefly TWO classify.mjs files in this
// repo, each described as the shared one; a merge that keeps the better file but drops its tests is
// how that happens again.
//
// ⛔ EVERY CASE MUST CARRY A LIFECYCLE SHELL EXEC. Attribution runs before scope assignment, so an
// event whose pid is not in a lifecycle subtree is dropped and the case would assert nothing at all
// while still "passing". The `sh` exec at pid 20 is what makes the file events count; pid 10 is the
// launching root and is excluded by --root-pid.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLASSIFY = path.join(HERE, 'classify.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'classify-test-'));
const PROJ = '/proj', HOME = '/home/u';

const run = (name, events, platform = 'linux') => {
  const f = path.join(tmp, `${name}.ndjson`);
  fs.writeFileSync(f, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
  const out = path.join(tmp, `${name}.json`);
  execFileSync(process.execPath, [CLASSIFY, f, '--project', PROJ, '--home', HOME,
    '--platform', platform, '--root-pid', '10', '--json', out], { stdio: 'pipe' });
  return JSON.parse(fs.readFileSync(out, 'utf8'));
};

// The launching root (pid 10, excluded) and the lifecycle shell beneath it (pid 20, attributed).
const TREE = [
  { op: 'exec', path: '/bin/sh', result: 'ok', pid: 10, ppid: 1 },
  { op: 'exec', path: '/bin/sh', result: 'ok', pid: 20, ppid: 10 },
];
const ev = (op, p, pid = 20) => ({ op, path: p, result: 'ok', pid, ppid: 10 });

let failed = 0;
const check = (label, ok, detail) => {
  if (!ok) failed++;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}${ok || detail === undefined ? '' : `  (got ${JSON.stringify(detail)})`}`);
};

console.log('\n=== classify.mjs golden cases ===');

// Rule 2. `deps` is nested INSIDE `project`, so a naive first-match-wins over an unsorted root list
// assigns this to `project`. Longest-first ordering is the only thing that gets it right.
{
  const r = run('nested-deps', [...TREE,
    ev('write', `${PROJ}/node_modules/pkg/bin/tool`),
    ev('write', `${PROJ}/dist/out.js`),
  ]);
  check('nested deps root wins over the project root that contains it', r.writes.deps === 1, r.writes);
  check('a project write outside node_modules stays project', r.writes.project === 1, r.writes);
  check('grant names both scopes', r.grant.write?.deps === true && r.grant.write?.project === true, r.grant);
}

// Rule 1. Normalization must happen BEFORE the prefix test, or a path with `.`/`..` in it fails to
// match a root it is plainly inside and falls into `outside`.
{
  const r = run('normalize', [...TREE, ev('read', `${PROJ}/./sub/../read.txt`)]);
  check('`.` and `..` collapse before the prefix test', r.reads.project === 1, r.reads);
  check('a normalized path is not mistaken for outside', r.reads.outside === undefined, r.reads);
}

// Rule 3. The single most dangerous rounding available. An unmapped write is REPORTED; there must be
// no branch anywhere that promotes it to a whole-disk grant.
//
// The path is macOS's TMPDIR shape on purpose. It is the real unmapped case a worklist run produces
// — TMPDIR lives outside both the project and $HOME on macOS — rather than a contrived one. Note it
// is NOT `/opt/...`: that is a SYSTEM dir and lands in `systemfs`, a distinction pinned just below.
{
  const p = '/private/var/folders/zz/T/pkg-scratch';
  const r = run('unmapped', [...TREE, ev('write', p)]);
  check('an unmapped write is reported', r.outsideWrites.includes(p), r.outsideWrites);
  check('an unmapped write does NOT become a disk grant', !JSON.stringify(r.grant).includes('disk'), r.grant);
  check('an unmapped write does not silently widen any scope', r.grant.write === undefined, r.grant);
}

// A system-dir write is a DIFFERENT finding from an unmapped one: an unprivileged user would simply
// be refused it, so it is bucketed apart rather than lumped into `outside`.
{
  const r = run('systemfs', [...TREE, ev('write', '/opt/weird/thing')]);
  check('a system-dir write is bucketed as systemfs, not outside', r.systemWrites.includes('/opt/weird/thing'), { systemWrites: r.systemWrites, outsideWrites: r.outsideWrites });
  check('a system-dir write produces no grant either', r.grant.write === undefined, r.grant);
}

// Rule 3 again, other namespace: /proc is a read-floor question, never a write need.
{
  const r = run('kernelfs', [...TREE, ev('read', '/proc/self/stat')]);
  check('a /proc read is bucketed as kernelfs, not outside', r.reads.kernelfs === 1, r.reads);
  check('a /proc read produces no grant', r.grant.write === undefined && !r.grant.network, r.grant);
}

// Rule 1, the case-folding half. macOS and Windows fold; Linux does not. The same event stream must
// classify differently on darwin than on linux, which is what proves folding is actually applied.
{
  const evs = [...TREE, ev('write', '/PROJ_UPPER/x')];
  const linux = run('fold-linux', evs, 'linux');
  check('linux does NOT fold, so a case-mismatched root is outside', linux.writes.outside === 1, linux.writes);
  const darwin = run('fold-darwin', [
    { op: 'exec', path: '/bin/sh', result: 'ok', pid: 10, ppid: 1 },
    { op: 'exec', path: '/bin/sh', result: 'ok', pid: 20, ppid: 10 },
    ev('write', '/PROJ/x'),
  ], 'darwin');
  check('darwin folds, so /PROJ matches the /proj root', darwin.writes.project === 1, darwin.writes);
}

// Attribution. The launching root's own writes are the package manager's, not the script's, and
// counting them is a 100% over-prediction on every package. This is the case that would have caught
// the macOS worklist scoring 0/6.
{
  const r = run('attribution', [...TREE,
    ev('write', `${HOME}/.npm/_cacache/blob`, 10),   // the launcher — npm's own cache
    ev('write', `${PROJ}/dist/out.js`, 20),          // the lifecycle script
  ]);
  check('the launching root\'s writes are NOT attributed to the package', r.writes.userHome === undefined, r.writes);
  check('the lifecycle shell\'s writes ARE attributed', r.writes.project === 1, r.writes);
  check('the whole-tree count still records what was dropped', r.allTreeWrites === 2, r.allTreeWrites);
}

// A stream with no shell at all must report UNKNOWN rather than an empty grant that reads as
// "this package needs nothing".
{
  const r = run('no-shell', [
    { op: 'exec', path: '/usr/bin/node', result: 'ok', pid: 10, ppid: 1 },
    ev('write', `${PROJ}/dist/out.js`, 10),
  ]);
  check('no lifecycle shell resolves to zero pids rather than a confident empty grant',
    r.lifecyclePids === 0 && r.grant.write === undefined, { lifecyclePids: r.lifecyclePids, grant: r.grant });
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failed === 0 ? '\n  ALL GOLDEN CASES PASSED\n' : `\n  ${failed} GOLDEN CASE(S) FAILED\n`);
process.exit(failed === 0 ? 0 : 1);
