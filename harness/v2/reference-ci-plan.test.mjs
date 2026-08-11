import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { loadNodeMatrix } from './node-matrix.mjs';
import { planReferenceCells } from './reference-ci-plan.mjs';

test('the full CI plan crosses all supported Node versions with every corpus OS', () => {
  const { matrix } = loadNodeMatrix();
  const plan = planReferenceCells(matrix, { os: 'all', node: 'all' });
  assert.equal(plan.include.length, 27);
  assert.deepEqual(new Set(plan.include.map((cell) => cell.os)), new Set(['linux', 'macos', 'windows']));
  assert.deepEqual(new Set(plan.include.map((cell) => cell.node)),
    new Set(matrix.versions.map((entry) => entry.version)));
  assert.ok(plan.include.every((cell) => !cell.runner.endsWith('-latest') && cell.shard === 0 && cell.shards === 1));
});

test('a selected CI cell must name a checked-in runtime and OS', () => {
  const { matrix } = loadNodeMatrix();
  assert.deepEqual(planReferenceCells(matrix, { os: 'linux', node: '26.7.0' }), {
    include: [{ os: 'linux', runner: 'ubuntu-24.04', node: '26.7.0', npm: '11.19.0', shard: 0, shards: 1 }],
  });
  assert.throws(() => planReferenceCells(matrix, { os: 'solaris', node: '26.7.0' }), /unknown reference OS/);
  assert.throws(() => planReferenceCells(matrix, { os: 'linux', node: '26.7.1' }), /unknown reference Node/);
});

test('a profile cannot silently omit one of the requested operating systems', () => {
  const { matrix } = loadNodeMatrix();
  const profile = { id: 'posix-v1', supportedPlatforms: ['linux', 'darwin'] };
  assert.equal(planReferenceCells(matrix, { os: 'macos', node: '26.7.0', profile }).include.length, 1);
  assert.throws(() => planReferenceCells(matrix, { os: 'all', node: '26.7.0', profile }),
    /profile posix-v1 does not support windows/);
});

test('eight shards keep a complete all-platform matrix under the GitHub job limit', () => {
  const { matrix } = loadNodeMatrix();
  const plan = planReferenceCells(matrix, { os: 'all', node: 'all', shards: 8 });
  assert.equal(plan.include.length, 216);
  assert.equal(new Set(plan.include.map((cell) => `${cell.os}/${cell.node}/${cell.shard}`)).size, 216);
});

test('sixteen shards are available for a selected cell but cannot overflow the full matrix', () => {
  const { matrix } = loadNodeMatrix();
  const plan = planReferenceCells(matrix, { os: 'windows', node: '22.23.2', shards: 16 });
  assert.equal(plan.include.length, 16);
  assert.equal(new Set(plan.include.map((cell) => cell.shard)).size, 16);
  assert.throws(() => planReferenceCells(matrix, { os: 'all', node: 'all', shards: 16 }),
    /exceeding the GitHub matrix limit of 256/);
});

test('the workflow separates the fixed harness runtime from the exact package runtime', () => {
  const { matrix } = loadNodeMatrix();
  const workflow = fs.readFileSync(new URL('../../.github/workflows/reference-accounting.yml', import.meta.url), 'utf8');
  assert.match(workflow, new RegExp(`node-version: '${matrix.harnessNode.replaceAll('.', '\\.')}'`));
  assert.match(workflow, /HARNESS_NODE=.*node/);
  assert.match(workflow, /NODE_EXECUTABLE=\$TARGET_NODE/);
  assert.match(workflow, /"\$HARNESS_NODE" harness\/v2\/run-reference-batch\.mjs/);
  assert.match(workflow, /--node "\$TARGET_NODE"/);
  assert.match(workflow, /--npm npm/);
  assert.match(workflow, /reference-profile-host\.mjs --profile "\$REFERENCE_PROFILE_FILE"/);
  assert.match(workflow, /child-stdio-linux-v1\) PROFILE_FILE=harness\/v2\/reference-profile-child-stdio-linux\.json/);
  assert.match(workflow, /gnu-make-darwin-v1\) PROFILE_FILE=harness\/v2\/reference-profile-gnu-make-darwin\.json/);
  assert.match(workflow, /lifecycle-debug-darwin-v1\) PROFILE_FILE=harness\/v2\/reference-profile-lifecycle-debug-darwin\.json/);
  assert.match(workflow, /gnu-make-automake-darwin-v1\) PROFILE_FILE=harness\/v2\/reference-profile-gnu-make-automake-darwin\.json/);
  assert.match(workflow, /gnu-make-automake-libtool-darwin-v1\) PROFILE_FILE=harness\/v2\/reference-profile-gnu-make-automake-libtool-darwin\.json/);
  assert.match(workflow, /redis-build-darwin-v1\) PROFILE_FILE=harness\/v2\/reference-profile-redis-build-darwin\.json/);
  assert.match(workflow, /redis-build-darwin-v2\) PROFILE_FILE=harness\/v2\/reference-profile-redis-build-darwin-v2\.json/);
  assert.match(workflow, /redis-build-linux-v1\) PROFILE_FILE=harness\/v2\/reference-profile-redis-build-linux\.json/);
  assert.match(workflow, /--profile "\$REFERENCE_PROFILE_FILE"/);
  assert.match(workflow, /--profile "\$\{\{ needs\.plan\.outputs\.profile_file \}\}"/);
  assert.match(workflow, /actions\/download-artifact@v8/);
  assert.match(workflow,
    /name: reference-evidence-[\s\S]*?include-hidden-files: true[\s\S]*?if-no-files-found: error/);
  assert.match(workflow, /reference-report\.mjs/);
  assert.match(workflow, /needs: \[plan, build, test\]/);
  assert.equal([...workflow.matchAll(/harness\/run-tests\.mjs/g)].length, 1);
  assert.match(workflow, /Run the complete harness test suite once per OS/);
  assert.match(workflow, /Nub subject cache was not populated by the build job/);
  assert.match(workflow, /default: main/);
  assert.match(workflow, /cargo build -p nub-cli --profile fast/);
  assert.doesNotMatch(workflow, /cargo build[^\n]*build-jail-catalog-override/);
  assert.match(workflow, /key: nub-reference-subject-v1-/);
  assert.doesNotMatch(workflow, /key: nub-subject-v2-/);
  assert.doesNotMatch(workflow, /key: nub-bin-v1-/);
  assert.match(workflow, /path: \$\{\{ env\.NUB_SUBJECT_CACHE_PATH \}\}/);
  assert.doesNotMatch(workflow, /NUB_BIN_CACHE_PATH/);
  assert.match(workflow,
    /cp vendor\/busybox-w32\/busybox64\.exe \/tmp\/nub\/target\/release\/busybox\.exe/);
  assert.match(workflow, /Windows Nub subject is missing its bundled POSIX shell/);
  assert.match(workflow, /--nub-git-sha/);
  assert.match(workflow, /ARGS\+=\(--strict --complete\)/);
});
