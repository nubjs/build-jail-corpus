// The era-dep-mismatch detector missed two whole classes, both measured against the corpus on
// 2026-08-31 and both fixed together because the same records need each.
//
//   LAYOUT   `/store/` cannot match `node_modules/.store/` — the `.` sits between the slash and the
//            word — so only the SHARED cache layout was recognised, never the project-local one.
//            7 logs name a `.store` path beside a SyntaxError; 5 name no shared path at all.
//   SPELLING top-level `await` under an era Node raises `Unexpected reserved word`, not
//            `Unexpected token`, which is the single likeliest shape for a MODERN dependency on an
//            OLD runtime — exactly what this detector exists to find. 3 logs carry it.
//
// Net effect over all 6,880 driver logs: storeSyntaxError 61 -> 65, nothing lost. The four are
// `@bazel/cypress@2.3.3`, `@bazel/cypress@3.8.0` (Unexpected token) and `spectron@11.1.0`,
// `spectron@12.0.0` (Unexpected reserved word, both on `puppeteer@25.9.0/install.mjs`).
//
// ⛔ THE CONTROLS ARE THE REASON THIS FILE EXISTS. Widening the layout newly reaches nub's OWN
// provisioned node-gyp under `pm/tools/.../.store/`, and widening the spelling reaches a string the
// harness itself once produced. Both must stay OUT of the dependency bucket, or the count this
// detector reports becomes a number about two different defects and actionable for neither.

import test from 'node:test';
import assert from 'node:assert/strict';
import { detectEraDepMismatch } from './record.mjs';

const log = (...lines) => lines.join('\n');

const SHARED = '/home/runner/.cache/nub/pm/store/psl@1.15.0-2f9ec0a830a560da/node_modules/psl/dist/psl.cjs';
const LOCAL = '/home/runner/v2-uwDIG1/jail-off-control/node_modules/.store/puppeteer@25.9.0/node_modules/puppeteer/install.mjs';
const TOOLS = '/Users/runner/.cache/nub/pm/tools/node-gyp/v3/node_modules/.store/node-gyp@3.8.0/node_modules/node-gyp/bin/node-gyp.js';

test('⭑ the project-local `.store` layout is recognised', () => {
  const out = detectEraDepMismatch(log(`    | ${LOCAL}:39`, '    | SyntaxError: Unexpected token ...'));
  assert.equal(out?.storeSyntaxError, LOCAL);
});

test('⭑ the shared `pm/store` layout still is — the widening loses nothing', () => {
  const out = detectEraDepMismatch(log(`    | ${SHARED}:1`, '    | SyntaxError: Unexpected token ...'));
  assert.equal(out?.storeSyntaxError, SHARED);
});

test('⭑ `Unexpected reserved word` classifies — the top-level-await shape', () => {
  // `spectron@11.1.0` and `@12.0.0`: era Node loading puppeteer@25.9.0's modern install.mjs.
  const out = detectEraDepMismatch(log(`    | ${LOCAL}:39`, '    | SyntaxError: Unexpected reserved word'));
  assert.equal(out?.storeSyntaxError, LOCAL);
});

test("⭑ CONTROL: nub's OWN provisioned node-gyp under pm/tools is NOT a dependency mismatch", () => {
  // `lzo@0.1.1` (darwin) is the observed case. The old `/store/` needle missed this path by
  // accident; `[./]store/` reaches it, so the exclusion is what keeps the widening honest.
  const out = detectEraDepMismatch(log(`    | ${TOOLS}:1`, '    | SyntaxError: Unexpected token ...'));
  assert.equal(out?.storeSyntaxError ?? null, null,
    'harness tooling must never be reported against the subject package');
});

test("⭑ CONTROL: the runner's own npm stays in the toolchain bucket, not the dependency one", () => {
  const npm = '/Users/runner/hostedtoolcache/node/22.23.2/arm64/lib/node_modules/npm/lib/cli.js';
  const out = detectEraDepMismatch(log(`        ${npm}:2`, '        SyntaxError: Unexpected token ...'));
  assert.equal(out?.storeSyntaxError ?? null, null);
  assert.equal(out?.toolchainSyntaxError, npm);
});

test('⭑ CONTROL: a reserved-word error naming no store path classifies as nothing', () => {
  // `measure.sh:104` records that the harness's own `arm-cap.mjs` once produced this exact string
  // under an era Node with a rewritten PATH. 0 corpus logs still do — but the separation rests on
  // the PATH test, not on that fix holding, so it is pinned here rather than assumed.
  const self = '/home/runner/work/build-jail-corpus/harness/v2/arm-cap.mjs';
  const out = detectEraDepMismatch(log(`    | ${self}:12`, '    | SyntaxError: Unexpected reserved word'));
  assert.equal(out?.storeSyntaxError ?? null, null,
    'a harness self-failure must never be reported as the package\'s dependency mismatch');
});
