// The override probe: that it requires POSITIVE EVIDENCE, that all three drivers ask the same
// question, and that the Linux gate can actually fire.
//
// ⛔ THE DEFECT THIS FILE GUARDS. Every driver decided "was this nub built with
// `build-jail-catalog-override`?" by running `NUB_BUILD_JAIL_CATALOG=<doc> nub --version` and
// reading `rc == 0` — inferring the capability from the ABSENCE of an error. There are THREE binary
// classes and exit code collapses the two that matter. MEASURED 2026-08-06 on eleven real binaries,
// darwin/arm64:
//
//   worktrees/integ/target/fast/nub   feature ON      rc=0  "warning: build-jail catalog OVERRIDDEN from …"
//   worktrees/integ/target/debug/nub  AWARE, off      rc=1  "…not built with the `build-jail-catalog-override` feature…"
//   9x shared-target-*/{fast,debug}   feature ABSENT  rc=0  byte-identical to a run with NO variable set
//
// So the preflight built to refuse a featureless binary admitted every binary that had never heard
// of the question — nine of the eleven on that host, i.e. every nub not built from the feature
// branch. On `measure.sh` that made a FATAL `exit 3` unable to fire in the direction it exists for;
// on the other two it wrote a false `buildJailCatalogOverride: true` into record provenance.
//
// ⛔ THE FALSE-NEGATIVE DIRECTION IS THE EXPENSIVE ONE, AND IT IS THE OPPOSITE OF THIS PROJECT'S
// USUAL BIAS. A stricter probe that wrongly refuses a GOOD binary makes `measure.sh` exit 3 and
// blocks ALL Linux measurement — worse than the defect being fixed. Every case below that asserts a
// refusal is therefore paired with a positive control in the same case: "we detect the feature" must
// not be satisfiable by refusing everything.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  OVERRIDDEN_MARKER,
  REJECTED_MARKER_RE,
  overrideProbeSaysHonoured,
  overrideProbeClass,
} from './override-probe.mjs';

const HERE = import.meta.dirname;
const read = (f) => fs.readFileSync(path.join(HERE, f), 'utf8');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'ovprobe-'));

// ⛔ A SKIP IS NOT A PASS, so it carries its reason into the TAP output. The bash cases replay a
// block from a shell driver; MEASURED on the corpus Windows VM there is no bash at all, so they
// would die `spawnSync bash ENOENT` — a failure that says nothing about the probe. The pure-JS
// cases above them, including the cross-driver drift guard, run everywhere.
const SHELL_SKIP = process.platform === 'win32'
  ? 'no bash on Windows: this case replays a block extracted from a shell driver'
  : false;

// ── The captured truth. Real output, not paraphrase. ───────────────────────────────────────────
// ⛔ THESE ARE TRANSCRIPTS, NOT INVENTIONS. A fixture written from memory tests the fixture: the
// previous stub in `measure-macos-provenance.test.mjs` said `catalog OVERRIDDEN from …`, which no
// nub prints, and it would have kept passing against a driver hunting a string that never occurs.
// Captured 2026-08-06 from the binaries named above.
const CAPTURED = {
  honoured_overridden: {
    status: 0,
    output: 'warning: build-jail catalog OVERRIDDEN from /tmp/nub-probe-cat-aBc123.json'
      + ' (v2: 1 packages, 1 grants, 0 baseline paths, 0 env)'
      + ' — development-only, not a shipped configuration\n'
      + 'v0.7.1\n» node v26.5.0 (resolved from package.json#engines.node)\n',
  },
  honoured_rejected_unreadable: {
    status: 0,
    output: 'warning: build-jail catalog override at /tmp/nub-probe-cat-aBc123.json was REJECTED'
      + ' (cannot read: No such file or directory (os error 2)); using the compiled-in catalog\n'
      + 'v0.7.1\n» node v26.5.0 (resolved from package.json#engines.node)\n',
  },
  honoured_rejected_unparseable: {
    status: 0,
    output: 'warning: build-jail catalog override at /tmp/nub-probe-cat-aBc123.json was REJECTED'
      + ' (not valid JSON: key must be a string at line 1 column 3); using the compiled-in catalog\n'
      + 'v0.7.1\n» node v26.5.0 (resolved from package.json#engines.node)\n',
  },
  disabled: {
    status: 1,
    output: 'Error: NUB_BUILD_JAIL_CATALOG is set, but this binary was not built with the'
      + ' `build-jail-catalog-override` feature, so it cannot honour it.\n'
      + '  Refusing rather than running the compiled-in catalog under an override\'s name.\n'
      + '  Rebuild with `--features nub-cli/build-jail-catalog-override`, or unset the variable.\n',
  },
  // ⛔ THE WHOLE DEFECT IN ONE FIXTURE: rc=0, and not one word about the catalog.
  absent: {
    status: 0,
    output: 'v0.7.2\n» node v26.5.0 (resolved from package.json#engines.node)\n',
  },
};

test('INSTRUMENT: the absent-class transcript is genuinely indistinguishable from an unset run', () => {
  // The premise the whole file rests on. If these ever differ, exit code is not the only signal and
  // the reasoning below needs revisiting rather than the code.
  const unset = 'v0.7.2\n» node v26.5.0 (resolved from package.json#engines.node)\n';
  assert.equal(CAPTURED.absent.output, unset,
    'the class-3 transcript differs from a no-variable run — re-derive why the old probe failed');
  assert.equal(CAPTURED.absent.status, 0);
});

test('the predicate credits ONLY a binary that acted on the variable', () => {
  assert.equal(overrideProbeSaysHonoured(CAPTURED.honoured_overridden.output), true,
    'a binary that loaded the catalog was refused — this is the direction that blocks measurement');
  assert.equal(overrideProbeSaysHonoured(CAPTURED.absent.output), false,
    'silence was read as consent: a binary that ignored the variable was credited with the feature');
  assert.equal(overrideProbeSaysHonoured(CAPTURED.disabled.output), false,
    'a binary that refused the variable was credited with honouring it');
});

test('a REJECTED banner is sufficient evidence, so a schema change cannot block measurement', () => {
  // ⛔ WHY THIS IS DELIBERATE, NOT SLOPPY. `fs::read_to_string` fails before any schema parsing, so
  // FellBack proves the feature is COMPILED IN whatever the catalog grammar has since become.
  // Requiring OVERRIDDEN alone would couple a FATAL gate to the v2 schema, and a grammar change
  // would then block every Linux measurement — strictly worse than the bug this file fixes.
  for (const k of ['honoured_rejected_unreadable', 'honoured_rejected_unparseable']) {
    assert.equal(overrideProbeSaysHonoured(CAPTURED[k].output), true,
      `${k}: a binary that read the variable and fell back was reported as lacking the feature`);
  }
  // The safety net must not become a blanket amnesty: the two refusing classes stay refused even
  // though neither produced a usable catalog either.
  assert.equal(overrideProbeSaysHonoured(CAPTURED.disabled.output), false);
  assert.equal(overrideProbeSaysHonoured(CAPTURED.absent.output), false);
});

test('the three classes are NAMED, because they call for different actions', () => {
  // `disabled` is a rebuild of the same tree with one flag; `absent` means the checkout predates the
  // seam and no flag will produce it. A gate that says only "not built with the feature" sends the
  // second case chasing a flag that cannot help.
  const cls = (k) => overrideProbeClass(CAPTURED[k].output, CAPTURED[k].status);
  assert.equal(cls('honoured_overridden'), 'honoured');
  assert.equal(cls('honoured_rejected_unreadable'), 'honoured');
  assert.equal(cls('disabled'), 'disabled');
  assert.equal(cls('absent'), 'absent');
});

test('CROSS-DRIVER: all three drivers ask for the same two markers', () => {
  // ⛔ THE DRIFT GUARD, and the reason the predicate is a shared module at all. `measure-windows.mjs`
  // imports it; the two shell drivers cannot import JS, so they carry the patterns as `grep`
  // arguments and this case is what keeps the three spellings in agreement. Same shape as
  // `ci-env-scrub.test.mjs`, which guards the mirrored CI key list for the same reason.
  const shell = { 'measure.sh': read('measure.sh'), 'measure-macos.sh': read('measure-macos.sh') };
  for (const [name, src] of Object.entries(shell)) {
    assert.ok(src.includes(`grep -q '${OVERRIDDEN_MARKER}'`),
      `${name} does not grep for the OVERRIDDEN marker exactly as override-probe.mjs spells it`);
    assert.ok(src.includes(`grep -q '${REJECTED_MARKER_RE.source}'`),
      `${name} does not grep for the REJECTED marker exactly as override-probe.mjs spells it`);
  }
  const win = read('measure-windows.mjs');
  assert.match(win, /import \{ overrideProbeSaysHonoured \} from '\.\/override-probe\.mjs'/,
    'measure-windows.mjs no longer imports the shared predicate — it has a private copy to drift');
  assert.match(win, /overrideProbeSaysHonoured\(/,
    'measure-windows.mjs imports the predicate but does not call it');
});

test('CROSS-DRIVER: none of the known silence-inferring spellings has come back', () => {
  // ⛔ A TEXTUAL GUARD, AND ITS LIMIT IS NAMED ON PURPOSE. It catches the spellings this defect has
  // actually worn, not "any possible exit-code inference" — a source pattern cannot decide that.
  // The load-bearing guards are behavioural: the Linux gate cases below replay `measure.sh` against
  // an ignoring stub, and `measure-macos-provenance.test.mjs` does the same for the darwin marker.
  // This case is what covers `measure-windows.mjs`, which no host here can run.
  const silence = [
    // The original shell spelling: run the probe discarding all output, and branch on `if`.
    // ⛔ THE MATCH MUST CROSS NEWLINES — `measure-macos.sh` spells this across a `\` continuation,
    // and a `[^\n]*` version of this pattern silently missed it. Bounded rather than greedy so it
    // cannot span unrelated lines further down the file.
    /if\s+(?:NUB_CACHE_DIR=\S+\s+)?NUB_BUILD_JAIL_CATALOG=[\s\S]{0,160}?--version\s*>\/dev\/null\s*2>&1/,
    // the same inference respelled against a captured status, which is what a partial revert looks
    // like: the probe still writes its output to a file, and then nothing reads it
    /if\s*\[\s*"\$NUB_PROBE_RC"\s*-(?:eq|ne)\s*0\s*\]\s*;?\s*then\s*\n\s*NUB_HAS_OVERRIDE=true/,
    // the JS spelling
    /hasOverride\s*=\s*pr\.status\s*===\s*0/,
  ];
  for (const f of ['measure.sh', 'measure-macos.sh', 'measure-windows.mjs']) {
    const src = read(f);
    for (const re of silence) {
      assert.doesNotMatch(src, re,
        `${f} decides the override feature from an exit code alone: a binary that has never heard `
        + 'of NUB_BUILD_JAIL_CATALOG exits 0 and would be credited with honouring it');
    }
  }
});

// ── The Linux gate, end to end. ────────────────────────────────────────────────────────────────
// The preflight sliced out of the shipped driver and replayed against stub binaries, as
// `measure-macos-provenance.test.mjs` does for the darwin marker. A hand-copied transcription would
// pass forever while the driver rotted beside it.
const SRC = read('measure.sh').split('\n');

/** The probe block plus the fatal gate, lifted from `measure.sh`. Throws on anchor drift. */
const gateBlock = () => {
  const open = SRC.findIndex((l) => /^NUB_HAS_OVERRIDE=false;/.test(l));
  assert.notEqual(open, -1, 'ANCHOR DRIFT: measure.sh no longer initialises NUB_HAS_OVERRIDE');
  const exit = SRC.findIndex((l, i) => i > open && /^\s*exit 3$/.test(l));
  assert.notEqual(exit, -1, 'ANCHOR DRIFT: no `exit 3` follows the override probe');
  let close = exit;
  while (close < SRC.length && SRC[close] !== 'fi') close++;
  assert.notEqual(close, SRC.length, 'ANCHOR DRIFT: the fatal gate is never closed');
  const block = SRC.slice(open, close + 1).join('\n');
  assert.match(block, /NUB_BUILD_JAIL_CATALOG/, 'the extracted block does not exercise the override');
  assert.match(block, /exit 3/, 'the extracted block lost the fatal gate');
  // The emission in the middle needs `node`; it is not what these cases assert, and its absence
  // must not be mistaken for the gate passing.
  return `set -u\n${block}\necho PREFLIGHT-PASSED\n`;
};

/** Replay the preflight with `$NUB` set to `bin`. Exit code captured, never read through a pipe. */
const preflight = (bin) => {
  const r = spawnSync('bash', ['-c', gateBlock()], {
    encoding: 'utf8', env: { ...process.env, NUB: bin },
  });
  return { status: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
};

/** The same three classes, as executable stubs. */
const stubs = (dir) => {
  const mk = (name, body) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, body);
    fs.chmodSync(p, 0o755);
    return p;
  };
  return {
    on: mk('nub-feature', '#!/bin/sh\n'
      + 'echo "warning: build-jail catalog OVERRIDDEN from $NUB_BUILD_JAIL_CATALOG'
      + ' (v2: 1 packages, 1 grants, 0 baseline paths, 0 env)'
      + ' — development-only, not a shipped configuration" >&2\necho v0.0.0-feature\n'),
    // Honours the variable but cannot use THIS document — the schema-drift case, which must PASS.
    rejecting: mk('nub-rejecting', '#!/bin/sh\n'
      + 'echo "warning: build-jail catalog override at $NUB_BUILD_JAIL_CATALOG was REJECTED'
      + ' (not valid JSON: key must be a string at line 1 column 3); using the compiled-in catalog" >&2\n'
      + 'echo v0.0.0-feature\n'),
    off: mk('nub-nofeature', '#!/bin/sh\n'
      + 'if [ -n "$NUB_BUILD_JAIL_CATALOG" ]; then\n'
      + '  echo "Error: NUB_BUILD_JAIL_CATALOG is set, but this binary was not built with the'
      + ' \\`build-jail-catalog-override\\` feature, so it cannot honour it." >&2\n  exit 1\nfi\n'
      + 'echo v0.0.0-nofeature\n'),
    absent: mk('nub-preseam', '#!/bin/sh\necho v0.0.0-preseam\n'),
  };
};

test('the Linux gate ADMITS a feature-enabled binary', { skip: SHELL_SKIP }, () => {
  // ⛔ THE CONTROL THAT HAS TO COME FIRST. Without it, every refusal case below is satisfied by a
  // gate that refuses everything — which would exit 3 on every Linux run and block all measurement.
  const { on, rejecting } = stubs(tmp());
  for (const [label, bin] of [['loaded', on], ['fell back', rejecting]]) {
    const r = preflight(bin);
    assert.equal(r.status, 0, `the gate refused a binary that ${label} the catalog:\n${r.out}`);
    assert.match(r.out, /PREFLIGHT-PASSED/, `the gate did not reach the end for ${label}:\n${r.out}`);
  }
});

test('the Linux gate REFUSES a binary that ignores the catalog, and says which class it is',
  { skip: SHELL_SKIP }, () => {
    // The defect: this stub exits 0 and says nothing, and the old probe passed it.
    const { absent } = stubs(tmp());
    const r = preflight(absent);
    assert.equal(r.status, 3, `a binary that ignored NUB_BUILD_JAIL_CATALOG passed the gate:\n${r.out}`);
    assert.doesNotMatch(r.out, /PREFLIGHT-PASSED/, 'the gate printed a refusal but carried on anyway');
    assert.match(r.out, /IGNORED NUB_BUILD_JAIL_CATALOG/,
      'the refusal does not distinguish an ignoring binary from a refusing one, so it sends the '
      + 'reader after a rebuild flag that cannot help');
  });

test('the Linux gate REFUSES a binary that knows the feature but was built without it',
  { skip: SHELL_SKIP }, () => {
    const { off } = stubs(tmp());
    const r = preflight(off);
    assert.equal(r.status, 3, `a binary that refuses the catalog passed the gate:\n${r.out}`);
    assert.match(r.out, /knows `build-jail-catalog-override` but was not built with it/,
      'the refusal does not name the class it found');
  });
