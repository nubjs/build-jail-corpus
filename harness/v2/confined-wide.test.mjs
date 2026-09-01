// The wide-but-confined probe: its path set, its guard, and its round trip through `record.mjs`.
//
// ⛔ WHAT THIS FILE IS FOR. `linux-ladder.test.mjs` and `macos-ladder.test.mjs` execute the DRIVERS and
// prove the probe fires in the right place and publishes nothing. This file covers the two halves
// those cannot reach: the path set itself — where a single wrong string silently turns the probe into
// the confound it exists to remove — and the recorder, whose job is to fail CLOSED on anything it
// cannot read.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  CONFINED_WIDE_MARKER, CONFINED_WIDE_PATHS, RESULTS,
  confinedWideBaseline, interpretation, marker,
} from './confined-wide.mjs';
import { buildCatalog } from './dep-scaffold.mjs';
import { parseDriverLog } from './record.mjs';

const HERE = import.meta.dirname;
const PLATFORMS = Object.keys(CONFINED_WIDE_PATHS);

// ── THE PATH SET ──────────────────────────────────────────────────────────────────────────────────

test('⭑ THE LOAD-BEARING GUARD: no path set contains a whole-filesystem spelling', () => {
  // ⛔ WHY THIS IS THE MOST IMPORTANT CASE IN THE FILE. The probe's entire claim is that the sandbox
  // STAYS ENGAGED, and both backends decide that from the path STRING. Linux's `is_whole_root` accepts
  // `"" | "**" | "/" | "/**"` and DROPS the grant outright; Windows' `is_whole_fs` accepts
  // `"**" | "/**" | "/"` and sets `degrade.generous_read`, which declines the LowBox token. Either way
  // the probe would be measuring the ABSENCE of confinement and reporting it as "confined and wide" —
  // the one wrong answer nothing downstream can catch, because a passing arm looks identical.
  //
  // `catalog_v2::parse_baseline` refuses the bare `/`, `~` and `$home` on its own, but NOT `/**`.
  for (const p of PLATFORMS) {
    for (const b of confinedWideBaseline(p)) {
      assert.ok(!['', '**', '/', '/**', '~', '$home'].includes(b.path.trim()),
        `${p}: \`${b.path}\` is the whole filesystem — the probe would relax the fs axis`);
    }
  }
});

test('⭑ RED CONTROL: a whole-filesystem spelling in the set is REFUSED, not quietly emitted', () => {
  // ⛔ THE CASE ABOVE ONLY CHECKS TODAY'S CONSTANT, so on its own it says nothing about what happens
  // when someone adds `/**` tomorrow. This drives the guard itself, on every spelling both backends
  // recognise, so the protection survives an edit to the table rather than only describing it.
  const saved = CONFINED_WIDE_PATHS.linux;
  try {
    for (const bad of ['/**', '**', '/', '~', '$home', '  /  ']) {
      CONFINED_WIDE_PATHS.linux = ['/tmp', bad];
      assert.throws(() => confinedWideBaseline('linux'), /whole-filesystem spelling/,
        `\`${bad}\` was accepted into a probe path set`);
    }
  } finally { CONFINED_WIDE_PATHS.linux = saved; }
});

test('every probe path is granted WRITE — a read-only entry would measure the rung below it', () => {
  // The probe's whole subject is the WRITE axis. `read:"disk"` is already the last confined rung, so a
  // baseline that granted reads would re-run that rung under a new name and always agree with it.
  for (const p of PLATFORMS) {
    for (const b of confinedWideBaseline(p)) {
      assert.equal(b.write, true, `${p}: \`${b.path}\` is read-only`);
      // `catalog_v2::parse_baseline` rejects any key outside this set and refuses the WHOLE catalog,
      // which leaves the arm VOID rather than merely narrow.
      assert.deepEqual(Object.keys(b).sort(), ['notes', 'path', 'write']);
    }
  }
});

test('macOS names /usr/local and NOT /usr, which SIP makes unwritable at any grant', () => {
  // Granting a path the OS refuses anyway costs a rule and measures nothing — and on Windows the same
  // shape costs an ACE write per launch. Stated as a case because it is the kind of entry a later edit
  // adds "for symmetry" with Linux.
  assert.ok(CONFINED_WIDE_PATHS.darwin.includes('/usr/local'));
  assert.ok(!CONFINED_WIDE_PATHS.darwin.includes('/usr'));
  assert.ok(CONFINED_WIDE_PATHS.linux.includes('/usr'), 'Linux dropped the system root it CAN grant');
});

test('the host temp root is in every POSIX set — it is the likeliest single member', () => {
  // ⛔ THE MECHANISM, from `linux_landlock.rs`: there is no mount namespace under Landlock, so
  // `TmpMode::Private` is only a per-run scratch dir with `TMPDIR` repointed. The REAL `/tmp` is simply
  // ungranted at every confined rung, and `relax_fs_to_full_disk` puts tmp back to `Shared` — which
  // its own doc names as the residual failure the terminal tier exists to have none of. So a script
  // writing a hardcoded `/tmp/...` path can currently only ever pass unconfined.
  assert.ok(CONFINED_WIDE_PATHS.linux.includes('/tmp'));
  assert.ok(CONFINED_WIDE_PATHS.darwin.includes('/tmp'));
  // `/tmp` and `/var` are symlinks into `/private` on macOS, and a matcher that resolves one does not
  // necessarily resolve the other, so both spellings are named. One rule each.
  assert.ok(CONFINED_WIDE_PATHS.darwin.includes('/private/tmp'));
});

test('⭑ win32 is BOUNDED, and says so — the ceiling there is ownership, not the token', () => {
  // ⛔ MEASURED, NOT ASSUMED: `.frizz/sandbox-MECHANISM-FACTS.md` §5l (2026-08-01, runs 30688900451 /
  // 30689267117 / 30689583039, both images, FAILURES=0). An AppContainer holding a BROAD filesystem
  // grant works — the token survives a wide grant. What bounds the grant is what an unprivileged
  // caller can install an ACE on: `C:\`, `C:\ProgramData`, `C:\Users` and `C:\Users\Public` return
  // ERR 5 on the DACL write, and `C:\Program Files` and `C:\Windows` refuse it even ELEVATED because
  // TrustedInstaller owns them. The measured ceiling is `%USERPROFILE%` and below plus whatever nub
  // creates — and the last confined rung's `write.userHome` already covers most of that.
  //
  // ⇒ on win32 a PASS still proves the package is confinable; a FAIL does NOT separate a token problem
  // from a path problem. Carrying that in the marker is what stops a reader taking the win32 answer
  // for the POSIX one.
  assert.equal(interpretation('win32'), 'bounded');
  assert.equal(interpretation('linux'), 'full');
  assert.equal(interpretation('darwin'), 'full');
  assert.equal(JSON.parse(marker('fail', 'win32').replace(/^\s*\S+\s/, '')).interpretation, 'bounded');
});

test('a platform with no probe set returns null rather than an empty baseline', () => {
  // An empty baseline would run the arm at the PLAIN rung while the driver reported a probe result for
  // an experiment it never made. Null is what makes the caller refuse instead.
  assert.equal(confinedWideBaseline('sunos'), null);
});

// ── THE CATALOG DOCUMENT ──────────────────────────────────────────────────────────────────────────

test('⭑ `baseline` appears ONLY when asked for, so every other arm is byte-identical', () => {
  // ⛔ THE LADDER RESTS ON ONE VARIABLE PER ARM. An arm carrying the baseline key is an arm running a
  // different experiment while reporting under the same rung, so the default path must be exactly what
  // it was before the parameter existed.
  const plain = buildCatalog('demo', { network: true }, '/nonexistent');
  assert.ok(!('baseline' in plain.catalog), 'a plain arm grew a baseline key');
  const wide = buildCatalog('demo', { network: true }, '/nonexistent', confinedWideBaseline('linux'));
  assert.deepEqual(Object.keys(wide.catalog).sort(), ['baseline', 'packages']);
  // The TARGET's grant is untouched by the widening: the probe widens the floor every script stands
  // on, not the package's own entry, which is what keeps the arm comparable to the rung it sits beside.
  assert.deepEqual(wide.catalog.packages, plain.catalog.packages);
  // An empty array is not a baseline either — same reason.
  assert.ok(!('baseline' in buildCatalog('demo', {}, '/nonexistent', []).catalog));
});

test('⭑ the CLI writes the baseline only under --confined-wide', () => {
  // Driven through the real CLI rather than the export, because the two shell drivers reach this code
  // only through `node dep-scaffold.mjs …` and an export-only test would not have caught a flag that
  // was never parsed.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cw-cli-'));
  try {
    const run = (...extra) => {
      execFileSync('node', [path.join(HERE, 'dep-scaffold.mjs'), dir, 'demo', '{"network":true}',
        '/nonexistent', ...extra], { encoding: 'utf8' });
      return JSON.parse(fs.readFileSync(path.join(dir, 'cat.json'), 'utf8'));
    };
    assert.ok(!('baseline' in run()), 'the default CLI path emitted a baseline');
    const wide = run('--confined-wide');
    assert.ok(Array.isArray(wide.baseline) && wide.baseline.length > 0);
    assert.ok(wide.baseline.every((b) => b.write === true));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ── THE RECORDER ──────────────────────────────────────────────────────────────────────────────────

test('⭑ the marker round-trips into the record', () => {
  const r = parseDriverLog(`  => MINIMUM {"write":"disk","network":true}   (ladder fallback; synthesized grant was insufficient)\n${marker('pass', 'linux')}`);
  assert.equal(r.confinedWide.result, 'pass');
  assert.equal(r.confinedWide.interpretation, 'full');
  assert.ok(r.confinedWide.paths.includes('/tmp'));
  // And the ladder's own verdict is untouched by the probe's presence in the log.
  assert.deepEqual(r.grant, { write: 'disk', network: true });
});

test('⭑ FAIL CLOSED: an unreadable marker leaves the field NULL and notes it', () => {
  // ⛔ THE DIRECTION THAT MATTERS. Null is "not established", so the package stays on whatever the
  // ladder concluded — the WIDER grant. The failure this forbids is a fabricated `pass`, which is the
  // only reading that could make an unconfinable package look confinable.
  for (const bad of [
    `  ${CONFINED_WIDE_MARKER} {not json}`,
    `  ${CONFINED_WIDE_MARKER} {"result":"maybe"}`,
    `  ${CONFINED_WIDE_MARKER} {"result":true}`,
    `  ${CONFINED_WIDE_MARKER} {}`,
  ]) {
    const r = parseDriverLog(bad);
    assert.equal(r.confinedWide, null, `\`${bad}\` produced a result`);
    assert.ok(r.notes.includes('confined-wide-marker-unparsable'), `\`${bad}\` was dropped silently`);
  }
});

test('a log with no marker at all carries null and NO note', () => {
  // ⛔ ABSENT IS NOT UNPARSABLE. Every record taken before the probe existed, and every record whose
  // confined rung passed, has no marker — noting those would flood `notes` with a non-finding and
  // train a reader to ignore the token that does carry information.
  const r = parseDriverLog('  => VERIFIED {"network":true}   (observed, then verified)');
  assert.equal(r.confinedWide, null);
  assert.ok(!r.notes.includes('confined-wide-marker-unparsable'));
});

test('every result the module can emit is one the recorder accepts', () => {
  // ⛔ THE TWO ENDS OF ONE CONTRACT, PINNED TOGETHER. A result added to `RESULTS` without teaching the
  // recorder would fail closed — safe, but silently — and the whole measurement would vanish from
  // every record while both halves stayed green in isolation.
  for (const result of RESULTS) {
    assert.equal(parseDriverLog(marker(result)).confinedWide.result, result);
  }
  assert.throws(() => marker('sortof'), /unknown result/);
});
