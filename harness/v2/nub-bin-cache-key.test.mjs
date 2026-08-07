// No workflow may acquire its nub probe binary through a bare-PREFIX cache key.
//
// ⛔ THE DEFECT THIS GUARDS. A restore keyed `nub-bin-v1-<os>-${{ inputs.nub_sha }}` behind
// `restore-keys: nub-bin-v1-<os>-` serves WHATEVER BINARY WAS CACHED LAST whenever the exact key
// misses — and on a scheduled run, with `nub_sha` empty, the exact key is the bare prefix, which
// matches nothing, so the fallback is the only path taken. MEASURED on run 31145732202: the newest
// `nub-bin-v1-windows-*` was created 2026-08-06T07:33:54Z, the Windows-jail fix `4bd4687521` the run
// existed to exercise landed 2026-08-06T21:04:55Z, and that cache's `lastAccessedAt` is
// 2026-08-07T03:54:14Z. Every arm — including the KNOWN-SUFFICIENT control — died on the pre-fix
// behaviour, and an entire Windows measurement run was unattributable.
//
// ⛔ "THE ARM NEEDS THE FEATURE, NOT A SPECIFIC COMMIT" IS THE ARGUMENT THAT FAILED, and it failed
// in four workflows at once because each was written by copying the last. `4bd4687521` is a
// CORRECTNESS fix, not a feature flag: a binary that carries `build-jail-catalog-override` and
// predates it cannot run a Windows jailed arm at all. So a feature probe — which every one of these
// workflows does run, and which passed — cannot substitute for pinning the commit.
//
// ⛔ THE SECOND SHAPE IS THE ONE THAT LOOKS FINE. A literal exact key (`nub-bin-v1-macos-none`, or
// the bare `nub-bin-v1-linux-` used as the key itself) can never match a real save, so the prefix
// fallback is not a fallback — it is the whole mechanism, permanently. Both shapes were live in this
// repo, which is why both are asserted here.
//
// ⛔ THIS IS A TEXT SCAN, DELIBERATELY. There is no YAML parser in this repo (no package.json, no
// node_modules), and `no-inline-tmp-path.test.mjs` establishes the precedent: a scoped regex over
// the workflow text, with its extractor proven against known-answer samples FIRST. An unvalidated
// scan that silently matches nothing reports every workflow clean, which is the exact vacuous green
// this file exists to prevent one level up.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const WORKFLOWS = path.join(import.meta.dirname, '..', '..', '.github', 'workflows');
const files = fs.readdirSync(WORKFLOWS).filter((f) => f.endsWith('.yml') || f.endsWith('.yaml'));
const read = (f) => fs.readFileSync(path.join(WORKFLOWS, f), 'utf8');

/**
 * Every `restore-keys:` list entry that names a `nub-bin-` prefix. Scoped to the probe-binary cache
 * on purpose: a prefix fallback on a CARGO or npm cache is ordinary and correct — a stale compiler
 * artifact is revalidated by the build, while a stale nub binary IS the measurement.
 */
const prefixFallbacks = (text) => {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)restore-keys:/.exec(lines[i]);
    if (!m) continue;
    // The block form (`restore-keys: |`) puts entries on the following MORE-indented lines; the
    // inline form puts one on the same line. Both are read, so neither spelling evades the guard.
    const inline = /^\s*restore-keys:\s*(\S.*)$/.exec(lines[i]);
    if (inline && inline[1] !== '|' && inline[1] !== '>') {
      if (/nub-bin-/.test(inline[1])) out.push(inline[1].trim());
      continue;
    }
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (l.trim() === '') continue;
      if ((/^(\s*)/.exec(l))[1].length <= m[1].length) break;
      if (/nub-bin-/.test(l)) out.push(l.trim());
    }
  }
  return out;
};

/**
 * Every `key:` for a `nub-bin-` cache whose value is a fixed literal — i.e. carries no `${{ … }}`
 * commit expression, so it names no commit and can only ever resolve through a fallback.
 */
const unpinnedKeys = (text) => [...text.matchAll(/^\s*key:\s*(nub-bin-\S*)\s*$/gm)]
  .map((m) => m[1])
  .filter((k) => !k.includes('${{'));

// ⛔ AN ENTRY HERE IS A DECISION, NOT A WAY TO GET GREEN, and the reason is required for the same
// motive as `marker-contract.test.mjs`'s LOG_ONLY: an undocumented allowlist is the defect with a
// rubber stamp on it. The default answer is "pin the key".
const ALLOWED = new Map([
  ['win-acl-probe.yml',
   'Restore-ONLY: this workflow has no build step, so an exact key would make every miss a silent '
   + 'no-op — the nub arms are skipped and the probe answers nothing, which is strictly worse than '
   + 'answering with a binary whose identity the log records. Pinning it properly means adding a '
   + 'Windows cold Rust build to a probe that today costs minutes, and that is a cost decision the '
   + 'maintainer owns rather than a drive-by. It compensates by logging the resolved cache key and '
   + 'by exercising the override feature; neither compares the commit against the fix under test, '
   + 'so the residual risk is real and is recorded here rather than hidden.'],
]);

// ── CONTROLS — everything below is worthless without these ────────────────────────────────────────

test('CONTROL: the extractors flag a known-bad workflow and clear a known-good one', () => {
  const bad = [
    '      - name: Restore a feature-enabled nub binary',
    '        uses: actions/cache/restore@v4',
    '        with:',
    '          path: /tmp/nub/target/release/nub',
    '          key: nub-bin-v1-macos-none',
    '          restore-keys: |',
    '            nub-bin-v1-macos-',
  ].join('\n');
  assert.deepEqual(prefixFallbacks(bad), ['nub-bin-v1-macos-'],
    'the fallback extractor missed a known prefix fallback — every result it produces is worthless');
  assert.deepEqual(unpinnedKeys(bad), ['nub-bin-v1-macos-none'],
    'the key extractor missed a known literal key');

  const good = [
    '          key: nub-bin-v1-macos-${{ env.NUB_GIT_SHA }}',
  ].join('\n');
  assert.deepEqual(prefixFallbacks(good), [], 'a restore with no fallback must not be flagged');
  assert.deepEqual(unpinnedKeys(good), [], 'a key pinned to a resolved SHA must not be flagged');

  // …and an unrelated cache keeps its fallback. Without this the guard would be a blanket ban on
  // `restore-keys`, which is correct for a nub binary and wrong for a compiler cache.
  const cargo = [
    '          key: cargo-${{ hashFiles(\'**/Cargo.lock\') }}',
    '          restore-keys: |',
    '            cargo-',
  ].join('\n');
  assert.deepEqual(prefixFallbacks(cargo), [], 'a non-nub-bin cache fallback must not be flagged');
});

test('CONTROL: the scan is reading real workflow files that mention the probe-binary cache', () => {
  // Guards against a wrong WORKFLOWS path turning both assertions below into a pass over an empty
  // set — the failure mode that would make this whole file report "clean" forever.
  assert.ok(files.length >= 2, `only ${files.length} workflow file(s) found — the path is wrong`);
  const withNubBin = files.filter((f) => /nub-bin-/.test(read(f)));
  assert.ok(withNubBin.length >= 2,
    `only ${withNubBin.length} workflow(s) mention nub-bin- — the scan is not reading what it thinks`);
});

// ── THE GUARD ─────────────────────────────────────────────────────────────────────────────────────

test('⭑ no workflow restores its nub probe binary through a bare-prefix fallback', () => {
  const offenders = [];
  for (const f of files) {
    if (ALLOWED.has(f)) continue;
    for (const k of prefixFallbacks(read(f))) offenders.push(`${f}: restore-keys ${k}`);
  }
  assert.deepEqual(offenders, [],
    'these serve whatever nub binary was cached last whenever the exact key misses, so the record '
    + 'or probe result below them is attributable to nothing:\n  ' + offenders.join('\n  ')
    + '\nKey on a SHA resolved in its own step BEFORE the restore, drop restore-keys, and add a '
    + 'cache/save so a miss costs one rebuild per SHA rather than one per run.');
});

test('⭑ every nub-bin cache key names a commit rather than a fixed literal', () => {
  const offenders = [];
  for (const f of files) {
    if (ALLOWED.has(f)) continue;
    for (const k of unpinnedKeys(read(f))) offenders.push(`${f}: key ${k}`);
  }
  assert.deepEqual(offenders, [],
    'a literal key can never match a real save (`nub-bin-v1-<os>-<sha>`), so the restore can only '
    + 'ever resolve through a fallback — the prefix is not a backstop, it is the whole mechanism:\n  '
    + offenders.join('\n  '));
});

test('every allowlist exemption is real, reasoned, and still needed', () => {
  // Keeps the allowlist from becoming a graveyard: an entry for a workflow that no longer has a
  // fallback would silently exempt a NEW one added to the same file later.
  for (const [f, why] of ALLOWED) {
    assert.ok(files.includes(f), `the allowlist names ${f}, which no longer exists — delete the entry`);
    assert.ok(prefixFallbacks(read(f)).length > 0 || unpinnedKeys(read(f)).length > 0,
      `${f} no longer has a prefix fallback or literal key — delete its exemption`);
    assert.ok(why && why.length > 120, `the exemption for ${f} has no real reason recorded`);
  }
});
