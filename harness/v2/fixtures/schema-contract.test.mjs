// ⛔ ADVISORY, NOT A GATE. Read this before "fixing" a failure here.
// `node --test harness/v2/fixtures/schema-contract.test.mjs`
//
// This checks that the DERIVED event streams — `events.ndjson.gz` — have not drifted apart by
// accident. It does NOT check the archive, and it must never constrain what a platform records.
//
// ⛔ THE ARCHIVE IS THE RAW PER-OS TRACER OUTPUT (`trace.txt.gz` + `capture.json`), and per-OS
// formats with per-OS parsers are the settled shape. Requiring every adapter to satisfy one key set
// is ITSELF a canonicalization: it forces each lane to trim to the intersection of what all three
// tracers can express, so anything dtrace exposes that strace and ETW do not would have to be
// dropped or bloated into everyone's schema. That is the same lossy-classification failure as scope
// tags, one level out. ⇒ **If satisfying an assertion here would cost fidelity in a raw capture or
// in a platform's derived view, the capture wins and the assertion gets relaxed.** A macOS-only
// field is a REASON to capture it, not a reason to leave it out.
//
// What it is still good for, and it is worth keeping: each adapter's own suite passes against its
// own spelling, so nothing else in the tree notices when two of them diverge for no reason. A
// cross-platform query (`eventlog-query.mjs`) is only writable once because these agree today.
//
// It runs against COMMITTED REAL LOGS, not constructed ones. A hand-written fixture agrees with
// whatever the author believed the schema was, which is exactly the belief under test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';

const HERE = new URL('.', import.meta.url).pathname;
const load = (name) => {
  const p = `${HERE}${name}`;
  if (!existsSync(p)) return null;
  return gunzipSync(readFileSync(p)).toString('utf8').trim().split('\n').map((l) => JSON.parse(l));
};

const LOGS = {
  linux: load('linux-hugo-extended-0.141.0.events.ndjson.gz'),
  macos: load('macos-apollo-rover-0.2.1.events.ndjson.gz'),
};

// Every platform present must satisfy all of these. A platform whose fixture is missing is SKIPPED
// with a named assertion rather than silently passing — a contract test that quietly tests one
// platform is the failure mode it exists to prevent.
const present = Object.entries(LOGS).filter(([, v]) => v);
test('at least two platforms have a committed log, or this test proves nothing', () => {
  assert.ok(present.length >= 2,
    `only ${present.map(([k]) => k).join(', ') || 'none'} committed — a one-platform contract test is vacuous`);
});

for (const [plat, rows] of present) {
  test(`${plat}: the header carries the ROOTS, which is what makes a re-parse possible`, () => {
    const h = rows.find((r) => r.k === 'h');
    assert.ok(h, 'a `k:"h"` header line must come first');
    assert.equal(h.v, 1, 'schema version');
    // ⛔ Every path in the stream is machine-specific (`/home/runner/v2-hNdvB5/…`). Without the
    // roots a future classifier cannot tell a project write from a home write and the log is a pile
    // of strings — so this is the one header field whose absence makes the file worthless.
    assert.ok(h.roots && h.roots.project, 'roots.project');
    assert.ok(h.roots.home, 'roots.home');
  });

  test(`${plat}: NO SCOPE TAG anywhere — the log retains inputs, not a classification`, () => {
    // A scope tag freezes the classifier that produced it. The `tmp` scope was being added while
    // this corpus was measured; with raw paths plus roots that is a re-parse, with scope tags it
    // would have been a full re-measure. This is the property retention is FOR.
    const text = JSON.stringify(rows.filter((r) => r.k === 'e'));
    for (const s of ['"scope"', '"deps"', '"userHome"', '"outside"', '"systemfs"']) {
      assert.ok(!text.includes(s), `a derived scope leaked into ${plat}: ${s}`);
    }
  });

  test(`${plat}: events use the shared key set`, () => {
    const evs = rows.filter((r) => r.k === 'e');
    assert.ok(evs.length > 100, 'a real log, not a stub');
    for (const e of evs.slice(0, 500)) {
      assert.equal(typeof e.p, 'number', 'p = pid');
      assert.equal(typeof e.o, 'string', 'o = neutral op class');
      assert.equal(typeof e.s, 'string', 's = the RAW syscall, which `o` cannot reconstruct');
      assert.ok(e.r === 0 || typeof e.r === 'string', 'r = 0 or an errno SYMBOL, never ok/denied');
      assert.equal(typeof e.n, 'number', 'n = repeat count, what makes dedup lossless');
    }
  });

  test(`${plat}: the process table carries what attribution would need to be RECOMPUTED`, () => {
    const ps = rows.filter((r) => r.k === 'p');
    assert.ok(ps.length > 0, 'a `k:"p"` row per process');
    for (const p of ps) {
      assert.equal(typeof p.pid, 'number');
      assert.ok('ppid' in p && 'exe' in p && 'argv' in p && 'cwd' in p && 'life' in p,
        'ppid/exe/argv/cwd/life — a boolean alone could only ever be re-measured');
    }
    assert.ok(ps.some((p) => p.life === 1), 'at least one process attributed to the lifecycle script');
    assert.ok(ps.some((p) => p.argv), 'and at least one argv, which is what a future rule replays from');
  });

  test(`${plat}: a two-path operation kept both ends`, () => {
    // The macOS lane lost 100% of its rename destinations for as long as its adapter existed, and
    // the decoder printed a confident grant the whole time. `g` is the field that would have caught
    // it, so its presence on a real log is worth asserting rather than assuming.
    const two = rows.filter((r) => r.k === 'e' && r.g);
    assert.ok(two.length > 0, 'no two-path event in a real trace is itself suspicious');
    for (const e of two.slice(0, 50)) assert.notEqual(e.f, e.g);
  });

  test(`${plat}: failed calls are RETAINED with their errno`, () => {
    // Nothing is filtered. A failed lookup names a fallback path the script probed for, and on a
    // machine where it exists the same script reads it — so dropping ENOENT is the under-grant
    // direction, not the free win it looks like.
    const failed = rows.filter((r) => r.k === 'e' && r.r !== 0);
    assert.ok(failed.length > 0, 'a real trace always contains failed lookups');
    assert.ok(failed.every((e) => /^E[A-Z0-9]+$/.test(e.r)), 'every result is a legible errno symbol');
  });
}

// ── THE ARCHIVE CLAIM, EXECUTED ───────────────────────────────────────────────────────────────
// ⛔ This is the one assertion that is NOT advisory, because it is the property the whole retention
// design rests on: the derived log is REGENERABLE from the archived raw trace. If it is not, then
// the raw trace is not actually an archive and a decoder bug is still a re-measure.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync as gunzip } from 'node:zlib';

const RAW = `${HERE}macos-apollo-rover-0.2.1.trace.txt.gz`;
if (existsSync(RAW)) {
  test('the derived macOS log regenerates from the archived raw trace, losing nothing', () => {
    const dir = mkdtempSync(join(tmpdir(), 'regen-'));
    const trace = join(dir, 'trace.txt');
    writeFileSync(trace, gunzip(readFileSync(RAW)));
    const out = join(dir, 'events.ndjson');
    execFileSync(process.execPath, [
      `${HERE}../adapters/macos-eventlog.mjs`, trace, '--out', out,
      '--pkg', '@apollo/rover', '--version', '0.2.1',
      // The roots come from the ARCHIVED log's own header, which is the point of recording them.
      '--project', LOGS.macos.find((r) => r.k === 'h').roots.project,
      '--home', LOGS.macos.find((r) => r.k === 'h').roots.home,
    ], { encoding: 'utf8' });
    const key = (e) => `${e.p}|${e.s}|${e.f}|${e.g ?? ''}|${e.r}|${e.n}`;
    const before = new Set(LOGS.macos.filter((r) => r.k === 'e').map(key));
    const after = new Set(readFileSync(out, 'utf8').trim().split('\n')
      .map((l) => JSON.parse(l)).filter((r) => r.k === 'e').map(key));

    // ⛔ SUPERSET, NOT EQUALITY, AND THAT IS DELIBERATE. A decoder is allowed to get BETTER — to
    // resolve an fd it previously could not, or to learn a syscall it used to skip — and a
    // byte-equality assertion would make every such improvement a test failure, which trains people
    // to update the fixture instead of reading the diff. What may never happen is a LOSS: an event
    // the archive supports that a later decoder stops producing. That is the direction that turns a
    // re-parse back into a re-measure.
    const lost = [...before].filter((k) => !after.has(k));
    assert.deepEqual(lost.slice(0, 5), [], `${lost.length} archived event(s) no longer regenerate`);
    assert.ok(after.size >= before.size, `regeneration produced ${after.size} of ${before.size}`);
  });
}
