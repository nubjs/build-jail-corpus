// Known-answer tests for the Windows ETW adapter's PARSE half.
//
// ⛔ EVERY CASE BELOW IS A DECODING FAILURE THAT WAS MEASURED ON A REAL RUNNER, NOT IMAGINED. The
// known-answer fixture in `probes/win-viability/` performed a rename and a hard link at paths it
// named itself; at BOTH keyword masks the DESTINATION of each was absent entirely from the
// normalized stream (run 31116467283). The cause is here rather than in the capture script: a
// handle op resolved its path as `nameByObject.get(FileObject)` first, and on a RenamePath that
// FileObject still names the SOURCE -- so the source won, the source had already been emitted by
// the Rename event, the dedup set swallowed it, and the destination silently never existed.
//
// ⛔ THE ADAPTER IS A SCRIPT, NOT A MODULE, SO THESE DRIVE IT AS A SUBPROCESS over a synthetic
// capture directory. That is deliberate: the alternative is refactoring `windows.mjs` to export a
// `decode()` the way `linux.mjs` does, and the fourteen write shapes that pass today all run
// through the code path such a refactor would move. A subprocess test costs a few milliseconds and
// touches nothing.
//
// ⛔ WHAT THESE CAN AND CANNOT PROVE. They pin the RESOLUTION ORDER -- that a destination event's
// payload path beats the handle tables, that a rename keeps BOTH ends, that a shared Irp does not
// evict one for the other. They cannot prove anything about the KERNEL: which field it populates on
// events 26/27/28 is the provider's business, and `wevtutil gp /ge:true` publishes no templates for
// it. That was settled by reading a real trace instead (run 31118563399) -- it is `FilePath`, and
// every destination arrived as an absolute NT device path. Both plausible spellings stay covered
// here so the decoder is not pinned to one observation, and `windows.mjs --dump-dest N` prints the
// raw payload so the next person can re-settle it by reading rather than by guessing.
import { test } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const ADAPTER = path.join(import.meta.dirname, 'windows.mjs');
const VOL = '\\Device\\HarddiskVolume4';
const PID = 4242, TID = 77, PPID = 4200;

const ev = (id, data, pid = PID) => {
  const fields = Object.entries(data).map(([k, v]) => `    <Data Name="${k}">${v}</Data>`).join('\n');
  return `<Event xmlns="x">
  <System>
    <Provider Name="Microsoft-Windows-Kernel-File" />
    <EventID>${id}</EventID>
    <Execution ProcessID="${pid}" ThreadID="${TID}" />
  </System>
  <EventData>
${fields}
  </EventData>
</Event>`;
};

// One decode run: write a synthetic capture, invoke the adapter, return its events plus stderr.
//
// `shortNames` writes the archived 8.3 map into the capture directory, exactly where the capture
// host's resolution pass would leave it. `env` overrides the child's environment so a test can
// prove the decode does NOT depend on it.
function decode(events, { fileMask = '0x1FF0', extraArgs = [], shortNames = null, env = null } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'winadapt-'));
  fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify({
    schema: 'nub-obs-win/1', host: 'SYNTHETIC-HOST', rootPid: PID, launcherPid: PPID,
    devmap: { [VOL]: 'C:' }, eventsLost: 0, eventsTotal: events.length, fileMask,
  }));
  if (shortNames) {
    fs.writeFileSync(path.join(dir, 'shortnames.json'), JSON.stringify({
      schema: 'nub-obs-win-shortnames/1', host: 'SYNTHETIC-HOST',
      resolvedAt: '2026-01-01T00:00:00.000Z', entries: shortNames,
    }));
  }
  fs.writeFileSync(path.join(dir, 'trace.xml'), `<Events>\n${events.join('\n')}\n</Events>\n`);
  const outFile = path.join(dir, 'events.ndjson');
  const r = spawnSync(process.execPath, [ADAPTER, dir, '--out', outFile, ...extraArgs],
    { encoding: 'utf8', ...(env ? { env: { ...process.env, ...env } } : {}) });
  assert.equal(r.status, 0, `adapter exited ${r.status}\n${r.stderr}`);
  const lines = fs.readFileSync(outFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  fs.rmSync(dir, { recursive: true, force: true });
  return { events: lines, stderr: r.stderr };
}

const writes = (d) => new Set(d.events.filter((e) => e.op === 'write' && e.result === 'ok').map((e) => e.path));
const reads = (d) => new Set(d.events.filter((e) => e.op === 'read' && e.result === 'ok').map((e) => e.path));

// The shape the kernel emits for `rename(SRC, DST)`: the handle was opened on SRC, the Rename and
// the RenamePath share ONE Irp, and a single OperationEnd settles both.
const renameSeq = (destField, destValue) => [
  ev(12, { Irp: '0xA0', FileObject: '0xF1', FileName: `${VOL}\\w\\SRC.bin`, CreateOptions: '0x01000000' }),
  ev(24, { Irp: '0xA0', Status: '0x0' }),
  ev(19, { Irp: '0xB0', FileObject: '0xF1' }),
  ev(27, { Irp: '0xB0', FileObject: '0xF1', [destField]: destValue }),
  ev(24, { Irp: '0xB0', Status: '0x0' }),
];

test('a rename destination is emitted from the RenamePath payload, not the source handle', () => {
  const w = writes(decode(renameSeq('FilePath', `${VOL}\\w\\DST.bin`)));
  assert.ok(w.has('C:\\w\\DST.bin'), `destination absent; got ${[...w]}`);
});

test('a rename keeps BOTH ends even though Rename and RenamePath share one Irp', () => {
  // The regression this guards is specific and was visible in the probe as `orphan creates` going
  // 8 -> 23: a single-valued pending map is last-writer-wins, so putting the destination in it
  // evicts the source and trades one missing end of the rename for the other.
  const w = writes(decode(renameSeq('FilePath', `${VOL}\\w\\DST.bin`)));
  assert.ok(w.has('C:\\w\\SRC.bin'), `source absent; got ${[...w]}`);
  assert.ok(w.has('C:\\w\\DST.bin'), `destination absent; got ${[...w]}`);
});

test('the destination field is read from whichever spelling the payload carries', () => {
  // DEST_PATH_FIELDS exists because the provider publishes no template. Both candidates resolve.
  for (const field of ['FilePath', 'FileName']) {
    const w = writes(decode(renameSeq(field, `${VOL}\\w\\DST.bin`)));
    assert.ok(w.has('C:\\w\\DST.bin'), `${field}: destination absent; got ${[...w]}`);
  }
});

test('a bare-leaf destination is anchored to the source directory', () => {
  const w = writes(decode(renameSeq('FilePath', 'DST.bin')));
  assert.ok(w.has('C:\\w\\DST.bin'), `relative destination not anchored; got ${[...w]}`);
});

test('a hardlink destination is emitted from SetLinkPath', () => {
  const d = decode([
    ev(12, { Irp: '0xA0', FileObject: '0xF2', FileName: `${VOL}\\w\\LINKSRC.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xA0', Status: '0x0' }),
    ev(28, { Irp: '0xB1', FileObject: '0xF2', FilePath: `${VOL}\\w\\LINKDST.bin` }),
    ev(24, { Irp: '0xB1', Status: '0x0' }),
  ]);
  assert.ok(writes(d).has('C:\\w\\LINKDST.bin'), `hardlink destination absent; got ${[...writes(d)]}`);
});

test('a hardlink keeps BOTH names, and keeps them PAIRED in one record', () => {
  // ⛔ A HARD LINK IS A SECOND NAME FOR EXISTING CONTENT, so afterwards two live paths reach the
  // same bytes. Two unrelated single-path records lose which link went with which target the moment
  // two link operations interleave -- and a link whose target is unknown is not merely an
  // under-grant, it is a path the model cannot reason about at all. SetLinkPath carries both ends
  // in ONE event, so splitting them apart on the way out would be discarding a fact we were given.
  const d = decode([
    ev(12, { Irp: '0xA0', FileObject: '0xF2', FileName: `${VOL}\\w\\LINKSRC.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xA0', Status: '0x0' }),
    ev(28, { Irp: '0xB1', FileObject: '0xF2', FilePath: `${VOL}\\w\\LINKDST.bin` }),
    ev(24, { Irp: '0xB1', Status: '0x0' }),
  ]);
  const link = d.events.find((e) => e.path === 'C:\\w\\LINKDST.bin');
  assert.ok(link, `the new name is absent; got ${JSON.stringify(d.events)}`);
  assert.equal(link.kind, 'hardlink', 'the record does not say it is a hard link');
  assert.equal(link.path2, 'C:\\w\\LINKSRC.bin', 'the record does not name the content it links to');
  // And the old name is in the stream in its own right, from the open that made the link.
  assert.ok(reads(d).has('C:\\w\\LINKSRC.bin'), `the existing name is absent; got ${[...reads(d)]}`);
});

test('a rename record names both ends and calls itself a rename', () => {
  const d = decode(renameSeq('FilePath', `${VOL}\\w\\DST.bin`));
  const mv = d.events.find((e) => e.path === 'C:\\w\\DST.bin');
  assert.equal(mv?.kind, 'rename');
  assert.equal(mv?.path2, 'C:\\w\\SRC.bin');
});

test('a delete carries no path2, because both ends are the same file', () => {
  const d = decode([
    ev(12, { Irp: '0xA0', FileObject: '0xF3', FileName: `${VOL}\\w\\GONE.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xA0', Status: '0x0' }),
    ev(26, { Irp: '0xC0', FileObject: '0xF3', FilePath: `${VOL}\\w\\GONE.bin` }),
    ev(24, { Irp: '0xC0', Status: '0x0' }),
  ]);
  const del = d.events.find((e) => e.op === 'write' && e.path === 'C:\\w\\GONE.bin');
  assert.ok(del, 'the deleted path is absent');
  assert.equal(del.path2, undefined, 'a self-referential path2 was emitted');
});

test('a DeletePath reports the deleted path', () => {
  const d = decode([
    ev(26, { Irp: '0xC0', FileObject: '0xF9', FilePath: `${VOL}\\w\\GONE.bin` }),
    ev(24, { Irp: '0xC0', Status: '0x0' }),
  ]);
  assert.ok(writes(d).has('C:\\w\\GONE.bin'), `deleted path absent; got ${[...writes(d)]}`);
});

test('a \\??\\ destination decodes to its drive letter rather than landing in kernelfs', () => {
  // classify.mjs sends anything starting `\??\` to the `kernelfs` bucket, where a real write is
  // reported as filesystem metadata and never reaches a grant.
  const w = writes(decode(renameSeq('FilePath', '\\??\\C:\\w\\DST.bin')));
  assert.ok(w.has('C:\\w\\DST.bin'), `\\??\\ prefix not decoded; got ${[...w]}`);
});

test('a refused destination is reported as denied, never as a successful write', () => {
  const d = decode([
    ev(12, { Irp: '0xA0', FileObject: '0xF1', FileName: `${VOL}\\w\\SRC.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xA0', Status: '0x0' }),
    ev(27, { Irp: '0xB0', FileObject: '0xF1', FilePath: `${VOL}\\w\\DST.bin` }),
    ev(24, { Irp: '0xB0', Status: '0xC0000022' }),       // STATUS_ACCESS_DENIED
  ]);
  assert.ok(!writes(d).has('C:\\w\\DST.bin'), 'a denied rename destination was reported as a write');
  assert.ok(d.events.some((e) => e.path === 'C:\\w\\DST.bin' && e.result === 'denied'),
    `the refusal was dropped instead of recorded; got ${JSON.stringify(d.events)}`);
});

test('the ordinary read path is untouched: a FILE_OPEN create is still a read', () => {
  // The control. Every one of the fourteen shapes that passed before this change runs through this
  // branch, so a test that only checks the new behavior cannot tell a fix from a rewrite.
  const d = decode([
    ev(12, { Irp: '0xD0', FileObject: '0xE1', FileName: `${VOL}\\w\\INPUT.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xD0', Status: '0x0' }),
  ]);
  assert.deepEqual([...reads(d)], ['C:\\w\\INPUT.bin']);
  assert.equal(writes(d).size, 0, 'a plain FILE_OPEN was reported as a write');
});

test('a write through a FILE_OPEN handle is still rescued by the Write event', () => {
  const d = decode([
    ev(12, { Irp: '0xD0', FileObject: '0xE2', FileName: `${VOL}\\w\\RW.bin`, CreateOptions: '0x01000000' }),
    ev(24, { Irp: '0xD0', Status: '0x0' }),
    ev(16, { Irp: '0xD1', FileObject: '0xE2' }),
    ev(24, { Irp: '0xD1', Status: '0x0' }),
  ]);
  assert.ok(writes(d).has('C:\\w\\RW.bin'), `write-through-handle lost; got ${[...writes(d)]}`);
});

test('a capture taken at the old mask is called out rather than read as complete', () => {
  // ⛔ THE POINT OF RETENTION IS THAT A STREAM CAN BE RE-READ LATER. A record captured at 0x11F0
  // has no rename or hardlink destinations in it and nothing in the events themselves says so, so
  // the meta has to. Silence here is what would let a short stream be trusted.
  const d = decode([ev(26, { Irp: '0xC0', FilePath: `${VOL}\\w\\X.bin` }), ev(24, { Irp: '0xC0', Status: '0x0' })],
    { fileMask: '0x11F0' });
  assert.match(d.stderr, /RENAME and HARDLINK DESTINATIONS ARE MISSING/);
});

// ── 8.3 SHORT NAMES: the decode must not depend on WHERE it is decoded (VENUE-PORTABILITY R2) ───
//
// ⛔ THESE REPLACE A TEST THAT PINNED THE DEFECT. The old case asserted expansion was inert "when
// the capture came from another host", which passed because `meta.host` never equalled this
// machine's `COMPUTERNAME` — and would have passed identically on a machine where it DID, by taking
// the other branch. It could therefore never have caught the real failure: one archive decoding
// differently on two machines. The map is now an archive artifact, so the same three cases below
// give the same answers on every machine, and the last one is the control that says so.
const SHORT_WRITE = [
  ev(12, { Irp: '0xA1', FileObject: '0xF5', FileName: `${VOL}\\Users\\RUNNER~1\\x.bin`, CreateOptions: '0x05000000' }),
  ev(24, { Irp: '0xA1', Status: '0x0' }),
];

test('an archive with no 8.3 map keeps the short spelling, and says the ARCHIVE is why', () => {
  const d = decode(SHORT_WRITE);
  assert.ok(writes(d).has('C:\\Users\\RUNNER~1\\x.bin'), `short name was rewritten with no map; got ${[...writes(d)]}`);
  // The reason must name the archive, not two machines. An "off because you are elsewhere" message
  // is the old behaviour restated, and a reader cannot check it.
  assert.match(d.stderr, /no recorded 8\.3 map/);
  assert.match(d.stderr, /property of this ARCHIVE/);
});

test('a recorded 8.3 map expands the path, on any machine, with no filesystem access', () => {
  // The map names a path that exists on NO machine, least of all this one. If the decoder were
  // still resolving against the filesystem this could not pass anywhere; that it passes is what
  // proves the map is the sole authority.
  const d = decode(SHORT_WRITE, {
    shortNames: { 'c:\\users\\runner~1': 'runneradmin' },
  });
  assert.ok(writes(d).has('C:\\Users\\runneradmin\\x.bin'),
    `recorded map was not applied; got ${[...writes(d)]}`);
  assert.match(d.stderr, /8\.3 names 1 paths expanded/);
});

test('a map that does not cover a component keeps it short and reports the archive as INCOMPLETE', () => {
  // ⛔ THE STATE THAT LOOKS FINE. An absent key is not the same as a recorded `null`: the first
  // means the map is partial, the second means the capture host looked and found nothing. Merging
  // them would let a partial archive read as a complete one, and the path then falls to the
  // `outside` scope — reported, never granted, which is an under-grant.
  const d = decode(SHORT_WRITE, { shortNames: { 'c:\\users\\somethingelse~1': 'x' } });
  assert.ok(writes(d).has('C:\\Users\\RUNNER~1\\x.bin'), `uncovered component was rewritten; got ${[...writes(d)]}`);
  assert.match(d.stderr, /map is INCOMPLETE/);
  assert.match(d.stderr, /1 not covered by the archived map/);
});

test('a recorded null is an ANSWER — kept short, and NOT reported as an incomplete archive', () => {
  const d = decode(SHORT_WRITE, { shortNames: { 'c:\\users\\runner~1': null } });
  assert.ok(writes(d).has('C:\\Users\\RUNNER~1\\x.bin'), `a recorded null was treated as a long name; got ${[...writes(d)]}`);
  assert.match(d.stderr, /1 kept short/);
  assert.doesNotMatch(d.stderr, /map is INCOMPLETE/);
});

test('⭑ THE VENUE CONTROL: the decode is byte-identical under two different COMPUTERNAMEs', () => {
  // ⛔ THIS IS THE ACCEPTANCE TEST'S OWN INSTRUMENT, IN MINIATURE. The venue-portability test
  // compares two archives; if the decoder answers differently depending on the machine reading it,
  // that comparison is measuring the reader. `COMPUTERNAME` is the exact variable both Windows
  // decoders used to key on, so setting it to two values that BOTH differ from the capture's host
  // and to one that MATCHES it exercises all three branches of the mechanism that was removed.
  const map = { 'c:\\users\\runner~1': 'runneradmin' };
  const under = (COMPUTERNAME) => {
    const d = decode(SHORT_WRITE, { shortNames: map, env: { COMPUTERNAME } });
    return `${[...writes(d)].sort().join('|')}  ${/8\.3 names (\d+) paths expanded/.exec(d.stderr)?.[1]}`;
  };
  const onCaptureHost = under('SYNTHETIC-HOST');    // the capture's own meta.host
  const elsewhere = under('SOME-OTHER-RUNNER');
  const unset = under('');
  assert.equal(onCaptureHost, elsewhere,
    'the decoder still varies with COMPUTERNAME — an archive would decode differently by venue');
  assert.equal(onCaptureHost, unset, 'the decoder varies with COMPUTERNAME being absent');
  assert.match(onCaptureHost, /runneradmin/, 'positive control: the map must actually have been applied');
});

test('--resolve-shortnames off Windows refuses rather than recording this machine\'s names', () => {
  // The resolution pass is capture-host-only by construction. Run anywhere else it would record a
  // map of the WRONG machine's directory names into the archive — a fabricated fact that every
  // later decode would then faithfully reproduce.
  const d = decode(SHORT_WRITE, { extraArgs: ['--resolve-shortnames'] });
  if (process.platform === 'win32') return;   // the positive path is exercised on the runner
  assert.match(d.stderr, /refusing to invent a map/);
  assert.ok(writes(d).has('C:\\Users\\RUNNER~1\\x.bin'), `short name was rewritten off Windows; got ${[...writes(d)]}`);
});
