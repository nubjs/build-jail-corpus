// Known-answer tests for the Windows RETENTION adapter.
//
// ⛔ EVERY CASE HERE IS A DIFFERENCE FROM `windows.mjs`, NOT A RESTATEMENT OF IT. The synthesis
// decoder is correct for what it does and is deliberately left alone; the things it DROPS are the
// whole reason this adapter exists, so a test that only checked "a write is a write" would pass
// against either file and prove nothing about retention. Each test below names the thing the
// synthesis decoder discards and asserts the archive keeps it.
//
// The fixtures are literal tracerpt-shaped XML lines fed to the SAME `decodeLines` the CLI streams
// a real 300 MB trace through — one code path, so a green fixture is evidence about the real thing.
import { test } from 'node:test';
import assert from 'node:assert';
import { decodeLines, makeDosPath } from './windows-retain.mjs';

const VOL = '\\Device\\HarddiskVolume3';
const META = { rootPid: 100, launcherPid: 1, host: 'CAPTUREBOX', devmap: { [VOL]: 'C:' } };

// A tracerpt `<Event>` block, in the shape the real converter emits.
const ev = (provider, id, pid, tid, data, ts = '2026-08-06T12:00:00.000000000Z') => [
  '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
  ' <System>',
  `  <Provider Name="${provider}" Guid="{00000000-0000-0000-0000-000000000000}" />`,
  `  <EventID>${id}</EventID>`,
  `  <TimeCreated SystemTime="${ts}" />`,
  `  <Execution ProcessID="${pid}" ThreadID="${tid}" ProcessorID="0" />`,
  ' </System>',
  ' <EventData>',
  ...Object.entries(data).map(([k, v]) => `  <Data Name="${k}">${v}</Data>`),
  ' </EventData>',
  '</Event>',
];
const file = (id, pid, data, tid = 900) => ev('Microsoft-Windows-Kernel-File', id, pid, tid, data);
const decode = (lines, opts = {}) => decodeLines(lines, { meta: META, ...opts });
const find = (d, pred) => d.events.filter(pred);

// A Create that opens `path` for writing under Irp `irp`, then completes with `status`.
const createThenEnd = (pid, irp, ntPath, status, createOptions = '0x05000000') => [
  ...file(12, pid, { Irp: irp, FileObject: '0xF1', FileName: ntPath, CreateOptions: createOptions,
    ShareAccess: '0x3', FileAttributes: '0x80' }),
  ...file(24, pid, { Irp: irp, Status: status }),
];

test('a failure that is NOT one of the four refusals is RETAINED with its raw NTSTATUS', async () => {
  // ⛔ THE SINGLE BIGGEST DIFFERENCE FROM THE SYNTHESIS DECODER. windows.mjs keeps four refusal
  // codes and counts everything else into `skippedFailed`, so a probe for a file that is not there
  // — STATUS_OBJECT_NAME_NOT_FOUND — leaves no trace at all. "What did this package look for and
  // fail to find" is exactly the question a future grant model asks and today's cannot.
  const d = await decode([
    ...createThenEnd(100, '0xA1', `${VOL}\\proj\\maybe.node`, '0xC0000034'),  // OBJECT_NAME_NOT_FOUND
    ...createThenEnd(100, '0xA2', `${VOL}\\proj\\locked.db`, '0xC0000043'),   // SHARING_VIOLATION
  ]);
  const probe = find(d, (e) => e.f === 'C:\\proj\\maybe.node');
  assert.strictEqual(probe.length, 1, 'the not-found probe must survive into the archive');
  assert.strictEqual(probe[0].st, '0xc0000034', 'the raw NTSTATUS is kept, not reduced to a boolean');
  // STATUS_SHARING_VIOLATION has NO POSIX errno at all — it cannot be expressed in the Linux or
  // macOS schema, which is why the archive keeps the status rather than a cross-platform result.
  const shared = find(d, (e) => e.f === 'C:\\proj\\locked.db');
  assert.strictEqual(shared[0].st, '0xc0000043');
});

test('an operation whose OperationEnd never arrived is kept and MARKED, never dropped', async () => {
  // windows.mjs drops a Create left pending, and is right to: a status it had to guess could invent
  // a read into a grant. For an archive the operation demonstrably happened and only its outcome is
  // missing, so dropping it would delete evidence to avoid an ambiguity the record can just state.
  const d = await decode(file(12, 100, { Irp: '0xB1', FileObject: '0xF9',
    FileName: `${VOL}\\proj\\truncated-by-trace-stop`, CreateOptions: '0x05000000' }));
  const e = find(d, (x) => x.f.endsWith('truncated-by-trace-stop'));
  assert.strictEqual(e.length, 1, 'a pending op must reach the archive');
  assert.strictEqual(e[0].uns, 1, 'and must be marked as having no settled status');
  assert.strictEqual(e[0].st, null);
  assert.strictEqual(d.stats.unsettled, 1, 'and must be counted so the loss is visible');
});

test('an Irp reused before its OperationEnd records BOTH operations', async () => {
  // Irp pointers are reused back to back, so the pairing has to be nearest-in-time and consuming.
  // windows.mjs lets the second Create evict the first and counts an `orphanCreate`; here the
  // displaced request is recorded with an unknown status instead of vanishing.
  const d = await decode([
    ...file(12, 100, { Irp: '0xC1', FileObject: '0xF2', FileName: `${VOL}\\proj\\first`, CreateOptions: '0x05000000' }),
    ...file(12, 100, { Irp: '0xC1', FileObject: '0xF3', FileName: `${VOL}\\proj\\second`, CreateOptions: '0x01000000' }),
    ...file(24, 100, { Irp: '0xC1', Status: '0x0' }),
  ]);
  assert.ok(find(d, (e) => e.f === 'C:\\proj\\first').length === 1, 'the displaced request survives');
  const second = find(d, (e) => e.f === 'C:\\proj\\second')[0];
  assert.strictEqual(second.st, '0x00000000', 'the surviving request takes the status');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\first')[0].uns, 1, 'the displaced one is marked unknown');
});

test('a rename keeps BOTH ends on one record, with the destination as the primary path', async () => {
  // The destination events are the only carriers of a NEW name; for a RenamePath the FileObject
  // still names the SOURCE. Emitting the two ends as unrelated records loses which rename went with
  // which target the moment two interleave — the failure the macOS lane shipped for its whole life.
  const d = await decode([
    ...file(12, 100, { Irp: '0xD0', FileObject: '0xFA', FileName: `${VOL}\\proj\\old.tmp`, CreateOptions: '0x01000000' }),
    ...file(24, 100, { Irp: '0xD0', Status: '0x0' }),
    ...file(27, 100, { Irp: '0xD1', FileObject: '0xFA', FilePath: `${VOL}\\proj\\new.node`, InfoClass: '65' }),
    ...file(24, 100, { Irp: '0xD1', Status: '0x0' }),
  ]);
  const r = find(d, (e) => e.kind === 'rename');
  assert.strictEqual(r.length, 1, 'exactly one paired rename record');
  assert.strictEqual(r[0].f, 'C:\\proj\\new.node', 'the DESTINATION is the primary path — it needs the grant');
  assert.strictEqual(r[0].g, 'C:\\proj\\old.tmp', 'and the source rides along rather than being a second record');
});

test('a relative rename destination is anchored to the SOURCE directory, or left alone', async () => {
  // A bare leaf arrives when the caller set RootDirectory on the rename information. It can only
  // mean the source's directory; with no source there is nothing to anchor it to and inventing a
  // parent would be a fabricated path.
  const anchored = await decode([
    ...file(12, 100, { Irp: '0xE0', FileObject: '0xFB', FileName: `${VOL}\\proj\\sub\\a.tmp`, CreateOptions: '0x01000000' }),
    ...file(24, 100, { Irp: '0xE0', Status: '0x0' }),
    ...file(27, 100, { Irp: '0xE1', FileObject: '0xFB', FilePath: 'b.node' }),
    ...file(24, 100, { Irp: '0xE1', Status: '0x0' }),
  ]);
  assert.ok(find(anchored, (e) => e.f === 'C:\\proj\\sub\\b.node').length === 1,
    'a leaf destination resolves against the source directory');

  const orphan = await decode(file(27, 100, { FilePath: 'nowhere.node' }));
  assert.strictEqual(orphan.events.length, 0, 'a leaf with no source is dropped rather than invented');
  assert.strictEqual(orphan.stats.destUnresolved, 1, 'and the drop is counted');
});

test('a destination path comes from FilePath, which OUTRANKS FileName on events 26/27/28', async () => {
  // ⛔ MEASURED TWICE, BY TWO AGENTS ON TWO HARNESSES, ON REAL `windows-latest` RUNS. Every other
  // Kernel-File event names its path field `FileName`; 26/27/28 name theirs `FilePath`. A decoder
  // that ends in `?? data.FileName` therefore reads the WRONG path — or undefined — on exactly the
  // three events that carry a destination, even when the mask is delivering them correctly. This
  // fixture puts both fields on one event with different values so the precedence is pinned rather
  // than incidentally satisfied by a fixture that only ever sets one.
  const d = await decode([
    ...file(12, 100, { Irp: '0x70', FileObject: '0xAA', FileName: `${VOL}\\proj\\src.tmp`, CreateOptions: '0x01000000' }),
    ...file(24, 100, { Irp: '0x70', Status: '0x0' }),
    ...file(28, 100, { Irp: '0x71', FileObject: '0xAA',
      FilePath: `${VOL}\\proj\\the-real-destination`, FileName: `${VOL}\\proj\\a-decoy` }),
    ...file(24, 100, { Irp: '0x71', Status: '0x0' }),
  ]);
  const link = find(d, (e) => e.kind === 'hardlink');
  assert.strictEqual(link.length, 1, 'the hardlink is paired');
  assert.strictEqual(link[0].f, 'C:\\proj\\the-real-destination', 'FilePath wins');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\a-decoy').length, 0, 'FileName must not win');
  // ⛔ AND THE HARDLINK CASE IS THE ONE THAT IS UNRECOVERABLE IF LOST. NTFS emits no NameCreate for
  // a second name on an existing FileKey, so event 28 at keyword 0x800 is the SOLE carrier of this
  // path — unlike a rename destination, which also shows up as its own NameCreate. A narrow-mask
  // archive is permanently missing it; no re-parse can bring it back.
  assert.strictEqual(link[0].g, 'C:\\proj\\src.tmp', 'and the link target rides along');
});

test('the create DISPOSITION survives as a number, not as a read/write boolean', async () => {
  // windows.mjs collapses the disposition to op read-or-write, which is what a grant needs. The
  // number is what the kernel said, and OPEN_IF vs OVERWRITE_IF vs SUPERSEDE are different facts a
  // later model may want to separate.
  const d = await decode([
    ...createThenEnd(100, '0xF1', `${VOL}\\proj\\r`, '0x0', '0x01000000'),   // FILE_OPEN
    ...createThenEnd(100, '0xF2', `${VOL}\\proj\\w`, '0x0', '0x05000000'),   // FILE_OVERWRITE_IF
  ]);
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\r')[0].d, 1);
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\r')[0].o, 'open-r');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\w')[0].d, 5);
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\w')[0].o, 'open-w');
  // ShareAccess and CreateOptions have no POSIX spelling and are kept verbatim.
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\w')[0].co, '0x05000000');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\w')[0].sa, '0x3');
});

test('repeated identical operations collapse to a count and SUM their byte counts', async () => {
  // Per-operation I/O size is the field no other lane has — `-e trace=file` never subscribes to
  // `write` at all, so the Linux archive infers writes from an open's flags. Dedup keeps the
  // derived view smaller than the raw it summarizes; summing `io` is what stops the collapse from
  // throwing away the one number the collapse would otherwise destroy.
  const lines = [];
  for (const [i, size] of [4096, 8192, 1024].entries()) {
    lines.push(...file(12, 100, { Irp: `0x1${i}`, FileObject: '0xFC', FileName: `${VOL}\\proj\\big.bin`, CreateOptions: '0x01000000' }));
    lines.push(...file(24, 100, { Irp: `0x1${i}`, Status: '0x0' }));
    lines.push(...file(16, 100, { Irp: `0x2${i}`, FileObject: '0xFC', IOSize: String(size) }));
    lines.push(...file(24, 100, { Irp: `0x2${i}`, Status: '0x0' }));
  }
  const d = await decode(lines);
  const w = find(d, (e) => e.o === 'write' && e.f === 'C:\\proj\\big.bin');
  assert.strictEqual(w.length, 1, 'three identical writes are one line');
  assert.strictEqual(w[0].n, 3, 'with a repeat count');
  assert.strictEqual(w[0].io, 13312, 'and the byte counts summed (4096 + 8192 + 1024)');
});

test('events outside the traced subtree stay out of the DERIVED view and are counted', async () => {
  // A system-wide ETW session sees the whole box. The subtree filter is what makes the derived view
  // about this package — but it is a RULE, and a rule can change, so the count is published and the
  // events themselves remain in the raw archive.
  const d = await decode([
    ...createThenEnd(4, '0xA9', `${VOL}\\Windows\\System32\\somebody-elses.dll`, '0x0'),
    ...createThenEnd(100, '0xAA', `${VOL}\\proj\\ours`, '0x0'),
  ]);
  assert.strictEqual(find(d, (e) => e.f.includes('somebody-elses')).length, 0);
  assert.strictEqual(d.stats.outOfSubtree, 1, 'the filtered event is counted, not silently gone');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\ours').length, 1);
});

test('a grandchild process is followed, and its whole ProcessStart payload is kept', async () => {
  // ParentProcessID on ProcessStart is the only way to follow grandchildren. Keeping the FULL
  // payload settles by evidence at re-parse time which fields this Windows build actually published
  // — windows.mjs reads ImageName and discards the rest, including anything a later question needs.
  const d = await decode([
    ...ev('Microsoft-Windows-Kernel-Process', 1, 4, 8,
      { ProcessID: '200', ParentProcessID: '100', ImageName: `${VOL}\\nodejs\\node.exe`, MandatoryLabel: 'S-1-16-8192' }),
    ...ev('Microsoft-Windows-Kernel-Process', 1, 4, 8,
      { ProcessID: '300', ParentProcessID: '200', ImageName: `${VOL}\\Windows\\System32\\cmd.exe` }),
    ...createThenEnd(300, '0xB9', `${VOL}\\proj\\by-grandchild`, '0x0'),
  ]);
  assert.strictEqual(d.procs.length, 2, 'child and grandchild both recorded');
  assert.strictEqual(d.procs[0].data.MandatoryLabel, 'S-1-16-8192', 'the whole payload is kept verbatim');
  assert.strictEqual(find(d, (e) => e.f === 'C:\\proj\\by-grandchild').length, 1,
    "a grandchild's writes are attributed into the subtree");
});

test('deferred I/O is billed to the requesting process, not to System', async () => {
  // The header PID is System for work the filesystem completes on a worker thread; IssuingThreadId
  // still names the requester, and every event header is a free (tid -> pid) fact.
  const d = await decode([
    ...file(12, 100, { Irp: '0xC9', FileObject: '0xFD', FileName: `${VOL}\\proj\\deferred`, CreateOptions: '0x01000000' }, 777),
    ...file(24, 100, { Irp: '0xC9', Status: '0x0' }, 777),
    ...file(16, 4, { Irp: '0xCA', FileObject: '0xFD', IOSize: '512', IssuingThreadId: '777' }, 5),
    ...file(24, 4, { Irp: '0xCA', Status: '0x0' }, 5),
  ]);
  const w = find(d, (e) => e.o === 'write' && e.f === 'C:\\proj\\deferred');
  assert.strictEqual(w.length, 1);
  assert.strictEqual(w[0].p, 100, 'the write belongs to the process that asked for it');
  assert.strictEqual(d.stats.reattributedByThread, 1);
});

test('an NT device path with no devmap entry is passed through, never given a drive letter', async () => {
  // A named pipe or a UNC share is a real touch. Inventing a mapping for it would be a fabricated
  // fact; the classifier's "maps to no scope" rule is the right place to decide about it.
  const dos = makeDosPath({ [VOL]: 'C:' });
  assert.strictEqual(dos(`${VOL}\\x`), 'C:\\x');
  assert.strictEqual(dos('\\??\\C:\\x'), 'C:\\x', 'the DosDevices prefix is the same namespace');
  assert.strictEqual(dos('\\Device\\NamedPipe\\foo'), '\\Device\\NamedPipe\\foo');
  assert.strictEqual(dos('\\Device\\Mup\\server\\share'), '\\Device\\Mup\\server\\share');
});

test('read-only operations the grant model ignores are still archived', async () => {
  // A directory enumeration and a metadata query are things the package DID. They cannot affect a
  // write grant, which is why the synthesis decoder has no use for the first and drops it; an
  // archive that only kept what today's model consumes is the exact failure this design refuses.
  const d = await decode([
    ...file(12, 100, { Irp: '0xE9', FileObject: '0xFE', FileName: `${VOL}\\proj\\node_modules`, CreateOptions: '0x01000000' }),
    ...file(24, 100, { Irp: '0xE9', Status: '0x0' }),
    ...file(20, 100, { Irp: '0xEA', FileObject: '0xFE' }),
    ...file(24, 100, { Irp: '0xEA', Status: '0x0' }),
  ]);
  assert.strictEqual(find(d, (e) => e.o === 'direnum').length, 1, 'a directory enumeration is retained');
});

test('the archive carries no scope tag — roots live in the header, not on the events', async () => {
  // ⛔ THE RULE THE WHOLE DESIGN RESTS ON. A log carrying `scope:"outside"` forces a RE-MEASURE to
  // adopt a scope that did not exist when the corpus was measured; a log carrying the raw path and
  // the roots makes the same change a RE-PARSE. This asserts the tempting field is absent.
  const d = await decode(createThenEnd(100, '0xFA', `${VOL}\\proj\\anything`, '0x0'));
  for (const e of d.events) {
    assert.ok(!('scope' in e), 'no event may carry a classifier verdict');
    assert.ok(!('bucket' in e), 'nor any other name for one');
  }
});
