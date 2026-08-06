// Both-directions validation of the Windows adapter against a fixture whose behaviour is known
// exactly. The fixture is C:\obs\fx, built by fixture/setup-fixture.ps1 + child.mjs + grandchild.ps1.
//
// A probe that cannot report a false negative is not validated, so this asserts in both directions:
// every deliberate action must be PRESENT, every decoy must be ABSENT, and inside the namespace the
// fixture fully controls the emitted set must be EXACTLY the expected one -- no more, no less.
//
// --selftest goes one further. For each positive assertion it deletes the events that assertion
// matches and re-runs it, requiring it to FAIL. An assertion that stays green with its evidence
// removed is measuring nothing, and would have hidden the empty-stream bug that the first version
// of the parser actually had.
//
//   usage: node validate-windows.mjs <events.ndjson> <capture-dir> [--selftest]
import fs from 'node:fs';

const [evPath, capDir] = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const selftest = process.argv.includes('--selftest');
if (!evPath || !capDir) { console.error('usage: validate-windows.mjs <events.ndjson> <capture-dir> [--selftest]'); process.exit(2); }

const meta = JSON.parse(fs.readFileSync(`${capDir}/meta.json`, 'utf8'));
const all = fs.readFileSync(evPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));

const FX = 'C:\\obs\\fx';
const HOME_WRITE = `${meta.userProfile}\\fx-userprofile-write.txt`;

// Roles, not PIDs. PIDs change every run; the SHAPE of the tree is the invariant, and expressing
// the expectation in roles is also what makes "the grandchild did this" checkable.
const execs = all.filter((e) => e.op === 'exec');
const roleOf = new Map([[meta.rootPid, 'root']]);
const child = execs.find((e) => e.ppid === meta.rootPid && e.pid !== meta.rootPid);
if (child) roleOf.set(child.pid, 'child');
const grand = child && execs.find((e) => e.ppid === child.pid);
if (grand) roleOf.set(grand.pid, 'grandchild');
const role = (pid) => roleOf.get(pid) ?? `pid:${pid}`;

const has = (evs, pred) => evs.some(pred);
const mentions = (evs, s) => evs.filter((e) => (e.path ?? '').includes(s));

// ---------------------------------------------------------------------------------------------
// The assertions. Each is a pure predicate over the event list so --selftest can re-run it against
// a mutated list.
// ---------------------------------------------------------------------------------------------
const EXPECTED_FX_SET = [
  // Incidental but fully explained: each process opens its working directory, and node and
  // powershell each open the one script they were told to run.
  'read|C:\\obs\\fx|ok|root',
  'read|C:\\obs\\fx\\|ok|root',
  'read|C:\\obs\\fx|ok|child',
  'read|C:\\obs\\fx\\|ok|child',
  'read|C:\\obs\\fx\\child.mjs|ok|child',
  'read|C:\\obs\\fx|ok|grandchild',
  'read|C:\\obs\\fx\\|ok|grandchild',
  'read|C:\\obs\\fx\\grandchild.ps1|ok|grandchild',
  // The deliberate three that live inside the fixture namespace.
  'write|C:\\obs\\fx\\proj\\wrote-in-project.txt|ok|child',
  'read|C:\\obs\\fx\\proj\\read-only-input.txt|ok|child',
  'write|C:\\obs\\fx\\denied\\blocked.txt|denied|child',
];

const CHECKS = [
  { id: 'P1', dir: '+', what: 'project write is reported',
    match: (e) => e.op === 'write' && e.path === `${FX}\\proj\\wrote-in-project.txt` && e.result === 'ok',
    ok: (evs) => has(evs, (e) => e.op === 'write' && e.path === `${FX}\\proj\\wrote-in-project.txt` && e.result === 'ok' && role(e.pid) === 'child') },

  { id: 'P2', dir: '+', what: 'userprofile write is reported, attributed to the GRANDCHILD',
    match: (e) => e.op === 'write' && e.path === HOME_WRITE,
    ok: (evs) => has(evs, (e) => e.op === 'write' && e.path === HOME_WRITE && e.result === 'ok' && role(e.pid) === 'grandchild') },

  { id: 'P3', dir: '+', what: 'the read-only input is reported as a READ',
    match: (e) => e.op === 'read' && e.path === `${FX}\\proj\\read-only-input.txt`,
    ok: (evs) => has(evs, (e) => e.op === 'read' && e.path === `${FX}\\proj\\read-only-input.txt` && e.result === 'ok' && role(e.pid) === 'child') },

  { id: 'P4', dir: '+', what: 'the pinned TCP connect is reported, attributed to the GRANDCHILD',
    match: (e) => e.op === 'connect' && e.host === '1.1.1.1',
    ok: (evs) => has(evs, (e) => e.op === 'connect' && e.host === '1.1.1.1' && e.port === 443 && e.result === 'ok' && role(e.pid) === 'grandchild') },

  { id: 'P5', dir: '+', what: 'the ACL-denied write is reported as DENIED',
    match: (e) => e.path === `${FX}\\denied\\blocked.txt`,
    ok: (evs) => has(evs, (e) => e.op === 'write' && e.path === `${FX}\\denied\\blocked.txt` && e.result === 'denied') },

  { id: 'P6', dir: '+', what: 'the exec chain is three levels deep (cmd -> node -> powershell)',
    match: (e) => e.op === 'exec',
    ok: (evs) => {
      const x = evs.filter((e) => e.op === 'exec');
      const c = x.find((e) => e.ppid === meta.rootPid && e.pid !== meta.rootPid);
      return !!(c && x.find((e) => e.ppid === c.pid));
    } },

  { id: 'P7', dir: '+', what: 'the PowerShell Invoke-WebRequest peer is reported (the dprint shape)',
    match: (e) => e.op === 'connect' && e.host !== '1.1.1.1',
    ok: (evs) => has(evs, (e) => e.op === 'connect' && e.host !== '1.1.1.1' && e.port === 443 && role(e.pid) === 'grandchild') },

  { id: 'N1', dir: '-', what: 'the never-touched decoy appears nowhere',
    ok: (evs) => mentions(evs, 'never-touched.txt').length === 0 },

  { id: 'N2', dir: '-', what: 'the missing-file probe is NOT reported (failed != refused)',
    ok: (evs) => mentions(evs, 'does-not-exist.txt').length === 0 },

  { id: 'N3', dir: '-', what: 'the read-only input is never reported as a WRITE',
    ok: (evs) => !has(evs, (e) => e.op === 'write' && e.path === `${FX}\\proj\\read-only-input.txt`) },

  { id: 'N4', dir: '-', what: 'no connect to a peer the fixture never contacted',
    ok: (evs) => !has(evs, (e) => e.op === 'connect' && e.host === '9.9.9.9') },

  { id: 'N5', dir: '-', what: 'the ACL-denied write is the ONLY refusal',
    ok: (evs) => {
      const d = evs.filter((e) => e.result === 'denied');
      return d.length === 1 && d[0].path === `${FX}\\denied\\blocked.txt`;
    } },

  { id: 'E1', dir: '=', what: 'inside the fixture namespace the emitted set is EXACTLY the expected one',
    ok: (evs) => {
      const got = new Set(evs.filter((e) => (e.path ?? '').startsWith(FX)).map((e) => `${e.op}|${e.path}|${e.result}|${role(e.pid)}`));
      const want = new Set(EXPECTED_FX_SET);
      const missing = [...want].filter((k) => !got.has(k));
      const extra = [...got].filter((k) => !want.has(k));
      E1_missing = missing; E1_extra = extra;
      return missing.length === 0 && extra.length === 0;
    } },
];
let E1_missing = [], E1_extra = [];

// ---------------------------------------------------------------------------------------------
let failed = 0;
console.log(`capture: user ${meta.whoami}  elevated ${meta.elevated}  exit ${meta.exitCode}  ` +
  `events ${meta.eventsTotal}  lost ${meta.eventsLost}`);
console.log(`tree:    root ${meta.rootPid} -> child ${child?.pid ?? '?'} -> grandchild ${grand?.pid ?? '?'}`);
console.log(`stream:  ${all.length} normalized events\n`);

for (const c of CHECKS) {
  const pass = c.ok(all);
  if (!pass) failed++;
  console.log(`  [${pass ? 'PASS' : 'FAIL'}] ${c.dir} ${c.id}  ${c.what}`);
  if (!pass && c.id === 'E1') {
    E1_missing.forEach((k) => console.log(`             missing: ${k}`));
    E1_extra.forEach((k) => console.log(`             extra:   ${k}`));
  }
}

if (selftest) {
  console.log('\nself-test: each positive assertion must FAIL once its evidence is deleted');
  for (const c of CHECKS.filter((c) => c.match)) {
    const mutated = all.filter((e) => !c.match(e));
    const stillPasses = c.ok(mutated);
    if (stillPasses) failed++;
    console.log(`  [${stillPasses ? 'FAIL' : 'PASS'}] ${c.id} went red with ${all.length - mutated.length} event(s) removed`);
  }
}

console.log(`\n${failed === 0 ? 'VALIDATION PASSED' : `VALIDATION FAILED (${failed})`}`);
process.exit(failed === 0 ? 0 : 1);
