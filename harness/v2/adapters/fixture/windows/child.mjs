// Level 2 of the process tree: cmd.exe -> node.exe (this) -> powershell.exe (grandchild).
// Everything here is deliberate; the validator asserts this exact set and nothing more
// inside C:\obs\fx.
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

// (1) WRITE inside the project.
fs.writeFileSync('C:\\obs\\fx\\proj\\wrote-in-project.txt', 'project write\n');

// (2) READ a file it never writes.
const got = fs.readFileSync('C:\\obs\\fx\\proj\\read-only-input.txt', 'utf8');
if (got.trim() !== 'input') throw new Error('fixture read came back wrong: ' + JSON.stringify(got));

// (3) NEAR-MISS for the refusal predicate: a failing open that is NOT a refusal.
// STATUS_OBJECT_NAME_NOT_FOUND must never be reported as denied.
try { fs.readFileSync('C:\\obs\\fx\\proj\\does-not-exist.txt'); } catch { /* expected ENOENT */ }

// (4) A genuine REFUSAL: STATUS_ACCESS_DENIED against the ACL-denied directory.
let refused = false;
try { fs.writeFileSync('C:\\obs\\fx\\denied\\blocked.txt', 'nope'); } catch (e) { refused = e.code === 'EPERM' || e.code === 'EACCES'; }
if (!refused) throw new Error('fixture expected a refusal and did not get one');

// (5) The GRANDCHILD does the userprofile write and the TCP connect. An adapter that watches
// only the direct child sees neither.
const r = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\\obs\\fx\\grandchild.ps1'], { stdio: 'inherit' });
if (r.status !== 0) throw new Error('grandchild failed: ' + r.status);
console.log('CHILD-OK');
