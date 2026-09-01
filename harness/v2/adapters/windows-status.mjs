// The win32 outcome vocabulary: which NTSTATUS codes are a refusal, which single one the DACL check
// produces, and which events are a Create. ONE definition, shared by the decoder that emits `st`
// (`windows-retain.mjs`) and the scorer that reads it (`denial-witness.mjs`).
//
// ⛔⛔ WHY THIS IS A LEAF MODULE RATHER THAN THREE EXPORTS ON `windows-retain.mjs`. It was the latter
// first, and `three-driver-parity.test.mjs` caught it immediately and correctly: `denial-witness.mjs`
// is reached by `measure.sh` and `measure-macos.sh`, so importing the retain adapter for a constant
// dragged `windows-retain.mjs`, `windows-shortnames.mjs` and `windows.ps1` into BOTH POSIX drivers'
// module closure. Their platform exemptions went stale in the same instant — "which all three drivers
// now have — delete the entry" — which is that test doing exactly its job. A shared constant must not
// make a Linux driver depend on an ETW decoder.
//
// So this file imports NOTHING. Same construction and same reason as `tool-cache-leaves.mjs`, whose
// own header records it: a leaf "imports nothing at all, so it cannot re-open the cycle, and sharing
// the leaf list is the only way this file and the two classifiers cannot come to disagree".
//
// ⛔ A SECOND COPY IS THE FAILURE THIS PREVENTS, AND IT HAS HAPPENED HERE BEFORE. `denial-witness.mjs`
// records it: `measure.sh` emitted `network` where `record.mjs` matched `no-network`, both sides had
// passing tests, and the recomputation silently deleted nothing while the record still claimed it had
// narrowed. A duplicated vocabulary drifts, and both copies look right on their own.

// ⛔⛔ ACCESS_DENIED IS BROKEN OUT SEPARATELY, AND THAT SPLIT IS A SAFETY ARGUMENT RATHER THAN TIDINESS.
// It is the ONLY one of the four an AppContainer DACL refusal produces: a LowBox token reaches an
// object only where that object's ACL names its package SID, and the check that fails is
// `SeAccessCheck`. `denial-witness.mjs`'s win32 positive control keys on this code alone.
//
// The other three come from elsewhere, and one of them is HARNESS NOISE that would have validated a
// broken instrument. MEASURED over all 1,688 committed win32 streams: 19 carry a refused `Create`,
// and every one of those 40 events is `0xc0000061` STATUS_PRIVILEGE_NOT_HELD on
// `…\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\…` — Explorer's jump-list, refused
// because `windows.ps1` deliberately strips SeBackup/SeRestore/SeTakeOwnership. That is the PRIVILEGE
// check, not the DACL check. A control keying on "a refused Create" would have passed on those 19
// while proving nothing about whether a LowBox denial is visible at all. ZERO of the 1,688 carry
// `0xc0000022` on a Create, which is what makes it a real discriminant rather than a rubber stamp.
export const ACCESS_DENIED_NTSTATUS = 0xc0000022;

// ⛔ ONLY A GENUINE REFUSAL IS A REFUSAL, and the near-miss here is not a string that also matches
// something innocent — it is the temptation to call every non-zero NTSTATUS a denial. A probe for a
// file that is not there returns STATUS_OBJECT_NAME_NOT_FOUND, which means the operation did not
// happen rather than that it was forbidden. Only these four say "you were not allowed".
//
// The NUMBER is canonical because that is what the kernel gives and what `windows.mjs` tests against.
export const REFUSAL_NTSTATUS = new Set([
  ACCESS_DENIED_NTSTATUS, // STATUS_ACCESS_DENIED       — the DACL check, incl. every LowBox refusal
  0xc0000061,             // STATUS_PRIVILEGE_NOT_HELD  — the privilege check
  0xc00000a2,             // STATUS_MEDIA_WRITE_PROTECTED
  0xc0000121,             // STATUS_CANNOT_DELETE
]);

// The spelling `windows-retain.mjs` writes into `st`: lower-case, `0x`-prefixed, zero-padded to
// eight digits. Defined here so the emitter and the scorer cannot format the same status two ways —
// a scorer comparing `0xc0000022` against an emitter writing `0xC0000022` would match nothing and
// read CLEAN, which is the failure direction this whole axis is built to refuse.
export const statusHex = (n) => `0x${n.toString(16).padStart(8, '0')}`;

export const REFUSAL_ACCESS_DENIED = statusHex(ACCESS_DENIED_NTSTATUS);
// ⛔ DERIVED FROM THE NUMBERS, NEVER RETYPED. Two hand-written lists of the same four codes is the
// drift this file exists to prevent, and a typo in the hex form would be invisible: the scorer would
// simply stop matching one status and quietly answer CLEAN more often.
export const REFUSAL_STATUS = new Set([...REFUSAL_NTSTATUS].map(statusHex));

// The Create-family events, by the NAME the retain decoder writes into `s` (Kernel-File 12 and 30).
// Keyed on the name rather than the numeric id because the name is what survives into the derived
// stream a scorer reads.
export const CREATE_EVENTS = new Set(['Create', 'CreateNewFile']);
