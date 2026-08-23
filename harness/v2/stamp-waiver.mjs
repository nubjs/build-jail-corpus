// When falsify may accept the artifact gate ALONE as evidence the jail enforced a grant.
//
// ⛔ THIS FILE WEAKENS A CONTROL, SO IT IS DELIBERATELY NARROW AND SEPARATELY TESTED. falsify's
// win32 network case asserts a refusal TEXT — `WARN_NUB_JAIL_NET_DENIED` / `blocked network access`.
// That line is emitted by nub's net-gate shim (`crates/nub-sandbox/src/backend/net_gate_shim.js`),
// which reaches a confined Node only as a `NODE_OPTIONS --import` term. `build_jail.rs` stamps that
// term ONLY when the interpreter supports `--import`:
//
//     fn supports_import(version: &str) -> bool { major > 20 || (major == 20 && minor >= 6) }
//
// and REMOVES `NODE_OPTIONS` outright otherwise — deliberately, because an unrecognised option there
// aborts Node at startup, which would turn a missing repair into a broken install.
//
// So an arm pinned to an older era Node HAS NO SHIM, and the OS layer denies the download silently.
// MEASURED: `mozjpeg@6.0.1` pins to era Node 10.24.1. falsify's win32 case went red on `refusal=—`
// the same day era-Node provisioning landed in that lane, against a jail that was enforcing
// correctly the whole time — which the artifact gate reported all along (`artifacts=7/8 missing=1`).
//
// The waiver never relaxes `mustDetect`, so the artifact gate stays a hard assertion. It only stops
// the case demanding evidence in a vocabulary the arm cannot speak.

/// The Node an arm ACTUALLY ran on, read from the driver's own `ERA-NODE PINNED` marker.
///
/// ⛔ READ, NEVER RECOMPUTED. Deriving the era from the package's publish date would answer the
/// adjacent question — what we WOULD pin — and the two come apart exactly when the pin fails to
/// engage, which is the case most worth catching. `null` when the marker is absent, and every
/// consumer treats `null` as strict.
export function eraNodeFromDriverOut(out) {
  const m = /ERA-NODE PINNED\s+v?(\d+)\.(\d+)/.exec(String(out ?? ''));
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  return Number.isFinite(major) && Number.isFinite(minor) ? { major, minor } : null;
}

/// Whether nub would stamp its `--import` shims into an arm running this Node. Mirrors
/// `supports_import` in `crates/nub-cli/src/pm_engine/build_jail.rs` exactly.
export function supportsImport(eraNode) {
  if (!eraNode) return false;
  const { major, minor } = eraNode;
  return major > 20 || (major === 20 && minor >= 6);
}

/// Whether a missing refusal TEXT is excusable for this case on this arm.
///
/// Three conjuncts, and dropping any one of them turns a scoped waiver into a hole:
///   * the case OPTED IN (`refusalNeedsImportStamp`) — no other case is affected;
///   * the era is KNOWN — an unreadable marker must fail loud, never open;
///   * that era cannot carry the stamp — a modern arm is still held to the text.
export function refusalTextWaived(kase, eraNode) {
  if (!kase?.refusalNeedsImportStamp) return false;
  if (!eraNode) return false;
  return !supportsImport(eraNode);
}
