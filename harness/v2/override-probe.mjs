// The ONE predicate that decides whether a nub binary honours `NUB_BUILD_JAIL_CATALOG`, shared so
// the three drivers cannot drift apart. Same shape as `ci-env-scrub.sh` and `artifact-gate.mjs`:
// one definition, three consumers, a test that asserts they agree.
//
// ⛔⛔ WHY THIS EXISTS: A PROBE THAT INFERS A CAPABILITY FROM THE ABSENCE OF AN ERROR REPORTS
// "PRESENT" FOR ANYTHING THAT HAS NEVER HEARD OF THE QUESTION. Every driver used to read
// `rc == 0` from `NUB_BUILD_JAIL_CATALOG=<doc> nub --version`. There are THREE binary classes and
// exit code collapses the two that matter — MEASURED 2026-08-06 on eleven real binaries,
// darwin/arm64:
//
//   worktrees/integ/target/fast/nub   feature ON      rc=0  "warning: build-jail catalog OVERRIDDEN from …"
//   worktrees/integ/target/debug/nub  AWARE, off      rc=1  "…not built with the `build-jail-catalog-override` feature…"
//   9x shared-target-*/{fast,debug}   feature ABSENT  rc=0  byte-identical to running with NO variable set
//
// Class 1 and class 3 are indistinguishable by exit code, so `rc == 0` passed all nine class-3
// binaries — every nub on that host. On the Linux driver that made a FATAL preflight unable to fire
// in the direction it exists for; on macOS and Windows it wrote a false `buildJailCatalogOverride:
// true` into a record's provenance.
//
// A content search for the feature name is EXACTLY INVERTED and is not the fix: Rust does not embed
// feature names, and the literal `build-jail-catalog-override` lives only in the refusal a
// FEATURELESS build prints. The drivers' own comments carry that measurement.
//
// MECHANISM, from `crates/nub-sandbox/src/catalog_override.rs` on `sandbox/integration`:
// `decide()` returns `Err` — which `main.rs` turns into a rc=1 abort — whenever the variable is set
// and `cfg!(feature = "build-jail-catalog-override")` is false. `load()` is therefore unreachable
// without the feature, so NEITHER banner below can be produced by a class-2 or class-3 binary.
// That is what makes a banner positive evidence rather than a correlate.

/// The binary parsed the catalog and replaced the compiled-in one.
export const OVERRIDDEN_MARKER = 'build-jail catalog OVERRIDDEN from';

/// The binary read the variable, tried to load the catalog, and fell back to the compiled-in one.
///
/// ⛔ THIS COUNTS AS PROOF, AND THAT IS DELIBERATE. `fs::read_to_string` fails before any schema
/// parsing, so `FellBack` establishes the feature is COMPILED IN independently of whether the probe
/// document still matches the catalog grammar. Requiring OVERRIDDEN alone would couple a FATAL gate
/// to the v2 schema, and a grammar change would then block every measurement — the one failure here
/// that is worse than the defect this predicate fixes. VERIFIED by feeding the feature-on binary
/// three documents its parser refuses (malformed JSON, valid JSON of the wrong shape, and a
/// nonexistent path): all three still resolved to honoured, and none of them rescued a class-2 or
/// class-3 binary.
export const REJECTED_MARKER_RE = /build-jail catalog override at .* was REJECTED/;

/// The feature name, which appears in a class-2 refusal and nowhere else in a probe's output.
export const FEATURE_NAME = 'build-jail-catalog-override';

/// `true` only when `output` carries positive evidence the binary acted on the variable.
/// `output` is the probe run's stdout and stderr concatenated — the banner goes to stderr, the
/// version to stdout, and no caller should have to know which.
export function overrideProbeSaysHonoured(output) {
  const s = String(output ?? '');
  return s.includes(OVERRIDDEN_MARKER) || REJECTED_MARKER_RE.test(s);
}

/// Which of the three classes the probe saw. `honoured` is the only one that may measure.
/// The two refusals are kept apart because they call for different actions: `disabled` is a rebuild
/// of the same tree with one flag, `absent` means the checkout predates the seam entirely and no
/// flag will produce it.
export function overrideProbeClass(output, status) {
  const s = String(output ?? '');
  if (overrideProbeSaysHonoured(s)) return 'honoured';
  if (status !== 0 && s.includes(FEATURE_NAME)) return 'disabled';
  return 'absent';
}
