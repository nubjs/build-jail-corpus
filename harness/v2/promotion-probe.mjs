// CAN A `writePaths` NARROWING REST ON EVIDENCE THAT COULD HAVE FAILED? — the paired arm that
// answers it, and the gate that scores it.
//
// ⛔⛔ THIS EXISTS BECAUSE A `writePaths` GRANT CARRIES NO CAPABILITY TOKEN, SO NO ARM COULD EVER
// HAVE GONE RED ON IT. `publish-guard.mjs`'s `capsOf` flattens a grant to `write.*` / `read.*` /
// `network` tokens; `{"writePaths":["Library/Preferences/clerk"]}` flattens to the EMPTY set, so
// `hasRedArm` is false by construction and every narrowing to such a grant lands on WITHHOLD.
// MEASURED on the committed corpus: `@clerk/shared@2.9.2` is exactly that record —
// `records-v2/runs/darwin-arm64/@clerk+shared/2.9.2/results.json` carries
// `grant: {"writePaths":["Library/Preferences/clerk"]}`, `minimality: "MINIMAL"` and
// `notes: ["arms-unfalsifiable", …]`, while the win32 and linux records for the same version still
// carry the whole-home `{"write":{"userHome":true}}` it would replace.
//
// The guard is not wrong there, it is BLIND: nothing in the run ever dropped `writePaths` and asked
// what happened. This module is the missing question, and it refuses to be answered cheaply.
//
// ── WHY EVERY EXISTING DETECTOR IS STRUCTURALLY BLIND TO IT ─────────────────────────────────────
//
// `writePaths` grants nothing. `crates/nub-sandbox/src/catalog_v2.rs` says so in its own words —
// "`write_paths` has ZERO consumers in the compiler — its only readers are in
// `persist_declared_home_writes` — so it cannot decide whether a write SUCCEEDS, only whether the
// result is KEPT … What is lost is persistence ACROSS INSTALLS." So dropping an entry denies no
// write: the script still writes into its private home, the install still exits 0, and what
// disappears is the artefact, one install later. Against that:
//
//   rc                the install cannot fail for a reason that only exists after it finished.
//   artifact gate     `artifact-gate.mjs` walks `<base>/node_modules/<pkg>` and nothing else — its
//                     own header calls the package's own directory "the ONE universe both layouts
//                     genuinely share". A home write is outside it by definition.
//   denial witness    `denial-witness.mjs` scores REFUSALS decoded from a jailed trace. A dropped
//                     `writePaths` produces no refusal at all, so the witness reads CLEAN on a run
//                     where the artefact was silently discarded.
//
// `observe.mjs` states the consequence and stops there: "a `no-writePaths` arm would report
// 'droppable' for every package on earth." That is true of an arm scored by the three detectors
// above, and it is why this module brings a fourth.
//
// ── THE DETECTOR: THE PROMOTION GATE ────────────────────────────────────────────────────────────
//
// `build_jail.rs::persist_declared_home_writes` runs after the lifecycle scripts and, for each
// declared entry, merges `<private jail home>/<rel>` into `<real home>/<rel>`. So the observable is
// not an exit code, it is a DIRECTORY IN THE REAL HOME, and the gate is simply: after the arm, is
// `<real home>/<rel>` there?
//
// ⛔ THE ARM IS A PAIR, AND A SINGLE ARM OF IT PROVES NOTHING.
//
//   CONTROL   the record's own grant, `writePaths` INCLUDED, run with a fresh real home.
//             Every declared entry must be PRESENT afterwards.
//   DROP      the same grant with `writePaths` removed, run with a DIFFERENT fresh real home.
//             Every declared entry must be ABSENT afterwards.
//
// CONTROL alone is a green that could not have failed. DROP alone is a red that could not have been
// green. The pair is the experiment: it says the entry's arrival in the real home is caused BY THE
// DECLARATION, in this venue, for this package — which is precisely the "a live detector
// demonstrably fired" that `publish-guard.mjs` asks for and could not previously get.
//
// ⛔⛔ AND THE PAIR IS FALSIFIABLE IN THE DIRECTION THAT MATTERS, WHICH IS THE CONTROL. A
// `writePaths` grant is a claim that the script's home writes FOLLOWED `$HOME` and therefore landed
// in the throwaway home, needing no live handle on the real one. `write-paths.mjs::refuseUserHome`
// names the opposite case: a write that reached the real home BY ABSOLUTE PATH is refused unless
// `write:{userHome}` is granted, and "promotion cannot help because there is nothing of its in the
// private home". If the derivation got that split wrong, the control arm — which grants no
// real-home write — finds the entry ABSENT, and this module reports UNPROVEN. So the control is not
// ceremony: it is the arm that catches the under-grant this whole narrowing risks.
//
// ── WHAT A GREEN DROP ARM MAY NEVER DO ──────────────────────────────────────────────────────────
//
// ⛔⛔ A PASSING DROP ARM DOES NOT LICENSE DROPPING `writePaths`, AND THIS MODULE WILL NOT LET IT.
// That is why `no-writePaths` is NOT a leave-one-out term in `descent-terms.mjs` and never reaches
// `overPredictedBy`: a term there is one whose green NARROWS the grant, and narrowing `writePaths`
// away on a green install arm is exactly the under-grant `observe.mjs` warns about — the package
// installs fine and loses its artefact at RUN time, which no arm in this harness can see. The only
// thing a green DROP arm does here is INVALIDATE the pair, so the record gets no promotion evidence
// and keeps whatever it had. Evidence in one direction only, by construction.
//
// ── THE ONE CASE THIS MODULE REFUSES TO PROBE AT ALL ────────────────────────────────────────────
//
// Same discipline as `descent-terms.mjs`'s win32 `no-network` refusal: an arm that could not have
// gone red is worse than no arm, so it is declined by name with the reason attached.
//
//   HOME-WRITE GRANTED  If the grant already carries `write:{userHome}` or `write:"disk"`, the
//                       control arm's PRESENT is unattributable — the script could have written the
//                       real home directly and promotion moved nothing. The pair would then be
//                       measuring the grant it was supposed to test.
//
// ⛔⛔ AND THE BASELINE DOES NOT CONTAMINATE THE DROP ARM, THOUGH `measure.sh` STILL SAYS IT WOULD.
// An UNCATALOGUED package promotes `baseline_caps().write_paths` — `.cache`, `.npm`, `.electron`,
// `AppData/Local`, `Library/Caches` — so if a drop arm reached the jail with the package ABSENT from
// the catalog, every entry under one of those prefixes would be promoted anyway and could never go
// red. That WAS the arrangement `verify()`'s own comment describes ("nub REJECTS a catalog entry that
// widens nothing … express the empty grant by OMITTING the package under test"), and that comment is
// stale on both halves. `dep-scaffold.mjs::buildCatalog` writes `packages[target] = {default: grant}`
// UNCONDITIONALLY, and `catalog_v2.rs` now says of the rejection: "AN ENTRY THAT GRANTS NOTHING IS THE
// TIGHTEST GRANT THERE IS, AND REJECTING IT WAS A DEFECT … a present-but-empty entry grants NO egress
// and NO write, while ABSENCE grants the baseline". So the drop arm always carries an explicit entry
// with an empty `write_paths`, `persist_declared_home_writes` returns before its loop, and nothing is
// promoted. A pre-emptive skip list keyed on the baseline would have been a hardcoded claim about a
// Rust constant no harness process links, standing in for a measurement the pair already makes: an
// entry that shows up in the DROP arm for any reason at all scores `UNPROVEN-DROP` and licenses
// nothing.
//
// ⛔ THE PLATFORM IS NOT GUESSED — THE CONTROL ARM IS THE PLATFORM TEST. Promotion ships on all
// three (`persist_declared_home_writes`: "WINDOWS PROMOTES THROUGH THIS SAME BODY … What was
// actually missing was a call site"), but the binary a given run measured may predate that call
// site. A hardcoded allow-list would be a claim about the binary; a control arm that comes back
// ABSENT is a measurement of it. So an unsupported platform reports UNPROVEN rather than a wrong
// PROVEN, and no list has to be kept in step with a release.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** The marker the drivers print, and the only thing `record.mjs` parses. */
export const PROMOTION_PROBE_MARKER = 'PROMOTION-PROBE';

/** Verdicts, in the order of decreasing evidentiary weight. */
export const VERDICT = {
  /** control PRESENT and drop ABSENT on every probed entry — the declaration caused the artefact. */
  PROVEN: 'PROVEN',
  /** the control arm did not produce an entry: the declaration moves nothing here. */
  UNPROVEN_CONTROL: 'UNPROVEN-CONTROL',
  /** the drop arm produced an entry anyway: that entry's arm could not have failed. */
  UNPROVEN_DROP: 'UNPROVEN-DROP',
  /** an arm did not run, or its home was unreadable. Nothing measured, nothing licensed. */
  VOID: 'VOID',
  /** the probe was declined before it ran; `reason` says which case. */
  UNSUPPORTED: 'UNSUPPORTED',
};

/** Why a probe was declined. Machine-readable; the driver prints the prose beside it. */
export const SKIP_REASONS = {
  'no-declaration': 'the grant declares no `writePaths`, so there is nothing to promote',
  'home-write-granted':
    'the grant already carries a live write on the real home (`write:{userHome}` or `write:"disk"`), '
    + 'so an entry appearing in the real home could have been written directly and the control arm '
    + 'would not attribute it to the promotion',
};

const posix = (p) => String(p).replace(/\\/g, '/').replace(/\/+$/, '');

/**
 * Does this grant hand the script a live handle on the REAL home?
 *
 * `write` is either a map of scopes or the string reach `"disk"` — the same two shapes
 * `descent-terms.mjs` enumerates, and the string form is the one a `typeof === 'object'` test drops
 * on the floor.
 */
export const grantsRealHomeWrite = (grant) => {
  const w = grant?.write;
  if (w === 'disk') return true;
  return !!(w && typeof w === 'object' && w.userHome === true);
};

/**
 * Should the probe run, and on which entries?
 *
 * Returns `{ supported, entries, skipped }`. EVERY declared entry is probed — see the header for why
 * a baseline-derived skip list would be a hardcoded claim standing in for the measurement the pair
 * already makes. `skipped` therefore carries the declared list only in the one declined case, so a
 * reader of `driver.out` can see WHICH entries went unexamined and why.
 */
export function probePlan(grant) {
  const declared = Array.isArray(grant?.writePaths) ? grant.writePaths.filter(Boolean) : [];
  if (!declared.length) {
    return { supported: false, reason: 'no-declaration', entries: [], skipped: [] };
  }
  if (grantsRealHomeWrite(grant)) {
    return { supported: false, reason: 'home-write-granted', entries: [], skipped: declared };
  }
  return { supported: true, reason: null, entries: declared, skipped: [] };
}

/**
 * Score one probed pair.
 *
 * `observed` is `{ control: {<entry>: boolean}, drop: {<entry>: boolean} }` — whether the entry was
 * found in that arm's own real home. A missing entry in either map is VOID, never a `false`: an arm
 * that did not report is not an arm that reported absence, and collapsing the two is how a probe
 * that never ran would read as a red drop arm.
 */
export function scoreProbe(plan, observed) {
  if (!plan?.supported) {
    return { verdict: VERDICT.UNSUPPORTED, reason: plan?.reason ?? 'no-declaration', entries: [] };
  }
  const rows = [];
  for (const e of plan.entries) {
    const c = observed?.control?.[e];
    const d = observed?.drop?.[e];
    if (typeof c !== 'boolean' || typeof d !== 'boolean') {
      return {
        verdict: VERDICT.VOID,
        reason: `no observation for '${e}' on ${typeof c !== 'boolean' ? 'the control' : 'the drop'} arm`,
        entries: rows,
      };
    }
    rows.push({ entry: e, control: c, drop: d });
  }
  const controlMiss = rows.filter((r) => !r.control);
  if (controlMiss.length) {
    return {
      verdict: VERDICT.UNPROVEN_CONTROL,
      reason: `the control arm — which grants no write on the real home — did not produce `
        + `${controlMiss.map((r) => `'${r.entry}'`).join(', ')}, so the declaration moves nothing here `
        + 'and the narrowing has no evidence behind it',
      entries: rows,
    };
  }
  const dropHit = rows.filter((r) => r.drop);
  if (dropHit.length) {
    return {
      verdict: VERDICT.UNPROVEN_DROP,
      reason: `the drop arm produced ${dropHit.map((r) => `'${r.entry}'`).join(', ')} anyway, so that `
        + 'arm could not have failed and the pair measures nothing',
      entries: rows,
    };
  }
  return {
    verdict: VERDICT.PROVEN,
    reason: `every declared entry (${rows.map((r) => r.entry).join(', ')}) reached the real home under `
      + 'the grant and did NOT under the same grant with `writePaths` removed — the promotion gate '
      + 'fired, so the drop arm went red on a live detector',
    entries: rows,
  };
}

/**
 * The capability tokens a scored probe licenses a record to DROP.
 *
 * ⛔⛔ EXACTLY ONE TOKEN, AND THE SCOPE IS THE WHOLE ARGUMENT. A PROVEN pair shows the script's home
 * artefact reached the real home THROUGH THE PROMOTION, under a grant carrying no real-home write.
 * That is direct evidence the writes followed `$HOME` and needed no live handle — i.e. that
 * `write.userHome` is unnecessary. It says nothing whatever about `network`, about `read`, or about
 * `write.deps`/`write.project`, so those tokens are not in the set and a narrowing that drops one of
 * them gets no licence from here. `publish-guard.mjs` requires EVERY dropped token to be licensed,
 * which is `record.mjs`'s own `every`-over-dropped-capabilities rule, deliberately.
 */
export const licensedCaps = (scored) => (
  scored?.verdict === VERDICT.PROVEN ? new Set(['write.userHome']) : new Set()
);

/** The marker line a driver prints, and the shape `record.mjs` parses back. */
export const markerLine = (platform, grant, plan, scored) => `  ${PROMOTION_PROBE_MARKER} ${JSON.stringify({
  platform,
  verdict: scored.verdict,
  reason: scored.reason,
  entries: scored.entries,
  skipped: plan.skipped ?? [],
})}`;

/**
 * Ready-to-print prose for a driver, marker included.
 *
 * ⛔ AN UNSUPPORTED PROBE PRINTS TOO. A silent skip is indistinguishable from a driver that does not
 * run this probe at all, which is the state every `writePaths` record was already in — and the whole
 * complaint against that state was that an analysis looking for disproving evidence could not tell
 * "none exists" from "none was sought".
 */
export function verdictLines(platform, grant, plan, scored) {
  if (!plan.supported) {
    return [
      `  => PROMOTION PROBE UNSUPPORTED — ${SKIP_REASONS[plan.reason] ?? plan.reason}`,
      markerLine(platform, grant, plan, scored),
    ];
  }
  const head = scored.verdict === VERDICT.PROVEN
    ? `  => PROMOTION PROVEN — ${scored.reason}`
    : `  => PROMOTION ${scored.verdict} — ${scored.reason}`;
  return [
    head,
    ...scored.entries.map((r) => `     ${r.entry}: control=${r.control ? 'PRESENT' : 'ABSENT'} `
      + `drop=${r.drop ? 'PRESENT' : 'ABSENT'}`),
    ...(plan.skipped.length
      ? [`     not probed (baseline promotes these anyway): ${plan.skipped.join(', ')}`]
      : []),
    markerLine(platform, grant, plan, scored),
  ];
}

/**
 * Look each planned entry up in an arm's own real home.
 *
 * ⛔ A MISSING HOME DIRECTORY IS NOT AN ABSENT ENTRY. `null` propagates to VOID through `scoreProbe`,
 * because a home the driver never created reads exactly like a drop arm that correctly discarded
 * everything — and that mistake manufactures the red arm this whole module exists to require honest
 * evidence for.
 *
 * ⛔ PRESENCE IS `existsSync` ON THE ENTRY, NOT A FILE COUNT. `promote_declared_path`'s invariant is
 * that promotion can only ever ADD, and it renames whole subtrees where the destination is absent,
 * so the directory's arrival is the event. A count would need a reference to compare against, and
 * the only honest reference is the other arm — which is what the pair already is.
 */
export function observeHome(home, entries, { fs, path }) {
  if (!home || !fs.existsSync(home)) return null;
  const out = {};
  for (const e of entries) out[e] = fs.existsSync(path.join(home, ...posix(e).split('/')));
  return out;
}

/**
 * The two arms, as `[label, grant]`, in the order a driver must run them.
 *
 * ⛔ THE DROP GRANT IS COMPUTED BY `descent-terms.mjs::narrow`, NEVER BY A LOCAL `delete`. That module
 * owns the applier for exactly the reason its own header gives — three inline copies of one drop are
 * how a name came to mean different things in different drivers — and its applier THROWS on a drop it
 * cannot genuinely apply, where a `delete g.writePaths` on a grant that declares none would silently
 * produce the unnarrowed grant and the pair would compare an arm against itself.
 */
export function probeArms(grant, narrow) {
  return [
    ['control', JSON.parse(JSON.stringify(grant))],
    ['drop', narrow(grant, ['no-writePaths'])],
  ];
}

// CLI for the two shell drivers. `measure-windows.mjs` imports the functions directly.
//
// ⛔ THE SPELLING IS NOT DUPLICATED INTO BASH, for the reason `descent-terms.mjs` gives at its own
// CLI: three hand-written copies of one vocabulary is how the Linux descent came to emit names the
// other two drivers spelled differently, undetected until the records were re-parsed.
//
// ⛔ A THROW MUST EXIT NON-ZERO AND PRINT NOTHING ON STDOUT. `--entries` is read into a shell
// variable and iterated; an error message on that channel would become a path the driver then
// creates.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const arg = (flag) => {
    const i = process.argv.indexOf(flag);
    return i === -1 ? null : process.argv[i + 1];
  };
  const grantRaw = arg('--grant');
  if (grantRaw === null) {
    console.error('usage: promotion-probe.mjs --grant <json> [--entries] '
      + '[--score --control-home <dir> --drop-home <dir>] [--platform <p>]');
    process.exit(2);
  }
  const grant = JSON.parse(grantRaw);
  const platform = arg('--platform') ?? process.platform;
  const plan = probePlan(grant);
  if (process.argv.includes('--entries')) {
    // One entry per line, so a path with a space survives. Empty output = do not run the pair.
    for (const e of plan.entries) console.log(e);
  } else if (process.argv.includes('--score')) {
    const observed = plan.supported
      ? {
        control: observeHome(arg('--control-home'), plan.entries, { fs, path }),
        drop: observeHome(arg('--drop-home'), plan.entries, { fs, path }),
      }
      : {};
    for (const l of verdictLines(platform, grant, plan, scoreProbe(plan, observed))) console.log(l);
  } else {
    console.error('promotion-probe.mjs: one of --entries or --score is required');
    process.exit(2);
  }
}
