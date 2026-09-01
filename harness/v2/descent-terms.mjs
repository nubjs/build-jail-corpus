// WHICH CAPABILITIES A VERIFIED GRANT CAN BE ASKED TO DROP — the descent's variant vocabulary, in
// one place because three drivers have to speak it identically.
//
// ⛔⛔ THIS EXISTS TO MAKE THE TERMINAL RUNG DESCENDABLE. `{"write":"disk","network":true}` is the last
// rung of every ladder, and until this module all three drivers REFUSED to descend it — "no droppable
// terms, so no descent". The stated reason was real: `write` arrives there as the STRING `"disk"`, and
// the generator each driver carried did `Object.keys(g.write ?? {})`, which on a string yields
// `["0","1","2","3"]` and would have manufactured four `no-write-<digit>` arms `record.mjs` cannot
// parse. Refusing the whole descent was the safe answer to that, and it cost the corpus everything the
// descent produces: MEASURED on the committed records 2026-09-01, all 75 `write:"disk"` records carry
// `overPredictedBy: []`, `minimality: null` and `grantSource: "synthesized"`. Every one of them is a
// whole-filesystem grant that no arm has ever tried to disprove, and an analysis looking for
// disproving evidence structurally cannot find any.
//
// The repair is not to descend the write axis. It is to notice that the rung is a BUNDLE — the same
// observation that made every OTHER rung descendable — and that its SECOND term is droppable even
// though its first is not.
//
// ── WHY THE WRITE AXIS HAS NO DROPPABLE TERM, AND WHY THAT IS A MEASUREMENT ─────────────────────────
//
// The shipped per-package grant vocabulary is `catalog_v2::Reach = None | Scopes(Vec<Scope>) | Disk`
// with `Scope = Deps | Project | UserHome` (`crates/nub-sandbox/src/catalog_v2.rs`). `"disk"` is
// `Reach::Disk`, the top of a three-value lattice, and every value BELOW it is `Scopes` — which is
// exactly what ladder rungs 0 and 1 are. So by the time a package reaches the terminal rung, every
// narrower write reach the catalog can spell has ALREADY been refuted, by a failed arm, on this
// package, in this run. `no-write-disk` would not be an untried hypothesis; it would be a re-run of
// rung 0 with a new name on it.
//
// That is why this module emits NO write term rather than a `no-write-disk` one, and the distinction
// is not cosmetic. `record.mjs`'s `applyGrantSourceRule` matches `/^no-write-(.+)$/` and would accept
// `no-write-disk`, then evaluate `delete "disk"["disk"]` — a no-op on a string primitive — and publish
// `grantSource: "descended"` beside a grant identical to the wide one. That is the exact silent no-op
// `descent-vocabulary.test.mjs` was written to prevent, reintroduced through the front door.
//
// ⛔ SO THE WRITE AXIS IS ADJUDICATED SOMEWHERE ELSE, AND IT IS NOT THIS MODULE'S JOB TO DUPLICATE IT.
// `confined-wide.mjs` is the arm that asks whether a `write:"disk"` package needs the whole filesystem
// or merely fails under confinement, and it runs on this exact rung already. It cannot narrow a record
// — its widening rides the catalog's GLOBAL `baseline`, which has no per-package spelling — so it is a
// diagnosis, and this module leaves it to it. What the drivers print here NAMES that division, so a
// reader of a `DESCENT-UNSUPPORTED` line is not left thinking the write axis was forgotten.
//
// ── WHY `network` IS DROPPABLE ON POSIX AND NOT ON WINDOWS ──────────────────────────────────────────
//
// `relax_fs_to_full_disk` (`crates/nub-sandbox/src/compiler/preset.rs`) mutates `policy.fs` and
// NOTHING else — no `policy.net` field is touched — so whether the net axis survives the terminal rung
// is a per-backend question, and the three backends answer it differently:
//
//   linux    `linux.rs`: `sandboxing = confine_fs || policy.net.enforce || policy.env.enforce || …`.
//            The net axis is a seccomp filter over `SYS_socket`/`SYS_socketpair`, independent of the
//            Landlock ruleset the fs axis compiles to. A relaxed fs does not stand the filter down.
//   darwin   `macos.rs`: `needs_sandbox = fs_confines(policy) || tmp_confines(policy) ||
//            policy.net.enforce`, and `emit_fs` carries a dedicated branch for exactly this state —
//            "Fully relaxed fs — grant every file op (we wrapped only to enforce net)". Supported, by
//            name, in the backend.
//   win32    `windows.rs`: `if policy.build_jail && !confine_fs { … deg.lost.push("net") … return
//            plain_command(…) }`. There is no LowBox token, and its own comment says why: "egress is
//            an AppContainer CAPABILITY here (`internetClient`), so declining the token declines the
//            net axis with it. A full-disk package that the catalog does NOT admit to the network
//            therefore reaches it anyway on Windows".
//
// ⛔⛔ SO A `no-network` ARM AT THE TERMINAL RUNG ON win32 WOULD BE UNFALSIFIABLE BY CONSTRUCTION, AND
// RUNNING IT IS WORSE THAN NOT DESCENDING AT ALL. The child holds unrestricted egress whether the
// grant admits it or not, so the arm cannot go red for a network reason; it goes green, the record
// narrows to `{"write":"disk"}`, and the catalog then states that a package which used the network
// freely does not need it. That is a vacuous pass turned into an under-grant — the direction that
// breaks a real install, arrived at through the one instrument that was supposed to prevent it. The
// corpus already carries an `arms-unfalsifiable` marker for arms that could not have gone red; this
// module refuses to CREATE one. win32 gets `UNSUPPORTED`, said out loud, with the backend reason
// attached.
//
// ⛔ THE win32 ANSWER IS DERIVED FROM THE BACKEND SOURCE, NOT FROM A RUN. nub reports the loss in its
// `Degradation` (`lost: ["net"]`) but no driver captures that output today, so there is no marker to
// key on. Reading the source is the available evidence and it is unambiguous; if a driver ever learns
// to parse the degradation, `NET_ENFORCED_AT_FULL_DISK` is the one line that should start consulting
// it instead.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * The write reach that is a STRING rather than a map of scopes. `catalog_v2::Reach::Disk`.
 *
 * There is exactly one, and this module refuses any other string rather than guessing — a future
 * reach spelled as a string would otherwise fall into whichever branch happened to be last.
 */
export const ATOMIC_WRITE_REACH = 'disk';

/**
 * Platforms whose backend still ENFORCES the network axis once the fs axis is fully relaxed.
 *
 * Not a preference list. Each entry is a branch read out of `crates/nub-sandbox/src/backend/`, quoted
 * in this file's header. A platform missing from this set does not lose the descent — it loses the one
 * term whose arm could not have failed there.
 */
export const NET_ENFORCED_AT_FULL_DISK = new Set(['linux', 'darwin']);

/** The marker the drivers print when nothing is droppable but the grant is not empty. */
export const DESCENT_UNSUPPORTED_MARKER = 'DESCENT-UNSUPPORTED';

/** Why an axis produced no term. Machine-readable; the prose in `verdictLines` mirrors these. */
export const SKIP_REASONS = {
  'reach-atomic':
    'write:"disk" is `Reach::Disk`, the top of the catalog\'s three-value write lattice, and every '
    + 'narrower reach it can spell was already refuted by a failed ladder rung on this package',
  'net-axis-lost-at-full-disk':
    'the network axis is not enforced at write:"disk" on this platform (declining the AppContainer '
    + 'token declines egress with it), so a passing drop arm could not have failed',
};

/**
 * The capabilities a leave-one-out descent may drop from `grant`, and the axes it may not.
 *
 * Returns `{ terms, skipped }`. `terms` is the driver's arm list, in the order the drivers have always
 * emitted (network, write, read) so a log's shape does not shift. `skipped` records every axis that
 * HOLDS a capability but yielded no term, which is what separates "this grant is empty" from "this
 * grant is wide and nothing about it can be tested here" — two states the drivers used to print the
 * same sentence for, and `record.mjs` reads that sentence as `minimality: MINIMAL`.
 *
 * ⛔ THROWS ON AN UNRECOGNISED `write` SHAPE. The failure this whole module exists to prevent is a
 * generator that fabricates names out of a value it did not understand, so the only safe response to
 * an unknown shape is to stop. A driver that dies here fails the run; a driver that guesses publishes
 * a grant nobody measured.
 */
export function descentTerms(grant, platform = process.platform) {
  if (!grant || typeof grant !== 'object') throw new Error(`descent-terms: \`${grant}\` is not a grant`);
  const terms = [];
  const skipped = [];

  const w = grant.write;
  const writeIsAtomic = w === ATOMIC_WRITE_REACH;
  if (w !== undefined && w !== null && !writeIsAtomic && typeof w !== 'object') {
    throw new Error(
      `descent-terms: \`write: ${JSON.stringify(w)}\` is neither a map of scopes nor `
        + `\`"${ATOMIC_WRITE_REACH}"\` — refusing to guess which arms it implies`,
    );
  }

  // ⛔ THE ORDER IS network, write, read — the order all three drivers already emitted. Keeping it
  // means no committed log's arm sequence changes meaning, and the descent's `$NARROWER` summary line
  // keeps listing capabilities in the order a reader of an older log expects.
  if (grant.network) {
    if (writeIsAtomic && !NET_ENFORCED_AT_FULL_DISK.has(platform)) {
      skipped.push({ axis: 'network', reason: 'net-axis-lost-at-full-disk', platform });
    } else {
      terms.push('no-network');
    }
  }
  if (writeIsAtomic) skipped.push({ axis: 'write', reason: 'reach-atomic' });
  else for (const k of Object.keys(w ?? {})) terms.push(`no-write-${k}`);
  if (grant.read) terms.push('no-read');

  // ⛔ THE REGRESSION GUARD, AND IT IS THE POINT OF CENTRALISING THIS. `Object.keys("disk")` is
  // `["0","1","2","3"]`, and a reintroduced `Object.keys(g.write ?? {})` over the string form would
  // sail past every test that only checks the HAPPY shapes. This assertion cannot: it fires on the
  // exact names that mistake produces, and on `no-write-disk`, which parses in `record.mjs` and
  // recomputes to nothing.
  for (const t of terms) {
    const m = /^no-write-(.+)$/.exec(t);
    if (!m) continue;
    if (typeof w !== 'object' || w === null || !(m[1] in w)) {
      throw new Error(
        `descent-terms: fabricated \`${t}\` — \`${m[1]}\` is not a write scope of `
          + `${JSON.stringify(w)}; \`record.mjs\` would parse this name and recompute nothing`,
      );
    }
  }
  return { terms, skipped };
}

/**
 * `grant` with every capability in `names` removed — the arm's actual grant.
 *
 * ⛔⛔ THE APPLIER FAILS CLOSED, WHICH THE THREE INLINE COPIES OF IT DID NOT. Each driver carried its
 * own `delete g.write[k]`, and on a STRING `write` that expression is a silent no-op: JavaScript
 * evaluates `delete "disk"["disk"]` to `true` and changes nothing. An arm built that way would run the
 * UNNARROWED grant, pass trivially, and be recorded as proof the capability was droppable — a vacuous
 * pass promoted to an under-grant. A name this function cannot genuinely apply is a throw, never a
 * grant that merely looks narrowed.
 */
export function narrow(grant, names) {
  const g = JSON.parse(JSON.stringify(grant));
  for (const n of names) {
    if (n === 'no-network') { delete g.network; continue; }
    if (n === 'no-read') { delete g.read; continue; }
    const w = /^no-write-(.+)$/.exec(n);
    if (!w) throw new Error(`descent-terms: \`${n}\` is not a drop name this vocabulary defines`);
    if (typeof g.write !== 'object' || g.write === null || !(w[1] in g.write)) {
      throw new Error(
        `descent-terms: \`${n}\` cannot be applied to \`write: ${JSON.stringify(g.write)}\` — `
          + 'the drop would be a no-op and the arm would run the UNNARROWED grant',
      );
    }
    delete g.write[w[1]];
    if (!Object.keys(g.write).length) delete g.write;
  }
  return g;
}

/** Every arm the descent will run: `[name, narrowedGrant]`, in emission order. */
export function variants(grant, platform = process.platform) {
  return descentTerms(grant, platform).terms.map((t) => [t, narrow(grant, [t])]);
}

/**
 * What a driver prints when `terms` is empty, as an array of ready-to-print lines.
 *
 * ⛔⛔ THE TWO EMPTY CASES ARE NOT THE SAME RECORD, AND THEY USED TO PRINT THE SAME SENTENCE.
 * `record.mjs` matches `/grant is already empty/` and sets `minimality: 'MINIMAL'`, which is honest
 * for a grant with no capabilities — nothing to narrow, minimal by construction. Reaching that line
 * with `{"write":"disk","network":true}` in hand would publish the corpus's WIDEST grant as PROVEN
 * MINIMAL off a descent that ran zero arms. So an empty term list on a non-empty grant gets its own
 * verdict, which `record.mjs` reads as `UNPROVEN`, plus a JSON marker carrying the per-axis reason.
 */
export function verdictLines(grant, platform = process.platform) {
  const { terms, skipped } = descentTerms(grant, platform);
  if (terms.length) return [];
  if (!skipped.length) {
    // Verbatim: `record.mjs` keys on `grant is already empty` and this is the only producer left.
    return ['  DESCEND   grant is already empty — nothing to narrow; MINIMAL by construction.'];
  }
  const why = skipped.map((s) => `${s.axis}: ${SKIP_REASONS[s.reason]}`).join('; ');
  return [
    `  => DESCENT UNSUPPORTED — ${why}; MINIMALITY IS UNPROVEN`,
    // The write axis is not unexamined, it is examined by a different arm. Saying so here is what
    // keeps a reader from filing "nothing was measured" against a package CONFINED-WIDE answered.
    ...(skipped.some((s) => s.axis === 'write')
      ? ['     ⇒ the write axis is adjudicated by the CONFINED-WIDE probe on this rung, not by a'
         + ' leave-one-out arm; read that marker for whether confinement is possible at all.']
      : []),
    `  ${DESCENT_UNSUPPORTED_MARKER} ${JSON.stringify({ platform, grant, skipped })}`,
  ];
}

// CLI for the two shell drivers. `measure-windows.mjs` imports the functions directly.
//
// ⛔ THE SPELLING IS NOT DUPLICATED INTO BASH, for the same reason `confined-wide.mjs` is not: three
// hand-written copies of one vocabulary is precisely how `measure.sh` came to emit the bare `network`
// / `write.deps` names for the whole life of the Linux descent while the other two spelled them
// correctly, and nothing noticed until the records were re-parsed.
if (fs.realpathSync(process.argv[1] || '.') === fs.realpathSync(fileURLToPath(import.meta.url))) {
  const arg = (flag) => {
    const i = process.argv.indexOf(flag);
    return i === -1 ? null : process.argv[i + 1];
  };
  const platform = arg('--platform') ?? process.platform;
  const MODES = ['terms', 'verdict', 'variants', 'narrow'];
  const mode = MODES.find((m) => process.argv.includes(`--${m}`)) ?? null;
  const raw = mode === null ? null : arg(`--${mode}`);
  if (!mode || raw === null || raw === undefined) {
    console.error(`usage: descent-terms.mjs --${MODES.join('|--')} <grant-json> [--drop "<names>"] [--platform <p>]`);
    process.exit(2);
  }
  const grant = JSON.parse(raw);
  // ⛔ A THROW MUST EXIT NON-ZERO AND PRINT NOTHING ON STDOUT. The shell reads stdout into `$CAPS` and
  // into the arm's grant; an error message on that channel would become an arm name or a grant. A
  // throw here is precisely the case where failing beats continuing.
  if (mode === 'terms') console.log(descentTerms(grant, platform).terms.join(' '));
  else if (mode === 'verdict') for (const l of verdictLines(grant, platform)) console.log(l);
  else if (mode === 'variants') {
    for (const [n, g] of variants(grant, platform)) console.log(`${n}\t${JSON.stringify(g)}`);
  } else console.log(JSON.stringify(narrow(grant, (arg('--drop') ?? '').split(/\s+/).filter(Boolean))));
}
