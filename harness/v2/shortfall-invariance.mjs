// Did the artifact shortfall RESPOND to widening the grant, or was it there the whole way up?
//
// ⛔ THIS IS THE ONE QUESTION THE LADDER CANNOT ASK ITSELF. Every driver reads one boolean per rung, so
// four arms that each exited 0 and each fell short by the SAME files are indistinguishable from four
// arms that failed for four different reasons — and both land on the terminal verdict, which discards
// the record.
//
// ⛔ ALL THREE DRIVERS CONSULT THIS, AND FOR A WHILE ONLY ONE DID. `measure.sh` has since it was
// written; `measure-macos.sh` and `measure-windows.mjs` were taught it together, because a
// single-driver edit is exactly the cross-driver asymmetry that let macOS ship without a ladder at
// all. The cost of the gap was measured on `@arbitrum/sdk@3.0.0-beta.0`: darwin ran all three rungs
// and got `rc=0 artifacts=816/1117 missing=301 shortfall=0d0532fa4785` at every one of them,
// including `write:"disk"`, and recorded `UNDER-PREDICTED` — while Linux, from a different tracer,
// had already recorded the same package `ARTIFACT-GATE-SUSPECT`. Both verdicts are excluded from the
// catalog (`collate.mjs:187`), so the gap was never a broken-install risk; it was a TRIAGE gap, and
// the distinction it erases — "needs a wider grant" versus "no grant will ever help" — is the one
// that manufactures false under-grant findings.
//
// The rule being applied: a shortfall INVARIANT under widening is not a capability gap. The top rung
// is `{"write":"disk","network":true}` and the rung below it adds `"read":"disk"`, so every axis the
// harness models reaches its maximum somewhere in the ladder. A shortfall unchanged across all of them
// cannot be caused by a denied write, a denied read, or a blocked socket — there is no narrower grant
// for it to be evidence about. It says something about the ARM's toolchain, which is a different
// question and not this harness's.
//
// MEASURED over the 45 `records-v2/runs/linux-x64` records this was FIRST written against: the predicate
// holds on exactly 2 (`lmdb-store@2.0.0-alpha2`, `windows-foreground-love@0.6.1`) and on NONE of the
// 12 `MINIMAL` ones. `windows-foreground-love@0.6.1` is the cost of not having it — it synthesized
// `{"write":{"project":true},"network":true}`, that arm exited 0 with all 18 artifacts present and 3
// node-gyp bookkeeping files a few hundred bytes short, the identical shortfall survived every rung up
// to `write:"disk"`, and a correct grant was thrown away.
//
// ⛔ IT IS DELIBERATELY NOT A LOOSENING OF THE GATE. The gate stays a single-arm predicate and its
// verdict on every arm is unchanged; this reads the SEQUENCE of those verdicts. Nothing here can make
// one arm pass that did not pass before.
//
//   usage: <ledger on stdin> node shortfall-invariance.mjs [--arms <n>]
//   ledger: one `rc:shortfall-digest:ok|abs:missing-count` line per grant-WIDENING arm, in order.
//   exit 0 = grant-independent (stdout: `GRANT-INDEPENDENT <count> <digest>`)
//   exit 1 = not established (stdout: the clause that refused, so a log says WHY, not just no)
import crypto from 'node:crypto';

// The IDENTITY of a shortfall, and the ONE definition of it in the harness. Three call sites want it:
// `artifact-gate.mjs` prints it as `shortfall=<digest>` for the two POSIX drivers, and
// `measure-windows.mjs` computes it for its own inline gate, which cannot call the POSIX gate. It
// lives here, beside the predicate that COMPARES digests, rather than being mirrored per driver —
// a mirrored constant is the defect class `ci-env-scrub.test.mjs` exists to police, and there is no
// reason to create a second instance of it.
//
// ⛔ SORTED BEFORE HASHING. The manifest walk's order is filesystem-dependent, so two arms with the
// SAME shortfall would otherwise disagree on its identity — and disagreeing digests are read here as
// "the shortfall responded to the grant", i.e. the refusing direction.
//
// ⛔ `none` FOR AN EMPTY SHORTFALL IS LOAD-BEARING, not a display choice. `classify` refuses that
// value by name, so an arm that passed the gate can never be counted toward grant-independence.
export function shortfallDigest(missing) {
  return missing.length
    ? crypto.createHash('sha1').update(missing.slice().sort().join('\n')).digest('hex').slice(0, 12)
    : 'none';
}

export function classify(ledger, armsExpected = 4) {
  const arms = ledger
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [rc, sig, state, count] = l.split(':');
      return { rc, sig, state, count };
    });

  // A truncated ladder makes "invariant" a claim about too few points to be worth making. The full set
  // is the synth arm plus every rung up to `write:"disk"`, under which no write can be denied — that
  // top rung is what makes grant-independence mean anything at all.
  if (arms.length !== armsExpected) {
    return { ok: false, why: `ladder was not fully walked (${arms.length} arms, expected ${armsExpected})` };
  }
  // ⛔ THE EXIT-CODE CLAUSE IS NOT WHAT DOES THE SEPARATING — THE DIGEST CLAUSE IS, and conflating them
  // is how this rule would swallow a healthy record. `mozjpeg@6.0.1` is `MINIMAL` with rc=0 on BOTH its
  // arms; it is held out ONLY because its shortfall MOVED (0 -> 1) when the grant narrowed. A rule
  // keyed on exit codes alone would bless it and destroy the gate's discrimination at rc=0.
  if (arms.some((a) => a.rc !== '0')) return { ok: false, why: 'an arm exited non-zero' };

  // ⛔⛔ `<package absent>` IS EXCLUDED AND THIS IS THE SAFETY CLAUSE OF THE WHOLE FILE.
  // MEASURED on `netlify-cli@26.2.0`: `artifacts=ABSENT/1110` on all four arms, 3 files in the entire
  // arm tree against OBSERVE's 35,566. The package is not installed at all, so no arm measured
  // anything and the shortfall is "invariant" only in the sense that nothing happened four times.
  // Blessing it would publish `{"write":{"userHome":true}}` off a run in which nothing installed — an
  // under-grant of unknown size, and under-granting is the one direction that breaks a real install.
  // An absent package is a FAILED arm here for exactly the reason it is one inside the gate.
  if (arms.some((a) => a.state === 'abs')) return { ok: false, why: 'the package was ABSENT from an arm — nothing was measured' };

  // `?` is an arm whose gate line carried no digest (a gate that could not run, or an rc=3 arm with no
  // reference). It can never equal another arm's digest, so an unreadable arm can only ever REFUSE the
  // claim — never silently support it. That direction is chosen, not incidental.
  const sigs = new Set(arms.map((a) => a.sig));
  if (sigs.size !== 1) return { ok: false, why: `the shortfall CHANGED across arms (${[...sigs].join(', ')}) — it responded to the grant` };
  const [sig] = sigs;
  if (sig === '?') return { ok: false, why: 'an arm produced no readable shortfall digest' };
  // Unreachable from the driver, which only consults this after the ladder has already failed every
  // arm — but a `none` digest means every arm PASSED, and answering "grant-independent" to that would
  // report a clean run as suspect.
  if (sig === 'none') return { ok: false, why: 'no shortfall — the arms passed the gate' };

  return { ok: true, count: arms[0].count, sig };
}

// ⛔ `pathToFileURL`, not the string form. On Windows `process.argv[1]` is a backslash path while
// `import.meta.url` is `file:///C:/...`, so the comparison never matches, the CLI silently does
// nothing and the process exits 0. See the note on the same guard in `record.mjs`, where the same
// mistake would have cost the whole win32 corpus.
// `process.argv[1] &&` guards the IMPORT case: `pathToFileURL(undefined)` THROWS, so without it
// merely importing this module from a context with no argv[1] (`node -e`, a REPL, an embedder)
// dies before any caller runs. The string form it replaced was wrong but total--it returned false.
if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  const { default: fs } = await import('node:fs');
  const argv = process.argv.slice(2);
  const armsExpected = argv.includes('--arms') ? Number(argv[argv.indexOf('--arms') + 1]) : 4;
  const r = classify(fs.readFileSync(0, 'utf8'), armsExpected);
  if (r.ok) {
    console.log(`GRANT-INDEPENDENT ${r.count} ${r.sig}`);
    process.exit(0);
  }
  console.log(`NOT-ESTABLISHED ${r.why}`);
  process.exit(1);
}
